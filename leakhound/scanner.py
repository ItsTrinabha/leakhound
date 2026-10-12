"""Scanning front-ends: a directory tree, git history, or staged changes."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence

from .config import Settings, is_test_path
from .detector import Detector
from .models import CommitInfo, Finding

_BINARY_SNIFF_BYTES = 8192
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_COMMIT_MARKER = "\x00LEAKHOUND-COMMIT\x00"
_GIT_LOG_FORMAT = "--format=" + _COMMIT_MARKER.replace("\x00", "%x00") + "%H%x00%an%x00%ae%x00%aI%x00%s"


class ScanError(Exception):
    """Raised when a scan cannot run at all (bad path, not a git repo, ...)."""


@dataclass
class ScanStats:
    """Counters describing how much work a scan did."""

    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    commits_scanned: int = 0
    duration: float = 0.0


@dataclass
class ScanResult:
    """Findings plus the context needed to report them."""

    root: str
    mode: str  # "files", "git" or "staged"
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    suppressed: int = 0
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Shared post-processing
# --------------------------------------------------------------------------- #


def _postprocess(findings: Iterable[Finding], settings: Settings, result: ScanResult) -> list[Finding]:
    """Apply test-path policy and baseline suppression, then sort."""
    kept: list[Finding] = []
    for finding in findings:
        if is_test_path(finding.path):
            if settings.exclude_tests:
                result.suppressed += 1
                continue
            finding.tags.append("test-path")
            if settings.downgrade_tests:
                finding.severity = finding.severity.downgraded()
        if finding.fingerprint in settings.allowlist.fingerprints:
            result.suppressed += 1
            continue
        kept.append(finding)
    kept.sort(key=lambda f: (f.path, f.line, f.column, f.rule_id))
    return kept


# --------------------------------------------------------------------------- #
# Directory scanning
# --------------------------------------------------------------------------- #


def _git_available() -> bool:
    return shutil.which("git") is not None


def _is_git_worktree(path: Path) -> bool:
    if not _git_available():
        return False
    proc = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def _git_listed_files(root: Path) -> Optional[list[str]]:
    """Tracked + untracked-but-not-ignored files, honouring .gitignore."""
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True, check=False,
    )
    if proc.returncode != 0:
        return None
    files = [p for p in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if p]
    return sorted(set(files))


def _walk_files(root: Path, settings: Settings) -> Iterator[str]:
    """Walk ``root`` without following symlinks, pruning ignored directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = sorted(d for d in dirnames if not settings.allowlist.is_path_ignored(rel_dir + d))
        for name in sorted(filenames):
            yield rel_dir + name


def _read_text(path: Path, settings: Settings) -> Optional[str]:
    """Read a file as text, or return ``None`` if it should be skipped."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > settings.max_file_size:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:_BINARY_SNIFF_BYTES]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_path(target: Path, settings: Settings, use_gitignore: bool = True) -> ScanResult:
    """Scan the current contents of a file or directory tree.

    When ``target`` is inside a git work tree and ``use_gitignore`` is true,
    only files git would track are scanned (``.gitignore`` is honoured).
    """
    started = time.perf_counter()
    if not target.exists():
        raise ScanError(f"path does not exist: {target}")
    detector = Detector(settings)

    if target.is_file():
        root = target.parent
        candidates: Iterable[str] = [target.name]
    else:
        root = target
        listed = _git_listed_files(root) if use_gitignore and _is_git_worktree(root) else None
        candidates = listed if listed is not None else _walk_files(root, settings)

    result = ScanResult(root=str(target), mode="files")
    raw: list[Finding] = []
    for rel in candidates:
        if settings.allowlist.is_path_ignored(rel):
            result.stats.files_skipped += 1
            continue
        text = _read_text(root / rel, settings)
        if text is None:
            result.stats.files_skipped += 1
            continue
        result.stats.files_scanned += 1
        result.stats.bytes_scanned += len(text)
        raw.extend(detector.scan_text(text, rel))

    result.findings = _postprocess(raw, settings, result)
    result.stats.duration = time.perf_counter() - started
    return result


# --------------------------------------------------------------------------- #
# Git scanning
# --------------------------------------------------------------------------- #


@dataclass
class _Hunk:
    path: str
    start_line: int
    lines: list[str]
    commit: Optional[CommitInfo]


def _unquote_git_path(raw: str) -> str:
    raw = raw.rstrip("\t")
    if raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape").encode("latin-1").decode(
            "utf-8", "replace"
        )
    return raw[2:] if raw.startswith("b/") else raw


def parse_unified_diff(lines: Iterable[str]) -> Iterator[_Hunk]:
    """Yield the *added* lines of each hunk in ``git log -p``/``git diff`` output.

    Only additions matter: a secret is leaked by the commit that adds it.
    Lines are grouped per hunk so multi-line secrets (private keys) stay intact
    and line numbers can be mapped back to the post-change file.
    """
    commit: Optional[CommitInfo] = None
    path: Optional[str] = None
    in_header = False
    hunk: Optional[_Hunk] = None

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if line.startswith(_COMMIT_MARKER):
            if hunk and hunk.lines:
                yield hunk
            hunk, path = None, None
            parts = line[len(_COMMIT_MARKER):].split("\x00")
            parts += [""] * (5 - len(parts))
            commit = CommitInfo(sha=parts[0], author=parts[1], email=parts[2], date=parts[3], message=parts[4])
            continue
        if line.startswith("diff --git "):
            if hunk and hunk.lines:
                yield hunk
            hunk, path, in_header = None, None, True
            continue
        if in_header:
            if line.startswith("+++ "):
                target = line[4:]
                path = None if target.startswith("/dev/null") else _unquote_git_path(target)
            elif line.startswith("@@"):
                in_header = False
            else:
                continue
        if line.startswith("@@"):
            if hunk and hunk.lines:
                yield hunk
            match = _HUNK_RE.match(line)
            hunk = _Hunk(path, int(match.group(1)), [], commit) if (match and path) else None
            continue
        if hunk is not None and line.startswith("+"):
            hunk.lines.append(line[1:])
    if hunk and hunk.lines:
        yield hunk


def _run_git_stream(root: Path, args: Sequence[str]) -> Iterator[str]:
    cmd = ["git", "-C", str(root), "-c", "core.quotepath=off", *args]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace"
    )
    assert proc.stdout is not None
    try:
        yield from proc.stdout
    finally:
        proc.stdout.close()
        stderr = proc.stderr.read() if proc.stderr else ""
        if proc.wait() != 0:
            raise ScanError(f"git {' '.join(args[:2])} failed: {stderr.strip()}")


def scan_git(
    target: Path,
    settings: Settings,
    log_opts: Optional[Sequence[str]] = None,
    staged: bool = False,
) -> ScanResult:
    """Scan git history (every line ever added) or the staged index.

    Args:
        target: Any path inside the repository.
        settings: Scan settings.
        log_opts: Extra ``git log`` arguments, e.g. ``["main~10..main"]``.
            Defaults to ``["--all"]`` (every branch, tag and stash).
        staged: Scan ``git diff --cached`` instead of history; ideal for a
            pre-commit hook.

    A secret that appears in several commits is reported once, attributed to
    the oldest commit that added it.
    """
    started = time.perf_counter()
    if not _git_available():
        raise ScanError("git executable not found on PATH")
    if not target.exists() or not _is_git_worktree(target if target.is_dir() else target.parent):
        raise ScanError(f"not a git repository: {target}")
    root = target if target.is_dir() else target.parent

    if staged:
        args = ["diff", "--cached", "-U0", "--no-color", "--no-ext-diff"]
        mode = "staged"
    else:
        args = ["log", "-p", "-U0", "--no-color", "--no-ext-diff", _GIT_LOG_FORMAT, *(log_opts or ["--all"])]
        mode = "git"

    result = ScanResult(root=str(target), mode=mode)
    detector = Detector(settings)
    by_fingerprint: dict[str, Finding] = {}
    seen_commits: set[str] = set()
    seen_paths: set[tuple[str, str]] = set()

    for hunk in parse_unified_diff(_run_git_stream(root, args)):
        sha = hunk.commit.sha if hunk.commit else ""
        if sha:
            seen_commits.add(sha)
        if (sha, hunk.path) not in seen_paths:
            seen_paths.add((sha, hunk.path))
            if settings.allowlist.is_path_ignored(hunk.path):
                result.stats.files_skipped += 1
                continue
            result.stats.files_scanned += 1
        elif settings.allowlist.is_path_ignored(hunk.path):
            continue
        text = "\n".join(hunk.lines)
        result.stats.bytes_scanned += len(text)
        for finding in detector.scan_text(text, hunk.path, line_offset=hunk.start_line - 1):
            finding.source = mode
            finding.commit = hunk.commit
            # git log is newest-first, so later hunks are older: overwrite to
            # keep the commit that introduced the secret.
            by_fingerprint[finding.fingerprint] = finding

    result.stats.commits_scanned = len(seen_commits)
    result.findings = _postprocess(by_fingerprint.values(), settings, result)
    result.stats.duration = time.perf_counter() - started
    return result
