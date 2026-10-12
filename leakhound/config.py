"""Scan settings, allowlists and ``.leakhound.toml`` loading.

Example ``.leakhound.toml``::

    [scan]
    max_file_size = 1048576       # bytes; larger files are skipped
    exclude_tests = false         # true: drop findings in test paths entirely
    disabled_rules = ["jwt"]

    [entropy]
    enabled = true
    base64_threshold = 4.5
    hex_threshold = 3.0
    min_length = 20

    [allowlist]
    paths = ["docs/*", "*.snap"]        # globs; extra to the built-in ignores
    regexes = ["^sk_test_"]             # secrets matching these are ignored
    stopwords = ["not-a-real"]          # secrets containing these are ignored

    [[rules]]                           # custom rules
    id = "acme-api-key"
    name = "ACME API Key"
    regex = "acme_[a-z0-9]{32}"
    severity = "high"
    keywords = ["acme_"]
"""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Optional

from .entropy import EntropySettings
from .models import Severity
from .rules import BUILTIN_RULES, Rule

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on old interpreters
    tomllib = None

CONFIG_FILENAME = ".leakhound.toml"
INLINE_ALLOW_MARKER = "leakhound:allow"

#: Directories and files that never contain first-party secrets worth reporting
#: (dependencies, caches, VCS internals) or cannot be meaningfully scanned.
DEFAULT_IGNORED_PATHS: tuple[str, ...] = (
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "__pycache__", ".venv", "venv", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".idea", ".gradle", ".terraform",
    # lock files are full of integrity hashes
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock",
    "uv.lock",
    # generated / minified
    "*.min.js", "*.min.css", "*.map", "*.svg",
    # binary formats
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp", "*.ico", "*.webp", "*.tiff",
    "*.pdf", "*.zip", "*.gz", "*.tgz", "*.bz2", "*.xz", "*.7z", "*.rar",
    "*.jar", "*.war", "*.class", "*.pyc", "*.pyo", "*.so", "*.dll", "*.dylib",
    "*.exe", "*.bin", "*.o", "*.a", "*.woff", "*.woff2", "*.ttf", "*.otf",
    "*.eot", "*.mp3", "*.mp4", "*.mov", "*.avi", "*.wav", "*.ogg", "*.sqlite",
    "*.db", "*.parquet",
)

#: Substrings that mark a value as a placeholder rather than a real secret.
DEFAULT_STOPWORDS: tuple[str, ...] = (
    "example", "sample", "placeholder", "changeme", "change_me", "dummy",
    "redacted", "xxxxxx", "******", "your_", "your-", "<your", "${", "{{",
    "insert_", "replace_me", "todo",
)

_TEST_DIRS = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "testdata", "test_data",
     "fixtures", "__fixtures__", "mocks", "__mocks__", "testing"}
)
_TEST_FILE_RE = re.compile(
    r"(^test_.*\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$|Test\.java$|_spec\.rb$|Tests?\.cs$)"
)


class ConfigError(Exception):
    """Raised for invalid configuration files or options."""


def is_test_path(path: str) -> bool:
    """True when ``path`` (POSIX, relative) looks like test code or fixtures."""
    parts = PurePosixPath(path).parts
    if any(part.lower() in _TEST_DIRS for part in parts[:-1]):
        return True
    return bool(parts) and bool(_TEST_FILE_RE.search(parts[-1]))


@dataclass
class Allowlist:
    """Rules for ignoring paths and known-safe secret values.

    Path patterns are shell globs. A pattern without ``/`` matches any single
    path component (so ``node_modules`` or ``*.png`` work at any depth); a
    pattern containing ``/`` is matched against the whole relative path.
    """

    paths: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORED_PATHS))
    regexes: list[re.Pattern] = field(default_factory=list)
    stopwords: list[str] = field(default_factory=lambda: list(DEFAULT_STOPWORDS))
    fingerprints: set[str] = field(default_factory=set)

    def is_path_ignored(self, rel_path: str) -> bool:
        parts = PurePosixPath(rel_path).parts
        for pattern in self.paths:
            if "/" in pattern.rstrip("/"):
                if fnmatch.fnmatchcase(rel_path, pattern.rstrip("/")):
                    return True
            elif any(fnmatch.fnmatchcase(part, pattern.rstrip("/")) for part in parts):
                return True
        return False

    def is_secret_allowed(self, secret: str) -> bool:
        """True when ``secret`` is a placeholder or explicitly allowlisted."""
        lowered = secret.lower()
        if any(word in lowered for word in self.stopwords):
            return True
        if len(set(secret)) <= 3:  # "aaaaaaaa", "12121212"
            return True
        return any(regex.search(secret) for regex in self.regexes)


@dataclass
class Settings:
    """Everything that controls a scan."""

    rules: list[Rule] = field(default_factory=lambda: list(BUILTIN_RULES))
    entropy: EntropySettings = field(default_factory=EntropySettings)
    allowlist: Allowlist = field(default_factory=Allowlist)
    max_file_size: int = 1024 * 1024
    exclude_tests: bool = False
    downgrade_tests: bool = True
    disabled_rule_ids: set[str] = field(default_factory=set)

    def without_rules(self, rule_ids: Iterable[str]) -> "Settings":
        """Return a copy with the given rule ids disabled."""
        ids = set(rule_ids)
        known = {r.id for r in self.rules} | {"high-entropy-string", "high-entropy-hex"}
        unknown = ids - known
        if unknown:
            raise ConfigError(f"unknown rule id(s): {', '.join(sorted(unknown))}")
        return replace(
            self,
            rules=[r for r in self.rules if r.id not in ids],
            disabled_rule_ids=self.disabled_rule_ids | ids,
        )


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

_ALLOWED_KEYS = {
    "scan": {"max_file_size", "exclude_tests", "downgrade_tests", "disabled_rules"},
    "entropy": {"enabled", "base64_threshold", "hex_threshold", "min_length", "max_length"},
    "allowlist": {"paths", "regexes", "stopwords"},
    "rules": None,
}
_RULE_KEYS = {"id", "name", "description", "regex", "severity", "keywords", "min_entropy", "tags"}


def _expect(value: Any, kind: type | tuple[type, ...], where: str) -> Any:
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise ConfigError(f"{where}: expected {getattr(kind, '__name__', kind)}, got {type(value).__name__}")
    return value


def _string_list(value: Any, where: str) -> list[str]:
    _expect(value, list, where)
    return [_expect(item, str, f"{where}[]") for item in value]


def _compile(pattern: str, where: str) -> re.Pattern:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"{where}: invalid regex {pattern!r}: {exc}") from None


def _custom_rule(raw: dict[str, Any], index: int) -> Rule:
    where = f"rules[{index}]"
    _expect(raw, dict, where)
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    for required in ("id", "regex"):
        if required not in raw:
            raise ConfigError(f"{where}: missing required key '{required}'")
    try:
        severity = Severity.parse(raw.get("severity", "high"))
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None
    rule_id = _expect(raw["id"], str, f"{where}.id")
    return Rule(
        id=rule_id,
        name=_expect(raw.get("name", rule_id), str, f"{where}.name"),
        description=_expect(raw.get("description", f"Custom rule {rule_id}."), str, f"{where}.description"),
        severity=severity,
        regex=_compile(_expect(raw["regex"], str, f"{where}.regex"), f"{where}.regex"),
        keywords=tuple(k.lower() for k in _string_list(raw.get("keywords", []), f"{where}.keywords")),
        min_entropy=float(_expect(raw.get("min_entropy", 0.0), (int, float), f"{where}.min_entropy")),
        tags=tuple(_string_list(raw.get("tags", ["custom"]), f"{where}.tags")),
    )


def settings_from_dict(data: dict[str, Any], base: Optional[Settings] = None) -> Settings:
    """Build :class:`Settings` from a parsed config mapping."""
    settings = base or Settings()
    for section, value in data.items():
        if section not in _ALLOWED_KEYS:
            raise ConfigError(f"unknown config section [{section}]")
        if _ALLOWED_KEYS[section] is not None:
            _expect(value, dict, f"[{section}]")
            unknown = set(value) - _ALLOWED_KEYS[section]
            if unknown:
                raise ConfigError(f"[{section}]: unknown key(s): {', '.join(sorted(unknown))}")

    scan = data.get("scan", {})
    if "max_file_size" in scan:
        settings.max_file_size = _expect(scan["max_file_size"], int, "scan.max_file_size")
    if "exclude_tests" in scan:
        settings.exclude_tests = _expect(scan["exclude_tests"], bool, "scan.exclude_tests")
    if "downgrade_tests" in scan:
        settings.downgrade_tests = _expect(scan["downgrade_tests"], bool, "scan.downgrade_tests")

    ent = data.get("entropy", {})
    if ent:
        kwargs: dict[str, Any] = {}
        for key in ("base64_threshold", "hex_threshold"):
            if key in ent:
                kwargs[key] = float(_expect(ent[key], (int, float), f"entropy.{key}"))
        for key in ("min_length", "max_length"):
            if key in ent:
                kwargs[key] = _expect(ent[key], int, f"entropy.{key}")
        if "enabled" in ent:
            kwargs["enabled"] = _expect(ent["enabled"], bool, "entropy.enabled")
        settings.entropy = replace(settings.entropy, **kwargs)

    allow = data.get("allowlist", {})
    settings.allowlist.paths.extend(_string_list(allow.get("paths", []), "allowlist.paths"))
    settings.allowlist.stopwords.extend(s.lower() for s in _string_list(allow.get("stopwords", []), "allowlist.stopwords"))
    settings.allowlist.regexes.extend(
        _compile(p, "allowlist.regexes") for p in _string_list(allow.get("regexes", []), "allowlist.regexes")
    )

    custom = data.get("rules", [])
    _expect(custom, list, "rules")
    existing = {r.id for r in settings.rules}
    for index, raw in enumerate(custom):
        rule = _custom_rule(raw, index)
        if rule.id in existing:
            raise ConfigError(f"rules[{index}]: duplicate rule id '{rule.id}'")
        existing.add(rule.id)
        settings.rules.append(rule)

    disabled = _string_list(scan.get("disabled_rules", []), "scan.disabled_rules")
    return settings.without_rules(disabled) if disabled else settings


def load_settings(scan_root: Path, config_path: Optional[Path] = None) -> Settings:
    """Load settings from ``config_path`` or ``<scan_root>/.leakhound.toml``.

    Missing default config is fine (built-in defaults are used); a missing
    explicitly-requested config is an error.
    """
    path = config_path
    if path is None:
        root_dir = scan_root if scan_root.is_dir() else scan_root.parent
        candidate = root_dir / CONFIG_FILENAME
        if not candidate.is_file():
            return Settings()
        path = candidate
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    if tomllib is None:  # pragma: no cover
        raise ConfigError("reading .leakhound.toml requires Python 3.11+")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from None
    return settings_from_dict(data)


def load_baseline(path: Path) -> set[str]:
    """Return the fingerprints recorded in a previous JSON report."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read baseline {path}: {exc}") from None
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list):
        raise ConfigError(f"baseline {path} is not a leakhound JSON report")
    return {f["fingerprint"] for f in findings if isinstance(f, dict) and "fingerprint" in f}
