"""Command-line interface.

Exit codes (stable, safe to use in CI):
    0  no findings at or above ``--fail-on`` severity
    1  findings at or above ``--fail-on`` severity
    2  usage, configuration or runtime error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .config import ConfigError, Settings, load_baseline, load_settings
from .entropy import EntropySettings
from .models import Severity
from .reporters import FORMATS
from .rules import all_rule_metadata
from .scanner import ScanError, ScanResult, scan_git, scan_path

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="file, directory or repository to scan (default: .)")
    out = parser.add_argument_group("output")
    out.add_argument("-f", "--format", choices=sorted(FORMATS), default="console", help="report format (default: console)")
    out.add_argument("-o", "--output", type=Path, help="write the report to a file instead of stdout")
    out.add_argument("--no-redact", action="store_true", help="print secrets in full (default: masked)")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colours (also honours NO_COLOR)")
    out.add_argument("--min-severity", type=_severity, default=Severity.LOW, metavar="SEV",
                     help="only report findings at or above SEV (low|medium|high|critical)")
    gate = parser.add_argument_group("CI gating")
    gate.add_argument("--fail-on", type=_severity, default=Severity.LOW, metavar="SEV",
                      help="exit 1 if any finding is at or above SEV (default: low)")
    gate.add_argument("--exit-zero", action="store_true", help="always exit 0 unless an error occurs")
    det = parser.add_argument_group("detection")
    det.add_argument("-c", "--config", type=Path, help="config file (default: <path>/.leakhound.toml if present)")
    det.add_argument("--baseline", type=Path, help="JSON report of accepted findings to suppress")
    det.add_argument("--disable-rule", action="append", default=[], metavar="ID", help="disable a rule (repeatable)")
    det.add_argument("--no-entropy", action="store_true", help="disable generic high-entropy detection")
    det.add_argument("--exclude-tests", action="store_true",
                     help="drop findings in test/fixture paths (default: report them one severity lower)")
    det.add_argument("--max-file-size", type=int, metavar="BYTES", help="skip files larger than this")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakhound",
        description="Find leaked secrets (API keys, tokens, private keys, passwords) in code and git history.",
        epilog="Exit codes: 0 = clean, 1 = secrets found, 2 = error.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    scan = sub.add_parser("scan", help="scan the current files in a directory tree")
    _add_common(scan)
    scan.add_argument("--no-gitignore", action="store_true",
                      help="in a git work tree, also scan files ignored by .gitignore")

    git = sub.add_parser("git", help="scan every line ever added in git history (or the staged index)")
    _add_common(git)
    mode = git.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="scan only staged changes (for pre-commit hooks)")
    mode.add_argument("--log-opts", metavar="OPTS",
                      help='extra git log arguments, e.g. "origin/main..HEAD" (default: "--all")')

    rules = sub.add_parser("rules", help="list the built-in detection rules")
    rules.add_argument("-f", "--format", choices=["table", "json"], default="table")
    return parser


def _settings_from_args(args: argparse.Namespace, target: Path) -> Settings:
    settings = load_settings(target, args.config)
    if args.disable_rule:
        settings = settings.without_rules(args.disable_rule)
    if args.no_entropy:
        settings.entropy = EntropySettings(enabled=False)
    if args.exclude_tests:
        settings.exclude_tests = True
    if args.max_file_size is not None:
        settings.max_file_size = args.max_file_size
    if args.baseline:
        settings.allowlist.fingerprints |= load_baseline(args.baseline)
    return settings


def _list_rules(fmt: str) -> int:
    rules = all_rule_metadata()
    if fmt == "json":
        payload = [
            {"id": r.id, "name": r.name, "severity": r.severity.label, "description": r.description, "tags": list(r.tags)}
            for r in rules
        ]
        print(json.dumps(payload, indent=2))
        return EXIT_CLEAN
    width = max(len(r.id) for r in rules)
    print(f"{'ID':{width}}  {'SEVERITY':8}  NAME")
    for rule in rules:
        print(f"{rule.id:{width}}  {rule.severity.label:8}  {rule.name}")
    print(f"\n{len(rules)} rules")
    return EXIT_CLEAN


def _use_color(args: argparse.Namespace) -> bool:
    if args.no_color or args.output or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def run(argv: Optional[Sequence[str]] = None) -> int:
    """Parse ``argv``, run the scan and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        return _list_rules(args.format)

    target = Path(args.path)
    try:
        settings = _settings_from_args(args, target)
        if args.command == "git":
            log_opts = args.log_opts.split() if args.log_opts else None
            result: ScanResult = scan_git(target, settings, log_opts=log_opts, staged=args.staged)
        else:
            result = scan_path(target, settings, use_gitignore=not args.no_gitignore)
    except (ConfigError, ScanError) as exc:
        print(f"leakhound: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    result.findings = [f for f in result.findings if f.severity >= args.min_severity]
    report = FORMATS[args.format](
        result,
        redact_secrets=not args.no_redact,
        color=_use_color(args),
        rules=all_rule_metadata(settings.rules),
    )
    if args.output:
        try:
            args.output.write_text(report, encoding="utf-8")
        except OSError as exc:
            print(f"leakhound: error: cannot write {args.output}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"leakhound: wrote {args.format} report with {len(result.findings)} finding(s) to {args.output}",
              file=sys.stderr)
    else:
        sys.stdout.write(report)

    if args.exit_zero:
        return EXIT_CLEAN
    failing = any(f.severity >= args.fail_on for f in result.findings)
    return EXIT_FINDINGS if failing else EXIT_CLEAN


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Console-script entry point."""
    try:
        return run(argv)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("leakhound: interrupted", file=sys.stderr)
        return 130
