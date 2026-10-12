"""Human-readable terminal output with optional ANSI colours."""

from __future__ import annotations

from collections import Counter

from .. import __version__
from ..models import Finding, Severity
from ..scanner import ScanResult

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_COLORS = {
    Severity.CRITICAL: "\033[1;35m",  # bold magenta
    Severity.HIGH: "\033[1;31m",  # bold red
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.LOW: "\033[36m",  # cyan
}


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.enabled else text


def _format_finding(finding: Finding, style: _Style, redact_secrets: bool) -> list[str]:
    sev = finding.severity
    header = (
        f"{style(f'[{sev.label.upper():8}]', _COLORS[sev])} "
        f"{style(finding.rule_name, _BOLD)} {style(f'({finding.rule_id})', _DIM)}"
    )
    lines = [
        header,
        f"    location : {finding.path}:{finding.line}:{finding.column}",
        f"    secret   : {finding.display_secret(redact_secrets)}   {style(f'entropy {finding.entropy:.2f}', _DIM)}",
        f"    code     : {finding.display_line(redact_secrets, limit=120)}",
    ]
    if finding.commit:
        c = finding.commit
        lines.append(f"    commit   : {c.sha[:12]}  {c.author} <{c.email}>  {c.date}")
        lines.append(f"    message  : {c.message[:100]}")
    if finding.tags:
        lines.append(f"    tags     : {', '.join(finding.tags)}")
    return lines


def render(result: ScanResult, redact_secrets: bool = True, color: bool = False, **_: object) -> str:
    """Render findings for a terminal, grouped in path/line order."""
    style = _Style(color)
    stats = result.stats
    scope = {
        "files": f"{stats.files_scanned} files",
        "git": f"{stats.commits_scanned} commits ({stats.files_scanned} file changes)",
        "staged": f"{stats.files_scanned} staged files",
    }[result.mode]
    out = [style(f"leakhound {__version__}", _BOLD) + f"  scanned {scope} in {stats.duration:.2f}s", ""]

    for finding in result.findings:
        out.extend(_format_finding(finding, style, redact_secrets))
        out.append("")

    counts = Counter(f.severity for f in result.findings)
    if result.findings:
        breakdown = ", ".join(
            style(f"{counts[s]} {s.label}", _COLORS[s]) for s in sorted(Severity, reverse=True) if counts[s]
        )
        out.append(style(f"Found {len(result.findings)} potential secret(s)", _BOLD) + f": {breakdown}")
        out.append("Rotate any real credential above before removing it; deleting it from code does not revoke it.")
    else:
        out.append(style("No secrets found.", "\033[1;32m"))
    if result.suppressed:
        out.append(style(f"{result.suppressed} finding(s) suppressed by baseline or test-path policy.", _DIM))
    for warning in result.warnings:
        out.append(style(f"warning: {warning}", _DIM))
    return "\n".join(out) + "\n"
