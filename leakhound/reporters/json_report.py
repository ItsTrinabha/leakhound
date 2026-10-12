"""Machine-readable JSON report (also usable as a ``--baseline`` file)."""

from __future__ import annotations

import json
from collections import Counter

from .. import __version__
from ..models import Severity
from ..scanner import ScanResult


def summary(result: ScanResult) -> dict:
    """Counts by severity plus scan statistics."""
    counts = Counter(f.severity for f in result.findings)
    return {
        "total": len(result.findings),
        "by_severity": {s.label: counts.get(s, 0) for s in sorted(Severity, reverse=True)},
        "suppressed": result.suppressed,
        "files_scanned": result.stats.files_scanned,
        "files_skipped": result.stats.files_skipped,
        "bytes_scanned": result.stats.bytes_scanned,
        "commits_scanned": result.stats.commits_scanned,
        "duration_seconds": round(result.stats.duration, 3),
    }


def render(result: ScanResult, redact_secrets: bool = True, **_: object) -> str:
    """Render the scan result as pretty-printed JSON."""
    document = {
        "tool": {"name": "leakhound", "version": __version__},
        "target": result.root,
        "mode": result.mode,
        "summary": summary(result),
        "findings": [f.to_dict(redact_secrets) for f in result.findings],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
