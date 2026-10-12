"""leakhound - find leaked secrets in source trees and git history."""

__version__ = "1.0.0"

from .config import Settings, load_settings  # noqa: E402
from .models import Finding, Severity  # noqa: E402
from .scanner import ScanResult, scan_git, scan_path  # noqa: E402

__all__ = [
    "Finding",
    "ScanResult",
    "Settings",
    "Severity",
    "__version__",
    "load_settings",
    "scan_git",
    "scan_path",
]
