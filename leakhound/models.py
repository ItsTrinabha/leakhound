"""Core data types shared by the detector, scanners and reporters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class Severity(IntEnum):
    """Ordered severity levels. Higher values are more severe."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        """Parse a case-insensitive severity name such as ``"high"``.

        Raises:
            ValueError: if ``value`` is not a known severity.
        """
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {choices})") from None

    @property
    def label(self) -> str:
        """Lower-case name used in output, e.g. ``"critical"``."""
        return self.name.lower()

    def downgraded(self) -> "Severity":
        """Return the next lower severity (``LOW`` stays ``LOW``)."""
        return Severity(max(self.value - 1, Severity.LOW.value))

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.label


def redact(secret: str, keep: int = 4) -> str:
    """Mask a secret so it can be shown in logs without leaking it.

    The first ``keep`` characters are preserved (enough to recognise the
    provider prefix) and the rest is replaced with a fixed-width mask, so the
    output length does not reveal the secret's length either. Secrets that are
    too short to safely reveal any prefix are fully masked. For PEM blocks the
    (non-secret) header is kept so the key type stays visible.
    """
    if secret.startswith("-----BEGIN"):
        header_end = secret.find("-----", len("-----BEGIN"))
        if header_end != -1:
            return secret[: header_end + 5] + " ********"
    if len(secret) <= keep * 2:
        return "*" * 8
    return secret[:keep] + "*" * 8


@dataclass(frozen=True)
class CommitInfo:
    """Metadata of the git commit that introduced a finding."""

    sha: str
    author: str
    email: str
    date: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "sha": self.sha,
            "author": self.author,
            "email": self.email,
            "date": self.date,
            "message": self.message,
        }


@dataclass
class Finding:
    """A single suspected secret.

    Attributes:
        rule_id: Stable identifier of the rule that fired (e.g. ``aws-access-key-id``).
        rule_name: Human readable rule name.
        description: Why this is a problem / what the secret is.
        severity: Effective severity (may be downgraded for test paths).
        path: POSIX path relative to the scan root.
        line, column: 1-based start position of the secret.
        end_line, end_column: 1-based end position; ``end_column`` is exclusive.
        secret: The raw matched secret. Never printed unless redaction is off.
        line_text: The source line the secret starts on (trimmed).
        entropy: Shannon entropy of the secret in bits per character.
        source: ``"file"``, ``"git"`` or ``"staged"``.
        commit: Commit that introduced the secret (git mode only).
        tags: Extra labels such as ``"test-path"``.
    """

    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    path: str
    line: int
    column: int
    end_line: int
    end_column: int
    secret: str
    line_text: str
    entropy: float
    source: str = "file"
    commit: Optional[CommitInfo] = None
    tags: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable identity used for baselines and de-duplication.

        It deliberately ignores line numbers and commits so that a known,
        accepted finding stays suppressed when surrounding code moves.
        """
        raw = f"{self.rule_id}\0{self.path}\0{self.secret}".encode("utf-8", "replace")
        return hashlib.sha256(raw).hexdigest()[:32]

    def display_secret(self, redact_secrets: bool = True) -> str:
        """The secret as it should appear in output."""
        return redact(self.secret) if redact_secrets else self.secret

    def display_line(self, redact_secrets: bool = True, limit: int = 200) -> str:
        """The source line with the secret masked (when redacting)."""
        text = self.line_text
        if redact_secrets:
            first_line = self.secret.splitlines()[0] if self.secret else ""
            if first_line and first_line in text:
                text = text.replace(first_line, redact(self.secret))
        text = text.strip()
        if len(text) > limit:
            text = text[: limit - 3] + "..."
        return text

    def to_dict(self, redact_secrets: bool = True) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.label,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "secret": self.display_secret(redact_secrets),
            "line_text": self.display_line(redact_secrets),
            "entropy": round(self.entropy, 3),
            "source": self.source,
            "commit": self.commit.to_dict() if self.commit else None,
            "tags": list(self.tags),
            "fingerprint": self.fingerprint,
        }
