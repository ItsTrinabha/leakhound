"""Turns text into findings by running regex rules and the entropy detector."""

from __future__ import annotations

from bisect import bisect_right

from .config import INLINE_ALLOW_MARKER, Settings
from .entropy import iter_candidates, shannon_entropy
from .models import Finding
from .rules import ENTROPY_BASE64_RULE, ENTROPY_HEX_RULE, Rule


class LineIndex:
    """Maps character offsets in a text to 1-based (line, column) positions."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._starts = [0]
        position = text.find("\n")
        while position != -1:
            self._starts.append(position + 1)
            position = text.find("\n", position + 1)

    def locate(self, offset: int) -> tuple[int, int]:
        index = bisect_right(self._starts, offset) - 1
        return index + 1, offset - self._starts[index] + 1

    def line_text(self, line: int) -> str:
        start = self._starts[line - 1]
        end = self._starts[line] - 1 if line < len(self._starts) else len(self._text)
        return self._text[start:end].rstrip("\r")


class Detector:
    """Scans a chunk of text for secrets according to :class:`Settings`."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def scan_text(self, text: str, path: str, line_offset: int = 0) -> list[Finding]:
        """Return findings in ``text``.

        Args:
            text: The content to scan.
            path: Relative path reported in findings.
            line_offset: Added to line numbers; used when ``text`` is a diff
                hunk that starts part-way through a file.
        """
        lowered = text.lower()
        index = LineIndex(text)
        allowlist = self.settings.allowlist
        findings: list[Finding] = []
        spans: list[tuple[int, int]] = []

        for rule in self.settings.rules:
            if rule.regex is None or not rule.applies_to(lowered):
                continue
            for match in rule.regex.finditer(text):
                secret, start, end = rule.extract(match)
                if not secret:
                    continue
                entropy = shannon_entropy(secret)
                if entropy < rule.min_entropy:
                    continue
                if rule.validator is not None and not rule.validator(secret):
                    continue
                if allowlist.is_secret_allowed(secret):
                    continue
                if any(start < s_end and s_start < end for s_start, s_end in spans):
                    continue  # an earlier, more specific rule already reported it
                finding = self._build(rule, index, path, secret, start, end, entropy, line_offset)
                if finding is not None:
                    findings.append(finding)
                    spans.append((start, end))

        disabled = self.settings.disabled_rule_ids
        for candidate in iter_candidates(text, self.settings.entropy):
            rule = ENTROPY_HEX_RULE if candidate.kind == "hex" else ENTROPY_BASE64_RULE
            if rule.id in disabled:
                continue
            if any(candidate.start < s_end and s_start < candidate.end for s_start, s_end in spans):
                continue
            if allowlist.is_secret_allowed(candidate.token):
                continue
            finding = self._build(
                rule, index, path, candidate.token, candidate.start, candidate.end, candidate.entropy, line_offset
            )
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _build(
        rule: Rule,
        index: LineIndex,
        path: str,
        secret: str,
        start: int,
        end: int,
        entropy: float,
        line_offset: int,
    ) -> Finding | None:
        line, column = index.locate(start)
        end_line, end_column = index.locate(end)
        line_text = index.line_text(line)
        if INLINE_ALLOW_MARKER in line_text:
            return None
        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            description=rule.description,
            severity=rule.severity,
            path=path,
            line=line + line_offset,
            column=column,
            end_line=end_line + line_offset,
            end_column=end_column,
            secret=secret,
            line_text=line_text,
            entropy=entropy,
        )
