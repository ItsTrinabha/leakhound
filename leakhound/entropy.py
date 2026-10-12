"""Shannon-entropy based detection of generic, high-randomness secrets.

Named regex rules only catch secrets whose format is known. Many credentials
(internal API keys, random passwords, HMAC keys) have no recognisable prefix,
but they *are* random, and randomness is measurable: a string drawn uniformly
from a large alphabet has high Shannon entropy, while identifiers, words and
paths do not.

To keep false positives low the detector only considers tokens that appear in
a value position (quoted, or right after ``=`` / ``:``), and applies several
shape filters before comparing entropy against a length-aware threshold.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterator

# A run of base64 / base64url characters, optionally followed by padding.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# Words on a line that indicate a hex string is a digest, not a secret.
_HASH_CONTEXT_RE = re.compile(
    r"(?i)sha\d*|md5|hash|checksum|digest|integrity|commit|revision|\brev\b|\bgit|etag|fingerprint|uuid|guid"
)
# The token must follow an assignment / key separator or an opening quote.
# Comparison and compound operators (==, !=, -=, ::) do not count.
_VALUE_PREFIX_RE = re.compile(r"""(?:(?<![=!<>+\-*/%&|^:])=|(?<!:):|=>|:=)\s*["'`]?$|["'`]$""")


_PIECE_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")


def mean_piece_length(token: str) -> float:
    """Average length of the camelCase / snake_case / digit pieces of ``token``.

    Identifiers and paths split into real words (``size|End|Cent|Dir|64|Locator``,
    ``Modules|xxlimited|35``) and average well over 3 characters per piece.
    Random strings flip between digits, lower and upper case constantly and
    average under 2.
    """
    pieces = _PIECE_RE.findall(token)
    return sum(map(len, pieces)) / len(pieces) if pieces else 0.0


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy of ``data`` in bits per character.

    ``"aaaa"`` has entropy 0.0; a string of 64 distinct characters has 6.0.
    """
    if not data:
        return 0.0
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in Counter(data).values())


@dataclass(frozen=True)
class EntropySettings:
    """Tunable thresholds for the entropy detector.

    Attributes:
        enabled: Turn entropy detection on or off.
        base64_threshold: Entropy (bits/char) a long base64-like token must reach.
        hex_threshold: Entropy a hex token must reach.
        min_length: Minimum token length considered at all.
        max_length: Tokens longer than this (embedded blobs) are ignored.
    """

    enabled: bool = True
    base64_threshold: float = 4.5
    hex_threshold: float = 3.0
    min_length: int = 20
    max_length: int = 256


@dataclass(frozen=True)
class EntropyCandidate:
    """A token that passed the entropy check."""

    token: str
    start: int
    end: int
    entropy: float
    kind: str  # "base64" or "hex"


def _base64_threshold(length: int, ceiling: float) -> float:
    """Length-aware threshold for base64-like tokens.

    Short random strings cannot reach high entropy simply because they do not
    contain enough distinct characters (a 20-char string tops out at
    log2(20) ~= 4.32). The configured threshold therefore applies in full to
    tokens of 40+ characters and is scaled down by log2(length) / log2(40)
    for shorter ones, keeping short random tokens detectable without lowering
    the bar for long ones.
    """
    return ceiling * min(1.0, math.log2(length) / math.log2(40))


_BLOB_LINE_RE = re.compile(r"""^\s*["'`]?[A-Za-z0-9+/_\-]{40,}={0,2}["'`]?[,;+\\]?\s*$""")


def _in_blob(text: str, line_start: int, line_end: int) -> bool:
    """True when a neighbouring line is also a bare base64 run.

    Embedded images, fonts and certificates are stored as many consecutive
    lines of base64; individually each line looks like a random secret.
    """
    prev_end = line_start - 1
    if prev_end > 0:
        prev_start = text.rfind("\n", 0, prev_end) + 1
        if _BLOB_LINE_RE.match(text[prev_start:prev_end]):
            return True
    if line_end < len(text):
        next_end = text.find("\n", line_end + 1)
        next_line = text[line_end + 1 : len(text) if next_end == -1 else next_end]
        if _BLOB_LINE_RE.match(next_line):
            return True
    return False


def _line_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    return line_start, (len(text) if line_end == -1 else line_end)


def iter_candidates(text: str, settings: EntropySettings) -> Iterator[EntropyCandidate]:
    """Yield high-entropy tokens found in ``text``.

    Filters applied, in order:
      * token length within ``[min_length, max_length]``;
      * token sits in a value position (quoted, or after ``=``/``:``);
      * not part of a data URI or a multi-line embedded base64 blob;
      * not a UUID;
      * mixed character classes (digits + letters, and both cases for base64);
      * not made of words (identifiers, paths), measured by the average
        camelCase piece length;
      * hex tokens on lines that talk about hashes/commits are skipped, as are
        base64 tokens right after such a word (``sha256=...``);
      * entropy above the (length-aware) threshold.
    """
    if not settings.enabled:
        return
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0)
        start, end = match.span()
        if not settings.min_length <= len(token) <= settings.max_length:
            continue
        line_start, line_end = _line_bounds(text, start, end)
        prefix = text[line_start:start]
        if not _VALUE_PREFIX_RE.search(prefix):
            continue
        line = text[line_start:line_end]
        if "base64," in line or "data:" in line:
            continue
        if _UUID_RE.match(token):
            continue

        if _HEX_RE.fullmatch(token):
            context = text[max(0, line_start - 120):line_end]  # include the previous line or two
            if len(token) < 32 or _HASH_CONTEXT_RE.search(context):
                continue
            if not (re.search(r"[0-9]", token) and re.search(r"[a-fA-F]", token)):
                continue
            entropy = shannon_entropy(token)
            if entropy >= settings.hex_threshold:
                yield EntropyCandidate(token, start, end, entropy, "hex")
            continue

        if not (re.search(r"[0-9]", token) and re.search(r"[a-z]", token) and re.search(r"[A-Z]", token)):
            continue
        if mean_piece_length(token) >= 3.0:
            continue
        if _HASH_CONTEXT_RE.search(prefix[-40:]):  # "sha256=...", "integrity": "..."
            continue
        if len(token) >= 40 and _in_blob(text, line_start, line_end):
            continue
        entropy = shannon_entropy(token)
        if entropy >= _base64_threshold(len(token), settings.base64_threshold):
            yield EntropyCandidate(token, start, end, entropy, "base64")
