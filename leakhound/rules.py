"""Built-in detection rules.

Each :class:`Rule` couples a regular expression with metadata and optional
post-match checks (minimum entropy, a validator function). Rules declare
lower-case ``keywords``; a rule only runs on text containing one of them,
which keeps scanning fast even with many rules.

When a pattern has capture groups, the first group that participated in the
match is the secret; otherwise the whole match is.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import Severity

Validator = Callable[[str], bool]


@dataclass(frozen=True)
class Rule:
    """A named secret-detection rule.

    Attributes:
        id: Stable kebab-case identifier, used in output, config and SARIF.
        name: Short human readable name.
        description: What was found and why it matters.
        severity: Default severity of a finding.
        regex: Compiled pattern, or ``None`` for detectors implemented in code
            (the entropy detectors).
        keywords: Lower-case substrings; the rule is skipped when none occur.
        min_entropy: Discard matches whose secret is less random than this.
        validator: Optional extra check on the extracted secret.
        tags: Free-form labels for reporting.
    """

    id: str
    name: str
    description: str
    severity: Severity
    regex: Optional[re.Pattern] = None
    keywords: tuple[str, ...] = ()
    min_entropy: float = 0.0
    validator: Optional[Validator] = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    def extract(self, match: re.Match) -> tuple[str, int, int]:
        """Return ``(secret, start, end)`` for a regex match."""
        for index in range(1, (match.re.groups or 0) + 1):
            if match.group(index) is not None:
                return match.group(index), match.start(index), match.end(index)
        return match.group(0), match.start(), match.end()

    def applies_to(self, lowered_text: str) -> bool:
        """Cheap keyword pre-filter. ``lowered_text`` must be lower-cased."""
        return not self.keywords or any(k in lowered_text for k in self.keywords)


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #


def _b64url_json(segment: str) -> Optional[dict]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        value = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def valid_jwt(token: str) -> bool:
    """A JWT is only reported when its header decodes to JSON with ``alg``."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header = _b64url_json(parts[0])
    return header is not None and "alg" in header and _b64url_json(parts[1]) is not None


_PEM_BODY_RE = re.compile(r"-----BEGIN[^-]*-----(.*?)-----END", re.S)


def valid_private_key(block: str) -> bool:
    """Require a real-looking base64 body (rejects ``...`` placeholders)."""
    match = _PEM_BODY_RE.search(block)
    if not match:
        return False
    body = match.group(1).replace("\\n", "\n").replace("\\r", "")
    # Drop PEM headers such as "Proc-Type: 4,ENCRYPTED" before measuring the body.
    body = "".join(line.strip() for line in body.splitlines() if ":" not in line)
    return "..." not in body and len(re.findall(r"[A-Za-z0-9+/=]", body)) >= 32


_WORDS_RE = re.compile(r"[A-Za-z]+(?:[-_.#/][A-Za-z]+)*")  # letters and separators only
_FILE_LIKE_RE = re.compile(r"\.(txt|json|pem|key|ya?ml|env|cfg|ini|conf|crt|cer|p12|pfx|toml|xml)$", re.I)


def plausible_password(value: str) -> bool:
    """Heuristics for generic ``password = "..."`` style assignments.

    Rejects values that are clearly not literal secrets: URLs, file names,
    variable references, function calls, code expressions, plain lower-case words,
    UPPER_CASE constant names and values made only of words (``X-Auth-Token``).
    """
    if "://" in value or "(" in value or value[0] in "$%@&*":
        return False
    # Code expressions: indexing (token[0]), attribute chains (self.tokenizer), trailing comma.
    if re.search(r"\w\[|\]$|,$", value) or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", value):
        return False
    if re.fullmatch(r"[A-Z_.\-]+", value):  # CONSTANT_NAME
        return False
    if _FILE_LIKE_RE.search(value):
        return False
    if _WORDS_RE.fullmatch(value):  # "AnyHttpUrl", "module-secrets#docs"
        return False
    return True


_PLACEHOLDER_PASSWORDS = frozenset(
    {"password", "passwd", "pass", "pwd", "secret", "changeme", "admin", "root", "user", "test", "guest", "pass123"}
)


def url_password(value: str) -> bool:
    """Reject template variables and well-known placeholder passwords in URLs."""
    return value.lower() not in _PLACEHOLDER_PASSWORDS and value[0] not in "${%<*"


# --------------------------------------------------------------------------- #
# Rule table
# --------------------------------------------------------------------------- #

_C, _H, _M, _L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
# Characters that may not directly follow a token for it to be a whole token.
_END = r"(?![A-Za-z0-9_\-])"


def _rule(
    rule_id: str,
    name: str,
    description: str,
    pattern: str,
    severity: Severity,
    keywords: tuple[str, ...],
    **kwargs,
) -> Rule:
    return Rule(
        id=rule_id,
        name=name,
        description=description,
        severity=severity,
        regex=re.compile(pattern),
        keywords=tuple(k.lower() for k in keywords),
        **kwargs,
    )


BUILTIN_RULES: tuple[Rule, ...] = (
    _rule(
        "private-key", "Private Key",
        "A PEM/OpenSSH private key block. Anyone holding it can impersonate the key owner.",
        r"(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{32,}?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----)",
        _C, ("private key",), validator=valid_private_key, tags=("key",),
    ),
    _rule(
        "aws-access-key-id", "AWS Access Key ID",
        "An AWS access key ID. Usually leaked together with its secret access key.",
        r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b",
        _H, ("akia", "asia", "abia", "acca"), tags=("aws", "cloud"),
    ),
    _rule(
        "aws-secret-access-key", "AWS Secret Access Key",
        "An AWS secret access key assigned to an AWS-named variable.",
        r"(?i)(?<![a-z0-9])aws_?(?:secret)?_?(?:access)?_?key[\"']?\s*(?:=|:=|:|=>)\s*[\"']?([a-z0-9/+]{40})(?![a-z0-9/+=])",
        _C, ("aws",), min_entropy=3.5, tags=("aws", "cloud"),
    ),
    _rule(
        "github-token", "GitHub Token",
        "A GitHub personal access, OAuth, user-to-server, server-to-server or refresh token.",
        r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b",
        _C, ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), tags=("github", "vcs"),
    ),
    _rule(
        "github-fine-grained-pat", "GitHub Fine-Grained Token",
        "A GitHub fine-grained personal access token.",
        r"\b(github_pat_[A-Za-z0-9_]{82})\b",
        _C, ("github_pat_",), tags=("github", "vcs"),
    ),
    _rule(
        "gitlab-pat", "GitLab Personal Access Token",
        "A GitLab personal access token.",
        r"\b(glpat-[A-Za-z0-9_\-]{20,})" + _END,
        _C, ("glpat-",), tags=("gitlab", "vcs"),
    ),
    _rule(
        "google-api-key", "Google API Key",
        "A Google Cloud / Firebase / Maps API key.",
        r"\b(AIza[0-9A-Za-z_\-]{35})" + _END,
        _H, ("aiza",), tags=("google", "cloud"),
    ),
    _rule(
        "google-oauth-client-secret", "Google OAuth Client Secret",
        "A Google OAuth 2.0 client secret.",
        r"\b(GOCSPX-[A-Za-z0-9_\-]{28})" + _END,
        _H, ("gocspx-",), tags=("google", "oauth"),
    ),
    _rule(
        "slack-token", "Slack Token",
        "A Slack bot, user, app or workspace token.",
        r"\b(xox[abposre]-[0-9]{8,14}-[0-9A-Za-z\-]{10,120})" + _END,
        _H, ("xox",), tags=("slack", "chat"),
    ),
    _rule(
        "slack-webhook-url", "Slack Webhook URL",
        "A Slack incoming-webhook URL; anyone can post to the channel with it.",
        r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,32})",
        _M, ("hooks.slack.com",), tags=("slack", "webhook"),
    ),
    _rule(
        "stripe-live-key", "Stripe Live Secret Key",
        "A Stripe live-mode secret or restricted key with access to real payments.",
        r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,99})\b",
        _C, ("_live_",), tags=("stripe", "payments"),
    ),
    _rule(
        "stripe-test-key", "Stripe Test Secret Key",
        "A Stripe test-mode secret key. Low impact, but signals keys are kept in code.",
        r"\b((?:sk|rk)_test_[0-9A-Za-z]{24,99})\b",
        _L, ("_test_",), tags=("stripe", "payments"),
    ),
    _rule(
        "twilio-api-key", "Twilio API Key",
        "A Twilio API key SID.",
        r"\b(SK[0-9a-fA-F]{32})\b",
        _H, ("sk",), min_entropy=3.0, tags=("twilio",),
    ),
    _rule(
        "sendgrid-api-key", "SendGrid API Key",
        "A SendGrid API key that can send email as your domain.",
        r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})" + _END,
        _H, ("sg.",), tags=("sendgrid", "email"),
    ),
    _rule(
        "npm-token", "npm Access Token",
        "An npm access token that can publish packages.",
        r"\b(npm_[A-Za-z0-9]{36})\b",
        _H, ("npm_",), tags=("npm", "supply-chain"),
    ),
    _rule(
        "pypi-token", "PyPI API Token",
        "A PyPI upload token that can publish packages.",
        r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})" + _END,
        _H, ("pypi-ageichlwas5vcmc",), tags=("pypi", "supply-chain"),
    ),
    _rule(
        "openai-api-key", "OpenAI API Key",
        "An OpenAI API key.",
        r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,200}T3BlbkFJ[A-Za-z0-9_\-]{20,200})" + _END,
        _H, ("t3blbkfj",), tags=("ai",),
    ),
    _rule(
        "anthropic-api-key", "Anthropic API Key",
        "An Anthropic API key.",
        r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,120})" + _END,
        _H, ("sk-ant-",), tags=("ai",),
    ),
    _rule(
        "huggingface-token", "Hugging Face Token",
        "A Hugging Face access token.",
        r"\b(hf_[A-Za-z]{34})\b",
        _H, ("hf_",), min_entropy=3.5, tags=("ai",),
    ),
    _rule(
        "shopify-token", "Shopify Access Token",
        "A Shopify app, custom app or private app access token.",
        r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b",
        _H, ("shpat_", "shpca_", "shppa_", "shpss_"), tags=("shopify",),
    ),
    _rule(
        "digitalocean-token", "DigitalOcean Token",
        "A DigitalOcean personal access, OAuth or refresh token.",
        r"\b(do[opr]_v1_[a-f0-9]{64})\b",
        _H, ("_v1_",), tags=("digitalocean", "cloud"),
    ),
    _rule(
        "hashicorp-vault-token", "HashiCorp Vault Token",
        "A HashiCorp Vault service, batch or recovery token.",
        r"\b(hv[sbr]\.[A-Za-z0-9_\-]{24,})" + _END,
        _C, ("hvs.", "hvb.", "hvr."), min_entropy=3.5, tags=("vault",),
    ),
    _rule(
        "azure-storage-account-key", "Azure Storage Account Key",
        "An Azure Storage account key inside a connection string.",
        r"AccountKey=([A-Za-z0-9+/]{86}==)",
        _C, ("accountkey=",), tags=("azure", "cloud"),
    ),
    _rule(
        "databricks-token", "Databricks Token",
        "A Databricks personal access token.",
        r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b",
        _H, ("dapi",), tags=("databricks",),
    ),
    _rule(
        "telegram-bot-token", "Telegram Bot Token",
        "A Telegram bot API token.",
        r"\b([0-9]{8,10}:AA[0-9A-Za-z_\-]{33})" + _END,
        _M, (":aa",), tags=("telegram", "chat"),
    ),
    _rule(
        "discord-webhook-url", "Discord Webhook URL",
        "A Discord webhook URL; anyone can post to the channel with it.",
        r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,72})",
        _M, ("discord",), tags=("discord", "webhook"),
    ),
    _rule(
        "jwt", "JSON Web Token",
        "A signed JSON Web Token. It may grant access until it expires.",
        r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})" + _END,
        _M, ("eyj",), validator=valid_jwt, tags=("token",),
    ),
    _rule(
        "credentials-in-url", "Credentials in URL",
        "A URL with an embedded username and password (e.g. a database DSN).",
        r"\b[A-Za-z][A-Za-z0-9+.\-]{1,20}://[^\s:/?#@'\"`]{1,128}:([^\s:/?#@'\"`]{3,128})@[A-Za-z0-9.\-\[\]]+",
        _H, ("://",), validator=url_password, tags=("url",),
    ),
    _rule(
        "generic-secret", "Generic Secret Assignment",
        "A literal value assigned to a variable or key named like a password, secret, token or API key.",
        # 1) quoted assignment in code:      api_key = "..."   /  "password": "..."
        # 2) unquoted .env / YAML / INI line: DB_PASSWORD=...  /  secret: ...
        r"(?im)(?:password|passwd|pwd|secret|api[_.\-]?key|apikey|access[_.\-]?token|auth[_.\-]?token|client[_.\-]?secret|token)"
        r"[a-z0-9_.\-]*[\"']?\s*(?:=|:=|:|=>)\s*[\"']([^\"'\s]{8,200})[\"']"
        r"|^[ \t]*(?:export[ \t]+)?[a-z0-9_.\-]*(?:password|passwd|secret|api[_.\-]?key|token)[a-z0-9_.\-]*[ \t]*[=:][ \t]*([^\s\"'#]{8,200})[ \t]*$",
        _M, ("pass", "pwd", "secret", "key", "token"), min_entropy=3.0, validator=plausible_password,
        tags=("generic",),
    ),
)

# Entropy "rules" have no regex; they are metadata for findings produced by
# :mod:`leakhound.entropy` so reporters can treat every finding uniformly.
ENTROPY_BASE64_RULE = Rule(
    id="high-entropy-string",
    name="High-Entropy String",
    description="A long, highly random base64-like value in an assignment; likely a secret without a known format.",
    severity=Severity.MEDIUM,
    tags=("entropy", "generic"),
)
ENTROPY_HEX_RULE = Rule(
    id="high-entropy-hex",
    name="High-Entropy Hex String",
    description="A long, random hexadecimal value in an assignment; may be a key or token.",
    severity=Severity.LOW,
    tags=("entropy", "generic"),
)


def all_rule_metadata(rules: tuple[Rule, ...] | list[Rule] = BUILTIN_RULES) -> list[Rule]:
    """Every rule that can produce a finding, including the entropy detectors."""
    return [*rules, ENTROPY_BASE64_RULE, ENTROPY_HEX_RULE]
