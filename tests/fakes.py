"""Deterministic fake secrets for tests.

Secrets are *generated* at test time rather than committed, so this
repository never contains strings that look like live credentials (which
would trip push protection and make `leakhound scan .` noisy). Every value
is random garbage that merely has the right *shape* for its rule.

Fixture templates under ``tests/fixtures/leaky_project`` reference these
values as ``{{NAME}}`` placeholders; :func:`render_fixture` fills them in.
"""

from __future__ import annotations

import base64
import json
import random
import re
import shutil
import string
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
_PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")

_rng = random.Random(1337)
ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"
B64URL = ALNUM + "-_"
HEX = "0123456789abcdef"


def rand(alphabet: str, length: int) -> str:
    """Random string that uses every character class (digit/lower/upper) its alphabet offers."""
    classes = [set(c) for c in (string.digits, string.ascii_lowercase, string.ascii_uppercase) if set(c) & set(alphabet)]
    while True:
        value = "".join(_rng.choice(alphabet) for _ in range(length))
        if length < 8 or all(cls & set(value) for cls in classes):
            return value


def _b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def _private_key() -> str:
    body = "\n".join(rand(B64, 64) for _ in range(12))
    kind = "RSA " + "PRIVATE KEY"
    return f"-----BEGIN {kind}-----\n{body}\n{rand(B64, 24)}==\n-----END {kind}-----"


def _jwt() -> str:
    header = _b64url({"alg": "HS256", "typ": "JWT"})
    payload = _b64url({"sub": "1234567890", "name": "svc-deploy", "iat": 1700000000})
    return f"{header}.{payload}.{rand(B64URL, 43)}"


FAKE: dict[str, str] = {
    "AWS_ACCESS_KEY_ID": "AKIA" + rand(string.ascii_uppercase + "234567", 16),
    "AWS_SECRET_ACCESS_KEY": rand(B64, 40),
    "GITHUB_TOKEN": "ghp" + "_" + rand(ALNUM, 36),
    "GITHUB_FINE_GRAINED": "github" + "_pat_" + rand(ALNUM + "_", 82),
    "GITLAB_TOKEN": "glpat" + "-" + rand(ALNUM, 20),
    "GOOGLE_API_KEY": "AIza" + rand(ALNUM, 35),
    "SLACK_BOT_TOKEN": "xoxb" + "-" + rand(string.digits, 11) + "-" + rand(string.digits, 12) + "-" + rand(ALNUM, 24),
    "SLACK_WEBHOOK": "https://hooks.slack.com/services/T" + rand(string.ascii_uppercase + string.digits, 8)
    + "/B" + rand(string.ascii_uppercase + string.digits, 8) + "/" + rand(ALNUM, 24),
    "STRIPE_LIVE_KEY": "sk_" + "live_" + rand(ALNUM, 24),
    "STRIPE_TEST_KEY": "sk_" + "test_" + rand(ALNUM, 24),
    "SENDGRID_KEY": "SG." + rand(ALNUM, 22) + "." + rand(ALNUM, 43),
    "NPM_TOKEN": "npm" + "_" + rand(ALNUM, 36),
    "OPENAI_KEY": "sk-proj-" + rand(ALNUM, 40) + "T3Blbk" + "FJ" + rand(ALNUM, 40),
    "HF_TOKEN": "hf" + "_" + rand(string.ascii_letters, 34),
    "DO_TOKEN": "dop" + "_v1_" + rand(HEX, 64),
    "VAULT_TOKEN": "hvs" + "." + rand(ALNUM, 90),
    "TELEGRAM_TOKEN": rand(string.digits, 10) + ":AA" + rand(ALNUM, 33),
    "AZURE_ACCOUNT_KEY": rand(B64, 86) + "==",
    "PRIVATE_KEY": _private_key(),
    "JWT": _jwt(),
    "DB_PASSWORD": rand(ALNUM, 18),
    "API_KEY": rand(ALNUM, 32),
    "DSN_PASSWORD": rand(ALNUM, 16),
    "SESSION_SALT": rand(ALNUM, 40),
    "HMAC_HEX": rand(HEX, 64),
}


def render(text: str) -> str:
    """Replace ``{{NAME}}`` placeholders with fake secrets."""
    return _PLACEHOLDER_RE.sub(lambda m: FAKE[m.group(1)], text)


def render_fixture(name: str, dest: Path) -> Path:
    """Copy fixture ``name`` to ``dest`` with all placeholders filled in."""
    src = FIXTURES / name
    shutil.copytree(src, dest)
    for path in dest.rglob("*"):
        if path.is_file():
            try:
                original = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue  # binary fixture, copied as-is
            rendered = render(original)
            if rendered != original:
                path.write_text(rendered, encoding="utf-8")
    return dest
