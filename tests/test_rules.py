"""Every built-in rule fires on a realistic fake and stays quiet on near-misses."""

import pytest

from fakes import FAKE
from leakhound.config import Settings
from leakhound.detector import Detector
from leakhound.rules import BUILTIN_RULES, plausible_password, valid_jwt, valid_private_key


def detect(text, path="file.txt"):
    return Detector(Settings()).scan_text(text, path)


POSITIVE = [
    ("private-key", FAKE["PRIVATE_KEY"]),
    ("aws-access-key-id", f"key = {FAKE['AWS_ACCESS_KEY_ID']}"),
    ("aws-secret-access-key", f"aws_secret_access_key = {FAKE['AWS_SECRET_ACCESS_KEY']}"),
    ("github-token", f"token: {FAKE['GITHUB_TOKEN']}"),
    ("github-fine-grained-pat", FAKE["GITHUB_FINE_GRAINED"]),
    ("gitlab-pat", FAKE["GITLAB_TOKEN"]),
    ("google-api-key", FAKE["GOOGLE_API_KEY"]),
    ("slack-token", FAKE["SLACK_BOT_TOKEN"]),
    ("slack-webhook-url", FAKE["SLACK_WEBHOOK"]),
    ("stripe-live-key", FAKE["STRIPE_LIVE_KEY"]),
    ("stripe-test-key", FAKE["STRIPE_TEST_KEY"]),
    ("sendgrid-api-key", FAKE["SENDGRID_KEY"]),
    ("npm-token", FAKE["NPM_TOKEN"]),
    ("openai-api-key", FAKE["OPENAI_KEY"]),
    ("huggingface-token", FAKE["HF_TOKEN"]),
    ("digitalocean-token", FAKE["DO_TOKEN"]),
    ("hashicorp-vault-token", FAKE["VAULT_TOKEN"]),
    ("telegram-bot-token", FAKE["TELEGRAM_TOKEN"]),
    ("azure-storage-account-key", f"AccountName=x;AccountKey={FAKE['AZURE_ACCOUNT_KEY']};"),
    ("jwt", FAKE["JWT"]),
    ("credentials-in-url", f"mysql://root:{FAKE['DSN_PASSWORD']}@10.0.0.5:3306/db"),
    ("generic-secret", f'client_secret = "{FAKE["API_KEY"]}"'),
    ("generic-secret", f'{{"password": "{FAKE["DB_PASSWORD"]}"}}'),
    ("generic-secret", f"export DB_PASSWORD={FAKE['DB_PASSWORD']}"),
]


@pytest.mark.parametrize(("rule_id", "text"), POSITIVE, ids=[f"{r}-{i}" for i, (r, _) in enumerate(POSITIVE)])
def test_rule_detects_fake_secret(rule_id, text):
    findings = detect(text)
    assert [f.rule_id for f in findings] == [rule_id]


NEGATIVE = [
    "AKIAIOSFODNN7EXAMPLE",  # AWS's documented example key
    "ghp_your_token_here",
    "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx",
    "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----",
    "eyJhbGciOi.eyJzdWIiOi.notreallyajwt",  # JWT-shaped but undecodable
    "postgres://user:password@localhost/db",
    "postgres://app:${DB_PASS}@db/app",
    "https://example.com/path?q=1",
    'password = os.environ["DB_PASSWORD"]',
    'password = "changeme123"',
    'secret_file = "config/secrets.yaml"',
    'TOKEN_HEADER = "X-Auth-Token"',
    "api_key: <your-api-key-here>",
    "API_KEY=${API_KEY}",
    "token: {{ vault_token }}",
    "SECRET_NAME=DATABASE_PASSWORD",
]


@pytest.mark.parametrize("text", NEGATIVE)
def test_near_misses_are_not_reported(text):
    assert detect(text) == []


def test_rule_ids_are_unique_and_keywords_lowercase():
    ids = [r.id for r in BUILTIN_RULES]
    assert len(ids) == len(set(ids))
    for rule in BUILTIN_RULES:
        assert all(k == k.lower() for k in rule.keywords), rule.id


def test_validators():
    assert valid_jwt(FAKE["JWT"])
    assert not valid_jwt("a.b.c")
    assert valid_private_key(FAKE["PRIVATE_KEY"])
    assert not valid_private_key("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")
    assert plausible_password("Tr0ub4dor&3xyz")
    assert not plausible_password("https://host/x")
    assert not plausible_password("keys/server.pem")


def test_escaped_private_key_in_json_is_detected():
    key = FAKE["PRIVATE_KEY"].replace("\n", "\\n")
    findings = detect(f'{{"type": "service_account", "private_key": "{key}"}}', "sa.json")
    assert [f.rule_id for f in findings] == ["private-key"]


def test_positions_are_one_based_and_exact():
    token = FAKE["GITHUB_TOKEN"]
    (finding,) = detect(f"line one\n  TOKEN = '{token}'\n")
    assert (finding.line, finding.column) == (2, 12)
    assert finding.end_column == 12 + len(token)
    assert finding.secret == token


@pytest.mark.parametrize(
    "text",
    [
        "password = '" + "aA" * 50_000,  # unterminated quote
        "secret: " + "Ab-" * 30_000,
        "x" * 100_000 + "-----BEGIN PRIVATE KEY-----" + "A" * 100_000,
        "postgres://" + "a" * 100_000,
        "token = " + "self.tok[" * 10_000,
        "aB3" * 50_000,
    ],
    ids=["unterminated-quote", "dash-words", "unterminated-pem", "long-url", "nested-index", "long-run"],
)
def test_pathological_input_scans_fast(text):
    """Guards against catastrophic regex backtracking (ReDoS) in any rule."""
    import time

    started = time.perf_counter()
    detect(text)
    assert time.perf_counter() - started < 2.0
