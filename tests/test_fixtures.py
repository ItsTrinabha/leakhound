"""End-to-end: the planted secrets are all found, at the right place, and the
clean project produces nothing."""

from pathlib import Path

from fakes import FIXTURES, FAKE
from leakhound import Settings, scan_path

# (rule id, file, placeholder name planted in that file)
EXPECTED = [
    ("generic-secret", ".env", "DB_PASSWORD"),
    ("slack-token", ".env", "SLACK_BOT_TOKEN"),
    ("sendgrid-api-key", ".env", "SENDGRID_KEY"),
    ("openai-api-key", ".env", "OPENAI_KEY"),
    ("stripe-test-key", ".env", "STRIPE_TEST_KEY"),
    ("aws-access-key-id", "config/settings.py", "AWS_ACCESS_KEY_ID"),
    ("aws-secret-access-key", "config/settings.py", "AWS_SECRET_ACCESS_KEY"),
    ("github-token", "config/settings.py", "GITHUB_TOKEN"),
    ("stripe-live-key", "config/settings.py", "STRIPE_LIVE_KEY"),
    ("generic-secret", "config/settings.py", "API_KEY"),
    ("credentials-in-url", "config/settings.py", "DSN_PASSWORD"),
    ("high-entropy-string", "config/settings.py", "SESSION_SALT"),
    ("npm-token", "deploy/ci.yml", "NPM_TOKEN"),
    ("gitlab-pat", "deploy/ci.yml", "GITLAB_TOKEN"),
    ("github-fine-grained-pat", "deploy/ci.yml", "GITHUB_FINE_GRAINED"),
    ("slack-webhook-url", "deploy/ci.yml", "SLACK_WEBHOOK"),
    ("private-key", "deploy/id_rsa", "PRIVATE_KEY"),
    ("google-api-key", "src/client.js", "GOOGLE_API_KEY"),
    ("jwt", "src/client.js", "JWT"),
    ("huggingface-token", "src/integrations.yaml", "HF_TOKEN"),
    ("digitalocean-token", "src/integrations.yaml", "DO_TOKEN"),
    ("hashicorp-vault-token", "src/integrations.yaml", "VAULT_TOKEN"),
    ("telegram-bot-token", "src/integrations.yaml", "TELEGRAM_TOKEN"),
    ("azure-storage-account-key", "src/integrations.yaml", "AZURE_ACCOUNT_KEY"),
    ("high-entropy-hex", "src/integrations.yaml", "HMAC_HEX"),
]


def _template_line(rel: str, placeholder: str) -> int:
    lines = (FIXTURES / "leaky_project" / rel).read_text().splitlines()
    for number, line in enumerate(lines, start=1):
        if "{{" + placeholder + "}}" in line and "leakhound:allow" not in line:
            return number
    raise AssertionError(f"{placeholder} not planted in {rel}")


def test_every_planted_secret_is_found_exactly_once(leaky_dir: Path):
    result = scan_path(leaky_dir, Settings())
    got = sorted((f.rule_id, f.path, f.line, f.secret) for f in result.findings)
    want = sorted((rule, rel, _template_line(rel, ph), FAKE[ph]) for rule, rel, ph in EXPECTED)
    assert got == want


def test_leaky_project_suppressions_hold(leaky_dir: Path):
    result = scan_path(leaky_dir, Settings())
    texts = {f.line_text for f in result.findings}
    assert not any("leakhound:allow" in t or "changeme" in t or "os.environ" in t for t in texts)


def test_clean_project_has_no_findings(clean_dir: Path):
    result = scan_path(clean_dir, Settings())
    assert result.findings == []
    # binary files and lock files were skipped, the rest scanned
    assert result.stats.files_scanned == 3
    assert result.stats.files_skipped == 3


def test_fixture_templates_themselves_scan_clean():
    """The committed templates only contain {{PLACEHOLDERS}}, never secrets."""
    assert scan_path(FIXTURES, Settings()).findings == []
