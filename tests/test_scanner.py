from pathlib import Path

import pytest

from fakes import FAKE
from leakhound import Settings, Severity, scan_path
from leakhound.config import ConfigError, is_test_path, load_settings, settings_from_dict
from leakhound.scanner import ScanError


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def rule_ids(result):
    return [f.rule_id for f in result.findings]


def test_scan_single_file(tmp_path):
    write(tmp_path, "one.py", f"t = '{FAKE['GITHUB_TOKEN']}'\n")
    result = scan_path(tmp_path / "one.py", Settings())
    assert [(f.rule_id, f.path) for f in result.findings] == [("github-token", "one.py")]


def test_missing_path_raises(tmp_path):
    with pytest.raises(ScanError):
        scan_path(tmp_path / "nope", Settings())


def test_default_ignored_directories_are_pruned(tmp_path):
    write(tmp_path, "node_modules/pkg/index.js", f"k='{FAKE['GITHUB_TOKEN']}'")
    write(tmp_path, ".venv/lib/x.py", f"k='{FAKE['GITHUB_TOKEN']}'")
    write(tmp_path, "app.min.js", f"k='{FAKE['GITHUB_TOKEN']}'")
    assert scan_path(tmp_path, Settings()).findings == []


def test_large_files_are_skipped(tmp_path):
    write(tmp_path, "big.txt", "x" * 2000 + FAKE["GITHUB_TOKEN"])
    settings = Settings(max_file_size=1000)
    result = scan_path(tmp_path, settings)
    assert result.findings == [] and result.stats.files_skipped == 1


def test_binary_files_are_skipped(tmp_path):
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01" + FAKE["GITHUB_TOKEN"].encode())
    assert scan_path(tmp_path, Settings()).findings == []


def test_test_paths_are_downgraded_and_tagged(tmp_path):
    write(tmp_path, "tests/test_api.py", f"k = '{FAKE['GITHUB_TOKEN']}'")
    (finding,) = scan_path(tmp_path, Settings()).findings
    assert finding.severity is Severity.HIGH  # critical -> high
    assert "test-path" in finding.tags


def test_test_paths_can_be_excluded(tmp_path):
    write(tmp_path, "tests/test_api.py", f"k = '{FAKE['GITHUB_TOKEN']}'")
    result = scan_path(tmp_path, Settings(exclude_tests=True))
    assert result.findings == [] and result.suppressed == 1


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_x.py", True), ("pkg/__tests__/a.js", True), ("src/a.spec.ts", True),
        ("internal/foo_test.go", True), ("spec/models/user_spec.rb", True), ("testdata/k.pem", True),
        ("src/app.py", False), ("src/contest.py", False), ("latest/config.yml", False),
    ],
)
def test_is_test_path(path, expected):
    assert is_test_path(path) is expected


def test_config_file_allowlists_and_custom_rules(tmp_path):
    write(tmp_path, ".leakhound.toml", """
[scan]
disabled_rules = ["jwt", "high-entropy-string"]

[allowlist]
paths = ["docs/*"]
regexes = ["^sk_test_"]

[[rules]]
id = "acme-key"
name = "ACME Key"
regex = "acme_[a-z0-9]{24}"
severity = "critical"
keywords = ["acme_"]
""")
    write(tmp_path, "docs/guide.md", FAKE["GITHUB_TOKEN"])
    write(tmp_path, "app.py", "\n".join([
        f"stripe = '{FAKE['STRIPE_TEST_KEY']}'",
        f"jwt = '{FAKE['JWT']}'",
        "acme = 'acme_" + "k3j5h6g7f8d9s0a1q2w3e4r5'",
    ]))
    settings = load_settings(tmp_path)
    result = scan_path(tmp_path, settings)
    assert rule_ids(result) == ["acme-key"]
    assert result.findings[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    "data",
    [
        {"bogus": {}},
        {"scan": {"nope": 1}},
        {"scan": {"max_file_size": "big"}},
        {"scan": {"disabled_rules": ["no-such-rule"]}},
        {"allowlist": {"regexes": ["("]}},
        {"rules": [{"id": "x"}]},
        {"rules": [{"id": "x", "regex": "a", "severity": "apocalyptic"}]},
        {"rules": [{"id": "github-token", "regex": "a"}]},
    ],
)
def test_invalid_config_is_rejected(data):
    with pytest.raises(ConfigError):
        settings_from_dict(data)


def test_missing_explicit_config_is_an_error(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(tmp_path, tmp_path / "missing.toml")


def test_baseline_fingerprints_suppress_known_findings(tmp_path):
    write(tmp_path, "a.py", f"k = '{FAKE['GITHUB_TOKEN']}'")
    first = scan_path(tmp_path, Settings())
    settings = Settings()
    settings.allowlist.fingerprints = {f.fingerprint for f in first.findings}
    # moving the secret to another line keeps the same fingerprint
    write(tmp_path, "a.py", f"\n\n# moved\nk = '{FAKE['GITHUB_TOKEN']}'")
    second = scan_path(tmp_path, settings)
    assert second.findings == [] and second.suppressed == 1


def test_gitignore_is_respected_in_git_worktrees(git_repo):
    git_repo.write(".gitignore", "local.env\n")
    git_repo.write("local.env", f"T={FAKE['GITHUB_TOKEN']}\n")
    git_repo.write("app.py", "print('hi')\n")
    assert scan_path(git_repo.path, Settings()).findings == []
    unfiltered = scan_path(git_repo.path, Settings(), use_gitignore=False)
    assert rule_ids(unfiltered) == ["github-token"]
