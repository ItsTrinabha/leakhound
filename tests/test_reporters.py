import json

from fakes import FAKE
from leakhound import Settings, scan_git, scan_path
from leakhound.reporters import console, json_report, sarif
from leakhound.rules import all_rule_metadata


def test_json_report_structure_and_redaction(leaky_dir):
    result = scan_path(leaky_dir, Settings())
    doc = json.loads(json_report.render(result))
    assert doc["tool"]["name"] == "leakhound"
    assert doc["summary"]["total"] == len(result.findings) == len(doc["findings"])
    assert sum(doc["summary"]["by_severity"].values()) == doc["summary"]["total"]
    raw = json.dumps(doc)
    for name in ("GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "STRIPE_LIVE_KEY"):
        assert FAKE[name] not in raw, f"{name} leaked into redacted JSON"
    first = doc["findings"][0]
    assert {"rule_id", "severity", "path", "line", "column", "fingerprint", "secret"} <= set(first)


def test_json_report_without_redaction_contains_secret(leaky_dir):
    result = scan_path(leaky_dir, Settings())
    assert FAKE["GITHUB_TOKEN"] in json_report.render(result, redact_secrets=False)


def test_sarif_is_valid_2_1_0_shape(leaky_dir):
    result = scan_path(leaky_dir, Settings())
    log = json.loads(sarif.render(result, rules=all_rule_metadata()))
    assert log["version"] == "2.1.0"
    (run,) = log["runs"]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == len(all_rule_metadata())
    assert len(run["results"]) == len(result.findings)
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in {"error", "warning", "note"}
        region = res["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1 and region["startColumn"] >= 1
        assert res["partialFingerprints"]["leakhound/v1"]
    for rule in rules:
        assert float(rule["properties"]["security-severity"]) > 0
    assert FAKE["GITHUB_TOKEN"] not in json.dumps(log)


def test_console_report_clean_and_dirty(leaky_dir, clean_dir):
    dirty = console.render(scan_path(leaky_dir, Settings()), color=False)
    assert "Found 25 potential secret(s)" in dirty
    assert "config/settings.py:7:17" in dirty
    assert FAKE["GITHUB_TOKEN"] not in dirty
    assert "\033[" not in dirty
    clean = console.render(scan_path(clean_dir, Settings()), color=False)
    assert "No secrets found." in clean


def test_console_report_shows_commit_details(git_repo):
    git_repo.write("x.py", f"k='{FAKE['GITHUB_TOKEN']}'\n")
    sha = git_repo.commit("oops")
    out = console.render(scan_git(git_repo.path, Settings()))
    assert sha[:12] in out and "Test Author" in out and "oops" in out
