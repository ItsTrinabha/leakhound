import json
import subprocess
import sys
from pathlib import Path

import pytest

from fakes import FAKE
from leakhound.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, run

ROOT = Path(__file__).resolve().parents[1]


def test_exit_codes(leaky_dir, clean_dir, capsys):
    assert run(["scan", str(clean_dir)]) == EXIT_CLEAN
    assert run(["scan", str(leaky_dir)]) == EXIT_FINDINGS
    assert run(["scan", str(leaky_dir / "does-not-exist")]) == EXIT_ERROR
    assert run(["scan", str(leaky_dir), "--exit-zero"]) == EXIT_CLEAN


def test_fail_on_threshold(tmp_path):
    (tmp_path / "a.env").write_text(f"STRIPE={FAKE['STRIPE_TEST_KEY']}\n")  # low severity
    assert run(["scan", str(tmp_path), "--fail-on", "medium"]) == EXIT_CLEAN
    assert run(["scan", str(tmp_path), "--fail-on", "low"]) == EXIT_FINDINGS


def test_bad_arguments_exit_2():
    with pytest.raises(SystemExit) as exc:
        run(["scan", ".", "--fail-on", "apocalyptic"])
    assert exc.value.code == EXIT_ERROR


def test_json_output_to_file_and_baseline_roundtrip(leaky_dir, tmp_path, capsys):
    report = tmp_path / "baseline.json"
    assert run(["scan", str(leaky_dir), "-f", "json", "-o", str(report)]) == EXIT_FINDINGS
    data = json.loads(report.read_text())
    assert data["summary"]["total"] == 25
    assert run(["scan", str(leaky_dir), "--baseline", str(report)]) == EXIT_CLEAN
    assert "25 finding(s) suppressed" in capsys.readouterr().out


def test_min_severity_filters_output(leaky_dir, capsys):
    run(["scan", str(leaky_dir), "-f", "json", "--min-severity", "critical"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["findings"] and {f["severity"] for f in doc["findings"]} == {"critical"}


def test_disable_rule_and_no_entropy(leaky_dir, capsys):
    run(["scan", str(leaky_dir), "-f", "json", "--no-entropy", "--disable-rule", "jwt"])
    ids = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert not ids & {"jwt", "high-entropy-string", "high-entropy-hex"}
    assert run(["scan", str(leaky_dir), "--disable-rule", "nope"]) == EXIT_ERROR


def test_no_redact(leaky_dir, capsys):
    run(["scan", str(leaky_dir), "--no-redact"])
    assert FAKE["GITHUB_TOKEN"] in capsys.readouterr().out


def test_git_subcommand(git_repo, capsys):
    git_repo.write("a.py", f"t = '{FAKE['GITHUB_TOKEN']}'\n")
    git_repo.commit("leak")
    git_repo.write("a.py", "t = None\n")
    git_repo.commit("fix")
    assert run(["scan", str(git_repo.path)]) == EXIT_CLEAN
    assert run(["git", str(git_repo.path), "-f", "sarif"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert '"ruleId": "github-token"' in out
    assert run(["git", str(git_repo.path), "--log-opts", "HEAD~1..HEAD"]) == EXIT_CLEAN


def test_rules_subcommand(capsys):
    assert run(["rules", "-f", "json"]) == EXIT_CLEAN
    rules = json.loads(capsys.readouterr().out)
    assert {"private-key", "aws-access-key-id", "high-entropy-string"} <= {r["id"] for r in rules}


def test_module_entry_point_runs_as_subprocess(clean_dir):
    proc = subprocess.run(
        [sys.executable, "-m", "leakhound", "scan", str(clean_dir), "--no-color"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "No secrets found." in proc.stdout


def test_project_source_tree_scans_clean():
    """Dogfooding: leakhound's own repository contains no secrets."""
    assert run(["scan", str(ROOT), "--no-gitignore"]) == EXIT_CLEAN
