from fakes import FAKE
from leakhound import Settings, scan_git, scan_path
from leakhound.scanner import ScanError, parse_unified_diff

import pytest


def test_secret_deleted_from_tree_is_still_found_in_history(git_repo):
    git_repo.write("app.py", "import os\n")
    git_repo.commit("initial")
    git_repo.write("app.py", f"import os\nTOKEN = '{FAKE['GITHUB_TOKEN']}'\n")
    leaking_sha = git_repo.commit("add token")
    git_repo.write("app.py", "import os\nTOKEN = os.environ['TOKEN']\n")
    git_repo.commit("remove token")

    assert scan_path(git_repo.path, Settings()).findings == []

    result = scan_git(git_repo.path, Settings())
    (finding,) = result.findings
    assert finding.rule_id == "github-token"
    assert (finding.path, finding.line) == ("app.py", 2)
    assert finding.commit.sha == leaking_sha
    assert finding.commit.author == "Test Author"
    assert finding.commit.message == "add token"
    assert finding.source == "git"
    assert result.stats.commits_scanned == 3


def test_secret_reported_once_attributed_to_oldest_commit(git_repo):
    git_repo.write("a.txt", f"key: {FAKE['NPM_TOKEN']}\n")
    first = git_repo.commit("introduce")
    git_repo.write("a.txt", "header\n" + f"key: {FAKE['NPM_TOKEN']}\n")
    git_repo.commit("touch file")  # the line itself is unchanged, so not re-added
    git_repo.git("checkout", "-q", "-b", "other")
    git_repo.write("b.txt", "nothing here\n")
    git_repo.commit("other branch")

    result = scan_git(git_repo.path, Settings())
    assert [(f.rule_id, f.commit.sha) for f in result.findings] == [("npm-token", first)]


def test_multiline_private_key_in_history(git_repo):
    git_repo.write("keys/deploy_key", FAKE["PRIVATE_KEY"] + "\n")
    git_repo.commit("add key")
    (finding,) = scan_git(git_repo.path, Settings()).findings
    assert finding.rule_id == "private-key" and finding.line == 1


def test_log_opts_limit_the_range(git_repo):
    git_repo.write("a.py", f"t = '{FAKE['GITHUB_TOKEN']}'\n")
    git_repo.commit("leak")
    git_repo.write("b.py", "x = 1\n")
    git_repo.commit("clean")
    assert scan_git(git_repo.path, Settings(), log_opts=["HEAD~1..HEAD"]).findings == []


def test_staged_mode_scans_only_the_index(git_repo):
    git_repo.write("README.md", "hello\n")
    git_repo.commit("init")
    git_repo.write("config.py", f"KEY = '{FAKE['STRIPE_LIVE_KEY']}'\n")
    assert scan_git(git_repo.path, Settings(), staged=True).findings == []  # not staged yet
    git_repo.git("add", "config.py")
    (finding,) = scan_git(git_repo.path, Settings(), staged=True).findings
    assert (finding.rule_id, finding.source, finding.commit) == ("stripe-live-key", "staged", None)


def test_ignored_paths_are_skipped_in_history(git_repo):
    git_repo.write("node_modules/x/index.js", f"t='{FAKE['GITHUB_TOKEN']}'\n")
    git_repo.commit("vendored")
    assert scan_git(git_repo.path, Settings()).findings == []


def test_not_a_repository(tmp_path):
    with pytest.raises(ScanError):
        scan_git(tmp_path, Settings())


def test_diff_parser_handles_tricky_lines():
    diff = [
        "diff --git a/f.txt b/f.txt\n",
        "--- a/f.txt\n",
        "+++ b/f.txt\n",
        "@@ -1,0 +5,2 @@\n",
        "+++ this added line starts with two plus signs\n",
        "+second\n",
        "diff --git a/gone.txt b/gone.txt\n",
        "--- a/gone.txt\n",
        "+++ /dev/null\n",
        "@@ -1 +0,0 @@\n",
        "-removed\n",
    ]
    (hunk,) = list(parse_unified_diff(diff))
    assert hunk.path == "f.txt" and hunk.start_line == 5
    assert hunk.lines == ["++ this added line starts with two plus signs", "second"]
