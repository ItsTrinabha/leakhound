"""Shared pytest fixtures."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fakes import render_fixture  # noqa: E402


@pytest.fixture
def leaky_dir(tmp_path: Path) -> Path:
    """The leaky fixture project with fake secrets rendered in."""
    return render_fixture("leaky_project", tmp_path / "leaky")


@pytest.fixture
def clean_dir(tmp_path: Path) -> Path:
    """A realistic project with no secrets (but plenty of near-misses)."""
    return render_fixture("clean_project", tmp_path / "clean")


class GitRepo:
    """Tiny helper around a throwaway git repository."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test Author")
        self.git("config", "user.email", "author@example.test")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.path), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    def write(self, rel: str, content: str) -> None:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def git_repo(tmp_path: Path) -> GitRepo:
    return GitRepo(tmp_path / "repo")
