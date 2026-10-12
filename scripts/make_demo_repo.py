"""Create a throwaway git repository with secrets buried in its history.

    python scripts/make_demo_repo.py /tmp/leaky-demo
    leakhound scan /tmp/leaky-demo     # current files: clean
    leakhound git  /tmp/leaky-demo     # history: finds what was "deleted"

All secrets are randomly generated fakes (see tests/fakes.py).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from fakes import FAKE  # noqa: E402


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def commit(repo: Path, files: dict[str, str], message: str) -> None:
    for rel, content in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def main(target: str) -> None:
    repo = Path(target)
    if repo.exists() and any(repo.iterdir()):
        sys.exit(f"{repo} exists and is not empty")
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "Demo Dev")
    git(repo, "config", "user.email", "dev@demo.invalid")

    commit(repo, {"app.py": "import os\n\nprint('hello')\n"}, "Initial commit")
    commit(repo, {"app.py": f"import os\n\nSTRIPE_KEY = '{FAKE['STRIPE_LIVE_KEY']}'\nprint('hello')\n"},
           "Add payments (quick hack)")
    commit(repo, {"deploy/id_rsa": FAKE["PRIVATE_KEY"] + "\n",
                  ".env": f"DB_PASSWORD={FAKE['DB_PASSWORD']}\nSLACK_BOT_TOKEN={FAKE['SLACK_BOT_TOKEN']}\n"},
           "Deploy config")
    commit(repo, {"app.py": "import os\n\nSTRIPE_KEY = os.environ['STRIPE_KEY']\nprint('hello')\n"},
           "Move Stripe key to env")
    (repo / "deploy/id_rsa").unlink()
    (repo / ".env").unlink()
    commit(repo, {".gitignore": ".env\n"}, "Remove secrets")
    print(f"demo repository created at {repo}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "leaky-demo")
