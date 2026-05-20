"""Target repo cloning and SHA pinning."""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    """A git command failed."""


def _run(cmd: list[str], *, cwd: Path | None = None) -> str:
    """Run a git command, returning stripped stdout. Raises GitError on failure."""
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise GitError(
            f"{' '.join(cmd)} failed:\n{result.stderr.strip()}"
        )
    return result.stdout.strip()


def clone(url: str, dest: Path) -> None:
    """Clone ``url`` into ``dest`` (must not exist)."""
    if dest.exists():
        raise GitError(f"clone destination already exists: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "clone", url, str(dest)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise GitError(f"git clone failed:\n{result.stderr.strip()}")


def fetch(repo: Path) -> None:
    """``git fetch --all --tags`` in ``repo``."""
    _run(["git", "fetch", "--all", "--tags"], cwd=repo)


def checkout(repo: Path, sha: str) -> None:
    """Detach HEAD at ``sha`` in ``repo``."""
    _run(["git", "checkout", "--detach", sha], cwd=repo)


def current_sha(repo: Path) -> str:
    """Return the full HEAD commit SHA of ``repo``."""
    return _run(["git", "rev-parse", "HEAD"], cwd=repo)
