"""Tests for target repo cloning + SHA pinning.

These use real local git repos (no network) so the helpers exercise actual
git invocations end-to-end.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vuln_scanner import target


def _init_origin(path: Path, commits: int = 2) -> list[str]:
    """Create a bare-style local repo with N commits; return SHAs."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=path, check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"], cwd=path, check=True,
    )
    shas = []
    for i in range(commits):
        (path / f"file{i}.txt").write_text(f"commit {i}\n")
        subprocess.run(["git", "add", "."], cwd=path, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", f"commit {i}"], cwd=path, check=True,
        )
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True,
        ).stdout.strip()
        shas.append(sha)
    return shas


class TestClone:
    def test_clones_to_dest(self, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin)
        dest = tmp_path / "cloned"
        target.clone(str(origin), dest)
        assert (dest / ".git").is_dir()
        assert (dest / "file0.txt").is_file()

    def test_refuses_existing_dest(self, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin)
        dest = tmp_path / "existing"
        dest.mkdir()
        with pytest.raises(target.GitError, match="already exists"):
            target.clone(str(origin), dest)


class TestCurrentSha:
    def test_returns_head(self, tmp_path):
        origin = tmp_path / "origin"
        shas = _init_origin(origin, commits=3)
        assert target.current_sha(origin) == shas[-1]


class TestCheckout:
    def test_detaches_at_sha(self, tmp_path):
        origin = tmp_path / "origin"
        shas = _init_origin(origin, commits=3)
        dest = tmp_path / "cloned"
        target.clone(str(origin), dest)

        # Check out the middle commit
        target.checkout(dest, shas[1])
        assert target.current_sha(dest) == shas[1]

        # File from commit 2 should not exist at commit 1
        assert not (dest / "file2.txt").exists()
        assert (dest / "file0.txt").exists()
        assert (dest / "file1.txt").exists()

    def test_invalid_sha_raises(self, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin)
        dest = tmp_path / "cloned"
        target.clone(str(origin), dest)
        with pytest.raises(target.GitError):
            target.checkout(dest, "deadbeefdeadbeef")


class TestFetch:
    def test_pulls_new_commits(self, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin, commits=1)
        dest = tmp_path / "cloned"
        target.clone(str(origin), dest)
        sha_before = target.current_sha(dest)

        # Add a commit in the origin
        (origin / "new.txt").write_text("after clone\n")
        subprocess.run(["git", "add", "."], cwd=origin, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "post-clone"], cwd=origin, check=True,
        )
        new_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=origin, check=True, capture_output=True, text=True,
        ).stdout.strip()

        # Before fetch, the clone doesn't know about new_sha
        with pytest.raises(target.GitError):
            target.checkout(dest, new_sha)

        target.fetch(dest)
        target.checkout(dest, new_sha)
        assert target.current_sha(dest) == new_sha
        # Local HEAD still at the original (detached at new_sha now)
        assert target.current_sha(dest) != sha_before
