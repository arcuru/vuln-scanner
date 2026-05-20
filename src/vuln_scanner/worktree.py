"""Git worktree isolation for task execution."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from taskrunner import Task


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=check,
    )


def slugify(path: str) -> str:
    """Convert a string into a git-ref-safe branch name component."""
    # Replace any path separator with dash
    slug = path.replace("/", "-").replace("\\", "-")
    # Replace characters forbidden in git refs: space ~ ^ : ? * [ \
    slug = re.sub(r"[ ~^:?*\[\]\\]", "-", slug)
    # Collapse consecutive dashes
    slug = re.sub(r"-{2,}", "-", slug)
    # Strip leading/trailing dots and dashes
    slug = slug.strip(".-")
    # Clamp length (git branch names have practical limit ~250 chars)
    if len(slug) > 200:
        slug = slug[:200]
    return slug


def ensure_worktree(
    repo: Path,
    worktree: Path,
    branch: str,
    start_point: str = "HEAD",
) -> None:
    """Create a worktree + branch, cleaning up stale state first."""
    if worktree.exists():
        git(repo, "worktree", "remove", "--force", str(worktree), check=False)
        if worktree.exists():
            shutil.rmtree(worktree)
        git(repo, "branch", "-D", branch, check=False)
    git(repo, "worktree", "add", "-b", branch, str(worktree), start_point, "--quiet")


def commit_worktree(worktree: Path, message: str) -> None:
    """Stage and commit everything in a worktree."""
    git(worktree, "add", "-A", check=False)
    git(worktree, "commit", "-m", message, "--allow-empty", "--quiet", check=False)


class WorktreeSetup:
    """SetupCallbacks implementation using git worktrees for isolation.

    Each task gets its own worktree branched off the repo. Phase 2+ tasks
    branch off their parent task's branch so investigation artifacts are
    available.
    """

    def __init__(self, repo: Path, branch_prefix: str, worktree_dir: Path) -> None:
        self.repo = repo
        self.branch_prefix = branch_prefix
        self.worktree_dir = worktree_dir
        self.worktree_dir.mkdir(parents=True, exist_ok=True)

    def setup_work_dir(self, task: Task, phase_name: str, output_dir: Path) -> Path:
        slug = slugify(task.id)
        branch = f"{self.branch_prefix}-{phase_name}/{slug}"
        worktree = self.worktree_dir / f"{phase_name}-{slug}"

        # Determine start point — branch off parent if available
        start_point = "HEAD"
        if task.parent_task:
            parent_slug = slugify(task.parent_task)
            parent_phase = task.metadata.get("parent_phase", "scan")
            start_point = f"{self.branch_prefix}-{parent_phase}/{parent_slug}"

        ensure_worktree(self.repo, worktree, branch, start_point)
        return worktree

    def teardown_work_dir(self, task: Task, work_dir: Path, phase_name: str) -> None:
        commit_worktree(work_dir, f"{self.branch_prefix}: {phase_name} {task.id}")

    def setup_consolidation_dir(
        self,
        task: Task,
        phase_name: str,
        output_dir: Path,
        all_outputs: dict[str, dict[str, dict[str, Path]]],
    ) -> Path:
        worktree = self.setup_work_dir(task, phase_name, output_dir)

        # Copy all prior phase outputs into the worktree for Claude to read
        reports_dir = worktree / "reports"
        for prev_phase, tasks in all_outputs.items():
            for task_id, outputs in tasks.items():
                for _name, path in outputs.items():
                    if path.exists():
                        dest = reports_dir / prev_phase / task_id / path.name
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(path, dest)

        return worktree
