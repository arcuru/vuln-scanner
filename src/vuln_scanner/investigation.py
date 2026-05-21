"""Investigation directory primitives.

An investigation directory is one folder per scan target. It contains:

    vuln-scanner.toml      config (committed)
    MANIFEST.toml          target URL, latest-run pointer
    target/                cloned scan target (gitignored)
    worktrees/             ephemeral worktrees (gitignored)
    .vuln-scanner.lock     concurrency guard
    runs/<run-id>/         immutable per-run output
        manifest.toml      tool version, target SHA, status, summary counts
        config.toml        effective config snapshot for this run
        logs/              one log file per task (agent stdout / SDK stream)
        transcripts/       full Claude transcripts keyed by task id
        recon/, hunt/, validate/, dedupe/, consolidate/
            <task-id>/task.toml   backend, model, session, timings, cost
    SUMMARY.md             symlink to latest run's consolidate/SUMMARY.md

This module owns the on-disk shape: manifest read/write, run-id generation,
lockfile, symlink updates. It does NOT know about the pipeline or the agent.
"""

from __future__ import annotations

import fcntl
import shutil
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MANIFEST_NAME = "MANIFEST.toml"
RUN_MANIFEST_NAME = "manifest.toml"
RUN_CONFIG_NAME = "config.toml"
TASK_TOML_NAME = "task.toml"
TRANSCRIPTS_DIRNAME = "transcripts"
LOCKFILE_NAME = ".vuln-scanner.lock"
SUMMARY_NAME = "SUMMARY.md"
CONFIG_NAME = "vuln-scanner.toml"
RUNS_DIRNAME = "runs"
TARGET_DIRNAME = "target"
WORKTREES_DIRNAME = "worktrees"


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------


@dataclass
class Manifest:
    """Top-level MANIFEST.toml — target identity + latest-run pointer."""

    target_url: str
    latest_run: str | None = None  # run-id of most recent run

    @classmethod
    def load(cls, path: Path) -> Manifest:
        data = tomllib.loads(path.read_text())
        target = data.get("target", {})
        return cls(
            target_url=target["url"],
            latest_run=target.get("latest_run"),
        )

    def dump(self, path: Path) -> None:
        lines = [
            "[target]",
            f'url = "{self.target_url}"',
        ]
        if self.latest_run:
            lines.append(f'latest_run = "{self.latest_run}"')
        path.write_text("\n".join(lines) + "\n")


@dataclass
class RunManifest:
    """Per-run manifest.toml — provenance and outcome of one scan run."""

    run_id: str
    target_sha: str
    tool_version: str
    started_at: str  # ISO 8601 UTC
    finished_at: str | None = None
    status: str = "running"  # running | completed | failed | interrupted
    models: dict[str, str] = field(default_factory=dict)  # phase -> model id
    summary: dict[str, int] = field(default_factory=dict)  # confirmed/rejected/etc.

    @classmethod
    def load(cls, path: Path) -> RunManifest:
        data = tomllib.loads(path.read_text())
        return cls(
            run_id=data["run_id"],
            target_sha=data["target_sha"],
            tool_version=data["tool_version"],
            started_at=data["started_at"],
            finished_at=data.get("finished_at"),
            status=data.get("status", "completed"),
            models=data.get("models", {}),
            summary=data.get("summary", {}),
        )

    def dump(self, path: Path) -> None:
        lines = [
            f'run_id = "{self.run_id}"',
            f'target_sha = "{self.target_sha}"',
            f'tool_version = "{self.tool_version}"',
            f'started_at = "{self.started_at}"',
        ]
        if self.finished_at:
            lines.append(f'finished_at = "{self.finished_at}"')
        lines.append(f'status = "{self.status}"')
        if self.models:
            lines.append("")
            lines.append("[models]")
            for phase, model in self.models.items():
                lines.append(f'{phase} = "{model}"')
        if self.summary:
            lines.append("")
            lines.append("[summary]")
            for key, val in self.summary.items():
                lines.append(f"{key} = {int(val)}")
        path.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Run identity
# ---------------------------------------------------------------------------


def make_run_id(target_sha: str, *, now: datetime | None = None) -> str:
    """Generate a run-id: ``2026-05-20T14-30-abc1234``."""
    when = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H-%M")
    short = target_sha[:7] if target_sha else "unknown"
    return f"{when}-{short}"


def iso_now() -> str:
    """Return current time as ISO 8601 UTC string (suffixed ``Z``)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------


class LockHeld(RuntimeError):  # noqa: N818 — reads as state, not Error subclass
    """Raised when another vuln-scanner process holds the investigation lock."""


@contextmanager
def investigation_lock(inv_dir: Path) -> Iterator[None]:
    """Hold an exclusive flock on .vuln-scanner.lock for the duration of the block.

    Raises ``LockHeld`` if another process already holds it.
    """
    lock_path = inv_dir / LOCKFILE_NAME
    lock_path.touch(exist_ok=True)
    fd = lock_path.open("r+")
    try:
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            fd.close()
            raise LockHeld(
                f"Another vuln-scanner run holds {lock_path}. "
                f"Wait for it to finish, or delete the lockfile if it's stale."
            ) from e
        try:
            yield
        finally:
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
    finally:
        if not fd.closed:
            fd.close()


# ---------------------------------------------------------------------------
# Directory queries
# ---------------------------------------------------------------------------


def is_investigation_dir(path: Path) -> bool:
    """True if ``path`` looks like an investigation directory."""
    return (path / MANIFEST_NAME).is_file() and (path / CONFIG_NAME).is_file()


def list_runs(inv_dir: Path) -> list[Path]:
    """Return all run directories under ``runs/`` sorted lexicographically (so
    chronologically, given the timestamp prefix in the run-id).
    """
    runs_dir = inv_dir / RUNS_DIRNAME
    if not runs_dir.is_dir():
        return []
    return sorted(p for p in runs_dir.iterdir() if p.is_dir())


def latest_run(inv_dir: Path) -> Path | None:
    """Return the most recent run directory, or None if there are no runs."""
    runs = list_runs(inv_dir)
    return runs[-1] if runs else None


# ---------------------------------------------------------------------------
# Per-task metadata and transcript capture
# ---------------------------------------------------------------------------


def _toml_value(v: Any) -> str:
    """Render a Python value as a TOML scalar/array.

    Handles the subset of types we actually emit in task.toml: str, bool, int,
    float, None (→ skipped by caller), and lists of strings.
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    # Default: quote as string. Escape backslashes and double-quotes only —
    # task.toml values come from program-controlled sources (paths, model IDs,
    # UUIDs), not user input, so this is sufficient.
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def write_task_toml(path: Path, data: dict[str, Any]) -> None:
    """Write a per-task metadata file at ``path``.

    ``data`` may contain nested dicts (rendered as `[section]` headers).
    ``None`` values are skipped.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    # Top-level scalars first, then nested tables
    top = {k: v for k, v in data.items() if not isinstance(v, dict)}
    nested = {k: v for k, v in data.items() if isinstance(v, dict)}
    for k, v in top.items():
        if v is None:
            continue
        lines.append(f"{k} = {_toml_value(v)}")
    for section, body in nested.items():
        if not body:
            continue
        lines.append("")
        lines.append(f"[{section}]")
        for k, v in body.items():
            if v is None:
                continue
            lines.append(f"{k} = {_toml_value(v)}")
    path.write_text("\n".join(lines) + "\n")


def find_claude_transcript(session_id: str) -> Path | None:
    """Locate ``~/.claude/projects/*/<session_id>.jsonl``.

    Returns the most recently modified match (Claude Code writes one transcript
    file per session under a project-encoded directory). Returns ``None`` if
    no match is found.
    """
    if not session_id:
        return None
    base = Path.home() / ".claude" / "projects"
    if not base.is_dir():
        return None
    matches = list(base.glob(f"*/{session_id}.jsonl"))
    if not matches:
        return None
    return max(matches, key=lambda p: p.stat().st_mtime)


def copy_transcript(session_id: str, dest: Path) -> Path | None:
    """Copy the Claude transcript for ``session_id`` into ``dest``.

    Returns the destination path on success, ``None`` if the source can't be
    found. Idempotent — overwrites any existing destination file.
    """
    src = find_claude_transcript(session_id)
    if src is None:
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return dest


# ---------------------------------------------------------------------------
# SUMMARY.md symlink
# ---------------------------------------------------------------------------


def update_summary_symlink(inv_dir: Path, run_dir: Path) -> None:
    """Point ``<inv_dir>/SUMMARY.md`` at the run's consolidated summary.

    The consolidate phase writes ``<run_dir>/consolidate/SUMMARY.md``. No-op
    if the run hasn't produced one yet (e.g. interrupted before consolidate).
    """
    src = run_dir / "consolidate" / SUMMARY_NAME
    if not src.is_file():
        return
    link = inv_dir / SUMMARY_NAME
    if link.is_symlink() or link.exists():
        link.unlink()
    # Use a relative target so the investigation folder is portable.
    link.symlink_to(src.relative_to(inv_dir))
