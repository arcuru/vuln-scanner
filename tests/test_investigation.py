"""Tests for investigation directory primitives."""

from __future__ import annotations

import multiprocessing
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vuln_scanner import investigation
from vuln_scanner.investigation import (
    LockHeld,
    Manifest,
    RunManifest,
    investigation_lock,
    is_investigation_dir,
    iso_now,
    latest_run,
    list_runs,
    make_run_id,
    update_summary_symlink,
)

# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------


class TestManifest:
    def test_minimal_round_trip(self, tmp_path):
        path = tmp_path / "MANIFEST.toml"
        Manifest(target_url="https://github.com/u/r").dump(path)
        loaded = Manifest.load(path)
        assert loaded.target_url == "https://github.com/u/r"
        assert loaded.latest_run is None

    def test_with_latest_run(self, tmp_path):
        path = tmp_path / "MANIFEST.toml"
        Manifest(
            target_url="https://github.com/u/r",
            latest_run="2026-05-20T14-30-abc1234",
        ).dump(path)
        loaded = Manifest.load(path)
        assert loaded.latest_run == "2026-05-20T14-30-abc1234"


class TestRunManifest:
    def test_minimal_round_trip(self, tmp_path):
        path = tmp_path / "manifest.toml"
        RunManifest(
            run_id="rid",
            target_sha="abc",
            tool_version="0.1.0",
            started_at="2026-05-20T14:30:00Z",
        ).dump(path)
        loaded = RunManifest.load(path)
        assert loaded.run_id == "rid"
        assert loaded.target_sha == "abc"
        assert loaded.tool_version == "0.1.0"
        assert loaded.status == "running"
        assert loaded.models == {}
        assert loaded.summary == {}

    def test_full_round_trip(self, tmp_path):
        path = tmp_path / "manifest.toml"
        original = RunManifest(
            run_id="rid",
            target_sha="abc1234",
            tool_version="0.1.0",
            started_at="2026-05-20T14:30:00Z",
            finished_at="2026-05-20T15:42:00Z",
            status="completed",
            models={"recon": "claude-sonnet-4-6", "hunt": "claude-sonnet-4-6"},
            summary={"confirmed": 3, "rejected": 12, "unique_vulns": 2},
        )
        original.dump(path)
        loaded = RunManifest.load(path)
        assert loaded == original

    def test_status_round_trips(self, tmp_path):
        for status in ("running", "completed", "failed", "interrupted"):
            path = tmp_path / f"{status}.toml"
            RunManifest(
                run_id="x", target_sha="y", tool_version="z",
                started_at="2026-01-01T00:00:00Z", status=status,
            ).dump(path)
            assert RunManifest.load(path).status == status


# ---------------------------------------------------------------------------
# Run identity
# ---------------------------------------------------------------------------


class TestMakeRunId:
    def test_format(self):
        now = datetime(2026, 5, 20, 14, 30, tzinfo=UTC)
        assert make_run_id("abc1234567890", now=now) == "2026-05-20T14-30-abc1234"

    def test_empty_sha(self):
        now = datetime(2026, 5, 20, 14, 30, tzinfo=UTC)
        assert make_run_id("", now=now) == "2026-05-20T14-30-unknown"

    def test_sorts_chronologically(self):
        # Lexicographic sort on the run-id string == chronological order
        ids = [
            make_run_id("aaa", now=datetime(2026, 1, 1, tzinfo=UTC)),
            make_run_id("bbb", now=datetime(2026, 6, 15, tzinfo=UTC)),
            make_run_id("ccc", now=datetime(2027, 1, 1, tzinfo=UTC)),
        ]
        assert sorted(ids) == ids


def test_iso_now_is_utc_zulu():
    s = iso_now()
    assert s.endswith("Z")
    # parses
    datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Directory queries
# ---------------------------------------------------------------------------


class TestIsInvestigationDir:
    def test_true_when_both_files_present(self, tmp_path):
        (tmp_path / "MANIFEST.toml").write_text("[target]\nurl=\"x\"")
        (tmp_path / "vuln-scanner.toml").write_text("")
        assert is_investigation_dir(tmp_path)

    def test_false_when_manifest_missing(self, tmp_path):
        (tmp_path / "vuln-scanner.toml").write_text("")
        assert not is_investigation_dir(tmp_path)

    def test_false_when_config_missing(self, tmp_path):
        (tmp_path / "MANIFEST.toml").write_text("[target]\nurl=\"x\"")
        assert not is_investigation_dir(tmp_path)

    def test_false_when_empty(self, tmp_path):
        assert not is_investigation_dir(tmp_path)


class TestListRuns:
    def test_empty(self, tmp_path):
        assert list_runs(tmp_path) == []
        assert latest_run(tmp_path) is None

    def test_sorted(self, tmp_path):
        runs = tmp_path / "runs"
        runs.mkdir()
        # Create out of order to verify sort
        (runs / "2026-06-01T10-00-bbb").mkdir()
        (runs / "2026-01-01T10-00-aaa").mkdir()
        (runs / "2027-01-01T10-00-ccc").mkdir()
        listed = list_runs(tmp_path)
        assert [p.name for p in listed] == [
            "2026-01-01T10-00-aaa",
            "2026-06-01T10-00-bbb",
            "2027-01-01T10-00-ccc",
        ]
        assert latest_run(tmp_path).name == "2027-01-01T10-00-ccc"

    def test_ignores_non_directories(self, tmp_path):
        runs = tmp_path / "runs"
        runs.mkdir()
        (runs / "actual-run").mkdir()
        (runs / "stray-file").write_text("")
        assert [p.name for p in list_runs(tmp_path)] == ["actual-run"]


# ---------------------------------------------------------------------------
# Summary symlink
# ---------------------------------------------------------------------------


class TestUpdateSummarySymlink:
    def test_creates_symlink(self, tmp_path):
        run_dir = tmp_path / "runs" / "r1"
        run_dir.mkdir(parents=True)
        (run_dir / "SUMMARY.md").write_text("# hello")
        update_summary_symlink(tmp_path, run_dir)
        link = tmp_path / "SUMMARY.md"
        assert link.is_symlink()
        assert link.read_text() == "# hello"

    def test_relative_target(self, tmp_path):
        run_dir = tmp_path / "runs" / "r1"
        run_dir.mkdir(parents=True)
        (run_dir / "SUMMARY.md").write_text("# x")
        update_summary_symlink(tmp_path, run_dir)
        # Target should be relative so the investigation folder is portable
        link = tmp_path / "SUMMARY.md"
        assert not Path(str(link.readlink())).is_absolute()

    def test_replaces_existing_symlink(self, tmp_path):
        r1 = tmp_path / "runs" / "r1"
        r2 = tmp_path / "runs" / "r2"
        for r, body in ((r1, "first"), (r2, "second")):
            r.mkdir(parents=True)
            (r / "SUMMARY.md").write_text(body)
        update_summary_symlink(tmp_path, r1)
        update_summary_symlink(tmp_path, r2)
        assert (tmp_path / "SUMMARY.md").read_text() == "second"

    def test_noop_when_run_has_no_summary(self, tmp_path):
        run_dir = tmp_path / "runs" / "r1"
        run_dir.mkdir(parents=True)
        update_summary_symlink(tmp_path, run_dir)
        assert not (tmp_path / "SUMMARY.md").exists()


# ---------------------------------------------------------------------------
# Lockfile
# ---------------------------------------------------------------------------


def _hold_lock_in_child(inv_dir: str, hold_seconds: float) -> None:
    """Subprocess target: acquire lock and sleep."""
    with investigation_lock(Path(inv_dir)):
        time.sleep(hold_seconds)


class TestLock:
    def test_simple_acquire_release(self, tmp_path):
        with investigation_lock(tmp_path):
            pass
        # Can re-acquire after release
        with investigation_lock(tmp_path):
            pass

    def test_concurrent_acquire_raises(self, tmp_path):
        ctx = multiprocessing.get_context("spawn")
        child = ctx.Process(target=_hold_lock_in_child, args=(str(tmp_path), 2.0))
        child.start()
        # Wait briefly for the child to acquire
        time.sleep(0.5)
        try:
            with pytest.raises(LockHeld):
                with investigation_lock(tmp_path):
                    pytest.fail("should not have acquired the lock")
        finally:
            child.join(timeout=5)

    def test_lockfile_created(self, tmp_path):
        with investigation_lock(tmp_path):
            assert (tmp_path / investigation.LOCKFILE_NAME).exists()
