"""Tests for the CLI subcommands."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import pytest

from vuln_scanner import cli, investigation
from vuln_scanner.investigation import Manifest, RunManifest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _init_origin(path: Path) -> str:
    """Create a tiny local git repo; return its HEAD SHA."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@e.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True)
    (path / "README.md").write_text("# test\n")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=path, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def cwd(tmp_path, monkeypatch):
    """Run the test with cwd=tmp_path so cli subcommands operate there."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


class TestCmdInit:
    def test_scaffolds_directory(self, cwd, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin)

        args = argparse.Namespace(target_url=str(origin), config=None)
        cli.cmd_init(args)

        assert (cwd / "vuln-scanner.toml").is_file()
        assert (cwd / "MANIFEST.toml").is_file()
        assert (cwd / "target" / ".git").is_dir()
        assert (cwd / "target" / "README.md").is_file()
        assert (cwd / ".gitignore").is_file()

        # Manifest records the URL
        manifest = Manifest.load(cwd / "MANIFEST.toml")
        assert manifest.target_url == str(origin)
        assert manifest.latest_run is None

        # is_investigation_dir agrees we're set up
        assert investigation.is_investigation_dir(cwd)

    def test_refuses_existing_investigation(self, cwd, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin)
        (cwd / "vuln-scanner.toml").write_text("")
        (cwd / "MANIFEST.toml").write_text('[target]\nurl="x"')

        args = argparse.Namespace(target_url=str(origin), config=None)
        with pytest.raises(SystemExit):
            cli.cmd_init(args)

    def test_refuses_existing_target_dir(self, cwd, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin)
        (cwd / "target").mkdir()

        args = argparse.Namespace(target_url=str(origin), config=None)
        with pytest.raises(SystemExit):
            cli.cmd_init(args)

    def test_default_config_is_loadable(self, cwd, tmp_path):
        """The auto-generated vuln-scanner.toml must round-trip through load_config."""
        from vuln_scanner.config import load_config

        origin = tmp_path / "origin"
        _init_origin(origin)
        cli.cmd_init(argparse.Namespace(target_url=str(origin), config=None))

        cfg = load_config(str(cwd / "vuln-scanner.toml"))
        assert cfg.agent == "claude"
        assert cfg.branch_prefix == "vuln-scan"
        # commented-out model entries should not leak in
        assert cfg.recon_model is None
        assert cfg.hunt_model is None

    def test_copies_provided_config(self, cwd, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin)
        cfg_src = tmp_path / "myconfig.toml"
        cfg_src.write_text(
            "[scan]\nprompt_profile = \"vuln-scan\"\nmax_tasks = 7\n",
        )
        args = argparse.Namespace(target_url=str(origin), config=str(cfg_src))
        cli.cmd_init(args)
        assert "max_tasks = 7" in (cwd / "vuln-scanner.toml").read_text()

    def test_gitignore_entries(self, cwd, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin)
        args = argparse.Namespace(target_url=str(origin), config=None)
        cli.cmd_init(args)
        text = (cwd / ".gitignore").read_text()
        assert "target/" in text
        assert "worktrees/" in text
        assert investigation.LOCKFILE_NAME in text

    def test_appends_to_existing_gitignore(self, cwd, tmp_path):
        origin = tmp_path / "origin"
        _init_origin(origin)
        (cwd / ".gitignore").write_text("*.pyc\n")
        args = argparse.Namespace(target_url=str(origin), config=None)
        cli.cmd_init(args)
        text = (cwd / ".gitignore").read_text()
        assert "*.pyc" in text  # preserved
        assert "target/" in text  # added


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


class TestCmdStatus:
    def test_requires_investigation_dir(self, cwd):
        with pytest.raises(SystemExit):
            cli.cmd_status(argparse.Namespace())

    def test_empty_runs(self, cwd, tmp_path, capsys):
        origin = tmp_path / "origin"
        _init_origin(origin)
        cli.cmd_init(argparse.Namespace(target_url=str(origin), config=None))

        cli.cmd_status(argparse.Namespace())
        out = capsys.readouterr().out
        assert "Target:" in out
        assert str(origin) in out
        assert "No runs yet" in out

    def test_lists_runs(self, cwd, tmp_path, capsys, monkeypatch):
        # Rich truncates the run-id column under a narrow terminal; force a
        # wide one so the full ID appears in captured output.
        monkeypatch.setenv("COLUMNS", "300")

        origin = tmp_path / "origin"
        _init_origin(origin)
        cli.cmd_init(argparse.Namespace(target_url=str(origin), config=None))

        # Synthesize two runs
        for run_id, sha, status, confirmed in (
            ("2026-05-20T14-30-aaa1234", "aaa1234deadbeef", "completed", 3),
            ("2026-05-21T09-00-bbb5678", "bbb5678cafef00d", "failed", 0),
        ):
            run_dir = cwd / "runs" / run_id
            run_dir.mkdir(parents=True)
            RunManifest(
                run_id=run_id,
                target_sha=sha,
                tool_version="0.1.0",
                started_at="2026-05-20T14:30:00Z",
                finished_at="2026-05-20T15:00:00Z",
                status=status,
                models={"recon": "claude-sonnet-4-6", "hunt": "claude-sonnet-4-6",
                        "validate": "claude-opus-4-7"},
                summary={"confirmed": confirmed, "rejected": 5, "unique_vulns": confirmed},
            ).dump(run_dir / "manifest.toml")

        cli.cmd_status(argparse.Namespace())
        out = capsys.readouterr().out
        assert "2026-05-20T14-30-aaa1234" in out
        assert "2026-05-21T09-00-bbb5678" in out
        assert "completed" in out
        assert "failed" in out


# ---------------------------------------------------------------------------
# Summary parsing helper
# ---------------------------------------------------------------------------


class TestSummaryCountsParsing:
    def test_full_summary(self, tmp_path):
        findings = tmp_path / "FINDINGS.md"
        findings.write_text(
            "# Deduplicated Findings\n"
            "## Scan Summary\n"
            "- **Total hunt tasks:** 20\n"
            "- **Confirmed:** 3 | **Rejected:** 12 | **Needs review:** 1\n"
            "- **Unique vulnerabilities:** 2\n"
        )
        counts = cli._summary_counts_from_findings(findings)
        assert counts == {"confirmed": 3, "rejected": 12, "needs_review": 1, "unique_vulns": 2}

    def test_partial_summary(self, tmp_path):
        findings = tmp_path / "FINDINGS.md"
        findings.write_text("**Confirmed:** 5\n")
        assert cli._summary_counts_from_findings(findings) == {"confirmed": 5}

    def test_missing_file(self, tmp_path):
        assert cli._summary_counts_from_findings(tmp_path / "nope.md") == {}

    def test_no_counts(self, tmp_path):
        findings = tmp_path / "FINDINGS.md"
        findings.write_text("# no counts here\n")
        assert cli._summary_counts_from_findings(findings) == {}


# ---------------------------------------------------------------------------
# Tool version
# ---------------------------------------------------------------------------


def test_tool_version_returns_string():
    v = cli._tool_version()
    assert isinstance(v, str)
    assert v  # non-empty
