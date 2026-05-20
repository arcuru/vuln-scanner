"""Smoke tests for the built-in vuln-scan prompt profile.

These guard against:
- The prompts/ files going missing from the package
- A future $placeholder typo in a .md file (string.Template.substitute raises)
- Per-task substitution dropping its arguments
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_scanner.configs import vuln_scan


def test_recon_prompt_renders():
    out = vuln_scan.recon_prompt()
    # Shared $environment block was substituted
    assert "isolated git worktree" in out
    # Attack class list was substituted
    assert "command_injection" in out
    # No leftover $placeholder
    assert "$environment" not in out
    assert "$attack_classes" not in out


def test_hunt_prompt_substitutes_all_fields():
    out = vuln_scan.hunt_prompt(
        attack_class="sql_injection",
        scope="src/db/query.py",
        function="run_query",
        entry_point="POST /search",
        rationale="user search term concatenated into SQL",
        arch_summary="Flask app with raw SQL.",
    )
    for needle in (
        "sql_injection",
        "src/db/query.py",
        "run_query",
        "POST /search",
        "user search term concatenated into SQL",
        "Flask app with raw SQL.",
    ):
        assert needle in out, f"missing: {needle}"
    # No leftover Template syntax
    assert "$attack_class" not in out
    assert "$scope" not in out
    assert "$function_hint" not in out


def test_hunt_prompt_empty_function_omits_target_line():
    out = vuln_scan.hunt_prompt(
        attack_class="xss",
        scope="src/views/",
        function="",
        entry_point="GET /",
        rationale="user-rendered content",
        arch_summary="",
    )
    # When function is empty the "Target function" hint is omitted entirely
    assert "Target function" not in out


def test_validate_prompt_renders():
    out = vuln_scan.validate_prompt()
    assert "adversarial reviewer" in out
    # The output-format markdown template intentionally keeps {{attack_class}}
    # as a literal placeholder for the agent to fill in
    assert "{{attack_class}}" in out
    assert "$environment" not in out


def test_dedupe_prompt_renders():
    out = vuln_scan.dedupe_prompt()
    assert "Deduplicated Findings" in out
    assert "$environment" not in out


def test_gapfill_prompt_lists_attack_classes():
    out = vuln_scan.gapfill_prompt()
    assert "command_injection" in out
    assert "$attack_classes" not in out


def test_consolidate_prompt_none_when_no_dedupe_output(tmp_path):
    assert vuln_scan.consolidate_prompt(tmp_path) is None


def test_consolidate_prompt_renders_when_findings_exist(tmp_path):
    dedupe_dir = tmp_path / "dedupe"
    dedupe_dir.mkdir()
    (dedupe_dir / "FINDINGS.md").write_text("# findings")
    out = vuln_scan.consolidate_prompt(tmp_path)
    assert out is not None
    assert "SUMMARY.md" in out


def test_all_prompt_files_present():
    """Sanity: every prompt referenced by the profile exists on disk."""
    prompts_dir = Path(vuln_scan.__file__).parent / "prompts"
    expected = {
        "_environment.md",
        "recon.md",
        "hunt.md",
        "validate.md",
        "dedupe.md",
        "gapfill.md",
        "consolidate.md",
    }
    actual = {p.name for p in prompts_dir.glob("*.md")}
    assert expected <= actual, f"missing: {expected - actual}"


def test_substitute_fails_loudly_on_missing_var(monkeypatch, tmp_path):
    """A typo'd $placeholder in a prompt should KeyError, not silently render."""
    bad_prompt = tmp_path / "bogus.md"
    bad_prompt.write_text("$environment and $not_a_real_var")
    monkeypatch.setattr(vuln_scan, "_PROMPTS_DIR", tmp_path)
    with pytest.raises(KeyError):
        vuln_scan._render("bogus")
