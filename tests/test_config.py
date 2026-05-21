"""Tests for config loading -- TOML overlay, Python profiles, fallbacks."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from vuln_scanner.claude import BACKENDS, ClaudeBackend, CommandBackend
from vuln_scanner.config import load_config

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


MINIMAL_PROFILE = textwrap.dedent(
    """
    def recon_prompt(*, prior_runs_path=""):
        return f"recon prior={prior_runs_path}"

    def hunt_prompt(*, attack_class, scope, function, entry_point,
                    rationale, arch_summary):
        return f"hunt {attack_class} {scope}"

    def validate_prompt():
        return "validate"
    """
).strip()


FULL_PROFILE = MINIMAL_PROFILE + textwrap.dedent(
    """

    def dedupe_prompt():
        return "dedupe"

    def consolidate_prompt(output_dir, *, prior_runs_path=""):
        return f"consolidate {output_dir} prior={prior_runs_path}"
    """
)


def _write_profile(tmp_path: Path, body: str = MINIMAL_PROFILE) -> Path:
    p = tmp_path / "profile.py"
    p.write_text(body)
    return p


def _write_toml(tmp_path: Path, profile_path: Path, body: str = "") -> Path:
    header = textwrap.dedent(
        f"""
        [scan]
        prompt_profile = "{profile_path}"
        """
    ).strip()
    p = tmp_path / "config.toml"
    p.write_text(header + "\n" + body)
    return p


# ---------------------------------------------------------------------------
# Python profile loading
# ---------------------------------------------------------------------------


class TestLoadPythonProfile:
    def test_minimal_profile(self, tmp_path):
        cfg = load_config(str(_write_profile(tmp_path)))
        assert cfg.recon_prompt() == "recon prior="
        assert cfg.recon_prompt(prior_runs_path="/x") == "recon prior=/x"
        assert cfg.validate_prompt() == "validate"
        assert not cfg.has_dedupe
        assert not cfg.has_consolidate

    def test_full_profile(self, tmp_path):
        cfg = load_config(str(_write_profile(tmp_path, FULL_PROFILE)))
        assert cfg.has_dedupe
        assert cfg.has_consolidate
        assert cfg.dedupe_prompt() == "dedupe"
        assert cfg.consolidate_prompt(Path("/out")) == "consolidate /out prior="
        assert (
            cfg.consolidate_prompt(Path("/out"), prior_runs_path="/p")
            == "consolidate /out prior=/p"
        )

    def test_builtin_profile_by_name(self):
        # Builtin profile in src/vuln_scanner/configs/vuln_scan.py
        cfg = load_config("vuln_scan")
        assert isinstance(cfg.recon_prompt(), str)
        assert cfg.branch_prefix == "vuln-scan"

    def test_missing_required_prompt(self, tmp_path):
        p = tmp_path / "bad.py"
        p.write_text("def recon_prompt(): return 'r'\n")
        with pytest.raises(SystemExit):
            load_config(str(p))

    def test_unknown_profile_name(self):
        with pytest.raises(SystemExit):
            load_config("nope-does-not-exist")


# ---------------------------------------------------------------------------
# TOML overlay
# ---------------------------------------------------------------------------


class TestTomlOverlay:
    def test_defaults_when_only_profile_set(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = _write_toml(tmp_path, profile)
        cfg = load_config(str(toml))

        assert cfg.agent == "claude"
        assert cfg.branch_prefix == "vuln-scan"
        assert cfg.max_tasks == 0
        assert cfg.task_timeout == 0
        assert cfg.recon_model is None
        assert cfg.recon_output == "HUNT_QUEUE.json"

    def test_scan_section(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = _write_toml(
            tmp_path,
            profile,
            textwrap.dedent(
                """
                [scan]
                branch_prefix = "audit"
                max_tasks = 50
                task_timeout = 1200

                [scan.task_timeouts]
                hunt = 900
                validate = 600
                """
            ),
        )
        # We have to re-write because _write_toml already added [scan]
        # — patch by writing fresh:
        toml.write_text(textwrap.dedent(
            f"""
            [scan]
            prompt_profile = "{profile}"
            branch_prefix = "audit"
            max_tasks = 50
            task_timeout = 1200

            [scan.task_timeouts]
            hunt = 900
            validate = 600
            """
        ).strip())

        cfg = load_config(str(toml))
        assert cfg.branch_prefix == "audit"
        assert cfg.max_tasks == 50
        assert cfg.task_timeout == 1200
        assert cfg.task_timeouts == {"hunt": 900, "validate": 600}

    def test_agent_backend_and_flags(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = tmp_path / "c.toml"
        toml.write_text(textwrap.dedent(
            f"""
            [scan]
            prompt_profile = "{profile}"

            [agent]
            backend = "pi"
            flags = "--verbose --thinking high"
            """
        ).strip())
        cfg = load_config(str(toml))
        assert cfg.agent == "pi"
        assert cfg.agent_flags == "--verbose --thinking high"

    def test_nested_model_overrides(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = tmp_path / "c.toml"
        toml.write_text(textwrap.dedent(
            f"""
            [scan]
            prompt_profile = "{profile}"

            [agent.models]
            recon    = "model-a"
            hunt     = "model-b"
            validate = "model-c"
            dedupe   = "model-d"
            """
        ).strip())
        cfg = load_config(str(toml))
        assert cfg.recon_model == "model-a"
        assert cfg.hunt_model == "model-b"
        assert cfg.validate_model == "model-c"
        assert cfg.dedupe_model == "model-d"
        # not set -> remains None
        assert cfg.consolidate_model is None

    def test_flat_model_keys_supported(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = tmp_path / "c.toml"
        toml.write_text(textwrap.dedent(
            f"""
            [scan]
            prompt_profile = "{profile}"

            [agent]
            model_recon = "flat-recon"
            model_hunt  = "flat-hunt"
            """
        ).strip())
        cfg = load_config(str(toml))
        assert cfg.recon_model == "flat-recon"
        assert cfg.hunt_model == "flat-hunt"

    def test_attack_classes_top_level(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = tmp_path / "c.toml"
        toml.write_text(textwrap.dedent(
            f"""
            attack_classes = ["sql_injection", "xss"]

            [scan]
            prompt_profile = "{profile}"
            """
        ).strip())
        cfg = load_config(str(toml))
        assert cfg.attack_classes == ["sql_injection", "xss"]

    def test_output_filename_overrides(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = tmp_path / "c.toml"
        toml.write_text(textwrap.dedent(
            f"""
            [scan]
            prompt_profile = "{profile}"

            [output]
            recon = "ARCH.json"
            hunt  = "BUG.md"
            """
        ).strip())
        cfg = load_config(str(toml))
        assert cfg.recon_output == "ARCH.json"
        assert cfg.hunt_output == "BUG.md"
        # untouched
        assert cfg.validate_output == "VERIFICATION.md"

    def test_files_section(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = tmp_path / "c.toml"
        toml.write_text(textwrap.dedent(
            f"""
            [scan]
            prompt_profile = "{profile}"

            [files]
            extensions = "py,rs"
            exclude_dirs = ["target", "build"]
            """
        ).strip())
        cfg = load_config(str(toml))
        assert cfg.extensions == "py,rs"
        assert cfg.exclude_dirs == {"target", "build"}


# ---------------------------------------------------------------------------
# Custom backends via TOML
# ---------------------------------------------------------------------------


class TestCustomBackendsFromToml:
    def test_register_custom_backend(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = tmp_path / "c.toml"
        toml.write_text(textwrap.dedent(
            f"""
            [scan]
            prompt_profile = "{profile}"

            [agent]
            backend = "gemini-test"

            [agent.backends.gemini-test]
            executable  = "gemini-cli"
            prompt_flag = "--prompt"
            model_flag  = "--model"
            extra_args  = ["--yes"]
            """
        ).strip())

        try:
            cfg = load_config(str(toml))
            assert cfg.agent == "gemini-test"
            backend = BACKENDS["gemini-test"]
            assert isinstance(backend, CommandBackend)
            cmd = backend.build_command("hi", model="gp", flags="")
            assert cmd == [
                "gemini-cli",
                "--yes",
                "--model",
                "gp",
                "--prompt",
                "hi",
            ]
        finally:
            BACKENDS.pop("gemini-test", None)

    def test_invalid_backend_definition_exits(self, tmp_path):
        profile = _write_profile(tmp_path)
        toml = tmp_path / "c.toml"
        toml.write_text(textwrap.dedent(
            f"""
            [scan]
            prompt_profile = "{profile}"

            [agent.backends.broken]
            prompt_flag = "-p"
            """
        ).strip())
        with pytest.raises(SystemExit):
            load_config(str(toml))

    def test_builtin_backends_not_clobbered(self):
        # Sanity: after all the above test munging, the built-ins are intact.
        assert isinstance(BACKENDS["claude"], ClaudeBackend)


# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------


class TestTimeoutFor:
    def _cfg(self, tmp_path, *, default: int, overrides: dict[str, int] | None = None):
        cfg = load_config(str(_write_profile(tmp_path)))
        cfg.task_timeout = default
        cfg.task_timeouts = overrides or {}
        return cfg

    def test_no_default_no_override(self, tmp_path):
        cfg = self._cfg(tmp_path, default=0)
        assert cfg.timeout_for("hunt") is None

    def test_default_used_when_no_override(self, tmp_path):
        cfg = self._cfg(tmp_path, default=600)
        assert cfg.timeout_for("hunt") == 600

    def test_per_phase_override_wins(self, tmp_path):
        cfg = self._cfg(tmp_path, default=600, overrides={"hunt": 900})
        assert cfg.timeout_for("hunt") == 900
        assert cfg.timeout_for("validate") == 600

    def test_zero_override_means_no_timeout(self, tmp_path):
        # An explicit 0 in task_timeouts disables the global default for that phase.
        cfg = self._cfg(tmp_path, default=600, overrides={"hunt": 0})
        assert cfg.timeout_for("hunt") is None
        assert cfg.timeout_for("validate") == 600


# ---------------------------------------------------------------------------
# Model selection
# ---------------------------------------------------------------------------


class TestModelFor:
    def test_model_for_unset(self, tmp_path):
        cfg = load_config(str(_write_profile(tmp_path)))
        for phase in ("recon", "hunt", "validate", "dedupe", "consolidate"):
            assert cfg.model_for(phase) is None

    def test_model_for_set(self, tmp_path):
        cfg = load_config(str(_write_profile(tmp_path)))
        cfg.hunt_model = "claude-sonnet-4-6"
        assert cfg.model_for("hunt") == "claude-sonnet-4-6"
        assert cfg.model_for("recon") is None

    def test_model_for_unknown_phase(self, tmp_path):
        cfg = load_config(str(_write_profile(tmp_path)))
        # unknown phase -> None (no attribute, getattr default)
        assert cfg.model_for("gapfill") is None


# ---------------------------------------------------------------------------
# Config object construction directly from a module (no I/O)
# ---------------------------------------------------------------------------


class TestDumpEffectiveToml:
    def test_round_trips_through_loader(self, tmp_path):
        """Snapshot then re-load — settings must survive the round trip."""
        import tomllib

        profile = _write_profile(tmp_path)
        toml = tmp_path / "c.toml"
        toml.write_text(textwrap.dedent(
            f"""
            attack_classes = ["sql_injection", "xss"]

            [scan]
            prompt_profile = "{profile}"
            branch_prefix = "audit"
            max_tasks = 7
            task_timeout = 1200

            [scan.task_timeouts]
            hunt = 900

            [agent]
            backend = "pi"
            flags = "--verbose"

            [agent.models]
            hunt = "model-x"

            [output]
            recon = "ARCH.json"

            [files]
            extensions = "py,rs"
            exclude_dirs = ["target", "build"]
            """
        ).strip())
        cfg = load_config(str(toml))

        snapshot = cfg.dump_effective_toml()
        data = tomllib.loads(snapshot)

        assert data["attack_classes"] == ["sql_injection", "xss"]
        assert data["scan"]["branch_prefix"] == "audit"
        assert data["scan"]["max_tasks"] == 7
        assert data["scan"]["task_timeout"] == 1200
        assert data["scan"]["task_timeouts"] == {"hunt": 900}
        assert data["agent"]["backend"] == "pi"
        assert data["agent"]["flags"] == "--verbose"
        assert data["agent"]["models"] == {"hunt": "model-x"}
        assert data["output"]["recon"] == "ARCH.json"
        assert data["files"]["extensions"] == "py,rs"
        assert set(data["files"]["exclude_dirs"]) == {"target", "build"}

    def test_omits_models_section_when_none_configured(self, tmp_path):
        import tomllib
        cfg = load_config(str(_write_profile(tmp_path)))
        data = tomllib.loads(cfg.dump_effective_toml())
        assert "models" not in data.get("agent", {})


class TestConfigFromModule:
    def test_defaults_from_minimal_module(self, tmp_path):
        cfg = load_config(str(_write_profile(tmp_path)))
        assert cfg.agent == "claude"
        assert cfg.agent_flags == ""
        assert cfg.branch_prefix == "vuln-scan"
        assert cfg.max_tasks == 0
        assert isinstance(cfg.attack_classes, list)
        assert "sql_injection" in cfg.attack_classes

    def test_hunt_prompt_kwargs_passed_through(self, tmp_path):
        cfg = load_config(str(_write_profile(tmp_path)))
        assert cfg.hunt_prompt(
            attack_class="sqli",
            scope="api",
            function="lookup",
            entry_point="/users",
            rationale="user input",
            arch_summary="rest",
        ) == "hunt sqli api"
