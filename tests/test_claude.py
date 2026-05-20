"""Tests for backend command construction and registry lookup."""

from __future__ import annotations

import pytest

from vuln_scanner.claude import (
    BACKENDS,
    ClaudeBackend,
    CommandBackend,
    PiBackend,
    register_backend,
    run_agent,
)


class TestClaudeBackend:
    def test_minimal(self):
        cmd = ClaudeBackend().build_command("hi", model=None, flags="")
        assert cmd == ["claude", "--dangerously-skip-permissions", "-p", "hi"]

    def test_with_model_and_flags(self):
        cmd = ClaudeBackend().build_command(
            "do x", model="claude-opus-4-7", flags="--verbose --thinking high"
        )
        assert cmd == [
            "claude",
            "--dangerously-skip-permissions",
            "--model",
            "claude-opus-4-7",
            "--verbose",
            "--thinking",
            "high",
            "-p",
            "do x",
        ]

    def test_prompt_is_last_arg(self):
        # Prompts can contain spaces / shell metacharacters -- they must arrive
        # as a single argv element, not be word-split.
        cmd = ClaudeBackend().build_command(
            "find $(bugs); rm -rf /", model=None, flags="--verbose"
        )
        assert cmd[-1] == "find $(bugs); rm -rf /"
        assert cmd[-2] == "-p"


class TestPiBackend:
    def test_minimal(self):
        cmd = PiBackend().build_command("hi", model=None, flags="")
        assert cmd == ["pi", "-p", "hi"]

    def test_with_model(self):
        cmd = PiBackend().build_command(
            "hi", model="anthropic/claude-sonnet-4", flags=""
        )
        assert cmd == ["pi", "--model", "anthropic/claude-sonnet-4", "-p", "hi"]


class TestCommandBackend:
    def test_minimal(self):
        b = CommandBackend(executable="tool", prompt_flag="--prompt")
        assert b.build_command("hi", model=None, flags="") == [
            "tool",
            "--prompt",
            "hi",
        ]

    def test_full(self):
        b = CommandBackend(
            executable="gemini-cli",
            prompt_flag="--prompt",
            model_flag="--model",
            extra_args=["--yes", "--no-color"],
        )
        cmd = b.build_command("hi", model="gemini-pro", flags="--verbose")
        assert cmd == [
            "gemini-cli",
            "--yes",
            "--no-color",
            "--model",
            "gemini-pro",
            "--verbose",
            "--prompt",
            "hi",
        ]

    def test_model_ignored_when_no_model_flag(self):
        b = CommandBackend(executable="tool", prompt_flag="-p", model_flag=None)
        cmd = b.build_command("hi", model="some-model", flags="")
        # model is silently dropped because the backend has no model flag
        assert cmd == ["tool", "-p", "hi"]

    def test_no_model_omits_model_flag(self):
        b = CommandBackend(executable="tool", prompt_flag="-p", model_flag="--model")
        cmd = b.build_command("hi", model=None, flags="")
        assert "--model" not in cmd

    def test_empty_flags_string(self):
        b = CommandBackend(executable="tool", prompt_flag="-p")
        cmd = b.build_command("hi", model=None, flags="")
        # split("") would yield [""] -- guard ensures no empty arg sneaks in
        assert "" not in cmd


class TestCommandBackendFromDict:
    def test_minimal_required_fields(self):
        b = CommandBackend.from_dict("x", {"executable": "tool", "prompt_flag": "-p"})
        assert b.executable == "tool"
        assert b.prompt_flag == "-p"
        assert b.model_flag is None
        assert b.extra_args is None

    def test_full(self):
        b = CommandBackend.from_dict(
            "gemini",
            {
                "executable": "gemini-cli",
                "prompt_flag": "--prompt",
                "model_flag": "--model",
                "extra_args": ["--yes"],
            },
        )
        assert b.model_flag == "--model"
        assert b.extra_args == ["--yes"]

    def test_missing_executable(self):
        with pytest.raises(ValueError, match="executable"):
            CommandBackend.from_dict("x", {"prompt_flag": "-p"})

    def test_missing_prompt_flag(self):
        with pytest.raises(ValueError, match="prompt_flag"):
            CommandBackend.from_dict("x", {"executable": "tool"})

    def test_executable_wrong_type(self):
        with pytest.raises(ValueError, match="executable"):
            CommandBackend.from_dict("x", {"executable": 42, "prompt_flag": "-p"})

    def test_model_flag_wrong_type(self):
        with pytest.raises(ValueError, match="model_flag"):
            CommandBackend.from_dict(
                "x", {"executable": "t", "prompt_flag": "-p", "model_flag": 1}
            )

    def test_extra_args_wrong_shape(self):
        with pytest.raises(ValueError, match="extra_args"):
            CommandBackend.from_dict(
                "x",
                {"executable": "t", "prompt_flag": "-p", "extra_args": "not-a-list"},
            )

    def test_extra_args_wrong_element_type(self):
        with pytest.raises(ValueError, match="extra_args"):
            CommandBackend.from_dict(
                "x",
                {"executable": "t", "prompt_flag": "-p", "extra_args": ["ok", 2]},
            )

    def test_error_includes_backend_name(self):
        with pytest.raises(ValueError, match=r"\[agent\.backends\.gemini\]"):
            CommandBackend.from_dict("gemini", {})


class TestRegistry:
    def test_builtins_present(self):
        assert isinstance(BACKENDS["claude"], ClaudeBackend)
        assert isinstance(BACKENDS["pi"], PiBackend)

    def test_register_backend(self):
        b = CommandBackend(executable="my-cli", prompt_flag="-p")
        try:
            register_backend("mycli-test", b)
            assert BACKENDS["mycli-test"] is b
        finally:
            BACKENDS.pop("mycli-test", None)

    def test_run_agent_unknown_backend(self, tmp_path):
        with pytest.raises(ValueError, match="Unknown agent backend"):
            run_agent(
                tmp_path,
                "hi",
                tmp_path / "log",
                agent="does-not-exist",
            )
