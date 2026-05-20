"""Agent invocation — dispatches to the configured backend via a pluggable protocol.

Built-in backends (claude, pi) are Python classes.  Additional backends can be
defined in TOML config under [agent.backends.<name>] — no code changes needed.
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from taskrunner.core import RunContext

# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------


class Backend(Protocol):
    """Knows how to build a command for a specific agent CLI."""

    def build_command(
        self, prompt: str, *, model: str | None, flags: str,
    ) -> list[str]:
        """Return the full argv list for this backend.

        Args:
            prompt: The prompt text (passed via the backend's prompt flag).
            model:  Optional model name override (None = use backend default).
            flags:  Extra space-separated flags string from config.
        """
        ...


# ---------------------------------------------------------------------------
# Built-in backends
# ---------------------------------------------------------------------------


class ClaudeBackend:
    """Claude Code CLI (https://github.com/anthropics/claude-code)."""

    def build_command(
        self, prompt: str, *, model: str | None, flags: str,
    ) -> list[str]:
        cmd = ["claude", "--dangerously-skip-permissions"]
        if model:
            cmd.extend(["--model", model])
        if flags:
            cmd.extend(flags.split())
        cmd.extend(["-p", prompt])
        return cmd


class PiBackend:
    """Oh My Pi agent CLI."""

    def build_command(
        self, prompt: str, *, model: str | None, flags: str,
    ) -> list[str]:
        cmd = ["pi"]
        if model:
            cmd.extend(["--model", model])
        if flags:
            cmd.extend(flags.split())
        cmd.extend(["-p", prompt])
        return cmd


# ---------------------------------------------------------------------------
# Config-driven backend — no Python code required.
# ---------------------------------------------------------------------------


@dataclass
class CommandBackend:
    """Backend defined entirely from config (TOML or dict).

    Example TOML::

        [agent.backends.gemini]
        executable = "gemini-cli"
        model_flag = "--model"
        prompt_flag = "--prompt"
        extra_args = ["--yes"]

    Attributes:
        executable:  Binary name or path.
        model_flag:  Flag placed before the model name (omit if unsupported).
        prompt_flag: Flag placed before the prompt text (required).
        extra_args:  Always-on arguments inserted before model/prompt/flags.
    """

    executable: str
    prompt_flag: str
    model_flag: str | None = None
    extra_args: list[str] | None = None

    def build_command(
        self, prompt: str, *, model: str | None, flags: str,
    ) -> list[str]:
        cmd = [self.executable]
        if self.extra_args:
            cmd.extend(self.extra_args)
        if model and self.model_flag:
            cmd.extend([self.model_flag, model])
        if flags:
            cmd.extend(flags.split())
        cmd.extend([self.prompt_flag, prompt])
        return cmd

    @classmethod
    def from_dict(cls, name: str, data: dict[str, object]) -> CommandBackend:
        """Create from a dict (as parsed from TOML).

        ``name`` is only used for error messages.
        """
        executable = data.get("executable")
        if not executable or not isinstance(executable, str):
            raise ValueError(
                f"[agent.backends.{name}] requires 'executable' (string)"
            )

        prompt_flag = data.get("prompt_flag")
        if not prompt_flag or not isinstance(prompt_flag, str):
            raise ValueError(
                f"[agent.backends.{name}] requires 'prompt_flag' (string)"
            )

        model_flag = data.get("model_flag")
        if model_flag is not None and not isinstance(model_flag, str):
            raise ValueError(
                f"[agent.backends.{name}] 'model_flag' must be a string or omitted"
            )

        extra_args = data.get("extra_args")
        if extra_args is not None:
            if not isinstance(extra_args, list) or not all(
                isinstance(a, str) for a in extra_args
            ):
                raise ValueError(
                    f"[agent.backends.{name}] 'extra_args' must be a list of strings"
                )

        return cls(
            executable=executable,
            prompt_flag=prompt_flag,
            model_flag=model_flag,
            extra_args=extra_args,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


BACKENDS: dict[str, Backend] = {
    "claude": ClaudeBackend(),
    "pi": PiBackend(),
}


def register_backend(name: str, backend: Backend) -> None:
    """Register a backend (called by config loader for TOML-defined backends)."""
    BACKENDS[name] = backend


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_agent(
    cwd: Path,
    prompt: str,
    log_path: Path,
    ctx: RunContext | None = None,
    *,
    agent: str = "claude",
    agent_flags: str = "",
    model: str | None = None,
) -> bool:
    """Run the configured agent in the given directory.

    Args:
        cwd: Working directory for the agent process.
        prompt: The prompt text (passed via backend-specific flags).
        log_path: Path to write stdout/stderr.
        ctx: Optional RunContext for process lifecycle management.
        agent: Backend name — key in BACKENDS dict.
        agent_flags: Space-separated extra flags from config.
        model: Optional model name override (None = backend default).

    If ctx is provided, registers the process for graceful cleanup on interrupt.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        backend = BACKENDS[agent]
    except KeyError:
        raise ValueError(
            f"Unknown agent backend: {agent!r}. "
            f"Available: {', '.join(sorted(BACKENDS))}"
        ) from None

    cmd = backend.build_command(prompt, model=model, flags=agent_flags)

    with open(log_path, "wb") as log_file:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if ctx:
            ctx.runner.register_process(proc)
        try:
            effective_timeout = None
            if ctx and ctx.task.timeout:
                effective_timeout = ctx.task.timeout
            proc.wait(timeout=effective_timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=5)
            return False
        finally:
            if ctx:
                ctx.runner.unregister_process(proc)

    return proc.returncode == 0
