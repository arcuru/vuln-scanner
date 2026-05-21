"""Agent invocation — dispatches to the configured backend via a pluggable protocol.

Built-in backends:
  - claude       Subprocesses the Claude Code CLI (`claude -p`)
  - claude-sdk   Uses the in-process Claude Agent SDK Python library
  - pi           Subprocesses the Oh My Pi agent CLI

Additional CLI-based backends can be defined in TOML config under
[agent.backends.<name>] — no code changes needed.
"""

from __future__ import annotations

import os
import signal
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from taskrunner.core import RunContext

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    """Outcome + provenance of one agent invocation.

    Truthy iff ``success`` so existing ``ok = backend.run(...)`` /
    ``if not ok:`` callers keep working.

    Fields beyond ``success`` are best-effort — populated when the backend
    knows them, ``None`` otherwise. Workers persist this into a per-task
    ``task.toml`` for post-hoc reproducibility.
    """

    success: bool
    session_id: str | None = None
    command: list[str] | None = None  # argv for subprocess backends
    sdk_options: dict[str, Any] | None = None  # for in-process SDK backend
    model_used: str | None = None  # actual model the agent reports having used
    duration_ms: int | None = None
    total_cost_usd: float | None = None
    num_turns: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.success


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------


class Backend(Protocol):
    """Runs the agent for one task. Implementations may subprocess a CLI or
    call an in-process library (e.g. claude-agent-sdk).
    """

    def run(
        self,
        *,
        cwd: Path,
        prompt: str,
        log_path: Path,
        ctx: RunContext | None,
        model: str | None,
        flags: str,
        session_id: str | None = None,
    ) -> RunResult:
        """Execute the agent. Returns a RunResult (truthy on success).

        Implementations are responsible for:
        - writing stdout/stderr (or equivalent event stream) to ``log_path``
        - respecting ``ctx.task.timeout`` if set (and ``ctx`` non-None)
        - registering processes with ``ctx.runner`` so SIGINT propagates
        - propagating ``session_id`` to the underlying agent when supported
          (so transcripts can be retrieved by UUID after the run)
        """
        ...


# ---------------------------------------------------------------------------
# Subprocess base: backends that build an argv and Popen it
# ---------------------------------------------------------------------------


class _SubprocessBackend:
    """Mixin providing a default ``run()`` that wraps a CLI invocation.

    Subclasses override ``build_command()`` to produce the argv.
    """

    # Override in subclasses that support session UUIDs (e.g. ClaudeBackend).
    supports_session_id: bool = False

    def build_command(
        self,
        prompt: str,
        *,
        model: str | None,
        flags: str,
        session_id: str | None = None,
    ) -> list[str]:
        raise NotImplementedError

    def run(
        self,
        *,
        cwd: Path,
        prompt: str,
        log_path: Path,
        ctx: RunContext | None,
        model: str | None,
        flags: str,
        session_id: str | None = None,
    ) -> RunResult:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = self.build_command(
            prompt, model=model, flags=flags, session_id=session_id,
        )

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
                return RunResult(
                    success=False,
                    session_id=session_id if self.supports_session_id else None,
                    command=cmd,
                    model_used=model,
                )
            finally:
                if ctx:
                    ctx.runner.unregister_process(proc)

        return RunResult(
            success=proc.returncode == 0,
            session_id=session_id if self.supports_session_id else None,
            command=cmd,
            model_used=model,
        )


# ---------------------------------------------------------------------------
# Built-in backends
# ---------------------------------------------------------------------------


class ClaudeBackend(_SubprocessBackend):
    """Claude Code CLI (https://github.com/anthropics/claude-code)."""

    supports_session_id = True

    def build_command(
        self,
        prompt: str,
        *,
        model: str | None,
        flags: str,
        session_id: str | None = None,
    ) -> list[str]:
        cmd = ["claude", "--dangerously-skip-permissions"]
        if session_id:
            cmd.extend(["--session-id", session_id])
        if model:
            cmd.extend(["--model", model])
        if flags:
            cmd.extend(flags.split())
        cmd.extend(["-p", prompt])
        return cmd


class PiBackend(_SubprocessBackend):
    """Oh My Pi agent CLI."""

    def build_command(
        self,
        prompt: str,
        *,
        model: str | None,
        flags: str,
        session_id: str | None = None,
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
class CommandBackend(_SubprocessBackend):
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
        self,
        prompt: str,
        *,
        model: str | None,
        flags: str,
        session_id: str | None = None,
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

# Lazily register claude-sdk so an import error in the SDK doesn't break the
# subprocess backends. The SDK module's import-time check decides whether the
# package is installed.
try:
    from vuln_scanner.claude_sdk import ClaudeSDKBackend

    BACKENDS["claude-sdk"] = ClaudeSDKBackend()
except ImportError:
    pass


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
    session_id: str | None = None,
) -> RunResult:
    """Run the configured agent in the given directory.

    Args:
        cwd: Working directory for the agent process.
        prompt: The prompt text (passed via backend-specific flags).
        log_path: Path to write stdout/stderr.
        ctx: Optional RunContext for process lifecycle management.
        agent: Backend name — key in BACKENDS dict.
        agent_flags: Space-separated extra flags from config.
        model: Optional model name override (None = backend default).
        session_id: Optional UUID to pin the agent's session (so the
            transcript can be located by ID afterwards). If omitted, one is
            generated; backends that don't support session IDs ignore it.

    Returns a :class:`RunResult` (truthy on success).

    If ctx is provided, registers the process for graceful cleanup on interrupt.
    """
    try:
        backend = BACKENDS[agent]
    except KeyError:
        raise ValueError(
            f"Unknown agent backend: {agent!r}. "
            f"Available: {', '.join(sorted(BACKENDS))}"
        ) from None

    if session_id is None:
        session_id = str(uuid.uuid4())

    return backend.run(
        cwd=cwd,
        prompt=prompt,
        log_path=log_path,
        ctx=ctx,
        model=model,
        flags=agent_flags,
        session_id=session_id,
    )
