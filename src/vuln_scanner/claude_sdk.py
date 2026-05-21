"""Claude Agent SDK backend — runs the agent in-process via claude-agent-sdk.

The module-level import of ``claude_agent_sdk`` triggers an ImportError at
load time if the package isn't installed. ``claude.py`` swallows that to keep
the subprocess backends usable without the SDK installed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

from taskrunner.core import RunContext

if TYPE_CHECKING:
    from vuln_scanner.claude import RunResult


class ClaudeSDKBackend:
    """Uses the in-process claude-agent-sdk library instead of subprocessing.

    Differences vs. ClaudeBackend (the CLI wrapper):
    - Streams structured events (assistant turns, tool calls, the final
      ResultMessage with token/cost info) into the log file, one repr per line.
    - Per-task timeout enforced via ``asyncio.wait_for`` rather than killing a
      child process group.
    - No subprocess to register with the runner's signal handler; SIGINT
      propagates via asyncio's default handler.

    ``flags`` is a CLI-string concept and is ignored by this backend.
    """

    supports_session_id = True

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
        # Local import to avoid a circular import at module load.
        from vuln_scanner.claude import RunResult

        log_path.parent.mkdir(parents=True, exist_ok=True)

        options = ClaudeAgentOptions(
            cwd=str(cwd),
            model=model,
            permission_mode="bypassPermissions",
            session_id=session_id,
        )

        # Mutable holder so _run() can hand back the final ResultMessage.
        final: list[ResultMessage] = []

        async def _run() -> bool:
            with open(log_path, "w") as log_file:
                success = False
                async for msg in query(prompt=prompt, options=options):
                    log_file.write(f"{msg!r}\n")
                    log_file.flush()
                    if isinstance(msg, ResultMessage):
                        success = msg.subtype == "success"
                        final.append(msg)
                return success

        timeout = ctx.task.timeout if ctx and ctx.task.timeout else None
        try:
            if timeout:
                ok = asyncio.run(asyncio.wait_for(_run(), timeout=timeout))
            else:
                ok = asyncio.run(_run())
        except TimeoutError:
            ok = False

        sdk_options = {
            "cwd": str(cwd),
            "model": model,
            "permission_mode": "bypassPermissions",
            "session_id": session_id,
        }

        if not final:
            return RunResult(
                success=ok,
                session_id=session_id or "",
                sdk_options=sdk_options,
                model_used=model,
            )

        res = final[-1]
        # model_usage is a dict keyed by model id; pick the primary key.
        model_used = model
        if res.model_usage:
            model_used = next(iter(res.model_usage.keys()))

        return RunResult(
            success=ok,
            session_id=res.session_id or session_id or "",
            sdk_options=sdk_options,
            model_used=model_used,
            duration_ms=res.duration_ms,
            total_cost_usd=res.total_cost_usd,
            num_turns=res.num_turns,
            extra={"model_usage": res.model_usage} if res.model_usage else {},
        )
