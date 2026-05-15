"""Claude Code invocation helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path

from taskrunner.core import RunContext


def run_claude(cwd: Path, prompt: str, log_path: Path, ctx: RunContext | None = None) -> bool:
    """Run claude --dangerously-skip-permissions in the given directory.

    If ctx is provided, registers the process for graceful cleanup on interrupt.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as log_file:
        proc = subprocess.Popen(
            ["claude", "--dangerously-skip-permissions", "-p", prompt],
            cwd=str(cwd),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if ctx:
            ctx.runner.register_process(proc)
        try:
            proc.wait()
        finally:
            if ctx:
                ctx.runner.unregister_process(proc)

    return proc.returncode == 0
