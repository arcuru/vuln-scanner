"""CLI entry point for vuln-scanner.

Pipeline:
    recon → hunt → validate → dedupe → gapfill → hunt2 → validate2 → consolidate

- Recon produces architecture doc + structured hunt queue (HUNT_QUEUE.json)
- Hunt tasks are attack-class-scoped with iterative PoC loop
- Validate is adversarial — tries to DISPROVE findings
- Dedupe groups findings by root cause into FINDINGS.json
- Gapfill identifies coverage gaps and produces HUNT_QUEUE_2.json
- Hunt2/Validate2 re-run on gap-filling tasks
- Consolidate produces the final human-readable SUMMARY.md
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from taskrunner import Phase, Pipeline, SetupCallbacks, Task, TaskRunner, TaskStatus
from taskrunner.model import RunContext
from vuln_scanner.claude import run_agent
from vuln_scanner.config import Config, load_config
from vuln_scanner.files import find_source_files
from vuln_scanner.worktree import WorktreeSetup, slugify

logger = logging.getLogger("vuln-scanner")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_url(s: str) -> bool:
    """Return True if the string looks like a git URL."""
    parsed = urlparse(s)
    return parsed.scheme in ("http", "https", "ssh", "git") or s.startswith("git@")


def _clone_repo(url: str, dest: Path) -> Path:
    """Clone a git repo, returning the path to the cloned directory."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", url, str(dest)],
            check=True,
            stdout=sys.stderr,
            stderr=sys.stderr,
        )
    except subprocess.CalledProcessError:
        # Clean up the empty directory on failure
        try:
            dest.rmdir()
        except OSError:
            pass
        raise
    return dest


def _copy_task_outputs(ctx: RunContext, outputs: dict[str, str]) -> None:
    """Copy task output files from worktree root to the phase output directory.

    Task outputs are relative paths like 'task-id/FINDING.md'. The source
    file in the worktree is just the filename (e.g. FINDING.md).
    """
    for rel_path in outputs.values():
        filename = Path(rel_path).name
        src = ctx.work_dir / filename
        if src.exists():
            dest = ctx.output_dir / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)


def _read_queue_summary(queue_path: Path) -> str:
    """Extract architecture_summary from a hunt queue JSON file."""
    try:
        queue = json.loads(queue_path.read_text())
        if isinstance(queue, dict):
            return queue.get("architecture_summary", "")
        return ""
    except (json.JSONDecodeError, FileNotFoundError):
        return ""


# ---------------------------------------------------------------------------
# Worker factories
# ---------------------------------------------------------------------------


def _make_recon_worker(cfg: Config):
    """Recon worker: produce architecture doc + HUNT_QUEUE.json."""

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.recon_prompt()
        ok = run_agent(ctx.work_dir, prompt, ctx.log_path, ctx, agent=cfg.agent, agent_flags=cfg.agent_flags, model=cfg.recon_model)

        output_in_wt = ctx.work_dir / cfg.recon_output
        if output_in_wt.exists():
            shutil.copy2(output_in_wt, ctx.output_dir / cfg.recon_output)
            return True

        if not ok:
            task.error = "claude exited non-zero"
        else:
            task.error = f"{cfg.recon_output} not written by recon agent"
        return False

    return worker


def _make_hunt_worker(cfg: Config, *, model: str | None = None):
    """Hunt worker: attack-class-scoped vulnerability search with PoC loop.

    Reads architecture summary from the worktree's queue file (from recon),
    falling back to task.inputs["arch_summary"].
    """
    _model = model  # capture for closure

    def worker(task: Task, ctx: RunContext) -> bool:
        # Try to read architecture summary from worktree (inherited from recon)
        queue_path = ctx.work_dir / cfg.recon_output
        arch_summary = _read_queue_summary(queue_path)

        # Fall back to task inputs (used by hunt2 when no inherited queue)
        if not arch_summary:
            arch_summary = task.inputs.get("arch_summary", "")

        prompt = cfg.hunt_prompt(
            attack_class=task.metadata["attack_class"],
            scope=task.metadata["scope"],
            function=task.metadata.get("function", ""),
            entry_point=task.metadata.get("entry_point", ""),
            rationale=task.metadata.get("rationale", ""),
            arch_summary=arch_summary,
        )

        ok = run_agent(ctx.work_dir, prompt, ctx.log_path, ctx, agent=cfg.agent, agent_flags=cfg.agent_flags, model=_model or cfg.hunt_model)

        output_in_wt = ctx.work_dir / cfg.hunt_output
        if output_in_wt.exists():
            _copy_task_outputs(ctx, task.outputs)
            return True

        if not ok:
            task.error = "claude exited non-zero"
        else:
            task.error = f"{cfg.hunt_output} not written by hunt agent"
        return False

    return worker


def _make_validate_worker(cfg: Config, *, model: str | None = None):
    """Adversarial validate worker: disprove the hunter's finding."""
    _model = model  # capture for closure

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.validate_prompt()
        ok = run_agent(ctx.work_dir, prompt, ctx.log_path, ctx, agent=cfg.agent, agent_flags=cfg.agent_flags, model=_model or cfg.validate_model)

        output_in_wt = ctx.work_dir / cfg.validate_output
        if output_in_wt.exists():
            _copy_task_outputs(ctx, task.outputs)
            return True

        if not ok:
            task.error = "claude exited non-zero"
        else:
            task.error = f"{cfg.validate_output} not written by validate agent"
        return False

    return worker


def _make_dedupe_worker(cfg: Config, output_dir: Path, *, model: str | None = None):
    """Dedupe worker: group validated findings by root cause."""
    _model = model

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.dedupe_prompt()
        if prompt is None:
            task.error = "dedupe_prompt returned None"
            return False

        ok = run_agent(ctx.work_dir, prompt, ctx.log_path, ctx, agent=cfg.agent, agent_flags=cfg.agent_flags, model=_model or cfg.dedupe_model)

        output_in_wt = ctx.work_dir / cfg.dedupe_output
        if output_in_wt.exists():
            dest = ctx.output_dir / cfg.dedupe_output
            shutil.copy2(output_in_wt, dest)
            return True

        if not ok:
            task.error = "claude exited non-zero"
        else:
            task.error = f"{cfg.dedupe_output} not written by dedupe agent"
        return False

    return worker


def _make_gapfill_worker(cfg: Config, output_dir: Path, *, model: str | None = None):
    """Gapfill worker: identify coverage gaps and produce HUNT_QUEUE_2.json."""
    _model = model

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.gapfill_prompt()
        if prompt is None:
            task.error = "gapfill_prompt returned None"
            return False

        ok = run_agent(ctx.work_dir, prompt, ctx.log_path, ctx, agent=cfg.agent, agent_flags=cfg.agent_flags, model=_model or cfg.gapfill_model)

        output_in_wt = ctx.work_dir / cfg.gapfill_output
        if output_in_wt.exists():
            dest = ctx.output_dir / cfg.gapfill_output
            shutil.copy2(output_in_wt, dest)
            return True

        if not ok:
            task.error = "claude exited non-zero"
        else:
            task.error = f"{cfg.gapfill_output} not written by gapfill agent"
        return False

    return worker


def _make_consolidate_worker(cfg: Config, output_dir: Path, *, model: str | None = None):
    """Consolidation worker: merge all findings into a human-readable summary."""
    _model = model

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.consolidate_prompt(output_dir)
        if prompt is None:
            task.error = f"consolidate_prompt returned None (no dedupe output in {output_dir / 'dedupe'})"
            return False

        ok = run_agent(ctx.work_dir, prompt, ctx.log_path, ctx, agent=cfg.agent, agent_flags=cfg.agent_flags, model=_model or cfg.consolidate_model)

        output_in_wt = ctx.work_dir / cfg.consolidate_output
        if output_in_wt.exists():
            dest = ctx.output_dir / cfg.consolidate_output
            shutil.copy2(output_in_wt, dest)
            return True

        if not ok:
            task.error = "claude exited non-zero"
        else:
            task.error = f"{cfg.consolidate_output} not written by consolidate agent"
        return False

    return worker


# ---------------------------------------------------------------------------
# Pipeline construction
# ---------------------------------------------------------------------------


def build_pipeline(repo: Path, cfg: Config, output_dir: Path) -> Pipeline:
    """Build the full recon → hunt → validate → dedupe → gapfill → hunt2 → validate2 → consolidate pipeline."""

    phases: list[Phase] = []
    max_t = cfg.max_tasks

    # -- 1. Recon --
    recon_task = Task(
        id="recon",
        description="Recon — mapping architecture and attack surface",
        worker=_make_recon_worker(cfg),
        outputs={"queue": cfg.recon_output},
        timeout=cfg.timeout_for("recon"),
    )
    phases.append(Phase.fan_out(name="recon", tasks=[recon_task]))

    # -- 2. Hunt --
    hunt_worker = _make_hunt_worker(cfg)

    def make_hunt_tasks(prev_tasks: list[Task]) -> list[Task]:
        return _tasks_from_queue(
            queue_path=output_dir / "recon" / cfg.recon_output,
            worker=hunt_worker,
            cfg=cfg,
            parent_task="recon",
            parent_phase="recon",
            phase_name="hunt",
            max_tasks=max_t,
            timeout=cfg.timeout_for("hunt"),
        )

    phases.append(Phase.fan_out(name="hunt", tasks_from=make_hunt_tasks))

    # -- 3. Validate --
    validate_worker = _make_validate_worker(cfg)

    def make_validate_tasks(prev_tasks: list[Task]) -> list[Task]:
        return _make_validate_tasks_from(
            prev_tasks, validate_worker, cfg, "hunt", timeout=cfg.timeout_for("validate"),
        )
    phases.append(Phase.fan_out(name="validate", tasks_from=make_validate_tasks))

    # -- 4. Dedupe (optional) --
    if cfg.has_dedupe:
        phases.append(
            Phase.consolidate(
                name="dedupe",
                description="Deduplicating findings by root cause",
                worker=_make_dedupe_worker(cfg, output_dir),
                output=cfg.dedupe_output,
                timeout=cfg.timeout_for("dedupe"),
            )
        )

    # -- 5. Gapfill (optional) --
    if cfg.has_gapfill:
        phases.append(
            Phase.consolidate(
                name="gapfill",
                description="Identifying coverage gaps",
                worker=_make_gapfill_worker(cfg, output_dir),
                output=cfg.gapfill_output,
                timeout=cfg.timeout_for("gapfill"),
            )
        )

        # -- 6. Hunt2 (from gapfill queue) --
        hunt2_worker = _make_hunt_worker(cfg, model=cfg.hunt2_model)
        def make_hunt2_tasks(prev_tasks: list[Task]) -> list[Task]:
            return _tasks_from_queue(
                queue_path=output_dir / "gapfill" / cfg.gapfill_output,
                worker=hunt2_worker,
                cfg=cfg,
                parent_task=None,
                parent_phase=None,
                phase_name="hunt2",
                max_tasks=max_t,
                timeout=cfg.timeout_for("hunt2"),
            )

        phases.append(Phase.fan_out(name="hunt2", tasks_from=make_hunt2_tasks))

        # -- 7. Validate2 --
        validate2_worker = _make_validate_worker(cfg, model=cfg.validate2_model)
        def make_validate2_tasks(prev_tasks: list[Task]) -> list[Task]:
            return _make_validate_tasks_from(
                prev_tasks, validate2_worker, cfg, "hunt2", timeout=cfg.timeout_for("validate2"),
            )

        phases.append(Phase.fan_out(name="validate2", tasks_from=make_validate2_tasks))

    # -- 8. Consolidate (optional) --
    if cfg.has_consolidate:
        phases.append(
            Phase.consolidate(
                name="consolidate",
                description="Writing final report",
                worker=_make_consolidate_worker(cfg, output_dir),
                output=cfg.consolidate_output,
                timeout=cfg.timeout_for("consolidate"),
            )
        )

    return Pipeline(phases=phases)


# ---------------------------------------------------------------------------
# Task factories (shared logic)
# ---------------------------------------------------------------------------


def _tasks_from_queue(
    *,
    queue_path: Path,
    worker,
    cfg: Config,
    parent_task: str | None,
    parent_phase: str | None,
    phase_name: str,
    max_tasks: int = 0,
    timeout: int | None = None,
) -> list[Task]:
    """Create hunt tasks from a HUNT_QUEUE.json file.

    Used by both hunt (from recon queue) and hunt2 (from gapfill queue).
    If max_tasks > 0, only the first N tasks are returned.
    """
    if not queue_path.exists():
        logger.warning(f"Queue file not found: {queue_path}")
        return []

    try:
        queue = json.loads(queue_path.read_text())
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Failed to parse queue {queue_path}: {e}")
        return []

    arch_summary = queue.get("architecture_summary", "")
    entries = queue.get("tasks", [])
    if not entries:
        logger.warning(f"Queue {queue_path} contains no tasks")
        return []

    tasks = []
    for entry in entries:
        attack_class = entry.get("attack_class", "")
        scope = entry.get("scope", "")
        if not attack_class or not scope:
            logger.warning(f"Skipping malformed queue entry: {entry}")
            continue

        task_id = entry.get("id") or f"{attack_class}__{slugify(scope)}"

        meta = {
            "attack_class": attack_class,
            "scope": scope,
            "function": entry.get("function", ""),
            "entry_point": entry.get("entry_point", ""),
            "rationale": entry.get("rationale", ""),
        }
        if parent_phase:
            meta["parent_phase"] = parent_phase

        tasks.append(
            Task(
                id=task_id,
                description=f"Hunt {attack_class} in {scope}",
                worker=worker,
                inputs={"arch_summary": arch_summary},
                outputs={"finding": f"{task_id}/{cfg.hunt_output}"},
                metadata=meta,
                parent_task=parent_task,
                timeout=timeout,
            )
        )

    if max_tasks and len(tasks) > max_tasks:
        logger.info(
            f"Truncating {phase_name} tasks from {len(tasks)} to {max_tasks} (max_tasks limit)"
        )
        tasks = tasks[:max_tasks]

    logger.info(f"Created {len(tasks)} tasks for {phase_name} from {queue_path}")
    return tasks


def _make_validate_tasks_from(
    prev_tasks: list[Task],
    validate_worker,
    cfg: Config,
    parent_phase: str,
    timeout: int | None = None,
) -> list[Task]:
    """Create validate tasks for each completed hunt/hunt2 task."""
    validate_tasks = []
    for t in prev_tasks:
        if t.status != TaskStatus.COMPLETED:
            continue
        validate_tasks.append(
            Task(
                id=f"validate-{t.id}",
                description=f"Validate {t.description.removeprefix('Hunt ')}",
                worker=validate_worker,
                outputs={"verification": f"{t.id}/{cfg.validate_output}"},
                parent_task=t.id,
                metadata={
                    "parent_phase": parent_phase,
                    "attack_class": t.metadata.get("attack_class", ""),
                    "scope": t.metadata.get("scope", ""),
                },
                timeout=timeout,
            )
        )
    return validate_tasks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-phase LLM vulnerability scanner — "
                    "recon → hunt → validate → dedupe → gapfill → hunt2 → validate2 → consolidate",
    )
    parser.add_argument(
        "repo",
        help="Path to local git repo, or URL to clone (https://... or git@...)",
    )
    parser.add_argument(
        "-c", "--config", required=True,
        help="Config name (builtin) or path to config .py file",
    )
    parser.add_argument(
        "-j", "--jobs", type=int, default=4,
        help="Number of parallel workers (default: 4)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    console = Console(stderr=True)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    cfg = load_config(args.config)

    # Resolve repo — clone if URL, otherwise use local path
    scan_dir = Path.cwd()
    if _is_url(args.repo):
        repo_name = args.repo.rstrip("/").split("/")[-1].removesuffix(".git")
        repo = scan_dir / repo_name
        if repo.exists():
            console.print(f"[yellow]Repo already exists at {repo}, using existing[/yellow]")
        else:
            console.print(f"[bold]Cloning {args.repo} → {repo}...[/bold]")
            _clone_repo(args.repo, repo)
            console.print()
    else:
        repo = Path(args.repo).resolve()
        if not repo.is_dir():
            console.print(f"[red]Directory not found: {repo}[/red]")
            sys.exit(1)

    output_dir = scan_dir / "output"
    worktree_dir = scan_dir / "worktrees"
    logs_dir = output_dir / "logs"

    for d in [output_dir, worktree_dir, logs_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # Show config summary
    source_files = find_source_files(repo, cfg.extensions, cfg.exclude_dirs)
    phases_list = ["recon", "hunt", "validate"]
    if cfg.has_dedupe:
        phases_list.append("dedupe")
    if cfg.has_gapfill:
        phases_list.extend(["gapfill", "hunt2", "validate2"])
    if cfg.has_consolidate:
        phases_list.append("consolidate")

    console.print(f"[bold]Config:[/bold]     {args.config}")
    console.print(f"[bold]Repo:[/bold]       {repo}")
    console.print(f"[bold]Files:[/bold]      {len(source_files)} source files found")
    console.print(f"[bold]Workers:[/bold]    {args.jobs}")
    console.print(f"[bold]Pipeline:[/bold]   {' → '.join(phases_list)}")
    console.print(f"[bold]Attack classes:[/bold] {len(cfg.attack_classes)} available")
    console.print()

    # Set up worktree isolation
    wt = WorktreeSetup(repo, cfg.branch_prefix, worktree_dir)
    callbacks = SetupCallbacks(
        setup_work_dir=wt.setup_work_dir,
        teardown_work_dir=wt.teardown_work_dir,
        setup_consolidation_dir=wt.setup_consolidation_dir,
    )

    # Build and run pipeline
    pipeline = build_pipeline(repo, cfg, output_dir)
    runner = TaskRunner(
        jobs=args.jobs,
        output_dir=output_dir,
        callbacks=callbacks,
        console=console,
    )
    runner.run(pipeline)

    console.print()
    console.print(f"[dim]Output: {output_dir}[/dim]")
    console.print(f"[dim]Worktrees: {worktree_dir}[/dim]")
