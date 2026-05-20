"""CLI entry point for vuln-scanner.

Subcommands operating on an investigation directory in cwd:

    vuln-scanner init <target-url> [-c config.toml]
        Scaffold an investigation directory: clone target/, write
        vuln-scanner.toml and MANIFEST.toml.

    vuln-scanner run [--sha <sha>] [-j N] [-v]
        Execute one scan run against target/. Creates runs/<timestamp>-<sha>/.
        Resumes mid-run via .done sentinels.

    vuln-scanner status
        List runs with target SHAs, models, timing, and verdict counts.

Pipeline (per run): recon → hunt → validate → dedupe → consolidate.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import logging
import re
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

from rich.console import Console
from rich.table import Table

from taskrunner import Phase, Pipeline, SetupCallbacks, Task, TaskRunner, TaskStatus
from taskrunner.model import RunContext
from vuln_scanner import investigation, target
from vuln_scanner.claude import run_agent
from vuln_scanner.config import Config, load_config
from vuln_scanner.investigation import (
    CONFIG_NAME,
    RUNS_DIRNAME,
    SUMMARY_NAME,
    TARGET_DIRNAME,
    WORKTREES_DIRNAME,
    LockHeld,
    Manifest,
    RunManifest,
)
from vuln_scanner.worktree import WorktreeSetup, slugify

logger = logging.getLogger("vuln-scanner")


# ---------------------------------------------------------------------------
# Worker helpers
# ---------------------------------------------------------------------------


def _copy_task_outputs(ctx: RunContext, outputs: dict[str, str]) -> None:
    """Copy task output files from worktree root to the phase output directory."""
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


def _make_recon_worker(cfg: Config, prior_runs_path: str):
    """Recon worker: map architecture + produce HUNT_QUEUE.json.

    ``prior_runs_path`` is the absolute path of ``runs/`` (empty string for
    first run). The recon agent reads prior runs' SUMMARY.md from there.
    """

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.recon_prompt(prior_runs_path=prior_runs_path)
        ok = run_agent(
            ctx.work_dir, prompt, ctx.log_path, ctx,
            agent=cfg.agent, agent_flags=cfg.agent_flags, model=cfg.recon_model,
        )

        output_in_wt = ctx.work_dir / cfg.recon_output
        if output_in_wt.exists():
            shutil.copy2(output_in_wt, ctx.output_dir / cfg.recon_output)
            return True

        task.error = "agent exited non-zero" if not ok else (
            f"{cfg.recon_output} not written by recon agent"
        )
        return False

    return worker


def _make_hunt_worker(cfg: Config):
    """Hunt worker: attack-class-scoped vulnerability search with PoC loop."""

    def worker(task: Task, ctx: RunContext) -> bool:
        queue_path = ctx.work_dir / cfg.recon_output
        arch_summary = _read_queue_summary(queue_path) or task.inputs.get(
            "arch_summary", ""
        )

        prompt = cfg.hunt_prompt(
            attack_class=task.metadata["attack_class"],
            scope=task.metadata["scope"],
            function=task.metadata.get("function", ""),
            entry_point=task.metadata.get("entry_point", ""),
            rationale=task.metadata.get("rationale", ""),
            arch_summary=arch_summary,
        )

        ok = run_agent(
            ctx.work_dir, prompt, ctx.log_path, ctx,
            agent=cfg.agent, agent_flags=cfg.agent_flags, model=cfg.hunt_model,
        )

        output_in_wt = ctx.work_dir / cfg.hunt_output
        if output_in_wt.exists():
            _copy_task_outputs(ctx, task.outputs)
            return True

        task.error = "agent exited non-zero" if not ok else (
            f"{cfg.hunt_output} not written by hunt agent"
        )
        return False

    return worker


def _make_validate_worker(cfg: Config):
    """Adversarial validate worker: disprove the hunter's finding."""

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.validate_prompt()
        ok = run_agent(
            ctx.work_dir, prompt, ctx.log_path, ctx,
            agent=cfg.agent, agent_flags=cfg.agent_flags, model=cfg.validate_model,
        )

        output_in_wt = ctx.work_dir / cfg.validate_output
        if output_in_wt.exists():
            _copy_task_outputs(ctx, task.outputs)
            return True

        task.error = "agent exited non-zero" if not ok else (
            f"{cfg.validate_output} not written by validate agent"
        )
        return False

    return worker


def _make_dedupe_worker(cfg: Config):
    """Dedupe worker: group validated findings by root cause."""

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.dedupe_prompt()
        if prompt is None:
            task.error = "dedupe_prompt returned None"
            return False

        ok = run_agent(
            ctx.work_dir, prompt, ctx.log_path, ctx,
            agent=cfg.agent, agent_flags=cfg.agent_flags, model=cfg.dedupe_model,
        )

        output_in_wt = ctx.work_dir / cfg.dedupe_output
        if output_in_wt.exists():
            shutil.copy2(output_in_wt, ctx.output_dir / cfg.dedupe_output)
            return True

        task.error = "agent exited non-zero" if not ok else (
            f"{cfg.dedupe_output} not written by dedupe agent"
        )
        return False

    return worker


def _make_consolidate_worker(cfg: Config, output_dir: Path, prior_runs_path: str):
    """Consolidation worker: cumulative SUMMARY.md across all runs."""

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.consolidate_prompt(output_dir, prior_runs_path=prior_runs_path)
        if prompt is None:
            task.error = (
                f"consolidate_prompt returned None "
                f"(no dedupe output in {output_dir / 'dedupe'})"
            )
            return False

        ok = run_agent(
            ctx.work_dir, prompt, ctx.log_path, ctx,
            agent=cfg.agent, agent_flags=cfg.agent_flags, model=cfg.consolidate_model,
        )

        output_in_wt = ctx.work_dir / cfg.consolidate_output
        if output_in_wt.exists():
            shutil.copy2(output_in_wt, ctx.output_dir / cfg.consolidate_output)
            return True

        task.error = "agent exited non-zero" if not ok else (
            f"{cfg.consolidate_output} not written by consolidate agent"
        )
        return False

    return worker


# ---------------------------------------------------------------------------
# Pipeline construction
# ---------------------------------------------------------------------------


def build_pipeline(
    repo: Path,
    cfg: Config,
    output_dir: Path,
    *,
    prior_runs_path: str = "",
) -> Pipeline:
    """Build the recon → hunt → validate → dedupe → consolidate pipeline."""
    phases: list[Phase] = []
    max_t = cfg.max_tasks

    # -- 1. Recon --
    recon_task = Task(
        id="recon",
        description="Recon — mapping architecture and attack surface",
        worker=_make_recon_worker(cfg, prior_runs_path),
        outputs={"queue": cfg.recon_output},
        timeout=cfg.timeout_for("recon"),
    )
    phases.append(Phase.fan_out(name="recon", tasks=[recon_task]))

    # -- 2. Hunt (fan-out from recon's queue) --
    hunt_worker = _make_hunt_worker(cfg)

    def make_hunt_tasks(prev_tasks: list[Task]) -> list[Task]:
        return _tasks_from_queue(
            queue_path=output_dir / "recon" / cfg.recon_output,
            worker=hunt_worker,
            cfg=cfg,
            parent_task="recon",
            phase_name="hunt",
            max_tasks=max_t,
            timeout=cfg.timeout_for("hunt"),
        )

    phases.append(Phase.fan_out(name="hunt", tasks_from=make_hunt_tasks))

    # -- 3. Validate (fan-out from completed hunts) --
    validate_worker = _make_validate_worker(cfg)

    def make_validate_tasks(prev_tasks: list[Task]) -> list[Task]:
        return _make_validate_tasks_from(
            prev_tasks, validate_worker, cfg, timeout=cfg.timeout_for("validate"),
        )

    phases.append(Phase.fan_out(name="validate", tasks_from=make_validate_tasks))

    # -- 4. Dedupe (optional) --
    if cfg.has_dedupe:
        phases.append(
            Phase.consolidate(
                name="dedupe",
                description="Deduplicating findings by root cause",
                worker=_make_dedupe_worker(cfg),
                output=cfg.dedupe_output,
                timeout=cfg.timeout_for("dedupe"),
            )
        )

    # -- 5. Consolidate (optional) --
    if cfg.has_consolidate:
        phases.append(
            Phase.consolidate(
                name="consolidate",
                description="Writing cumulative report",
                worker=_make_consolidate_worker(cfg, output_dir, prior_runs_path),
                output=cfg.consolidate_output,
                timeout=cfg.timeout_for("consolidate"),
            )
        )

    return Pipeline(phases=phases)


def _tasks_from_queue(
    *,
    queue_path: Path,
    worker: Callable[..., bool],
    cfg: Config,
    parent_task: str | None,
    phase_name: str,
    max_tasks: int = 0,
    timeout: int | None = None,
) -> list[Task]:
    """Create hunt tasks from a HUNT_QUEUE.json file."""
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
        logger.warning(f"Queue {queue_path} contains no tasks — bailing early")
        return []

    tasks = []
    for entry in entries:
        attack_class = entry.get("attack_class", "")
        scope = entry.get("scope", "")
        if not attack_class or not scope:
            logger.warning(f"Skipping malformed queue entry: {entry}")
            continue

        task_id = entry.get("id") or f"{attack_class}__{slugify(scope)}"
        tasks.append(
            Task(
                id=task_id,
                description=f"Hunt {attack_class} in {scope}",
                worker=worker,
                inputs={"arch_summary": arch_summary},
                outputs={"finding": f"{task_id}/{cfg.hunt_output}"},
                metadata={
                    "attack_class": attack_class,
                    "scope": scope,
                    "function": entry.get("function", ""),
                    "entry_point": entry.get("entry_point", ""),
                    "rationale": entry.get("rationale", ""),
                    "parent_phase": "recon",
                },
                parent_task=parent_task,
                timeout=timeout,
            )
        )

    if max_tasks and len(tasks) > max_tasks:
        logger.info(
            f"Truncating {phase_name} tasks from {len(tasks)} to {max_tasks}"
        )
        tasks = tasks[:max_tasks]

    logger.info(f"Created {len(tasks)} tasks for {phase_name}")
    return tasks


def _make_validate_tasks_from(
    prev_tasks: list[Task],
    validate_worker: Callable[..., bool],
    cfg: Config,
    timeout: int | None = None,
) -> list[Task]:
    """Create validate tasks for each completed hunt task."""
    out = []
    for t in prev_tasks:
        if t.status != TaskStatus.COMPLETED:
            continue
        out.append(
            Task(
                id=f"validate-{t.id}",
                description=f"Validate {t.description.removeprefix('Hunt ')}",
                worker=validate_worker,
                outputs={"verification": f"{t.id}/{cfg.validate_output}"},
                parent_task=t.id,
                metadata={
                    "parent_phase": "hunt",
                    "attack_class": t.metadata.get("attack_class", ""),
                    "scope": t.metadata.get("scope", ""),
                },
                timeout=timeout,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Investigation helpers
# ---------------------------------------------------------------------------


def _tool_version() -> str:
    """Best-effort: the installed package version."""
    try:
        return importlib.metadata.version("vuln-scanner")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _require_investigation_dir(console: Console) -> Path:
    """Ensure cwd looks like an investigation directory; exit otherwise."""
    cwd = Path.cwd()
    if not investigation.is_investigation_dir(cwd):
        console.print(
            f"[red]{cwd} is not an investigation directory.[/red] "
            f"Run [bold]vuln-scanner init <target-url>[/bold] first."
        )
        sys.exit(1)
    return cwd


def _summary_counts_from_findings(findings_path: Path) -> dict[str, int]:
    """Best-effort parse of FINDINGS.md scan summary counts.

    Returns {} if the file is missing or the counts can't be located.
    Looks for lines like '- **Confirmed:** 3' under the Scan Summary header.
    """
    if not findings_path.is_file():
        return {}
    text = findings_path.read_text()
    counts: dict[str, int] = {}
    for key, pattern in (
        ("confirmed", r"\*\*Confirmed:\*\*\s+(\d+)"),
        ("rejected", r"\*\*Rejected:\*\*\s+(\d+)"),
        ("needs_review", r"\*\*Needs review:\*\*\s+(\d+)"),
        ("unique_vulns", r"\*\*Unique vulnerabilities:\*\*\s+(\d+)"),
    ):
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            counts[key] = int(m.group(1))
    return counts


# ---------------------------------------------------------------------------
# Subcommand: init
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> None:
    console = Console(stderr=True)
    cwd = Path.cwd()

    if investigation.is_investigation_dir(cwd):
        console.print(f"[red]{cwd} is already an investigation directory.[/red]")
        sys.exit(1)

    target_dir = cwd / TARGET_DIRNAME
    if target_dir.exists():
        console.print(f"[red]{target_dir} already exists; refusing to overwrite.[/red]")
        sys.exit(1)

    # Clone target first — fails fast on bad URLs before we write anything else.
    console.print(f"[bold]Cloning {args.target_url} → {target_dir}...[/bold]")
    target.clone(args.target_url, target_dir)
    sha = target.current_sha(target_dir)
    console.print(f"[dim]target HEAD: {sha}[/dim]")

    # Config: copy from -c if given, else write a minimal default pointing at the builtin profile.
    config_path = cwd / CONFIG_NAME
    if args.config:
        src = Path(args.config).resolve()
        if not src.is_file():
            console.print(f"[red]Config file not found: {src}[/red]")
            sys.exit(1)
        shutil.copy2(src, config_path)
    else:
        config_path.write_text(
            "# vuln-scanner config. See https://github.com/... for all options.\n"
            "\n"
            "[scan]\n"
            'prompt_profile = "vuln-scan"\n'
            "\n"
            "[agent]\n"
            'backend = "claude"\n'
        )

    Manifest(target_url=args.target_url).dump(cwd / "MANIFEST.toml")

    # .gitignore — only write if not already present (user may have started a repo).
    gitignore = cwd / ".gitignore"
    ignores = [
        TARGET_DIRNAME + "/",
        WORKTREES_DIRNAME + "/",
        investigation.LOCKFILE_NAME,
    ]
    existing = gitignore.read_text() if gitignore.exists() else ""
    additions = "\n".join(i for i in ignores if i not in existing)
    if additions:
        gitignore.write_text((existing + "\n" if existing else "") + additions + "\n")

    console.print(f"[green]Initialized investigation at {cwd}[/green]")
    console.print("Next: [bold]vuln-scanner run[/bold]")


# ---------------------------------------------------------------------------
# Subcommand: run
# ---------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> None:
    console = Console(stderr=True)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    inv_dir = _require_investigation_dir(console)
    cfg = load_config(str(inv_dir / CONFIG_NAME))

    target_dir = inv_dir / TARGET_DIRNAME
    if not target_dir.is_dir():
        console.print(f"[red]Target directory missing: {target_dir}[/red]")
        sys.exit(1)

    # Pin target SHA (fetch + checkout if --sha given, else use current HEAD)
    if args.sha:
        console.print(f"[dim]Fetching and checking out {args.sha}...[/dim]")
        target.fetch(target_dir)
        target.checkout(target_dir, args.sha)
    target_sha = target.current_sha(target_dir)

    run_id = investigation.make_run_id(target_sha)
    run_dir = inv_dir / RUNS_DIRNAME / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    worktree_dir = inv_dir / WORKTREES_DIRNAME
    worktree_dir.mkdir(exist_ok=True)
    (run_dir / "logs").mkdir(exist_ok=True)

    prior_runs_path = str(inv_dir / RUNS_DIRNAME)

    # Per-run manifest with models recorded
    run_manifest = RunManifest(
        run_id=run_id,
        target_sha=target_sha,
        tool_version=_tool_version(),
        started_at=investigation.iso_now(),
        models={
            phase: cfg.model_for(phase) or "(backend default)"
            for phase in ("recon", "hunt", "validate", "dedupe", "consolidate")
        },
    )
    run_manifest.dump(run_dir / investigation.RUN_MANIFEST_NAME)

    console.print(f"[bold]Investigation:[/bold] {inv_dir}")
    console.print(f"[bold]Target:[/bold]        {target_dir} @ {target_sha[:12]}")
    console.print(f"[bold]Run:[/bold]           {run_id}")
    console.print(f"[bold]Workers:[/bold]       {args.jobs}")
    console.print(f"[bold]Tool version:[/bold]  {run_manifest.tool_version}")
    prior = investigation.list_runs(inv_dir)
    if len(prior) > 1:  # current run is now in the list
        console.print(f"[bold]Prior runs:[/bold]    {len(prior) - 1}")
    console.print()

    with investigation.investigation_lock(inv_dir):
        wt = WorktreeSetup(target_dir, cfg.branch_prefix, worktree_dir)
        callbacks = SetupCallbacks(
            setup_work_dir=wt.setup_work_dir,
            teardown_work_dir=wt.teardown_work_dir,
            setup_consolidation_dir=wt.setup_consolidation_dir,
        )

        pipeline = build_pipeline(
            target_dir, cfg, run_dir, prior_runs_path=prior_runs_path,
        )
        runner = TaskRunner(
            jobs=args.jobs,
            output_dir=run_dir,
            callbacks=callbacks,
            console=console,
        )
        try:
            runner.run(pipeline)
            run_manifest.status = "completed"
        except KeyboardInterrupt:
            run_manifest.status = "interrupted"
            raise
        except Exception:
            run_manifest.status = "failed"
            raise
        finally:
            run_manifest.finished_at = investigation.iso_now()
            run_manifest.summary = _summary_counts_from_findings(
                run_dir / "dedupe" / cfg.dedupe_output
            )
            run_manifest.dump(run_dir / investigation.RUN_MANIFEST_NAME)

    # Update top-level pointers
    inv_manifest = Manifest.load(inv_dir / "MANIFEST.toml")
    inv_manifest.latest_run = run_id
    inv_manifest.dump(inv_dir / "MANIFEST.toml")
    investigation.update_summary_symlink(inv_dir, run_dir)

    console.print()
    console.print(f"[dim]Run output: {run_dir}[/dim]")
    if (run_dir / SUMMARY_NAME).is_file():
        console.print(f"[dim]Summary: {inv_dir / SUMMARY_NAME}[/dim]")


# ---------------------------------------------------------------------------
# Subcommand: status
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> None:
    console = Console()
    inv_dir = _require_investigation_dir(console)
    inv_manifest = Manifest.load(inv_dir / "MANIFEST.toml")

    console.print(f"[bold]Target:[/bold] {inv_manifest.target_url}")
    target_dir = inv_dir / TARGET_DIRNAME
    if target_dir.is_dir():
        try:
            console.print(
                f"[bold]Target HEAD:[/bold] {target.current_sha(target_dir)}"
            )
        except target.GitError:
            pass
    console.print()

    runs = investigation.list_runs(inv_dir)
    if not runs:
        console.print("[dim]No runs yet. Run [bold]vuln-scanner run[/bold] to start.[/dim]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Run")
    table.add_column("SHA")
    table.add_column("Started")
    table.add_column("Status")
    table.add_column("Models (recon/hunt/validate)")
    table.add_column("Confirmed", justify="right")
    table.add_column("Rejected", justify="right")
    table.add_column("Vulns", justify="right")

    for run_dir in runs:
        mpath = run_dir / investigation.RUN_MANIFEST_NAME
        if not mpath.is_file():
            continue
        m = RunManifest.load(mpath)
        models = (
            f"{m.models.get('recon', '-')[:18]} / "
            f"{m.models.get('hunt', '-')[:18]} / "
            f"{m.models.get('validate', '-')[:18]}"
        )
        status_color = {
            "completed": "green",
            "failed": "red",
            "interrupted": "yellow",
            "running": "cyan",
        }.get(m.status, "")
        table.add_row(
            m.run_id,
            m.target_sha[:12],
            m.started_at,
            f"[{status_color}]{m.status}[/{status_color}]" if status_color else m.status,
            models,
            str(m.summary.get("confirmed", "-")),
            str(m.summary.get("rejected", "-")),
            str(m.summary.get("unique_vulns", "-")),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="Multi-phase LLM vulnerability scanner over a single target investigation.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser(
        "init",
        help="Initialize an investigation directory in cwd (clones target, writes config).",
    )
    p_init.add_argument("target_url", help="Git URL of the target repo to clone")
    p_init.add_argument(
        "-c", "--config",
        help="Path to a vuln-scanner.toml to copy in (default: minimal built-in)",
    )
    p_init.set_defaults(func=cmd_init)

    p_run = sub.add_parser(
        "run",
        help="Execute one scan run against target/ in cwd.",
    )
    p_run.add_argument(
        "--sha",
        help="Target commit SHA to pin (default: keep current target HEAD)",
    )
    p_run.add_argument(
        "-j", "--jobs", type=int, default=4,
        help="Parallel workers (default: 4)",
    )
    p_run.add_argument(
        "-v", "--verbose", action="store_true",
    )
    p_run.set_defaults(func=cmd_run)

    p_status = sub.add_parser(
        "status",
        help="List runs in this investigation.",
    )
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()

    try:
        args.func(args)
    except LockHeld as e:
        Console(stderr=True).print(f"[red]{e}[/red]")
        sys.exit(1)
    except target.GitError as e:
        Console(stderr=True).print(f"[red]git error: {e}[/red]")
        sys.exit(1)
