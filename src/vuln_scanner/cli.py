"""CLI entry point for claude-sweep."""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path

from rich.console import Console

from taskrunner import Phase, Pipeline, SetupCallbacks, Task, TaskRunner, TaskStatus
from taskrunner.model import RunContext

from vuln_scanner.claude import run_claude
from vuln_scanner.config import Config, load_config
from vuln_scanner.files import find_source_files, select_claude, select_random
from vuln_scanner.worktree import WorktreeSetup, slugify

logger = logging.getLogger("vuln-scanner")


# ---------------------------------------------------------------------------
# Workers — thin wrappers that invoke Claude in the worktree
# ---------------------------------------------------------------------------


def _make_phase1_worker(cfg: Config):
    """Create a phase 1 worker bound to the config."""

    def worker(task: Task, ctx: RunContext) -> bool:
        rel_path = task.inputs["file"]
        prompt = cfg.phase1_prompt(rel_path)
        ok = run_claude(ctx.work_dir, prompt, ctx.log_path, ctx)

        output_in_wt = ctx.work_dir / cfg.phase1_output
        if output_in_wt.exists():
            dest = ctx.output_dir / task.outputs["report"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(output_in_wt, dest)
            return True

        if not ok:
            task.error = "claude exited non-zero"
        else:
            task.error = f"{cfg.phase1_output} not written"
        return False

    return worker


def _make_phase2_worker(cfg: Config):
    """Create a phase 2 worker bound to the config."""

    def worker(task: Task, ctx: RunContext) -> bool:
        rel_path = task.inputs["file"]

        # Copy phase 1 report into worktree so Claude can read it
        p1_report = task.inputs.get("report_path")
        if p1_report:
            p1_path = Path(p1_report)
            if p1_path.exists():
                shutil.copy2(p1_path, ctx.work_dir / cfg.phase1_output)

        prompt = cfg.phase2_prompt(rel_path)
        ok = run_claude(ctx.work_dir, prompt, ctx.log_path, ctx)

        output_in_wt = ctx.work_dir / cfg.phase2_output
        if output_in_wt.exists():
            dest = ctx.output_dir / task.outputs["verified"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(output_in_wt, dest)
            return True

        if not ok:
            task.error = "claude exited non-zero"
        else:
            task.error = f"{cfg.phase2_output} not written"
        return False

    return worker


def _make_phase3_worker(cfg: Config, output_dir: Path):
    """Create a phase 3 consolidation worker bound to the config."""

    def worker(task: Task, ctx: RunContext) -> bool:
        prompt = cfg.phase3_prompt(output_dir)
        if prompt is None:
            task.error = "no phase3_prompt defined"
            return False

        ok = run_claude(ctx.work_dir, prompt, ctx.log_path, ctx)

        output_in_wt = ctx.work_dir / cfg.phase3_output
        if output_in_wt.exists():
            dest = output_dir / cfg.phase3_output
            shutil.copy2(output_in_wt, dest)
            return True

        if not ok:
            task.error = "claude exited non-zero"
        else:
            task.error = f"{cfg.phase3_output} not written"
        return False

    return worker


# ---------------------------------------------------------------------------
# Pipeline construction
# ---------------------------------------------------------------------------


def build_pipeline(
    files: list[Path],
    repo: Path,
    cfg: Config,
    output_dir: Path,
) -> Pipeline:
    """Build the scan → verify → consolidate pipeline."""
    phase1_worker = _make_phase1_worker(cfg)
    phase2_worker = _make_phase2_worker(cfg)

    scan_tasks = []
    for f in files:
        rel = str(f.relative_to(repo))
        slug = slugify(rel)
        scan_tasks.append(
            Task(
                id=slug,
                description=f"Scan {rel}",
                worker=phase1_worker,
                inputs={"file": rel},
                outputs={"report": f"{rel}.md"},
            )
        )

    def make_verify_tasks(prev_tasks: list[Task]) -> list[Task]:
        verify_tasks = []
        for t in prev_tasks:
            if t.status != TaskStatus.COMPLETED:
                continue
            rel = t.inputs["file"]
            slug = slugify(rel)
            # Resolve the phase 1 report path
            report_path = output_dir / "scan" / t.outputs["report"]
            verify_tasks.append(
                Task(
                    id=f"verify-{slug}",
                    description=f"Verify {rel}",
                    worker=phase2_worker,
                    inputs={"file": rel, "report_path": str(report_path)},
                    outputs={"verified": f"{rel}.md"},
                    parent_task=t.id,
                    metadata={"parent_phase": "scan"},
                )
            )
        return verify_tasks

    phases = [
        Phase.fan_out(name="scan", tasks=scan_tasks),
        Phase.fan_out(name="verify", tasks_from=make_verify_tasks),
    ]

    if cfg.has_phase3:
        phase3_worker = _make_phase3_worker(cfg, output_dir)
        phases.append(
            Phase.consolidate(
                name="consolidate",
                description="Consolidating results",
                worker=phase3_worker,
                output=cfg.phase3_output,
            )
        )

    return Pipeline(phases=phases)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-phase LLM sweep over a git repo",
    )
    parser.add_argument("repo", help="Path to the git repo (relative to cwd)")
    parser.add_argument(
        "-c", "--config", required=True,
        help="Config name (builtin) or path to config .py file",
    )
    parser.add_argument(
        "-j", "--jobs", type=int, default=4,
        help="Number of parallel workers (default: 4)",
    )
    parser.add_argument(
        "-n", "--limit", type=int, default=0,
        help="Max number of files to scan (0 = all)",
    )
    parser.add_argument(
        "-d", "--dir", default="",
        help="Subdirectory within repo to scope the scan (e.g. src/auth)",
    )
    parser.add_argument(
        "--pick", choices=["random", "claude"], default="random",
        help="File selection strategy: random (default) or claude (AI-prioritized)",
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
    repo = Path(args.repo).resolve()
    scan_dir = Path.cwd()
    output_dir = scan_dir / "output"
    worktree_dir = scan_dir / "worktrees"
    logs_dir = output_dir / "logs"

    for d in [output_dir, worktree_dir, logs_dir]:
        d.mkdir(parents=True, exist_ok=True)

    scan_root = repo / args.dir if args.dir else repo
    if not scan_root.is_dir():
        console.print(f"[red]Directory not found: {scan_root}[/red]")
        sys.exit(1)

    console.print(f"[bold]Config:[/bold]     {args.config}")
    console.print(f"[bold]Repo:[/bold]       {repo}")
    if args.dir:
        console.print(f"[bold]Scope:[/bold]      {args.dir}/")
    console.print(f"[bold]Workers:[/bold]    {args.jobs}")
    console.print(f"[bold]Selection:[/bold]  {args.pick}")
    if args.limit:
        console.print(f"[bold]Limit:[/bold]      {args.limit} files")
    console.print()

    # Find and select files
    files = find_source_files(scan_root, cfg.extensions, cfg.exclude_dirs)
    total_found = len(files)
    if args.limit:
        if args.pick == "claude":
            console.print(
                f"Found {total_found} source files, "
                f"asking Claude to pick {args.limit}..."
            )
            files = select_claude(files, args.limit, repo, logs_dir, cfg.priority_prompt)
        else:
            files = select_random(files, args.limit)
    console.print(f"Found {total_found} source files, scanning {len(files)}")
    console.print()

    # Set up worktree isolation
    wt = WorktreeSetup(repo, cfg.branch_prefix, worktree_dir)
    callbacks = SetupCallbacks(
        setup_work_dir=wt.setup_work_dir,
        teardown_work_dir=wt.teardown_work_dir,
        setup_consolidation_dir=wt.setup_consolidation_dir,
    )

    # Build and run pipeline
    pipeline = build_pipeline(files, repo, cfg, output_dir)
    runner = TaskRunner(
        jobs=args.jobs,
        output_dir=output_dir,
        callbacks=callbacks,
        console=console,
    )
    runner.run(pipeline)

    console.print()
    console.print(f"[dim]Cleanup: rm -rf {scan_dir}[/dim]")
