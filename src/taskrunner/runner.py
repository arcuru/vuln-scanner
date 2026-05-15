"""Task runner — executes pipelines and task graphs."""

from __future__ import annotations

import signal
import subprocess
import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from taskrunner.graph import TaskGraph
from taskrunner.model import (
    GraphResult,
    Phase,
    PhaseResult,
    Pipeline,
    RunContext,
    SetupCallbacks,
    Task,
    TaskStatus,
)
from taskrunner.scheduler import FIFOScheduler, Scheduler


class TaskRunner:
    """Executes pipelines and task graphs with concurrency control, progress UI,
    and process management."""

    def __init__(
        self,
        jobs: int = 4,
        output_dir: Path = Path("output"),
        callbacks: SetupCallbacks | None = None,
        console: Console | None = None,
        progress_columns: list[ProgressColumn] | None = None,
    ) -> None:
        self.jobs = jobs
        self.output_dir = output_dir
        self.callbacks = callbacks or SetupCallbacks()
        self.console = console or Console(stderr=True)
        self._progress_columns = progress_columns

        # Process tracking for graceful shutdown
        self._active_processes: set[subprocess.Popen[Any]] = set()
        self._process_lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = None
        self._interrupted = False

        # Collected outputs: phase_name -> task_id -> output_name -> path
        self._all_outputs: dict[str, dict[str, dict[str, Path]]] = {}

    def register_process(self, proc: subprocess.Popen[Any]) -> None:
        """Register a subprocess for cleanup on interrupt.

        Workers should call this for any long-running subprocess they spawn.
        """
        with self._process_lock:
            self._active_processes.add(proc)

    def unregister_process(self, proc: subprocess.Popen[Any]) -> None:
        """Unregister a completed subprocess."""
        with self._process_lock:
            self._active_processes.discard(proc)

    def _make_progress(self) -> Progress:
        """Create a Progress instance, using custom columns if configured."""
        if self._progress_columns:
            return Progress(*self._progress_columns, console=self.console)
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
        )

    # -------------------------------------------------------------------
    # Pipeline execution (backward-compatible)
    # -------------------------------------------------------------------

    def run(self, pipeline: Pipeline) -> dict[str, PhaseResult]:
        """Execute all phases in order. Returns results keyed by phase name."""
        results: dict[str, PhaseResult] = {}
        prev_tasks: list[Task] = []

        old_sigint = signal.getsignal(signal.SIGINT)
        old_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        try:
            for phase in pipeline.phases:
                if self._interrupted:
                    break

                # Resolve dynamic tasks
                if phase.tasks_from and not phase.tasks:
                    phase.tasks = phase.tasks_from(prev_tasks)

                if not phase.tasks:
                    self.console.print(
                        f"[yellow]Phase '{phase.name}': no tasks, skipping[/yellow]"
                    )
                    continue

                result = self._run_phase(phase, prev_tasks)
                results[phase.name] = result
                prev_tasks = phase.tasks

            self._print_phase_summary(results)

        finally:
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)

        return results

    def _run_phase(self, phase: Phase, prev_tasks: list[Task]) -> PhaseResult:
        """Execute a single phase."""
        phase_output = self.output_dir / phase.name
        phase_output.mkdir(parents=True, exist_ok=True)
        logs_dir = self.output_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        self._all_outputs.setdefault(phase.name, {})

        completed = 0
        failed = 0
        skipped = 0
        lock = threading.Lock()

        workers = 1 if phase.consolidation else min(self.jobs, len(phase.tasks))

        self.console.print(
            f"\n[bold]═══ {phase.name} [/bold]"
            f"[dim]({len(phase.tasks)} tasks, {workers} workers)[/dim]"
        )

        progress = self._make_progress()

        with progress:
            overall_id = progress.add_task(
                phase.name, total=len(phase.tasks),
            )

            task_progress_ids: dict[str, TaskID] = {}
            for task in phase.tasks:
                tid = progress.add_task(
                    task.description,
                    total=1,
                    visible=False,
                )
                task_progress_ids[task.id] = tid

            with ThreadPoolExecutor(max_workers=workers) as executor:
                self._executor = executor
                futures: dict[Future[bool], Task] = {}

                for task in phase.tasks:
                    if self._interrupted:
                        break

                    if self._task_outputs_exist(task, phase_output):
                        task.status = TaskStatus.SKIPPED
                        with lock:
                            skipped += 1
                            progress.update(overall_id, advance=1)
                            tid = task_progress_ids[task.id]
                            progress.update(
                                tid, visible=True, completed=1,
                                description=f"[dim]SKIP {task.description}[/dim]",
                            )
                            progress.remove_task(tid)
                            self._register_outputs(task, phase_output)
                        continue

                    future = executor.submit(
                        self._execute_task, task, phase, phase_output,
                        logs_dir, progress, task_progress_ids[task.id], lock,
                    )
                    futures[future] = task

                for future in as_completed(futures):
                    if self._interrupted:
                        break

                    task = futures[future]
                    try:
                        success = future.result()
                    except Exception as e:
                        success = False
                        task.error = str(e)
                        task.status = TaskStatus.FAILED

                    tid = task_progress_ids[task.id]
                    with lock:
                        if success:
                            completed += 1
                            progress.update(
                                tid, completed=1,
                                description=f"[green]✓[/green] {task.description}",
                            )
                        else:
                            failed += 1
                            err = f" ({task.error})" if task.error else ""
                            progress.update(
                                tid, completed=1,
                                description=f"[red]✗[/red] {task.description}{err}",
                            )
                        progress.remove_task(tid)
                        progress.update(overall_id, advance=1)

                self._executor = None

        return PhaseResult(
            phase=phase.name,
            total=len(phase.tasks),
            completed=completed,
            failed=failed,
            skipped=skipped,
        )

    def _execute_task(
        self,
        task: Task,
        phase: Phase,
        phase_output: Path,
        logs_dir: Path,
        progress: Progress,
        progress_id: TaskID,
        lock: threading.Lock,
    ) -> bool:
        """Execute a single task in its own work directory (phase mode)."""
        task.status = TaskStatus.RUNNING

        with lock:
            progress.update(progress_id, visible=True)

        if phase.consolidation and self.callbacks.setup_consolidation_dir:
            work_dir = self.callbacks.setup_consolidation_dir(
                task, phase.name, phase_output, self._all_outputs,
            )
        elif self.callbacks.setup_work_dir:
            work_dir = self.callbacks.setup_work_dir(task, phase.name, phase_output)
        else:
            work_dir = phase_output / task.id
            work_dir.mkdir(parents=True, exist_ok=True)

        log_path = logs_dir / f"{task.id}.log"

        with open(log_path, "a") as log_file:
            ctx = RunContext(
                task=task,
                work_dir=work_dir,
                output_dir=phase_output,
                log_path=log_path,
                log_file=log_file,
                phase_name=phase.name,
                all_outputs=self._all_outputs,
                runner=self,
                progress=progress,
                progress_id=progress_id,
            )

            try:
                success = task.worker(task, ctx)
            except Exception as e:
                task.error = str(e)
                success = False

        if success:
            task.status = TaskStatus.COMPLETED
            self._register_outputs(task, phase_output)
        else:
            task.status = TaskStatus.FAILED

        if self.callbacks.teardown_work_dir:
            self.callbacks.teardown_work_dir(task, work_dir, phase.name)

        return success

    # -------------------------------------------------------------------
    # Graph execution (DAG mode)
    # -------------------------------------------------------------------

    def run_graph(
        self,
        graph: TaskGraph,
        scheduler: Scheduler | None = None,
    ) -> GraphResult:
        """Execute a task graph with pluggable scheduling.

        Tasks are dispatched dynamically as their dependencies are satisfied.
        The scheduler controls which ready task to run next, enabling custom
        priority and concurrency constraint logic.

        Args:
            graph:     The task graph to execute.
            scheduler: Scheduling strategy.  Defaults to FIFO.

        Returns:
            GraphResult with execution statistics.
        """
        scheduler = scheduler or FIFOScheduler()
        graph.validate()

        output_dir = self.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        logs_dir = output_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        completed_ids: set[str] = set()
        failed_ids: set[str] = set()
        skipped_ids: set[str] = set()
        running_futures: dict[Future[bool], Task] = {}
        lock = threading.Lock()

        total = len(graph.tasks)

        old_sigint = signal.getsignal(signal.SIGINT)
        old_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        progress = self._make_progress()

        try:
            with progress:
                overall_id = progress.add_task("total", total=total)

                # Pre-create per-task progress bars (hidden, indeterminate)
                # Workers can set total via ctx.progress.update(ctx.progress_id, total=N)
                task_progress_ids: dict[str, TaskID] = {}
                for task in graph.tasks.values():
                    tid = progress.add_task(
                        task.description,
                        total=None,
                        visible=False,
                    )
                    task_progress_ids[task.id] = tid

                with ThreadPoolExecutor(max_workers=self.jobs) as executor:
                    self._executor = executor

                    while not self._interrupted:
                        # Recompute pending from graph each iteration
                        # to pick up dynamically injected tasks
                        all_task_ids = set(graph.tasks.keys())
                        done_ids = completed_ids | failed_ids | skipped_ids
                        running_ids = {t.id for t in running_futures.values()}
                        pending = all_task_ids - done_ids - running_ids

                        if not pending and not running_futures:
                            break

                        # Update progress total if graph grew
                        current_total = len(all_task_ids)
                        if current_total != total:
                            total = current_total
                            progress.update(overall_id, total=total)

                        # Register progress bars for newly injected tasks
                        for tid in pending:
                            if tid not in task_progress_ids:
                                task = graph.tasks[tid]
                                pid = progress.add_task(
                                    task.description,
                                    total=None,
                                    visible=False,
                                )
                                task_progress_ids[tid] = pid

                        # Skip tasks whose dependencies failed
                        newly_skipped = self._skip_blocked_tasks(
                            graph, pending, failed_ids, skipped_ids,
                        )
                        for skip_id in newly_skipped:
                            pending.discard(skip_id)
                            skipped_ids.add(skip_id)
                            with lock:
                                done_ids = completed_ids | failed_ids | skipped_ids
                                pid = task_progress_ids[skip_id]
                                desc = graph.tasks[skip_id].description
                                progress.update(
                                    pid, visible=True, completed=1,
                                    description=f"[dim]SKIP {desc}[/dim]",
                                )
                                progress.remove_task(pid)
                                progress.update(overall_id, advance=1)

                        # Recompute done_ids after skips
                        done_ids = completed_ids | failed_ids | skipped_ids

                        # Compute ready set (pending tasks with deps satisfied)
                        ready = [
                            t for t in graph.ready(done_ids)
                            if t.id in pending
                        ]

                        # Check for resumability (skip tasks with existing outputs)
                        for task in list(ready):
                            if self._task_outputs_exist(task, output_dir):
                                task.status = TaskStatus.SKIPPED
                                pending.discard(task.id)
                                skipped_ids.add(task.id)
                                ready.remove(task)
                                self._register_outputs(task, output_dir)
                                with lock:
                                    pid = task_progress_ids[task.id]
                                    progress.update(
                                        pid, visible=True, completed=1,
                                        description=f"[dim]SKIP {task.description}[/dim]",
                                    )
                                    progress.remove_task(pid)
                                    progress.update(overall_id, advance=1)

                        # Fill open slots
                        running_list = list(running_futures.values())
                        completed_list = [
                            graph.tasks[tid] for tid in completed_ids
                        ]

                        while len(running_futures) < self.jobs and ready:
                            task = scheduler.select(
                                ready=ready,
                                running=running_list,
                                completed=completed_list,
                            )
                            if task is None:
                                break
                            ready.remove(task)

                            future = executor.submit(
                                self._execute_graph_task,
                                task, graph, output_dir, logs_dir,
                                progress, task_progress_ids[task.id], lock,
                            )
                            running_futures[future] = task
                            running_list.append(task)

                        # Wait for one completion
                        if running_futures:
                            done_future = next(as_completed(running_futures))
                            finished_task = running_futures.pop(done_future)

                            try:
                                success = done_future.result()
                            except Exception as e:
                                success = False
                                finished_task.error = str(e)
                                finished_task.status = TaskStatus.FAILED

                            pid = task_progress_ids[finished_task.id]
                            with lock:
                                if success:
                                    completed_ids.add(finished_task.id)
                                    progress.update(
                                        pid, completed=1,
                                        description=f"[green]✓[/green] {finished_task.description}",
                                    )
                                else:
                                    failed_ids.add(finished_task.id)
                                    err = f" ({finished_task.error})" if finished_task.error else ""
                                    progress.update(
                                        pid, completed=1,
                                        description=f"[red]✗[/red] {finished_task.description}{err}",
                                    )
                                progress.remove_task(pid)
                                progress.update(overall_id, advance=1)

                        elif pending:
                            # Deadlock: tasks pending but nothing running or selectable
                            blocked = [graph.tasks[tid] for tid in pending]
                            self.console.print(
                                f"[red]Deadlock: {len(blocked)} tasks pending but "
                                f"none can be scheduled[/red]"
                            )
                            for t in blocked:
                                t.status = TaskStatus.FAILED
                                t.error = "Deadlocked — unresolvable dependencies"
                                failed_ids.add(t.id)
                                pending.discard(t.id)
                                with lock:
                                    pid = task_progress_ids[t.id]
                                    progress.update(
                                        pid, visible=True, completed=1,
                                        description=f"[red]✗[/red] {t.description} (deadlock)",
                                    )
                                    progress.remove_task(pid)
                                    progress.update(overall_id, advance=1)

                    self._executor = None

            # Print summary
            self._print_graph_summary(
                total, len(completed_ids), len(failed_ids), len(skipped_ids),
            )

        finally:
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)

        return GraphResult(
            total=total,
            completed=len(completed_ids),
            failed=len(failed_ids),
            skipped=len(skipped_ids),
            failed_tasks=[
                graph.tasks[tid] for tid in failed_ids
            ],
        )

    def _execute_graph_task(
        self,
        task: Task,
        graph: TaskGraph,
        output_dir: Path,
        logs_dir: Path,
        progress: Progress,
        progress_id: TaskID,
        lock: threading.Lock,
    ) -> bool:
        """Execute a single task in graph mode."""
        task.status = TaskStatus.RUNNING

        with lock:
            progress.update(progress_id, visible=True)

        phase_name = task.metadata.get("_phase", "")
        is_consolidation = task.metadata.get("_consolidation", False)

        if is_consolidation and self.callbacks.setup_consolidation_dir:
            work_dir = self.callbacks.setup_consolidation_dir(
                task, phase_name, output_dir, self._all_outputs,
            )
        elif self.callbacks.setup_work_dir:
            work_dir = self.callbacks.setup_work_dir(task, phase_name, output_dir)
        else:
            work_dir = output_dir / task.id
            work_dir.mkdir(parents=True, exist_ok=True)

        log_path = logs_dir / f"{task.id}.log"

        with open(log_path, "a") as log_file:
            ctx = RunContext(
                task=task,
                work_dir=work_dir,
                output_dir=output_dir,
                log_path=log_path,
                log_file=log_file,
                phase_name=phase_name,
                all_outputs=self._all_outputs,
                runner=self,
                progress=progress,
                progress_id=progress_id,
                graph=graph,
            )

            try:
                success = task.worker(task, ctx)
            except Exception as e:
                task.error = str(e)
                success = False

        if success:
            task.status = TaskStatus.COMPLETED
            self._register_outputs(task, output_dir)
        else:
            task.status = TaskStatus.FAILED

        if self.callbacks.teardown_work_dir:
            self.callbacks.teardown_work_dir(task, work_dir, phase_name)

        return success

    @staticmethod
    def _skip_blocked_tasks(
        graph: TaskGraph,
        pending: set[str],
        failed_ids: set[str],
        skipped_ids: set[str],
    ) -> list[str]:
        """Find pending tasks that can never run because a dependency failed."""
        newly_skipped: list[str] = []
        blocked = failed_ids | skipped_ids

        for tid in list(pending):
            task = graph.tasks[tid]
            if any(dep in blocked for dep in task.depends_on):
                task.status = TaskStatus.SKIPPED
                task.error = "Dependency failed"
                newly_skipped.append(tid)

        return newly_skipped

    # -------------------------------------------------------------------
    # Shared helpers
    # -------------------------------------------------------------------

    def _task_outputs_exist(self, task: Task, output_dir: Path) -> bool:
        """Check if all declared outputs already exist (for resumability)."""
        if not task.outputs:
            return False
        return all(
            (output_dir / path).exists()
            for path in task.outputs.values()
        )

    def _register_outputs(self, task: Task, output_dir: Path) -> None:
        """Record resolved output paths for downstream phases/tasks."""
        phase_name = task.metadata.get("_phase", output_dir.name)
        self._all_outputs.setdefault(phase_name, {})[task.id] = {
            name: output_dir / path
            for name, path in task.outputs.items()
        }

    # -------------------------------------------------------------------
    # Process management + signal handling
    # -------------------------------------------------------------------

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle SIGINT/SIGTERM gracefully."""
        self._interrupted = True
        self.console.print("\n[yellow]Interrupted — cleaning up...[/yellow]")
        self._kill_active_processes()

        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

        raise KeyboardInterrupt()

    def _kill_active_processes(self) -> None:
        """Terminate all registered subprocesses."""
        import os

        with self._process_lock:
            for proc in list(self._active_processes):
                try:
                    if proc.poll() is not None:
                        continue
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        proc.terminate()

                    try:
                        proc.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            proc.kill()

                    for pipe in (proc.stdin, proc.stdout, proc.stderr):
                        if pipe:
                            try:
                                pipe.close()
                            except Exception:
                                pass
                except Exception:
                    pass
            self._active_processes.clear()

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------

    def _print_phase_summary(self, results: dict[str, PhaseResult]) -> None:
        """Print a summary table of all phases."""
        self.console.print()

        table = Table(title="Summary", show_edge=False)
        table.add_column("Phase", style="bold")
        table.add_column("Total", justify="right")
        table.add_column("Completed", justify="right", style="green")
        table.add_column("Failed", justify="right", style="red")
        table.add_column("Skipped", justify="right", style="dim")

        for name, result in results.items():
            table.add_row(
                name,
                str(result.total),
                str(result.completed),
                str(result.failed),
                str(result.skipped),
            )

        self.console.print(table)

    def _print_graph_summary(
        self, total: int, completed: int, failed: int, skipped: int,
    ) -> None:
        """Print a summary for graph execution."""
        self.console.print()

        table = Table(title="Summary", show_edge=False)
        table.add_column("", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("Total", str(total))
        table.add_row("[green]Completed[/green]", str(completed))
        table.add_row("[red]Failed[/red]", str(failed))
        table.add_row("[dim]Skipped[/dim]", str(skipped))

        self.console.print(table)
