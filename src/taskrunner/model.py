"""Data model for taskrunner."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from rich.progress import Progress, TaskID

if TYPE_CHECKING:
    from taskrunner.graph import TaskGraph
    from taskrunner.runner import TaskRunner


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Task:
    """A unit of work.

    Attributes:
        id:           Unique identifier (used for output paths, branch names, etc.)
        description:  Human-readable label shown in progress bars.
        worker:       Callable that executes this task.  Signature:
                        (task: Task, context: RunContext) -> bool
        inputs:       Arbitrary input data the worker reads.
        outputs:      Map of output names -> relative paths.  The runner resolves
                      these against the output directory.
        metadata:     Freeform dict for worker-specific data (scheduling hints,
                      hostnames, creator info, etc.)
        depends_on:   Task IDs that must complete before this task can run.
        parent_task:  ID of a task from a previous phase that this task depends on.
                      Used by the runner to set up work directories (e.g. branching
                      a worktree off the parent's branch).  This is a setup hint,
                      not a scheduling dependency -- use depends_on for that.
        status:       Current status -- managed by the runner.
        error:        Error message if status is FAILED.
        timeout:      Maximum seconds for this task (None = use runner default).
    """

    id: str
    description: str
    worker: Callable[[Task, RunContext], bool]
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    parent_task: str | None = None
    status: TaskStatus = TaskStatus.PENDING
    error: str | None = None
    timeout: int | None = None


@dataclass
class RunContext:
    """Context passed to every worker function.

    Attributes:
        task:         The task being executed.
        work_dir:     Isolated working directory for this task.
        output_dir:   Output directory (shared, for collecting results).
        log_path:     Path to the log file for this task.
        log_file:     Open file handle for logging.  Write to this instead of
                      stdout/stderr (which would clobber the progress display).
                      Also usable as subprocess stdout/stderr::

                          proc = subprocess.Popen(cmd, stdout=ctx.log_file,
                                                  stderr=ctx.log_file)

        phase_name:   Name of the current phase (empty string in graph mode).
        all_outputs:  Read-only view of all collected outputs.
                      Keyed by phase/group name -> task id -> output name -> path.
        runner:       Reference to the TaskRunner (for process registration).
        progress:     Rich Progress instance for updating task progress.
                      Workers can call progress.update(progress_id, ...) to
                      report byte-level or step-level progress.
        progress_id:  The TaskID for this task's progress bar.  Workers can
                      update total, completed, description, etc.
    """

    task: Task
    work_dir: Path
    output_dir: Path
    log_path: Path
    log_file: IO[bytes]
    phase_name: str
    all_outputs: dict[str, dict[str, dict[str, Path]]]
    runner: TaskRunner
    progress: Progress | None = None
    progress_id: TaskID | None = None
    graph: TaskGraph | None = None

    def print(self, *args: Any, **kwargs: Any) -> None:
        """Print to the task's log file (not stdout).

        Writes UTF-8 encoded text. Same signature as builtin print().
        """
        text = " ".join(str(a) for a in args)
        end = kwargs.get("end", "\n")
        self.log_file.write((text + end).encode("utf-8"))
        self.log_file.flush()

    def subprocess_args(self) -> dict[str, Any]:
        """Common kwargs for subprocess.Popen/run to capture output to the log.

        Usage::

            proc = subprocess.Popen(cmd, **ctx.subprocess_args())
            # or
            subprocess.run(cmd, **ctx.subprocess_args(), check=True)
        """
        return {
            "stdout": self.log_file,
            "stderr": self.log_file,
            "cwd": str(self.work_dir),
        }


@dataclass
class Phase:
    """A named group of tasks that execute in parallel.

    Either provide ``tasks`` directly, or ``tasks_from`` to dynamically generate
    tasks from the previous phase's completed tasks.
    """

    name: str
    tasks: list[Task] = field(default_factory=list)
    tasks_from: Callable[[list[Task]], list[Task]] | None = None
    consolidation: bool = False

    @classmethod
    def fan_out(
        cls,
        name: str,
        tasks: list[Task] | None = None,
        tasks_from: Callable[[list[Task]], list[Task]] | None = None,
    ) -> Phase:
        """Create a fan-out phase (many parallel tasks)."""
        return cls(name=name, tasks=tasks or [], tasks_from=tasks_from)

    @classmethod
    def consolidate(
        cls,
        name: str,
        description: str,
        worker: Callable[[Task, RunContext], bool],
        output: str = "SUMMARY.md",
        timeout: int | None = None,
    ) -> Phase:
        """Create a consolidation phase (single task that reads all prior outputs)."""
        task = Task(
            id=f"{name}-consolidation",
            description=description,
            worker=worker,
            outputs={"summary": output},
            timeout=timeout,
        )
        return cls(name=name, tasks=[task], consolidation=True)


@dataclass
class Pipeline:
    """Ordered sequence of phases."""

    phases: list[Phase]

    def has_dynamic_phases(self) -> bool:
        """Return True if any phase uses tasks_from."""
        return any(p.tasks_from is not None for p in self.phases)

    def to_graph(self) -> TaskGraph:
        """Convert static phases into a TaskGraph with inter-phase dependency edges.

        Raises ValueError if any phase uses tasks_from (dynamic phases must be
        resolved by the runner).
        """
        from taskrunner.graph import TaskGraph

        if self.has_dynamic_phases():
            raise ValueError(
                "Cannot convert pipeline with dynamic phases (tasks_from) to a "
                "static graph. Use TaskRunner.run(pipeline) instead."
            )

        graph = TaskGraph()
        prev_phase_ids: list[str] = []

        for phase in self.phases:
            current_phase_ids: list[str] = []
            for task in phase.tasks:
                # Add inter-phase dependencies
                task.depends_on = list(set(task.depends_on) | set(prev_phase_ids))
                # Store phase name in metadata for the runner
                task.metadata.setdefault("_phase", phase.name)
                task.metadata.setdefault("_consolidation", phase.consolidation)
                graph.add(task)
                current_phase_ids.append(task.id)
            prev_phase_ids = current_phase_ids

        return graph


@dataclass
class SetupCallbacks:
    """Hooks for customizing work directory setup.

    These allow callers to control isolation strategy (worktrees, containers,
    temp dirs, etc.) without the runner needing to know the details.

    Attributes:
        setup_work_dir:    Called before each task. Must create and return the
                           work directory. Receives (task, phase_name, output_dir).
        teardown_work_dir: Called after each task completes. Receives
                           (task, work_dir, phase_name).
        setup_consolidation_dir: Called for consolidation phases. Receives
                                 (task, phase_name, output_dir, all_outputs).
    """

    setup_work_dir: Callable[[Task, str, Path], Path] | None = None
    teardown_work_dir: Callable[[Task, Path, str], None] | None = None
    setup_consolidation_dir: Callable[
        [Task, str, Path, dict[str, dict[str, dict[str, Path]]]], Path
    ] | None = None


@dataclass
class PhaseResult:
    """Result of executing a phase."""

    phase: str
    total: int
    completed: int
    failed: int
    skipped: int


@dataclass
class GraphResult:
    """Result of executing a task graph."""

    total: int
    completed: int
    failed: int
    skipped: int
    failed_tasks: list[Task] = field(default_factory=list)
