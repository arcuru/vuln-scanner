"""taskrunner — parallel task execution with DAG scheduling, phases, and Rich progress.

Core abstractions:
    Task        — unit of work with inputs, outputs, status, and metadata
    TaskGraph   — set of tasks with dependency edges (the DAG)
    Scheduler   — pluggable strategy for picking which ready task runs next
    Phase       — a named collection of tasks that run in parallel
    Pipeline    — ordered sequence of phases (sugar on top of TaskGraph)
    TaskRunner  — executes a pipeline or task graph with concurrency control

Graph mode (DAG):

    from taskrunner import Task, TaskGraph, TaskRunner

    def my_worker(task: Task, ctx: RunContext) -> bool:
        ...
        return True

    graph = TaskGraph()
    graph.add(Task(id="a", description="Step A", worker=my_worker))
    graph.add(Task(id="b", description="Step B", worker=my_worker, depends_on=["a"]))

    runner = TaskRunner(jobs=4)
    result = runner.run_graph(graph)

Pipeline mode (backward-compatible):

    from taskrunner import Task, Phase, Pipeline, TaskRunner

    pipeline = Pipeline(phases=[
        Phase(name="scan", tasks=[...]),
        Phase(name="verify", tasks_from=lambda prev: [...]),
    ])
    runner = TaskRunner(jobs=4)
    results = runner.run(pipeline)
"""

from taskrunner.graph import CycleError, MissingDependencyError, TaskGraph
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
from taskrunner.runner import TaskRunner
from taskrunner.scheduler import FIFOScheduler, Scheduler

__all__ = [
    "CycleError",
    "FIFOScheduler",
    "GraphResult",
    "MissingDependencyError",
    "Phase",
    "PhaseResult",
    "Pipeline",
    "RunContext",
    "Scheduler",
    "SetupCallbacks",
    "Task",
    "TaskGraph",
    "TaskRunner",
    "TaskStatus",
]
