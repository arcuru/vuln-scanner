"""Backward-compatibility shim — all symbols moved to submodules.

Import from ``taskrunner`` directly instead::

    from taskrunner import Task, TaskRunner, TaskGraph
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
