"""Task graph with dependency tracking."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from taskrunner.model import Task, TaskStatus


class CycleError(Exception):
    """Raised when a dependency cycle is detected in the task graph."""


class MissingDependencyError(Exception):
    """Raised when a task depends on a non-existent task ID."""


@dataclass
class TaskGraph:
    """A set of tasks with dependency edges.

    The fundamental execution unit for the DAG-based runner.  Tasks declare
    dependencies via ``depends_on`` (list of task IDs).  A task is *ready*
    when all its dependencies have completed (or failed/skipped).

    Thread-safe: ``add()`` can be called from worker threads to inject new
    tasks during execution.
    """

    tasks: dict[str, Task] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, task: Task) -> None:
        """Add a task to the graph.

        Raises ValueError if a task with the same ID already exists.
        """
        with self._lock:
            if task.id in self.tasks:
                raise ValueError(f"Duplicate task ID: {task.id!r}")
            self.tasks[task.id] = task

    def ready(self, done_ids: set[str]) -> list[Task]:
        """Return tasks whose dependencies are all satisfied.

        A task is ready when:
        - Its status is PENDING (not yet submitted)
        - All task IDs in its ``depends_on`` are present in ``done_ids``

        Args:
            done_ids: Set of task IDs that have completed, failed, or been skipped.

        Returns:
            List of ready tasks, in insertion order.
        """
        with self._lock:
            return [
                task
                for task in self.tasks.values()
                if task.id not in done_ids
                and task.status == TaskStatus.PENDING
                and all(dep in done_ids for dep in task.depends_on)
            ]

    def validate(self) -> None:
        """Check the graph for errors.

        Raises:
            MissingDependencyError: If a task depends on a non-existent task ID.
            CycleError: If there is a dependency cycle.
        """
        with self._lock:
            self._check_missing_deps()
            self._check_cycles()

    def _check_missing_deps(self) -> None:
        for task in self.tasks.values():
            for dep_id in task.depends_on:
                if dep_id not in self.tasks:
                    raise MissingDependencyError(
                        f"Task {task.id!r} depends on {dep_id!r}, "
                        f"which does not exist in the graph"
                    )

    def _check_cycles(self) -> None:
        """Detect cycles using iterative DFS with three-color marking."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {tid: WHITE for tid in self.tasks}

        for start_id in self.tasks:
            if color[start_id] != WHITE:
                continue

            stack: list[tuple[str, int]] = [(start_id, 0)]
            color[start_id] = GRAY

            while stack:
                node_id, dep_idx = stack.pop()
                deps = self.tasks[node_id].depends_on

                if dep_idx < len(deps):
                    # Push current node back with next dep index
                    stack.append((node_id, dep_idx + 1))

                    dep_id = deps[dep_idx]
                    if color[dep_id] == GRAY:
                        raise CycleError(
                            f"Dependency cycle detected involving task {dep_id!r}"
                        )
                    if color[dep_id] == WHITE:
                        color[dep_id] = GRAY
                        stack.append((dep_id, 0))
                else:
                    color[node_id] = BLACK

    def descendants(self, task_id: str) -> set[str]:
        """Return all task IDs that transitively depend on the given task."""
        result: set[str] = set()
        queue = [task_id]
        while queue:
            current = queue.pop()
            with self._lock:
                for task in self.tasks.values():
                    if current in task.depends_on and task.id not in result:
                        result.add(task.id)
                        queue.append(task.id)
        return result
