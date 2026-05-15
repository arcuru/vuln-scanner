"""Pluggable task scheduling."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from taskrunner.model import Task


@runtime_checkable
class Scheduler(Protocol):
    """Protocol for task selection strategies.

    The scheduler picks which ready task to run next.  Returning ``None``
    when ``ready`` is non-empty signals that all ready tasks are currently
    blocked by external constraints (e.g. per-host connection limits) and
    the runner should wait for a running task to complete before retrying.
    """

    def select(
        self,
        ready: list[Task],
        running: list[Task],
        completed: list[Task],
    ) -> Task | None:
        """Pick the next task to run from the ready set.

        Args:
            ready:     Tasks whose dependencies are satisfied and are not yet running.
            running:   Tasks currently being executed.
            completed: Tasks that have finished (successfully or not).

        Returns:
            The task to run next, or None to wait.
        """
        ...


class FIFOScheduler:
    """Run ready tasks in insertion order (the default)."""

    def select(
        self,
        ready: list[Task],
        running: list[Task],
        completed: list[Task],
    ) -> Task | None:
        return ready[0] if ready else None
