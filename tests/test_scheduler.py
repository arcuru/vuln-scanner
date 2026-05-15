"""Tests for Scheduler protocol and FIFOScheduler."""

from taskrunner import FIFOScheduler, Scheduler, Task


def _noop(task, ctx):
    return True


class TestFIFOScheduler:
    def test_implements_protocol(self):
        assert isinstance(FIFOScheduler(), Scheduler)

    def test_returns_first_ready(self):
        s = FIFOScheduler()
        tasks = [
            Task(id="a", description="A", worker=_noop),
            Task(id="b", description="B", worker=_noop),
        ]
        assert s.select(ready=tasks, running=[], completed=[]) is tasks[0]

    def test_returns_none_when_empty(self):
        s = FIFOScheduler()
        assert s.select(ready=[], running=[], completed=[]) is None


class TestCustomScheduler:
    def test_custom_scheduler_satisfies_protocol(self):
        class PriorityScheduler:
            def select(self, ready, running, completed):
                return min(ready, key=lambda t: t.metadata.get("priority", 0))

        s = PriorityScheduler()
        assert isinstance(s, Scheduler)

        tasks = [
            Task(id="low", description="Low", worker=_noop, metadata={"priority": 10}),
            Task(id="high", description="High", worker=_noop, metadata={"priority": 1}),
        ]
        selected = s.select(ready=tasks, running=[], completed=[])
        assert selected.id == "high"

    def test_scheduler_returning_none_blocks(self):
        """A scheduler can return None to signal all ready tasks are constrained."""
        class BlockingScheduler:
            def select(self, ready, running, completed):
                return None

        s = BlockingScheduler()
        tasks = [Task(id="a", description="A", worker=_noop)]
        assert s.select(ready=tasks, running=[], completed=[]) is None
