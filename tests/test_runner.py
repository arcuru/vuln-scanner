"""Integration tests for TaskRunner.run_graph()."""

import threading
import time
from pathlib import Path

import pytest

from taskrunner import (
    Phase,
    Pipeline,
    Task,
    TaskGraph,
    TaskRunner,
    TaskStatus,
)
from taskrunner.model import RunContext


def _success_worker(task: Task, ctx: RunContext) -> bool:
    return True


def _fail_worker(task: Task, ctx: RunContext) -> bool:
    return False


def _slow_worker(task: Task, ctx: RunContext) -> bool:
    time.sleep(0.05)
    return True


def _recording_worker(record: list):
    """Create a worker that records execution order."""
    lock = threading.Lock()

    def worker(task: Task, ctx: RunContext) -> bool:
        with lock:
            record.append(task.id)
        return True

    return worker


class TestRunGraphFlat:
    """Flat graph (no dependencies) tests."""

    def test_all_succeed(self, tmp_path: Path):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_success_worker))
        g.add(Task(id="b", description="B", worker=_success_worker))
        g.add(Task(id="c", description="C", worker=_success_worker))

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.total == 3
        assert result.completed == 3
        assert result.failed == 0

    def test_one_fails(self, tmp_path: Path):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_success_worker))
        g.add(Task(id="b", description="B", worker=_fail_worker))

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.completed == 1
        assert result.failed == 1
        assert len(result.failed_tasks) == 1
        assert result.failed_tasks[0].id == "b"

    def test_empty_graph(self, tmp_path: Path):
        g = TaskGraph()
        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        result = runner.run_graph(g)
        assert result.total == 0
        assert result.completed == 0


class TestRunGraphDependencies:
    """DAG dependency tests."""

    def test_linear_chain(self, tmp_path: Path):
        """a -> b -> c must execute in order."""
        order = []
        worker = _recording_worker(order)

        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=worker))
        g.add(Task(id="b", description="B", worker=worker, depends_on=["a"]))
        g.add(Task(id="c", description="C", worker=worker, depends_on=["b"]))

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.completed == 3
        assert order == ["a", "b", "c"]

    def test_diamond(self, tmp_path: Path):
        """a -> {b, c} -> d. d must run after both b and c."""
        order = []
        worker = _recording_worker(order)

        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=worker))
        g.add(Task(id="b", description="B", worker=worker, depends_on=["a"]))
        g.add(Task(id="c", description="C", worker=worker, depends_on=["a"]))
        g.add(Task(id="d", description="D", worker=worker, depends_on=["b", "c"]))

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.completed == 4
        assert order[0] == "a"
        assert order[-1] == "d"
        assert set(order[1:3]) == {"b", "c"}

    def test_failed_dep_skips_descendants(self, tmp_path: Path):
        """If a fails, b (depends on a) should be skipped."""
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_fail_worker))
        g.add(Task(id="b", description="B", worker=_success_worker, depends_on=["a"]))
        g.add(Task(id="c", description="C", worker=_success_worker))

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.failed == 1
        assert result.skipped == 1
        assert result.completed == 1
        assert g.tasks["b"].status == TaskStatus.SKIPPED


class TestRunGraphScheduler:
    """Custom scheduler tests."""

    def test_priority_scheduler(self, tmp_path: Path):
        """Scheduler that picks highest priority (lowest number) first."""
        order = []
        worker = _recording_worker(order)

        class PriorityScheduler:
            def select(self, ready, running, completed):
                if not ready:
                    return None
                return min(ready, key=lambda t: t.metadata.get("priority", 999))

        g = TaskGraph()
        g.add(Task(id="low", description="Low", worker=worker, metadata={"priority": 3}))
        g.add(Task(id="med", description="Med", worker=worker, metadata={"priority": 2}))
        g.add(Task(id="high", description="High", worker=worker, metadata={"priority": 1}))

        # Use jobs=1 to force serial execution so order is deterministic
        runner = TaskRunner(jobs=1, output_dir=tmp_path)
        result = runner.run_graph(g, scheduler=PriorityScheduler())

        assert result.completed == 3
        assert order == ["high", "med", "low"]

    def test_scheduler_returning_none_waits(self, tmp_path: Path):
        """Scheduler that blocks some tasks until others complete."""
        order = []
        worker = _recording_worker(order)

        class OneAtATimeScheduler:
            """Only allow one task of each 'group' at a time."""
            def select(self, ready, running, completed):
                if not ready:
                    return None
                running_groups = {t.metadata.get("group") for t in running}
                for task in ready:
                    if task.metadata.get("group") not in running_groups:
                        return task
                return None  # All groups busy

        g = TaskGraph()
        g.add(Task(id="a1", description="A1", worker=worker, metadata={"group": "a"}))
        g.add(Task(id="a2", description="A2", worker=worker, metadata={"group": "a"}))
        g.add(Task(id="b1", description="B1", worker=worker, metadata={"group": "b"}))

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        result = runner.run_graph(g, scheduler=OneAtATimeScheduler())

        assert result.completed == 3

    def test_deadlock_detection(self, tmp_path: Path):
        """Scheduler that always returns None causes deadlock detection."""
        class NeverScheduler:
            def select(self, ready, running, completed):
                return None

        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_success_worker))

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        result = runner.run_graph(g, scheduler=NeverScheduler())

        assert result.failed == 1
        assert g.tasks["a"].error == "Deadlocked — unresolvable dependencies"


class TestRunGraphLogging:
    """Log file and ctx.print() tests."""

    def test_ctx_print_writes_to_log(self, tmp_path: Path):
        def logging_worker(task: Task, ctx: RunContext) -> bool:
            ctx.print("hello from task")
            ctx.print(f"working in {ctx.work_dir}")
            return True

        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=logging_worker))

        runner = TaskRunner(jobs=1, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.completed == 1
        log = (tmp_path / "logs" / "a.log").read_text()
        assert "hello from task" in log
        assert "working in" in log

    def test_log_file_usable_as_subprocess_stdout(self, tmp_path: Path):
        import subprocess

        def subprocess_worker(task: Task, ctx: RunContext) -> bool:
            proc = subprocess.run(
                ["echo", "subprocess output"],
                stdout=ctx.log_file,
                stderr=ctx.log_file,
            )
            return proc.returncode == 0

        g = TaskGraph()
        g.add(Task(id="b", description="B", worker=subprocess_worker))

        runner = TaskRunner(jobs=1, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.completed == 1
        log = (tmp_path / "logs" / "b.log").read_text()
        assert "subprocess output" in log

    def test_subprocess_args_helper(self, tmp_path: Path):
        import subprocess

        def helper_worker(task: Task, ctx: RunContext) -> bool:
            proc = subprocess.run(
                ["echo", "via helper"],
                **ctx.subprocess_args(),
            )
            return proc.returncode == 0

        g = TaskGraph()
        g.add(Task(id="c", description="C", worker=helper_worker))

        runner = TaskRunner(jobs=1, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.completed == 1
        log = (tmp_path / "logs" / "c.log").read_text()
        assert "via helper" in log


class TestRunGraphResumability:
    """Output-exists skip tests."""

    def test_skips_task_with_existing_outputs(self, tmp_path: Path):
        g = TaskGraph()
        g.add(Task(
            id="a", description="A", worker=_success_worker,
            outputs={"report": "report.txt"},
        ))
        # Pre-create the output
        (tmp_path / "report.txt").write_text("already done")
        (tmp_path / "a.done").write_text("")

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.skipped == 1
        assert result.completed == 0


class TestPipelineToGraph:
    """Pipeline.to_graph() backward compatibility."""

    def test_static_pipeline_converts(self, tmp_path: Path):
        order = []
        worker = _recording_worker(order)

        pipeline = Pipeline(phases=[
            Phase(name="phase1", tasks=[
                Task(id="a", description="A", worker=worker),
                Task(id="b", description="B", worker=worker),
            ]),
            Phase(name="phase2", tasks=[
                Task(id="c", description="C", worker=worker),
            ]),
        ])

        graph = pipeline.to_graph()
        assert "a" in graph.tasks
        assert "b" in graph.tasks
        assert "c" in graph.tasks
        # c should depend on a and b
        assert set(graph.tasks["c"].depends_on) == {"a", "b"}

    def test_dynamic_pipeline_raises(self):
        pipeline = Pipeline(phases=[
            Phase(name="p1", tasks_from=lambda prev: []),
        ])
        with pytest.raises(ValueError, match="dynamic phases"):
            pipeline.to_graph()

    def test_pipeline_run_still_works(self, tmp_path: Path):
        """The existing run(pipeline) path should still work."""
        order = []
        worker = _recording_worker(order)

        pipeline = Pipeline(phases=[
            Phase(name="scan", tasks=[
                Task(id="a", description="A", worker=worker),
            ]),
            Phase(name="verify", tasks=[
                Task(id="b", description="B", worker=worker),
            ]),
        ])

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        results = runner.run(pipeline)

        assert "scan" in results
        assert "verify" in results
        assert results["scan"].completed == 1
        assert results["verify"].completed == 1

    def test_pipeline_with_tasks_from(self, tmp_path: Path):
        """Dynamic pipeline with tasks_from should work via run()."""
        order = []
        worker = _recording_worker(order)

        pipeline = Pipeline(phases=[
            Phase(name="scan", tasks=[
                Task(id="a", description="A", worker=worker),
            ]),
            Phase(
                name="verify",
                tasks_from=lambda prev: [
                    Task(
                        id=f"verify-{t.id}",
                        description=f"Verify {t.id}",
                        worker=worker,
                    )
                    for t in prev
                    if t.status == TaskStatus.COMPLETED
                ],
            ),
        ])

        runner = TaskRunner(jobs=4, output_dir=tmp_path)
        results = runner.run(pipeline)

        assert results["scan"].completed == 1
        assert results["verify"].completed == 1
        assert "verify-a" in order


class TestRunGraphDynamicInjection:
    """Workers can inject new tasks into the graph during execution."""

    def test_worker_injects_task(self, tmp_path: Path):
        """A worker can add a new task via ctx.graph and it gets executed."""
        order = []
        lock = threading.Lock()

        def worker(task: Task, ctx: RunContext) -> bool:
            with lock:
                order.append(task.id)
            if task.id == "a":
                assert ctx.graph is not None
                ctx.graph.add(Task(
                    id="injected",
                    description="Injected",
                    worker=worker,
                ))
            return True

        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=worker))
        g.add(Task(id="b", description="B", worker=worker))

        runner = TaskRunner(jobs=1, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.total == 3
        assert result.completed == 3
        assert "injected" in order

    def test_injected_task_depends_on_completed(self, tmp_path: Path):
        """Injected task depending on an already-completed task runs after it."""
        order = []
        lock = threading.Lock()

        def worker(task: Task, ctx: RunContext) -> bool:
            with lock:
                order.append(task.id)
            if task.id == "a":
                ctx.graph.add(Task(
                    id="c",
                    description="C",
                    worker=worker,
                    depends_on=["a"],
                ))
            return True

        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=worker))
        g.add(Task(id="b", description="B", worker=worker))

        runner = TaskRunner(jobs=1, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.completed == 3
        assert order.index("a") < order.index("c")

    def test_injected_task_depends_on_pending(self, tmp_path: Path):
        """Injected task waits for its dependency to complete."""
        order = []
        lock = threading.Lock()

        def worker(task: Task, ctx: RunContext) -> bool:
            if task.id == "a":
                # Inject a task that depends on "b" which hasn't completed yet
                ctx.graph.add(Task(
                    id="c",
                    description="C",
                    worker=worker,
                    depends_on=["b"],
                ))
            if task.id == "b":
                time.sleep(0.05)
            with lock:
                order.append(task.id)
            return True

        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=worker))
        g.add(Task(id="b", description="B", worker=worker))

        runner = TaskRunner(jobs=2, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.completed == 3
        assert order.index("b") < order.index("c")

    def test_injected_task_skipped_on_dep_failure(self, tmp_path: Path):
        """Injected task is skipped if its dependency fails."""

        def worker(task: Task, ctx: RunContext) -> bool:
            if task.id == "a":
                ctx.graph.add(Task(
                    id="c",
                    description="C",
                    worker=worker,
                    depends_on=["b"],
                ))
                return True
            if task.id == "b":
                return False
            return True

        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=worker))
        g.add(Task(id="b", description="B", worker=worker))

        runner = TaskRunner(jobs=1, output_dir=tmp_path)
        result = runner.run_graph(g)

        assert result.completed == 1  # only "a"
        assert result.failed == 1     # "b"
        assert result.skipped == 1    # "c"

    def test_ctx_graph_is_none_in_phase_mode(self, tmp_path: Path):
        """In pipeline mode, ctx.graph should be None."""
        seen_graph = []

        def worker(task: Task, ctx: RunContext) -> bool:
            seen_graph.append(ctx.graph)
            return True

        pipeline = Pipeline(phases=[
            Phase(name="p1", tasks=[
                Task(id="a", description="A", worker=worker),
            ]),
        ])

        runner = TaskRunner(jobs=1, output_dir=tmp_path)
        runner.run(pipeline)

        assert seen_graph == [None]
