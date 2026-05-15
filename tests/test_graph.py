"""Tests for TaskGraph."""

import pytest

from taskrunner import Task, TaskGraph, TaskStatus
from taskrunner.graph import CycleError, MissingDependencyError


def _noop(task, ctx):
    return True


class TestTaskGraphAdd:
    def test_add_task(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        assert "a" in g.tasks

    def test_add_duplicate_raises(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        with pytest.raises(ValueError, match="Duplicate"):
            g.add(Task(id="a", description="A2", worker=_noop))


class TestTaskGraphReady:
    def test_no_deps_all_ready(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        g.add(Task(id="b", description="B", worker=_noop))
        ready = g.ready(set())
        assert {t.id for t in ready} == {"a", "b"}

    def test_dep_not_satisfied(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        g.add(Task(id="b", description="B", worker=_noop, depends_on=["a"]))
        ready = g.ready(set())
        assert [t.id for t in ready] == ["a"]

    def test_dep_satisfied(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        g.add(Task(id="b", description="B", worker=_noop, depends_on=["a"]))
        ready = g.ready({"a"})
        assert [t.id for t in ready] == ["b"]

    def test_excludes_non_pending(self):
        g = TaskGraph()
        t = Task(id="a", description="A", worker=_noop)
        t.status = TaskStatus.RUNNING
        g.add(t)
        assert g.ready(set()) == []

    def test_diamond(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        g.add(Task(id="b", description="B", worker=_noop, depends_on=["a"]))
        g.add(Task(id="c", description="C", worker=_noop, depends_on=["a"]))
        g.add(Task(id="d", description="D", worker=_noop, depends_on=["b", "c"]))

        # Initially only a is ready
        assert [t.id for t in g.ready(set())] == ["a"]
        # After a completes, b and c are ready
        assert {t.id for t in g.ready({"a"})} == {"b", "c"}
        # After a and b, only c is ready (d needs c too)
        assert {t.id for t in g.ready({"a", "b"})} == {"c"}
        # After a, b, c all done, d is ready
        assert {t.id for t in g.ready({"a", "b", "c"})} == {"d"}


class TestTaskGraphValidate:
    def test_valid_graph(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        g.add(Task(id="b", description="B", worker=_noop, depends_on=["a"]))
        g.validate()  # should not raise

    def test_missing_dependency(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop, depends_on=["missing"]))
        with pytest.raises(MissingDependencyError, match="missing"):
            g.validate()

    def test_self_cycle(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop, depends_on=["a"]))
        with pytest.raises(CycleError):
            g.validate()

    def test_two_node_cycle(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop, depends_on=["b"]))
        g.add(Task(id="b", description="B", worker=_noop, depends_on=["a"]))
        with pytest.raises(CycleError):
            g.validate()

    def test_three_node_cycle(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop, depends_on=["c"]))
        g.add(Task(id="b", description="B", worker=_noop, depends_on=["a"]))
        g.add(Task(id="c", description="C", worker=_noop, depends_on=["b"]))
        with pytest.raises(CycleError):
            g.validate()


class TestTaskGraphDescendants:
    def test_no_descendants(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        assert g.descendants("a") == set()

    def test_direct_descendants(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        g.add(Task(id="b", description="B", worker=_noop, depends_on=["a"]))
        g.add(Task(id="c", description="C", worker=_noop, depends_on=["a"]))
        assert g.descendants("a") == {"b", "c"}

    def test_transitive_descendants(self):
        g = TaskGraph()
        g.add(Task(id="a", description="A", worker=_noop))
        g.add(Task(id="b", description="B", worker=_noop, depends_on=["a"]))
        g.add(Task(id="c", description="C", worker=_noop, depends_on=["b"]))
        assert g.descendants("a") == {"b", "c"}
