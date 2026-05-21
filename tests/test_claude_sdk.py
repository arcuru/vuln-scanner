"""Tests for the Claude Agent SDK backend.

We mock ``claude_agent_sdk.query`` so no real API calls happen. The fake
yields a real ``ResultMessage`` instance so the backend's ``isinstance``
check passes naturally.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from claude_agent_sdk import ResultMessage

from vuln_scanner.claude import BACKENDS
from vuln_scanner.claude_sdk import ClaudeSDKBackend


def _result(subtype: str) -> ResultMessage:
    """Build a minimal ResultMessage with the given subtype."""
    return ResultMessage(
        subtype=subtype,
        duration_ms=10,
        duration_api_ms=5,
        is_error=(subtype != "success"),
        num_turns=1,
        session_id="11111111-1111-1111-1111-111111111111",
    )


def _fake_query_yielding(*messages):
    """Return an async-iterator factory that yields the given messages."""
    async def factory(prompt, options):
        for m in messages:
            yield m
    return factory


class TestRegistry:
    def test_registered(self):
        assert isinstance(BACKENDS["claude-sdk"], ClaudeSDKBackend)


class TestRun:
    def test_success(self, tmp_path):
        backend = ClaudeSDKBackend()
        with patch(
            "vuln_scanner.claude_sdk.query",
            _fake_query_yielding(_result("success")),
        ):
            ok = backend.run(
                cwd=tmp_path, prompt="hi", log_path=tmp_path / "log",
                ctx=None, model=None, flags="",
            )
        assert ok.success is True
        assert (tmp_path / "log").is_file()
        assert "ResultMessage" in (tmp_path / "log").read_text()

    def test_failure_subtype(self, tmp_path):
        backend = ClaudeSDKBackend()
        with patch(
            "vuln_scanner.claude_sdk.query",
            _fake_query_yielding(_result("error_max_turns")),
        ):
            ok = backend.run(
                cwd=tmp_path, prompt="hi", log_path=tmp_path / "log",
                ctx=None, model=None, flags="",
            )
        assert ok.success is False

    def test_no_result_message(self, tmp_path):
        backend = ClaudeSDKBackend()
        with patch(
            "vuln_scanner.claude_sdk.query",
            _fake_query_yielding(),  # stream ends without a ResultMessage
        ):
            ok = backend.run(
                cwd=tmp_path, prompt="hi", log_path=tmp_path / "log",
                ctx=None, model=None, flags="",
            )
        assert ok.success is False

    def test_timeout(self, tmp_path):
        async def slow(prompt, options):
            await asyncio.sleep(10)
            yield _result("success")

        # Stub ctx so the backend reads its timeout
        class _StubTask:
            timeout = 1
        class _StubCtx:
            task = _StubTask()

        backend = ClaudeSDKBackend()
        with patch("vuln_scanner.claude_sdk.query", slow):
            ok = backend.run(
                cwd=tmp_path, prompt="hi", log_path=tmp_path / "log",
                ctx=_StubCtx(), model=None, flags="",
            )
        assert ok.success is False

    def test_model_passed_to_options(self, tmp_path):
        captured = {}

        async def capturing(prompt, options):
            captured["model"] = options.model
            captured["cwd"] = options.cwd
            captured["permission_mode"] = options.permission_mode
            yield _result("success")

        backend = ClaudeSDKBackend()
        with patch("vuln_scanner.claude_sdk.query", capturing):
            backend.run(
                cwd=tmp_path, prompt="hi", log_path=tmp_path / "log",
                ctx=None, model="claude-opus-4-7", flags="",
            )
        assert captured["model"] == "claude-opus-4-7"
        assert captured["cwd"] == str(tmp_path)
        assert captured["permission_mode"] == "bypassPermissions"

    def test_unused_flags_string_ignored(self, tmp_path):
        """``flags`` is a CLI concept; SDK backend should accept and drop it."""
        backend = ClaudeSDKBackend()
        with patch(
            "vuln_scanner.claude_sdk.query",
            _fake_query_yielding(_result("success")),
        ):
            ok = backend.run(
                cwd=tmp_path, prompt="hi", log_path=tmp_path / "log",
                ctx=None, model=None, flags="--verbose --thinking high",
            )
        assert ok.success is True
