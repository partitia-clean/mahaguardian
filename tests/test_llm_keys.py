"""
Tests for guardian/llm_keys.py — LLM API key management and rotation.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import guardian.audit as audit_module
import guardian.llm_keys as llm_keys_module
from guardian.llm_keys import (
    init_llm_keys,
    rotate_llm_key,
    schedule_rotation,
    send_llm_key_to_agent,
    stop_rotation,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_VAULT = {
    "llm_api_keys": {
        "anthropic": "FAKE-ANTHROPIC-KEY-DO-NOT-LOG",
        "openai": "FAKE-OPENAI-KEY-DO-NOT-LOG",
    },
    "tool_api_keys": {
        "google_calendar": "gc-key",
    },
}


@pytest.fixture(autouse=True)
def setup_modules(tmp_path):
    """Initialise audit and llm_keys modules."""
    audit_db = tmp_path / "audit.db"
    audit_module.init_audit_log(audit_db)
    init_llm_keys(FAKE_VAULT.copy())
    yield
    llm_keys_module._vault = None
    llm_keys_module._rotation_tasks.clear()


@pytest.fixture
def mock_connection():
    """Mock mTLS connection (httpx.AsyncClient-like)."""
    conn = AsyncMock()
    conn.post = AsyncMock(return_value=MagicMock(status_code=200))
    return conn


# ---------------------------------------------------------------------------
# init_llm_keys
# ---------------------------------------------------------------------------

class TestInitLlmKeys:
    def test_sets_vault_reference(self):
        assert llm_keys_module._vault is not None

    @pytest.mark.asyncio
    async def test_raises_without_init(self, tmp_path):
        llm_keys_module._vault = None
        conn = AsyncMock()
        with pytest.raises(RuntimeError, match="not initialised"):
            await send_llm_key_to_agent("alpha", "anthropic", conn)


# ---------------------------------------------------------------------------
# send_llm_key_to_agent
# ---------------------------------------------------------------------------

class TestSendLlmKeyToAgent:
    @pytest.mark.asyncio
    async def test_returns_rotation_id(self, mock_connection):
        rotation_id = await send_llm_key_to_agent(
            "alpha", "anthropic", mock_connection
        )
        assert isinstance(rotation_id, str)
        assert len(rotation_id) > 0

    @pytest.mark.asyncio
    async def test_posts_to_connection(self, mock_connection):
        await send_llm_key_to_agent("alpha", "anthropic", mock_connection)
        mock_connection.post.assert_called_once()
        call_args = mock_connection.post.call_args
        assert "/llm-key/rotate" in call_args.args[0]
        payload = call_args.kwargs["json"]
        assert payload["provider"] == "anthropic"
        assert payload["key"] == "FAKE-ANTHROPIC-KEY-DO-NOT-LOG"

    @pytest.mark.asyncio
    async def test_key_value_not_in_audit_log(self, mock_connection):
        await send_llm_key_to_agent("alpha", "anthropic", mock_connection)
        entries = audit_module.query_log(action="llm_key.send")
        assert len(entries) >= 1
        for entry in entries:
            for v in entry.values():
                if isinstance(v, str):
                    assert "FAKE-ANTHROPIC-KEY-DO-NOT-LOG" not in v

    @pytest.mark.asyncio
    async def test_audit_logs_provider(self, mock_connection):
        await send_llm_key_to_agent("alpha", "anthropic", mock_connection)
        entries = audit_module.query_log(action="llm_key.send")
        assert entries[-1]["resource"] == "anthropic"
        assert entries[-1]["agent_id"] == "alpha"

    @pytest.mark.asyncio
    async def test_openai_provider(self, mock_connection):
        rotation_id = await send_llm_key_to_agent(
            "alpha", "openai", mock_connection
        )
        assert isinstance(rotation_id, str)
        payload = mock_connection.post.call_args.kwargs["json"]
        assert payload["provider"] == "openai"
        assert payload["key"] == "FAKE-OPENAI-KEY-DO-NOT-LOG"

    @pytest.mark.asyncio
    async def test_missing_provider_raises(self, mock_connection):
        with pytest.raises(KeyError, match="nonexistent"):
            await send_llm_key_to_agent(
                "alpha", "nonexistent", mock_connection
            )

    @pytest.mark.asyncio
    async def test_each_call_different_rotation_id(self, mock_connection):
        r1 = await send_llm_key_to_agent("alpha", "anthropic", mock_connection)
        r2 = await send_llm_key_to_agent("alpha", "anthropic", mock_connection)
        assert r1 != r2


# ---------------------------------------------------------------------------
# rotate_llm_key
# ---------------------------------------------------------------------------

class TestRotateLlmKey:
    @pytest.mark.asyncio
    async def test_returns_new_rotation_id(self, mock_connection):
        new_id = await rotate_llm_key(
            "alpha", "anthropic", mock_connection, "old-rotation-id"
        )
        assert isinstance(new_id, str)
        assert new_id != "old-rotation-id"

    @pytest.mark.asyncio
    async def test_audit_logs_rotation(self, mock_connection):
        await rotate_llm_key(
            "alpha", "anthropic", mock_connection, "old-id"
        )
        entries = audit_module.query_log(action="llm_key.rotate")
        assert len(entries) >= 1
        assert "old-id" in entries[-1]["result"]

    @pytest.mark.asyncio
    async def test_key_not_in_rotation_audit(self, mock_connection):
        await rotate_llm_key(
            "alpha", "anthropic", mock_connection, "old"
        )
        entries = audit_module.query_log(action="llm_key.rotate")
        for entry in entries:
            for v in entry.values():
                if isinstance(v, str):
                    assert "FAKE-ANTHROPIC-KEY-DO-NOT-LOG" not in v


# ---------------------------------------------------------------------------
# schedule_rotation / stop_rotation
# ---------------------------------------------------------------------------

class TestScheduleRotation:
    @pytest.mark.asyncio
    async def test_creates_task(self, mock_connection):
        await schedule_rotation(
            "alpha",
            interval_minutes=1,
            provider="anthropic",
            mtls_connection=mock_connection,
        )
        assert "alpha" in llm_keys_module._rotation_tasks
        task = llm_keys_module._rotation_tasks["alpha"]
        assert not task.done()
        # Cleanup
        stop_rotation("alpha")

    @pytest.mark.asyncio
    async def test_initial_key_sent(self, mock_connection):
        await schedule_rotation(
            "alpha",
            interval_minutes=1,
            provider="anthropic",
            mtls_connection=mock_connection,
        )
        # The initial send happens during schedule_rotation
        mock_connection.post.assert_called()
        stop_rotation("alpha")

    @pytest.mark.asyncio
    async def test_schedule_audit_logged(self, mock_connection):
        await schedule_rotation(
            "alpha",
            interval_minutes=5,
            provider="anthropic",
            mtls_connection=mock_connection,
        )
        entries = audit_module.query_log(action="llm_key.schedule_start")
        assert len(entries) >= 1
        assert "alpha" == entries[-1]["agent_id"]
        stop_rotation("alpha")

    @pytest.mark.asyncio
    async def test_missing_connection_raises(self):
        with pytest.raises(ValueError, match="mtls_connection"):
            await schedule_rotation(
                "alpha",
                interval_minutes=1,
                provider="anthropic",
                mtls_connection=None,
            )


class TestStopRotation:
    @pytest.mark.asyncio
    async def test_cancels_task(self, mock_connection):
        await schedule_rotation(
            "alpha",
            interval_minutes=1,
            provider="anthropic",
            mtls_connection=mock_connection,
        )
        task = llm_keys_module._rotation_tasks["alpha"]
        stop_rotation("alpha")
        # Give event loop a chance to process cancellation
        await asyncio.sleep(0.01)
        assert task.cancelled() or task.done()

    @pytest.mark.asyncio
    async def test_removes_from_tasks_dict(self, mock_connection):
        await schedule_rotation(
            "alpha",
            interval_minutes=1,
            provider="anthropic",
            mtls_connection=mock_connection,
        )
        stop_rotation("alpha")
        assert "alpha" not in llm_keys_module._rotation_tasks

    def test_stop_nonexistent_does_not_raise(self):
        stop_rotation("nonexistent")  # should not raise

    def test_stop_audit_logged(self):
        stop_rotation("alpha")
        entries = audit_module.query_log(action="llm_key.schedule_stop")
        assert len(entries) >= 1


# ---------------------------------------------------------------------------
# Crash recovery (FIX B)
# ---------------------------------------------------------------------------

class TestRotationCrashRecovery:
    @pytest.mark.asyncio
    async def test_loop_continues_after_failure(self, mock_connection):
        """
        FIX B: If rotation fails on one attempt, the loop continues
        and retries on the next interval instead of crashing.
        """
        call_count = 0

        async def flaky_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                # First rotation call (call 1 is initial send, 2 is first rotation)
                raise ConnectionError("simulated network failure")
            return MagicMock(status_code=200)

        mock_connection.post = AsyncMock(side_effect=flaky_post)

        await schedule_rotation(
            "alpha",
            interval_minutes=0,  # 0 minutes = immediate for testing
            provider="anthropic",
            mtls_connection=mock_connection,
        )

        # Let the loop run a couple of iterations (sleep(0) in loop)
        await asyncio.sleep(0.05)
        stop_rotation("alpha")

        # The failure should have been logged
        entries = audit_module.query_log(action="llm_key.rotation_failed")
        assert len(entries) >= 1
        assert "simulated network failure" in entries[0]["result"]

        # But the loop continued — there should be successful sends after the failure
        assert call_count >= 3


# ---------------------------------------------------------------------------
# Duplicate task prevention (FIX C)
# ---------------------------------------------------------------------------

class TestDuplicateTaskPrevention:
    @pytest.mark.asyncio
    async def test_second_schedule_cancels_first(self, mock_connection):
        """
        FIX C: Calling schedule_rotation twice for the same agent
        cancels the first task before starting the second.
        """
        await schedule_rotation(
            "alpha",
            interval_minutes=1,
            provider="anthropic",
            mtls_connection=mock_connection,
        )
        first_task = llm_keys_module._rotation_tasks["alpha"]

        await schedule_rotation(
            "alpha",
            interval_minutes=1,
            provider="anthropic",
            mtls_connection=mock_connection,
        )
        second_task = llm_keys_module._rotation_tasks["alpha"]

        # First task should be cancelled, second should be running
        await asyncio.sleep(0.01)
        assert first_task.cancelled() or first_task.done()
        assert not second_task.done()

        # Only one task in the dict
        assert len([k for k in llm_keys_module._rotation_tasks if k == "alpha"]) == 1

        stop_rotation("alpha")
