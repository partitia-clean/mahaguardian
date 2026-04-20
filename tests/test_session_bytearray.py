"""
Tests for AgentSession.llm_api_key bytearray enforcement.

Verifies that the property setter always converts to bytearray
and zeros the old key before replacement.
"""
from __future__ import annotations

import pytest

from agent.session import AgentSession


class TestLlmApiKeyPropertySetter:
    """The llm_api_key setter must enforce bytearray on every assignment."""

    def test_assign_str_becomes_bytearray(self):
        session = AgentSession()
        session.llm_api_key = "sk-test-key-abc"
        assert isinstance(session.llm_api_key, bytearray)
        assert session.llm_api_key == bytearray(b"sk-test-key-abc")

    def test_assign_bytes_becomes_bytearray(self):
        session = AgentSession()
        session.llm_api_key = b"sk-test-key-bytes"
        assert isinstance(session.llm_api_key, bytearray)
        assert session.llm_api_key == bytearray(b"sk-test-key-bytes")

    def test_assign_bytearray_stays_bytearray(self):
        session = AgentSession()
        key = bytearray(b"sk-test-key-ba")
        session.llm_api_key = key
        assert isinstance(session.llm_api_key, bytearray)
        assert session.llm_api_key is key

    def test_assign_none(self):
        session = AgentSession()
        session.llm_api_key = "sk-initial"
        session.llm_api_key = None
        assert session.llm_api_key is None

    def test_assign_invalid_type_raises(self):
        session = AgentSession()
        with pytest.raises(TypeError, match="must be str, bytes, or bytearray"):
            session.llm_api_key = 12345


class TestOldKeyZeroed:
    """Assigning a new key must zero the old key in place first."""

    def test_old_key_zeroed_on_replacement(self):
        session = AgentSession()
        session.llm_api_key = "old-secret-key"
        old_ref = session.llm_api_key  # grab reference before replacement
        session.llm_api_key = "new-secret-key"
        # Old bytearray should now be all zeros
        assert all(b == 0 for b in old_ref)

    def test_old_key_zeroed_on_none_assignment(self):
        session = AgentSession()
        session.llm_api_key = "secret-to-clear"
        old_ref = session.llm_api_key
        session.llm_api_key = None
        assert all(b == 0 for b in old_ref)


class TestClearZeros:
    """clear() must zero all bytes before dropping the reference."""

    def test_clear_zeros_key(self):
        session = AgentSession()
        session.llm_api_key = "sk-clear-me"
        key_ref = session.llm_api_key
        session.clear()
        # The bytearray we held a reference to should be all zeros
        assert all(b == 0 for b in key_ref)

    def test_clear_resets_to_none(self):
        session = AgentSession()
        session.llm_api_key = "sk-something"
        session.clear()
        # After clear, the backing field is None
        assert session.llm_api_key is None

    def test_clear_with_empty_key_does_not_raise(self):
        session = AgentSession()
        session.clear()  # should not raise


class TestGetLlmApiKey:
    """get_llm_api_key() must still return the decoded string."""

    def test_roundtrip_via_setter(self):
        session = AgentSession()
        session.llm_api_key = "sk-roundtrip"
        assert session.get_llm_api_key() == "sk-roundtrip"

    def test_roundtrip_via_set_method(self):
        session = AgentSession()
        session.set_llm_api_key("sk-method")
        assert session.get_llm_api_key() == "sk-method"
