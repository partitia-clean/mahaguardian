"""
Tests for Workstream 3: LLM Key Delivery Pipeline.

Covers:
- /session/start returns LLM key
- LLM key never appears in audit log
- RotatedKey repr redacts key
- Session state registry
- WebSocket-based key rotation
"""
from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import guardian.audit as audit_module
import guardian.main as main_module
import guardian.mtls as mtls_module
import guardian.payments as payments_module
import guardian.tokens as tokens_module
import guardian.tools as tools_module
import guardian.vault as vault_module
import guardian.llm_keys as llm_keys_module
from guardian.main import app
from guardian.session_state import (
    SessionInfo,
    clear_all,
    get_session,
    is_external_agent,
    register_session,
    remove_session,
)
from guardian.tokens import generate_token_keypair, init_tokens, issue_token
from guardian.vault import init_vault, unlock_vault
from shared.models import RotatedKey

PASSPHRASE = "llm-delivery-test-2026"
CERT_PASSPHRASE = "test-cert-passphrase"


@pytest.fixture(autouse=True)
def setup(tmp_path, monkeypatch):
    """Isolate every module to tmp_path."""
    audit_module.init_audit_log(tmp_path / "audit.db")

    # FIX 10: TRUST_REQUEST_CERT defaults to False in production.
    # Patch to True for tests that use TestClient (no real TLS).
    monkeypatch.setattr(main_module, "TRUST_REQUEST_CERT", True)

    monkeypatch.setattr(vault_module, "VAULT_DIR", tmp_path / "vault")
    monkeypatch.setattr(vault_module, "VAULT_PATH", tmp_path / "vault" / "vault.enc")
    monkeypatch.setattr(vault_module, "KEYS_DIR", tmp_path / "vault" / "keys")
    monkeypatch.setattr(vault_module, "AGE_KEY_PATH", tmp_path / "vault" / "keys" / "master.key")
    monkeypatch.setattr(vault_module, "AGE_PUBKEY_PATH", tmp_path / "vault" / "keys" / "master.key.pub")

    certs = tmp_path / "certs"
    monkeypatch.setattr(mtls_module, "CERTS_DIR", certs)
    monkeypatch.setattr(mtls_module, "CA_CERT_PATH", certs / "ca.crt")
    monkeypatch.setattr(mtls_module, "CA_KEY_PATH", certs / "ca.key")
    monkeypatch.setattr(mtls_module, "GUARDIAN_CERT_PATH", certs / "guardian.crt")
    monkeypatch.setattr(mtls_module, "GUARDIAN_KEY_PATH", certs / "guardian.key")
    monkeypatch.setattr(mtls_module, "AGENT_CERTS_DIR", certs / "agents")

    yield tmp_path

    tokens_module._signing_key = None
    tokens_module._verify_key = None
    tokens_module._db_path = None
    main_module._signing_key_bytes = None
    main_module._verify_key_bytes = None
    main_module._revocation_store = None
    main_module._deduplicator = None
    payments_module._vault = None
    tools_module._vault = None
    main_module._vault_dict = None
    llm_keys_module._vault = None
    clear_all()


def _full_init(tmp_path):
    """Full Guardian init returning (vault_dict, agent_cert_b64)."""
    import nacl.signing as _nacl
    init_vault(PASSPHRASE)
    vault_dict = unlock_vault(PASSPHRASE)

    ca_cert, ca_key = mtls_module.generate_ca(CERT_PASSPHRASE)
    agent_cert, _ = mtls_module.generate_agent_cert(
        "alpha", ca_cert, ca_key, CERT_PASSPHRASE,
    )

    # Phase 3 token state
    _sk = _nacl.SigningKey.generate()
    main_module._signing_key_bytes = bytes(_sk)
    main_module._verify_key_bytes = bytes(_sk.verify_key)
    from shared.token import RevocationStore, RequestDeduplicator
    main_module._revocation_store = RevocationStore()
    main_module._deduplicator = RequestDeduplicator()

    tools_module.init_tools(vault_dict)
    payments_module.init_payments(vault_dict)
    llm_keys_module.init_llm_keys(vault_dict)
    main_module._vault_dict = vault_dict

    agent_cert_b64 = base64.b64encode(agent_cert).decode("ascii")
    return vault_dict, agent_cert_b64


# ---------------------------------------------------------------------------
# Session state registry
# ---------------------------------------------------------------------------

class TestSessionState:

    def test_register_and_get(self):
        info = SessionInfo(agent_id="alpha", session_id="sess-1")
        register_session(info)
        assert get_session("alpha") is info

    def test_get_missing_returns_none(self):
        assert get_session("nonexistent") is None

    def test_remove_session(self):
        register_session(SessionInfo(agent_id="alpha", session_id="sess-1"))
        remove_session("alpha")
        assert get_session("alpha") is None

    def test_is_external_primary(self):
        register_session(SessionInfo(
            agent_id="alpha", session_id="sess-1", is_primary=True,
        ))
        assert is_external_agent("alpha") is False

    def test_is_external_external(self):
        register_session(SessionInfo(
            agent_id="ext-1", session_id="sess-2", is_primary=False,
        ))
        assert is_external_agent("ext-1") is True

    def test_is_external_unknown_defaults_external(self):
        assert is_external_agent("unknown") is True

    def test_clear_all(self):
        register_session(SessionInfo(agent_id="a", session_id="s1"))
        register_session(SessionInfo(agent_id="b", session_id="s2"))
        clear_all()
        assert get_session("a") is None
        assert get_session("b") is None


# ---------------------------------------------------------------------------
# RotatedKey repr redaction
# ---------------------------------------------------------------------------

class TestRotatedKeyRepr:

    def test_repr_does_not_contain_key(self):
        rk = RotatedKey(provider="anthropic", key="sk-secret-key-123", rotation_id="r1")
        r = repr(rk)
        assert "sk-secret-key-123" not in r

    def test_key_accessible_via_field(self):
        rk = RotatedKey(provider="anthropic", key="sk-secret-key-123", rotation_id="r1")
        assert rk.key == "sk-secret-key-123"


# ---------------------------------------------------------------------------
# /session/start returns LLM key
# ---------------------------------------------------------------------------

class TestSessionStartLLMKey:

    def _setup_soul_files(self, tmp_path, vault_dict):
        """Create the SOUL files needed for /session/start."""
        from guardian.soul import (
            generate_soul_keypair,
            sign_soul,
            update_soul_hash_ledger,
        )
        import guardian.soul as soul_module

        # Patch paths
        core_dir = tmp_path / "core"
        core_dir.mkdir(parents=True, exist_ok=True)
        agents_dir = core_dir / "agents"
        agents_dir.mkdir(parents=True, exist_ok=True)

        soul_module.SOUL_HASH_PATH = core_dir / "SOUL.hash"

        priv, pub = generate_soul_keypair()
        pub_b64 = base64.b64encode(pub).decode("ascii")

        # Store soul public key in vault
        if "signing_keys" not in vault_dict:
            vault_dict["signing_keys"] = {}
        vault_dict["signing_keys"]["soul_public_key"] = pub_b64

        # Create master SOUL
        master = core_dir / "master-SOUL.lock"
        master.write_text('[meta]\nagent = "master"\n', encoding="utf-8")
        sign_soul(master, priv)
        update_soul_hash_ledger(master, priv)

        # Create agent SOUL
        agent_soul = agents_dir / "alpha-SOUL.lock"
        agent_soul.write_text('[meta]\nagent = "alpha"\n', encoding="utf-8")
        sign_soul(agent_soul, priv)
        update_soul_hash_ledger(agent_soul, priv)

        return core_dir, agents_dir

    def test_session_start_includes_llm_key(self, setup, monkeypatch):
        """Response includes llm_key when vault has one."""
        tmp_path = setup
        vault_dict, agent_cert_b64 = _full_init(tmp_path)

        # Add LLM key to vault
        vault_dict["llm_api_keys"] = {"anthropic": "sk-test-key-abc"}

        core_dir, agents_dir = self._setup_soul_files(tmp_path, vault_dict)
        monkeypatch.setattr(main_module, "CORE_DIR", core_dir)
        monkeypatch.setattr(main_module, "AGENTS_SOUL_DIR", agents_dir)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/session/start", json={
            "agent_id": "alpha",
            "agent_cert_b64": agent_cert_b64,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["llm_key"] == "sk-test-key-abc"
        assert data["llm_provider"] == "anthropic"
        assert "rotation_id" in data

    def test_session_start_without_llm_key(self, setup, monkeypatch):
        """Response omits llm_key when vault has none."""
        tmp_path = setup
        vault_dict, agent_cert_b64 = _full_init(tmp_path)

        # No llm_api_keys in vault
        core_dir, agents_dir = self._setup_soul_files(tmp_path, vault_dict)
        monkeypatch.setattr(main_module, "CORE_DIR", core_dir)
        monkeypatch.setattr(main_module, "AGENTS_SOUL_DIR", agents_dir)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/session/start", json={
            "agent_id": "alpha",
            "agent_cert_b64": agent_cert_b64,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "llm_key" not in data

    def test_llm_key_not_in_audit_log(self, setup, monkeypatch):
        """The LLM key value must NEVER appear in any audit log entry."""
        tmp_path = setup
        vault_dict, agent_cert_b64 = _full_init(tmp_path)
        vault_dict["llm_api_keys"] = {"anthropic": "sk-super-secret-12345"}

        core_dir, agents_dir = self._setup_soul_files(tmp_path, vault_dict)
        monkeypatch.setattr(main_module, "CORE_DIR", core_dir)
        monkeypatch.setattr(main_module, "AGENTS_SOUL_DIR", agents_dir)

        client = TestClient(app, raise_server_exceptions=False)
        client.post("/session/start", json={
            "agent_id": "alpha",
            "agent_cert_b64": agent_cert_b64,
        })

        # Check all audit entries
        entries = audit_module.query_log()
        for entry in entries:
            for field in ("action", "resource", "result", "agent_id"):
                val = entry.get(field, "") or ""
                assert "sk-super-secret-12345" not in val, (
                    f"LLM key found in audit log field '{field}': {val}"
                )


# ---------------------------------------------------------------------------
# WebSocket-based key rotation
# ---------------------------------------------------------------------------

class TestWSKeyRotation:

    def test_schedule_ws_rotation_creates_task(self, setup):
        """schedule_ws_rotation creates an asyncio task."""
        tmp_path = setup
        init_vault(PASSPHRASE)
        vault_dict = unlock_vault(PASSPHRASE)
        vault_dict["llm_api_keys"] = {"anthropic": "sk-test"}
        llm_keys_module.init_llm_keys(vault_dict)

        mock_ws = AsyncMock()

        async def run():
            from guardian.llm_keys import schedule_ws_rotation, _rotation_tasks, stop_rotation
            await schedule_ws_rotation(
                agent_id="alpha",
                ws_client=mock_ws,
                provider="anthropic",
                interval_minutes=1,
            )
            assert "alpha" in _rotation_tasks
            # Clean up
            stop_rotation("alpha")

        asyncio.run(run())

    def test_agent_key_rotation_handler_stores_bytearray(self, setup):
        """Agent's _handle_key_rotation stores key as bytearray."""
        from agent.main import _handle_key_rotation, _session

        async def run():
            await _handle_key_rotation({
                "key": "sk-rotated-key",
                "provider": "anthropic",
                "rotation_id": "r-123",
            })
            assert isinstance(_session.llm_api_key, bytearray)
            assert _session.get_llm_api_key() == "sk-rotated-key"

        asyncio.run(run())
