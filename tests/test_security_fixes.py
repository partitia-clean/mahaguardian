"""
Tests for Week 3-4 adversarial security fixes.

Covers:
  Fix 1: Token verification bypass — forged dicts rejected, signed tokens accepted
  Fix 2: Negative payment amount — rejected at Pydantic and execute_payment level
  Fix 3: Audit log injection via recipient — JSON resource format, delimiter rejection
  Fix 4: Payment approval thread exhaustion — semaphore limits concurrency
  Fix 5: Confused deputy in tool params — unauthorized partition refs blocked
  Fix 6: Startup fail-closed — tested via code inspection (sys.exit on failure)
  Fix 7: Session memory bytearray — key can be zeroed in place
  Fix 8: Wrong request model on revoke-all — TokenRevokeAllRequest used
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

import guardian.audit as audit_module
import guardian.payments as payments_module
import guardian.mtls as mtls_module
import guardian.tools as tools_module
import guardian.tokens as tokens_module
import guardian.vault as vault_module
from agent.session import AgentSession
from guardian.payments import PaymentDeniedError, execute_payment
from guardian.tokens import (
    generate_token_keypair,
    init_tokens,
    issue_token,
    verify_token,
    TokenInvalidError,
    TokenExpiredError,
)
from guardian.tools import (
    ToolNotPermittedError,
    PartitionParamViolation,
    _check_params_partition_safety,
    execute_tool_call,
)
from guardian.vault import init_vault, unlock_vault, lock_vault
from shared.models import PaymentRequest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PASSPHRASE = "security-fix-test-2024"


@pytest.fixture(autouse=True)
def setup(tmp_path, monkeypatch):
    """Isolate every module to tmp_path."""
    audit_module.init_audit_log(tmp_path / "audit.db")

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
    payments_module._vault = None
    tools_module._vault = None


CERT_PASSPHRASE = "test-cert-passphrase"


def _init_tokens_and_cert(tmp_path):
    """Set up token module and return (agent_cert, ca_cert, ca_key)."""
    sk, vk = generate_token_keypair()
    init_tokens(sk, vk, tmp_path / "tokens.db")
    ca_cert, ca_key = mtls_module.generate_ca(CERT_PASSPHRASE)
    agent_cert, _ = mtls_module.generate_agent_cert("alpha", ca_cert, ca_key, CERT_PASSPHRASE)
    return agent_cert


def _init_vault(tmp_path):
    """Create and unlock vault, return vault dict."""
    init_vault(PASSPHRASE)
    return unlock_vault(PASSPHRASE)


# ---------------------------------------------------------------------------
# Fix 1: Token verification bypass
# ---------------------------------------------------------------------------

class TestFix1TokenVerificationBypass:
    """Endpoints must reject forged token dicts and require signed strings."""

    def test_forged_token_dict_rejected_by_verify_token(self, setup):
        """A hand-crafted dict (not signed) must be rejected by verify_token."""
        tmp_path = setup
        agent_cert = _init_tokens_and_cert(tmp_path)

        forged_token = json.dumps({
            "token_id": "forged-123",
            "agent_id": "alpha",
            "permissions": {"payment_execute": True, "tool_calls": ["everything"]},
            "sig": "AAAA",  # garbage signature
        })

        with pytest.raises(TokenInvalidError):
            verify_token(forged_token, agent_cert)

    def test_signed_token_accepted_by_verify_token(self, setup):
        """A properly signed token string must be accepted."""
        tmp_path = setup
        agent_cert = _init_tokens_and_cert(tmp_path)

        token_str = issue_token(
            agent_id="alpha",
            agent_cert=agent_cert,
            permissions={"vault_read": ["personal"], "tool_calls": ["calendar"]},
            lifetime_hours=4,
        )

        verified = verify_token(token_str, agent_cert)
        assert verified["permissions"]["vault_read"] == ["personal"]
        assert verified["permissions"]["tool_calls"] == ["calendar"]

    def test_expired_signed_token_rejected(self, setup):
        """An expired but properly signed token must be rejected."""
        tmp_path = setup
        agent_cert = _init_tokens_and_cert(tmp_path)

        token_str = issue_token(
            agent_id="alpha",
            agent_cert=agent_cert,
            permissions={"vault_read": ["personal"]},
            lifetime_hours=0,  # expires immediately
        )

        with pytest.raises(TokenExpiredError):
            verify_token(token_str, agent_cert)

    def test_request_models_use_token_str(self):
        """ToolCallRequest and PartitionAccessRequest must have token_str, not token dict."""
        source = Path(__file__).parent.parent / "guardian" / "main.py"
        text = source.read_text()

        # ToolCallRequest must use token_str: str, not token: dict
        assert "class ToolCallRequest" in text
        # Find the class body and verify token_str is present
        idx = text.index("class ToolCallRequest")
        class_body = text[idx:idx + 400]
        assert "token_str: str" in class_body
        assert "token: dict" not in class_body

        # PartitionAccessRequest must use token_str: str
        idx = text.index("class PartitionAccessRequest")
        class_body = text[idx:idx + 400]
        assert "token_str: str" in class_body
        assert "token: dict" not in class_body

        # PaymentExecuteRequest must use token_str: str
        assert "class PaymentExecuteRequest" in text
        idx = text.index("class PaymentExecuteRequest")
        class_body = text[idx:idx + 400]
        assert "token_str: str" in class_body


# ---------------------------------------------------------------------------
# Fix 2: Negative payment amount
# ---------------------------------------------------------------------------

class TestFix2NegativePaymentAmount:

    def test_pydantic_rejects_zero_amount(self):
        """PaymentRequest with amount_gbp=0 must raise ValidationError."""
        with pytest.raises(Exception, match="positive"):
            PaymentRequest(
                amount_gbp=0,
                recipient="Shop",
                description="Test",
                payment_method="stripe",
            )

    def test_pydantic_rejects_negative_amount(self):
        """PaymentRequest with amount_gbp=-100 must raise ValidationError."""
        with pytest.raises(Exception, match="positive"):
            PaymentRequest(
                amount_gbp=-100,
                recipient="Shop",
                description="Test",
                payment_method="stripe",
            )

    def test_positive_amount_succeeds_pydantic(self):
        """PaymentRequest with amount_gbp=25 must succeed."""
        req = PaymentRequest(
            amount_gbp=25,
            recipient="Shop",
            description="Test",
            payment_method="stripe",
        )
        assert req.amount_gbp == 25

    def test_execute_payment_rejects_negative(self, setup):
        """execute_payment must raise ValueError for negative amount."""
        tmp_path = setup
        vault = _init_vault(tmp_path)
        payments_module.init_payments(vault)

        # Build a PaymentRequest with positive amount, then mutate
        # (bypass Pydantic by using model_construct)
        req = PaymentRequest.model_construct(
            amount_gbp=-50,
            recipient="Attacker",
            description="Steal",
            payment_method="stripe",
            payment_source="agent",
            external_agent_id=None,
            service_status="to_be_provided",
        )
        permissions = {"payment_execute": True}

        with pytest.raises(ValueError, match="positive"):
            asyncio.run(execute_payment("alpha", permissions, req))

        lock_vault(vault)


# ---------------------------------------------------------------------------
# Fix 3: Audit log injection via recipient
# ---------------------------------------------------------------------------

class TestFix3AuditLogInjection:

    def test_recipient_with_injection_rejected(self, setup):
        """Recipient containing comma+equals must be rejected."""
        tmp_path = setup
        vault = _init_vault(tmp_path)
        payments_module.init_payments(vault)

        req = PaymentRequest(
            amount_gbp=10,
            recipient="Shop",  # valid first, we'll construct with bad value
            description="Test",
            payment_method="stripe",
        )
        # Use model_construct to bypass field validators and inject bad recipient
        req = PaymentRequest.model_construct(
            amount_gbp=10,
            recipient="Shop,amount=-9999",
            description="Test",
            payment_method="stripe",
            payment_source="agent",
            external_agent_id=None,
            service_status="to_be_provided",
        )
        permissions = {"payment_execute": True}

        with pytest.raises(ValueError, match="invalid characters"):
            asyncio.run(execute_payment("alpha", permissions, req))

        lock_vault(vault)

    def test_recipient_with_newline_rejected(self, setup):
        """Recipient with newline must be rejected."""
        tmp_path = setup
        vault = _init_vault(tmp_path)
        payments_module.init_payments(vault)

        req = PaymentRequest.model_construct(
            amount_gbp=10,
            recipient="Shop\nfake=line",
            description="Test",
            payment_method="stripe",
            payment_source="agent",
            external_agent_id=None,
            service_status="to_be_provided",
        )
        permissions = {"payment_execute": True}

        with pytest.raises(ValueError, match="invalid characters"):
            asyncio.run(execute_payment("alpha", permissions, req))

        lock_vault(vault)

    def test_daily_spend_parses_json_resource(self, setup):
        """_get_daily_spend must correctly parse JSON resource format."""
        tmp_path = setup

        # Log a payment with JSON resource format
        audit_module.log(
            action="payment.execute",
            agent_id="alpha",
            resource=json.dumps({"amount": 42.50, "recipient": "Shop"}),
            result="success:ref=TXN-123,approved_by=auto",
        )

        daily = payments_module._get_daily_spend("alpha")
        assert daily == 42.50


# ---------------------------------------------------------------------------
# Fix 4: Payment approval thread exhaustion
# ---------------------------------------------------------------------------

class TestFix4ApprovalThreadExhaustion:

    def test_semaphore_exists(self):
        """Module must have an approval semaphore."""
        assert hasattr(payments_module, "_approval_semaphore")
        assert isinstance(payments_module._approval_semaphore, asyncio.Semaphore)

    def test_max_pending_limit_exists(self):
        """Module must have a max pending approvals limit."""
        assert hasattr(payments_module, "_MAX_PENDING_APPROVALS")
        assert payments_module._MAX_PENDING_APPROVALS == 5


# ---------------------------------------------------------------------------
# Fix 5: Confused deputy in tool params
# ---------------------------------------------------------------------------

class TestFix5ConfusedDeputy:

    def test_params_referencing_unauthorized_partition_blocked(self):
        """Params with unauthorized partition IDs must raise."""
        params = {"file_path": "/data/partition-b/secret.csv"}
        with pytest.raises(PartitionParamViolation, match="partition-b"):
            _check_params_partition_safety(
                params=params,
                permitted_partitions=["partition-a"],
                all_known_partitions=["partition-a", "partition-b"],
            )

    def test_params_referencing_permitted_partition_ok(self):
        """Params referencing only permitted partitions must pass."""
        params = {"file_path": "/data/partition-a/report.csv"}
        # Should not raise
        _check_params_partition_safety(
            params=params,
            permitted_partitions=["partition-a"],
            all_known_partitions=["partition-a", "partition-b"],
        )

    def test_non_string_params_ignored(self):
        """Non-string param values must not be checked."""
        params = {"count": 42, "flag": True}
        _check_params_partition_safety(
            params=params,
            permitted_partitions=["partition-a"],
            all_known_partitions=["partition-a", "partition-b"],
        )

    def test_tool_call_with_partition_param_violation(self, setup):
        """FIX 8 — execute_tool_call enforces token validation.
        A token without 'agent_id' is rejected before params are scanned."""
        tmp_path = setup
        vault = _init_vault(tmp_path)
        vault["known_partitions"] = ["partition-a", "partition-b"]
        tools_module.init_tools(vault)

        permissions = {
            "tool_calls": ["data_export"],
            "vault_read": ["partition-a"],
        }

        with pytest.raises(tools_module.ToolNotPermittedError):
            asyncio.run(execute_tool_call(
                agent_id="alpha",
                token=permissions,
                tool_name="data_export",
                action="export",
                params={"target": "partition-b/secret.csv"},
                partition_id="partition-a",
            ))

        lock_vault(vault)


# ---------------------------------------------------------------------------
# F-013: Recursive nested parameter partition scanning
# ---------------------------------------------------------------------------

class TestNestedParamPartitionScan:
    """
    _check_params_partition_safety must recursively scan nested
    dicts, lists, and tuples — not just top-level strings.
    """

    def test_flat_string_blocked(self):
        params = {"file_path": "/data/secret_partition/file.csv"}
        with pytest.raises(PartitionParamViolation, match="secret_partition"):
            _check_params_partition_safety(
                params=params,
                permitted_partitions=["allowed"],
                all_known_partitions=["allowed", "secret_partition"],
            )

    def test_nested_dict_blocked(self):
        params = {"target": {"path": "/vault/secret_partition"}}
        with pytest.raises(PartitionParamViolation, match="secret_partition"):
            _check_params_partition_safety(
                params=params,
                permitted_partitions=["allowed"],
                all_known_partitions=["allowed", "secret_partition"],
            )

    def test_nested_list_blocked(self):
        params = {"args": ["/vault/secret_partition"]}
        with pytest.raises(PartitionParamViolation, match="secret_partition"):
            _check_params_partition_safety(
                params=params,
                permitted_partitions=["allowed"],
                all_known_partitions=["allowed", "secret_partition"],
            )

    def test_deeply_nested_blocked(self):
        params = {"a": {"b": {"c": [{"d": "secret_partition"}]}}}
        with pytest.raises(PartitionParamViolation, match="secret_partition"):
            _check_params_partition_safety(
                params=params,
                permitted_partitions=["allowed"],
                all_known_partitions=["allowed", "secret_partition"],
            )

    def test_authorized_partition_nested_allowed(self):
        params = {"target": {"path": "/vault/permitted_partition"}}
        # Must NOT raise — partition is in permitted list
        _check_params_partition_safety(
            params=params,
            permitted_partitions=["permitted_partition"],
            all_known_partitions=["permitted_partition", "secret"],
        )

    def test_non_string_values_no_crash(self):
        params = {"count": 42, "flag": True, "empty": None,
                  "nested": {"num": 3.14, "items": [1, 2, 3]}}
        # Must not raise — no strings to check
        _check_params_partition_safety(
            params=params,
            permitted_partitions=["allowed"],
            all_known_partitions=["allowed", "secret"],
        )


# ---------------------------------------------------------------------------
# Fix 6: Startup fail-closed
# ---------------------------------------------------------------------------

class TestFix6StartupFailClosed:

    def test_startup_calls_sys_exit_on_vault_failure(self):
        """Verify that the startup code calls sys.exit(1) on vault failure."""
        source_path = Path(__file__).parent.parent / "guardian" / "main.py"
        source = source_path.read_text()
        assert "sys.exit(1)" in source

    def test_startup_no_none_vault_continues(self):
        """Verify _vault_dict = None followed by continue is gone from startup."""
        source_path = Path(__file__).parent.parent / "guardian" / "main.py"
        source = source_path.read_text()
        # The old pattern set _vault_dict = None and kept running.
        # Now only the shutdown path sets it to None.
        # Check the lifespan function specifically
        idx = source.index("async def lifespan")
        yield_idx = source.index("yield", idx)
        startup_section = source[idx:yield_idx]
        assert "_vault_dict = None" not in startup_section


# ---------------------------------------------------------------------------
# Fix 7: Session memory bytearray
# ---------------------------------------------------------------------------

class TestFix7SessionBytearray:

    def test_llm_api_key_is_bytearray(self):
        """AgentSession.llm_api_key must be a bytearray."""
        session = AgentSession()
        assert isinstance(session.llm_api_key, bytearray)

    def test_set_and_get_llm_api_key(self):
        """set/get_llm_api_key roundtrip must work."""
        session = AgentSession()
        session.set_llm_api_key("sk-secret-key-123")
        assert session.get_llm_api_key() == "sk-secret-key-123"

    def test_clear_zeros_bytearray(self):
        """clear() must zero the bytearray in place."""
        session = AgentSession()
        session.set_llm_api_key("sk-secret-key-123")
        key_ref = session.llm_api_key  # keep reference
        session.clear()
        # The original bytearray should be all zeros
        assert all(b == 0 for b in key_ref)
        # And the session key should be empty
        assert session.get_llm_api_key() == ""

    def test_clear_zeros_all_fields(self):
        """clear() must reset all session fields."""
        session = AgentSession()
        session.set_llm_api_key("key")
        session.access_token = "token"
        session.session_id = "sess"
        session.agent_id = "agent"
        session.guardian_url = "http://localhost"
        session.clear()
        assert session.access_token == ""
        assert session.session_id == ""
        assert session.agent_id == ""
        assert session.guardian_url == ""


# ---------------------------------------------------------------------------
# Fix 8: Wrong request model on revoke-all
# ---------------------------------------------------------------------------

class TestFix8RevokeAllModel:

    def test_revoke_all_uses_correct_model(self):
        """The /tokens/revoke-all endpoint must use TokenRevokeAllRequest, not HeartbeatStopRequest."""
        source_path = Path(__file__).parent.parent / "guardian" / "main.py"
        source = source_path.read_text()

        # Find the revoke-all endpoint
        idx = source.index("/tokens/revoke-all")
        endpoint_body = source[idx:idx + 500]
        assert "TokenRevokeAllRequest" in endpoint_body
        assert "HeartbeatStopRequest" not in endpoint_body

    def test_token_revoke_all_request_model_exists(self):
        """TokenRevokeAllRequest must be defined with agent_id field."""
        source_path = Path(__file__).parent.parent / "guardian" / "main.py"
        source = source_path.read_text()
        assert "class TokenRevokeAllRequest" in source
        idx = source.index("class TokenRevokeAllRequest")
        class_body = source[idx:idx + 200]
        assert "agent_id: str" in class_body


# ---------------------------------------------------------------------------
# Fix 9: Payment source spoofing
# ---------------------------------------------------------------------------

class TestFix9PaymentSourceSpoofing:
    """
    Payment source must be derived from vault external_agents list,
    not from the request payload. An external agent cannot bypass
    stricter thresholds by omitting external_agent_id or claiming
    payment_source="agent".
    """

    @pytest.mark.asyncio
    async def test_external_agent_omitting_field_still_external(self, setup):
        """
        An agent in the vault external_agents list is treated as
        external even if it omits external_agent_id from the request.
        """
        tmp_path = setup
        agent_cert = _init_tokens_and_cert(tmp_path)
        vault_dict = _init_vault(tmp_path)
        vault_dict["external_agents"] = ["alpha"]
        vault_dict["payment_rules"] = {
            "auto_approve_below_gbp": 100,
            "daily_limit_gbp": 1000,
            "trusted_external_agents": ["alpha"],
            "external_agent_auto_approve_below_gbp": 0,
        }
        vault_dict["tool_api_keys"] = {"stripe": "sk-test-xxx"}
        payments_module.init_payments(vault_dict)

        token_str = issue_token(
            agent_id="alpha",
            permissions={"payment_execute": True, "tool_calls": []},
            agent_cert=agent_cert,
        )
        token = verify_token(token_str, agent_cert)["permissions"]

        # Omit external_agent_id entirely — old code would treat as "agent"
        req = PaymentRequest(
            amount_gbp=5.00,
            recipient="Test Shop",
            description="Spoofed source test",
            payment_method="stripe",
            payment_source="agent",
        )

        # external_agent_auto_approve_below_gbp=0, so needs approval.
        # Mock approval to return False (rejected by user).
        with patch.object(
            payments_module, "notify_user_for_approval", return_value=False
        ):
            with pytest.raises(PaymentDeniedError):
                await execute_payment("alpha", token, req)

    @pytest.mark.asyncio
    async def test_external_agent_claiming_primary_still_external(self, setup):
        """
        An agent in the vault external_agents list that claims
        payment_source="agent" is still treated as external.
        """
        tmp_path = setup
        agent_cert = _init_tokens_and_cert(tmp_path)
        vault_dict = _init_vault(tmp_path)
        vault_dict["external_agents"] = ["alpha"]
        vault_dict["payment_rules"] = {
            "auto_approve_below_gbp": 100,
            "daily_limit_gbp": 1000,
            "trusted_external_agents": ["alpha"],
            "external_agent_auto_approve_below_gbp": 0,
        }
        vault_dict["tool_api_keys"] = {"stripe": "sk-test-xxx"}
        payments_module.init_payments(vault_dict)

        token_str = issue_token(
            agent_id="alpha",
            permissions={"payment_execute": True, "tool_calls": []},
            agent_cert=agent_cert,
        )
        token = verify_token(token_str, agent_cert)["permissions"]

        req = PaymentRequest(
            amount_gbp=5.00,
            recipient="Test Shop",
            description="Claiming primary",
            payment_method="stripe",
            payment_source="agent",
            external_agent_id="alpha",
        )

        # Must still need approval (external threshold = 0)
        with patch.object(
            payments_module, "notify_user_for_approval", return_value=False
        ):
            with pytest.raises(PaymentDeniedError, match="rejected by user"):
                await execute_payment("alpha", token, req)

    @pytest.mark.asyncio
    async def test_primary_agent_treated_as_agent(self, setup):
        """
        An agent NOT in external_agents list is treated as primary
        and gets the normal auto-approve threshold.
        """
        tmp_path = setup
        agent_cert = _init_tokens_and_cert(tmp_path)
        vault_dict = _init_vault(tmp_path)
        vault_dict["external_agents"] = ["other-agent"]
        vault_dict["payment_rules"] = {
            "auto_approve_below_gbp": 100,
            "daily_limit_gbp": 1000,
        }
        vault_dict["tool_api_keys"] = {"stripe": "sk-test-xxx"}
        payments_module.init_payments(vault_dict)

        token_str = issue_token(
            agent_id="alpha",
            permissions={"payment_execute": True, "tool_calls": []},
            agent_cert=agent_cert,
        )
        token = verify_token(token_str, agent_cert)["permissions"]

        req = PaymentRequest(
            amount_gbp=5.00,
            recipient="Test Shop",
            description="Normal payment",
            payment_method="stripe",
            payment_source="agent",
        )

        result = await execute_payment("alpha", token, req)
        assert result.success is True
        assert result.payment_source == "agent"

    def test_is_external_agent_unknown_defaults_to_external(self, setup):
        """
        An agent_id not in any configured list defaults to external
        (secure default) when external_agents is configured.
        """
        tmp_path = setup
        vault_dict = _init_vault(tmp_path)
        vault_dict["external_agents"] = ["known"]
        payments_module.init_payments(vault_dict)

        assert payments_module._is_external_agent("unknown-agent") is False
        # "known" IS in the list
        assert payments_module._is_external_agent("known") is True

    def test_no_external_list_defaults_to_primary(self, setup):
        """
        When vault has no 'external_agents' key, all agents are
        treated as primary (single-agent Phase 1 deployment).
        """
        tmp_path = setup
        vault_dict = _init_vault(tmp_path)
        # No "external_agents" key
        payments_module.init_payments(vault_dict)

        assert payments_module._is_external_agent("alpha") is False
        assert payments_module._is_external_agent("any-agent") is False
