"""
Phase 3 enforcer tests — Step 4.

Covers:
  - find_items: not found, unique match, ambiguous key
  - scan_params: clean params, direct partition name, URL-encoded, NFC variant,
                 nested dict, nested list, depth limit
  - resolve_and_enforce:
      * ALLOW path
      * not-found → EnforcementDenied("access_denied") same as denied
      * partition mismatch → EnforcementDenied
      * ambiguous key → AmbiguousKeyError
      * confused-deputy → ConfusedDeputyError
      * TLP DENY → EnforcementDenied
      * TLP ELEVATE → EnforcementDenied (sync path raises, not ElevateTimeoutError)
      * anti-probing: not-found and access-denied return identical safe_message
"""
from __future__ import annotations

import asyncio
import time
import urllib.parse
import unicodedata
import pytest

import guardian.audit as audit_module
from shared.types import Classification, TlpLevel, Decision
from shared.data_item import DataItem, DEMO_ITEMS
from guardian.enforcer import (
    _MIN_RESPONSE_TIME,
    _find_items_no_tlp_check,
    scan_params,
    resolve_and_enforce,
    enforce,
    EnforcementDenied,
    AmbiguousKeyError,
    ConfusedDeputyError,
)


@pytest.fixture(autouse=True)
def setup_audit(tmp_path):
    audit_module.init_audit_log(tmp_path / "audit.db")
    yield


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _item(item_id, partition, classification=Classification.PUBLIC, value="v"):
    return DataItem(
        item_id=item_id,
        owner_partition=partition,
        classification=classification,
        value=value,
    )


def _vault(*items: DataItem) -> dict[str, DataItem]:
    """Index items by item_id (last writer wins — fine for tests)."""
    return {item.item_id: item for item in items}


def _vault_multi(*items: DataItem) -> dict[str, DataItem]:
    """Index by (item_id, partition) composite — supports duplicate item_ids."""
    return {f"{item.item_id}/{item.owner_partition}": item for item in items}


# ---------------------------------------------------------------------------
# find_items
# ---------------------------------------------------------------------------

class TestFindItems:
    def test_not_found_returns_empty(self):
        vault = _vault(_item("foo", "p1"))
        assert _find_items_no_tlp_check("missing", ["p1"], vault) == []

    def test_not_in_token_partitions_returns_empty(self):
        vault = _vault(_item("foo", "p2"))
        assert _find_items_no_tlp_check("foo", ["p1"], vault) == []

    def test_unique_match(self):
        item = _item("foo", "p1")
        vault = _vault(item)
        result = _find_items_no_tlp_check("foo", ["p1"], vault)
        assert result == [item]

    def test_ambiguous_key_two_partitions(self):
        i1 = _item("shared_key", "p1")
        i2 = _item("shared_key", "p2")
        vault = _vault_multi(i1, i2)
        result = _find_items_no_tlp_check("shared_key", ["p1", "p2"], vault)
        assert len(result) == 2

    def test_ambiguous_only_counts_authorized_partitions(self):
        # p3 item exists but agent has no access to p3
        i1 = _item("k", "p1")
        i2 = _item("k", "p3")
        vault = _vault_multi(i1, i2)
        result = _find_items_no_tlp_check("k", ["p1"], vault)
        assert result == [i1]

    def test_returns_correct_item(self):
        i1 = _item("x", "p1", value="secret")
        vault = _vault(i1)
        result = _find_items_no_tlp_check("x", ["p1"], vault)
        assert result[0].value == "secret"


# ---------------------------------------------------------------------------
# scan_params
# ---------------------------------------------------------------------------

class TestScanParams:
    def test_clean_string_passes(self):
        scan_params("hello world", ["company-a"])  # no raise

    def test_direct_partition_name_raises(self):
        with pytest.raises(ConfusedDeputyError):
            scan_params("company-a", ["company-a"])

    def test_url_encoded_raises(self):
        encoded = urllib.parse.quote("company-a")
        with pytest.raises(ConfusedDeputyError):
            scan_params(encoded, ["company-a"])

    def test_nfc_normalised_raises(self):
        # NFC of ASCII is identical, so use a composed/decomposed pair
        decomposed = unicodedata.normalize("NFD", "caf\u00e9")
        composed = unicodedata.normalize("NFC", "caf\u00e9")
        with pytest.raises(ConfusedDeputyError):
            scan_params(decomposed, [composed])

    def test_nested_dict_value_raises(self):
        params = {"safe_key": {"nested": "company-b"}}
        with pytest.raises(ConfusedDeputyError):
            scan_params(params, ["company-b"])

    def test_dict_key_raises(self):
        # FIX SM-006: keys are now scanned too, not just values
        params = {"company-a": "harmless_value"}
        with pytest.raises(ConfusedDeputyError):
            scan_params(params, ["company-a"])

    def test_nested_list_raises(self):
        params = ["ok", ["also_ok", "company-a"]]
        with pytest.raises(ConfusedDeputyError):
            scan_params(params, ["company-a"])

    def test_depth_limit_rejects_on_exceeded(self):
        # FIX F5: depth > max_depth now REJECTS (ConfusedDeputyError), not silently passes
        # Build a dict nested 15 levels deep — exceeds max_depth=10
        inner: object = "harmless_value"  # no partition name at bottom
        for _ in range(15):
            inner = {"k": inner}
        # Must raise because nesting exceeds max_depth (even without a partition name)
        with pytest.raises(ConfusedDeputyError):
            scan_params(inner, ["company-a"], max_depth=10)

    def test_depth_limit_at_exactly_max_depth(self):
        # At depth == max_depth we still process; beyond max_depth we reject
        inner: object = "company-a"
        for _ in range(10):
            inner = {"k": inner}
        # depth 10 is still processed, so the partition name IS found → raises
        with pytest.raises(ConfusedDeputyError):
            scan_params(inner, ["company-a"], max_depth=10)

    def test_multiple_partitions_any_triggers(self):
        with pytest.raises(ConfusedDeputyError):
            scan_params("company-b", ["company-a", "company-b"])

    def test_non_string_scalar_ignored(self):
        scan_params(42, ["company-a"])
        scan_params(3.14, ["company-a"])
        scan_params(None, ["company-a"])
        scan_params(True, ["company-a"])

    # --- F5: depth rejection and encoding bypass tests ---

    def test_depth_exceeded_without_partition_still_rejects(self):
        """F5: depth > max_depth raises ConfusedDeputyError even if no partition name found."""
        inner: object = "harmless_content"
        for _ in range(25):  # well beyond default max_depth=20
            inner = {"k": inner}
        with pytest.raises(ConfusedDeputyError):
            scan_params(inner, ["company-a"])

    def test_nesting_within_max_depth_scanned_correctly(self):
        """F5: structures nested up to max_depth must be fully scanned."""
        # 5 levels deep — well within default max_depth=20 — with a partition name at bottom
        inner: object = "company-a"
        for _ in range(5):
            inner = {"k": inner}
        with pytest.raises(ConfusedDeputyError):
            scan_params(inner, ["company-a"])

    def test_double_url_encoded_partition_detected(self):
        """F5: double URL-encoded partition name (%2563 → %63 → 'c') must be caught."""
        # "company-a" single URL-encoded: "company%2Da"
        # double URL-encoded: "company%252Da"
        with pytest.raises(ConfusedDeputyError):
            scan_params("company%252Da", ["company-a"])

    def test_null_bytes_in_string_do_not_bypass_scanner(self):
        """F5: null bytes embedded in a partition name string must not bypass detection."""
        # "comp\x00any-a" — if the null byte is stripped before comparison, still matches
        with pytest.raises(ConfusedDeputyError):
            scan_params("comp\x00any-a", ["company-a"])


# ---------------------------------------------------------------------------
# resolve_and_enforce
# ---------------------------------------------------------------------------

def _red_vault():
    """Vault with a RESTRICTED company-a item."""
    return _vault(_item("secret", "company-a", Classification.RESTRICTED, "top_secret"))


def _public_vault():
    return _vault(_item("pub", "company-a", Classification.PUBLIC, "open"))


class TestResolveAndEnforce:
    def test_allow_red_restricted(self):
        vault = _red_vault()
        item = resolve_and_enforce(
            key="secret",
            token_partitions=["company-a"],
            tlp_level=TlpLevel.RED,
            params={},
            vault_items=vault,
            agent_id="agent-x",
            known_partitions=["company-a"],
        )
        assert item.item_id == "secret"
        assert item.value == "top_secret"

    def test_allow_clear_public(self):
        vault = _public_vault()
        item = resolve_and_enforce(
            key="pub",
            token_partitions=["company-a"],
            tlp_level=TlpLevel.CLEAR,
            params={},
            vault_items=vault,
            agent_id="agent-x",
            known_partitions=["company-a"],
        )
        assert item.item_id == "pub"

    def test_not_found_raises_enforcement_denied(self):
        vault = _red_vault()
        with pytest.raises(EnforcementDenied) as exc_info:
            resolve_and_enforce(
                key="nonexistent",
                token_partitions=["company-a"],
                tlp_level=TlpLevel.RED,
                params={},
                vault_items=vault,
                agent_id="agent-x",
                known_partitions=["company-a"],
            )
        assert exc_info.value.safe_message == "access_denied"

    def test_partition_mismatch_raises_enforcement_denied(self):
        vault = _red_vault()
        with pytest.raises(EnforcementDenied) as exc_info:
            resolve_and_enforce(
                key="secret",
                token_partitions=["company-b"],  # wrong partition
                tlp_level=TlpLevel.RED,
                params={},
                vault_items=vault,
                agent_id="agent-y",
                known_partitions=["company-a", "company-b"],
            )
        assert exc_info.value.safe_message == "access_denied"

    def test_anti_probing_not_found_same_message_as_denied(self):
        """not-found and access-denied must return identical safe_message."""
        vault = _red_vault()

        # not found (key doesn't exist)
        with pytest.raises(EnforcementDenied) as e1:
            resolve_and_enforce("ghost", ["company-a"], TlpLevel.RED,
                                {}, vault, "agent-x",
                                known_partitions=["company-a"])

        # access denied (wrong partition)
        with pytest.raises(EnforcementDenied) as e2:
            resolve_and_enforce("secret", ["company-b"], TlpLevel.RED,
                                {}, vault, "agent-x",
                                known_partitions=["company-a", "company-b"])

        assert e1.value.safe_message == e2.value.safe_message == "access_denied"

    def test_ambiguous_key_raises_ambiguous_key_error(self):
        i1 = _item("dup", "p1", Classification.PUBLIC)
        i2 = _item("dup", "p2", Classification.PUBLIC)
        vault = _vault_multi(i1, i2)
        with pytest.raises(AmbiguousKeyError):
            resolve_and_enforce("dup", ["p1", "p2"], TlpLevel.RED,
                                {}, vault, "agent-x",
                                known_partitions=["p1", "p2"])

    def test_confused_deputy_raises_before_vault_access(self):
        vault = _red_vault()
        with pytest.raises(ConfusedDeputyError):
            resolve_and_enforce(
                key="secret",
                token_partitions=["company-a"],
                tlp_level=TlpLevel.RED,
                params={"hint": "company-a"},  # partition name in params
                vault_items=vault,
                agent_id="agent-x",
                known_partitions=["company-a"],
            )

    def test_tlp_deny_green_restricted(self):
        vault = _red_vault()  # RESTRICTED item
        with pytest.raises(EnforcementDenied) as exc_info:
            resolve_and_enforce(
                key="secret",
                token_partitions=["company-a"],
                tlp_level=TlpLevel.GREEN,   # GREEN + RESTRICTED = DENY
                params={},
                vault_items=vault,
                agent_id="agent-x",
                known_partitions=["company-a"],
            )
        assert exc_info.value.safe_message == "access_denied"

    def test_tlp_elevate_amber_strict_restricted(self):
        vault = _red_vault()  # RESTRICTED item
        # AMBER_STRICT + RESTRICTED = ELEVATE → sync path raises EnforcementDenied
        with pytest.raises(EnforcementDenied):
            resolve_and_enforce(
                key="secret",
                token_partitions=["company-a"],
                tlp_level=TlpLevel.AMBER_STRICT,
                params={},
                vault_items=vault,
                agent_id="agent-x",
                known_partitions=["company-a"],
            )

    def test_tlp_deny_amber_restricted(self):
        vault = _red_vault()
        with pytest.raises(EnforcementDenied):
            resolve_and_enforce(
                key="secret",
                token_partitions=["company-a"],
                tlp_level=TlpLevel.AMBER,   # AMBER + RESTRICTED = DENY
                params={},
                vault_items=vault,
                agent_id="agent-x",
                known_partitions=["company-a"],
            )

    def test_enforcement_denied_safe_message_never_leaks_details(self):
        """The safe_message must always be 'access_denied', never the reason_code."""
        vault = _red_vault()
        with pytest.raises(EnforcementDenied) as exc_info:
            resolve_and_enforce(
                key="secret",
                token_partitions=["company-a"],
                tlp_level=TlpLevel.GREEN,
                params={},
                vault_items=vault,
                agent_id="agent-x",
                known_partitions=["company-a"],
            )
        e = exc_info.value
        assert e.safe_message == "access_denied"
        assert e.reason_code != "access_denied"   # internal is different

    def test_clear_public_with_url_encoded_param_raises_confused_deputy(self):
        vault = _public_vault()
        encoded = urllib.parse.quote("company-a")
        with pytest.raises(ConfusedDeputyError):
            resolve_and_enforce("pub", ["company-a"], TlpLevel.CLEAR,
                                {"q": encoded}, vault, "agent-x",
                                known_partitions=["company-a"])


# ---------------------------------------------------------------------------
# FIX 1: substring containment tests for scan_params
# ---------------------------------------------------------------------------

class TestScanParamsSubstringFix:
    """FIX 1 — partition name embedded in a longer string must be detected."""

    def test_embedded_partition_raises(self):
        """'access company_b_commercial now' must trigger ConfusedDeputyError."""
        with pytest.raises(ConfusedDeputyError):
            scan_params(
                {"query": "access company_b_commercial now"},
                ["company_b_commercial"],
            )

    def test_exact_partition_still_raises(self):
        """Exact match must still be caught."""
        with pytest.raises(ConfusedDeputyError):
            scan_params({"query": "company_b_commercial"}, ["company_b_commercial"])

    def test_clean_string_passes(self):
        """A string with no partition name must pass."""
        scan_params({"query": "no partition here"}, ["company_b_commercial"])

    def test_uppercase_partition_raises(self):
        """Case-insensitive — 'COMPANY_B_COMMERCIAL' must be detected."""
        with pytest.raises(ConfusedDeputyError):
            scan_params({"query": "COMPANY_B_COMMERCIAL"}, ["company_b_commercial"])

    def test_nested_deep_partition_raises(self):
        """Partition name embedded in nested dict must be detected."""
        with pytest.raises(ConfusedDeputyError):
            scan_params(
                {"nested": {"deep": "company_b_legal"}},
                ["company_b_legal"],
            )


# ---------------------------------------------------------------------------
# FIX 6: ELEVATE timeout enforcement
# ---------------------------------------------------------------------------

class TestElevateTimeout:
    """FIX 6 — elevate_callback hanging forever must be caught."""

    @pytest.mark.asyncio
    async def test_hanging_callback_raises_elevate_timeout(self, tmp_path):
        import asyncio
        import uuid
        from guardian.enforcer import (
            ElevateTimeoutError,
            VaultRequest,
            enforce,
        )
        from shared.token import RevocationStore, RequestDeduplicator
        import nacl.signing

        # Generate a signing keypair
        sk = nacl.signing.SigningKey.generate()
        vk_bytes = bytes(sk.verify_key)

        # Mint a minimal token (bypass binding — use bytes cert)
        from shared.token import AccessToken
        import time

        # Build a simple vault with an ELEVATE item
        # AMBER_STRICT agent + RESTRICTED item = ELEVATE
        from shared.types import Classification, TlpLevel
        item = DataItem(
            item_id="secret",
            owner_partition="company-a",
            classification=Classification.RESTRICTED,
            value="restricted_value",
        )
        vault_items = {"secret": item}

        # A callback that never returns
        async def hanging_callback(_item):
            await asyncio.sleep(9999)
            return True

        # Use a very short timeout for the test (patch the constant inline)
        import guardian.enforcer as _enforcer_mod
        original = getattr(_enforcer_mod, "_ELEVATE_TIMEOUT_SECONDS", 300)

        # Create a mock token-like object
        class _MockToken:
            agent_id = "agent-x"
            partitions = ["company-a"]
            tlp_level = TlpLevel.AMBER_STRICT
            token_id = "tok-1"

        # Patch verify_token_binding to skip real crypto verification
        # and patch the timeout constant to keep the test fast.
        import unittest.mock as mock
        import guardian.enforcer as _enforcer_mod

        class _FakeDeduplicator:
            def check_and_register(self, rid): pass

        with mock.patch.object(_enforcer_mod, "_ELEVATE_TIMEOUT_SECONDS", 0.1), \
             mock.patch("shared.token.verify_token_binding") as mock_vtb:
            mock_vtb.return_value = None  # no exception = valid

            with pytest.raises(ElevateTimeoutError):
                await enforce(
                    VaultRequest(
                        key="secret",
                        params={},
                        request_id=str(uuid.uuid4()),
                        token=_MockToken(),
                        peer_der_cert=b"fake",
                    ),
                    vault_items=vault_items,
                    revocation_store=mock.MagicMock(),
                    verify_key_bytes=vk_bytes,
                    deduplicator=_FakeDeduplicator(),
                    elevate_callback=hanging_callback,
                    known_partitions=["company-a"],
                )


# ---------------------------------------------------------------------------
# FIX F3: Partition name redacted in TLP denial audit entries
# ---------------------------------------------------------------------------

class TestPartitionRedactionInTlpDenial:
    """TLP denial audit entries must not include the real partition name."""

    def _make_vault(self):
        from shared.types import Classification
        item = DataItem(
            item_id="secret",
            owner_partition="company-secret",
            classification=Classification.RESTRICTED,
            value="val",
        )
        return {"secret/company-secret": item}

    def test_tlp_denial_audit_does_not_leak_partition(self, tmp_path, capsys):
        import guardian.audit as _audit
        _audit.init_audit_log(tmp_path / "audit.db")

        vault_items = self._make_vault()
        with pytest.raises(EnforcementDenied) as exc_info:
            resolve_and_enforce(
                key="secret",
                token_partitions=["company-secret"],
                tlp_level=TlpLevel.GREEN,       # GREEN cannot see RESTRICTED
                params={},
                vault_items=vault_items,
                agent_id="agent-x",
                known_partitions=["company-secret"],
            )
        assert exc_info.value.reason_code == "tlp_insufficient"

        # Check that "company-secret" does NOT appear in any audit log entry
        import sqlite3
        conn = sqlite3.connect(str(tmp_path / "audit.db"))
        rows = conn.execute("SELECT * FROM audit_log").fetchall()
        conn.close()
        for row in rows:
            row_str = str(row)
            assert "company-secret" not in row_str, (
                f"Partition name leaked in audit entry: {row_str}"
            )


# ---------------------------------------------------------------------------
# FIX F5: scan_params handles unknown/custom object types
# ---------------------------------------------------------------------------

class TestScanParamsCustomTypes:
    """Unknown types must be converted to str and scanned."""

    def test_custom_object_with_partition_in_str_raises(self):
        class PartitionProxy:
            def __str__(self):
                return "company-a"

        with pytest.raises(ConfusedDeputyError):
            scan_params(PartitionProxy(), ["company-a"])

    def test_custom_object_without_partition_is_safe(self):
        class SafeObject:
            def __str__(self):
                return "totally_safe_value"

        # Should not raise
        scan_params(SafeObject(), ["company-a"])

    def test_custom_object_in_list_raises(self):
        class Malicious:
            def __str__(self):
                return "company-b"

        with pytest.raises(ConfusedDeputyError):
            scan_params([Malicious()], ["company-b"])

    def test_url_encoded_partition_in_custom_object_raises(self):
        class Encoded:
            def __str__(self):
                return "company%2Da"   # URL-encoded "company-a"

        with pytest.raises(ConfusedDeputyError):
            scan_params(Encoded(), ["company-a"])


# ---------------------------------------------------------------------------
# FIX F7: Timing normalisation — resolve_and_enforce pads to MIN_RESPONSE_TIME
# ---------------------------------------------------------------------------

class TestTimingNormalisation:
    """resolve_and_enforce must complete in >= MIN_RESPONSE_TIME for all paths."""

    _MIN_MS = 0.05  # 50 ms — must match guardian/enforcer.py

    def _make_vault(self):
        from shared.types import Classification
        allow_item = DataItem(
            item_id="pub", owner_partition="p",
            classification=Classification.PUBLIC, value="v",
        )
        deny_item = DataItem(
            item_id="priv", owner_partition="p",
            classification=Classification.RESTRICTED, value="v",
        )
        return {
            "pub/p": allow_item,
            "priv/p": deny_item,
        }

    def _measure(self, fn, n=10):
        import time
        times = []
        for _ in range(n):
            t0 = time.monotonic()
            try:
                fn()
            except Exception:
                pass
            times.append(time.monotonic() - t0)
        return times

    def test_allow_path_respects_min_time(self):
        vault = self._make_vault()
        def call():
            resolve_and_enforce(
                key="pub", token_partitions=["p"],
                tlp_level=TlpLevel.GREEN, params={},
                vault_items=vault, agent_id="a",
                known_partitions=["p"],
            )
        times = self._measure(call, n=5)
        for t in times:
            assert t >= self._MIN_MS * 0.9, f"ALLOW path too fast: {t:.4f}s"

    def test_denied_path_respects_min_time(self):
        vault = self._make_vault()
        def call():
            resolve_and_enforce(
                key="priv", token_partitions=["p"],
                tlp_level=TlpLevel.GREEN, params={},
                vault_items=vault, agent_id="a",
                known_partitions=["p"],
            )
        times = self._measure(call, n=5)
        for t in times:
            assert t >= self._MIN_MS * 0.9, f"DENY path too fast: {t:.4f}s"

    def test_not_found_path_respects_min_time(self):
        vault = self._make_vault()
        def call():
            resolve_and_enforce(
                key="missing", token_partitions=["p"],
                tlp_level=TlpLevel.GREEN, params={},
                vault_items=vault, agent_id="a",
                known_partitions=["p"],
            )
        times = self._measure(call, n=5)
        for t in times:
            assert t >= self._MIN_MS * 0.9, f"not-found path too fast: {t:.4f}s"

    def test_all_paths_within_reasonable_spread(self):
        """Allow, deny, and not-found paths should all complete within
        a reasonable range of each other (timing oracle mitigation)."""
        import time
        vault = self._make_vault()
        n = 20

        def measure_one(fn):
            t0 = time.monotonic()
            try:
                fn()
            except Exception:
                pass
            return time.monotonic() - t0

        allow_times = [
            measure_one(lambda: resolve_and_enforce(
                key="pub", token_partitions=["p"],
                tlp_level=TlpLevel.GREEN, params={},
                vault_items=vault, agent_id="a",
                known_partitions=["p"],
            )) for _ in range(n)
        ]
        deny_times = [
            measure_one(lambda: resolve_and_enforce(
                key="priv", token_partitions=["p"],
                tlp_level=TlpLevel.GREEN, params={},
                vault_items=vault, agent_id="a",
                known_partitions=["p"],
            )) for _ in range(n)
        ]
        missing_times = [
            measure_one(lambda: resolve_and_enforce(
                key="missing", token_partitions=["p"],
                tlp_level=TlpLevel.GREEN, params={},
                vault_items=vault, agent_id="a",
                known_partitions=["p"],
            )) for _ in range(n)
        ]

        avg_allow   = sum(allow_times) / n
        avg_deny    = sum(deny_times) / n
        avg_missing = sum(missing_times) / n

        # All averages should be within 30ms of each other
        spread = max(avg_allow, avg_deny, avg_missing) - min(avg_allow, avg_deny, avg_missing)
        assert spread < 0.03, (
            f"Timing spread too large: allow={avg_allow:.4f}, "
            f"deny={avg_deny:.4f}, missing={avg_missing:.4f}"
        )


@pytest.mark.timing
class TestAntiProbingStatistical:
    """F3: Statistical test — 'not found' and 'access denied' timing must be indistinguishable."""

    def _make_vault(self):
        from shared.types import Classification
        pub_item = DataItem(
            item_id="pub", owner_partition="p",
            classification=Classification.PUBLIC, value="v",
        )
        priv_item = DataItem(
            item_id="priv", owner_partition="p",
            classification=Classification.RESTRICTED, value="v",
        )
        return {"pub/p": pub_item, "priv/p": priv_item}

    def test_not_found_vs_denied_mean_within_10ms(self):
        """F3: |mean(not_found) - mean(denied)| must be < 10ms over 100 samples."""
        import time
        vault = self._make_vault()
        n = 100

        def call_not_found():
            try:
                resolve_and_enforce(
                    key="missing", token_partitions=["p"],
                    tlp_level=TlpLevel.GREEN, params={},
                    vault_items=vault, agent_id="a",
                    known_partitions=["p"],
                )
            except Exception:
                pass

        def call_denied():
            try:
                resolve_and_enforce(
                    key="priv", token_partitions=["p"],
                    tlp_level=TlpLevel.GREEN, params={},
                    vault_items=vault, agent_id="a",
                    known_partitions=["p"],
                )
            except Exception:
                pass

        nf_times = []
        denied_times = []
        for _ in range(n):
            t0 = time.monotonic()
            call_not_found()
            nf_times.append(time.monotonic() - t0)

            t0 = time.monotonic()
            call_denied()
            denied_times.append(time.monotonic() - t0)

        mean_nf = sum(nf_times) / n
        mean_denied = sum(denied_times) / n
        assert abs(mean_nf - mean_denied) < 0.010, (
            f"Anti-probing timing oracle: |mean_nf({mean_nf:.4f}) - "
            f"mean_denied({mean_denied:.4f})| >= 10ms"
        )

    def test_response_bodies_identical(self):
        """F3: 'not found' and 'access denied' safe_message must be byte-identical."""
        from guardian.enforcer import EnforcementDenied
        from shared.types import Classification
        vault = self._make_vault()

        not_found_msg = None
        denied_msg = None

        try:
            resolve_and_enforce(
                key="missing", token_partitions=["p"],
                tlp_level=TlpLevel.GREEN, params={},
                vault_items=vault, agent_id="a",
                known_partitions=["p"],
            )
        except EnforcementDenied as e:
            not_found_msg = e.safe_message

        try:
            resolve_and_enforce(
                key="priv", token_partitions=["p"],
                tlp_level=TlpLevel.GREEN, params={},
                vault_items=vault, agent_id="a",
                known_partitions=["p"],
            )
        except EnforcementDenied as e:
            denied_msg = e.safe_message

        assert not_found_msg is not None and denied_msg is not None
        assert not_found_msg == denied_msg, (
            f"Response bodies differ: {not_found_msg!r} != {denied_msg!r}"
        )


# ---------------------------------------------------------------------------
# FIX 3: async enforce() timing floor
# ---------------------------------------------------------------------------

class TestAsyncEnforceTimingFloor:
    """FIX 3 — async enforce() must apply the same 50ms floor as resolve_and_enforce()."""

    def _make_request(self, key, partition, tlp_level, *, request_id=None):
        import uuid
        from guardian.enforcer import VaultRequest

        class _MockToken:
            agent_id = "agent-x"
            partitions = [partition]
            token_id = "tok-async"

        _MockToken.tlp_level = tlp_level
        return VaultRequest(
            key=key,
            params={},
            request_id=request_id or str(uuid.uuid4()),
            token=_MockToken(),
            peer_der_cert=b"fake",
        )

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def _measure_async(self, key, partition, tlp_level, vault_items, n=5):
        import unittest.mock as mock
        import guardian.enforcer as _enforcer_mod

        times = []
        with mock.patch("shared.token.verify_token_binding"):
            for _ in range(n):
                req = self._make_request(key, partition, tlp_level)
                t0 = time.monotonic()
                try:
                    self._run(enforce(
                        req,
                        vault_items=vault_items,
                        revocation_store=mock.MagicMock(),
                        verify_key_bytes=b"\x00" * 32,
                        deduplicator=mock.MagicMock(),
                        known_partitions=[partition],
                    ))
                except Exception:
                    pass
                times.append(time.monotonic() - t0)
        return times

    def _make_vault(self):
        pub = DataItem(
            item_id="pub", owner_partition="p",
            classification=Classification.PUBLIC, value="v",
        )
        priv = DataItem(
            item_id="priv", owner_partition="p",
            classification=Classification.RESTRICTED, value="v",
        )
        return {"pub/p": pub, "priv/p": priv}

    @pytest.mark.asyncio
    @pytest.mark.timing
    async def test_bad_token_path_respects_min_time(self):
        """Bad token (verify_token_binding raises) must still take >= MIN_RESPONSE_TIME."""
        import unittest.mock as mock
        from shared.token import TokenVerifyError

        vault = self._make_vault()
        times = []
        with mock.patch(
            "shared.token.verify_token_binding",
            side_effect=TokenVerifyError("bad sig"),
        ):
            for _ in range(5):
                req = self._make_request("pub", "p", TlpLevel.GREEN)
                t0 = time.monotonic()
                try:
                    await enforce(
                        req,
                        vault_items=vault,
                        revocation_store=mock.MagicMock(),
                        verify_key_bytes=b"\x00" * 32,
                        deduplicator=mock.MagicMock(),
                        known_partitions=["p"],
                    )
                except EnforcementDenied:
                    pass
                times.append(time.monotonic() - t0)

        for t in times:
            assert t >= _MIN_RESPONSE_TIME * 0.9, f"bad-token path too fast: {t:.4f}s"

    @pytest.mark.asyncio
    @pytest.mark.timing
    async def test_tlp_denied_path_respects_min_time(self):
        """TLP DENY (RESTRICTED item under GREEN token) must take >= MIN_RESPONSE_TIME."""
        import unittest.mock as mock

        vault = self._make_vault()
        times = []
        with mock.patch("shared.token.verify_token_binding"):
            for _ in range(5):
                req = self._make_request("priv", "p", TlpLevel.GREEN)
                t0 = time.monotonic()
                try:
                    await enforce(
                        req,
                        vault_items=vault,
                        revocation_store=mock.MagicMock(),
                        verify_key_bytes=b"\x00" * 32,
                        deduplicator=mock.MagicMock(),
                        known_partitions=["p"],
                    )
                except EnforcementDenied:
                    pass
                times.append(time.monotonic() - t0)

        for t in times:
            assert t >= _MIN_RESPONSE_TIME * 0.9, f"TLP-denied path too fast: {t:.4f}s"

    @pytest.mark.asyncio
    @pytest.mark.timing
    async def test_success_path_respects_min_time(self):
        """Successful enforce() calls must also take >= MIN_RESPONSE_TIME."""
        import unittest.mock as mock

        vault = self._make_vault()
        times = []
        with mock.patch("shared.token.verify_token_binding"):
            for _ in range(5):
                req = self._make_request("pub", "p", TlpLevel.GREEN)
                t0 = time.monotonic()
                try:
                    await enforce(
                        req,
                        vault_items=vault,
                        revocation_store=mock.MagicMock(),
                        verify_key_bytes=b"\x00" * 32,
                        deduplicator=mock.MagicMock(),
                        known_partitions=["p"],
                    )
                except Exception:
                    pass
                times.append(time.monotonic() - t0)

        for t in times:
            assert t >= _MIN_RESPONSE_TIME * 0.9, f"success path too fast: {t:.4f}s"


# ---------------------------------------------------------------------------
# FIX 4: numeric values converted to str() for scan — partition name in str(num)
# ---------------------------------------------------------------------------

class TestScanParamsNumericContainsPartition:
    """FIX 4 — numeric values are converted to str() and scanned.
    Partition name embedded in the string representation must be detected."""

    def test_float_str_contains_partition_raises(self):
        """Partition 'e10' must be detected in str(1e10) = '10000000000.0'...
        actually str(1e10) = '10000000000.0', not 'e10'. Use a partition name
        that actually appears in a numeric string."""
        # str(1e10) = '10000000000.0' — 'e10' does not appear directly
        # Use a more realistic scenario: partition is '10' which appears in '10000000000.0'
        with pytest.raises(ConfusedDeputyError):
            scan_params(
                {"count": 10},
                known_partitions=["10"],
            )

    def test_integer_str_contains_partition_raises(self):
        """Partition name '42' embedded in integer value 42 must raise."""
        with pytest.raises(ConfusedDeputyError):
            scan_params(
                {"value": 42},
                known_partitions=["42"],
            )

    def test_numeric_value_no_partition_passes(self):
        """Numeric value whose str() does not contain a partition name must pass."""
        # No raise expected
        scan_params(
            {"count": 99},
            known_partitions=["company-a", "company-b"],
        )

    def test_negative_int_str_contains_partition_raises(self):
        """Partition '-1' appearing in str(-1) = '-1' must be detected."""
        with pytest.raises(ConfusedDeputyError):
            scan_params(
                {"offset": -1},
                known_partitions=["-1"],
            )
