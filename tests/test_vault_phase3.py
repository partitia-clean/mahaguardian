"""
Phase 3 vault tests — Step 6.

Covers:
  - seed_demo_items: all 4 demo items seeded; idempotency
  - _get_vault_items_unfiltered: returns deserialized DataItems with composite keys
  - Partition filtering and item lookup via _find_items_no_tlp_check() (enforcer)
  - Classification/tag filtering via _get_vault_items_unfiltered() with manual filter

NOTE: _vault_read/_vault_search/_vault_list have been removed (FIX 2).
Vault data retrieval is now ONLY possible through the enforcer pipeline.
Tests that previously used those functions now use _find_items_no_tlp_check() and
_get_vault_items_unfiltered() which are the actual code paths used by enforce().
"""
from __future__ import annotations

from typing import Optional

import pytest

import guardian.audit as audit_module
from guardian.vault import (
    _get_vault_items_unfiltered,
    seed_demo_items,
)
from guardian.enforcer import _find_items_no_tlp_check
from shared.data_item import DEMO_ITEMS, DataItem
from shared.types import Classification


# ---------------------------------------------------------------------------
# Helpers — replacements for the removed _vault_read/_vault_search/_vault_list
# ---------------------------------------------------------------------------

def _find(vault_dict: dict, key: str, *, token_partitions: list[str]) -> Optional[DataItem]:
    """Equivalent to old _vault_read — uses _find_items_no_tlp_check() from enforcer."""
    items = _find_items_no_tlp_check(key, token_partitions, _get_vault_items_unfiltered(vault_dict))
    return items[0] if len(items) == 1 else None


def _search(
    vault_dict: dict,
    *,
    token_partitions: list[str],
    tags: Optional[list[str]] = None,
    classification: Optional[Classification] = None,
) -> list[DataItem]:
    """Equivalent to old _vault_search — filters _get_vault_items_unfiltered() directly."""
    results = []
    for item in _get_vault_items_unfiltered(vault_dict).values():
        if item.owner_partition not in token_partitions:
            continue
        if classification is not None and item.classification != classification:
            continue
        if tags is not None and not any(t in item.tags for t in tags):
            continue
        results.append(item)
    return results


def _list(vault_dict: dict, *, token_partitions: list[str]) -> list[DataItem]:
    """Equivalent to old _vault_list."""
    return _search(vault_dict, token_partitions=token_partitions)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_audit(tmp_path):
    audit_module.init_audit_log(tmp_path / "audit.db")
    yield


@pytest.fixture
def empty_vault() -> dict:
    return {}


@pytest.fixture
def seeded_vault() -> dict:
    v: dict = {}
    seed_demo_items(v)
    return v


# ---------------------------------------------------------------------------
# seed_demo_items
# ---------------------------------------------------------------------------

class TestSeedDemoItems:
    def test_seeds_all_demo_items(self, empty_vault):
        seed_demo_items(empty_vault)
        assert len(empty_vault["data_items"]) == len(DEMO_ITEMS)

    def test_idempotent_on_repeated_call(self, seeded_vault):
        seed_demo_items(seeded_vault)  # second call
        assert len(seeded_vault["data_items"]) == len(DEMO_ITEMS)

    def test_preserves_existing_unrelated_items(self, empty_vault):
        empty_vault["data_items"] = [{
            "item_id": "extra",
            "owner_partition": "company-c",
            "classification": "PUBLIC",
            "value": "extra_value",
            "description": "",
            "tags": [],
        }]
        seed_demo_items(empty_vault)
        ids = {d["item_id"] for d in empty_vault["data_items"]}
        assert "extra" in ids

    def test_demo_items_have_correct_partitions(self, seeded_vault):
        partitions = {d["owner_partition"] for d in seeded_vault["data_items"]}
        assert "company-a" in partitions
        assert "company-b" in partitions

    def test_replaces_existing_demo_item(self, seeded_vault):
        # Mutate one item, re-seed, verify it's reset to demo value
        for d in seeded_vault["data_items"]:
            if d["item_id"] == "client_count":
                d["value"] = 9999
        seed_demo_items(seeded_vault)
        for d in seeded_vault["data_items"]:
            if d["item_id"] == "client_count":
                assert d["value"] == 40  # demo value restored


# ---------------------------------------------------------------------------
# _get_vault_items_unfiltered
# ---------------------------------------------------------------------------

class TestGetVaultItems:
    def test_returns_dict_of_data_items(self, seeded_vault):
        items = _get_vault_items_unfiltered(seeded_vault)
        assert isinstance(items, dict)
        assert len(items) == len(DEMO_ITEMS)

    def test_keys_are_composite(self, seeded_vault):
        items = _get_vault_items_unfiltered(seeded_vault)
        for key in items:
            assert "/" in key  # composite key: item_id/partition

    def test_values_are_data_items(self, seeded_vault):
        items = _get_vault_items_unfiltered(seeded_vault)
        for v in items.values():
            assert isinstance(v, DataItem)

    def test_classification_deserialized_as_enum(self, seeded_vault):
        items = _get_vault_items_unfiltered(seeded_vault)
        for item in items.values():
            assert isinstance(item.classification, Classification)

    def test_empty_vault_returns_empty_dict(self, empty_vault):
        assert _get_vault_items_unfiltered(empty_vault) == {}


# ---------------------------------------------------------------------------
# Item lookup via _find_items_no_tlp_check() — the actual enforcer path (replaces _vault_read)
# ---------------------------------------------------------------------------

class TestVaultItemLookup:
    """FIX 2: Tests now use _find_items_no_tlp_check() from guardian.enforcer, which is the
    actual code path called by enforce() and resolve_and_enforce()."""

    def test_find_authorized_item(self, seeded_vault):
        item = _find(seeded_vault, "client_count", token_partitions=["company-a"])
        assert item is not None
        assert item.item_id == "client_count"
        assert item.owner_partition == "company-a"

    def test_find_wrong_partition_returns_none(self, seeded_vault):
        item = _find(seeded_vault, "client_count", token_partitions=["company-b"])
        assert item is None

    def test_find_nonexistent_key_returns_none(self, seeded_vault):
        item = _find(seeded_vault, "nonexistent_key", token_partitions=["company-a"])
        assert item is None

    def test_find_company_b_item(self, seeded_vault):
        item = _find(seeded_vault, "v2g_profit_split", token_partitions=["company-b"])
        assert item is not None
        assert item.owner_partition == "company-b"

    def test_find_with_multi_partition_token(self, seeded_vault):
        item = _find(
            seeded_vault, "v2g_profit_split",
            token_partitions=["company-a", "company-b"],
        )
        assert item is not None


# ---------------------------------------------------------------------------
# Item filtering via _get_vault_items_unfiltered() (replaces _vault_search/_vault_list)
# ---------------------------------------------------------------------------

class TestVaultSearch:
    def test_search_by_partition_only(self, seeded_vault):
        results = _search(seeded_vault, token_partitions=["company-a"])
        assert all(r.owner_partition == "company-a" for r in results)
        assert len(results) == 2  # client_count + public_filings

    def test_search_excludes_other_partitions(self, seeded_vault):
        results = _search(seeded_vault, token_partitions=["company-a"])
        assert all(r.owner_partition != "company-b" for r in results)

    def test_search_by_classification(self, seeded_vault):
        results = _search(
            seeded_vault,
            token_partitions=["company-a"],
            classification=Classification.PUBLIC,
        )
        assert all(r.classification == Classification.PUBLIC for r in results)

    def test_search_restricted_only(self, seeded_vault):
        results = _search(
            seeded_vault,
            token_partitions=["company-a", "company-b"],
            classification=Classification.RESTRICTED,
        )
        assert len(results) == 2  # client_count + v2g_profit_split
        assert all(r.classification == Classification.RESTRICTED for r in results)

    def test_search_by_tag(self, seeded_vault):
        results = _search(
            seeded_vault,
            token_partitions=["company-b"],
            tags=["v2g"],
        )
        assert len(results) == 2  # v2g_profit_split + ev_driver_earnings
        assert all("v2g" in r.tags for r in results)

    def test_search_by_financials_tag(self, seeded_vault):
        results = _search(
            seeded_vault,
            token_partitions=["company-a", "company-b"],
            tags=["financials"],
        )
        assert len(results) == 2  # client_count + v2g_profit_split

    def test_search_tag_and_classification_combined(self, seeded_vault):
        results = _search(
            seeded_vault,
            token_partitions=["company-a", "company-b"],
            tags=["public"],
            classification=Classification.PUBLIC,
        )
        for r in results:
            assert r.classification == Classification.PUBLIC
            assert "public" in r.tags

    def test_search_empty_result_for_unauthorized_partition(self, seeded_vault):
        results = _search(seeded_vault, token_partitions=["company-c"])
        assert results == []

    def test_search_no_tag_match_returns_empty(self, seeded_vault):
        results = _search(
            seeded_vault,
            token_partitions=["company-a"],
            tags=["nonexistent_tag"],
        )
        assert results == []


class TestVaultList:
    def test_list_returns_all_authorized_items(self, seeded_vault):
        results = _list(seeded_vault, token_partitions=["company-a"])
        assert len(results) == 2

    def test_list_director_sees_both_partitions(self, seeded_vault):
        results = _list(seeded_vault, token_partitions=["company-a", "company-b"])
        assert len(results) == 4  # all demo items

    def test_list_empty_for_no_partitions(self, seeded_vault):
        results = _list(seeded_vault, token_partitions=[])
        assert results == []


# ---------------------------------------------------------------------------
# FIX 2: Structural enforcement — vault internals no longer importable
# ---------------------------------------------------------------------------

class TestVaultStructuralEnforcement:
    """FIX 2: Verify that the deleted functions are no longer importable,
    and that vault data is ONLY accessible through the enforcer pipeline."""

    def test_vault_read_not_importable(self):
        """_vault_read must not exist in guardian.vault after FIX 2."""
        import guardian.vault as _vault_mod
        assert not hasattr(_vault_mod, "_vault_read"), (
            "_vault_read still exists — FIX 2 incomplete"
        )

    def test_vault_search_not_importable(self):
        """_vault_search must not exist in guardian.vault after FIX 2."""
        import guardian.vault as _vault_mod
        assert not hasattr(_vault_mod, "_vault_search"), (
            "_vault_search still exists — FIX 2 incomplete"
        )

    def test_vault_list_not_importable(self):
        """_vault_list must not exist in guardian.vault after FIX 2."""
        import guardian.vault as _vault_mod
        assert not hasattr(_vault_mod, "_vault_list"), (
            "_vault_list still exists — FIX 2 incomplete"
        )

    def test_tlp_checked_contextvar_removed(self):
        """_TLP_CHECKED ContextVar must not exist after FIX 2."""
        import guardian.vault as _vault_mod
        assert not hasattr(_vault_mod, "_TLP_CHECKED"), (
            "_TLP_CHECKED still exists — FIX 2 incomplete"
        )

    def test_with_tlp_enforcement_removed(self):
        """_with_tlp_enforcement context manager must not exist after FIX 2."""
        import guardian.vault as _vault_mod
        assert not hasattr(_vault_mod, "_with_tlp_enforcement"), (
            "_with_tlp_enforcement still exists — FIX 2 incomplete"
        )

    def test_enforce_path_returns_data_for_valid_request(self, seeded_vault):
        """FIX 2: vault data IS accessible through resolve_and_enforce()."""
        from guardian.enforcer import resolve_and_enforce
        from shared.types import TlpLevel

        item = resolve_and_enforce(
            key="public_filings",
            token_partitions=["company-a"],
            tlp_level=TlpLevel.GREEN,
            params={},
            vault_items=_get_vault_items_unfiltered(seeded_vault),
            agent_id="test-agent",
            known_partitions=["company-a"],
        )
        assert item.item_id == "public_filings"

    def test_enforce_path_denies_tlp_violation(self, seeded_vault):
        """FIX 2: TLP denial still works through the enforcer pipeline."""
        from guardian.enforcer import resolve_and_enforce, EnforcementDenied
        from shared.types import TlpLevel

        with pytest.raises(EnforcementDenied) as exc_info:
            resolve_and_enforce(
                key="client_count",           # RESTRICTED
                token_partitions=["company-a"],
                tlp_level=TlpLevel.GREEN,     # GREEN cannot see RESTRICTED
                params={},
                vault_items=_get_vault_items_unfiltered(seeded_vault),
                agent_id="test-agent",
                known_partitions=["company-a"],
            )
        assert exc_info.value.reason_code == "tlp_insufficient"
