#!/usr/bin/env python3
"""
Generate multi-party scenario data files.

Outputs (to deploy/scenarios/ by default):
  agents.json       — 30 agents with TLP levels and partitions
  vault_data.json   — 32 data items with partition and classification
  engagements.json  — 5 engagements mapping advisors to clients
  truth_table.json  — 960 (30 agent × 32 item) enforcement decisions

Key-to-partition index is embedded in vault_data.json at generation
time so the enforcer resolves via exact string match — no prefix
matching, no wildcards.

Usage:
    python deploy/generate_scenario.py [--output-dir deploy/scenarios]

The exported Python lists (AGENTS, VAULT_ITEMS, ENGAGEMENTS) can be
imported directly by experiment scripts to avoid JSON I/O.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 12 partitions (opaque strings — exact match only)
# ---------------------------------------------------------------------------

ALL_PARTITIONS: list[str] = [
    "company_a_eng_b",   # Landia: MH engagement work product
    "company_a_eng_c",   # Landia: GreenGrid engagement work product
    "company_a_firm",    # Landia: firm-wide data
    "company_b_commercial",  # MH: V2G economics, OEM pipeline, commercial terms
    "company_b_legal",   # MH: legal structure, opinions, public filings
    "company_c",         # GreenGrid: all data
    "company_d_eng_b",   # Kessler: MH legal engagement work product
    "company_d_eng_e",   # Kessler: NordBatt engagement work product
    "company_d_eng_f",   # Kessler: ChargeNet engagement work product
    "company_d_firm",    # Kessler: firm-wide data
    "company_e",         # NordBatt: all data
    "company_f",         # ChargeNet: all data
]

# ---------------------------------------------------------------------------
# TLP display → wire value mapping
# ---------------------------------------------------------------------------

TLP_DISPLAY_TO_WIRE: dict[str, str] = {
    "FULL ACCESS":    "RED",
    "NEEDS APPROVAL": "AMBER_STRICT",
    "ADVISOR ACCESS": "AMBER",
    "PUBLIC ONLY":    "GREEN",
}

# ---------------------------------------------------------------------------
# Classification display → wire value mapping
# ---------------------------------------------------------------------------

CLF_DISPLAY_TO_WIRE: dict[str, str] = {
    "BOARD ONLY":       "RESTRICTED",
    "ADVISOR-SHAREABLE": "CONFIDENTIAL",
    "INTERNAL":         "INTERNAL",
    "PUBLIC":           "PUBLIC",
}

# ---------------------------------------------------------------------------
# Enforcement matrix  (TLP wire value × Classification wire value → decision)
# ---------------------------------------------------------------------------

MATRIX: dict[tuple[str, str], str] = {
    ("RED",          "RESTRICTED"):   "ALLOW",
    ("RED",          "CONFIDENTIAL"): "ALLOW",
    ("RED",          "INTERNAL"):     "ALLOW",
    ("RED",          "PUBLIC"):       "ALLOW",

    ("AMBER_STRICT", "RESTRICTED"):   "ELEVATE",
    ("AMBER_STRICT", "CONFIDENTIAL"): "ALLOW",
    ("AMBER_STRICT", "INTERNAL"):     "ALLOW",
    ("AMBER_STRICT", "PUBLIC"):       "ALLOW",

    ("AMBER",        "RESTRICTED"):   "DENY",
    ("AMBER",        "CONFIDENTIAL"): "ALLOW",
    ("AMBER",        "INTERNAL"):     "ALLOW",
    ("AMBER",        "PUBLIC"):       "ALLOW",

    ("GREEN",        "RESTRICTED"):   "DENY",
    ("GREEN",        "CONFIDENTIAL"): "DENY",
    ("GREEN",        "INTERNAL"):     "DENY",
    ("GREEN",        "PUBLIC"):       "ALLOW",
}

# ---------------------------------------------------------------------------
# 32 data items
# ---------------------------------------------------------------------------

# Each item: {key, partition, classification, display_classification, value, description}
VAULT_ITEMS: list[dict] = [
    # MH Energy — commercial sub-partition
    {
        "key":            "b_v2g_economics_france",
        "partition":      "company_b_commercial",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"driver": "50%", "MH": "25%", "OEM": "25%"},
        "description":    "MH V2G economics — France pilot revenue split",
    },
    {
        "key":            "b_oem_pipeline_europe",
        "partition":      "company_b_commercial",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          ["BMW", "Stellantis", "Renault"],
        "description":    "MH OEM partnership pipeline — Europe",
    },
    {
        "key":            "b_commercial_terms",
        "partition":      "company_b_commercial",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          {"advisory_fee": "2.5%", "exclusivity": True},
        "description":    "MH commercial engagement terms",
    },

    # MH Energy — legal sub-partition
    {
        "key":            "b_legal_structure",
        "partition":      "company_b_legal",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"entity": "MH Energy Ltd", "jurisdiction": "UK"},
        "description":    "MH legal entity structure",
    },
    {
        "key":            "b_legal_opinions",
        "partition":      "company_b_legal",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          "Counsel opinion on V2G regulatory framework...",
        "description":    "MH V2G regulatory legal opinions",
    },
    {
        "key":            "b_regulatory_status",
        "partition":      "company_b_legal",
        "classification": "INTERNAL",
        "display":        "INTERNAL",
        "value":          "FCA sandbox application pending",
        "description":    "MH FCA sandbox application status",
    },
    {
        "key":            "b_public_filings",
        "partition":      "company_b_legal",
        "classification": "PUBLIC",
        "display":        "PUBLIC",
        "value":          "MH Energy Ltd, Companies House",
        "description":    "MH public regulatory filings",
    },

    # Landia Advisory — engagement B (MH)
    {
        "key":            "a_advisory_mandate_b",
        "partition":      "company_a_eng_b",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"client": "MH", "scope": "V2G strategy"},
        "description":    "Landia advisory mandate for MH engagement",
    },

    # Landia Advisory — engagement C (GreenGrid)
    {
        "key":            "a_advisory_mandate_c",
        "partition":      "company_a_eng_c",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"client": "GreenGrid", "scope": "renewables"},
        "description":    "Landia advisory mandate for GreenGrid engagement",
    },

    # Landia Advisory — firm-wide
    {
        "key":            "a_client_list",
        "partition":      "company_a_firm",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          ["MH", "GreenGrid", "Shell"],
        "description":    "Landia full client roster",
    },
    {
        "key":            "a_fee_schedule",
        "partition":      "company_a_firm",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          {"MH": "\u00a3200k", "GreenGrid": "\u00a3150k"},
        "description":    "Landia engagement fee schedule",
    },
    {
        "key":            "a_public_filings",
        "partition":      "company_a_firm",
        "classification": "PUBLIC",
        "display":        "PUBLIC",
        "value":          "Landia Advisory Ltd, Companies House",
        "description":    "Landia public regulatory filings",
    },

    # GreenGrid
    {
        "key":            "c_project_pipeline",
        "partition":      "company_c",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          ["Solar Farm Wales", "Wind Park Scotland"],
        "description":    "GreenGrid development project pipeline",
    },
    {
        "key":            "c_land_acquisitions",
        "partition":      "company_c",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          [{"site": "Pembroke", "acres": 200}],
        "description":    "GreenGrid land acquisition targets",
    },
    {
        "key":            "c_grid_contracts",
        "partition":      "company_c",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"operator": "National Grid", "term": "15yr"},
        "description":    "GreenGrid grid connection contracts",
    },
    {
        "key":            "c_board_minutes",
        "partition":      "company_c",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          "Q1 2026 board minutes...",
        "description":    "GreenGrid Q1 2026 board minutes",
    },
    {
        "key":            "c_public_filings",
        "partition":      "company_c",
        "classification": "PUBLIC",
        "display":        "PUBLIC",
        "value":          "GreenGrid Renewables Ltd",
        "description":    "GreenGrid public regulatory filings",
    },

    # Kessler Law — engagement B (MH)
    {
        "key":            "d_engagement_b",
        "partition":      "company_d_eng_b",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"client": "MH", "scope": "V2G legal DD"},
        "description":    "Kessler engagement notes for MH",
    },

    # Kessler Law — engagement E (NordBatt)
    {
        "key":            "d_engagement_e",
        "partition":      "company_d_eng_e",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"client": "NordBatt", "scope": "supply"},
        "description":    "Kessler engagement notes for NordBatt",
    },

    # Kessler Law — engagement F (ChargeNet)
    {
        "key":            "d_engagement_f",
        "partition":      "company_d_eng_f",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"client": "ChargeNet", "scope": "M&A"},
        "description":    "Kessler engagement notes for ChargeNet",
    },

    # Kessler Law — firm-wide
    {
        "key":            "d_all_clients",
        "partition":      "company_d_firm",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          ["MH", "NordBatt", "ChargeNet"],
        "description":    "Kessler full client roster",
    },
    {
        "key":            "d_public_filings",
        "partition":      "company_d_firm",
        "classification": "PUBLIC",
        "display":        "PUBLIC",
        "value":          "Kessler Law LLP, SRA register",
        "description":    "Kessler public regulatory filings",
    },

    # NordBatt
    {
        "key":            "e_cell_chemistry",
        "partition":      "company_e",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          {"type": "solid-state"},
        "description":    "NordBatt cell chemistry IP",
    },
    {
        "key":            "e_supply_contracts",
        "partition":      "company_e",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          [{"buyer": "MH", "volume": "50GWh"}],
        "description":    "NordBatt supply contract terms",
    },
    {
        "key":            "e_factory_plans",
        "partition":      "company_e",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          {"location": "Gothenburg"},
        "description":    "NordBatt factory build plans",
    },
    {
        "key":            "e_revenue_forecast",
        "partition":      "company_e",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"2026": "\u20ac120M"},
        "description":    "NordBatt revenue forecast 2026",
    },
    {
        "key":            "e_public_filings",
        "partition":      "company_e",
        "classification": "PUBLIC",
        "display":        "PUBLIC",
        "value":          "NordBatt AB, Bolagsverket",
        "description":    "NordBatt public regulatory filings",
    },

    # ChargeNet
    {
        "key":            "f_network_map",
        "partition":      "company_f",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"chargers": 12000},
        "description":    "ChargeNet EV charger network map",
    },
    {
        "key":            "f_acquisition_targets",
        "partition":      "company_f",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          ["FastCharge GmbH"],
        "description":    "ChargeNet M&A acquisition targets",
    },
    {
        "key":            "f_revenue_per_charger",
        "partition":      "company_f",
        "classification": "CONFIDENTIAL",
        "display":        "ADVISOR-SHAREABLE",
        "value":          {"avg": "\u20ac8,400/yr"},
        "description":    "ChargeNet revenue per charger",
    },
    {
        "key":            "f_board_minutes",
        "partition":      "company_f",
        "classification": "RESTRICTED",
        "display":        "BOARD ONLY",
        "value":          "Q1 2026 board minutes...",
        "description":    "ChargeNet Q1 2026 board minutes",
    },
    {
        "key":            "f_public_filings",
        "partition":      "company_f",
        "classification": "PUBLIC",
        "display":        "PUBLIC",
        "value":          "ChargeNet BV, KvK Netherlands",
        "description":    "ChargeNet public regulatory filings",
    },
]

assert len(VAULT_ITEMS) == 32, f"Expected 32 items, got {len(VAULT_ITEMS)}"

# ---------------------------------------------------------------------------
# 30 agents across 5 engagements
# ---------------------------------------------------------------------------

AGENTS: list[dict] = [
    # ------------------------------------------------------------------ Eng 1: Landia → MH
    {
        "agent_id":      "e1_director",
        "engagement":    1,
        "role":          "Director on Landia and MH boards",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_a_firm", "company_a_eng_b"],
    },
    {
        "agent_id":      "e1_advisor_a",
        "engagement":    1,
        "role":          "Landia strategy agent for MH (eng B notes only)",
        "access_level":  "ADVISOR ACCESS",
        "tlp_level":     "AMBER",
        "partitions":    ["company_a_eng_b"],
    },
    {
        "agent_id":      "e1_internal_a",
        "engagement":    1,
        "role":          "Landia internal — MH engagement",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_a_firm", "company_a_eng_b"],
    },
    {
        "agent_id":      "e1_internal_b",
        "engagement":    1,
        "role":          "MH internal agent",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_b_commercial", "company_b_legal"],
    },
    {
        "agent_id":      "e1_managing_b_for_a",
        "engagement":    1,
        "role":          "MH agent managing Landia (commercial + legal)",
        "access_level":  "NEEDS APPROVAL",
        "tlp_level":     "AMBER_STRICT",
        "partitions":    ["company_b_commercial", "company_b_legal"],
    },
    {
        "agent_id":      "e1_external_b",
        "engagement":    1,
        "role":          "External analyst — PUBLIC only",
        "access_level":  "PUBLIC ONLY",
        "tlp_level":     "GREEN",
        "partitions":    ["company_b_commercial", "company_b_legal"],
    },

    # ------------------------------------------------------------------ Eng 2: Landia → GreenGrid
    {
        "agent_id":      "e2_director",
        "engagement":    2,
        "role":          "Director on Landia and GreenGrid boards",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_a_firm", "company_a_eng_c"],
    },
    {
        "agent_id":      "e2_advisor_a",
        "engagement":    2,
        "role":          "Landia agent for GreenGrid (eng C notes only)",
        "access_level":  "ADVISOR ACCESS",
        "tlp_level":     "AMBER",
        "partitions":    ["company_a_eng_c"],
    },
    {
        "agent_id":      "e2_internal_a",
        "engagement":    2,
        "role":          "Landia internal — GreenGrid engagement",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_a_firm", "company_a_eng_c"],
    },
    {
        "agent_id":      "e2_internal_c",
        "engagement":    2,
        "role":          "GreenGrid internal agent",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_c"],
    },
    {
        "agent_id":      "e2_managing_c",
        "engagement":    2,
        "role":          "GreenGrid agent managing Landia",
        "access_level":  "ADVISOR ACCESS",
        "tlp_level":     "AMBER",
        "partitions":    ["company_c"],
    },
    {
        "agent_id":      "e2_external_c",
        "engagement":    2,
        "role":          "External analyst — PUBLIC only",
        "access_level":  "PUBLIC ONLY",
        "tlp_level":     "GREEN",
        "partitions":    ["company_c"],
    },

    # ------------------------------------------------------------------ Eng 3: Kessler → MH
    {
        "agent_id":      "e3_director",
        "engagement":    3,
        "role":          "Kessler senior partner (MH legal only, no commercial)",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_d_firm", "company_d_eng_b"],
    },
    {
        "agent_id":      "e3_lawyer_d",
        "engagement":    3,
        "role":          "Kessler legal agent for MH (legal sub-partition only)",
        "access_level":  "ADVISOR ACCESS",
        "tlp_level":     "AMBER",
        "partitions":    ["company_d_eng_b"],
    },
    {
        "agent_id":      "e3_internal_d",
        "engagement":    3,
        "role":          "Kessler internal — MH engagement",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_d_firm", "company_d_eng_b"],
    },
    {
        "agent_id":      "e3_internal_b_legal",
        "engagement":    3,
        "role":          "MH legal-side internal agent",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_b_legal"],
    },
    {
        "agent_id":      "e3_managing_b_for_d",
        "engagement":    3,
        "role":          "MH agent managing Kessler (legal only)",
        "access_level":  "ADVISOR ACCESS",
        "tlp_level":     "AMBER",
        "partitions":    ["company_b_legal"],
    },
    {
        "agent_id":      "e3_external_b",
        "engagement":    3,
        "role":          "External legal researcher — PUBLIC only",
        "access_level":  "PUBLIC ONLY",
        "tlp_level":     "GREEN",
        "partitions":    ["company_b_legal"],
    },

    # ------------------------------------------------------------------ Eng 4: Kessler → NordBatt
    {
        "agent_id":      "e4_director",
        "engagement":    4,
        "role":          "Kessler senior partner for NordBatt",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_d_firm", "company_d_eng_e", "company_e"],
    },
    {
        "agent_id":      "e4_lawyer_d",
        "engagement":    4,
        "role":          "Kessler agent for NordBatt — AMBER_STRICT (battery IP)",
        "access_level":  "NEEDS APPROVAL",
        "tlp_level":     "AMBER_STRICT",
        "partitions":    ["company_d_eng_e", "company_e"],
    },
    {
        "agent_id":      "e4_internal_d",
        "engagement":    4,
        "role":          "Kessler internal — NordBatt engagement",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_d_firm", "company_d_eng_e"],
    },
    {
        "agent_id":      "e4_internal_e",
        "engagement":    4,
        "role":          "NordBatt internal agent",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_e"],
    },
    {
        "agent_id":      "e4_managing_e",
        "engagement":    4,
        "role":          "NordBatt agent managing Kessler",
        "access_level":  "ADVISOR ACCESS",
        "tlp_level":     "AMBER",
        "partitions":    ["company_e"],
    },
    {
        "agent_id":      "e4_external_e",
        "engagement":    4,
        "role":          "External analyst — PUBLIC only",
        "access_level":  "PUBLIC ONLY",
        "tlp_level":     "GREEN",
        "partitions":    ["company_e"],
    },

    # ------------------------------------------------------------------ Eng 5: Kessler → ChargeNet
    {
        "agent_id":      "e5_director",
        "engagement":    5,
        "role":          "Kessler senior partner for ChargeNet",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_d_firm", "company_d_eng_f", "company_f"],
    },
    {
        "agent_id":      "e5_lawyer_d",
        "engagement":    5,
        "role":          "Kessler agent for ChargeNet M&A",
        "access_level":  "ADVISOR ACCESS",
        "tlp_level":     "AMBER",
        "partitions":    ["company_d_eng_f"],
    },
    {
        "agent_id":      "e5_internal_d",
        "engagement":    5,
        "role":          "Kessler internal — ChargeNet engagement",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_d_firm", "company_d_eng_f"],
    },
    {
        "agent_id":      "e5_internal_f",
        "engagement":    5,
        "role":          "ChargeNet internal agent",
        "access_level":  "FULL ACCESS",
        "tlp_level":     "RED",
        "partitions":    ["company_f"],
    },
    {
        "agent_id":      "e5_managing_f",
        "engagement":    5,
        "role":          "ChargeNet agent managing Kessler",
        "access_level":  "ADVISOR ACCESS",
        "tlp_level":     "AMBER",
        "partitions":    ["company_f"],
    },
    {
        "agent_id":      "e5_external_f",
        "engagement":    5,
        "role":          "External analyst — PUBLIC only",
        "access_level":  "PUBLIC ONLY",
        "tlp_level":     "GREEN",
        "partitions":    ["company_f"],
    },
]

assert len(AGENTS) == 30, f"Expected 30 agents, got {len(AGENTS)}"

# ---------------------------------------------------------------------------
# 5 engagements
# ---------------------------------------------------------------------------

ENGAGEMENTS: list[dict] = [
    {
        "id":       1,
        "advisor":  "company_a",
        "advisor_name": "Landia Advisory",
        "client":   "company_b",
        "client_name": "MH Energy",
        "scope":    "V2G strategy",
        "label":    "DEMO DAY",
        "advisor_partitions": ["company_a_eng_b", "company_a_firm"],
        "client_partitions":  ["company_b_commercial", "company_b_legal"],
    },
    {
        "id":       2,
        "advisor":  "company_a",
        "advisor_name": "Landia Advisory",
        "client":   "company_c",
        "client_name": "GreenGrid",
        "scope":    "Renewables strategy",
        "label":    "",
        "advisor_partitions": ["company_a_eng_c", "company_a_firm"],
        "client_partitions":  ["company_c"],
    },
    {
        "id":       3,
        "advisor":  "company_d",
        "advisor_name": "Kessler Law",
        "client":   "company_b",
        "client_name": "MH Energy",
        "scope":    "Legal due diligence",
        "label":    "",
        "advisor_partitions": ["company_d_eng_b", "company_d_firm"],
        "client_partitions":  ["company_b_legal"],
    },
    {
        "id":       4,
        "advisor":  "company_d",
        "advisor_name": "Kessler Law",
        "client":   "company_e",
        "client_name": "NordBatt",
        "scope":    "Supply contracts",
        "label":    "",
        "advisor_partitions": ["company_d_eng_e", "company_d_firm"],
        "client_partitions":  ["company_e"],
    },
    {
        "id":       5,
        "advisor":  "company_d",
        "advisor_name": "Kessler Law",
        "client":   "company_f",
        "client_name": "ChargeNet",
        "scope":    "M&A advisory",
        "label":    "",
        "advisor_partitions": ["company_d_eng_f", "company_d_firm"],
        "client_partitions":  ["company_f"],
    },
]

# ---------------------------------------------------------------------------
# Truth table computation
# ---------------------------------------------------------------------------

def _enforce_decision(
    agent_partitions: list[str],
    agent_tlp: str,
    item_partition: str,
    item_classification: str,
) -> str:
    """
    Compute the enforcement decision for one (agent, item) pair.

    Step 1: Partition check — exact string match only, no prefix matching.
    Step 2: TLP matrix lookup.

    Returns "ALLOW", "DENY", or "ELEVATE".
    """
    # Partition check (exact match — opaque strings)
    if item_partition not in agent_partitions:
        return "DENY"
    # TLP matrix
    return MATRIX[(agent_tlp, item_classification)]


def build_truth_table(
    agents: list[dict],
    vault_items: list[dict],
) -> list[dict]:
    """
    Build the 30 × 32 truth table.

    Each row:
      {agent_id, item_key, item_partition, item_classification,
       decision, deny_reason}

    deny_reason is "partition_barrier" or "tlp_insufficient" or "".
    """
    rows: list[dict] = []
    for agent in agents:
        for item in vault_items:
            in_partition = item["partition"] in agent["partitions"]
            if not in_partition:
                decision    = "DENY"
                deny_reason = "partition_barrier"
            else:
                matrix_decision = MATRIX[(agent["tlp_level"], item["classification"])]
                decision    = matrix_decision
                deny_reason = "" if decision == "ALLOW" else (
                    "tlp_insufficient" if decision == "DENY" else "elevate_required"
                )
            rows.append({
                "agent_id":          agent["agent_id"],
                "engagement":        agent["engagement"],
                "tlp_level":         agent["tlp_level"],
                "item_key":          item["key"],
                "item_partition":    item["partition"],
                "item_classification": item["classification"],
                "decision":          decision,
                "deny_reason":       deny_reason,
            })
    return rows


# ---------------------------------------------------------------------------
# Key-to-partition index
# ---------------------------------------------------------------------------

def build_key_index(vault_items: list[dict]) -> dict[str, str]:
    """Map item_key → partition for fast O(1) lookup."""
    return {item["key"]: item["partition"] for item in vault_items}


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def generate(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    key_index = build_key_index(VAULT_ITEMS)
    truth_table = build_truth_table(AGENTS, VAULT_ITEMS)

    vault_payload = {
        "items":     VAULT_ITEMS,
        "key_index": key_index,
        "count":     len(VAULT_ITEMS),
    }

    (output_dir / "agents.json").write_text(
        json.dumps({"agents": AGENTS, "count": len(AGENTS)}, indent=2, ensure_ascii=False)
    )
    (output_dir / "vault_data.json").write_text(
        json.dumps(vault_payload, indent=2, ensure_ascii=False)
    )
    (output_dir / "engagements.json").write_text(
        json.dumps({"engagements": ENGAGEMENTS}, indent=2, ensure_ascii=False)
    )
    (output_dir / "truth_table.json").write_text(
        json.dumps(
            {
                "rows":    truth_table,
                "count":   len(truth_table),
                "agents":  len(AGENTS),
                "items":   len(VAULT_ITEMS),
            },
            indent=2,
            ensure_ascii=False,
        )
    )

    print(f"Generated scenario in {output_dir}/")
    print(f"  agents.json:      {len(AGENTS)} agents")
    print(f"  vault_data.json:  {len(VAULT_ITEMS)} items, {len(key_index)} keys in index")
    print(f"  engagements.json: {len(ENGAGEMENTS)} engagements")
    print(f"  truth_table.json: {len(truth_table)} decisions "
          f"({len(AGENTS)} × {len(VAULT_ITEMS)})")

    # Quick sanity: count by decision type
    by_decision: dict[str, int] = {}
    for row in truth_table:
        by_decision[row["decision"]] = by_decision.get(row["decision"], 0) + 1
    for decision, count in sorted(by_decision.items()):
        print(f"    {decision}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate scenario JSON files."
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent / "scenarios"),
        help="Directory to write output files (default: deploy/scenarios/)",
    )
    args = parser.parse_args()
    generate(Path(args.output_dir))


if __name__ == "__main__":
    main()
