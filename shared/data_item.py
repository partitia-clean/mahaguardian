"""
DataItem — the unit of classified data stored in the vault.

Each item belongs to exactly one partition and has a Classification
level. The enforcer uses this to resolve which partition owns a key
and whether the requesting agent's TLP level permits access.

Value is stored as Any (encrypted at rest by the vault layer).
This module is pure data modelling — no crypto, no I/O.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shared.types import Classification


@dataclass
class DataItem:
    """
    A single classified data item in the vault.

    Fields:
      item_id          — unique key within vault (e.g. "client_count")
      owner_partition  — partition this item belongs to (e.g. "company-a")
      classification   — Classification enum level
      value            — actual data (encrypted at rest by vault layer)
      description      — human-readable label for audit reports
      tags             — optional metadata tags for search
    """
    item_id:         str
    owner_partition: str
    classification:  Classification
    value:           Any
    description:     str = ""
    tags:            list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Demo dataset — seeded into every vault instance for Demo Day MVP
# ---------------------------------------------------------------------------

DEMO_ITEMS: list[DataItem] = [
    DataItem(
        item_id         = "client_count",
        owner_partition = "company-a",
        classification  = Classification.RESTRICTED,
        value           = 40,
        description     = "Company A — total active client count",
        tags            = ["financials", "headcount"],
    ),
    DataItem(
        item_id         = "public_filings",
        owner_partition = "company-a",
        classification  = Classification.PUBLIC,
        value           = "https://filings.company-a.example/2025",
        description     = "Company A — public regulatory filings index",
        tags            = ["regulatory", "public"],
    ),
    DataItem(
        item_id         = "v2g_profit_split",
        owner_partition = "company-b",
        classification  = Classification.RESTRICTED,
        value           = {"company_b": 50, "grid_operator": 25, "ev_driver": 25},
        description     = "Company B — V2G profit-sharing breakdown (%)",
        tags            = ["financials", "v2g"],
    ),
    DataItem(
        item_id         = "ev_driver_earnings",
        owner_partition = "company-b",
        classification  = Classification.PUBLIC,
        value           = "€500/yr",
        description     = "Company B — average EV driver annual earnings from V2G",
        tags            = ["public", "v2g"],
    ),
]
