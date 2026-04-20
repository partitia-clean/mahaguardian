"""
Canonical enum types shared across all MahaGuardian components.

Use these everywhere — never raw strings for TLP levels,
classifications, or decisions.
"""
from __future__ import annotations

from enum import Enum


class TlpLevel(str, Enum):
    """Traffic Light Protocol level assigned to an agent session."""
    RED          = "RED"
    AMBER_STRICT = "AMBER_STRICT"
    AMBER        = "AMBER"
    GREEN        = "GREEN"
    CLEAR        = "CLEAR"


class Classification(str, Enum):
    """Data classification level assigned to a vault item."""
    RESTRICTED   = "RESTRICTED"
    CONFIDENTIAL = "CONFIDENTIAL"
    INTERNAL     = "INTERNAL"
    PUBLIC       = "PUBLIC"


class Decision(str, Enum):
    """Enforcement decision returned by the TLP matrix and enforcer."""
    ALLOW   = "ALLOW"
    DENY    = "DENY"
    ELEVATE = "ELEVATE"


class IsolationLevel(str, Enum):
    """Agent isolation level — governs sandboxing and verification requirements."""
    DEMO_SANDBOX = "DEMO_SANDBOX"
    ISOLATED     = "ISOLATED"
    SUPERVISED   = "SUPERVISED"
    VERIFIED     = "VERIFIED"
