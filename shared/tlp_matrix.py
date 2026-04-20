"""
TLP enforcement matrix.

Returns a Decision for every (TlpLevel, Classification) pair.
The matrix encodes which data classifications an agent at a given
TLP level may access:

  RED          — top-clearance: access all classifications
  AMBER_STRICT — RESTRICTED requires human elevation; others allowed
  AMBER        — RESTRICTED denied; CONFIDENTIAL and below allowed
  GREEN        — only PUBLIC allowed (HW8 canonical matrix)
  CLEAR        — only PUBLIC allowed

Use check_tlp() — never index MATRIX directly from application code.
"""
from __future__ import annotations

import unicodedata

from shared.types import Classification, Decision, TlpLevel


MATRIX: dict[tuple[TlpLevel, Classification], Decision] = {
    # --- RED: full clearance ---
    (TlpLevel.RED, Classification.RESTRICTED):   Decision.ALLOW,
    (TlpLevel.RED, Classification.CONFIDENTIAL): Decision.ALLOW,
    (TlpLevel.RED, Classification.INTERNAL):     Decision.ALLOW,
    (TlpLevel.RED, Classification.PUBLIC):       Decision.ALLOW,

    # --- AMBER_STRICT: RESTRICTED requires human approval ---
    (TlpLevel.AMBER_STRICT, Classification.RESTRICTED):   Decision.ELEVATE,
    (TlpLevel.AMBER_STRICT, Classification.CONFIDENTIAL): Decision.ALLOW,
    (TlpLevel.AMBER_STRICT, Classification.INTERNAL):     Decision.ALLOW,
    (TlpLevel.AMBER_STRICT, Classification.PUBLIC):       Decision.ALLOW,

    # --- AMBER: RESTRICTED denied outright ---
    (TlpLevel.AMBER, Classification.RESTRICTED):   Decision.DENY,
    (TlpLevel.AMBER, Classification.CONFIDENTIAL): Decision.ALLOW,
    (TlpLevel.AMBER, Classification.INTERNAL):     Decision.ALLOW,
    (TlpLevel.AMBER, Classification.PUBLIC):       Decision.ALLOW,

    # --- GREEN: only PUBLIC allowed (canonical HW8 matrix) ---
    (TlpLevel.GREEN, Classification.RESTRICTED):   Decision.DENY,
    (TlpLevel.GREEN, Classification.CONFIDENTIAL): Decision.DENY,
    (TlpLevel.GREEN, Classification.INTERNAL):     Decision.DENY,
    (TlpLevel.GREEN, Classification.PUBLIC):       Decision.ALLOW,

    # --- CLEAR: only PUBLIC allowed ---
    (TlpLevel.CLEAR, Classification.RESTRICTED):   Decision.DENY,
    (TlpLevel.CLEAR, Classification.CONFIDENTIAL): Decision.DENY,
    (TlpLevel.CLEAR, Classification.INTERNAL):     Decision.DENY,
    (TlpLevel.CLEAR, Classification.PUBLIC):       Decision.ALLOW,
}


def check_tlp(tlp: TlpLevel, classification: Classification) -> Decision:
    """
    Return the enforcement Decision for this (tlp, classification) pair.

    Fail-closed: any input that cannot be resolved to a valid enum member
    (unknown value, unicode confusable, empty string, wrong case) returns
    Decision.DENY rather than raising.

    Both arguments are NFC-normalised, upper-cased, and stripped before
    enum lookup (F6 — input normalization hardening).
    """
    try:
        if not isinstance(tlp, TlpLevel):
            normed = unicodedata.normalize("NFC", str(tlp)).upper().strip()
            tlp = TlpLevel(normed)
        if not isinstance(classification, Classification):
            normed = unicodedata.normalize("NFC", str(classification)).upper().strip()
            classification = Classification(normed)
        return MATRIX[(tlp, classification)]
    except (ValueError, KeyError):
        return Decision.DENY
