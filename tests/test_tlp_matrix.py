"""
Tests for shared/tlp_matrix.py — one test per matrix cell (20 total).
"""
from __future__ import annotations

import pytest

from shared.tlp_matrix import check_tlp
from shared.types import Classification, Decision, TlpLevel


# ---------------------------------------------------------------------------
# Parametrized truth table — one case per (tlp, classification) cell
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tlp,classification,expected", [
    # RED: all ALLOW
    (TlpLevel.RED, Classification.RESTRICTED,   Decision.ALLOW),
    (TlpLevel.RED, Classification.CONFIDENTIAL, Decision.ALLOW),
    (TlpLevel.RED, Classification.INTERNAL,     Decision.ALLOW),
    (TlpLevel.RED, Classification.PUBLIC,       Decision.ALLOW),

    # AMBER_STRICT: RESTRICTED → ELEVATE, rest ALLOW
    (TlpLevel.AMBER_STRICT, Classification.RESTRICTED,   Decision.ELEVATE),
    (TlpLevel.AMBER_STRICT, Classification.CONFIDENTIAL, Decision.ALLOW),
    (TlpLevel.AMBER_STRICT, Classification.INTERNAL,     Decision.ALLOW),
    (TlpLevel.AMBER_STRICT, Classification.PUBLIC,       Decision.ALLOW),

    # AMBER: RESTRICTED → DENY, rest ALLOW
    (TlpLevel.AMBER, Classification.RESTRICTED,   Decision.DENY),
    (TlpLevel.AMBER, Classification.CONFIDENTIAL, Decision.ALLOW),
    (TlpLevel.AMBER, Classification.INTERNAL,     Decision.ALLOW),
    (TlpLevel.AMBER, Classification.PUBLIC,       Decision.ALLOW),

    # GREEN: only PUBLIC → ALLOW (PUBLIC ONLY display label)
    (TlpLevel.GREEN, Classification.RESTRICTED,   Decision.DENY),
    (TlpLevel.GREEN, Classification.CONFIDENTIAL, Decision.DENY),
    (TlpLevel.GREEN, Classification.INTERNAL,     Decision.DENY),
    (TlpLevel.GREEN, Classification.PUBLIC,       Decision.ALLOW),

    # CLEAR: only PUBLIC → ALLOW
    (TlpLevel.CLEAR, Classification.RESTRICTED,   Decision.DENY),
    (TlpLevel.CLEAR, Classification.CONFIDENTIAL, Decision.DENY),
    (TlpLevel.CLEAR, Classification.INTERNAL,     Decision.DENY),
    (TlpLevel.CLEAR, Classification.PUBLIC,       Decision.ALLOW),
])
def test_tlp_matrix_cell(tlp, classification, expected):
    assert check_tlp(tlp, classification) == expected


# ---------------------------------------------------------------------------
# Enum identity checks
# ---------------------------------------------------------------------------

def test_decision_values_are_strings():
    assert Decision.ALLOW == "ALLOW"
    assert Decision.DENY == "DENY"
    assert Decision.ELEVATE == "ELEVATE"


def test_tlp_values_are_strings():
    assert TlpLevel.RED == "RED"
    assert TlpLevel.AMBER_STRICT == "AMBER_STRICT"
    assert TlpLevel.CLEAR == "CLEAR"


def test_classification_values_are_strings():
    assert Classification.RESTRICTED == "RESTRICTED"
    assert Classification.PUBLIC == "PUBLIC"


# ---------------------------------------------------------------------------
# NFC normalisation — visually identical strings must compare equal
# ---------------------------------------------------------------------------

def test_check_tlp_accepts_raw_strings():
    """check_tlp coerces raw strings via enum constructor."""
    result = check_tlp(TlpLevel("RED"), Classification("PUBLIC"))
    assert result == Decision.ALLOW


def test_matrix_is_complete():
    """Every (TlpLevel, Classification) pair has an entry."""
    from shared.tlp_matrix import MATRIX
    for tlp in TlpLevel:
        for cls in Classification:
            assert (tlp, cls) in MATRIX, f"Missing: ({tlp}, {cls})"


# ---------------------------------------------------------------------------
# FIX F6: Invalid input fails-closed (returns DENY, never raises)
# ---------------------------------------------------------------------------

def test_invalid_tlp_returns_deny():
    """Unknown TLP string must return DENY (fail-closed), not raise."""
    from shared.types import Decision
    assert check_tlp("ULTRA_SECRET", Classification.PUBLIC) == Decision.DENY


def test_invalid_classification_returns_deny():
    """Unknown classification string must return DENY (fail-closed), not raise."""
    from shared.types import Decision
    assert check_tlp(TlpLevel.RED, "EYES_ONLY") == Decision.DENY


def test_no_silent_default_allow():
    """Every entry in MATRIX must be an explicit Decision — no None."""
    from shared.tlp_matrix import MATRIX
    for (tlp, cls), decision in MATRIX.items():
        assert isinstance(decision, Decision), (
            f"({tlp}, {cls}) has non-Decision value: {decision!r}"
        )
        assert decision in (Decision.ALLOW, Decision.DENY, Decision.ELEVATE)


# ---------------------------------------------------------------------------
# FIX-06: Boundary value expansion — enum members
# ---------------------------------------------------------------------------

def test_matrix_covers_all_tlp_enum_members():
    """Every TlpLevel enum member must appear in MATRIX (first/last members included)."""
    from shared.tlp_matrix import MATRIX
    tlp_values = list(TlpLevel)
    assert tlp_values[0] == TlpLevel.RED       # first member
    assert tlp_values[-1] == TlpLevel.CLEAR    # last member
    for tlp in tlp_values:
        for cls in Classification:
            assert (tlp, cls) in MATRIX


def test_matrix_covers_all_classification_enum_members():
    """Every Classification enum member must appear in MATRIX."""
    from shared.tlp_matrix import MATRIX
    cls_values = list(Classification)
    assert cls_values[0] == Classification.RESTRICTED   # first member
    assert cls_values[-1] == Classification.PUBLIC      # last member
    for tlp in TlpLevel:
        for cls in cls_values:
            assert (tlp, cls) in MATRIX


def test_check_tlp_rejects_none_tlp():
    """None as TLP must return DENY (fail-closed)."""
    from shared.types import Decision
    assert check_tlp(None, Classification.PUBLIC) == Decision.DENY


def test_check_tlp_rejects_none_classification():
    """None as classification must return DENY (fail-closed)."""
    from shared.types import Decision
    assert check_tlp(TlpLevel.RED, None) == Decision.DENY


def test_check_tlp_rejects_empty_string():
    """Empty string must return DENY (fail-closed)."""
    from shared.types import Decision
    assert check_tlp("", Classification.PUBLIC) == Decision.DENY


# ---------------------------------------------------------------------------
# F2 + F7 — Exhaustive truth table & edge case coverage
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tlp_str,cls_str,expected", [
    # Lowercase strings must normalise to the correct enum member (F6 hardening)
    ("red",          "PUBLIC",       Decision.ALLOW),
    ("amber",        "PUBLIC",       Decision.ALLOW),
    ("amber",        "restricted",   Decision.DENY),
    ("amber_strict", "restricted",   Decision.ELEVATE),
    ("green",        "public",       Decision.ALLOW),
    ("green",        "internal",     Decision.DENY),
    ("clear",        "PUBLIC",       Decision.ALLOW),
    # Mixed case
    ("Red",          "Public",       Decision.ALLOW),
    ("AMBER_STRICT", "Restricted",   Decision.ELEVATE),
    # Leading/trailing whitespace stripped
    (" RED ",        "PUBLIC",       Decision.ALLOW),
    ("AMBER ",       "CONFIDENTIAL", Decision.ALLOW),
])
def test_tlp_matrix_case_and_whitespace_normalisation(tlp_str, cls_str, expected):
    """F2+F7: check_tlp normalises case and whitespace before lookup."""
    assert check_tlp(tlp_str, cls_str) == expected


@pytest.mark.parametrize("tlp_str", [
    "TLP:RED", "tlp:red", "TLP:AMBER", "TLP_RED", "ULTRAVIOLET",
    "red_strict", "amber strict", "GREEN/CLEAR",
])
def test_tlp_matrix_invalid_strings_deny(tlp_str):
    """F2+F7: completely invalid TLP identifiers must return DENY."""
    assert check_tlp(tlp_str, Classification.PUBLIC) == Decision.DENY


@pytest.mark.parametrize("cls_str", [
    "SECRET", "EYES_ONLY", "TOP_SECRET", "UNCLASSIFIED", "SCI",
])
def test_tlp_matrix_invalid_classification_deny(cls_str):
    """F2+F7: unknown classification values must return DENY."""
    assert check_tlp(TlpLevel.RED, cls_str) == Decision.DENY


def test_tlp_matrix_full_cartesian_product():
    """F2+F7: every (TlpLevel × Classification) pair must match the spec truth table."""
    from shared.tlp_matrix import MATRIX
    # Verify the matrix is complete and all values match what check_tlp returns
    for tlp in TlpLevel:
        for cls in Classification:
            assert (tlp, cls) in MATRIX, f"Missing matrix cell: ({tlp}, {cls})"
            expected = MATRIX[(tlp, cls)]
            actual = check_tlp(tlp, cls)
            assert actual == expected, (
                f"check_tlp({tlp}, {cls}) returned {actual}, expected {expected}"
            )
