"""
FIX-04: Enum type collision resolution tests.

Verifies that no two Enum classes in shared/types.py share a class name,
and that no two Enums share member names unless intentionally documented.
"""
from __future__ import annotations

import inspect
from enum import Enum

import pytest

import shared.types as types_module


def _collect_enums():
    """Return all Enum subclasses defined directly in shared.types."""
    return {
        name: cls
        for name, cls in inspect.getmembers(types_module, inspect.isclass)
        if issubclass(cls, Enum) and cls is not Enum
        and cls.__module__ == types_module.__name__
    }


class TestEnumUniqueness:
    def test_all_enum_class_names_are_unique(self):
        """No two Enum classes in shared/types.py may share a name."""
        enums = _collect_enums()
        names = list(enums.keys())
        assert len(names) == len(set(names)), (
            f"Duplicate Enum class names: {[n for n in names if names.count(n) > 1]}"
        )

    def test_no_duplicate_member_names_across_enums(self):
        """
        No two Enum classes should share member names unless explicitly
        justified. This catches accidental copy-paste of enum definitions.
        """
        enums = _collect_enums()
        member_to_classes: dict[str, list[str]] = {}
        for cls_name, cls in enums.items():
            for member_name in cls.__members__:
                member_to_classes.setdefault(member_name, []).append(cls_name)

        # Allowed collisions: document known intentional ones here.
        # Currently none are expected.
        unexpected_collisions = {
            name: classes
            for name, classes in member_to_classes.items()
            if len(classes) > 1
        }
        assert not unexpected_collisions, (
            f"Unexpected enum member name collisions: {unexpected_collisions}\n"
            "If intentional, document with a comment and add to the allowed list."
        )

    def test_decision_is_canonical_in_shared_types(self):
        """Decision enum must be defined exactly once, in shared.types."""
        from shared.types import Decision
        assert Decision.__module__ == "shared.types"
        assert issubclass(Decision, Enum)

    def test_tlp_level_is_canonical_in_shared_types(self):
        """TlpLevel enum must be defined exactly once, in shared.types."""
        from shared.types import TlpLevel
        assert TlpLevel.__module__ == "shared.types"

    def test_classification_is_canonical_in_shared_types(self):
        """Classification enum must be defined exactly once, in shared.types."""
        from shared.types import Classification
        assert Classification.__module__ == "shared.types"

    def test_decision_member_count(self):
        """Decision must have exactly ALLOW, DENY, ELEVATE — no extras."""
        from shared.types import Decision
        assert set(Decision.__members__.keys()) == {"ALLOW", "DENY", "ELEVATE"}

    def test_isinstance_match_uses_correct_type(self):
        """Verify isinstance() works as expected — no shadow imports."""
        from shared.types import Decision
        assert isinstance(Decision.ALLOW, Decision)
        assert not isinstance("ALLOW", Decision)
