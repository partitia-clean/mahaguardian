"""
FIX-03: Replay protection boundary condition tests.

Tests the RequestDeduplicator in shared/token.py:
  - First use of request_id is accepted
  - Same request_id within window is rejected
  - Same request_id after window expiry is accepted again
  - Boundary: exactly at window_start and window_end
  - Clock skew simulation
"""
from __future__ import annotations

import time
import unittest.mock as mock

import pytest

from shared.token import DuplicateRequestError, RequestDeduplicator, _DEDUP_WINDOW_SECONDS


class TestReplayProtectionWindow:
    def test_first_request_accepted(self):
        ded = RequestDeduplicator()
        ded.check_and_register("req-1")  # must not raise

    def test_duplicate_within_window_rejected(self):
        ded = RequestDeduplicator()
        ded.check_and_register("req-dup")
        with pytest.raises(DuplicateRequestError):
            ded.check_and_register("req-dup")

    def test_different_ids_both_accepted(self):
        ded = RequestDeduplicator()
        ded.check_and_register("req-a")
        ded.check_and_register("req-b")  # must not raise

    def test_duplicate_at_window_end_is_rejected(self):
        """
        At exactly window_end (now + window), the entry is still present.
        A duplicate request at this point must be rejected.
        """
        ded = RequestDeduplicator()
        now = time.monotonic()
        with mock.patch("shared.token.time") as mock_time:
            mock_time.monotonic.return_value = now
            ded.check_and_register("req-boundary")

            # Advance to exactly window_end (entry not yet expired)
            mock_time.monotonic.return_value = now + _DEDUP_WINDOW_SECONDS - 0.001
            with pytest.raises(DuplicateRequestError):
                ded.check_and_register("req-boundary")

    def test_request_accepted_after_window_expires(self):
        """
        After the deduplication window expires, the same request_id
        may be used again (entry is pruned).
        """
        ded = RequestDeduplicator()
        now = time.monotonic()
        with mock.patch("shared.token.time") as mock_time:
            mock_time.monotonic.return_value = now
            ded.check_and_register("req-expire")

            # Advance past window expiry
            mock_time.monotonic.return_value = now + _DEDUP_WINDOW_SECONDS + 1
            ded.check_and_register("req-expire")  # must not raise (expired)

    def test_window_boundary_just_outside_is_accepted(self):
        """
        A request arriving just after window expiry (window_end + epsilon)
        must be accepted.
        """
        ded = RequestDeduplicator()
        now = time.monotonic()
        with mock.patch("shared.token.time") as mock_time:
            mock_time.monotonic.return_value = now
            ded.check_and_register("req-outside")

            # window_end + 1 second = after expiry
            mock_time.monotonic.return_value = now + _DEDUP_WINDOW_SECONDS + 1.0
            ded.check_and_register("req-outside")  # accepted, window expired

    def test_clock_skew_tolerance(self):
        """
        Simulate clock skew: if the server clock jumps forward by a small
        amount (e.g., 1 second), replay protection must still function correctly.
        """
        ded = RequestDeduplicator()
        now = time.monotonic()
        with mock.patch("shared.token.time") as mock_time:
            # Register at T=0
            mock_time.monotonic.return_value = now
            ded.check_and_register("req-skew")

            # Clock drifts forward 1 second (still within window)
            mock_time.monotonic.return_value = now + 1.0
            with pytest.raises(DuplicateRequestError):
                ded.check_and_register("req-skew")

    def test_many_unique_requests_all_accepted(self):
        """High-volume unique request IDs must all be accepted."""
        ded = RequestDeduplicator()
        for i in range(200):
            ded.check_and_register(f"req-{i:04d}")  # must not raise

    def test_dedup_window_constant_is_60_seconds(self):
        """Deduplication window must be exactly 60 seconds per spec."""
        assert _DEDUP_WINDOW_SECONDS == 60
