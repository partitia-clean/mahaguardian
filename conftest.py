"""
Root conftest.py — ensures the project root is on sys.path so that
`import guardian.*` and `import shared.*` work from the tests directory.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


def pytest_configure(config):
    """Register custom markers to suppress PytestUnknownMarkWarning."""
    config.addinivalue_line(
        "markers",
        "timing: marks tests as timing-sensitive (may be flaky in slow CI environments)",
    )
