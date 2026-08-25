"""Pytest configuration shared by all test categories.

Puts the repo root on sys.path so tests can import the top-level packages
(``observability``, ``storage``, ...) without installing the project — the
pyproject has no build backend and CI runs plain ``uv run pytest``.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
