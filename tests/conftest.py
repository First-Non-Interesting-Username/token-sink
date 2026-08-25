"""Make top-level packages importable from tests.

The repo uses top-level packages (no src/ layout) and is not installed as a
distribution, so pytest needs the repo root on sys.path to import
``orchestrator``, ``providers``, etc.
"""

import sys
from pathlib import Path

ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
