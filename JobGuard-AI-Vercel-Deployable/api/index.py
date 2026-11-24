"""Vercel Serverless Function entrypoint for the JobGuard AI FastAPI backend."""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from backend.main import app  # noqa: E402, F401
