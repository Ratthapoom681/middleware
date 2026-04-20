"""
Pytest shared fixtures.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from uuid import uuid4

import pytest


@pytest.fixture
def workspace_tmp_dir() -> Path:
    """Create a temporary directory inside the writable workspace."""
    base_dir = Path(__file__).resolve().parent.parent / "test-runtime"
    base_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = base_dir / f"case-{uuid4().hex}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    try:
        yield tmp_dir
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
