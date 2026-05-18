from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


@pytest.fixture
def tmp_path():
    scratch_root = Path.cwd() / ".test-scratch"
    scratch_root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=scratch_root) as raw_path:
        yield Path(raw_path)
