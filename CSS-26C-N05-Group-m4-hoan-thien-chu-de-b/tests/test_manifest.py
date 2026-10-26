"""MANIFEST.txt phai khop sha256 cua tep trong evidence/ (chay sau make export-evidence)."""
import hashlib
from pathlib import Path

import pytest

EV = Path(__file__).resolve().parents[1] / "evidence"
MF = EV / "MANIFEST.txt"


@pytest.mark.skipif(not MF.exists(), reason="chua chay make export-evidence")
def test_manifest_khop_sha256():
    for line in MF.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((EV / name).read_bytes()).hexdigest() == digest, name
