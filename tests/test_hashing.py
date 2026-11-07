"""Tests for evidence hashing."""

import hashlib

import pytest

from utils.hashing import calculate_hash


def test_calculate_hash_reads_file_contents(tmp_path):
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"ForensiX evidence")
    assert calculate_hash(evidence) == hashlib.sha256(b"ForensiX evidence").hexdigest()


def test_calculate_hash_reports_missing_file(tmp_path):
    with pytest.raises(OSError, match="Unable to read evidence file"):
        calculate_hash(tmp_path / "missing.bin")
