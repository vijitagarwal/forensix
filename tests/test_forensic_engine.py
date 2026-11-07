"""Tests for the central forensic engine."""

from forensic_engine import ForensicEngine, analyze_file, analyze_files


def test_analyze_file_returns_structured_result(tmp_path):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("forensic sample", encoding="utf-8")
    result = analyze_file(evidence)
    assert result["original_filename"] == "evidence.txt"
    assert result["file_size"] == len(b"forensic sample")
    assert len(result["sha256_hash"]) == 64
    assert result["detected_file_type"] == "Unknown"
    assert result["extension_mismatch"] is True
    assert any("not proof" in warning for warning in result["analysis_warnings"])


def test_engine_supports_multiple_files_and_missing_files(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    results = analyze_files([first, second, tmp_path / "missing.bin"])
    assert len(results) == 3
    assert results[0]["sha256_hash"] != results[1]["sha256_hash"]
    assert results[2]["sha256_hash"] is None
    assert results[2]["analysis_warnings"]


def test_class_facade_uses_same_read_only_analysis(tmp_path):
    evidence = tmp_path / "sample.pdf"
    evidence.write_bytes(b"%PDF-1.7")
    result = ForensicEngine().analyze(evidence)
    assert result["detected_file_type"] == "PDF"
