"""Tests for magic-byte signature detection."""

from utils.file_signature import analyze_signature, identify_file_type


def test_detects_png_without_trusting_extension(tmp_path):
    evidence = tmp_path / "photo.bin"
    evidence.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    assert identify_file_type(evidence) == "PNG"
    assert analyze_signature(evidence)["extension_mismatch"] is True


def test_detects_supported_signatures(tmp_path):
    signatures = {
        "sample.pdf": (b"%PDF-1.7", "PDF"),
        "sample.exe": (b"MZ\x90\x00", "Windows Executable"),
        "sample.mp4": (b"\x00\x00\x00\x18ftypisom", "MP4"),
    }
    for filename, (header, expected) in signatures.items():
        evidence = tmp_path / filename
        evidence.write_bytes(header)
        assert identify_file_type(evidence) == expected


def test_unknown_file_is_not_inferred_from_extension(tmp_path):
    evidence = tmp_path / "notes.pdf"
    evidence.write_bytes(b"plain text")
    result = analyze_signature(evidence)
    assert result["detected_file_type"] == "Unknown"
    assert result["extension_mismatch"] is True
