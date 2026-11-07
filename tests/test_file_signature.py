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
    evidence.write_bytes(b"\x01\x02\x03\xff\xfe\x00")
    result = analyze_signature(evidence)
    assert result["detected_file_type"] == "Unknown"
    assert result["extension_mismatch"] is True


def test_detects_utf8_plain_text_without_extension_mismatch(tmp_path):
    evidence = tmp_path / "notes.txt"
    evidence.write_text("A simple forensic note.\n", encoding="utf-8")
    result = analyze_signature(evidence)
    assert result["detected_file_type"] == "Plain Text"
    assert result["extension_mismatch"] is False


def test_detects_empty_text_file(tmp_path):
    evidence = tmp_path / "empty.txt"
    evidence.write_bytes(b"")
    result = analyze_signature(evidence)
    assert result["detected_file_type"] == "Plain Text"
    assert result["extension_mismatch"] is False


def test_detects_unicode_text_file(tmp_path):
    evidence = tmp_path / "unicode.txt"
    evidence.write_text("Evidence note: café — नमस्ते\n", encoding="utf-8")
    assert identify_file_type(evidence) == "Plain Text"


def test_rejects_binary_content_named_txt(tmp_path):
    evidence = tmp_path / "binary.txt"
    evidence.write_bytes(b"\x00\x01\x02\xff\x80binary")
    result = analyze_signature(evidence)
    assert result["detected_file_type"] == "Unknown"
    assert result["extension_mismatch"] is True


def test_known_binary_signatures_remain_authoritative(tmp_path):
    png = tmp_path / "image.png"
    pdf = tmp_path / "document.pdf"
    png.write_bytes(b"\x89PNG\r\n\x1a\nnot-an-image")
    pdf.write_bytes(b"%PDF-1.7\nnot-a-complete-pdf")
    assert identify_file_type(png) == "PNG"
    assert identify_file_type(pdf) == "PDF"
