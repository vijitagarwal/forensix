"""Tests for metadata extraction."""

from PIL import Image

from utils.metadata import extract_metadata


def test_extracts_filesystem_metadata(tmp_path):
    evidence = tmp_path / "notes.txt"
    evidence.write_text("hello", encoding="utf-8")
    result = extract_metadata(evidence)
    assert result["filename"] == "notes.txt"
    assert result["file_size"] == 5
    assert result["extension"] == ".txt"
    assert result["pdf"]["status"] == "unavailable"


def test_extracts_image_metadata_and_handles_missing_exif(tmp_path):
    evidence = tmp_path / "image.png"
    Image.new("RGB", (2, 2), "red").save(evidence)
    result = extract_metadata(evidence)
    assert result["exif"]["status"] == "missing"


def test_malformed_pdf_is_unavailable_not_fatal(tmp_path):
    evidence = tmp_path / "broken.pdf"
    evidence.write_bytes(b"not a real PDF")
    result = extract_metadata(evidence)
    assert result["pdf"]["status"] == "unavailable"
