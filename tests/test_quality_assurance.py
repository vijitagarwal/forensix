"""End-to-end quality checks using generated, non-sensitive evidence samples."""

import hashlib

from PIL import Image
from pypdf import PdfWriter

from forensic_engine import analyze_file
from report_generator import generate_report
from utils.chain_of_custody import register_evidence, verify_event_chain
from utils.hashing import calculate_hash


def _write_pdf(path):
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    with path.open("wb") as stream:
        writer.write(stream)


def test_valid_pdf_png_jpeg_and_plain_text(tmp_path):
    pdf = tmp_path / "sample.pdf"
    png = tmp_path / "sample.png"
    jpeg = tmp_path / "sample.jpg"
    text = tmp_path / "sample.txt"
    _write_pdf(pdf)
    Image.new("RGB", (4, 4), "navy").save(png)
    Image.new("RGB", (4, 4), "gold").save(jpeg, format="JPEG")
    text.write_text("forensix sample", encoding="utf-8")

    assert analyze_file(pdf)["detected_file_type"] == "PDF"
    assert analyze_file(png)["detected_file_type"] == "PNG"
    assert analyze_file(jpeg)["detected_file_type"] == "JPEG"
    assert analyze_file(text)["detected_file_type"] == "Unknown"


def test_unsupported_and_malformed_files_are_reported_without_crashing(tmp_path):
    unsupported = tmp_path / "sample.xyz"
    malformed_pdf = tmp_path / "broken.pdf"
    unsupported.write_bytes(b"unsupported format")
    malformed_pdf.write_bytes(b"%PDF-not-valid")

    unsupported_result = analyze_file(unsupported)
    malformed_result = analyze_file(malformed_pdf)
    assert unsupported_result["detected_file_type"] == "Unknown"
    assert malformed_result["detected_file_type"] == "PDF"
    assert malformed_result["extracted_metadata"]["pdf"]["status"] == "unavailable"


def test_incorrect_extension_is_flagged_without_malicious_conclusion(tmp_path):
    evidence = tmp_path / "image.txt"
    Image.new("RGB", (2, 2), "white").save(evidence, format="PNG")
    result = analyze_file(evidence)
    assert result["detected_file_type"] == "PNG"
    assert result["extension_mismatch"] is True
    assert any("not proof" in warning for warning in result["analysis_warnings"])


def test_same_filename_records_are_distinct_and_original_is_unchanged(tmp_path):
    first = tmp_path / "one" / "same.bin"
    second = tmp_path / "two" / "same.bin"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(b"first evidence")
    second.write_bytes(b"second evidence")
    first_before = first.read_bytes()
    second_before = second.read_bytes()

    first_result = analyze_file(first)
    second_result = analyze_file(second)
    register, events = [], []
    first_record = register_evidence(
        register,
        events,
        original_filename=first.name,
        acquisition_hash=first_result["sha256_hash"],
        file_size=first_result["file_size"],
        investigator="qa",
    )
    second_record = register_evidence(
        register,
        events,
        original_filename=second.name,
        acquisition_hash=second_result["sha256_hash"],
        file_size=second_result["file_size"],
        investigator="qa",
    )

    assert first_record["evidence_id"] != second_record["evidence_id"]
    assert first_result["sha256_hash"] != second_result["sha256_hash"]
    assert first.read_bytes() == first_before
    assert second.read_bytes() == second_before


def test_modified_evidence_and_matching_or_mismatching_hashes(tmp_path):
    evidence = tmp_path / "sample.bin"
    evidence.write_bytes(b"original")
    acquisition_hash = calculate_hash(evidence)
    register, events = [], []
    record = register_evidence(
        register,
        events,
        original_filename=evidence.name,
        acquisition_hash=acquisition_hash,
        file_size=evidence.stat().st_size,
        investigator="qa",
    )
    assert calculate_hash(evidence) == acquisition_hash
    assert calculate_hash(evidence) == hashlib.sha256(b"original").hexdigest()

    evidence.write_bytes(b"modified")
    current_hash = calculate_hash(evidence)
    assert current_hash != acquisition_hash
    assert current_hash == hashlib.sha256(b"modified").hexdigest()
    assert record["acquisition_hash"] == acquisition_hash
    assert verify_event_chain(events)["valid"] is True


def test_html_report_escapes_untrusted_data():
    report = generate_report(
        [
            {
                "evidence_id": "FX-TEST",
                "original_filename": "<script>alert(1)</script>.txt",
                "file_size": 4,
                "sha256_hash": "a" * 64,
                "detected_file_type": "Unknown",
                "declared_extension": ".txt",
                "extension_mismatch": False,
                "analysis_timestamp": "2026-01-01T00:00:00+00:00",
                "extracted_metadata": {"note": "<unsafe>"},
                "analysis_warnings": [],
            }
        ]
    ).decode("utf-8")
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "Automated findings" in report
