"""Central orchestration for safe, read-only evidence analysis."""

from pathlib import Path
from typing import Iterable

from utils.file_signature import analyze_signature
from utils.hashing import calculate_hash
from utils.metadata import extract_metadata


def analyze_file(evidence_path: str | Path) -> dict[str, object]:
    """Analyze one file without modifying or executing it."""
    path = Path(evidence_path)
    warnings: list[str] = []
    try:
        metadata = extract_metadata(path)
    except OSError as exc:
        return {
            "original_filename": path.name,
            "file_size": None,
            "sha256_hash": None,
            "detected_file_type": "Unavailable",
            "declared_extension": path.suffix.lower(),
            "extension_mismatch": None,
            "extracted_metadata": {},
            "analysis_warnings": [str(exc)],
        }

    try:
        file_hash = calculate_hash(path)
    except (OSError, ValueError) as exc:
        file_hash = None
        warnings.append(str(exc))

    try:
        signature = analyze_signature(path)
    except OSError as exc:
        signature = {
            "detected_file_type": "Unavailable",
            "declared_extension": path.suffix.lower(),
            "extension_mismatch": None,
        }
        warnings.append(str(exc))

    if signature["extension_mismatch"]:
        warnings.append(
            "The detected type differs from the declared extension; this is "
            "not proof of malicious tampering."
        )
    exif_metadata = metadata.get("exif")
    if isinstance(exif_metadata, dict) and exif_metadata.get("status") == "unavailable":
        warnings.append("Image metadata is unavailable for this file.")
    pdf_metadata = metadata.get("pdf")
    if isinstance(pdf_metadata, dict) and pdf_metadata.get("status") == "unavailable":
        warnings.append("PDF metadata is unavailable for this file.")

    return {
        "original_filename": metadata["filename"],
        "file_size": metadata["file_size"],
        "sha256_hash": file_hash,
        "detected_file_type": signature["detected_file_type"],
        "declared_extension": signature["declared_extension"],
        "extension_mismatch": signature["extension_mismatch"],
        "extracted_metadata": metadata,
        "analysis_warnings": warnings,
    }


def analyze_files(evidence_paths: Iterable[str | Path]) -> list[dict[str, object]]:
    """Analyze multiple evidence files independently."""
    return [analyze_file(path) for path in evidence_paths]


class ForensicEngine:
    """Facade for applications that prefer an object-oriented API."""

    def analyze(self, evidence_path: str | Path) -> dict[str, object]:
        """Analyze one evidence file."""
        return analyze_file(evidence_path)

    def analyze_multiple(
        self, evidence_paths: Iterable[str | Path]
    ) -> list[dict[str, object]]:
        """Analyze multiple evidence files."""
        return analyze_files(evidence_paths)
