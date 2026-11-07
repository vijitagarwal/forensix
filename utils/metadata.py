"""Filesystem, image, and PDF metadata extraction utilities."""

from datetime import datetime
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError


def _time_or_unavailable(timestamp: float | None) -> str | None:
    """Convert a filesystem timestamp to ISO format when it exists."""
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp).isoformat()


def _image_metadata(path: Path) -> dict[str, object]:
    """Extract EXIF data while distinguishing missing and unavailable data."""
    try:
        with Image.open(path) as image:
            exif = image.getexif()
            if not exif:
                return {"status": "missing", "values": {}}
            values = {str(key): str(value) for key, value in exif.items()}
            return {"status": "extracted", "values": values}
    except (OSError, UnidentifiedImageError) as exc:
        return {"status": "unavailable", "reason": str(exc), "values": {}}


def _pdf_metadata(path: Path) -> dict[str, object]:
    """Extract PDF document metadata without treating parse errors as evidence."""
    try:
        reader = PdfReader(str(path), strict=False)
        metadata = reader.metadata
        if not metadata:
            return {"status": "missing", "values": {}}
        values = {
            str(key).lstrip("/"): str(value)
            for key, value in metadata.items()
            if value is not None
        }
        return {"status": "extracted" if values else "missing", "values": values}
    except (OSError, PdfReadError, ValueError) as exc:
        return {"status": "unavailable", "reason": str(exc), "values": {}}


def extract_metadata(file_path: str | Path) -> dict[str, object]:
    """Extract available metadata and report unavailable fields explicitly."""
    path = Path(file_path)
    try:
        stat = path.stat()
    except OSError as exc:
        raise OSError(f"Unable to inspect evidence file '{path}': {exc}") from exc

    extension = path.suffix.lower()
    metadata: dict[str, Any] = {
        "filename": path.name,
        "file_size": stat.st_size,
        "extension": extension,
        "creation_time": _time_or_unavailable(getattr(stat, "st_ctime", None)),
        "modification_time": _time_or_unavailable(getattr(stat, "st_mtime", None)),
        "exif": {"status": "not_applicable", "reason": "Not an image file", "values": {}},
        "pdf": {
            "status": "not_applicable",
            "reason": "Not a PDF file",
            "values": {},
        },
    }
    if extension in {".jpg", ".jpeg", ".jpe", ".png", ".gif"}:
        metadata["exif"] = _image_metadata(path)
    if extension == ".pdf":
        metadata["pdf"] = _pdf_metadata(path)
    return metadata
