"""Magic-byte file type detection and extension comparison utilities."""

from pathlib import Path


SIGNATURES = (
    (b"%PDF-", "PDF", {".pdf"}),
    (b"\x89PNG\r\n\x1a\n", "PNG", {".png"}),
    (b"\xff\xd8\xff", "JPEG", {".jpg", ".jpeg", ".jpe"}),
    (b"GIF87a", "GIF", {".gif"}),
    (b"GIF89a", "GIF", {".gif"}),
    (b"PK\x03\x04", "ZIP", {".zip", ".docx", ".xlsx", ".pptx", ".jar"}),
    (b"Rar!\x1a\x07\x00", "RAR", {".rar"}),
    (b"Rar!\x1a\x07\x01\x00", "RAR", {".rar"}),
    (b"ID3", "MP3", {".mp3"}),
    (b"RIFF", "WAV", {".wav"}),
    (b"MZ", "Windows Executable", {".exe", ".dll", ".sys", ".scr", ".com"}),
)
TEXT_SCAN_LIMIT = 1024 * 1024
TEXT_CONTROL_WHITELIST = {9, 10, 12, 13}


def _looks_like_plain_text(file_path: str | Path) -> bool:
    """Conservatively identify small, decodable text content.

    The scan is deliberately bounded so an unknown large binary file is not
    loaded into memory merely because its name suggests a text format.
    """
    path = Path(file_path)
    try:
        with path.open("rb") as evidence_file:
            content = evidence_file.read(TEXT_SCAN_LIMIT + 1)
    except OSError as exc:
        raise OSError(f"Unable to read evidence file '{path}': {exc}") from exc

    if len(content) > TEXT_SCAN_LIMIT or b"\x00" in content:
        return False
    try:
        decoded = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    controls = sum(
        1
        for character in decoded
        if ord(character) < 32 and ord(character) not in TEXT_CONTROL_WHITELIST
        or ord(character) == 127
    )
    return not decoded or controls / max(len(decoded), 1) <= 0.01


def _read_signature(file_path: str | Path) -> bytes:
    """Read enough leading bytes for supported signatures."""
    path = Path(file_path)
    try:
        with path.open("rb") as evidence_file:
            return evidence_file.read(64)
    except OSError as exc:
        raise OSError(f"Unable to read evidence file '{path}': {exc}") from exc


def identify_file_type(file_path: str | Path) -> str:
    """Identify a file type from its magic bytes, not its extension."""
    header = _read_signature(file_path)
    for signature, file_type, _ in SIGNATURES:
        if header.startswith(signature):
            return file_type
    if len(header) >= 12 and header[0:4] == b"RIFF" and header[8:12] == b"WAVE":
        return "WAV"
    if len(header) >= 12 and header[4:8] == b"ftyp":
        return "MP4"
    if len(header) >= 2 and header[0] == 0xFF and header[1] & 0xE0 == 0xE0:
        return "MP3"
    if _looks_like_plain_text(file_path):
        return "Plain Text"
    return "Unknown"


def compare_extension(file_path: str | Path, detected_type: str | None = None) -> dict[str, object]:
    """Compare the declared suffix with the detected magic-byte type."""
    path = Path(file_path)
    detected = detected_type or identify_file_type(path)
    declared_extension = path.suffix.lower()
    expected_extensions = next(
        (extensions for _, file_type, extensions in SIGNATURES if file_type == detected),
        set(),
    )
    if detected == "MP4":
        expected_extensions = {".mp4", ".m4v", ".mov"}
    if detected == "Plain Text":
        expected_extensions = {".txt", ".text", ".log", ".md", ".csv"}
    extension_mismatch = bool(declared_extension) and (
        not expected_extensions or declared_extension not in expected_extensions
    )
    return {
        "declared_extension": declared_extension,
        "extension_mismatch": extension_mismatch,
    }


def analyze_signature(file_path: str | Path) -> dict[str, object]:
    """Return detected type and non-conclusive extension comparison details."""
    detected_type = identify_file_type(file_path)
    return {
        "detected_file_type": detected_type,
        **compare_extension(file_path, detected_type),
    }
