"""Hashing utilities for digital evidence integrity checks."""

import hashlib
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


def calculate_hash(file_path: str | Path, algorithm: str = "sha256") -> str:
    """Return a hexadecimal hash digest, reading the file in chunks.

    File access errors are re-raised with the evidence path included so the
    caller can report the problem without silently producing a false result.
    """
    path = Path(file_path)
    if algorithm.lower() != "sha256":
        raise ValueError("ForensiX currently supports SHA-256 hashing only")

    try:
        digest = hashlib.sha256()
        with path.open("rb") as evidence_file:
            for chunk in iter(lambda: evidence_file.read(CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise OSError(f"Unable to read evidence file '{path}': {exc}") from exc
    return digest.hexdigest()
