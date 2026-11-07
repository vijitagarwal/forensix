"""Session-local evidence registration and append-only custody event chaining."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, MutableMapping
from uuid import uuid4


EVIDENCE_REGISTER_KEY = "evidence_register"
CUSTODY_EVENTS_KEY = "custody_events"
EVENT_TYPES = {
    "evidence_acquired",
    "evidence_analysed",
    "integrity_verified",
    "integrity_mismatch_detected",
}


def utc_timestamp() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _event_hash(event: dict[str, Any]) -> str:
    """Hash canonical event data, excluding the derived current hash."""
    payload = {key: value for key, value in event.items() if key != "current_event_hash"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def initialise_custody_state(state: MutableMapping[str, Any]) -> None:
    """Create the session-local register and event log if absent."""
    state.setdefault(EVIDENCE_REGISTER_KEY, [])
    state.setdefault(CUSTODY_EVENTS_KEY, [])


def register_evidence(
    register: list[dict[str, Any]],
    events: list[dict[str, Any]],
    *,
    original_filename: str,
    acquisition_hash: str,
    file_size: int,
    investigator: str,
    acquisition_notes: str = "",
    acquired_at: str | None = None,
) -> dict[str, Any]:
    """Register newly acquired evidence and append its acquisition event."""
    if not investigator.strip():
        raise ValueError("An investigator name or identifier is required")
    if len(acquisition_hash) != 64:
        raise ValueError("The acquisition hash must be a SHA-256 hexadecimal digest")
    evidence = {
        "evidence_id": f"FX-{uuid4().hex[:12].upper()}",
        "original_filename": original_filename,
        "acquisition_timestamp": acquired_at or utc_timestamp(),
        "acquisition_hash": acquisition_hash.lower(),
        "file_size": file_size,
        "investigator": investigator.strip(),
        "acquisition_notes": acquisition_notes.strip(),
        "current_integrity_status": "Not verified",
    }
    register.append(evidence)
    append_event(
        events,
        evidence_id=evidence["evidence_id"],
        event_type="evidence_acquired",
        event_description=f"Evidence acquired: {original_filename}",
        event_timestamp=evidence["acquisition_timestamp"],
        current_hash=evidence["acquisition_hash"],
    )
    return evidence


def append_event(
    events: list[dict[str, Any]],
    *,
    evidence_id: str,
    event_type: str,
    event_description: str,
    event_timestamp: str | None = None,
    current_hash: str | None = None,
) -> dict[str, Any]:
    """Append one event whose hash incorporates the preceding event hash."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unsupported custody event type: {event_type}")
    previous_hash = events[-1]["current_event_hash"] if events else None
    event = {
        "event_id": f"EV-{uuid4().hex[:12].upper()}",
        "evidence_id": evidence_id,
        "event_type": event_type,
        "utc_timestamp": event_timestamp or utc_timestamp(),
        "event_description": event_description,
        "previous_event_hash": previous_hash,
        "event_data_hash": current_hash,
    }
    event["current_event_hash"] = _event_hash(event)
    events.append(event)
    return event


def verify_event_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Verify event hashes and references without mutating the supplied log."""
    previous_hash: str | None = None
    for index, event in enumerate(events):
        if event.get("previous_event_hash") != previous_hash:
            return {
                "valid": False,
                "broken_at": index,
                "reason": "Previous event hash reference is invalid",
            }
        expected_hash = _event_hash(event)
        if event.get("current_event_hash") != expected_hash:
            return {
                "valid": False,
                "broken_at": index,
                "reason": "Current event hash does not match event data",
            }
        previous_hash = event["current_event_hash"]
    return {"valid": True, "broken_at": None, "reason": "Event chain is valid"}


def snapshot_custody_data(
    register: list[dict[str, Any]], events: list[dict[str, Any]]
) -> dict[str, Any]:
    """Return a JSON-safe copy for display or download."""
    return {
        "session_local_notice": (
            "This in-memory register is session-local. It can be lost when the "
            "session ends or altered outside the application's controls."
        ),
        "evidence_register": deepcopy(register),
        "event_log": deepcopy(events),
        "chain_verification": verify_event_chain(events),
    }
