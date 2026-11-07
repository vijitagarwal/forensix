"""Tests for session-local chain-of-custody records."""

from utils.chain_of_custody import (
    append_event,
    register_evidence,
    verify_event_chain,
)


def test_registration_creates_evidence_and_acquisition_event():
    register, events = [], []
    evidence = register_evidence(
        register,
        events,
        original_filename="sample.bin",
        acquisition_hash="a" * 64,
        file_size=12,
        investigator="analyst-01",
        acquisition_notes="Received from lab intake.",
        acquired_at="2026-01-01T00:00:00+00:00",
    )
    assert evidence["evidence_id"].startswith("FX-")
    assert evidence["acquisition_timestamp"].endswith("+00:00")
    assert events[0]["event_type"] == "evidence_acquired"
    assert verify_event_chain(events)["valid"] is True


def test_event_creation_chains_to_previous_event():
    events = []
    append_event(
        events,
        evidence_id="FX-ONE",
        event_type="evidence_acquired",
        event_description="Acquired",
        event_timestamp="2026-01-01T00:00:00+00:00",
    )
    second = append_event(
        events,
        evidence_id="FX-ONE",
        event_type="evidence_analysed",
        event_description="Analysed",
        event_timestamp="2026-01-01T00:01:00+00:00",
    )
    assert second["previous_event_hash"] == events[0]["current_event_hash"]
    assert verify_event_chain(events)["valid"] is True


def test_chain_detects_modified_event_data():
    events = []
    append_event(
        events,
        evidence_id="FX-ONE",
        event_type="evidence_acquired",
        event_description="Acquired",
    )
    events[0]["event_description"] = "Modified"
    result = verify_event_chain(events)
    assert result["valid"] is False
    assert "current event hash" in result["reason"].lower()


def test_chain_detects_broken_previous_reference():
    events = []
    append_event(
        events,
        evidence_id="FX-ONE",
        event_type="evidence_acquired",
        event_description="Acquired",
    )
    append_event(
        events,
        evidence_id="FX-ONE",
        event_type="evidence_analysed",
        event_description="Analysed",
    )
    events[1]["previous_event_hash"] = "broken"
    result = verify_event_chain(events)
    assert result["valid"] is False
    assert "previous event hash" in result["reason"].lower()


def test_multiple_evidence_records_have_independent_ids():
    register, events = [], []
    first = register_evidence(
        register,
        events,
        original_filename="one.bin",
        acquisition_hash="1" * 64,
        file_size=1,
        investigator="analyst",
    )
    second = register_evidence(
        register,
        events,
        original_filename="two.bin",
        acquisition_hash="2" * 64,
        file_size=2,
        investigator="analyst",
    )
    assert first["evidence_id"] != second["evidence_id"]
    assert len(register) == 2
    assert len(events) == 2
    assert verify_event_chain(events)["valid"] is True
