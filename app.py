"""Streamlit frontend for the ForensiX digital evidence analyzer."""

import json
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st

from forensic_engine import analyze_file
from report_generator import DISCLAIMER, generate_report
from utils.chain_of_custody import (
    append_event,
    initialise_custody_state,
    register_evidence,
    snapshot_custody_data,
    verify_event_chain,
)
from utils.hashing import calculate_hash


APP_TITLE = "ForensiX"
SUPPORTED_TYPES = [
    "pdf", "doc", "docx", "txt", "csv", "png", "jpg", "jpeg", "gif",
    "mp3", "wav", "mp4", "mov", "zip", "rar", "exe", "dll", "bin",
]


def configure_page() -> None:
    """Configure page metadata and the dashboard's visual language."""
    st.set_page_config(
        page_title="ForensiX | Digital Evidence Analyzer",
        page_icon="🔎",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');
        :root { --fx-cyan:#67e8f9; --fx-blue:#60a5fa; --fx-muted:#94a3b8; }
        .stApp { background: radial-gradient(circle at 85% 0%, #172554 0, #0b1120 38%, #070b14 100%); }
        html, body, [class*="css"] { font-family: 'Space Grotesk', sans-serif; }
        h1, h2, h3 { letter-spacing: -0.02em; }
        code, .mono { font-family: 'IBM Plex Mono', monospace; }
        [data-testid="stMetric"] { background: rgba(15, 23, 42, .78); border: 1px solid #1e3a5f; border-radius: 12px; padding: 14px; }
        [data-testid="stMetricLabel"] { color: #94a3b8; }
        [data-testid="stMetricValue"] { color: #67e8f9; }
        .fx-kicker { color:#67e8f9; font-family:'IBM Plex Mono'; font-size:.78rem; letter-spacing:.14em; text-transform:uppercase; }
        .fx-card { background:rgba(15,23,42,.72); border:1px solid #1e3a5f; border-radius:12px; padding:18px; margin:8px 0 16px; }
        .fx-warning { border-left:4px solid #f59e0b; background:#451a03; color:#fde68a; border-radius:6px; padding:10px 14px; margin:8px 0; }
        .fx-danger { border-left:4px solid #fb7185; background:#4c0519; color:#fecdd3; border-radius:6px; padding:10px 14px; margin:8px 0; }
        .fx-success { border-left:4px solid #34d399; background:#052e24; color:#a7f3d0; border-radius:6px; padding:10px 14px; margin:8px 0; }
        section[data-testid="stSidebar"] { background: #080f1d; border-right: 1px solid #1e3a5f; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def initialise_state() -> None:
    """Create stable session state containers for this browser session."""
    if "analysis_records" not in st.session_state:
        st.session_state.analysis_records = []
    initialise_custody_state(st.session_state)


def format_bytes(size: object) -> str:
    """Format a byte count without inventing a value for unavailable data."""
    if not isinstance(size, (int, float)):
        return "Unavailable"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return "Unavailable"


def analyse_uploaded_file(uploaded_file: Any, investigator: str, notes: str) -> dict[str, object]:
    """Analyse a Streamlit upload through a temporary, read-only copy."""
    suffix = Path(uploaded_file.name).suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temporary:
        temporary.write(uploaded_file.getvalue())
        temporary_path = Path(temporary.name)
    try:
        acquisition_hash = calculate_hash(temporary_path)
        evidence = register_evidence(
            st.session_state.evidence_register,
            st.session_state.custody_events,
            original_filename=uploaded_file.name,
            acquisition_hash=acquisition_hash,
            file_size=temporary_path.stat().st_size,
            investigator=investigator,
            acquisition_notes=notes,
        )
        result = analyze_file(temporary_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    result["original_filename"] = uploaded_file.name
    result["analysis_timestamp"] = datetime.now(timezone.utc).isoformat()
    result["evidence_id"] = evidence["evidence_id"]
    append_event(
        st.session_state.custody_events,
        evidence_id=evidence["evidence_id"],
        event_type="evidence_analysed",
        event_description=f"Evidence analysed: {uploaded_file.name}",
        current_hash=result.get("sha256_hash"),
    )
    for registered in st.session_state.evidence_register:
        if registered["evidence_id"] == evidence["evidence_id"]:
            registered["current_integrity_status"] = "Analysed; not verified"
            break
    return result


def render_header(section: str, description: str) -> None:
    """Render a consistent investigation-section header."""
    st.markdown('<div class="fx-kicker">FORENSIC INVESTIGATION PLATFORM / ONLINE</div>', unsafe_allow_html=True)
    st.title(section)
    st.caption(description)


def render_dashboard() -> None:
    """Render session-derived overview metrics and recent records."""
    records = st.session_state.analysis_records
    render_header("Investigation dashboard", "Evidence activity and file-signature telemetry for this session.")
    total_size = sum(
        record["file_size"] for record in records if isinstance(record.get("file_size"), int)
    )
    unique_hashes = {
        record["sha256_hash"] for record in records if record.get("sha256_hash")
    }
    mismatches = sum(1 for record in records if record.get("extension_mismatch") is True)
    metrics = st.columns(4)
    metrics[0].metric("Evidence analysed", len(records))
    metrics[1].metric("Total evidence size", format_bytes(total_size))
    metrics[2].metric("Unique SHA-256", len(unique_hashes))
    metrics[3].metric("Extension mismatches", mismatches)
    if not records:
        st.info("No evidence has been analysed yet. Open Evidence Analyzer to begin.")
        return

    left, right = st.columns([1.3, 1])
    with left:
        st.subheader("Recent evidence analysis")
        rows = [
            {
                "Evidence": record.get("evidence_id", "—"),
                "Filename": record.get("original_filename", "—"),
                "Signature": record.get("detected_file_type", "—"),
                "Size": format_bytes(record.get("file_size")),
                "Mismatch": "YES" if record.get("extension_mismatch") else "NO",
            }
            for record in records[-10:][::-1]
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)
    with right:
        st.subheader("File-type distribution")
        distribution = Counter(record.get("detected_file_type", "Unknown") for record in records)
        st.bar_chart(distribution)


def render_record(record: dict[str, object], index: int) -> None:
    """Render one structured analysis record."""
    filename = record.get("original_filename", "Unknown evidence")
    with st.expander(f"{record.get('evidence_id', f'FX-{index:04d}')}  |  {filename}", expanded=index == 1):
        columns = st.columns(4)
        columns[0].metric("SHA-256", str(record.get("sha256_hash") or "Unavailable")[:16] + "…")
        columns[1].metric("Detected type", str(record.get("detected_file_type", "Unavailable")))
        columns[2].metric("File size", format_bytes(record.get("file_size")))
        columns[3].metric("Declared extension", str(record.get("declared_extension") or "None"))
        if record.get("extension_mismatch"):
            st.markdown(
                '<div class="fx-warning"><strong>Extension mismatch:</strong> '
                "The signature differs from the declared extension. This is not proof "
                "of malicious tampering.</div>",
                unsafe_allow_html=True,
            )
        warnings = record.get("analysis_warnings", [])
        if warnings:
            for warning in warnings:
                st.warning(str(warning))
        st.json(record.get("extracted_metadata", {}))


def render_analyzer() -> None:
    """Render multi-file evidence upload and analysis controls."""
    render_header("Evidence analyzer", "Inspect evidence safely without executing or modifying uploaded files.")
    uploads = st.file_uploader(
        "Upload evidence files",
        type=SUPPORTED_TYPES,
        accept_multiple_files=True,
        help="Files are copied to temporary paths for read-only analysis and removed immediately afterward.",
    )
    investigator = st.text_input(
        "Investigator name or identifier",
        key="acquisition_investigator",
        placeholder="e.g. analyst-001",
    )
    notes = st.text_area(
        "Acquisition notes (optional)",
        key="acquisition_notes",
        placeholder="Record the acquisition context or source notes.",
    )
    if not uploads:
        st.info("Select one or more evidence files to begin analysis.")
        return
    if st.button("Analyse selected evidence", type="primary", use_container_width=True):
        if not investigator.strip():
            st.error("Enter an investigator name or identifier before acquiring evidence.")
            return
        progress = st.progress(0, text="Preparing evidence analysis…")
        new_records: list[dict[str, object]] = []
        for index, uploaded_file in enumerate(uploads, start=1):
            try:
                new_records.append(analyse_uploaded_file(uploaded_file, investigator, notes))
            except Exception as exc:
                new_records.append({
                    "evidence_id": f"FX-ERR-{index:04d}",
                    "original_filename": uploaded_file.name,
                    "file_size": None,
                    "sha256_hash": None,
                    "detected_file_type": "Unavailable",
                    "declared_extension": Path(uploaded_file.name).suffix.lower(),
                    "extension_mismatch": None,
                    "extracted_metadata": {},
                    "analysis_warnings": [f"Analysis failed for this file: {exc}"],
                    "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                })
            progress.progress(index / len(uploads), text=f"Analysed {index} of {len(uploads)} files")
        st.session_state.analysis_records.extend(new_records)
        progress.empty()
        st.success(f"Analysis complete: {len(new_records)} evidence record(s) added.")
    if st.session_state.analysis_records:
        st.subheader("Analysis results")
        for index, record in enumerate(st.session_state.analysis_records, start=1):
            render_record(record, index)
        payload = json.dumps(st.session_state.analysis_records, indent=2, default=str).encode("utf-8")
        st.download_button(
            "Download structured JSON results",
            data=payload,
            file_name="forensix-analysis-results.json",
            mime="application/json",
            use_container_width=True,
        )


def render_integrity() -> None:
    """Render byte-sequence integrity comparison."""
    render_header("Integrity verification", "Compare a current SHA-256 digest with an expected value.")
    upload = st.file_uploader("Upload previously analysed evidence", key="integrity_upload")
    expected = st.text_input("Expected SHA-256 hash", placeholder="64 hexadecimal characters")
    if st.button("Verify integrity", type="primary"):
        if upload is None:
            st.error("Upload a file before verifying integrity.")
            return
        normalized = expected.strip().lower()
        if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
            st.error("Enter a valid 64-character hexadecimal SHA-256 hash.")
            return
        suffix = Path(upload.name).suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temporary:
            temporary.write(upload.getvalue())
            temporary_path = Path(temporary.name)
        try:
            current = calculate_hash(temporary_path)
        except OSError as exc:
            st.error(str(exc))
            return
        finally:
            temporary_path.unlink(missing_ok=True)
        if current == normalized:
            matching = next(
                (
                    record
                    for record in st.session_state.evidence_register
                    if record.get("acquisition_hash") == normalized
                    or record.get("original_filename") == upload.name
                ),
                None,
            )
            if matching:
                matching["current_integrity_status"] = "MATCH"
                append_event(
                    st.session_state.custody_events,
                    evidence_id=matching["evidence_id"],
                    event_type="integrity_verified",
                    event_description=f"Integrity verified: {upload.name}",
                    current_hash=current,
                )
            st.markdown('<div class="fx-success"><strong>MATCH</strong> — the compared byte sequences are equal.</div>', unsafe_allow_html=True)
        else:
            matching = next(
                (
                    record
                    for record in st.session_state.evidence_register
                    if record.get("original_filename") == upload.name
                ),
                None,
            )
            if matching:
                matching["current_integrity_status"] = "MISMATCH"
                append_event(
                    st.session_state.custody_events,
                    evidence_id=matching["evidence_id"],
                    event_type="integrity_mismatch_detected",
                    event_description=f"Integrity mismatch detected: {upload.name}",
                    current_hash=current,
                )
            st.markdown('<div class="fx-danger"><strong>MISMATCH</strong> — the compared byte sequences differ.</div>', unsafe_allow_html=True)
        st.caption("A match establishes equality of the compared byte sequences; it does not establish authenticity or provenance of the original evidence.")


def render_report() -> None:
    """Render report review and download controls."""
    render_header("Investigation report", "Review session records and export an investigator-oriented report.")
    records = st.session_state.analysis_records
    if not records:
        st.info("No analysed evidence records are available for reporting.")
        return
    st.write(f"{len(records)} evidence record(s) are ready for review.")
    st.warning(DISCLAIMER)
    for index, record in enumerate(records, start=1):
        st.markdown(
            f"**{record.get('evidence_id', f'FX-{index:04d}')}** · "
            f"`{record.get('original_filename', 'Unknown')}` · "
            f"`{record.get('sha256_hash') or 'hash unavailable'}`"
        )
    report_bytes = generate_report(records)
    st.download_button(
        "Download investigation report",
        data=report_bytes,
        file_name="forensix-investigation-report.html",
        mime="text/html",
        type="primary",
        use_container_width=True,
    )


def render_chain_of_custody() -> None:
    """Render the session-local evidence register and tamper-evident event log."""
    render_header(
        "Chain of custody",
        "Review acquisition records and verify the session-local append-only event chain.",
    )
    register = st.session_state.evidence_register
    events = st.session_state.custody_events
    verification = verify_event_chain(events)
    if verification["valid"]:
        st.markdown(
            '<div class="fx-success"><strong>CHAIN VALID</strong> — all event hashes and '
            "previous-event references verify.</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div class="fx-danger"><strong>CHAIN INVALID</strong> — '
            f'{verification["reason"]} at event index {verification["broken_at"]}.</div>',
            unsafe_allow_html=True,
        )
    st.caption(
        "This in-memory register is session-local. It may be lost when the session "
        "ends or altered outside the application's controls; the hash chain is not "
        "a claim of permanent tamper-proof storage."
    )
    if not register:
        st.info("No evidence has been acquired in this session.")
        return
    st.subheader("Evidence register")
    rows = [
        {
            "Evidence ID": record["evidence_id"],
            "Filename": record["original_filename"],
            "Acquired (UTC)": record["acquisition_timestamp"],
            "Original SHA-256": record["acquisition_hash"],
            "Size": format_bytes(record["file_size"]),
            "Investigator": record["investigator"],
            "Current status": record["current_integrity_status"],
        }
        for record in register
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.subheader("Append-only event log")
    st.dataframe(events, use_container_width=True, hide_index=True)
    payload = json.dumps(
        snapshot_custody_data(register, events), indent=2, default=str
    ).encode("utf-8")
    st.download_button(
        "Download evidence register and event log",
        data=payload,
        file_name="forensix-chain-of-custody.json",
        mime="application/json",
        use_container_width=True,
    )


def main() -> None:
    """Run the ForensiX Streamlit application."""
    configure_page()
    initialise_state()
    with st.sidebar:
        st.markdown("## 🔎 ForensiX")
        st.caption("Digital Evidence Analyzer")
        section = st.radio(
            "Investigation modules",
            [
                "Dashboard",
                "Evidence Analyzer",
                "Integrity Verification",
                "Investigation Report",
                "Chain of Custody",
            ],
            label_visibility="collapsed",
        )
        st.divider()
        st.caption("Read-only analysis • session-local records")
        if st.button("Clear session records"):
            st.session_state.analysis_records = []
            st.rerun()
    if section == "Dashboard":
        render_dashboard()
    elif section == "Evidence Analyzer":
        render_analyzer()
    elif section == "Integrity Verification":
        render_integrity()
    elif section == "Investigation Report":
        render_report()
    else:
        render_chain_of_custody()


if __name__ == "__main__":
    main()
