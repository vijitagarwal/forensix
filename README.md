# ForensiX – Digital Evidence Analyzer

ForensiX is an academic digital-forensics analysis prototype built with
Python and Streamlit. It demonstrates safe, read-only inspection of sample
evidence, integrity comparison, basic metadata extraction, investigation
reporting, and a session-local chain-of-custody register.

> **Academic and ethical notice:** ForensiX is not a certified forensic
> acquisition platform. It does not replace validated acquisition hardware,
> forensic imaging procedures, evidence-handling policy, legal review, or
> qualified investigator interpretation. Use only evidence that you are
> authorized to inspect.

## Problem statement

Digital investigations need repeatable observations about files without
executing or changing the source evidence. A small, understandable tool can
help students learn how cryptographic hashes, file signatures, metadata,
integrity checks, reports, and custody records fit together while making the
limits of automated findings explicit.

## Features

- Read-only SHA-256 hashing with bounded-memory file reads.
- Magic-byte identification for PDF, PNG, JPEG, GIF, ZIP, RAR, MP3, WAV,
  MP4, and common Windows executable files.
- Conservative UTF-8 plain-text identification for text without a known
  binary signature.
- Extension mismatch warnings that do not claim malicious intent.
- Filesystem metadata plus image EXIF and PDF document metadata where
  available.
- Five Streamlit sections: Dashboard, Evidence Analyzer, Integrity
  Verification, Investigation Report, and Chain of Custody.
- JSON analysis downloads and HTML investigation reports.
- Session-local evidence IDs, acquisition records, and hash-chained custody
  events.
- Automated tests using generated temporary sample files.

## Technology stack

- Python 3.10+
- Streamlit
- Pillow
- pypdf
- pytest
- Python standard library (`hashlib`, `pathlib`, `tempfile`, `json`)

## Architecture

```text
app.py
├── forensic_engine.py
│   ├── utils/hashing.py
│   ├── utils/file_signature.py
│   └── utils/metadata.py
├── utils/chain_of_custody.py
└── report_generator.py
```

- `app.py` owns presentation, uploads, session state, and user feedback. It
  copies uploads to temporary paths for analysis and removes those copies.
- `forensic_engine.py` coordinates independent file observations and returns
  structured dictionaries.
- `utils/` contains reusable hashing, signature, metadata, and custody logic.
- `report_generator.py` serializes supplied observations into an escaped HTML
  report.
- `tests/` contains unit and end-to-end checks using temporary generated data.

## Installation

From the ForensiX directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Execution

```powershell
streamlit run app.py
```

The application opens a local Streamlit server. No database, authentication,
cloud service, or external evidence store is required.

## Forensic methodology

1. Evidence is received through the Streamlit uploader and copied to a
   temporary path; uploaded files are never executed.
2. The temporary copy is read to calculate a SHA-256 digest, inspect magic
   bytes, conservatively identify plain text when appropriate, collect
   supported metadata, and record warnings.
3. A Chain of Custody record stores the original filename, a unique evidence
   ID, UTC acquisition time, acquisition hash, size, investigator identifier,
   and notes.
4. Acquisition, analysis, and integrity-verification actions append events to
   a session-local hash chain.
5. Findings are observations for review. An extension mismatch is not proof of
   tampering, metadata does not prove who created a file, and a hash match
   establishes equality of the compared byte sequences rather than
   authenticity or provenance.

Metadata extractors report `extracted`, `missing`, `not_applicable`, or
`unavailable`. Only `unavailable` for an applicable extractor is surfaced as
an extraction warning.

## SHA-256 integrity verification

SHA-256 maps the exact bytes read from a file to a 64-character hexadecimal
digest. For verification, ForensiX hashes the uploaded comparison file and
compares it with the selected evidence record's acquisition hash (or an
explicit expected hash for an unregistered upload). A match means the
compared byte sequences are equal at the time of comparison; it does not by
itself establish that the original evidence was authentic or lawfully
acquired.

## Chain of Custody

The register assigns each acquisition a unique evidence ID. Each event stores
an event ID, evidence ID, type, UTC timestamp, description, previous event
hash, and current event hash. The current hash covers the event data and the
previous hash, allowing the in-memory chain to detect modified event data or
broken references.

This register is session-local and in memory. It can be lost when a session
ends and can be altered outside the application's controls. It is not a
permanent, independently secured, or legally certified tamper-proof evidence
store.

## Screenshots

Screenshots are not included in this repository yet.

- `[Screenshot placeholder: Dashboard]`
- `[Screenshot placeholder: Evidence Analyzer]`
- `[Screenshot placeholder: Chain of Custody]`

## Testing

Run the complete test suite:

```powershell
pytest -q
```

Tests cover valid PDF/PNG/JPEG/text samples, unsupported and malformed files,
incorrect extensions, duplicate filenames, modified evidence, matching and
mismatching hashes, unchanged originals, multiple registrations, custody
chain validation, and escaped HTML reports.

## Limitations

- Analysis is limited to the signatures and metadata formats implemented in
  this educational prototype.
- Filesystem creation time semantics vary by operating system.
- Some malformed or encrypted documents may expose only unavailable metadata.
- Session state is not durable and is not a substitute for controlled
  evidence storage or a validated forensic audit system.
- The HTML report is a presentation aid, not a court-certified forensic
  report.
