# ForensiX – Digital Evidence Analyzer

ForensiX is a beginner-friendly academic project for exploring digital
evidence analysis with Python and Streamlit.

## Project structure

```text
ForensiX/
├── app.py
├── forensic_engine.py
├── report_generator.py
├── requirements.txt
├── README.md
├── reports/
│   └── .gitkeep
└── utils/
    ├── __init__.py
    ├── file_signature.py
    ├── hashing.py
    └── metadata.py
```

The analysis engine is intentionally read-only: it hashes and inspects
evidence without executing or modifying the original files. The Streamlit
frontend provides dashboard metrics, multi-file analysis, integrity
verification, and HTML investigation reports. Extension mismatches are
warnings, not proof of tampering, and metadata does not prove who created a
file.

## Analysis modules

- `utils/hashing.py` calculates SHA-256 digests using bounded memory.
- `utils/file_signature.py` identifies supported formats from magic bytes and
  compares them with declared extensions.
- `utils/metadata.py` extracts filesystem metadata, image EXIF data, and PDF
  document metadata.
- `forensic_engine.py` combines these operations for one or more files and
  returns structured results with warnings.
- `report_generator.py` creates downloadable HTML investigation reports from
  session-local analysis records.
- `app.py` provides the four-section Streamlit investigation dashboard.
- `utils/chain_of_custody.py` maintains session-local evidence registration and
  a verifiable hash-chained event log.

## Run tests

```bash
pytest
```

## Setup

Create and activate a virtual environment, then install the dependencies:

```bash
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

## Run

```bash
streamlit run app.py
```
