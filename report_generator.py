"""Investigation report generation for analysed evidence records."""

from datetime import datetime, timezone
from html import escape
from typing import Iterable


DISCLAIMER = (
    "Automated findings are indicators for investigator review and require "
    "qualified investigator interpretation. An extension mismatch is not proof "
    "of malicious tampering, and metadata does not prove who created a file."
)


def _format_value(value: object) -> str:
    """Render a report value safely and readably."""
    if isinstance(value, dict):
        return "<dl>" + "".join(
            f"<dt>{escape(str(key))}</dt><dd>{_format_value(item)}</dd>"
            for key, item in value.items()
        ) + "</dl>"
    if isinstance(value, list):
        return "<ul>" + "".join(f"<li>{_format_value(item)}</li>" for item in value) + "</ul>"
    return escape(str(value if value is not None else "Unavailable"))


def generate_report(
    analysis_results: Iterable[dict[str, object]],
    generated_at: datetime | None = None,
) -> bytes:
    """Return a downloadable HTML investigation report.

    The report contains only supplied analysis records and does not infer
    conclusions beyond the engine's findings.
    """
    timestamp = generated_at or datetime.now(timezone.utc)
    records = list(analysis_results)
    sections: list[str] = []
    for index, record in enumerate(records, start=1):
        warnings = record.get("analysis_warnings", [])
        sections.append(
            f"""
            <section class="record">
              <h2>Evidence {index}: {escape(str(record.get("original_filename", "Unknown")))}</h2>
              <p><strong>Evidence identifier:</strong> {escape(str(record.get("evidence_id", f"FX-{index:04d}")))}</p>
              <table>
                <tr><th>SHA-256</th><td>{_format_value(record.get("sha256_hash"))}</td></tr>
                <tr><th>File size</th><td>{_format_value(record.get("file_size"))} bytes</td></tr>
                <tr><th>Detected signature</th><td>{_format_value(record.get("detected_file_type"))}</td></tr>
                <tr><th>Declared extension</th><td>{_format_value(record.get("declared_extension"))}</td></tr>
                <tr><th>Extension mismatch</th><td>{_format_value(record.get("extension_mismatch"))}</td></tr>
                <tr><th>Analysis timestamp</th><td>{_format_value(record.get("analysis_timestamp"))}</td></tr>
              </table>
              <h3>Metadata</h3>
              {_format_value(record.get("extracted_metadata", {}))}
              <h3>Warnings</h3>
              {_format_value(warnings if warnings else ["None recorded"])}
            </section>
            """
        )

    body = "\n".join(sections) or "<p>No evidence records were analysed.</p>"
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ForensiX Investigation Report</title>
  <style>
    body {{ background:#0b1120; color:#dbeafe; font:15px Arial,sans-serif; margin:40px; }}
    h1,h2 {{ color:#67e8f9; }} h3 {{ color:#a5f3fc; }}
    .banner {{ border:1px solid #155e75; background:#082f49; padding:16px; }}
    .record {{ border-top:1px solid #334155; margin-top:28px; padding-top:18px; }}
    table {{ border-collapse:collapse; width:100%; margin:12px 0; }}
    th,td {{ border:1px solid #334155; padding:9px; text-align:left; vertical-align:top; }}
    th {{ color:#a5f3fc; width:25%; }} dt {{ color:#93c5fd; margin-top:6px; }}
    dd {{ margin:2px 0 6px 12px; }} ul {{ margin-top:4px; }}
  </style>
</head>
<body>
  <h1>ForensiX Investigation Report</h1>
  <p>Generated: {escape(timestamp.isoformat())}</p>
  <div class="banner"><strong>Investigator disclaimer:</strong> {escape(DISCLAIMER)}</div>
  {body}
</body>
</html>"""
    return document.encode("utf-8")
