"""
Export forensic reports to PDF without external dependencies.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import wrap
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .report_builder import build_analysis_report

PAGE_WIDTH = 595
PAGE_HEIGHT = 842
LEFT_MARGIN = 50
TOP_MARGIN = 60
BOTTOM_MARGIN = 50
LINE_HEIGHT = 14
MAX_TEXT_WIDTH = 84


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_text(text: str, *, width: int = MAX_TEXT_WIDTH) -> List[str]:
    text = str(text or "").strip()
    if not text:
        return [""]
    pieces = []
    for paragraph in text.splitlines() or [""]:
        wrapped = wrap(paragraph, width=width, replace_whitespace=False) or [""]
        pieces.extend(wrapped)
    return pieces


def _render_lines_to_pages(lines: Iterable[Tuple[str, int]]) -> List[List[Tuple[str, int]]]:
    pages: List[List[Tuple[str, int]]] = [[]]
    y = PAGE_HEIGHT - TOP_MARGIN

    for text, font_size in lines:
        if y < BOTTOM_MARGIN:
            pages.append([])
            y = PAGE_HEIGHT - TOP_MARGIN
        pages[-1].append((text, font_size))
        y -= LINE_HEIGHT if font_size <= 12 else 18

    return pages


def _pdf_text_stream(page_lines: List[Tuple[str, int]]) -> str:
    chunks = ["BT", f"/F1 11 Tf", f"{LEFT_MARGIN} {PAGE_HEIGHT - TOP_MARGIN} Td"]
    current_font = 11

    for index, (line, font_size) in enumerate(page_lines):
        if index:
            chunks.append(f"0 -{LINE_HEIGHT if current_font <= 12 else 18} Td")
        if font_size != current_font:
            chunks.append(f"/F1 {font_size} Tf")
            current_font = font_size
        chunks.append(f"({_escape_pdf_text(line)}) Tj")

    chunks.append("ET")
    return "\n".join(chunks)


def _build_pdf(lines: List[Tuple[str, int]]) -> bytes:
    pages = _render_lines_to_pages(lines)
    objects: List[bytes] = []

    def add_object(content: str | bytes) -> int:
        data = content if isinstance(content, bytes) else content.encode("latin-1", errors="replace")
        objects.append(data)
        return len(objects)

    font_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_ids = []
    content_ids = []
    for page_lines in pages:
        stream = _pdf_text_stream(page_lines).encode("latin-1", errors="replace")
        content_id = add_object(
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"
        )
        content_ids.append(content_id)
        page_ids.append(add_object(""))

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    pages_id = add_object(
        f"<< /Type /Pages /Count {len(page_ids)} /Kids [ {kids} ] >>"
    )

    for idx, page_id in enumerate(page_ids):
        objects[page_id - 1] = (
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_ids[idx]} 0 R >>"
        ).encode("latin-1")

    catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        ).encode("ascii")
    )
    return bytes(pdf)


def _report_lines(report: Dict[str, object]) -> List[Tuple[str, int]]:
    lines: List[Tuple[str, int]] = []

    def add_block(text: str, *, font_size: int = 11, blank_line: bool = False) -> None:
        for wrapped in _wrap_text(text):
            lines.append((wrapped, font_size))
        if blank_line:
            lines.append(("", 11))

    add_block(str(report.get("title", "Memory Analysis Report")), font_size=16, blank_line=True)

    case_metadata = report.get("case_metadata", {})
    if isinstance(case_metadata, dict):
        for key, value in case_metadata.items():
            if value in (None, ""):
                continue
            add_block(f"{str(key).replace('_', ' ').title()}: {value}")
        if case_metadata:
            lines.append(("", 11))

    risk_summary = report.get("risk_summary", {})
    if isinstance(risk_summary, dict):
        add_block("Executive Summary", font_size=14)
        add_block(
            "Risk counts: "
            f"High {risk_summary.get('high', 0)}, "
            f"Medium {risk_summary.get('medium', 0)}, "
            f"Low {risk_summary.get('low', 0)}, "
            f"Informational {risk_summary.get('none', 0)}.",
            blank_line=True,
        )

    for paragraph in report.get("executive_summary", []):
        add_block(str(paragraph), blank_line=False)
    lines.append(("", 11))

    analyst_notice = str(report.get("analyst_notice", "")).strip()
    if analyst_notice:
        add_block("Analyst Review Notice", font_size=14)
        add_block(analyst_notice, blank_line=True)

    findings = report.get("findings", [])
    if findings:
        add_block("Detailed Findings", font_size=14, blank_line=True)
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            add_block(
                f"{finding.get('title', 'Finding')} [{finding.get('severity_label', 'Unknown')} | Risk {finding.get('risk_score', 0)}]",
                font_size=12,
            )
            add_block(f"Category: {finding.get('category', 'Finding')}")
            if finding.get("show_affected_asset") and finding.get("affected_asset"):
                add_block(f"Affected asset: {finding.get('affected_asset')}")
            affected_pids = finding.get("affected_pids", [])
            if finding.get("show_affected_pids") and affected_pids:
                add_block(
                    f"{finding.get('affected_pid_label', 'Affected PIDs')}: {', '.join(str(pid) for pid in affected_pids)}"
                )
            add_block(f"Summary: {finding.get('summary', '')}")
            add_block(f"Possible attack: {finding.get('attack', 'Unknown')}")
            add_block(f"What it means: {finding.get('meaning', '')}")

            mitre = finding.get("mitre", [])
            if mitre:
                add_block("MITRE ATT&CK:")
                for item in mitre:
                    add_block(f"- {item}")

            evidence = finding.get("evidence", [])
            if evidence:
                add_block("Evidence:")
                for item in evidence:
                    add_block(f"- {item}")

            remediations = finding.get("remediations", [])
            if remediations:
                add_block("Recommended remediation:")
                for item in remediations:
                    add_block(f"- {item}")

            lines.append(("", 11))
    else:
        add_block("Detailed Findings", font_size=14)
        add_block("No medium or high severity findings were generated by the current heuristics.", blank_line=True)

    timeline = report.get("timeline", [])
    add_block("Timeline Highlights", font_size=14, blank_line=True)
    if timeline:
        for event in list(timeline)[:20]:
            if not isinstance(event, dict):
                continue
            add_block(f"{event.get('timestamp', 'Unknown time')} - {event.get('description', '')}")
    else:
        add_block("No timestamped artefacts were available for timeline reporting.")

    return lines


def export_analysis_to_pdf(
    analysis: Any,
    output_path: str | Path,
    *,
    case_metadata: Optional[Dict[str, object]] = None,
) -> Path:
    """
    Build a narrative report from the analysis and export it as a PDF file.
    """

    report = build_analysis_report(analysis, case_metadata=case_metadata)
    pdf_bytes = _build_pdf(_report_lines(report))
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(pdf_bytes)
    return output
