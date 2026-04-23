"""
Build a simple forensic timeline from Volatility plugin outputs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..utils.helpers import extract_rows

TIMESTAMP_FIELD_HINTS = (
    "time",
    "date",
    "created",
    "modified",
    "accessed",
    "changed",
    "exit",
    "start",
    "lastwrite",
    "lastaccess",
)


def _normalise_rows(plugin_result: Any) -> List[Dict[str, Any]]:
    rows = extract_rows(plugin_result)
    normalised = []

    for row in rows:
        if isinstance(row, dict):
            normalised.append(row)
        elif isinstance(row, (list, tuple)):
            normalised.append(
                {f"column_{index}": value for index, value in enumerate(row)}
            )

    return normalised


def _parse_timestamp(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text or text.lower() in {"n/a", "-", "none", "not applicable"}:
        return None

    cleaned = text.replace(" UTC", "+00:00").replace("Z", "+00:00")
    if "." in cleaned and "+" in cleaned:
        head, tail = cleaned.rsplit("+", 1)
        head = head.split(".", 1)[0]
        cleaned = f"{head}+{tail}"

    formats = (
        None,
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    )

    for fmt in formats:
        try:
            if fmt is None:
                parsed = datetime.fromisoformat(cleaned)
            else:
                parsed = datetime.strptime(cleaned, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            continue

    return None


def _row_identity(row: Dict[str, Any]) -> str:
    for key in (
        "ImageFileName",
        "Name",
        "Process",
        "ProcessName",
        "Path",
        "File",
        "ServiceName",
    ):
        if row.get(key):
            return str(row[key])
    if row.get("PID") not in (None, ""):
        return f"PID {row['PID']}"
    return "artefact"


def _event_description(plugin_name: str, row: Dict[str, Any], field_name: str) -> str:
    identity = _row_identity(row)
    label = field_name.replace("_", " ")
    return f"{identity} reported by {plugin_name} ({label})"


def build_timeline(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    timeline = []

    for plugin_name, plugin_result in results.items():
        if isinstance(plugin_result, dict) and "error" in plugin_result:
            continue

        for row in _normalise_rows(plugin_result):
            for field_name, value in row.items():
                if not any(hint in str(field_name).lower() for hint in TIMESTAMP_FIELD_HINTS):
                    continue

                parsed = _parse_timestamp(value)
                if not parsed:
                    continue

                timeline.append(
                    {
                        "timestamp": parsed.isoformat(),
                        "plugin": plugin_name,
                        "field": str(field_name),
                        "description": _event_description(plugin_name, row, str(field_name)),
                        "raw_value": value,
                        "row": row,
                    }
                )

    timeline.sort(key=lambda event: event["timestamp"])
    return timeline
