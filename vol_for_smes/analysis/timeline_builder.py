"""
Build a simple forensic timeline from Volatility plugin outputs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PureWindowsPath
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

PID_FIELD_HINTS = ("pid", "PID", "Pid", "ProcessId", "OwnerPid")
PPID_FIELD_HINTS = (
    "ppid",
    "PPID",
    "Ppid",
    "ParentPid",
    "InheritedFromUniqueProcessId",
    "InheritedFromPid",
    "Parent PID",
)
PROCESS_NAME_FIELD_HINTS = (
    "Owner",
    "ImageFileName",
    "name",
    "Name",
    "Process",
    "ProcessName",
    "ServiceName",
    "Path",
    "File",
)
NETWORK_PLUGIN_NAMES = {"windows.netscan", "windows.sockets"}


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


def _safe_lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _clean_text(value: Any) -> str:
    text = str(value or "").strip()
    if text.lower() in {"", "-", "n/a", "none", "not applicable"}:
        return ""
    return text


def _normalise_name(value: Any) -> str:
    text = _clean_text(value)
    if not text:
        return ""
    if "\\" in text or "/" in text:
        basename = PureWindowsPath(text).name.strip()
        return basename or text
    return text


def _find_first(row: Dict[str, Any], *keys: str) -> Any:
    lowered = {_safe_lower(key): value for key, value in row.items()}
    for key in keys:
        lowered_key = _safe_lower(key)
        if lowered_key in lowered:
            return lowered[lowered_key]
    return None


def _extract_process_name(row: Dict[str, Any]) -> str:
    for key in PROCESS_NAME_FIELD_HINTS:
        value = _find_first(row, key)
        name = _normalise_name(value)
        if name:
            return name
    return ""


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


def _build_process_context_index(results: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    context_by_pid: Dict[int, Dict[str, Any]] = {}
    plugin_priority = {
        "windows.pslist": 0,
        "windows.pstree": 0,
        "windows.psscan": 1,
        "windows.cmdline": 2,
        "windows.envars": 2,
        "windows.sessions": 2,
        "windows.netscan": 3,
        "windows.sockets": 3,
    }

    for plugin_name, plugin_result in results.items():
        if isinstance(plugin_result, dict) and "error" in plugin_result:
            continue

        priority = plugin_priority.get(str(plugin_name), 10)
        for row in _normalise_rows(plugin_result):
            pid = _safe_int(_find_first(row, *PID_FIELD_HINTS))
            if pid is None:
                continue

            name = _extract_process_name(row)
            ppid = _safe_int(_find_first(row, *PPID_FIELD_HINTS))
            existing = context_by_pid.get(pid)
            if existing is None:
                context_by_pid[pid] = {
                    "name": name,
                    "ppid": ppid,
                    "priority": priority,
                }
                continue

            if existing.get("ppid") is None and ppid is not None:
                existing["ppid"] = ppid
            if name and (
                not existing.get("name")
                or priority < int(existing.get("priority", priority))
            ):
                existing["name"] = name
                existing["priority"] = priority

    return context_by_pid


def _row_identity(
    row: Dict[str, Any],
    process_context_by_pid: Dict[int, Dict[str, Any]],
) -> str:
    name = _extract_process_name(row)
    if name:
        return name

    pid = _safe_int(_find_first(row, *PID_FIELD_HINTS))
    if pid is not None:
        process_name = _clean_text(process_context_by_pid.get(pid, {}).get("name"))
        if process_name:
            return process_name
        return f"PID {pid}"
    return "artefact"


def _format_endpoint(address: Any, port: Any) -> str:
    address_text = _clean_text(address)
    port_text = _clean_text(port)
    if address_text and port_text:
        return f"{address_text}:{port_text}"
    return address_text or port_text


def _network_connection_summary(row: Dict[str, Any]) -> str:
    local_endpoint = _format_endpoint(
        _find_first(row, "LocalAddr", "LocalAddress", "Local"),
        _find_first(row, "LocalPort", "Port", "ProtoPort"),
    )
    remote_endpoint = _format_endpoint(
        _find_first(row, "ForeignAddr", "RemoteAddr", "RemoteAddress", "ForeignAddress"),
        _find_first(row, "ForeignPort", "RemotePort"),
    )
    state = _clean_text(_find_first(row, "State"))

    connection_parts = []
    if local_endpoint and remote_endpoint:
        connection_parts.append(f"{local_endpoint} -> {remote_endpoint}")
    elif local_endpoint:
        connection_parts.append(local_endpoint)

    if state:
        connection_parts.append(f"[{state}]")

    return " ".join(connection_parts)


def _event_description(
    plugin_name: str,
    row: Dict[str, Any],
    field_name: str,
    process_context_by_pid: Dict[int, Dict[str, Any]],
) -> str:
    identity = _row_identity(row, process_context_by_pid)
    label = field_name.replace("_", " ")
    pid = _safe_int(_find_first(row, *PID_FIELD_HINTS))
    description_subject = identity

    if pid is not None and identity != f"PID {pid}" and str(plugin_name) in NETWORK_PLUGIN_NAMES:
        description_subject = f"{identity} (PID {pid})"

    if str(plugin_name) in NETWORK_PLUGIN_NAMES:
        connection_summary = _network_connection_summary(row)
        if connection_summary:
            return (
                f"{description_subject} {connection_summary} "
                f"reported by {plugin_name} ({label})"
            )

    return f"{description_subject} reported by {plugin_name} ({label})"


def build_timeline(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    timeline = []
    process_context_by_pid = _build_process_context_index(results)

    for plugin_name, plugin_result in results.items():
        if isinstance(plugin_result, dict) and "error" in plugin_result:
            continue

        for row in _normalise_rows(plugin_result):
            pid = _safe_int(_find_first(row, *PID_FIELD_HINTS))
            process_context = process_context_by_pid.get(pid, {}) if pid is not None else {}
            for field_name, value in row.items():
                if not any(hint in str(field_name).lower() for hint in TIMESTAMP_FIELD_HINTS):
                    continue

                parsed = _parse_timestamp(value)
                if not parsed:
                    continue

                row_ppid = _safe_int(_find_first(row, *PPID_FIELD_HINTS))
                if row_ppid is None:
                    row_ppid = _safe_int(process_context.get("ppid"))

                timeline.append(
                    {
                        "timestamp": parsed.isoformat(),
                        "plugin": plugin_name,
                        "field": str(field_name),
                        "description": _event_description(
                            plugin_name,
                            row,
                            str(field_name),
                            process_context_by_pid,
                        ),
                        "entity_label": _row_identity(row, process_context_by_pid),
                        "pid": pid,
                        "ppid": row_ppid,
                        "raw_value": value,
                        "row": row,
                    }
                )

    timeline.sort(key=lambda event: event["timestamp"])
    return timeline
