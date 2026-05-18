"""
Higher-level network-focused analysis built from Volatility plugin output.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..utils.helpers import extract_rows
from .scoring import (
    build_mitre_tags,
    calculate_risk_score,
    infer_mitre_techniques,
    is_external_ip,
)

SUSPICIOUS_NETWORK_OWNERS = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

def _safe_lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _stringify(value: Any) -> str:
    return str(value or "").strip()


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


def _find_first(row: Dict[str, Any], *keys: str) -> Any:
    lowered = {_safe_lower(key): value for key, value in row.items()}
    for key in keys:
        if _safe_lower(key) in lowered:
            return lowered[_safe_lower(key)]
    return None


def _severity_rank(level: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(level, 0)


def _merge_severity(current: str, candidate: str) -> str:
    return candidate if _severity_rank(candidate) > _severity_rank(current) else current


def analyse_network_activity(results: Dict[str, Any]) -> Dict[str, Any]:
    netscan_rows = _normalise_rows(results.get("windows.netscan", []))
    sockets_rows = _normalise_rows(results.get("windows.sockets", []))

    all_rows = netscan_rows + sockets_rows
    suspicious_connections = []
    indicators: List[str] = []
    mitre_techniques = set()
    severity = "none"

    for row in all_rows:
        owner = _safe_lower(_find_first(row, "Owner", "ImageFileName", "Process"))
        pid = _stringify(_find_first(row, "PID", "Pid", "ProcessId"))
        local_addr = _stringify(_find_first(row, "LocalAddr", "LocalAddress", "Local"))
        foreign_addr = _stringify(
            _find_first(row, "ForeignAddr", "RemoteAddr", "RemoteAddress", "ForeignAddress")
        )
        local_port = _stringify(_find_first(row, "LocalPort", "Port", "ProtoPort"))
        foreign_port = _stringify(_find_first(row, "ForeignPort", "RemotePort"))
        state = _safe_lower(_find_first(row, "State"))

        connection_severity = "none"
        reasons = []

        if is_external_ip(foreign_addr):
            connection_severity = _merge_severity(connection_severity, "low")
            reasons.append("remote network endpoint present")
            mitre_techniques.add("T1071")

        if owner in SUSPICIOUS_NETWORK_OWNERS:
            connection_severity = _merge_severity(connection_severity, "medium")
            reasons.append("network activity owned by a scripting or LOLBin process")
            mitre_techniques.add("T1059")

        if state == "listening" and owner in {"rundll32.exe", "regsvr32.exe", "mshta.exe"}:
            connection_severity = _merge_severity(connection_severity, "high")
            reasons.append("unexpected listener process")
            mitre_techniques.add("T1218")

        if state in {"established", "close_wait"} and owner in {"powershell.exe", "cmd.exe"}:
            connection_severity = _merge_severity(connection_severity, "high")
            reasons.append("interactive shell process communicating over the network")
            mitre_techniques.add("T1071")
            if owner == "powershell.exe":
                mitre_techniques.add("T1059.001")

        if connection_severity != "none":
            connection_techniques = []
            if "remote network endpoint present" in reasons:
                connection_techniques.append("T1071")
            if "network activity owned by a scripting or LOLBin process" in reasons:
                connection_techniques.append("T1059")
            if "unexpected listener process" in reasons:
                connection_techniques.append("T1218")
            if "interactive shell process communicating over the network" in reasons:
                connection_techniques.append("T1071")
                if owner == "powershell.exe":
                    connection_techniques.append("T1059.001")
            connection_techniques.extend(
                infer_mitre_techniques(
                    plugin_name="network_analysis",
                    texts=reasons,
                    owner=owner,
                    state=state,
                )
            )
            connection_techniques = sorted(set(connection_techniques))

            suspicious_connections.append(
                {
                    "owner": owner,
                    "pid": pid,
                    "local_address": local_addr,
                    "local_port": local_port,
                    "remote_address": foreign_addr,
                    "remote_port": foreign_port,
                    "state": state,
                    "severity": connection_severity,
                    "risk_score": calculate_risk_score(connection_severity, connection_techniques, len(reasons)),
                    "mitre_tags": build_mitre_tags(connection_techniques),
                    "reasons": reasons,
                }
            )
            severity = _merge_severity(severity, connection_severity)
            indicators.append(
                f"{owner or 'unknown process'} (PID {pid or '?'}) {state or 'network activity'} "
                f"{local_addr}:{local_port} -> {foreign_addr}:{foreign_port}: {', '.join(reasons)}"
            )

    suspicious_connections.sort(
        key=lambda item: (
            -_severity_rank(item["severity"]),
            item.get("owner") or "",
            item.get("pid") or "",
        )
    )
    overall_techniques = sorted(
        set(mitre_techniques)
        | set(
            infer_mitre_techniques(
                plugin_name="network_analysis",
                texts=indicators,
            )
        )
    )

    return {
        "status": "analysed",
        "severity": severity,
        "risk_score": calculate_risk_score(severity, overall_techniques, len(indicators)),
        "mitre_tags": build_mitre_tags(overall_techniques),
        "summary": (
            f"{len(suspicious_connections)} suspicious network connection(s) identified"
            if suspicious_connections
            else "No suspicious network behaviour identified"
        ),
        "indicators": indicators,
        "suspicious_connections": suspicious_connections,
        "connection_count": len(all_rows),
    }
