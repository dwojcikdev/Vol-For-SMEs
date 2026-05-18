"""
Parse and analyse Volatility plugin output into higher-level findings.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from ..utils.helpers import extract_rows
from .activity_chains import build_activity_chains, build_suspicious_timeline
from .network_analysis import analyse_network_activity
from .process_analysis import analyse_process_activity
from .ransomware_references import match_ransomware_references
from .scoring import (
    analyse_command_line,
    build_mitre_tags,
    calculate_risk_score,
    infer_mitre_techniques,
    is_external_ip,
    is_ransomware_artifact_path,
    is_suspicious_executable_path,
    is_suspicious_module_path,
    is_suspicious_registry_run_key,
    is_user_writable_path,
    merge_rule_techniques,
    normalise_path,
)
from .timeline_builder import build_timeline


def _safe_lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _stringify(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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


def _describe_row_identity(row: Dict[str, Any]) -> str:
    parts = []

    name = _find_first(
        row,
        "ImageFileName",
        "Name",
        "Process",
        "ProcessName",
        "ServiceName",
        "Path",
        "File",
    )
    pid = _find_first(row, "PID", "Pid", "ProcessId")
    remote = _find_first(row, "ForeignAddr", "RemoteAddr", "RemoteAddress")

    if name:
        parts.append(_stringify(name))
    if pid not in (None, ""):
        parts.append(f"PID {_stringify(pid)}")
    if remote:
        parts.append(f"remote {_stringify(remote)}")

    return " | ".join(parts) or "unidentified row"


def _severity_rank(level: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(level, 0)


def _merge_severity(current: str, candidate: str) -> str:
    return candidate if _severity_rank(candidate) > _severity_rank(current) else current


def _rule_for_reference_hits(reference_hits: Iterable[Dict[str, Any]]) -> str:
    if any(hit.get("source") == "ransomware_note_names" for hit in reference_hits):
        return "ransomware_reference_note"
    return "ransomware_reference_pattern"


def _append_reference_hit(
    target: List[Dict[str, Any]],
    *,
    plugin_name: str,
    row: Dict[str, Any],
    path: str,
    reference_hits: List[Dict[str, Any]],
) -> Dict[str, Any]:
    entry = {
        "plugin": plugin_name,
        "pid": _safe_int(_find_first(row, "PID", "Pid", "ProcessId")),
        "path": normalise_path(path),
        "row_identity": _describe_row_identity(row),
        "pattern": reference_hits[0]["pattern"],
        "confidence": reference_hits[0]["confidence"],
        "match_scope": reference_hits[0]["match_scope"],
        "reference_hits": reference_hits,
        "rule_ids": [_rule_for_reference_hits(reference_hits)],
    }
    target.append(entry)
    return entry


def analyse_plugin_output(
    plugin_name: str,
    plugin_result: Any,
    all_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if isinstance(plugin_result, dict) and "error" in plugin_result:
        return {
            "plugin": plugin_name,
            "status": "error",
            "severity": "none",
            "summary": plugin_result["error"],
            "indicators": [],
            "row_count": 0,
            "rule_ids": [],
            "reference_hits": [],
        }

    rows = _normalise_rows(plugin_result)
    indicators: List[str] = []
    rule_ids: List[str] = []
    reference_hits: List[Dict[str, Any]] = []
    severity = "none"
    plugin_name = str(plugin_name)

    def add_indicator(text: str, *, candidate_severity: str, rule_id: str) -> None:
        nonlocal severity
        severity = _merge_severity(severity, candidate_severity)
        if rule_id and rule_id not in rule_ids:
            rule_ids.append(rule_id)
        if text and text not in indicators:
            indicators.append(text)

    if plugin_name == "windows.malfind" and rows:
        add_indicator(
            "Injected or executable memory was reported by malfind",
            candidate_severity="high",
            rule_id="malfind_injected_memory",
        )
        for row in rows:
            indicators.append(
                f"Injected or RWX memory candidate in {_describe_row_identity(row)}"
            )

    elif plugin_name == "windows.cmdline":
        for row in rows:
            command_line = _stringify(
                _find_first(row, "Args", "CommandLine", "Cmd", "Command")
            )
            for match in analyse_command_line(command_line):
                candidate_severity = (
                    "high"
                    if match["rule_id"] in {
                        "cmdline_encoded",
                        "cmdline_execution_policy_bypass",
                        "cmdline_download",
                        "cmdline_lolbin",
                    }
                    else "medium"
                )
                add_indicator(
                    f"Suspicious command line in {_describe_row_identity(row)}: {match['reason']}",
                    candidate_severity=candidate_severity,
                    rule_id=str(match["rule_id"]),
                )

    elif plugin_name == "windows.dlllist":
        for row in rows:
            path = _stringify(_find_first(row, "Path", "FullPath", "LoadPath"))
            if is_suspicious_module_path(path):
                add_indicator(
                    f"DLL loaded from a high-risk path in {_describe_row_identity(row)}",
                    candidate_severity="medium",
                    rule_id="module_user_writable",
                )

    elif plugin_name == "windows.handles":
        for row in rows:
            handle_name = _stringify(_find_first(row, "Name", "Details", "Path"))
            handle_type = _safe_lower(_find_first(row, "Type", "ObjectType"))
            if handle_type == "file":
                row_reference_hits = match_ransomware_references(handle_name)
                if row_reference_hits:
                    best_score = max(int(hit.get("score", 0)) for hit in row_reference_hits)
                    structured_hit = _append_reference_hit(
                        reference_hits,
                        plugin_name=plugin_name,
                        row=row,
                        path=handle_name,
                        reference_hits=row_reference_hits,
                    )
                    candidate_severity = (
                        "medium"
                        if best_score >= 18 or is_user_writable_path(handle_name)
                        else "low"
                    )
                    add_indicator(
                        f"Ransomware-related file handle observed in {_describe_row_identity(row)}",
                        candidate_severity=candidate_severity,
                        rule_id=structured_hit["rule_ids"][0],
                    )
                elif is_suspicious_executable_path(handle_name):
                    add_indicator(
                        f"Executable or script handle target in a suspicious path: {_describe_row_identity(row)}",
                        candidate_severity="medium",
                        rule_id="user_writable_handle_executable",
                    )
            elif handle_type == "key" and is_suspicious_registry_run_key(handle_name):
                add_indicator(
                    f"Autorun registry handle observed in {_describe_row_identity(row)}",
                    candidate_severity="medium",
                    rule_id="autorun_registry_key",
                )

    elif plugin_name in {"windows.filescan", "windows.shimcache"}:
        for row in rows:
            path = _stringify(
                _find_first(row, "Name", "Path", "FilePath", "File", "LastModified")
            )
            row_reference_hits = match_ransomware_references(path)
            if row_reference_hits:
                best_score = max(int(hit.get("score", 0)) for hit in row_reference_hits)
                structured_hit = _append_reference_hit(
                    reference_hits,
                    plugin_name=plugin_name,
                    row=row,
                    path=path,
                    reference_hits=row_reference_hits,
                )
                candidate_severity = (
                    "medium"
                    if best_score >= 18 or is_user_writable_path(path)
                    else "low"
                )
                add_indicator(
                    f"Ransomware-related file artefact observed in {_describe_row_identity(row)}",
                    candidate_severity=candidate_severity,
                    rule_id=structured_hit["rule_ids"][0],
                )
            elif is_suspicious_executable_path(path):
                add_indicator(
                    f"Executable or script artefact in a suspicious path: {_describe_row_identity(row)}",
                    candidate_severity="medium",
                    rule_id="user_writable_executable_artifact",
                )

    elif plugin_name == "windows.modules":
        for row in rows:
            path = _stringify(_find_first(row, "Path", "File", "Name"))
            if is_suspicious_module_path(path):
                add_indicator(
                    f"Kernel module loaded from a high-risk path in {_describe_row_identity(row)}",
                    candidate_severity="high",
                    rule_id="kernel_module_user_writable",
                )

    elif plugin_name == "windows.svcscan":
        for row in rows:
            path = _stringify(_find_first(row, "Binary", "BinaryPath", "Path"))
            if is_suspicious_executable_path(path):
                add_indicator(
                    f"Service binary in a suspicious path: {_describe_row_identity(row)}",
                    candidate_severity="high",
                    rule_id="service_user_writable_binary",
                )

    elif plugin_name in {"windows.netscan", "windows.sockets"}:
        for row in rows:
            foreign_addr = _safe_lower(
                _find_first(row, "ForeignAddr", "RemoteAddr", "RemoteAddress")
            )
            owner = _safe_lower(_find_first(row, "Owner", "ImageFileName", "Process"))
            state = _safe_lower(_find_first(row, "State"))
            if is_external_ip(foreign_addr):
                add_indicator(
                    f"External network endpoint observed in {_describe_row_identity(row)}",
                    candidate_severity="low",
                    rule_id="network_external_connection",
                )
            if owner in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"}:
                add_indicator(
                    f"Network-capable scripting utility observed in {_describe_row_identity(row)}",
                    candidate_severity="medium",
                    rule_id="network_shell_external",
                )
            if state == "listening" and owner in {"rundll32.exe", "regsvr32.exe"}:
                add_indicator(
                    f"Unexpected listener process in {_describe_row_identity(row)}",
                    candidate_severity="high",
                    rule_id="network_lolbin_listener",
                )

    if plugin_name == "windows.psscan" and all_results:
        pslist_rows = _normalise_rows(all_results.get("windows.pslist", []))
        visible = {
            _stringify(_find_first(row, "PID", "Pid", "ProcessId")) for row in pslist_rows
        }
        for row in rows:
            pid = _stringify(_find_first(row, "PID", "Pid", "ProcessId"))
            if pid and pid not in visible:
                add_indicator(
                    f"Process found in psscan but not pslist: {_describe_row_identity(row)}",
                    candidate_severity="high",
                    rule_id="hidden_process_psscan_only",
                )

    summary = (
        f"{len(indicators)} suspicious indicator(s) detected"
        if indicators
        else "No obvious malicious indicators detected by current heuristics"
    )
    all_techniques = merge_rule_techniques(
        rule_ids,
        fallback_techniques=infer_mitre_techniques(
            plugin_name=plugin_name,
            texts=indicators + [summary],
            paths=[hit.get("path", "") for hit in reference_hits],
        ),
    )

    return {
        "plugin": plugin_name,
        "status": "analysed",
        "severity": severity,
        "risk_score": calculate_risk_score(severity, all_techniques, len(indicators)),
        "mitre_tags": build_mitre_tags(all_techniques),
        "rule_ids": rule_ids,
        "reference_hits": reference_hits,
        "summary": summary,
        "indicators": indicators,
        "row_count": len(rows),
    }


def summarise_plugin_risk(plugin_findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    severities = [
        finding.get("severity", "none")
        for finding in plugin_findings
        if finding.get("status") == "analysed"
    ]
    counts = Counter(severities)
    return {
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "none": counts.get("none", 0),
    }


def _apply_chain_ids(
    process_analysis: Dict[str, Any],
    activity_chains: List[Dict[str, Any]],
) -> None:
    pid_to_chain = {}
    for chain in activity_chains:
        for process in chain.get("related_processes", []):
            pid = _safe_int(process.get("pid"))
            if pid is not None:
                pid_to_chain[pid] = chain.get("chain_id", "")

    for process in process_analysis.get("suspicious_processes", []):
        pid = _safe_int(process.get("pid"))
        if pid is not None and pid in pid_to_chain:
            process["chain_id"] = pid_to_chain[pid]


def analyse_artefacts(results: Dict[str, Any]) -> Dict[str, Any]:
    plugin_findings = {
        plugin_name: analyse_plugin_output(plugin_name, plugin_result, all_results=results)
        for plugin_name, plugin_result in results.items()
    }
    timeline = build_timeline(results)
    process_analysis = analyse_process_activity(results)
    network_analysis = analyse_network_activity(results)
    activity_chains = build_activity_chains(process_analysis, plugin_findings, timeline)
    suspicious_timeline = build_suspicious_timeline(activity_chains, timeline)
    _apply_chain_ids(process_analysis, activity_chains)

    return {
        "plugin_findings": plugin_findings,
        "risk_summary": summarise_plugin_risk(plugin_findings.values()),
        "process_analysis": process_analysis,
        "network_analysis": network_analysis,
        "activity_chains": activity_chains,
        "timeline": timeline,
        "suspicious_timeline": suspicious_timeline,
    }
