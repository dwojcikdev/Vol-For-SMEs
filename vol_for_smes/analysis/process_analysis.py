"""
Higher-level process-focused analysis built from multiple Volatility plugins.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..utils.helpers import extract_rows
from .scoring import (
    BROWSERS,
    COMMON_MISSPELLINGS,
    LOLBIN_PROCESSES,
    OFFICE_PROCESSES,
    SCRIPTING_AND_LOLBINS,
    SCRIPTING_PROCESSES,
    build_mitre_tags,
    infer_mitre_techniques,
    is_external_ip,
    is_suspicious_path,
    looks_random_process_name,
    score_command_line,
    severity_from_score,
)


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
        lowered_key = _safe_lower(key)
        if lowered_key in lowered:
            return lowered[lowered_key]
    return None


def _clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def _severity_rank(level: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(level, 0)


def _process_label(process: Dict[str, Any]) -> str:
    name = process.get("name") or "unknown"
    pid = process.get("pid")
    return f"{name} (PID {pid if pid is not None else '?'})"


def _new_process(pid: int, name: str = "unknown", parent_pid: int | None = None) -> Dict[str, Any]:
    return {
        "pid": pid,
        "name": _safe_lower(name) or "unknown",
        "ppid": parent_pid,
        "parent_name": None,
        "score": 0,
        "severity": "none",
        "reasons": [],
        "evidence": {"process_rows": []},
        "command_line": "",
        "mitre_tags": [],
    }


def _append_reason(process: Dict[str, Any], reason: str) -> None:
    if reason and reason not in process["reasons"]:
        process["reasons"].append(reason)


def _append_evidence(process: Dict[str, Any], key: str, value: Any) -> None:
    if key.endswith("_rows") or key.endswith("_hits") or key.endswith("_connections"):
        process["evidence"].setdefault(key, []).append(value)
    else:
        process["evidence"][key] = value


def _seed_processes_from_rows(
    processes: Dict[int, Dict[str, Any]],
    rows: List[Dict[str, Any]],
) -> None:
    for row in rows:
        pid = _safe_int(_find_first(row, "PID", "Pid", "pid", "ProcessId"))
        if pid is None:
            continue

        name = _stringify(
            _find_first(
                row,
                "ImageFileName",
                "Image File Name",
                "Name",
                "Process",
                "process",
            )
        ) or "unknown"
        parent_pid = _safe_int(
            _find_first(
                row,
                "PPID",
                "Ppid",
                "ParentPid",
                "InheritedFromUniqueProcessId",
                "InheritedFromPid",
                "Parent PID",
            )
        )

        if pid not in processes:
            processes[pid] = _new_process(pid, name=name, parent_pid=parent_pid)
        else:
            if processes[pid]["name"] == "unknown" and name:
                processes[pid]["name"] = _safe_lower(name)
            if processes[pid]["ppid"] is None and parent_pid is not None:
                processes[pid]["ppid"] = parent_pid

        _append_evidence(processes[pid], "process_rows", row)


def _extract_pid_set(rows: List[Dict[str, Any]]) -> set[int]:
    pids = set()
    for row in rows:
        pid = _safe_int(_find_first(row, "PID", "Pid", "pid", "ProcessId"))
        if pid is not None:
            pids.add(pid)
    return pids


def _count_known_processes(results: Dict[str, Any]) -> int:
    keys = (
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.malfind",
    )
    pids = set()
    for key in keys:
        pids.update(_extract_pid_set(_normalise_rows(results.get(key, []))))
    return len(pids)


def _apply_psscan_vs_pslist_score(
    processes: Dict[int, Dict[str, Any]],
    pslist_rows: List[Dict[str, Any]],
    psscan_rows: List[Dict[str, Any]],
) -> None:
    pslist_pids = _extract_pid_set(pslist_rows)
    psscan_pids = _extract_pid_set(psscan_rows)

    for pid in psscan_pids - pslist_pids:
        process = processes.get(pid)
        if not process:
            continue

        process["score"] += 40
        _append_reason(
            process,
            "Found by psscan but not pslist; possible hidden, unlinked, or terminated process",
        )
        _append_evidence(process, "psscan_not_pslist", True)


def _apply_process_name_score(processes: Dict[int, Dict[str, Any]]) -> None:
    for process in processes.values():
        name = _safe_lower(process.get("name"))

        if name in COMMON_MISSPELLINGS:
            process["score"] += 25
            _append_reason(process, COMMON_MISSPELLINGS[name])
        elif looks_random_process_name(name):
            process["score"] += 15
            _append_reason(process, "Process name appears random-looking")


def _apply_parent_child_score(processes: Dict[int, Dict[str, Any]]) -> None:
    pid_to_name = {
        pid: _safe_lower(process.get("name"))
        for pid, process in processes.items()
    }

    for process in processes.values():
        parent_pid = process.get("ppid")
        if parent_pid is not None:
            process["parent_name"] = pid_to_name.get(parent_pid)

    for process in processes.values():
        child = _safe_lower(process.get("name"))
        parent = _safe_lower(process.get("parent_name"))

        if not parent:
            continue

        if parent in OFFICE_PROCESSES and child in SCRIPTING_AND_LOLBINS:
            process["score"] += 30
            _append_reason(process, f"{child} was launched by Office process {parent}")

        if parent in BROWSERS and child in SCRIPTING_AND_LOLBINS:
            process["score"] += 25
            _append_reason(process, f"{child} was launched by browser process {parent}")

        if child == "svchost.exe" and parent != "services.exe":
            process["score"] += 30
            _append_reason(process, "svchost.exe has an unusual parent process")

        if child == "lsass.exe" and parent not in {"wininit.exe", "smss.exe"}:
            process["score"] += 30
            _append_reason(process, "lsass.exe has an unusual parent process")


def _apply_command_line_score(
    processes: Dict[int, Dict[str, Any]],
    cmdline_rows: List[Dict[str, Any]],
) -> None:
    for row in cmdline_rows:
        pid = _safe_int(_find_first(row, "PID", "Pid", "pid", "ProcessId"))
        if pid is None or pid not in processes:
            continue

        command_line = _stringify(
            _find_first(row, "Args", "CommandLine", "Command Line", "cmdline", "Cmd")
        )
        if not command_line:
            continue

        process = processes[pid]
        process["command_line"] = command_line
        score, reasons = score_command_line(command_line)
        if score <= 0:
            continue

        process["score"] += score
        for reason in reasons:
            _append_reason(process, reason)
        _append_evidence(process, "command_line", command_line)


def _apply_dlllist_score(
    processes: Dict[int, Dict[str, Any]],
    dlllist_rows: List[Dict[str, Any]],
) -> None:
    scored_pids = set()

    for row in dlllist_rows:
        pid = _safe_int(_find_first(row, "PID", "Pid", "pid", "ProcessId"))
        if pid is None or pid not in processes:
            continue

        path = _stringify(_find_first(row, "Path", "FullPath", "LoadPath"))
        if not is_suspicious_path(path):
            continue

        process = processes[pid]
        if pid not in scored_pids:
            process["score"] += 20
            _append_reason(process, "Process loaded module from a user-writable path")
            scored_pids.add(pid)

        _append_evidence(
            process,
            "dll_paths",
            {
                "path": path,
                "raw": row,
            },
        )


def _apply_malfind_score(
    processes: Dict[int, Dict[str, Any]],
    malfind_rows: List[Dict[str, Any]],
) -> None:
    scored_pids = set()

    for row in malfind_rows:
        pid = _safe_int(_find_first(row, "PID", "Pid", "pid", "ProcessId"))
        if pid is None:
            continue

        if pid not in processes:
            process_name = _stringify(
                _find_first(row, "Process", "ImageFileName", "Name", "process")
            ) or "unknown"
            processes[pid] = _new_process(pid, name=process_name)

        process = processes[pid]
        if pid not in scored_pids:
            process["score"] += 45
            _append_reason(process, "malfind reported possible injected executable memory")
            scored_pids.add(pid)

        _append_evidence(process, "malfind_rows", row)


def _apply_network_score(
    processes: Dict[int, Dict[str, Any]],
    network_rows: List[Dict[str, Any]],
) -> None:
    scored_pids = set()

    for row in network_rows:
        pid = _safe_int(_find_first(row, "PID", "Pid", "pid", "OwnerPid", "ProcessId"))
        if pid is None or pid not in processes:
            continue

        foreign_addr = _stringify(
            _find_first(
                row,
                "ForeignAddr",
                "Foreign Address",
                "ForeignAddress",
                "RemoteAddr",
            )
        )
        if not is_external_ip(foreign_addr):
            continue

        process = processes[pid]
        process_name = _safe_lower(process.get("name"))

        if pid not in scored_pids:
            if process_name in SCRIPTING_AND_LOLBINS:
                process["score"] += 25
                _append_reason(process, f"{process_name} has an external network connection")
            else:
                process["score"] += 10
                _append_reason(process, "Process has an external network connection")
            scored_pids.add(pid)

        _append_evidence(
            process,
            "network_connections",
            {
                "local_address": _stringify(
                    _find_first(row, "LocalAddr", "Local Address", "LocalAddress")
                ),
                "foreign_address": foreign_addr,
                "foreign_port": _stringify(
                    _find_first(row, "ForeignPort", "Foreign Port", "RemotePort")
                ),
                "raw": row,
            },
        )


def _build_process_techniques(process: Dict[str, Any]) -> List[str]:
    evidence = process.get("evidence", {})
    paths = [
        item.get("path", "")
        for item in evidence.get("dll_paths", [])
        if isinstance(item, dict)
    ]
    texts = list(process.get("reasons", []))

    if evidence.get("network_connections"):
        texts.append("external network connection")
    if process.get("name") in LOLBIN_PROCESSES:
        texts.append("living-off-the-land binary usage")

    techniques = set(
        infer_mitre_techniques(
            plugin_name="process_analysis",
            texts=texts,
            process_name=process.get("name"),
            command_line=process.get("command_line"),
            paths=paths,
        )
    )

    if process.get("name") in SCRIPTING_PROCESSES and process.get("command_line"):
        techniques.add("T1059")
        if "powershell" in _safe_lower(process.get("name")) or "pwsh" in _safe_lower(
            process.get("name")
        ):
            techniques.add("T1059.001")

    return sorted(techniques)


def build_suspicious_process_findings(
    results: Dict[str, Any],
) -> List[Dict[str, Any]]:
    pslist_rows = _normalise_rows(results.get("windows.pslist", []))
    psscan_rows = _normalise_rows(results.get("windows.psscan", []))
    pstree_rows = _normalise_rows(results.get("windows.pstree", []))
    cmdline_rows = _normalise_rows(results.get("windows.cmdline", []))
    dlllist_rows = _normalise_rows(results.get("windows.dlllist", []))
    malfind_rows = _normalise_rows(results.get("windows.malfind", []))
    network_rows = _normalise_rows(results.get("windows.netscan", [])) + _normalise_rows(
        results.get("windows.sockets", [])
    )

    processes: Dict[int, Dict[str, Any]] = {}
    _seed_processes_from_rows(processes, pslist_rows)
    _seed_processes_from_rows(processes, psscan_rows)
    _seed_processes_from_rows(processes, pstree_rows)

    _apply_psscan_vs_pslist_score(processes, pslist_rows, psscan_rows)
    _apply_process_name_score(processes)
    _apply_parent_child_score(processes)
    _apply_command_line_score(processes, cmdline_rows)
    _apply_dlllist_score(processes, dlllist_rows)
    _apply_malfind_score(processes, malfind_rows)
    _apply_network_score(processes, network_rows)

    findings = []
    for process in processes.values():
        score = int(process.get("score", 0))
        if score <= 0:
            continue

        process["severity"] = severity_from_score(score)
        process["risk_score"] = _clamp_score(score)
        process["mitre_tags"] = build_mitre_tags(_build_process_techniques(process))
        findings.append(process)

    findings.sort(
        key=lambda item: (
            -int(item.get("score", 0)),
            item.get("name") or "",
            int(item.get("pid", 0)),
        )
    )
    return findings


def analyse_process_activity(results: Dict[str, Any]) -> Dict[str, Any]:
    findings = build_suspicious_process_findings(results)
    indicators = [
        f"{_process_label(process)}: {', '.join(process.get('reasons', []))}"
        for process in findings
    ]

    overall_score = max((int(process.get("risk_score", 0)) for process in findings), default=0)
    overall_severity = severity_from_score(overall_score)
    overall_techniques = []
    for process in findings:
        overall_techniques.extend(
            tag.get("technique_id", "")
            for tag in process.get("mitre_tags", [])
            if isinstance(tag, dict)
        )

    public_findings = []
    for process in findings:
        public_findings.append(
            {
                "pid": _stringify(process.get("pid")),
                "name": process.get("name"),
                "ppid": _stringify(process.get("ppid"))
                if process.get("ppid") is not None
                else "",
                "parent_name": process.get("parent_name") or "",
                "severity": process.get("severity", "none"),
                "score": int(process.get("score", 0)),
                "risk_score": int(process.get("risk_score", 0)),
                "mitre_tags": process.get("mitre_tags", []),
                "reasons": list(process.get("reasons", [])),
                "command_line": process.get("command_line", ""),
                "evidence": process.get("evidence", {}),
            }
        )

    return {
        "status": "analysed",
        "severity": overall_severity,
        "score": overall_score,
        "risk_score": overall_score,
        "mitre_tags": build_mitre_tags(sorted(set(overall_techniques))),
        "summary": (
            f"{len(public_findings)} suspicious process(es) identified"
            if public_findings
            else "No suspicious process behaviour identified"
        ),
        "indicators": indicators,
        "suspicious_processes": public_findings,
        "process_count": _count_known_processes(results),
    }
