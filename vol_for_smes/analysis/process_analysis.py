"""
Higher-level process-focused analysis built from multiple Volatility plugins.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..utils.helpers import extract_rows
from .scoring import build_mitre_tags, calculate_risk_score, infer_mitre_techniques

SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

SUSPICIOUS_COMMAND_PATTERNS = (
    " -enc",
    " -encodedcommand",
    "frombase64string",
    "iex ",
    "invoke-expression",
    "downloadstring",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
)

SUSPICIOUS_PATH_KEYWORDS = (
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\programdata\\",
    "\\users\\public\\",
)


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


def _build_process_map(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    process_map = {}
    for row in rows:
        pid = _stringify(_find_first(row, "PID", "Pid", "ProcessId"))
        if not pid:
            continue
        process_map[pid] = {
            "pid": pid,
            "name": _stringify(_find_first(row, "ImageFileName", "Name", "Process")),
            "ppid": _stringify(_find_first(row, "PPID", "ParentPid", "InheritedFromPid")),
            "create_time": _stringify(_find_first(row, "CreateTime", "Create Time")),
            "raw": row,
        }
    return process_map


def _severity_rank(level: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(level, 0)


def _merge_severity(current: str, candidate: str) -> str:
    return candidate if _severity_rank(candidate) > _severity_rank(current) else current


def _process_label(process: Dict[str, Any]) -> str:
    name = process.get("name") or "unknown"
    pid = process.get("pid") or "?"
    return f"{name} (PID {pid})"


def analyse_process_activity(results: Dict[str, Any]) -> Dict[str, Any]:
    pslist_rows = _normalise_rows(results.get("windows.pslist", []))
    psscan_rows = _normalise_rows(results.get("windows.psscan", []))
    cmdline_rows = _normalise_rows(results.get("windows.cmdline", []))
    dlllist_rows = _normalise_rows(results.get("windows.dlllist", []))
    malfind_rows = _normalise_rows(results.get("windows.malfind", []))

    processes = _build_process_map(pslist_rows)
    suspicious_processes = []
    indicators: List[str] = []
    mitre_techniques = set()
    severity = "none"

    hidden_pids = {
        _stringify(_find_first(row, "PID", "Pid", "ProcessId"))
        for row in psscan_rows
        if _stringify(_find_first(row, "PID", "Pid", "ProcessId")) not in processes
    }

    for pid in hidden_pids:
        if not pid:
            continue
        severity = _merge_severity(severity, "high")
        indicators.append(f"Hidden process candidate found in psscan but not pslist: PID {pid}")
        mitre_techniques.add("T1564")

    cmdlines_by_pid = {}
    for row in cmdline_rows:
        pid = _stringify(_find_first(row, "PID", "Pid", "ProcessId"))
        if not pid:
            continue
        cmdlines_by_pid[pid] = _stringify(
            _find_first(row, "CommandLine", "Args", "Cmd", "Command")
        )

    dll_paths_by_pid = {}
    for row in dlllist_rows:
        pid = _stringify(_find_first(row, "PID", "Pid", "ProcessId"))
        if not pid:
            continue
        dll_paths_by_pid.setdefault(pid, []).append(
            _stringify(_find_first(row, "Path", "FullPath", "LoadPath"))
        )

    malfind_pids = {
        _stringify(_find_first(row, "PID", "Pid", "ProcessId"))
        for row in malfind_rows
        if _stringify(_find_first(row, "PID", "Pid", "ProcessId"))
    }

    for pid, process in processes.items():
        process_severity = "none"
        reasons = []
        name = _safe_lower(process.get("name"))
        cmdline = _safe_lower(cmdlines_by_pid.get(pid))
        dll_paths = [_safe_lower(path) for path in dll_paths_by_pid.get(pid, []) if path]

        if pid in malfind_pids:
            process_severity = _merge_severity(process_severity, "high")
            reasons.append("malfind identified suspicious injected or executable memory")
            mitre_techniques.add("T1055")

        if pid in hidden_pids:
            process_severity = _merge_severity(process_severity, "high")
            reasons.append("process appears in psscan but not pslist")
            mitre_techniques.add("T1564")

        if name in SUSPICIOUS_PROCESS_NAMES:
            process_severity = _merge_severity(process_severity, "low")
            reasons.append("script-capable or living-off-the-land process name")
            mitre_techniques.add("T1218")

        if cmdline and any(pattern in cmdline for pattern in SUSPICIOUS_COMMAND_PATTERNS):
            process_severity = _merge_severity(process_severity, "high")
            reasons.append("suspicious command-line execution pattern")
            mitre_techniques.add("T1059")
            if "powershell" in cmdline:
                mitre_techniques.add("T1059.001")

        if any(keyword in path for path in dll_paths for keyword in SUSPICIOUS_PATH_KEYWORDS):
            process_severity = _merge_severity(process_severity, "medium")
            reasons.append("loaded DLL from a user-writable path")
            mitre_techniques.add("T1574")

        if process_severity != "none":
            process_techniques = []
            if "malfind identified suspicious injected or executable memory" in reasons:
                process_techniques.append("T1055")
            if "process appears in psscan but not pslist" in reasons:
                process_techniques.append("T1564")
            if "script-capable or living-off-the-land process name" in reasons:
                process_techniques.append("T1218")
            if "suspicious command-line execution pattern" in reasons:
                process_techniques.append("T1059")
                if "powershell" in cmdline:
                    process_techniques.append("T1059.001")
            if "loaded DLL from a user-writable path" in reasons:
                process_techniques.append("T1574")
            process_techniques.extend(
                infer_mitre_techniques(
                    plugin_name="process_analysis",
                    texts=reasons,
                    process_name=name,
                    command_line=cmdline,
                    paths=dll_paths,
                )
            )
            process_techniques = sorted(set(process_techniques))

            suspicious_processes.append(
                {
                    "pid": pid,
                    "name": process.get("name"),
                    "ppid": process.get("ppid"),
                    "severity": process_severity,
                    "risk_score": calculate_risk_score(process_severity, process_techniques, len(reasons)),
                    "mitre_tags": build_mitre_tags(process_techniques),
                    "reasons": reasons,
                    "command_line": cmdlines_by_pid.get(pid, ""),
                }
            )
            severity = _merge_severity(severity, process_severity)
            indicators.append(f"{_process_label(process)}: {', '.join(reasons)}")

    suspicious_processes.sort(
        key=lambda item: (-_severity_rank(item["severity"]), item.get("name") or "", item["pid"])
    )
    overall_techniques = sorted(
        set(mitre_techniques)
        | set(
            infer_mitre_techniques(
                plugin_name="process_analysis",
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
            f"{len(suspicious_processes)} suspicious process(es) identified"
            if suspicious_processes
            else "No suspicious process behaviour identified"
        ),
        "indicators": indicators,
        "suspicious_processes": suspicious_processes,
        "process_count": len(processes),
    }
