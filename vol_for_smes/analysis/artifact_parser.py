"""
Parse and analyse Volatility plugin output into higher-level findings.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from ..utils.helpers import extract_rows
from .timeline_builder import build_timeline

SUSPICIOUS_PATH_KEYWORDS = (
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\perflogs\\",
    "\\recycler\\",
)

SUSPICIOUS_COMMAND_PATTERNS = (
    " -enc",
    " -encodedcommand",
    "frombase64string",
    "iex ",
    "invoke-expression",
    "downloadstring",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "certutil",
    "bitsadmin",
    "cmd.exe /c",
    "powershell",
)

SUSPICIOUS_FILE_PATTERNS = (
    ".ps1",
    ".vbs",
    ".js",
    ".hta",
    ".bat",
    ".cmd",
    ".dll",
    ".exe",
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
        }

    rows = _normalise_rows(plugin_result)
    indicators: List[str] = []
    severity = "none"
    plugin_name = str(plugin_name)

    if plugin_name == "windows.malfind" and rows:
        severity = "high"
        for row in rows:
            indicators.append(
                f"Injected or RWX memory candidate in {_describe_row_identity(row)}"
            )

    elif plugin_name == "windows.cmdline":
        for row in rows:
            command_line = _safe_lower(
                _find_first(row, "Args", "CommandLine", "Cmd", "Command")
            )
            if any(pattern in command_line for pattern in SUSPICIOUS_COMMAND_PATTERNS):
                severity = _merge_severity(severity, "high")
                indicators.append(
                    f"Suspicious command line in {_describe_row_identity(row)}"
                )

    elif plugin_name == "windows.dlllist":
        for row in rows:
            path = _safe_lower(_find_first(row, "Path", "FullPath", "LoadPath"))
            if any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS):
                severity = _merge_severity(severity, "medium")
                indicators.append(
                    f"DLL loaded from user-writable path in {_describe_row_identity(row)}"
                )

    elif plugin_name == "windows.handles":
        for row in rows:
            handle_name = _safe_lower(_find_first(row, "Name", "Details", "Path"))
            handle_type = _safe_lower(_find_first(row, "Type", "ObjectType"))
            if (
                any(keyword in handle_name for keyword in SUSPICIOUS_PATH_KEYWORDS)
                and handle_type in {"file", "key", "process", "mutant", ""}
            ):
                severity = _merge_severity(severity, "medium")
                indicators.append(
                    f"Suspicious handle target in {_describe_row_identity(row)}"
                )

    elif plugin_name in {"windows.filescan", "windows.shimcache"}:
        for row in rows:
            path = _safe_lower(
                _find_first(row, "Name", "Path", "FilePath", "File", "LastModified")
            )
            if any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS) and any(
                pattern in path for pattern in SUSPICIOUS_FILE_PATTERNS
            ):
                severity = _merge_severity(severity, "medium")
                indicators.append(
                    f"Executable or script artefact in a suspicious path: {_describe_row_identity(row)}"
                )

    elif plugin_name == "windows.ssdt" and rows:
        severity = "high"
        indicators.append("SSDT entries were returned and should be reviewed for hooks")

    elif plugin_name == "windows.modules":
        for row in rows:
            path = _safe_lower(_find_first(row, "Path", "File", "Name"))
            if any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS):
                severity = _merge_severity(severity, "high")
                indicators.append(
                    f"Kernel module loaded from suspicious path in {_describe_row_identity(row)}"
                )

    elif plugin_name == "windows.svcscan":
        for row in rows:
            path = _safe_lower(_find_first(row, "Binary", "BinaryPath", "Path"))
            if any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS):
                severity = _merge_severity(severity, "high")
                indicators.append(
                    f"Service binary in suspicious path: {_describe_row_identity(row)}"
                )

    elif plugin_name in {"windows.netscan", "windows.sockets"}:
        for row in rows:
            foreign_addr = _safe_lower(
                _find_first(row, "ForeignAddr", "RemoteAddr", "RemoteAddress")
            )
            owner = _safe_lower(_find_first(row, "Owner", "ImageFileName", "Process"))
            state = _safe_lower(_find_first(row, "State"))
            if foreign_addr and foreign_addr not in {"0.0.0.0", "::", "*"}:
                severity = _merge_severity(severity, "low")
            if owner in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"}:
                severity = _merge_severity(severity, "medium")
                indicators.append(
                    f"Network-capable scripting utility observed in {_describe_row_identity(row)}"
                )
            if state == "listening" and owner in {"rundll32.exe", "regsvr32.exe"}:
                severity = _merge_severity(severity, "high")
                indicators.append(
                    f"Unexpected listener process in {_describe_row_identity(row)}"
                )

    if plugin_name == "windows.psscan" and all_results:
        pslist_rows = _normalise_rows(all_results.get("windows.pslist", []))
        visible = {
            _stringify(_find_first(row, "PID", "Pid", "ProcessId")) for row in pslist_rows
        }
        hidden = []
        for row in rows:
            pid = _stringify(_find_first(row, "PID", "Pid", "ProcessId"))
            if pid and pid not in visible:
                hidden.append(row)
        if hidden:
            severity = _merge_severity(severity, "high")
            indicators.extend(
                f"Process found in psscan but not pslist: {_describe_row_identity(row)}"
                for row in hidden
            )

    summary = (
        f"{len(indicators)} suspicious indicator(s) detected"
        if indicators
        else "No obvious malicious indicators detected by current heuristics"
    )

    return {
        "plugin": plugin_name,
        "status": "analysed",
        "severity": severity,
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


def analyse_artifacts(results: Dict[str, Any]) -> Dict[str, Any]:
    plugin_findings = {
        plugin_name: analyse_plugin_output(plugin_name, plugin_result, all_results=results)
        for plugin_name, plugin_result in results.items()
    }
    timeline = build_timeline(results)

    return {
        "plugin_findings": plugin_findings,
        "risk_summary": summarise_plugin_risk(plugin_findings.values()),
        "timeline": timeline,
    }
