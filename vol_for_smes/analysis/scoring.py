"""
Shared MITRE ATT&CK tagging and internal risk scoring helpers.

The helpers in this module are intentionally rule-based so they keep working
across different memory dumps, not just the sample image used in tests.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

SEVERITY_BASE_SCORES = {
    "none": 0,
    "low": 25,
    "medium": 55,
    "high": 80,
}

MITRE_SCORES = {
    "T1055": 15,      # Process Injection
    "T1059": 10,      # Command and Scripting Interpreter
    "T1059.001": 12,  # PowerShell
    "T1036": 8,       # Masquerading
    "T1036.005": 10,  # Match Legitimate Name or Location
    "T1543.003": 15,  # Windows Service
    "T1547": 10,      # Boot or Logon Autostart Execution
    "T1564": 12,      # Hide Artifacts
    "T1562": 10,      # Impair Defenses
    "T1574": 10,      # Hijack Execution Flow
    "T1049": 8,       # System Network Connections Discovery
    "T1071": 12,      # Application Layer Protocol
    "T1105": 12,      # Ingress Tool Transfer
    "T1218": 10,      # System Binary Proxy Execution
}

MITRE_NAMES = {
    "T1036": "Masquerading",
    "T1036.005": "Match Legitimate Name or Location",
    "T1049": "System Network Connections Discovery",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1071": "Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1218": "System Binary Proxy Execution",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1547": "Boot or Logon Autostart Execution",
    "T1562": "Impair Defenses",
    "T1564": "Hide Artifacts",
    "T1574": "Hijack Execution Flow",
}

TECHNIQUE_KEYWORDS = {
    "T1036": ("masquerad",),
    "T1036.005": (
        "\\appdata\\",
        "\\temp\\",
        "\\tmp\\",
        "\\programdata\\",
        "\\users\\public\\",
        "\\perflogs\\",
        "\\recycler\\",
    ),
    "T1049": ("netscan", "sockets", "network connection", "listening", "established"),
    "T1055": ("malfind", "injected", "rwx", "executable memory", "process injection"),
    "T1059": (
        "cmd.exe",
        "powershell",
        "wscript",
        "cscript",
        "mshta",
        "command-line",
        "invoke-expression",
        "downloadstring",
        "iex ",
        "frombase64string",
        "encodedcommand",
    ),
    "T1059.001": ("powershell", " -enc", " -encodedcommand"),
    "T1071": ("foreignaddr", "remote endpoint", "remote address", "established", "close_wait"),
    "T1105": ("certutil", "bitsadmin", "downloadstring", "remote endpoint"),
    "T1218": ("rundll32", "regsvr32", "mshta", "lolbin"),
    "T1543.003": ("service binary", "svcscan", "windows service"),
    "T1547": ("autorun", "autostart", "run key", "startup"),
    "T1562": ("ssdt", "hook", "impair defenses"),
    "T1564": ("psscan but not pslist", "hidden process", "hide artifacts", "suspicious handle"),
    "T1574": ("dll loaded", "loaded dll", "module loaded", "hijack execution flow"),
}


def build_mitre_tags(technique_ids: Iterable[str]) -> List[Dict[str, str]]:
    unique_ids = []
    seen = set()
    for technique_id in technique_ids:
        if not technique_id or technique_id in seen:
            continue
        seen.add(technique_id)
        unique_ids.append(technique_id)

    return [
        {
            "technique_id": technique_id,
            "name": MITRE_NAMES.get(technique_id, "Unknown Technique"),
        }
        for technique_id in unique_ids
    ]


def calculate_risk_score(severity: str, technique_ids: Iterable[str], indicator_count: int = 0) -> int:
    score = SEVERITY_BASE_SCORES.get(severity, 0)
    score += sum(MITRE_SCORES.get(technique_id, 5) for technique_id in set(technique_ids))
    score += min(max(indicator_count, 0) * 2, 10)
    return max(0, min(100, score))


def infer_mitre_techniques(
    *,
    plugin_name: Optional[str] = None,
    texts: Optional[Iterable[str]] = None,
    process_name: Optional[str] = None,
    command_line: Optional[str] = None,
    paths: Optional[Iterable[str]] = None,
    owner: Optional[str] = None,
    state: Optional[str] = None,
) -> List[str]:
    signals = []

    if plugin_name:
        signals.append(str(plugin_name).lower())
    if process_name:
        signals.append(str(process_name).lower())
    if command_line:
        signals.append(str(command_line).lower())
    if owner:
        signals.append(str(owner).lower())
    if state:
        signals.append(str(state).lower())
    if texts:
        signals.extend(str(text).lower() for text in texts if text)
    if paths:
        signals.extend(str(path).lower() for path in paths if path)

    combined = "\n".join(signals)
    techniques = set()

    for technique_id, keywords in TECHNIQUE_KEYWORDS.items():
        if any(keyword in combined for keyword in keywords):
            techniques.add(technique_id)

    return sorted(techniques)
