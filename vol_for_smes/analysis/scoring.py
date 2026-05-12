"""
Shared scoring and MITRE ATT&CK helpers.

The process analysis pipeline now uses a score-led model. The legacy
``calculate_risk_score`` helper is kept for compatibility with the existing
plugin and network analyses.
"""

from __future__ import annotations

from ipaddress import ip_address
from typing import Iterable, List, Optional

SEVERITY_BASE_SCORES = {
    "none": 0,
    "low": 25,
    "medium": 55,
    "high": 80,
}

SEVERITY_LABELS = {
    "none": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
}

MITRE_SCORES = {
    "T1036": 8,       # Masquerading
    "T1036.005": 10,  # Match Legitimate Name or Location
    "T1049": 8,       # System Network Connections Discovery
    "T1055": 15,      # Process Injection
    "T1059": 10,      # Command and Scripting Interpreter
    "T1059.001": 12,  # PowerShell
    "T1071": 12,      # Application Layer Protocol
    "T1105": 12,      # Ingress Tool Transfer
    "T1218": 10,      # System Binary Proxy Execution
    "T1543.003": 15,  # Windows Service
    "T1547": 10,      # Boot or Logon Autostart Execution
    "T1562": 10,      # Impair Defenses
    "T1564": 12,      # Hide Artifacts
    "T1574": 10,      # Hijack Execution Flow
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

COMMON_MISSPELLINGS = {
    "svhost.exe": "Possible misspelling of svchost.exe",
    "scvhost.exe": "Possible misspelling of svchost.exe",
    "lsas.exe": "Possible misspelling of lsass.exe",
    "expl0rer.exe": "Possible misspelling of explorer.exe",
    "winlogn.exe": "Possible misspelling of winlogon.exe",
}

OFFICE_PROCESSES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
}

BROWSERS = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
}

SCRIPTING_PROCESSES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
}

LOLBIN_PROCESSES = {
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

SCRIPTING_AND_LOLBINS = SCRIPTING_PROCESSES | LOLBIN_PROCESSES

SUSPICIOUS_PATH_KEYWORDS = (
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\perflogs\\",
    "\\recycler\\",
)

SUSPICIOUS_CMD_PATTERNS = {
    "encoded PowerShell command": [
        "-enc",
        "-encodedcommand",
        "frombase64string",
    ],
    "hidden PowerShell window": [
        "-w hidden",
        "-windowstyle hidden",
    ],
    "PowerShell running without profile": [
        "-nop",
        "-noprofile",
    ],
    "execution policy bypass": [
        "-executionpolicy bypass",
        "-ep bypass",
    ],
    "download behaviour": [
        "http://",
        "https://",
        "ftp://",
        "downloadstring",
        "invoke-webrequest",
        "iwr ",
        "curl ",
        "wget ",
    ],
    "living-off-the-land binary usage": [
        "certutil",
        "bitsadmin",
        "mshta",
        "regsvr32",
        "rundll32",
    ],
}

TECHNIQUE_KEYWORDS = {
    "T1036": (
        "possible misspelling",
        "process name appears random-looking",
        "masquerad",
    ),
    "T1036.005": SUSPICIOUS_PATH_KEYWORDS,
    "T1049": ("netscan", "sockets", "network connection", "listening", "established"),
    "T1055": ("malfind", "injected", "rwx", "executable memory", "process injection"),
    "T1059": (
        "cmd.exe",
        "powershell",
        "pwsh",
        "wscript",
        "cscript",
        "command line contains",
        "hidden powershell window",
        "execution policy bypass",
    ),
    "T1059.001": ("powershell", "pwsh", " -enc", " -encodedcommand"),
    "T1071": (
        "external network connection",
        "foreignaddr",
        "remote endpoint",
        "remote address",
        "established",
        "close_wait",
    ),
    "T1105": (
        "download behaviour",
        "downloadstring",
        "invoke-webrequest",
        "curl ",
        "wget ",
        "http://",
        "https://",
        "ftp://",
    ),
    "T1218": (
        "living-off-the-land",
        "rundll32",
        "regsvr32",
        "mshta",
        "certutil",
        "bitsadmin",
        "lolbin",
    ),
    "T1543.003": ("service binary", "svcscan", "windows service"),
    "T1547": ("autorun", "autostart", "run key", "startup"),
    "T1562": ("ssdt", "hook", "impair defenses"),
    "T1564": (
        "psscan but not pslist",
        "possible hidden",
        "hidden process",
        "hidden, unlinked",
        "suspicious handle",
    ),
    "T1574": (
        "dll loaded",
        "loaded dll",
        "loaded module from a user-writable path",
        "module loaded",
        "hijack execution flow",
        "user-writable path",
    ),
}


def severity_from_score(score: int, *, title_case: bool = False) -> str:
    if score >= 70:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    elif score >= 15:
        severity = "low"
    else:
        severity = "none"

    if title_case:
        return SEVERITY_LABELS[severity]
    return severity


def score_command_line(cmdline: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    lower = str(cmdline or "").lower()

    for reason, patterns in SUSPICIOUS_CMD_PATTERNS.items():
        if any(pattern in lower for pattern in patterns):
            score += 15
            reasons.append(f"Command line contains {reason}")

    return score, reasons


def looks_random_process_name(name: str) -> bool:
    lower = str(name or "").lower().strip()
    if not lower.endswith(".exe"):
        return False

    stem = lower[:-4]
    if not 6 <= len(stem) <= 12 or not stem.isalnum():
        return False

    return any(char.isdigit() for char in stem) and any(char.isalpha() for char in stem)


def is_external_ip(ip: str) -> bool:
    text = str(ip or "").strip()
    if not text or text in {"0.0.0.0", "::", "*", "-"}:
        return False

    try:
        parsed = ip_address(text)
    except ValueError:
        return False

    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def is_suspicious_path(path: str) -> bool:
    lower = str(path or "").lower().replace("\\\\", "\\")
    return any(keyword in lower for keyword in SUSPICIOUS_PATH_KEYWORDS)


def build_mitre_tags(technique_ids: Iterable[str]) -> List[dict[str, str]]:
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


def calculate_risk_score(
    severity_or_score: str | int,
    technique_ids: Iterable[str],
    indicator_count: int = 0,
) -> int:
    if isinstance(severity_or_score, (int, float)):
        score = int(severity_or_score)
    else:
        score = SEVERITY_BASE_SCORES.get(str(severity_or_score), 0)

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

    combined = "\n".join(signals).replace("\\\\", "\\")
    techniques = set()

    for technique_id, keywords in TECHNIQUE_KEYWORDS.items():
        if any(keyword in combined for keyword in keywords):
            techniques.add(technique_id)

    return sorted(techniques)
