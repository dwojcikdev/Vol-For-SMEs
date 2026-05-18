"""
Shared scoring, path normalisation, and MITRE ATT&CK helpers.

The process analysis pipeline now uses stable internal rule identifiers first and
falls back to keyword inference only when a detector has not yet been migrated.
"""

from __future__ import annotations

import re
from ipaddress import ip_address
from typing import Any, Iterable, List, Mapping, Optional, Sequence

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

ATTACK_SNAPSHOT = {
    "source": "MITRE ATT&CK STIX",
    "collection": "Enterprise ATT&CK",
    "version": "18.1",
    "modified": "2025-11-13T14:00:00.188Z",
    "index_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json",
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
    "T1486": 18,      # Data Encrypted for Impact
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
    "T1486": "Data Encrypted for Impact",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1547": "Boot or Logon Autostart Execution",
    "T1562": "Impair Defenses",
    "T1564": "Hide Artifacts",
    "T1574": "Hijack Execution Flow",
}

RULE_MITRE_MAP = {
    "autorun_registry_key": ("T1547",),
    "cmdline_download": ("T1105",),
    "cmdline_encoded": ("T1059", "T1059.001"),
    "cmdline_execution_policy_bypass": ("T1059", "T1059.001"),
    "cmdline_hidden_window": ("T1059", "T1059.001"),
    "cmdline_lolbin": ("T1218",),
    "cmdline_no_profile": ("T1059", "T1059.001"),
    "hidden_process_psscan_only": ("T1564",),
    "kernel_module_user_writable": ("T1574",),
    "malfind_injected_memory": ("T1055",),
    "module_user_writable": ("T1574",),
    "network_external_connection": ("T1071",),
    "network_lolbin_listener": ("T1218",),
    "network_shell_external": ("T1071", "T1059"),
    "process_name_misspelling": ("T1036",),
    "process_name_random": ("T1036",),
    "process_parent_browser_lolbin": ("T1059", "T1218"),
    "process_parent_office_lolbin": ("T1059", "T1218"),
    "process_reference_file": ("T1486",),
    "process_reference_handle": ("T1486",),
    "process_reference_image": ("T1486",),
    "process_reference_name": ("T1486",),
    "process_user_writable_image": ("T1036.005",),
    "ransomware_reference_note": ("T1486",),
    "ransomware_reference_pattern": ("T1486",),
    "service_user_writable_binary": ("T1543.003",),
    "unusual_lsass_parent": ("T1036.005",),
    "unusual_svchost_parent": ("T1036.005",),
    "user_writable_executable_artifact": ("T1036.005",),
    "user_writable_handle_executable": ("T1036.005",),
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

SUSPICIOUS_EXECUTABLE_PATTERNS = (
    ".ps1",
    ".vbs",
    ".js",
    ".hta",
    ".bat",
    ".cmd",
    ".dll",
    ".exe",
    ".ocx",
    ".scr",
    ".com",
)

SUSPICIOUS_MODULE_PATTERNS = (
    ".dll",
    ".ocx",
    ".cpl",
)

USER_WRITABLE_PATH_KEYWORDS = (
    "\\users\\",
    "\\documents and settings\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\",
    "\\desktop\\",
    "\\downloads\\",
    "\\documents\\",
    "\\pictures\\",
    "\\music\\",
    "\\videos\\",
    "\\public\\",
    "\\recycle.bin\\",
    "\\recycler\\",
    "\\perflogs\\",
)

SUSPICIOUS_REGISTRY_RUN_KEY_PATTERNS = (
    "\\software\\microsoft\\windows\\currentversion\\run",
    "\\software\\microsoft\\windows\\currentversion\\runonce",
    "\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
)

TRUSTED_SOFTWARE_PATH_PATTERNS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\windows\\systemapps\\",
    "\\program files\\windowsapps\\microsoft.",
    "\\program files\\windowsapps\\microsoft\\",
    "\\programdata\\microsoft\\",
    "\\appdata\\local\\microsoft\\",
    "\\appdata\\local\\packages\\microsoft.",
    "\\appdata\\roaming\\microsoft\\",
)

COMMAND_LINE_RULES = (
    {
        "rule_id": "cmdline_encoded",
        "reason": "encoded PowerShell command",
        "patterns": ("-enc", "-encodedcommand", "frombase64string"),
        "score": 15,
    },
    {
        "rule_id": "cmdline_hidden_window",
        "reason": "hidden PowerShell window",
        "patterns": ("-w hidden", "-windowstyle hidden"),
        "score": 15,
    },
    {
        "rule_id": "cmdline_no_profile",
        "reason": "PowerShell running without profile",
        "patterns": ("-nop", "-noprofile"),
        "score": 15,
    },
    {
        "rule_id": "cmdline_execution_policy_bypass",
        "reason": "execution policy bypass",
        "patterns": ("-executionpolicy bypass", "-ep bypass"),
        "score": 15,
    },
    {
        "rule_id": "cmdline_download",
        "reason": "download behaviour",
        "patterns": (
            "http://",
            "https://",
            "ftp://",
            "downloadstring",
            "invoke-webrequest",
            "iwr ",
            "curl ",
            "wget ",
        ),
        "score": 15,
    },
    {
        "rule_id": "cmdline_lolbin",
        "reason": "living-off-the-land binary usage",
        "patterns": ("certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"),
        "score": 15,
    },
)

TECHNIQUE_KEYWORDS = {
    "T1036": (
        "possible misspelling",
        "process name appears random-looking",
        "masquerad",
    ),
    "T1036.005": (
        "executable or script artefact in a suspicious path",
        "executable or script handle target in a suspicious path",
        "user-writable executable",
    ),
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
    "T1486": (
        "ransomware-related file artefact",
        "ransom note",
        "decrypt",
        "recover",
        "restore_files",
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
        "loaded module from a high-risk path",
        "module loaded",
        "hijack execution flow",
        "user-writable path",
    ),
}

_DEVICE_PREFIX_RE = re.compile(r"^\\\\\?\\|^\\\?\\")
_TILDE_SEGMENT_RE = re.compile(r"~\d+")


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


def normalise_path(path: str) -> str:
    text = str(path or "").strip().strip("\"'")
    if not text:
        return ""

    text = text.replace("/", "\\")
    text = _DEVICE_PREFIX_RE.sub("", text)
    while "\\\\" in text:
        text = text.replace("\\\\", "\\")
    return text.lower()


def basename_from_path(path: str) -> str:
    normalised = normalise_path(path)
    if not normalised:
        return ""
    return normalised.rsplit("\\", 1)[-1]


def normalise_short_path(path: str) -> str:
    normalised = normalise_path(path)
    if not normalised:
        return ""
    parts = [
        _TILDE_SEGMENT_RE.sub("", segment)
        for segment in normalised.split("\\")
    ]
    return "\\".join(part for part in parts if part)


def extract_command_line_image(command_line: str) -> str:
    text = str(command_line or "").strip()
    if not text:
        return ""

    if text[0] in {'"', "'"}:
        quote = text[0]
        end_index = text.find(quote, 1)
        if end_index > 1:
            return normalise_path(text[1:end_index])

    first_token = text.split(" ", 1)[0]
    return normalise_path(first_token)


def analyse_command_line(command_line: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    lower = str(command_line or "").lower()

    for rule in COMMAND_LINE_RULES:
        if any(pattern in lower for pattern in rule["patterns"]):
            matches.append(
                {
                    "rule_id": rule["rule_id"],
                    "reason": f"Command line contains {rule['reason']}",
                    "score": int(rule["score"]),
                }
            )

    return matches


def score_command_line(cmdline: str) -> tuple[int, list[str]]:
    matches = analyse_command_line(cmdline)
    return (
        sum(int(match["score"]) for match in matches),
        [str(match["reason"]) for match in matches],
    )


def looks_random_process_name(name: str) -> bool:
    lower = basename_from_path(name)
    if not lower:
        return False

    if "." in lower:
        stem, ext = lower.rsplit(".", 1)
        if f".{ext}" in SUSPICIOUS_EXECUTABLE_PATTERNS:
            lower = stem

    lower = lower.strip()
    if not lower or not lower.isalnum():
        return False

    if len(lower) >= 12 and all(char in "0123456789abcdef" for char in lower):
        return True

    if not 6 <= len(lower) <= 20:
        return False

    digit_count = sum(char.isdigit() for char in lower)
    alpha_count = sum(char.isalpha() for char in lower)
    vowel_count = sum(char in "aeiou" for char in lower)

    return digit_count >= 2 and alpha_count >= 4 and vowel_count <= max(1, alpha_count // 5)


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


def is_user_writable_path(path: str) -> bool:
    lower = normalise_path(path)
    if not lower:
        return False
    if any(pattern in lower for pattern in TRUSTED_SOFTWARE_PATH_PATTERNS):
        return False
    return any(keyword in lower for keyword in USER_WRITABLE_PATH_KEYWORDS)


def is_suspicious_path(path: str) -> bool:
    return is_user_writable_path(path)


def _matches_any_suffix(path: str, suffixes: Iterable[str]) -> bool:
    lower = normalise_path(path)
    if not lower:
        return False

    candidates = [lower]
    basename = basename_from_path(lower)
    short_path = normalise_short_path(lower)
    short_basename = basename_from_path(short_path)

    if basename:
        candidates.append(basename)
    if short_path and short_path not in candidates:
        candidates.append(short_path)
    if short_basename and short_basename not in candidates:
        candidates.append(short_basename)

    if " " in lower:
        truncated = lower.split(" ", 1)[0]
        candidates.append(truncated.strip("\"'"))
        truncated_basename = basename_from_path(truncated)
        if truncated_basename:
            candidates.append(truncated_basename)

    return any(candidate.endswith(suffix) for candidate in candidates for suffix in suffixes)


def is_suspicious_executable_path(path: str) -> bool:
    return is_user_writable_path(path) and _matches_any_suffix(
        path,
        SUSPICIOUS_EXECUTABLE_PATTERNS,
    )


def is_suspicious_module_path(path: str) -> bool:
    return is_user_writable_path(path) and _matches_any_suffix(
        path,
        SUSPICIOUS_MODULE_PATTERNS,
    )


def is_suspicious_registry_run_key(path: str) -> bool:
    lower = normalise_path(path)
    return any(pattern in lower for pattern in SUSPICIOUS_REGISTRY_RUN_KEY_PATTERNS)


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


def techniques_for_rule_ids(rule_ids: Iterable[str]) -> list[str]:
    techniques = []
    seen = set()
    for rule_id in rule_ids:
        for technique_id in RULE_MITRE_MAP.get(str(rule_id or ""), ()):
            if technique_id in seen:
                continue
            seen.add(technique_id)
            techniques.append(technique_id)
    return techniques


def merge_rule_techniques(
    rule_ids: Iterable[str],
    *,
    fallback_techniques: Optional[Iterable[str]] = None,
) -> list[str]:
    technique_ids = techniques_for_rule_ids(rule_ids)
    seen = set(technique_ids)

    for technique_id in fallback_techniques or ():
        if not technique_id or technique_id in seen:
            continue
        seen.add(technique_id)
        technique_ids.append(str(technique_id))

    return technique_ids


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
        signals.extend(normalise_path(path) for path in paths if path)

    combined = "\n".join(signals)
    techniques = set()

    for technique_id, keywords in TECHNIQUE_KEYWORDS.items():
        if any(keyword in combined for keyword in keywords):
            techniques.add(technique_id)

    return sorted(techniques)


def is_ransomware_artifact_path(path: str) -> bool:
    from .ransomware_references import match_ransomware_references

    hits = match_ransomware_references(path)
    if not hits:
        return False

    best_score = max(int(hit.get("score", 0)) for hit in hits)
    if best_score >= 18:
        return True

    return is_user_writable_path(path) and sum(
        int(hit.get("score", 0)) for hit in hits[:3]
    ) >= 24
