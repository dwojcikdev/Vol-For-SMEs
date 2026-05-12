"""
Build human-readable forensic reports from analysis output.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, List, Optional

SEVERITY_LABELS = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "Informational",
}

TECHNIQUE_EXPLANATIONS = {
    "T1036": {
        "attack": "Masquerading",
        "meaning": "The artefact may be trying to look benign by copying a trusted name, path, or appearance.",
        "remediations": [
            "Validate the file's publisher, hash, and expected installation path.",
            "Compare the artefact against a known-good copy from the affected host or golden image.",
            "Remove or quarantine the disguised binary if it is not approved software.",
        ],
    },
    "T1036.005": {
        "attack": "Match Legitimate Name or Location",
        "meaning": "An executable or script was found in a path often abused to blend in with normal user activity.",
        "remediations": [
            "Review whether the file is expected in that directory and verify ownership.",
            "Collect the file for malware scanning and hash-based reputation checks.",
            "Block repeated execution from user-writable directories where appropriate.",
        ],
    },
    "T1049": {
        "attack": "System Network Connections Discovery",
        "meaning": "The activity may indicate reconnaissance intended to understand what network connections or listeners are present.",
        "remediations": [
            "Review adjacent processes and user activity for signs of hands-on-keyboard exploration.",
            "Restrict unnecessary administrative tooling on the host.",
            "Increase monitoring for follow-on discovery or lateral movement behaviour.",
        ],
    },
    "T1055": {
        "attack": "Process Injection",
        "meaning": "Code may have been inserted into another process to hide execution, steal data, or evade controls.",
        "remediations": [
            "Capture the affected process memory and preserve the host for deeper investigation.",
            "Isolate the endpoint and reset credentials used on the system if compromise is suspected.",
            "Reimage or rebuild the system if malicious injection is confirmed.",
        ],
    },
    "T1059": {
        "attack": "Command and Scripting Interpreter",
        "meaning": "An attacker may be using built-in scripting tools to execute payloads, download content, or automate actions.",
        "remediations": [
            "Review command-line history, parent-child process relationships, and user context.",
            "Constrain scripting engines with application control or allowlisting where possible.",
            "Disable or restrict unnecessary scripting interpreters on sensitive systems.",
        ],
    },
    "T1059.001": {
        "attack": "PowerShell",
        "meaning": "PowerShell may have been used for execution, download, lateral movement, or in-memory payload delivery.",
        "remediations": [
            "Review PowerShell logs, transcription, and AMSI/EDR telemetry if available.",
            "Look for encoded commands, downloaded content, and child process creation.",
            "Apply constrained language mode or execution policy controls where suitable.",
        ],
    },
    "T1071": {
        "attack": "Application Layer Protocol",
        "meaning": "Suspicious traffic may be using normal network protocols to communicate with remote systems or command infrastructure.",
        "remediations": [
            "Inspect the remote endpoints, associated domains, and firewall or proxy logs.",
            "Block confirmed malicious destinations and monitor for repeated contact attempts.",
            "Correlate the connection with the owning process and any downloaded content.",
        ],
    },
    "T1105": {
        "attack": "Ingress Tool Transfer",
        "meaning": "The host may have been used to download or receive attacker tools or additional payloads.",
        "remediations": [
            "Review browser, proxy, and command execution artefacts for downloaded files.",
            "Quarantine retrieved binaries and scan them in a controlled environment.",
            "Harden egress controls to reduce opportunistic tool transfer.",
        ],
    },
    "T1218": {
        "attack": "System Binary Proxy Execution",
        "meaning": "A legitimate Windows utility may be abused to launch or proxy malicious behaviour.",
        "remediations": [
            "Confirm whether the binary's invocation is consistent with approved software usage.",
            "Review the command line, loaded modules, and spawned child processes.",
            "Apply allowlisting and detection rules for known LOLBin abuse patterns.",
        ],
    },
    "T1543.003": {
        "attack": "Create or Modify System Process: Windows Service",
        "meaning": "A Windows service may have been used for persistence or privileged execution.",
        "remediations": [
            "Review the service configuration, binary path, account, and recent changes.",
            "Disable and remove malicious services after preserving evidence.",
            "Investigate how the service was created and whether additional persistence exists.",
        ],
    },
    "T1547": {
        "attack": "Boot or Logon Autostart Execution",
        "meaning": "An artefact may be configured to run automatically when the system starts or a user logs on.",
        "remediations": [
            "Inspect registry run keys, startup folders, and scheduled task configuration.",
            "Remove unauthorised persistence after preserving relevant artefacts.",
            "Review other persistence mechanisms on the same host.",
        ],
    },
    "T1562": {
        "attack": "Impair Defenses",
        "meaning": "The activity may be attempting to weaken security tooling or tamper with operating system protections.",
        "remediations": [
            "Validate kernel structures, hooks, and security product health on the endpoint.",
            "Rebuild or restore the host if kernel tampering is confirmed.",
            "Review surrounding activity for privilege escalation or persistence attempts.",
        ],
    },
    "T1564": {
        "attack": "Hide Artifacts",
        "meaning": "Processes, files, or handles may be concealed to make malicious activity harder to detect.",
        "remediations": [
            "Cross-check findings with multiple data sources and preserve the memory image.",
            "Perform deeper rootkit-focused investigation if hidden objects are confirmed.",
            "Isolate the host because hidden artefacts often indicate advanced compromise.",
        ],
    },
    "T1574": {
        "attack": "Hijack Execution Flow",
        "meaning": "A malicious library or module may be placed where a trusted process can load it.",
        "remediations": [
            "Verify DLL search order abuse, side-loading opportunities, and file provenance.",
            "Remove malicious modules and repair affected application installs.",
            "Harden file permissions on user-writable paths used by trusted applications.",
        ],
    },
}


def _severity_rank(level: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(level, 0)


def _severity_label(level: str) -> str:
    return SEVERITY_LABELS.get(level, level.title() if level else "Unknown")


def _normalise_severity(level: str) -> str:
    lowered = str(level or "").strip().lower()
    if lowered in SEVERITY_LABELS:
        return lowered
    return "none"


def _coerce_dict(value: Any) -> Dict[str, Any]:
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return dict(value)
    return {}


def _coerce_list_of_dicts(values: Any) -> List[Dict[str, Any]]:
    items = []
    for value in values or []:
        item = _coerce_dict(value)
        if item:
            items.append(item)
    return items


def _top_mitre_details(mitre_tags: Iterable[Dict[str, str]]) -> List[Dict[str, Any]]:
    details = []
    for tag in mitre_tags:
        technique_id = tag.get("technique_id", "")
        info = TECHNIQUE_EXPLANATIONS.get(technique_id)
        if not info:
            continue
        details.append(
            {
                "technique_id": technique_id,
                "name": tag.get("name", info["attack"]),
                "attack": info["attack"],
                "meaning": info["meaning"],
                "remediations": info["remediations"],
            }
        )
    return details


def _compose_meaning(summary: str, mitre_tags: Iterable[Dict[str, str]]) -> str:
    details = _top_mitre_details(mitre_tags)
    if details:
        return details[0]["meaning"]
    if summary:
        return f"This result deserves review because the analysis heuristics flagged: {summary.lower()}."
    return "This result should be reviewed by an analyst for context and business impact."


def _compose_attack_name(mitre_tags: Iterable[Dict[str, str]], fallback: str) -> str:
    details = _top_mitre_details(mitre_tags)
    if details:
        return details[0]["attack"]
    return fallback


def _compose_remediations(
    mitre_tags: Iterable[Dict[str, str]],
    *,
    extra_steps: Optional[Iterable[str]] = None,
) -> List[str]:
    steps = []
    seen = set()

    for detail in _top_mitre_details(mitre_tags):
        for step in detail["remediations"]:
            if step not in seen:
                seen.add(step)
                steps.append(step)

    for step in extra_steps or ():
        if step and step not in seen:
            seen.add(step)
            steps.append(step)

    if not steps:
        steps.extend(
            [
                "Preserve the affected host and memory image for follow-up investigation.",
                "Validate the finding against endpoint telemetry, logs, and approved software records.",
                "Contain the host if multiple suspicious findings point to active compromise.",
            ]
        )

    return steps[:6]


def _format_mitre_list(mitre_tags: Iterable[Dict[str, str]]) -> List[str]:
    return [
        f"{tag.get('technique_id', 'Unknown')} - {tag.get('name', 'Unknown Technique')}"
        for tag in mitre_tags
    ]


def _evidence_to_lines(evidence: Any) -> List[str]:
    if not evidence:
        return []

    if isinstance(evidence, dict):
        lines = []
        for key, value in evidence.items():
            label = str(key).replace("_", " ")
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        parts = [
                            f"{sub_key}={sub_value}"
                            for sub_key, sub_value in item.items()
                            if sub_key != "raw" and sub_value not in (None, "", [], {})
                        ]
                        lines.append(f"{label}: {', '.join(parts)}" if parts else label)
                    elif item not in (None, ""):
                        lines.append(f"{label}: {item}")
            elif isinstance(value, dict):
                parts = [
                    f"{sub_key}={sub_value}"
                    for sub_key, sub_value in value.items()
                    if sub_key != "raw" and sub_value not in (None, "", [], {})
                ]
                lines.append(f"{label}: {', '.join(parts)}" if parts else label)
            elif value not in (None, ""):
                lines.append(f"{label}: {value}")
        return lines

    if isinstance(evidence, (list, tuple, set)):
        return [str(item) for item in evidence if item not in (None, "")]

    return [str(evidence)]


def _build_finding_entry(
    *,
    title: str,
    category: str,
    severity: str,
    risk_score: int,
    summary: str,
    evidence: Iterable[str],
    mitre_tags: Iterable[Dict[str, str]],
    fallback_attack: str,
    extra_remediations: Optional[Iterable[str]] = None,
    affected_asset: Optional[str] = None,
) -> Dict[str, Any]:
    mitre_tags = list(mitre_tags)
    evidence = [str(item) for item in evidence if item]
    return {
        "title": title,
        "category": category,
        "severity": severity,
        "severity_label": _severity_label(severity),
        "risk_score": risk_score,
        "summary": summary,
        "affected_asset": affected_asset or "",
        "attack": _compose_attack_name(mitre_tags, fallback_attack),
        "meaning": _compose_meaning(summary, mitre_tags),
        "mitre": _format_mitre_list(mitre_tags),
        "evidence": evidence[:8],
        "remediations": _compose_remediations(
            mitre_tags,
            extra_steps=extra_remediations,
        ),
    }


def _top_findings(plugin_findings: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    interesting = [
        finding
        for finding in plugin_findings.values()
        if finding.get("severity") in {"high", "medium"}
    ]
    interesting.sort(
        key=lambda item: (
            -_severity_rank(item.get("severity", "none")),
            -int(item.get("risk_score", 0)),
            item.get("plugin", ""),
        )
    )
    return interesting


def _build_plugin_finding_entries(plugin_findings: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    entries = []
    for finding in _top_findings(plugin_findings):
        entries.append(
            _build_finding_entry(
                title=finding.get("plugin", "Unknown plugin"),
                category="Plugin Finding",
                severity=finding.get("severity", "none"),
                risk_score=int(finding.get("risk_score", 0)),
                summary=finding.get("summary", ""),
                evidence=finding.get("indicators", []),
                mitre_tags=finding.get("mitre_tags", []),
                fallback_attack="Suspicious forensic artefact",
                extra_remediations=[
                    "Review the full plugin output to confirm whether the indicator reflects malicious behaviour or legitimate administration.",
                ],
            )
        )
    return entries


def _build_process_finding_entries(process_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries = []
    for process in process_analysis.get("suspicious_processes", []):
        name = process.get("name") or "unknown process"
        pid = process.get("pid") or "?"
        entries.append(
            _build_finding_entry(
                title=f"Suspicious process: {name} (PID {pid})",
                category="Process Finding",
                severity=process.get("severity", "none"),
                risk_score=int(process.get("risk_score", 0)),
                summary=", ".join(process.get("reasons", [])) or process_analysis.get("summary", ""),
                evidence=process.get("reasons", []),
                mitre_tags=process.get("mitre_tags", []),
                fallback_attack="Suspicious process behaviour",
                extra_remediations=[
                    "Review the process parent, command line, loaded modules, and associated user account.",
                    "Collect the process binary and any referenced scripts for malware analysis.",
                ],
                affected_asset=f"{name} (PID {pid})",
            )
        )
    return entries


def _build_network_finding_entries(network_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries = []
    for connection in network_analysis.get("suspicious_connections", []):
        owner = connection.get("owner") or "unknown process"
        pid = connection.get("pid") or "?"
        local = f"{connection.get('local_address') or '?'}:{connection.get('local_port') or '?'}"
        remote = f"{connection.get('remote_address') or '?'}:{connection.get('remote_port') or '?'}"
        entries.append(
            _build_finding_entry(
                title=f"Suspicious network activity: {owner} (PID {pid})",
                category="Network Finding",
                severity=connection.get("severity", "none"),
                risk_score=int(connection.get("risk_score", 0)),
                summary=", ".join(connection.get("reasons", [])) or network_analysis.get("summary", ""),
                evidence=[f"{local} -> {remote} ({connection.get('state') or 'unknown state'})"] + list(connection.get("reasons", [])),
                mitre_tags=connection.get("mitre_tags", []),
                fallback_attack="Suspicious network communication",
                extra_remediations=[
                    "Check whether the remote endpoint is known, internal, or already blocked by security controls.",
                    "Review proxy, DNS, and firewall logs for related traffic from the same host.",
                ],
                affected_asset=f"{owner} (PID {pid})",
            )
        )
    return entries


def _looks_like_triage_report(analysis: Any) -> bool:
    if is_dataclass(analysis):
        analysis = asdict(analysis)

    return isinstance(analysis, dict) and {
        "memory_image",
        "output_directory",
        "clamav_available",
        "volatility_results",
        "process_findings",
        "findings",
    }.issubset(analysis.keys())


def _summarise_triage_risk(
    triage_findings: List[Dict[str, Any]],
    process_findings: List[Dict[str, Any]],
) -> Dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "none": 0}

    for finding in triage_findings:
        counts[_normalise_severity(finding.get("severity"))] += 1

    for process in process_findings:
        counts[_normalise_severity(process.get("severity"))] += 1

    return counts


def _aggregate_mitre_tags(items: Iterable[Dict[str, Any]]) -> List[Dict[str, str]]:
    tags = []
    seen = set()

    for item in items:
        for tag in item.get("mitre_tags", []) or []:
            technique_id = str(tag.get("technique_id", "")).strip()
            if not technique_id or technique_id in seen:
                continue
            seen.add(technique_id)
            tags.append(
                {
                    "technique_id": technique_id,
                    "name": str(tag.get("name", "Unknown Technique")),
                }
            )

    return tags


def _build_triage_summary_entries(triage_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    entries = []
    for finding in triage_findings:
        summary = str(finding.get("description", "") or finding.get("title", ""))
        evidence = list(finding.get("reasons", [])) + _evidence_to_lines(finding.get("evidence", {}))
        entries.append(
            _build_finding_entry(
                title=str(finding.get("title", "Triage finding")),
                category="Triage Finding",
                severity=_normalise_severity(finding.get("severity")),
                risk_score=int(finding.get("score", 0)),
                summary=summary,
                evidence=evidence,
                mitre_tags=finding.get("mitre_tags", []),
                fallback_attack="Known malware triage finding",
            )
        )
    return entries


def _normalise_triage_processes(process_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalised = []
    for process in process_findings:
        normalised.append(
            {
                "name": process.get("name") or "unknown process",
                "pid": str(process.get("pid") or "?"),
                "ppid": str(process.get("parent_pid") or ""),
                "parent_name": process.get("parent_name") or "",
                "severity": _normalise_severity(process.get("severity")),
                "score": int(process.get("score", 0)),
                "risk_score": int(process.get("score", 0)),
                "mitre_tags": list(process.get("mitre_tags", [])),
                "reasons": list(process.get("reasons", [])),
                "evidence": dict(process.get("evidence", {})),
            }
        )
    return normalised


def _build_triage_process_analysis(process_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    suspicious_processes = _normalise_triage_processes(process_findings)
    overall_score = max((item.get("risk_score", 0) for item in suspicious_processes), default=0)
    overall_severity = "none"
    if suspicious_processes:
        overall_severity = max(
            (item.get("severity", "none") for item in suspicious_processes),
            key=_severity_rank,
        )

    return {
        "summary": (
            f"{len(suspicious_processes)} suspicious process(es) identified"
            if suspicious_processes
            else "No suspicious process behaviour identified"
        ),
        "severity": overall_severity,
        "score": overall_score,
        "risk_score": overall_score,
        "mitre_tags": _aggregate_mitre_tags(suspicious_processes),
        "suspicious_processes": suspicious_processes,
    }


def _build_triage_report(
    triage_report: Any,
    *,
    case_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    triage_data = _coerce_dict(triage_report)
    triage_findings = _coerce_list_of_dicts(triage_data.get("findings", []))
    process_findings = _coerce_list_of_dicts(triage_data.get("process_findings", []))
    process_analysis = _build_triage_process_analysis(process_findings)
    findings = _sort_findings(
        _build_triage_summary_entries(triage_findings)
        + _build_process_finding_entries(process_analysis)
    )

    case_metadata = dict(case_metadata or {})
    case_metadata.setdefault("memory_image", triage_data.get("memory_image", ""))
    case_metadata.setdefault("output_directory", triage_data.get("output_directory", ""))
    case_metadata.setdefault("clamav_available", triage_data.get("clamav_available", False))

    clamav_hits = _coerce_list_of_dicts(triage_data.get("clamav_hits", []))
    risk_summary = _summarise_triage_risk(triage_findings, process_findings)

    executive_summary = [
        (
            "The known malware triage identified "
            f"{risk_summary.get('high', 0)} high, {risk_summary.get('medium', 0)} medium, "
            f"{risk_summary.get('low', 0)} low, and {risk_summary.get('none', 0)} informational findings."
        ),
        (
            f"{len(clamav_hits)} known malware signature hit(s) were detected in dumped artefacts."
            if clamav_hits
            else (
                "ClamAV was available but no known malware signatures were detected."
                if triage_data.get("clamav_available")
                else "ClamAV was not available during triage."
            )
        ),
        process_analysis.get("summary", "No process summary available."),
    ]

    if findings:
        top_finding = findings[0]
        executive_summary.append(
            f"The most urgent result is '{top_finding['title']}' with {top_finding['severity_label'].lower()} severity and risk score {top_finding['risk_score']}."
        )

    return {
        "title": case_metadata.get("title", "Vol For SMEs Known Malware Triage Report"),
        "case_metadata": case_metadata,
        "risk_summary": risk_summary,
        "executive_summary": executive_summary,
        "findings": findings,
        "timeline": [],
        "process_analysis": process_analysis,
        "network_analysis": {
            "summary": "No standalone network analysis view was generated for known malware triage.",
            "severity": "none",
            "risk_score": 0,
            "mitre_tags": [],
            "suspicious_connections": [],
        },
        "plugin_findings": {},
        "triage_findings": triage_findings,
        "clamav_hits": clamav_hits,
    }


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            -_severity_rank(item.get("severity", "none")),
            -int(item.get("risk_score", 0)),
            item.get("title", ""),
        ),
    )


def _executive_summary(analysis: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[str]:
    risk_summary = analysis.get("risk_summary", {})
    process_analysis = analysis.get("process_analysis", {})
    network_analysis = analysis.get("network_analysis", {})
    timeline = analysis.get("timeline", [])

    lines = [
        (
            "The memory analysis identified "
            f"{risk_summary.get('high', 0)} high, {risk_summary.get('medium', 0)} medium, "
            f"{risk_summary.get('low', 0)} low, and {risk_summary.get('none', 0)} informational plugin outcomes."
        ),
        process_analysis.get("summary", "No process summary available."),
        network_analysis.get("summary", "No network summary available."),
    ]

    if findings:
        top_finding = findings[0]
        lines.append(
            f"The most urgent result is '{top_finding['title']}' with {top_finding['severity_label'].lower()} severity and risk score {top_finding['risk_score']}."
        )

    if timeline:
        lines.append(f"{len(timeline)} timestamped artefact(s) were available to support timeline reconstruction.")

    return lines


def build_analysis_report(
    analysis: Any,
    *,
    case_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convert the structured analysis output into a richer reporting model.
    """
    if _looks_like_triage_report(analysis):
        return _build_triage_report(analysis, case_metadata=case_metadata)

    analysis = _coerce_dict(analysis)
    case_metadata = dict(case_metadata or {})
    plugin_entries = _build_plugin_finding_entries(analysis.get("plugin_findings", {}))
    process_entries = _build_process_finding_entries(analysis.get("process_analysis", {}))
    network_entries = _build_network_finding_entries(analysis.get("network_analysis", {}))
    findings = _sort_findings(plugin_entries + process_entries + network_entries)

    return {
        "title": case_metadata.get("title", "Vol For SMEs Memory Analysis Report"),
        "case_metadata": case_metadata,
        "risk_summary": analysis.get("risk_summary", {}),
        "executive_summary": _executive_summary(analysis, findings),
        "findings": findings,
        "timeline": analysis.get("timeline", []),
        "process_analysis": analysis.get("process_analysis", {}),
        "network_analysis": analysis.get("network_analysis", {}),
        "plugin_findings": analysis.get("plugin_findings", {}),
    }
