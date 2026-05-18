"""
Higher-level process-focused analysis built from multiple Volatility plugins.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..utils.helpers import extract_rows
from .ransomware_references import (
    match_ransomware_process_name,
    match_ransomware_references,
)
from .scoring import (
    BROWSERS,
    COMMON_MISSPELLINGS,
    LOLBIN_PROCESSES,
    OFFICE_PROCESSES,
    SCRIPTING_AND_LOLBINS,
    SCRIPTING_PROCESSES,
    analyse_command_line,
    basename_from_path,
    build_mitre_tags,
    extract_command_line_image,
    infer_mitre_techniques,
    is_external_ip,
    is_ransomware_artifact_path,
    is_suspicious_executable_path,
    is_suspicious_module_path,
    is_suspicious_registry_run_key,
    is_user_writable_path,
    looks_random_process_name,
    merge_rule_techniques,
    normalise_path,
    severity_from_score,
    SUSPICIOUS_EXECUTABLE_PATTERNS,
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
        "rule_ids": [],
        "reference_hits": [],
        "file_hits": [],
        "handle_hits": [],
        "chain_id": "",
        "evidence": {"process_rows": []},
        "command_line": "",
        "mitre_tags": [],
    }


def _append_reason(process: Dict[str, Any], reason: str) -> None:
    if reason and reason not in process["reasons"]:
        process["reasons"].append(reason)


def _append_rule_id(process: Dict[str, Any], rule_id: str) -> None:
    if rule_id and rule_id not in process["rule_ids"]:
        process["rule_ids"].append(rule_id)


def _add_scored_reason(process: Dict[str, Any], *, score: int, reason: str, rule_id: str) -> None:
    process["score"] += int(score)
    _append_reason(process, reason)
    _append_rule_id(process, rule_id)


def _append_evidence(process: Dict[str, Any], key: str, value: Any) -> None:
    if key.endswith("_rows") or key.endswith("_hits") or key.endswith("_connections"):
        process["evidence"].setdefault(key, []).append(value)
    else:
        process["evidence"][key] = value


def _reference_match_score(
    reference_hits: List[Dict[str, Any]],
    *,
    image_context: bool = False,
) -> int:
    has_note_reference = any(
        hit.get("source") == "ransomware_note_names"
        for hit in reference_hits
    )
    best_score = max((int(hit.get("score", 0)) for hit in reference_hits), default=0)

    if has_note_reference:
        return 60 if image_context else 45
    if best_score >= 24:
        return 45 if image_context else 35
    if best_score >= 18:
        return 35 if image_context else 30
    return 25 if image_context else 25


def _looks_like_process_image_path(value: Any) -> bool:
    candidate = _stringify(value)
    normalised = normalise_path(candidate)
    if not normalised or normalised in {"-", "n/a"}:
        return False

    has_path_shape = (
        ":\\" in normalised
        or normalised.startswith("\\device\\")
        or normalised.startswith("\\users\\")
        or normalised.startswith("\\windows\\")
        or normalised.startswith("\\program files")
        or normalised.startswith("\\programdata\\")
    )
    if not has_path_shape:
        return False

    return any(normalised.endswith(suffix) for suffix in SUSPICIOUS_EXECUTABLE_PATTERNS)


def _extract_seed_image_path(row: Dict[str, Any]) -> str:
    for key in ("Path", "path", "ImagePathName", "ExecutablePath", "FullPath", "Audit"):
        candidate = _stringify(_find_first(row, key))
        if _looks_like_process_image_path(candidate):
            return candidate

    for key in ("Cmd", "CommandLine", "Command Line", "Args"):
        command_line = _stringify(_find_first(row, key))
        image_path = extract_command_line_image(command_line)
        if image_path:
            return image_path

    return ""


def _path_related_to_process(path: str, process: Dict[str, Any]) -> bool:
    normalised_path = normalise_path(path)
    if not normalised_path:
        return False

    evidence = process.get("evidence", {})
    candidates = set()

    image_path = _stringify(evidence.get("image_path"))
    if image_path:
        candidates.add(normalise_path(image_path))

    image_from_command = extract_command_line_image(process.get("command_line", ""))
    if image_from_command:
        candidates.add(image_from_command)

    for item in evidence.get("dll_paths", []):
        if isinstance(item, dict) and item.get("path"):
            candidates.add(normalise_path(item["path"]))

    if normalised_path in candidates:
        return True

    basename = basename_from_path(normalised_path)
    return any(basename and basename == basename_from_path(candidate) for candidate in candidates)


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

        path = _extract_seed_image_path(row)
        if path and not processes[pid]["evidence"].get("image_path"):
            _append_evidence(processes[pid], "image_path", path)

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

        _add_scored_reason(
            process,
            score=40,
            reason="Found by psscan but not pslist; possible hidden, unlinked, or terminated process",
            rule_id="hidden_process_psscan_only",
        )
        _append_evidence(process, "psscan_not_pslist", True)


def _apply_process_name_score(processes: Dict[int, Dict[str, Any]]) -> None:
    for process in processes.values():
        name = _safe_lower(process.get("name"))
        reference_hits = match_ransomware_process_name(name)

        if reference_hits:
            structured_hit = {
                "pid": process.get("pid"),
                "path": normalise_path(name),
                "row_identity": _process_label(process),
                "reference_hits": reference_hits,
                "pattern": reference_hits[0]["pattern"],
                "confidence": reference_hits[0]["confidence"],
                "match_scope": reference_hits[0]["match_scope"],
                "rule_ids": [
                    "process_reference_name",
                    "ransomware_reference_note",
                ],
            }
            process["reference_hits"].append(structured_hit)
            _append_evidence(process, "name_reference_hits", structured_hit)
            _add_scored_reason(
                process,
                score=_reference_match_score(reference_hits, image_context=True),
                reason="Process name matches a known ransomware executable reference",
                rule_id="process_reference_name",
            )
            _append_rule_id(process, "ransomware_reference_note")

        if name in COMMON_MISSPELLINGS:
            _add_scored_reason(
                process,
                score=25,
                reason=COMMON_MISSPELLINGS[name],
                rule_id="process_name_misspelling",
            )
        elif looks_random_process_name(name):
            _add_scored_reason(
                process,
                score=15,
                reason="Process name appears random-looking",
                rule_id="process_name_random",
            )


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
            _add_scored_reason(
                process,
                score=30,
                reason=f"{child} was launched by Office process {parent}",
                rule_id="process_parent_office_lolbin",
            )

        if parent in BROWSERS and child in SCRIPTING_AND_LOLBINS:
            _add_scored_reason(
                process,
                score=25,
                reason=f"{child} was launched by browser process {parent}",
                rule_id="process_parent_browser_lolbin",
            )

        if child == "svchost.exe" and parent != "services.exe":
            _add_scored_reason(
                process,
                score=30,
                reason="svchost.exe has an unusual parent process",
                rule_id="unusual_svchost_parent",
            )

        if child == "lsass.exe" and parent not in {"wininit.exe", "smss.exe"}:
            _add_scored_reason(
                process,
                score=30,
                reason="lsass.exe has an unusual parent process",
                rule_id="unusual_lsass_parent",
            )


def _apply_image_path_score(processes: Dict[int, Dict[str, Any]]) -> None:
    for process in processes.values():
        evidence = process.get("evidence", {})
        image_path = _stringify(evidence.get("image_path"))
        if not image_path:
            image_path = extract_command_line_image(process.get("command_line", ""))
            if image_path:
                _append_evidence(process, "image_path", image_path)

        if image_path:
            reference_hits = match_ransomware_references(image_path)
            if reference_hits:
                structured_hit = {
                    "pid": process.get("pid"),
                    "path": normalise_path(image_path),
                    "row_identity": _process_label(process),
                    "reference_hits": reference_hits,
                    "pattern": reference_hits[0]["pattern"],
                    "confidence": reference_hits[0]["confidence"],
                    "match_scope": reference_hits[0]["match_scope"],
                    "rule_ids": [
                        "process_reference_image",
                        "ransomware_reference_note"
                        if any(hit.get("source") == "ransomware_note_names" for hit in reference_hits)
                        else "ransomware_reference_pattern",
                    ],
                }
                process["reference_hits"].append(structured_hit)
                _append_evidence(process, "image_reference_hits", structured_hit)

                _add_scored_reason(
                    process,
                    score=_reference_match_score(reference_hits, image_context=True),
                    reason="Process image matches ransomware reference data",
                    rule_id="process_reference_image",
                )
                if any(hit.get("source") == "ransomware_note_names" for hit in reference_hits):
                    _append_rule_id(process, "ransomware_reference_note")
                else:
                    _append_rule_id(process, "ransomware_reference_pattern")

        if image_path and is_suspicious_executable_path(image_path):
            _add_scored_reason(
                process,
                score=20,
                reason="Process image path is user-writable and executable",
                rule_id="process_user_writable_image",
            )


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
        _append_evidence(process, "command_line", command_line)

        image_path = extract_command_line_image(command_line)
        if image_path and not process["evidence"].get("image_path"):
            _append_evidence(process, "image_path", image_path)

        for match in analyse_command_line(command_line):
            _add_scored_reason(
                process,
                score=int(match["score"]),
                reason=str(match["reason"]),
                rule_id=str(match["rule_id"]),
            )


def _apply_dlllist_score(
    processes: Dict[int, Dict[str, Any]],
    dlllist_rows: List[Dict[str, Any]],
) -> None:
    scored_paths = set()

    for row in dlllist_rows:
        pid = _safe_int(_find_first(row, "PID", "Pid", "pid", "ProcessId"))
        if pid is None or pid not in processes:
            continue

        path = _stringify(_find_first(row, "Path", "FullPath", "LoadPath"))
        if not is_suspicious_module_path(path):
            continue

        process = processes[pid]
        normalised_path = normalise_path(path)
        if (pid, normalised_path) not in scored_paths:
            _add_scored_reason(
                process,
                score=20,
                reason="Process loaded module from a high-risk path",
                rule_id="module_user_writable",
            )
            scored_paths.add((pid, normalised_path))

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
            _add_scored_reason(
                process,
                score=45,
                reason="malfind reported possible injected executable memory",
                rule_id="malfind_injected_memory",
            )
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
                _add_scored_reason(
                    process,
                    score=25,
                    reason=f"{process_name} has an external network connection",
                    rule_id="network_shell_external",
                )
            else:
                _add_scored_reason(
                    process,
                    score=10,
                    reason="Process has an external network connection",
                    rule_id="network_external_connection",
                )
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


def _apply_handle_score(
    processes: Dict[int, Dict[str, Any]],
    handle_rows: List[Dict[str, Any]],
) -> None:
    scored_paths = set()

    for row in handle_rows:
        pid = _safe_int(_find_first(row, "PID", "Pid", "pid", "ProcessId"))
        if pid is None or pid not in processes:
            continue

        process = processes[pid]
        handle_name = _stringify(_find_first(row, "Name", "Details", "Path"))
        handle_type = _safe_lower(_find_first(row, "Type", "ObjectType"))

        if handle_type == "file":
            reference_hits = match_ransomware_references(handle_name)
            if reference_hits:
                structured_hit = {
                    "pid": pid,
                    "path": normalise_path(handle_name),
                    "row_identity": _process_label(process),
                    "reference_hits": reference_hits,
                    "pattern": reference_hits[0]["pattern"],
                    "confidence": reference_hits[0]["confidence"],
                    "match_scope": reference_hits[0]["match_scope"],
                    "rule_ids": [
                        "process_reference_handle",
                        "ransomware_reference_note"
                        if any(hit.get("source") == "ransomware_note_names" for hit in reference_hits)
                        else "ransomware_reference_pattern",
                    ],
                }
                process["reference_hits"].append(structured_hit)
                process["handle_hits"].append(structured_hit)
                _append_evidence(process, "handle_hits", structured_hit)

                scored_key = (pid, structured_hit["path"])
                if scored_key not in scored_paths:
                    _add_scored_reason(
                        process,
                        score=_reference_match_score(reference_hits),
                        reason="Process holds a file handle that matches ransomware reference data",
                        rule_id="process_reference_handle",
                    )
                    if any(hit.get("source") == "ransomware_note_names" for hit in reference_hits):
                        _append_rule_id(process, "ransomware_reference_note")
                    else:
                        _append_rule_id(process, "ransomware_reference_pattern")
                    scored_paths.add(scored_key)
            elif is_suspicious_executable_path(handle_name):
                scored_key = (pid, normalise_path(handle_name))
                if scored_key not in scored_paths:
                    _add_scored_reason(
                        process,
                        score=15,
                        reason="Process references an executable or script in a user-writable path",
                        rule_id="user_writable_handle_executable",
                    )
                    scored_paths.add(scored_key)

        if handle_type == "key" and is_suspicious_registry_run_key(handle_name):
            _add_scored_reason(
                process,
                score=20,
                reason="Process references an autorun registry location",
                rule_id="autorun_registry_key",
            )


def _apply_file_reference_score(
    processes: Dict[int, Dict[str, Any]],
    file_rows: List[Dict[str, Any]],
) -> None:
    for row in file_rows:
        path = _stringify(_find_first(row, "Name", "Path", "FilePath", "File"))
        if not path:
            continue

        reference_hits = match_ransomware_references(path)
        if not reference_hits and not is_ransomware_artifact_path(path):
            continue

        structured_hit = {
            "pid": None,
            "path": normalise_path(path),
            "row_identity": basename_from_path(path),
            "reference_hits": reference_hits,
            "pattern": reference_hits[0]["pattern"] if reference_hits else "",
            "confidence": reference_hits[0]["confidence"] if reference_hits else "low",
            "match_scope": reference_hits[0]["match_scope"] if reference_hits else "",
            "rule_ids": [
                "process_reference_file",
                "ransomware_reference_note"
                if any(hit.get("source") == "ransomware_note_names" for hit in reference_hits)
                else "ransomware_reference_pattern",
            ],
        }

        for process in processes.values():
            if not _path_related_to_process(path, process):
                continue
            process["reference_hits"].append(structured_hit)
            process["file_hits"].append(structured_hit)
            _append_evidence(process, "file_hits", structured_hit)
            if reference_hits:
                _add_scored_reason(
                    process,
                    score=_reference_match_score(reference_hits),
                    reason="Process correlates with ransomware-related file activity",
                    rule_id="process_reference_file",
                )
                if any(hit.get("source") == "ransomware_note_names" for hit in reference_hits):
                    _append_rule_id(process, "ransomware_reference_note")
                else:
                    _append_rule_id(process, "ransomware_reference_pattern")


def _build_process_techniques(process: Dict[str, Any]) -> List[str]:
    evidence = process.get("evidence", {})
    paths = [
        item.get("path", "")
        for item in evidence.get("dll_paths", [])
        if isinstance(item, dict)
    ]
    paths.extend(hit.get("path", "") for hit in process.get("reference_hits", []))
    texts = list(process.get("reasons", []))

    if evidence.get("network_connections"):
        texts.append("external network connection")
    if process.get("name") in LOLBIN_PROCESSES:
        texts.append("living-off-the-land binary usage")

    fallback = infer_mitre_techniques(
        plugin_name="process_analysis",
        texts=texts,
        process_name=process.get("name"),
        command_line=process.get("command_line"),
        paths=paths,
    )

    return merge_rule_techniques(process.get("rule_ids", []), fallback_techniques=fallback)


def build_suspicious_process_findings(
    results: Dict[str, Any],
) -> List[Dict[str, Any]]:
    pslist_rows = _normalise_rows(results.get("windows.pslist", []))
    psscan_rows = _normalise_rows(results.get("windows.psscan", []))
    pstree_rows = _normalise_rows(results.get("windows.pstree", []))
    cmdline_rows = _normalise_rows(results.get("windows.cmdline", []))
    dlllist_rows = _normalise_rows(results.get("windows.dlllist", []))
    malfind_rows = _normalise_rows(results.get("windows.malfind", []))
    handle_rows = _normalise_rows(results.get("windows.handles", []))
    file_rows = _normalise_rows(results.get("windows.filescan", [])) + _normalise_rows(
        results.get("windows.shimcache", [])
    )
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
    _apply_image_path_score(processes)
    _apply_dlllist_score(processes, dlllist_rows)
    _apply_malfind_score(processes, malfind_rows)
    _apply_network_score(processes, network_rows)
    _apply_handle_score(processes, handle_rows)
    _apply_file_reference_score(processes, file_rows)

    findings = []
    for process in processes.values():
        score = int(process.get("score", 0))
        if score <= 0:
            continue

        process["severity"] = severity_from_score(score)
        if process["severity"] == "none":
            continue

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
                "rule_ids": list(process.get("rule_ids", [])),
                "reasons": list(process.get("reasons", [])),
                "command_line": process.get("command_line", ""),
                "reference_hits": list(process.get("reference_hits", [])),
                "file_hits": list(process.get("file_hits", [])),
                "handle_hits": list(process.get("handle_hits", [])),
                "chain_id": process.get("chain_id", ""),
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
