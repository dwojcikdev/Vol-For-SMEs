"""
Correlate suspicious process, file, handle, and timeline evidence into higher
confidence activity chains.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .scoring import (
    basename_from_path,
    build_mitre_tags,
    extract_command_line_image,
    infer_mitre_techniques,
    merge_rule_techniques,
    normalise_path,
    severity_from_score,
)


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _stringify(value: Any) -> str:
    return str(value or "").strip()


def _process_label(process: Dict[str, Any]) -> str:
    return f"{process.get('name') or 'unknown'} (PID {process.get('pid') or '?'})"


def _hit_identity(hit: Dict[str, Any]) -> tuple[Any, ...]:
    return (
        _safe_int(hit.get("pid")),
        normalise_path(hit.get("path", "")),
        _stringify(hit.get("pattern")).lower(),
        _stringify(hit.get("match_scope")).lower(),
        _stringify(hit.get("row_identity")).lower(),
    )


def _normalise_hit(hit: Dict[str, Any], *, default_plugin: str = "") -> dict[str, Any]:
    enriched = dict(hit)
    if default_plugin and not enriched.get("plugin"):
        enriched["plugin"] = default_plugin
    path = _stringify(enriched.get("path"))
    if path:
        enriched["path"] = normalise_path(path)
    return enriched


def _append_unique_hit(
    target: list[dict[str, Any]],
    seen: set[tuple[Any, ...]],
    hit: Dict[str, Any],
    *,
    default_plugin: str = "",
) -> bool:
    if not isinstance(hit, dict):
        return False

    enriched = _normalise_hit(hit, default_plugin=default_plugin)
    identity = _hit_identity(enriched)
    if identity in seen:
        return False

    seen.add(identity)
    target.append(enriched)
    return True


def _collect_reference_hits(plugin_findings: Dict[str, Dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for plugin_name, finding in plugin_findings.items():
        for hit in finding.get("reference_hits", []):
            if not isinstance(hit, dict):
                continue
            hits.append(_normalise_hit(hit, default_plugin=plugin_name))
    return hits


def _collect_process_hits(
    related_processes: Iterable[Dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    reference_hits: list[dict[str, Any]] = []
    file_hits: list[dict[str, Any]] = []
    handle_hits: list[dict[str, Any]] = []
    seen_reference_hits: set[tuple[Any, ...]] = set()
    seen_file_hits: set[tuple[Any, ...]] = set()
    seen_handle_hits: set[tuple[Any, ...]] = set()

    for process in related_processes:
        for hit in process.get("reference_hits", []):
            _append_unique_hit(
                reference_hits,
                seen_reference_hits,
                hit,
                default_plugin="process_analysis",
            )
        for hit in process.get("file_hits", []):
            _append_unique_hit(
                file_hits,
                seen_file_hits,
                hit,
                default_plugin="process_analysis",
            )
        for hit in process.get("handle_hits", []):
            _append_unique_hit(
                handle_hits,
                seen_handle_hits,
                hit,
                default_plugin="process_analysis",
            )

    return reference_hits, file_hits, handle_hits


def _path_related_to_process(path: str, process: Dict[str, Any]) -> bool:
    normalised_path = normalise_path(path)
    if not normalised_path:
        return False

    evidence = process.get("evidence", {}) if isinstance(process.get("evidence"), dict) else {}
    candidates = set()

    image_path = _stringify(evidence.get("image_path"))
    if image_path:
        candidates.add(normalise_path(image_path))

    command_line = _stringify(process.get("command_line"))
    image_from_command = extract_command_line_image(command_line)
    if image_from_command:
        candidates.add(image_from_command)

    for item in evidence.get("dll_paths", []):
        if isinstance(item, dict) and item.get("path"):
            candidates.add(normalise_path(item["path"]))

    if normalised_path in candidates:
        return True

    basename = basename_from_path(normalised_path)
    return any(basename and basename == basename_from_path(candidate) for candidate in candidates)


def _build_reference_evidence_line(hit: Dict[str, Any]) -> str:
    path = _stringify(hit.get("path"))
    pattern = _stringify(hit.get("pattern"))
    plugin = _stringify(hit.get("plugin")) or "process_analysis"
    scope = _stringify(hit.get("match_scope"))
    confidence = _stringify(hit.get("confidence"))
    if not pattern:
        return (
            f"{plugin} correlated suspicious file activity "
            f"({confidence or 'low'}, {scope or 'path'}) for {path}"
        )
    return (
        f"{plugin} matched ransomware reference '{pattern}' "
        f"({confidence}, {scope}) for {path}"
    )


def build_activity_chains(
    process_analysis: Dict[str, Any],
    plugin_findings: Dict[str, Dict[str, Any]],
    timeline: Iterable[Dict[str, Any]],
) -> list[dict[str, Any]]:
    suspicious_processes = [
        process
        for process in process_analysis.get("suspicious_processes", [])
        if isinstance(process, dict)
    ]
    if not suspicious_processes:
        return []

    process_index = {}
    for process in suspicious_processes:
        pid = _safe_int(process.get("pid"))
        if pid is None:
            continue
        process_index[pid] = process

    reference_hits = _collect_reference_hits(plugin_findings)
    assigned_pids = set()
    chains = []

    for process in sorted(
        suspicious_processes,
        key=lambda item: -int(item.get("risk_score", 0)),
    ):
        primary_pid = _safe_int(process.get("pid"))
        if primary_pid is None or primary_pid in assigned_pids:
            continue

        related_pids = {primary_pid}
        changed = True
        while changed:
            changed = False
            for pid, candidate in process_index.items():
                parent_pid = _safe_int(candidate.get("ppid"))
                if pid in related_pids:
                    continue
                if parent_pid in related_pids:
                    related_pids.add(pid)
                    changed = True

        related_processes = [
            process_index[pid]
            for pid in sorted(related_pids)
            if pid in process_index
        ]
        assigned_pids.update(related_pids)

        process_reference_hits, process_file_hits, process_handle_hits = _collect_process_hits(
            related_processes
        )
        seen_reference_hits = {_hit_identity(hit) for hit in process_reference_hits}
        seen_file_hits = {_hit_identity(hit) for hit in process_file_hits}
        seen_handle_hits = {_hit_identity(hit) for hit in process_handle_hits}

        for hit in reference_hits:
            hit_pid = _safe_int(hit.get("pid"))
            if hit_pid is not None and hit_pid in related_pids:
                if _append_unique_hit(process_reference_hits, seen_reference_hits, hit):
                    plugin_name = _stringify(hit.get("plugin")).lower()
                    if "handles" in plugin_name:
                        _append_unique_hit(process_handle_hits, seen_handle_hits, hit)
                    elif "filescan" in plugin_name or "shimcache" in plugin_name:
                        _append_unique_hit(process_file_hits, seen_file_hits, hit)
                continue

            if any(_path_related_to_process(hit.get("path", ""), item) for item in related_processes):
                if _append_unique_hit(process_reference_hits, seen_reference_hits, hit):
                    plugin_name = _stringify(hit.get("plugin")).lower()
                    if "handles" in plugin_name:
                        _append_unique_hit(process_handle_hits, seen_handle_hits, hit)
                    else:
                        _append_unique_hit(process_file_hits, seen_file_hits, hit)

        timeline_entries = []
        file_basenames = {
            basename_from_path(hit.get("path", ""))
            for hit in process_reference_hits
            if hit.get("path")
        }
        seen_events = set()
        for event in timeline:
            if not isinstance(event, dict):
                continue
            event_pid = _safe_int(event.get("pid"))
            description = _stringify(event.get("description"))
            event_key = (
                _stringify(event.get("timestamp")),
                description,
                _stringify(event.get("pid")),
            )
            if event_key in seen_events:
                continue
            if event_pid in related_pids:
                seen_events.add(event_key)
                timeline_entries.append(event)
                continue
            if any(basename and basename in description.lower() for basename in file_basenames):
                seen_events.add(event_key)
                timeline_entries.append(event)

        rule_ids = set(process.get("rule_ids", []))
        reference_evidence_lines = []
        seen_reference_lines = set()
        for hit in process_reference_hits:
            rule_ids.update(hit.get("rule_ids", []))
            line = _build_reference_evidence_line(hit)
            if line not in seen_reference_lines:
                seen_reference_lines.add(line)
                reference_evidence_lines.append(line)

        reason_lines = list(process.get("reasons", []))

        for related_process in related_processes:
            rule_ids.update(related_process.get("rule_ids", []))
            if related_process is process:
                continue
            reasons = related_process.get("reasons", [])
            if reasons:
                reason_lines.append(
                    f"{_process_label(related_process)}: {', '.join(reasons[:2])}"
                )

        evidence_lines = reference_evidence_lines + reason_lines

        fallback_techniques = []
        for related_process in related_processes:
            fallback_techniques.extend(
                tag.get("technique_id", "")
                for tag in related_process.get("mitre_tags", [])
                if isinstance(tag, dict)
            )

        fallback_techniques.extend(
            infer_mitre_techniques(
                plugin_name="activity_chain",
                texts=evidence_lines,
                process_name=process.get("name"),
                command_line=process.get("command_line"),
                paths=[hit.get("path", "") for hit in process_reference_hits],
            )
        )

        activity_bonus = min(
            len(process_reference_hits) * 8
            + max(len(related_processes) - 1, 0) * 5,
            25,
        )
        risk_score = min(100, int(process.get("risk_score", 0)) + activity_bonus)
        technique_ids = merge_rule_techniques(rule_ids, fallback_techniques=fallback_techniques)

        summary = (
            f"{_process_label(process)} formed a suspicious activity chain with "
            f"{max(len(related_processes) - 1, 0)} related process(es) and "
            f"{len(process_reference_hits)} supporting artefact match(es)."
        )

        chains.append(
            {
                "chain_id": f"chain-{primary_pid}",
                "title": f"Correlated activity chain: {_process_label(process)}",
                "summary": summary,
                "severity": severity_from_score(risk_score),
                "risk_score": risk_score,
                "primary_process": process,
                "related_processes": related_processes,
                "reference_hits": process_reference_hits,
                "file_hits": process_file_hits,
                "handle_hits": process_handle_hits,
                "timeline": timeline_entries,
                "rule_ids": sorted(rule_ids),
                "mitre_tags": build_mitre_tags(technique_ids),
                "evidence": evidence_lines[:10],
            }
        )

    chains.sort(
        key=lambda item: (
            -int(item.get("risk_score", 0)),
            item.get("chain_id", ""),
        )
    )
    return chains


def build_suspicious_timeline(
    activity_chains: Iterable[Dict[str, Any]],
    timeline: Iterable[Dict[str, Any]],
) -> list[dict[str, Any]]:
    chain_events = []
    seen = set()

    for chain in activity_chains:
        for event in chain.get("timeline", []):
            if not isinstance(event, dict):
                continue
            event_key = (
                _stringify(event.get("timestamp")),
                _stringify(event.get("description")),
                _stringify(event.get("pid")),
            )
            if event_key in seen:
                continue
            seen.add(event_key)
            chain_events.append(event)

    if chain_events:
        chain_events.sort(key=lambda item: _stringify(item.get("timestamp")))
        return chain_events

    return [event for event in timeline if isinstance(event, dict)]
