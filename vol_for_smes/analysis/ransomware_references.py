"""
Offline ransomware note and extension references used by the analysis layer.

The packaged CSV resources are loaded with ``importlib.resources`` so the same
reference data is available from source checkouts, wheels, and the Windows
bundle.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from fnmatch import fnmatch
from functools import lru_cache
from importlib import resources
import re
from typing import Any, Iterable

from .scoring import basename_from_path, normalise_path, normalise_short_path

REFERENCE_NOTE_FILE = "ransomware_notes_list.csv"
REFERENCE_PATTERN_FILE = "extensions.csv"

_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
_WILDCARD_PATTERN = re.compile(r"[*?\[]")
_EDGE_DECORATION_PATTERN = re.compile(r"^[^a-z0-9]+|[^a-z0-9]+$")
_GENERIC_REFERENCE_TOKENS = {
    "a",
    "all",
    "back",
    "data",
    "decrypt",
    "decryption",
    "encrypted",
    "file",
    "files",
    "help",
    "html",
    "how",
    "instructions",
    "message",
    "note",
    "read",
    "readme",
    "recover",
    "recovery",
    "restore",
    "save",
    "txt",
    "unlock",
    "url",
    "your",
}

_SKIPPED_REFERENCE_PATTERNS = {
    ("ransomware_file_patterns", "suffix", "*.dll"),
    ("ransomware_file_patterns", "suffix", "*.lock"),
    ("ransomware_file_patterns", "glob", "*crypt*"),
}

_PROCESS_IMAGE_SUFFIXES = (".exe", ".scr", ".com")


def _looks_like_path_pattern(value: str) -> bool:
    entry = _normalise_entry(value)
    return (
        "\\" in entry
        or "/" in entry
        or entry.startswith("\\device\\")
        or re.match(r"^[a-z]:\\", entry) is not None
    )


@dataclass(frozen=True)
class ReferencePattern:
    source: str
    match_type: str
    pattern: str
    score: int
    confidence: str
    metadata: dict[str, str]


@dataclass(frozen=True)
class ReferenceIndex:
    exact_patterns: tuple[ReferencePattern, ...]
    glob_patterns: tuple[ReferencePattern, ...]
    suffix_patterns: tuple[ReferencePattern, ...]


def _normalise_entry(value: Any) -> str:
    return str(value or "").replace("\ufeff", "").replace("\xa0", " ").strip().lower()


def _read_note_entries() -> list[tuple[str, dict[str, str]]]:
    csv_path = resources.files(__package__).joinpath(REFERENCE_NOTE_FILE)
    with csv_path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        entries = []
        for row in reader:
            pattern = _normalise_entry(row.get("file_name"))
            if not pattern:
                continue
            metadata = {
                "description": _normalise_entry(row.get("metadata_description")),
                "reference_url": str(row.get("metadata_link") or "").strip(),
            }
            entries.append((pattern, metadata))
        return entries


def _read_extension_entries() -> list[tuple[str, dict[str, str]]]:
    csv_path = resources.files(__package__).joinpath(REFERENCE_PATTERN_FILE)
    with csv_path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)
        entries = []
        for row in reader:
            if not row:
                continue
            pattern = _normalise_entry(row[0])
            if not pattern:
                continue
            entries.append((pattern, {}))
        return entries


def _classify_pattern(source: str, entry: str) -> str:
    if not entry:
        return "exact"

    if _WILDCARD_PATTERN.search(entry):
        if (
            entry.startswith("*.")
            and entry.count("*") == 1
            and "?" not in entry
            and "[" not in entry
        ):
            return "suffix"
        return "glob"

    if entry.startswith(".") or entry.startswith("_"):
        return "suffix"

    return "exact"


def _pattern_specificity(pattern: str) -> int:
    return len("".join(_TOKEN_PATTERN.findall(pattern)))


def _keyword_density(pattern: str) -> int:
    tokens = [token for token in _TOKEN_PATTERN.findall(pattern) if token]
    if not tokens:
        return 0

    distinctive_tokens = [
        token for token in tokens
        if token not in _GENERIC_REFERENCE_TOKENS and len(token) >= 4
    ]
    return len(distinctive_tokens)


def _score_pattern(source: str, match_type: str, pattern: str) -> int:
    specificity = _pattern_specificity(pattern)
    distinctive_count = _keyword_density(pattern)

    if source == "ransomware_note_names":
        if match_type == "glob":
            return 28 if specificity >= 10 else 24
        if match_type == "suffix":
            return 20
        return 30 if specificity >= 8 else 24

    if match_type == "suffix":
        return 18 if specificity >= 4 else 10

    if match_type == "glob":
        return 18 if distinctive_count >= 1 or specificity >= 10 else 12

    if distinctive_count >= 1:
        return 18
    if specificity >= 10:
        return 12
    return 8


def _confidence_from_score(score: int) -> str:
    if score >= 24:
        return "high"
    if score >= 18:
        return "medium"
    return "low"


def _build_patterns(
    source: str,
    entries: Iterable[tuple[str, dict[str, str]]],
) -> list[ReferencePattern]:
    patterns: list[ReferencePattern] = []
    for entry, metadata in entries:
        match_type = _classify_pattern(source, entry)
        if (source, match_type, entry) in _SKIPPED_REFERENCE_PATTERNS:
            continue
        score = _score_pattern(source, match_type, entry)
        patterns.append(
            ReferencePattern(
                source=source,
                match_type=match_type,
                pattern=entry,
                score=score,
                confidence=_confidence_from_score(score),
                metadata=metadata,
            )
        )
    return patterns


@lru_cache(maxsize=1)
def load_ransomware_reference_index() -> ReferenceIndex:
    note_entries = _read_note_entries()
    pattern_entries = _read_extension_entries()

    deduped: dict[tuple[str, str, str], ReferencePattern] = {}
    for pattern in _build_patterns("ransomware_note_names", note_entries) + _build_patterns(
        "ransomware_file_patterns",
        pattern_entries,
    ):
        deduped[(pattern.source, pattern.match_type, pattern.pattern)] = pattern

    exact_patterns = []
    glob_patterns = []
    suffix_patterns = []
    for pattern in sorted(
        deduped.values(),
        key=lambda item: (item.source, item.match_type, item.pattern),
    ):
        if pattern.match_type == "glob":
            glob_patterns.append(pattern)
        elif pattern.match_type == "suffix":
            suffix_patterns.append(pattern)
        else:
            exact_patterns.append(pattern)

    return ReferenceIndex(
        exact_patterns=tuple(exact_patterns),
        glob_patterns=tuple(glob_patterns),
        suffix_patterns=tuple(suffix_patterns),
    )


def _path_candidates(path: str) -> dict[str, str]:
    normalised = normalise_path(path)
    short_path = normalise_short_path(path)
    basename = basename_from_path(normalised)
    short_basename = basename_from_path(short_path)

    return {
        "path": normalised,
        "basename": basename,
        "short_path": short_path,
        "short_basename": short_basename,
    }


def _build_hit(
    pattern: ReferencePattern,
    *,
    path: str,
    scope: str,
) -> dict[str, str | int | dict[str, str]]:
    return {
        "source": pattern.source,
        "match_type": pattern.match_type,
        "pattern": pattern.pattern,
        "confidence": pattern.confidence,
        "score": pattern.score,
        "match_scope": scope,
        "path": path,
        "basename": basename_from_path(path),
        "metadata": dict(pattern.metadata),
    }


def _strip_known_suffix(value: str, suffixes: tuple[str, ...]) -> str:
    for suffix in suffixes:
        if value.endswith(suffix):
            return value[: -len(suffix)]
    return value


def _reference_name_core(value: str) -> str:
    basename = basename_from_path(value)
    if not basename:
        return ""
    stem = _strip_known_suffix(basename, _PROCESS_IMAGE_SUFFIXES)
    return _EDGE_DECORATION_PATTERN.sub("", stem)


def _candidate_scopes(pattern: ReferencePattern) -> tuple[str, ...]:
    if pattern.match_type == "suffix":
        return ("basename", "short_basename")

    if _looks_like_path_pattern(pattern.pattern):
        return ("path", "short_path", "basename", "short_basename")

    return ("basename", "short_basename")


def match_ransomware_references(path: str) -> list[dict[str, str | int | dict[str, str]]]:
    candidates = _path_candidates(path)
    normalised_path = candidates["path"]
    if not normalised_path:
        return []

    index = load_ransomware_reference_index()
    hits: list[dict[str, str | int | dict[str, str]]] = []
    seen = set()

    for pattern in index.exact_patterns:
        for scope in _candidate_scopes(pattern):
            candidate = candidates.get(scope, "")
            if not candidate:
                continue
            if candidate == pattern.pattern or candidate.endswith(f"\\{pattern.pattern}"):
                dedupe_key = (pattern.source, pattern.match_type, pattern.pattern, scope)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                hits.append(_build_hit(pattern, path=normalised_path, scope=scope))
                break

    for pattern in index.glob_patterns:
        for scope in _candidate_scopes(pattern):
            candidate = candidates.get(scope, "")
            if not candidate:
                continue
            if fnmatch(candidate, pattern.pattern):
                dedupe_key = (pattern.source, pattern.match_type, pattern.pattern, scope)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                hits.append(_build_hit(pattern, path=normalised_path, scope=scope))
                break

    for pattern in index.suffix_patterns:
        suffix = pattern.pattern[1:] if pattern.pattern.startswith("*") else pattern.pattern
        for scope in _candidate_scopes(pattern):
            candidate = candidates.get(scope, "")
            if not candidate:
                continue
            if candidate.endswith(suffix):
                dedupe_key = (pattern.source, pattern.match_type, pattern.pattern, scope)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                hits.append(_build_hit(pattern, path=normalised_path, scope=scope))
                break

    hits.sort(
        key=lambda item: (
            -int(item.get("score", 0)),
            str(item.get("source", "")),
            str(item.get("pattern", "")),
        )
    )
    return hits


def match_ransomware_process_name(name: str) -> list[dict[str, str | int | dict[str, str]]]:
    basename = basename_from_path(name)
    if not basename:
        return []

    candidate_core = _reference_name_core(basename)
    if not candidate_core:
        return []

    index = load_ransomware_reference_index()
    hits: list[dict[str, str | int | dict[str, str]]] = []
    seen = set()

    for pattern in index.exact_patterns:
        if pattern.source != "ransomware_note_names":
            continue

        pattern_basename = basename_from_path(pattern.pattern)
        if not pattern_basename.endswith(_PROCESS_IMAGE_SUFFIXES):
            continue

        scope = ""
        if basename == pattern_basename:
            scope = "process_name"
        elif candidate_core == _reference_name_core(pattern_basename):
            scope = "process_name_core"
        else:
            continue

        dedupe_key = (pattern.source, pattern.match_type, pattern.pattern, scope)
        if dedupe_key in seen:
            continue

        seen.add(dedupe_key)
        hits.append(_build_hit(pattern, path=basename, scope=scope))

    hits.sort(
        key=lambda item: (
            -int(item.get("score", 0)),
            str(item.get("source", "")),
            str(item.get("pattern", "")),
        )
    )
    return hits
