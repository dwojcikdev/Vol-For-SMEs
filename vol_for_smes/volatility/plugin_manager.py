"""
Plugin catalog, preset, and discovery helpers for Vol For SMEs.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Sequence

from .command_resolver import build_volatility_command, resolve_volatility_command

# Dictionary of common Volatility plugins with simple descriptions
# Designed for users with limited memory forensics knowledge.
PLUGINS = {
    "windows.pslist": "Show running processes remembered in memory.",
    "windows.psscan": "Find processes by scanning memory directly, even if hidden.",
    "windows.pstree": "Show parent-child process relationships to help spot suspicious launches.",
    "windows.dlllist": "List loaded DLLs for each process to help spot suspicious modules.",
    "windows.cmdline": "Show the command line used to start each process.",
    "windows.handles": "List open files, registry keys, and other objects used by processes.",
    "windows.netscan": "Find network connections from memory to see active communication.",
    "windows.sockets": "List network sockets in use by programs.",
    "windows.filescan": "Scan memory for file objects, useful when files are hidden or deleted.",
    "windows.malfind": "Look for suspicious code inside processes that may indicate malware.",
    "windows.vadinfo": "Show memory regions allocated by a process to understand its memory usage.",
    "windows.ssdt": "Show system call hooks that can reveal kernel-level tampering.",
    "windows.modules": "List loaded kernel modules and drivers from memory.",
    "windows.shimcache": "Read application compatibility cache entries to see programs that ran.",
    "windows.svcscan": "List Windows services and their status from memory.",
    "windows.getsids": "Show security identifiers for processes, useful for checking account use.",
}


# Plugin groups for common investigation workflows.
PLUGIN_GROUPS = {
    "process_analysis": [
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.cmdline",
        "windows.dlllist",
        "windows.malfind",
        "windows.netscan",
    ],
    "network_analysis": [
        "windows.netscan",
        "windows.sockets",
    ],
    "malware_analysis": [
        "windows.malfind",
        "windows.vadinfo",
        "windows.handles",
    ],
    "system_analysis": [
        "windows.modules",
        "windows.ssdt",
        "windows.svcscan",
        "windows.getsids",
    ],
    "file_activity": [
        "windows.filescan",
        "windows.shimcache",
    ],
    # Default investigation used by Vol For SMEs.
    "default_investigation": [
        "windows.pslist",
        "windows.psscan",
        "windows.pstree",
        "windows.cmdline",
        "windows.netscan",
        "windows.malfind",
        "windows.dlllist",
        "windows.handles",
    ],
}

DEFAULT_PLUGIN_GROUP_NAME = "default_investigation"

SCORED_PLUGINS = {
    "windows.cmdline",
    "windows.dlllist",
    "windows.filescan",
    "windows.handles",
    "windows.malfind",
    "windows.modules",
    "windows.netscan",
    "windows.psscan",
    "windows.shimcache",
    "windows.sockets",
    "windows.ssdt",
    "windows.svcscan",
}

CONTEXT_PLUGINS = {
    "windows.pslist",
    "windows.pstree",
}

PLUGIN_LINE_PATTERN = re.compile(r"^ {4}(\S+?)(?: {2,}(.*\S))?\s*$")
PLUGIN_CONTINUATION_PATTERN = re.compile(r"^ {20,}(.*\S)\s*$")


@dataclass(frozen=True)
class PluginInfo:
    name: str
    description: str = ""
    source: str = "curated"
    os_family: str = "unknown"
    support_level: str = "runnable_only"
    aliases: tuple[str, ...] = ()


def _infer_os_family(plugin_name: str) -> str:
    prefix = str(plugin_name or "").split(".", 1)[0].lower()
    if prefix in {"windows", "linux", "mac"}:
        return prefix
    return "cross-platform"


def _support_level(plugin_name: str) -> str:
    if plugin_name in SCORED_PLUGINS:
        return "scored"
    if plugin_name in CONTEXT_PLUGINS:
        return "context"
    return "runnable_only"


def _unique_aliases(*groups: Sequence[str]) -> tuple[str, ...]:
    seen = set()
    aliases = []
    for group in groups:
        for alias in group:
            alias = str(alias or "").strip()
            if not alias or alias in seen:
                continue
            seen.add(alias)
            aliases.append(alias)
    return tuple(aliases)


def get_builtin_plugin_groups() -> Dict[str, list[str]]:
    return {name: list(plugins) for name, plugins in PLUGIN_GROUPS.items()}


def get_curated_plugin_catalog() -> Dict[str, PluginInfo]:
    return {
        plugin_name: PluginInfo(
            name=plugin_name,
            description=description,
            source="curated",
            os_family=_infer_os_family(plugin_name),
            support_level=_support_level(plugin_name),
        )
        for plugin_name, description in PLUGINS.items()
    }


def _preferred_catalog_name(plugin_name: str, curated_catalog: Mapping[str, PluginInfo]) -> str:
    for curated_name in sorted(curated_catalog, key=len, reverse=True):
        if plugin_name == curated_name:
            return curated_name
        if plugin_name.startswith(f"{curated_name}."):
            return curated_name
    return plugin_name


def _append_plugin_info(
    plugins: Dict[str, PluginInfo],
    *,
    plugin_name: str,
    description_parts: list[str],
) -> None:
    description = " ".join(part.strip() for part in description_parts if part.strip())
    plugins[plugin_name] = PluginInfo(
        name=plugin_name,
        description=description,
        source="discovered",
        os_family=_infer_os_family(plugin_name),
        support_level=_support_level(plugin_name),
    )


def _parse_plugin_help_output(help_text: str) -> Dict[str, PluginInfo]:
    plugins: Dict[str, PluginInfo] = {}
    in_plugin_section = False
    current_name = ""
    current_description: list[str] = []

    for raw_line in str(help_text or "").splitlines():
        line = raw_line.rstrip()
        if not in_plugin_section:
            if line.strip() == "Plugins:":
                in_plugin_section = True
            continue

        if not line.strip():
            continue
        if line.strip() == "PLUGIN":
            continue
        if line.lstrip().startswith("For plugin specific options"):
            continue

        plugin_match = PLUGIN_LINE_PATTERN.match(line)
        if plugin_match:
            if current_name:
                _append_plugin_info(
                    plugins,
                    plugin_name=current_name,
                    description_parts=current_description,
                )
            current_name = plugin_match.group(1).strip()
            current_description = []
            first_line = (plugin_match.group(2) or "").strip()
            if first_line:
                current_description.append(first_line)
            continue

        continuation_match = PLUGIN_CONTINUATION_PATTERN.match(line)
        if continuation_match and current_name:
            current_description.append(continuation_match.group(1).strip())
            continue

    if current_name:
        _append_plugin_info(
            plugins,
            plugin_name=current_name,
            description_parts=current_description,
        )

    return plugins


def discover_volatility_plugins(
    volatility_command: Sequence[str] | str | None = None,
    *,
    timeout: int = 30,
) -> Dict[str, PluginInfo]:
    command = resolve_volatility_command(volatility_command)
    result = subprocess.run(
        build_volatility_command(command, ["--help"]),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if not output:
        raise RuntimeError("Volatility did not return any plugin discovery output.")

    discovered_plugins = _parse_plugin_help_output(output)
    if not discovered_plugins:
        raise RuntimeError("Volatility help output did not contain a plugin list.")

    curated_catalog = get_curated_plugin_catalog()
    normalised_plugins: Dict[str, PluginInfo] = {}
    for discovered in discovered_plugins.values():
        catalog_name = _preferred_catalog_name(discovered.name, curated_catalog)
        aliases = ()
        if catalog_name != discovered.name:
            aliases = (discovered.name,)
        normalised_plugins[catalog_name] = PluginInfo(
            name=catalog_name,
            description=discovered.description,
            source="discovered",
            os_family=_infer_os_family(catalog_name),
            support_level=_support_level(catalog_name),
            aliases=aliases,
        )

    return normalised_plugins


def build_plugin_catalog(
    volatility_command: Sequence[str] | str | None = None,
) -> Dict[str, PluginInfo]:
    catalog = get_curated_plugin_catalog()
    try:
        discovered_plugins = discover_volatility_plugins(volatility_command)
    except RuntimeError:
        return catalog

    for plugin_name, discovered in discovered_plugins.items():
        if plugin_name in catalog:
            existing = catalog[plugin_name]
            catalog[plugin_name] = PluginInfo(
                name=plugin_name,
                description=existing.description or discovered.description,
                source=existing.source,
                os_family=existing.os_family,
                support_level=existing.support_level,
                aliases=_unique_aliases(existing.aliases, discovered.aliases),
            )
            continue

        catalog[plugin_name] = discovered

    return catalog


def validate_plugin_names(
    plugin_names: Iterable[str],
    *,
    plugin_catalog: Mapping[str, PluginInfo] | None = None,
) -> list[str]:
    catalog = dict(plugin_catalog or build_plugin_catalog())
    alias_map = {}
    for plugin_name, plugin_info in catalog.items():
        alias_map[plugin_name] = plugin_name
        for alias in plugin_info.aliases:
            alias_map[alias] = plugin_name

    validated = []
    seen = set()
    unknown = []
    for plugin_name in plugin_names:
        normalised = str(plugin_name or "").strip()
        if not normalised:
            continue

        resolved_name = alias_map.get(normalised)
        if not resolved_name:
            unknown.append(normalised)
            continue

        if resolved_name in seen:
            continue
        seen.add(resolved_name)
        validated.append(resolved_name)

    if unknown:
        raise ValueError(
            "Unknown plugins: " + ", ".join(sorted(set(unknown)))
        )

    return validated
