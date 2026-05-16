"""
Persistent settings helpers for custom plugin presets and GUI preferences.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Mapping

from ..utils.file_utils import get_app_data_dir, get_project_root
from ..volatility.plugin_manager import (
    DEFAULT_PLUGIN_GROUP_NAME,
    get_builtin_plugin_groups,
    validate_plugin_names,
)

SETTINGS_VERSION = 1
CUSTOM_PLUGIN_GROUPS_KEY = "custom_plugin_groups"
UI_THEME_KEY = "ui_theme"
DEFAULT_UI_THEME = "cyber_ocean"
DEFAULT_SETTINGS_PATH = get_app_data_dir() / "user_settings.json"
PROJECT_SETTINGS_FALLBACK_PATH = get_project_root() / "data" / "user_settings.json"


@dataclass(frozen=True)
class PluginPreset:
    name: str
    plugins: tuple[str, ...]
    built_in: bool = False


def get_settings_path(settings_path: str | Path | None = None) -> Path:
    if settings_path is None:
        return DEFAULT_SETTINGS_PATH
    return Path(settings_path)


def _empty_settings() -> dict:
    return {
        "version": SETTINGS_VERSION,
        CUSTOM_PLUGIN_GROUPS_KEY: {},
        UI_THEME_KEY: DEFAULT_UI_THEME,
    }


def load_settings(settings_path: str | Path | None = None) -> dict:
    path = get_settings_path(settings_path)
    if not path.is_file():
        if settings_path is None and PROJECT_SETTINGS_FALLBACK_PATH.is_file():
            path = PROJECT_SETTINGS_FALLBACK_PATH
        else:
            return _empty_settings()

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Settings file must contain a JSON object.")

    merged = _empty_settings()
    merged.update(data)
    groups = merged.get(CUSTOM_PLUGIN_GROUPS_KEY)
    if not isinstance(groups, dict):
        merged[CUSTOM_PLUGIN_GROUPS_KEY] = {}
    theme_name = str(merged.get(UI_THEME_KEY, DEFAULT_UI_THEME) or "").strip()
    merged[UI_THEME_KEY] = theme_name or DEFAULT_UI_THEME
    return merged


def save_settings(data: Mapping[str, object], settings_path: str | Path | None = None) -> Path:
    path = get_settings_path(settings_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(dict(data), file, indent=4)
    return path


def get_ui_theme_name(settings_path: str | Path | None = None) -> str:
    data = load_settings(settings_path)
    theme_name = str(data.get(UI_THEME_KEY, DEFAULT_UI_THEME) or "").strip()
    return theme_name or DEFAULT_UI_THEME


def save_ui_theme_name(
    theme_name: str,
    *,
    settings_path: str | Path | None = None,
) -> str:
    selected_theme = str(theme_name or "").strip()
    if not selected_theme:
        raise ValueError("Theme name cannot be empty.")

    data = load_settings(settings_path)
    data[UI_THEME_KEY] = selected_theme
    save_settings(data, settings_path)
    return selected_theme


def list_builtin_plugin_presets() -> Dict[str, PluginPreset]:
    return {
        name: PluginPreset(
            name=name,
            plugins=tuple(plugins),
            built_in=True,
        )
        for name, plugins in get_builtin_plugin_groups().items()
    }


def list_custom_plugin_presets(
    settings_path: str | Path | None = None,
) -> Dict[str, PluginPreset]:
    data = load_settings(settings_path)
    custom_groups = data.get(CUSTOM_PLUGIN_GROUPS_KEY, {})
    presets: Dict[str, PluginPreset] = {}

    for name, details in custom_groups.items():
        if not isinstance(details, dict):
            continue
        plugins = details.get("plugins", [])
        if not isinstance(plugins, list):
            continue
        preset_name = str(name or "").strip()
        if not preset_name:
            continue
        presets[preset_name] = PluginPreset(
            name=preset_name,
            plugins=tuple(str(plugin).strip() for plugin in plugins if str(plugin).strip()),
            built_in=False,
        )

    return presets


def list_plugin_presets(
    settings_path: str | Path | None = None,
) -> Dict[str, PluginPreset]:
    presets = list_builtin_plugin_presets()
    presets.update(list_custom_plugin_presets(settings_path))
    return presets


def get_plugin_preset(
    name: str,
    settings_path: str | Path | None = None,
) -> PluginPreset:
    preset_name = str(name or "").strip()
    presets = list_plugin_presets(settings_path)
    if preset_name not in presets:
        raise KeyError(f"Plugin preset '{preset_name}' was not found.")
    return presets[preset_name]


def save_custom_plugin_preset(
    name: str,
    plugins: Iterable[str],
    *,
    settings_path: str | Path | None = None,
    plugin_catalog=None,
) -> PluginPreset:
    preset_name = str(name or "").strip()
    if not preset_name:
        raise ValueError("Plugin preset name cannot be empty.")
    if preset_name in list_builtin_plugin_presets():
        raise ValueError(
            f"'{preset_name}' is a built-in plugin preset and cannot be overwritten."
        )

    validated_plugins = validate_plugin_names(
        plugins,
        plugin_catalog=plugin_catalog,
    )
    if not validated_plugins:
        raise ValueError("Plugin preset must contain at least one valid plugin.")

    data = load_settings(settings_path)
    custom_groups = dict(data.get(CUSTOM_PLUGIN_GROUPS_KEY, {}))
    custom_groups[preset_name] = {
        "plugins": validated_plugins,
    }
    data[CUSTOM_PLUGIN_GROUPS_KEY] = custom_groups
    save_settings(data, settings_path)

    return PluginPreset(
        name=preset_name,
        plugins=tuple(validated_plugins),
        built_in=False,
    )


def delete_custom_plugin_preset(
    name: str,
    *,
    settings_path: str | Path | None = None,
) -> bool:
    preset_name = str(name or "").strip()
    if not preset_name:
        return False
    if preset_name == DEFAULT_PLUGIN_GROUP_NAME or preset_name in get_builtin_plugin_groups():
        raise ValueError(
            f"'{preset_name}' is a built-in plugin preset and cannot be deleted."
        )

    data = load_settings(settings_path)
    custom_groups = dict(data.get(CUSTOM_PLUGIN_GROUPS_KEY, {}))
    if preset_name not in custom_groups:
        return False

    del custom_groups[preset_name]
    data[CUSTOM_PLUGIN_GROUPS_KEY] = custom_groups
    save_settings(data, settings_path)
    return True
