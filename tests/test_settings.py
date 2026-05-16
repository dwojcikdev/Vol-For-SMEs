import json

import pytest

from vol_for_smes.config import settings
from vol_for_smes.volatility.plugin_manager import PluginInfo


def test_load_settings_returns_empty_structure_when_file_is_missing(tmp_path):
    loaded = settings.load_settings(tmp_path / "missing.json")

    assert loaded == {
        "version": settings.SETTINGS_VERSION,
        settings.CUSTOM_PLUGIN_GROUPS_KEY: {},
        settings.UI_THEME_KEY: settings.DEFAULT_UI_THEME,
    }


def test_save_custom_plugin_preset_persists_and_can_be_loaded(tmp_path):
    settings_path = tmp_path / "user_settings.json"
    plugin_catalog = {
        "windows.pslist": PluginInfo(name="windows.pslist"),
        "windows.malfind": PluginInfo(name="windows.malfind"),
    }

    preset = settings.save_custom_plugin_preset(
        "my_triage",
        ["windows.pslist", "windows.malfind"],
        settings_path=settings_path,
        plugin_catalog=plugin_catalog,
    )

    assert preset.name == "my_triage"
    assert preset.plugins == ("windows.pslist", "windows.malfind")

    written = json.loads(settings_path.read_text(encoding="utf-8"))
    assert written[settings.CUSTOM_PLUGIN_GROUPS_KEY]["my_triage"]["plugins"] == [
        "windows.pslist",
        "windows.malfind",
    ]

    loaded_preset = settings.get_plugin_preset("my_triage", settings_path)
    assert loaded_preset == preset


def test_list_plugin_presets_includes_built_in_and_custom_presets(tmp_path):
    settings_path = tmp_path / "user_settings.json"
    plugin_catalog = {
        "windows.pslist": PluginInfo(name="windows.pslist"),
    }
    settings.save_custom_plugin_preset(
        "custom_processes",
        ["windows.pslist"],
        settings_path=settings_path,
        plugin_catalog=plugin_catalog,
    )

    presets = settings.list_plugin_presets(settings_path)

    assert "default_investigation" in presets
    assert presets["default_investigation"].built_in is True
    assert "custom_processes" in presets
    assert presets["custom_processes"].built_in is False


def test_save_custom_plugin_preset_rejects_built_in_names(tmp_path):
    with pytest.raises(ValueError, match="built-in plugin preset"):
        settings.save_custom_plugin_preset(
            "default_investigation",
            ["windows.pslist"],
            settings_path=tmp_path / "user_settings.json",
            plugin_catalog={"windows.pslist": PluginInfo(name="windows.pslist")},
        )


def test_delete_custom_plugin_preset_removes_saved_preset(tmp_path):
    settings_path = tmp_path / "user_settings.json"
    settings.save_custom_plugin_preset(
        "custom_network",
        ["windows.netscan"],
        settings_path=settings_path,
        plugin_catalog={"windows.netscan": PluginInfo(name="windows.netscan")},
    )

    deleted = settings.delete_custom_plugin_preset(
        "custom_network",
        settings_path=settings_path,
    )

    assert deleted is True
    assert "custom_network" not in settings.list_custom_plugin_presets(settings_path)


def test_save_ui_theme_name_persists_and_can_be_loaded(tmp_path):
    settings_path = tmp_path / "user_settings.json"

    saved_theme = settings.save_ui_theme_name(
        "high_contrast_light",
        settings_path=settings_path,
    )

    assert saved_theme == "high_contrast_light"

    written = json.loads(settings_path.read_text(encoding="utf-8"))
    assert written[settings.UI_THEME_KEY] == "high_contrast_light"
    assert settings.get_ui_theme_name(settings_path) == "high_contrast_light"

def test_load_settings_uses_repo_settings_fallback_when_default_file_is_missing(
    tmp_path,
    monkeypatch,
):
    default_settings_path = tmp_path / "AppData" / "Vol For SMEs" / "user_settings.json"
    repo_settings_path = tmp_path / "data" / "user_settings.json"
    repo_settings_path.parent.mkdir(parents=True, exist_ok=True)
    repo_settings_path.write_text(
        json.dumps(
            {
                "version": settings.SETTINGS_VERSION,
                settings.CUSTOM_PLUGIN_GROUPS_KEY: {},
                settings.UI_THEME_KEY: "forensic_slate",
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(settings, "DEFAULT_SETTINGS_PATH", default_settings_path)
    monkeypatch.setattr(settings, "PROJECT_SETTINGS_FALLBACK_PATH", repo_settings_path)

    loaded = settings.load_settings()

    assert loaded[settings.UI_THEME_KEY] == "forensic_slate"
    assert settings.get_settings_path() == default_settings_path
