import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication

from vol_for_smes.config import save_custom_plugin_preset, save_ui_theme_name
from vol_for_smes.gui.themes import theme_choices
from vol_for_smes.gui.main_window import MainWindow
from vol_for_smes.volatility.plugin_manager import PluginInfo


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app
    app.processEvents()


def _sample_catalog():
    return {
        "windows.pslist": PluginInfo(
            name="windows.pslist",
            description="List running processes",
            os_family="windows",
            support_level="context",
        ),
        "windows.psscan": PluginInfo(
            name="windows.psscan",
            description="Scan for hidden processes",
            os_family="windows",
            support_level="scored",
        ),
        "windows.malfind": PluginInfo(
            name="windows.malfind",
            description="Look for injected code",
            os_family="windows",
            support_level="scored",
        ),
        "frameworkinfo.FrameworkInfo": PluginInfo(
            name="frameworkinfo.FrameworkInfo",
            description="List framework information",
            os_family="cross-platform",
            support_level="runnable_only",
        ),
    }


def test_main_window_defaults_to_default_investigation_preset(qapp, tmp_path):
    window = MainWindow(
        settings_path=str(tmp_path / "user_settings.json"),
        plugin_catalog=_sample_catalog(),
    )

    assert window.preset_combo.currentText() == "default_investigation"
    assert window.active_theme_name == "cyber_ocean"
    assert window.control_tabs.count() == 2
    assert window.control_tabs.tabText(0) == "Investigation"
    assert window.control_tabs.tabText(1) == "Settings"
    assert window.theme_combo.count() == len(theme_choices()) == 10
    assert (
        window.preset_plugin_table.rowCount()
        == len(window.presets["default_investigation"].plugins)
    )
    assert window.export_button.isEnabled() is False

    window.close()
    window.deleteLater()
    qapp.processEvents()


def test_main_window_loads_saved_theme_and_applies_readable_warning_banner(qapp, tmp_path):
    settings_path = tmp_path / "user_settings.json"
    save_ui_theme_name("threat_intelligence_purple", settings_path=settings_path)

    window = MainWindow(
        settings_path=str(settings_path),
        plugin_catalog=_sample_catalog(),
    )

    assert window.active_theme_name == "threat_intelligence_purple"
    assert window.theme_combo.currentData() == "threat_intelligence_purple"
    assert "Threat Intelligence Purple" in window.theme_description_label.text()
    assert "QLabel#warningBanner" in qapp.styleSheet()
    assert "border-radius: 8px;" in qapp.styleSheet()

    window.close()
    window.deleteLater()
    qapp.processEvents()


def test_main_window_loads_custom_presets_from_settings(qapp, tmp_path):
    settings_path = tmp_path / "user_settings.json"
    catalog = _sample_catalog()
    save_custom_plugin_preset(
        "custom_triage",
        ["windows.pslist", "windows.malfind"],
        settings_path=settings_path,
        plugin_catalog=catalog,
    )

    window = MainWindow(
        settings_path=str(settings_path),
        plugin_catalog=catalog,
    )
    window.refresh_presets("custom_triage")

    combo_items = [window.preset_combo.itemText(index) for index in range(window.preset_combo.count())]

    assert "custom_triage" in combo_items
    assert window.preset_combo.currentText() == "custom_triage"
    assert window.preset_plugin_table.rowCount() == 2

    window.close()
    window.deleteLater()
    qapp.processEvents()
