import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication, QGraphicsView

from vol_for_smes.config import (
    save_custom_plugin_preset,
    save_ui_theme_name,
)
from vol_for_smes.gui.timeline_graph_view import TimelineGraphView
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

def test_main_window_filters_non_windows_plugins_from_catalog(qapp, tmp_path):
    window = MainWindow(
        settings_path=str(tmp_path / "user_settings.json"),
        plugin_catalog=_sample_catalog(),
    )

    assert "windows.pslist" in window.plugin_catalog
    assert "frameworkinfo.FrameworkInfo" not in window.plugin_catalog
    assert "Windows plugins available for investigations" in window.catalog_status_label.text()

    window.close()
    window.deleteLater()
    qapp.processEvents()


def test_main_window_starts_with_curated_catalog_before_background_refresh(
    qapp,
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr("vol_for_smes.gui.main_window.QTimer.singleShot", lambda *_args: None)

    window = MainWindow(settings_path=str(tmp_path / "user_settings.json"))

    assert "windows.pslist" in window.plugin_catalog
    assert window.catalog_refresh_in_progress is True
    assert "built-in Windows plugins" in window.catalog_status_label.text()

    window.close()
    window.deleteLater()
    qapp.processEvents()


def test_main_window_keeps_theme_selector_enabled_during_investigation(qapp, tmp_path):
    window = MainWindow(
        settings_path=str(tmp_path / "user_settings.json"),
        plugin_catalog=_sample_catalog(),
    )

    window._set_controls_enabled(False)

    assert window.run_button.isEnabled() is False
    assert window.preset_combo.isEnabled() is False
    assert window.theme_combo.isEnabled() is True

    window.close()
    window.deleteLater()
    qapp.processEvents()


def test_main_window_displays_memory_and_report_safety_notes(qapp, tmp_path):
    window = MainWindow(
        settings_path=str(tmp_path / "user_settings.json"),
        plugin_catalog=_sample_catalog(),
    )

    assert "copied local .mem file" in window.memory_safety_label.text().lower()
    assert "cloud-synced" in window.memory_safety_label.text().lower()
    assert "save reports to a separate local folder" in window.report_safety_label.text().lower()
    assert "do not upload memory images" in window.report_safety_label.text().lower()

    window.close()
    window.deleteLater()
    qapp.processEvents()


def test_main_window_populates_timeline_graph_tab(qapp, tmp_path):
    window = MainWindow(
        settings_path=str(tmp_path / "user_settings.json"),
        plugin_catalog=_sample_catalog(),
    )

    report = {
        "title": "Vol For SMEs Report",
        "risk_summary": {"high": 0, "medium": 0, "low": 0, "none": 0},
        "executive_summary": [],
        "analyst_notice": "Analyst review required.",
        "findings": [],
        "timeline": [
            {
                "timestamp": "2024-01-01T10:00:00+00:00",
                "plugin": "windows.pslist",
                "field": "CreateTime",
                "description": "explorer.exe reported by windows.pslist (CreateTime)",
                "entity_label": "explorer.exe",
                "pid": 400,
                "ppid": 4,
            },
            {
                "timestamp": "2024-01-01T10:05:00+00:00",
                "plugin": "windows.pslist",
                "field": "CreateTime",
                "description": "powershell.exe reported by windows.pslist (CreateTime)",
                "entity_label": "powershell.exe",
                "pid": 900,
                "ppid": 400,
            },
        ],
    }

    window._populate_report_views(report)

    assert window.tab_widget.count() == 5
    assert window.tab_widget.tabText(2) == "Timeline"
    assert window.tab_widget.tabText(3) == "Timeline Graph"
    assert window.tab_widget.tabText(4) == "Execution Log"
    assert window.timeline_graph_view.event_count == 2
    assert window.timeline_graph_view.lane_count == 2
    assert window.timeline_graph_view.relationship_count == 1
    assert "drag to pan" in window.timeline_graph_view.summary_label.text().lower()
    assert (
        window.timeline_graph_view.graphics_view.dragMode()
        == QGraphicsView.DragMode.ScrollHandDrag
    )

    window.close()
    window.deleteLater()
    qapp.processEvents()


def test_timeline_graph_defaults_to_investigation_events_when_noise_is_present(qapp):
    view = TimelineGraphView()

    view.set_timeline(
        [
            {
                "timestamp": "2024-01-01T10:00:00+00:00",
                "plugin": "windows.pslist",
                "field": "CreateTime",
                "description": "explorer.exe reported by windows.pslist (CreateTime)",
                "entity_label": "explorer.exe",
                "pid": 400,
                "ppid": 4,
                "row": {"pid": 400, "ppid": 4, "name": "explorer.exe"},
            },
            {
                "timestamp": "2024-01-01T10:05:00+00:00",
                "plugin": "windows.pslist",
                "field": "CreateTime",
                "description": "powershell.exe reported by windows.pslist (CreateTime)",
                "entity_label": "powershell.exe",
                "pid": 900,
                "ppid": 400,
                "row": {"pid": 900, "ppid": 400, "name": "powershell.exe"},
            },
            {
                "timestamp": "2024-01-01T10:05:30+00:00",
                "plugin": "windows.netscan",
                "field": "Created",
                "description": "powershell.exe reported by windows.netscan (Created)",
                "entity_label": "powershell.exe",
                "pid": 900,
                "ppid": 400,
                "row": {"pid": 900, "ppid": 400, "Owner": "powershell.exe"},
            },
            {
                "timestamp": "2024-01-01T10:05:30+00:00",
                "plugin": "windows.dlllist",
                "field": "ModifiedTime",
                "description": "CRYPT32.dll reported by windows.dlllist (ModifiedTime)",
                "entity_label": "CRYPT32.dll",
                "pid": 900,
                "ppid": 400,
                "row": {"pid": 900, "ppid": 400, "Path": "C:/Windows/System32/CRYPT32.dll"},
            },
        ]
    )

    assert view.filter_combo.currentData() == "focus"
    assert view.event_count == 3
    assert "investigation events" in view.summary_label.text().lower()

    view.deleteLater()
    qapp.processEvents()
