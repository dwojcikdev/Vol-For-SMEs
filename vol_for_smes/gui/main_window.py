"""
Primary PyQt6 window for Vol For SMEs.
"""

from __future__ import annotations

import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Mapping

from PyQt6.QtCore import QObject, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..analysis import analyse_artefacts
from ..config import (
    DEFAULT_UI_THEME,
    PluginPreset,
    delete_custom_plugin_preset,
    get_ui_theme_name,
    list_plugin_presets,
    save_custom_plugin_preset,
    save_ui_theme_name,
)
from ..investigation import (
    MEMORY_IMAGE_SELECTION_GUIDANCE,
    REPORT_EXPORT_GUIDANCE,
    build_report_case_metadata,
    default_report_path,
    run_investigation,
)
from ..reporting import build_analysis_report, export_analysis_to_pdf
from ..reporting.report_builder import ANALYST_REVIEW_NOTICE
from ..utils.file_utils import build_memory_image_metadata
from ..volatility import (
    PluginInfo,
    build_user_plugin_catalog,
    filter_user_plugin_catalog,
    get_user_curated_plugin_catalog,
)
from ..volatility import DEFAULT_PLUGIN_GROUP_NAME
from .themes import THEMES, apply_theme, get_theme_definition, theme_choices
from .timeline_graph_view import TimelineGraphView
from .timeline_view import TimelineView
from .widgets import PluginSelectionDialog, PluginTableWidget


class _SignalStream:
    def __init__(self, callback) -> None:
        self._callback = callback

    def write(self, text: str) -> None:
        if text:
            self._callback(text)

    def flush(self) -> None:
        return None


class InvestigationWorker(QObject):
    log_message = pyqtSignal(str)
    completed = pyqtSignal(object, object, object, str, object)
    failed = pyqtSignal(str)

    def __init__(
        self,
        memory_image: str,
        preset_name: str,
        settings_path: str | None = None,
    ) -> None:
        super().__init__()
        self.memory_image = memory_image
        self.preset_name = preset_name
        self.settings_path = settings_path

    def run(self) -> None:
        stream = _SignalStream(self.log_message.emit)
        try:
            with redirect_stdout(stream), redirect_stderr(stream):
                memory_image_metadata = build_memory_image_metadata(self.memory_image)
                results, preset = run_investigation(
                    self.memory_image,
                    self.preset_name,
                    settings_path=self.settings_path,
                    memory_image_metadata=memory_image_metadata,
                )
                if not results:
                    self.completed.emit(
                        None,
                        None,
                        preset,
                        self.memory_image,
                        memory_image_metadata,
                    )
                    return

                analysis = analyse_artefacts(results)
                self.completed.emit(
                    results,
                    analysis,
                    preset,
                    self.memory_image,
                    memory_image_metadata,
                )
        except Exception:
            self.failed.emit(traceback.format_exc())


class PluginCatalogWorker(QObject):
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def run(self) -> None:
        try:
            self.completed.emit(build_user_plugin_catalog())
        except Exception:
            self.failed.emit(traceback.format_exc())


class MainWindow(QMainWindow):
    def __init__(
        self,
        *,
        settings_path: str | None = None,
        plugin_catalog: Mapping[str, PluginInfo] | None = None,
    ) -> None:
        super().__init__()
        self.settings_path = settings_path
        self._provided_plugin_catalog = plugin_catalog
        self.plugin_catalog = (
            filter_user_plugin_catalog(plugin_catalog)
            if plugin_catalog is not None
            else get_user_curated_plugin_catalog()
        )
        self.catalog_refresh_in_progress = plugin_catalog is None
        self.presets: dict[str, PluginPreset] = {}
        self.current_results = None
        self.current_analysis = None
        self.current_preset: PluginPreset | None = None
        self.current_memory_image = ""
        self.current_memory_image_metadata = None
        self.worker_thread: QThread | None = None
        self.worker: InvestigationWorker | None = None
        self.catalog_thread: QThread | None = None
        self.catalog_worker: PluginCatalogWorker | None = None
        self.active_theme_name = self._load_initial_theme_name()

        self.setWindowTitle("Vol For SMEs")
        self.resize(1440, 900)

        self._apply_theme(self.active_theme_name)
        self._build_ui()
        self.refresh_presets()
        self._update_catalog_status()
        if self.catalog_refresh_in_progress:
            QTimer.singleShot(0, self._start_plugin_catalog_refresh)

    def _load_initial_theme_name(self) -> str:
        theme_name = get_ui_theme_name(self.settings_path)
        return theme_name if theme_name in THEMES else DEFAULT_UI_THEME

    def _apply_theme(self, theme_name: str) -> None:
        app = QApplication.instance()
        if app is None:
            return
        theme = apply_theme(app, theme_name)
        self.active_theme_name = theme.name

    def _build_ui(self) -> None:
        self.setStatusBar(QStatusBar(self))

        central = QWidget(self)
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        root_layout.addWidget(splitter)

        control_panel = QWidget(self)
        control_panel.setObjectName("controlPanel")
        control_layout = QVBoxLayout(control_panel)
        control_layout.setContentsMargins(12, 12, 12, 12)
        control_layout.setSpacing(12)

        heading = QLabel("Volatility for SMEs")
        heading.setObjectName("pageTitle")
        control_layout.addWidget(heading)

        subheading = QLabel(
            "Select a memory image, choose a plugin preset, and run the investigation."
        )
        subheading.setObjectName("supportingText")
        subheading.setWordWrap(True)
        control_layout.addWidget(subheading)

        disclaimer = QLabel(
            "Automated findings are heuristic indicators, not proof. "
            "Human review is required before making investigative or business decisions."
        )
        disclaimer.setObjectName("warningBanner")
        disclaimer.setWordWrap(True)
        control_layout.addWidget(disclaimer)

        self.control_tabs = QTabWidget(self)
        control_layout.addWidget(self.control_tabs, stretch=1)

        investigation_tab = QWidget(self)
        investigation_layout = QVBoxLayout(investigation_tab)
        investigation_layout.setContentsMargins(0, 0, 0, 0)
        investigation_layout.setSpacing(12)

        memory_box = QGroupBox("Memory Image", investigation_tab)
        memory_layout = QVBoxLayout(memory_box)
        memory_row = QHBoxLayout()
        self.memory_image_edit = QLineEdit()
        self.memory_image_edit.setPlaceholderText("Select a Windows memory image")
        memory_row.addWidget(self.memory_image_edit, stretch=1)
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self._browse_memory_image)
        memory_row.addWidget(browse_button)
        memory_layout.addLayout(memory_row)
        self.memory_safety_label = QLabel(MEMORY_IMAGE_SELECTION_GUIDANCE)
        self.memory_safety_label.setObjectName("warningBanner")
        self.memory_safety_label.setWordWrap(True)
        memory_layout.addWidget(self.memory_safety_label)
        investigation_layout.addWidget(memory_box)

        preset_box = QGroupBox("Plugin Preset", investigation_tab)
        preset_layout = QVBoxLayout(preset_box)
        preset_row = QHBoxLayout()
        self.preset_combo = QComboBox()
        self.preset_combo.currentTextChanged.connect(self._preset_changed)
        preset_row.addWidget(self.preset_combo, stretch=1)
        preset_layout.addLayout(preset_row)

        button_row = QHBoxLayout()
        self.save_preset_button = QPushButton("Save Custom Preset")
        self.save_preset_button.clicked.connect(self._open_custom_preset_dialog)
        button_row.addWidget(self.save_preset_button)
        self.delete_preset_button = QPushButton("Delete Selected Preset")
        self.delete_preset_button.clicked.connect(self._delete_selected_preset)
        button_row.addWidget(self.delete_preset_button)
        preset_layout.addLayout(button_row)

        self.catalog_status_label = QLabel()
        self.catalog_status_label.setObjectName("catalogStatus")
        self.catalog_status_label.setWordWrap(True)
        preset_layout.addWidget(self.catalog_status_label)
        investigation_layout.addWidget(preset_box)

        preview_box = QGroupBox("Selected Preset Plugins", investigation_tab)
        preview_layout = QVBoxLayout(preview_box)
        self.preset_plugin_table = PluginTableWidget(self)
        preview_layout.addWidget(self.preset_plugin_table)
        investigation_layout.addWidget(preview_box, stretch=1)

        action_row = QHBoxLayout()
        self.run_button = QPushButton("Run Investigation")
        self.run_button.clicked.connect(self._start_investigation)
        action_row.addWidget(self.run_button)
        self.export_button = QPushButton("Export PDF Report")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_pdf_report)
        action_row.addWidget(self.export_button)
        investigation_layout.addLayout(action_row)
        self.report_safety_label = QLabel(REPORT_EXPORT_GUIDANCE)
        self.report_safety_label.setObjectName("catalogStatus")
        self.report_safety_label.setWordWrap(True)
        investigation_layout.addWidget(self.report_safety_label)

        settings_tab = QWidget(self)
        settings_layout = QVBoxLayout(settings_tab)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(12)

        settings_intro = QLabel(
            "Configure the interface separately from the investigation workflow. "
            "Themes apply immediately and use explicit contrast for readable text, warnings, "
            "and results."
        )
        settings_intro.setObjectName("supportingText")
        settings_intro.setWordWrap(True)
        settings_layout.addWidget(settings_intro)

        appearance_box = QGroupBox("Appearance", settings_tab)
        appearance_layout = QVBoxLayout(appearance_box)
        appearance_row = QHBoxLayout()
        appearance_row.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox()
        for theme_name, theme_label in theme_choices():
            self.theme_combo.addItem(theme_label, theme_name)
        self.theme_combo.currentIndexChanged.connect(self._theme_changed)
        appearance_row.addWidget(self.theme_combo, stretch=1)
        appearance_layout.addLayout(appearance_row)

        self.theme_description_label = QLabel()
        self.theme_description_label.setObjectName("catalogStatus")
        self.theme_description_label.setWordWrap(True)
        appearance_layout.addWidget(self.theme_description_label)
        settings_layout.addWidget(appearance_box)

        settings_layout.addStretch(1)

        self.control_tabs.addTab(investigation_tab, "Investigation")
        self.control_tabs.addTab(settings_tab, "Settings")

        splitter.addWidget(control_panel)

        results_panel = QWidget(self)
        results_panel.setObjectName("resultsPanel")
        results_layout = QVBoxLayout(results_panel)
        results_layout.setContentsMargins(12, 12, 12, 12)
        results_layout.setSpacing(12)

        self.tab_widget = QTabWidget(self)
        self.summary_view = QPlainTextEdit()
        self.summary_view.setReadOnly(True)
        self.findings_view = QPlainTextEdit()
        self.findings_view.setReadOnly(True)
        self.timeline_view = TimelineView(self)
        self.timeline_graph_view = TimelineGraphView(self)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)

        self.tab_widget.addTab(self.summary_view, "Summary")
        self.tab_widget.addTab(self.findings_view, "Findings")
        self.tab_widget.addTab(self.timeline_view, "Timeline")
        self.tab_widget.addTab(self.timeline_graph_view, "Timeline Graph")
        self.tab_widget.addTab(self.log_view, "Execution Log")
        results_layout.addWidget(self.tab_widget)

        splitter.addWidget(results_panel)
        splitter.setSizes([430, 1010])
        self._sync_theme_combo()
        self._update_theme_description()

    def _update_catalog_status(self) -> None:
        plugin_count = len(self.plugin_catalog)
        scored_count = sum(
            1 for info in self.plugin_catalog.values() if info.support_level == "scored"
        )
        context_count = sum(
            1 for info in self.plugin_catalog.values() if info.support_level == "context"
        )
        if self.catalog_refresh_in_progress:
            self.catalog_status_label.setText(
                f"Loaded {plugin_count} built-in Windows plugins. "
                "Checking the bundled Volatility runtime for any additional Windows plugins..."
            )
            return

        self.catalog_status_label.setText(
            f"Discovered {plugin_count} Windows plugins available for investigations. "
            f"{scored_count} are scored automatically, {context_count} contribute contextual data, "
            "and the remainder are runnable-only."
        )

    def _start_plugin_catalog_refresh(self) -> None:
        if self.catalog_thread is not None:
            return

        self.catalog_thread = QThread(self)
        self.catalog_worker = PluginCatalogWorker()
        self.catalog_worker.moveToThread(self.catalog_thread)
        self.catalog_thread.started.connect(self.catalog_worker.run)
        self.catalog_worker.completed.connect(self._plugin_catalog_refresh_completed)
        self.catalog_worker.failed.connect(self._plugin_catalog_refresh_failed)
        self.catalog_thread.start()

    def _finish_plugin_catalog_refresh(self) -> None:
        if self.catalog_thread is not None:
            self.catalog_thread.quit()
            self.catalog_thread.wait()
        self.catalog_thread = None
        self.catalog_worker = None
        self.catalog_refresh_in_progress = False

    def _plugin_catalog_refresh_completed(self, plugin_catalog) -> None:
        self._finish_plugin_catalog_refresh()
        self.plugin_catalog = dict(plugin_catalog)
        self._update_selected_preset()
        self._update_catalog_status()

    def _plugin_catalog_refresh_failed(self, _error_text: str) -> None:
        self._finish_plugin_catalog_refresh()
        self._update_catalog_status()

    def _sync_theme_combo(self) -> None:
        theme_index = self.theme_combo.findData(self.active_theme_name)
        if theme_index < 0:
            theme_index = self.theme_combo.findData(DEFAULT_UI_THEME)
        self.theme_combo.blockSignals(True)
        self.theme_combo.setCurrentIndex(theme_index)
        self.theme_combo.blockSignals(False)

    def _update_theme_description(self) -> None:
        theme = get_theme_definition(self.active_theme_name)
        self.theme_description_label.setText(
            f"{theme.label}: {theme.description}"
        )

    def _theme_changed(self, index: int) -> None:
        theme_name = str(self.theme_combo.itemData(index) or "").strip()
        if not theme_name or theme_name == self.active_theme_name:
            return
        self._apply_theme(theme_name)
        save_ui_theme_name(theme_name, settings_path=self.settings_path)
        self._update_theme_description()
        theme_label = get_theme_definition(theme_name).label
        self.statusBar().showMessage(f"Theme changed to {theme_label}.", 5000)

    def refresh_presets(self, selected_name: str | None = None) -> None:
        self.presets = list_plugin_presets(self.settings_path)
        preset_names = list(self.presets)
        if not preset_names:
            self.preset_combo.clear()
            self.preset_plugin_table.set_plugins([], self.plugin_catalog)
            return

        if selected_name not in self.presets:
            selected_name = (
                DEFAULT_PLUGIN_GROUP_NAME
                if DEFAULT_PLUGIN_GROUP_NAME in self.presets
                else preset_names[0]
            )

        self.preset_combo.blockSignals(True)
        self.preset_combo.clear()
        self.preset_combo.addItems(preset_names)
        self._selected_preset_name = selected_name
        self.preset_combo.setCurrentText(selected_name)
        self.preset_combo.blockSignals(False)
        self._update_selected_preset()

    def _current_preset(self) -> PluginPreset:
        return self.presets[self._selected_preset_name]

    def _preset_changed(self, preset_name: str) -> None:
        if preset_name and preset_name in self.presets:
            self._selected_preset_name = preset_name
            self._update_selected_preset()

    def _update_selected_preset(self) -> None:
        preset = self._current_preset()
        self.preset_plugin_table.set_plugins(preset.plugins, self.plugin_catalog)
        self.delete_preset_button.setEnabled(not preset.built_in)

    def _browse_memory_image(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Select memory image",
            str(Path.cwd()),
            "Memory images (*.raw *.mem *.dmp *.vmem);;All files (*.*)",
        )
        if selected:
            self.memory_image_edit.setText(selected)

    def _open_custom_preset_dialog(self) -> None:
        current_preset = self._current_preset()
        dialog = PluginSelectionDialog(
            self.plugin_catalog,
            initial_preset=current_preset,
            parent=self,
        )
        if dialog.exec():
            preset = save_custom_plugin_preset(
                dialog.preset_name(),
                dialog.selected_plugins(),
                settings_path=self.settings_path,
                plugin_catalog=self.plugin_catalog,
            )
            self.refresh_presets(preset.name)
            self.statusBar().showMessage(
                f"Saved custom preset '{preset.name}'.",
                5000,
            )

    def _delete_selected_preset(self) -> None:
        preset = self._current_preset()
        if preset.built_in:
            QMessageBox.information(
                self,
                "Built-in preset",
                "Built-in presets cannot be deleted.",
            )
            return

        response = QMessageBox.question(
            self,
            "Delete preset",
            f"Delete the custom preset '{preset.name}'?",
        )
        if response != QMessageBox.StandardButton.Yes:
            return

        delete_custom_plugin_preset(
            preset.name,
            settings_path=self.settings_path,
        )
        self.refresh_presets()
        self.statusBar().showMessage(
            f"Deleted custom preset '{preset.name}'.",
            5000,
        )

    def _set_controls_enabled(self, enabled: bool) -> None:
        self.run_button.setEnabled(enabled)
        self.save_preset_button.setEnabled(enabled)
        self.delete_preset_button.setEnabled(enabled and not self._current_preset().built_in)
        self.preset_combo.setEnabled(enabled)
        self.theme_combo.setEnabled(True)

    def _start_investigation(self) -> None:
        memory_image = self.memory_image_edit.text().strip()
        if not memory_image:
            QMessageBox.warning(self, "Memory image required", "Select a memory image to analyse.")
            return
        if not Path(memory_image).expanduser().is_file():
            QMessageBox.warning(
                self,
                "Memory image not found",
                "The selected memory image path does not point to a file.",
            )
            return

        preset = self._current_preset()
        self.log_view.clear()
        self.summary_view.clear()
        self.findings_view.clear()
        self.timeline_view.set_timeline([])
        self.timeline_graph_view.set_timeline([])
        self.export_button.setEnabled(False)
        self._set_controls_enabled(False)
        self.statusBar().showMessage(
            f"Running preset '{preset.name}' against {memory_image}...",
        )

        self.worker_thread = QThread(self)
        self.worker = InvestigationWorker(
            memory_image,
            preset.name,
            settings_path=self.settings_path,
        )
        self.worker.moveToThread(self.worker_thread)
        self.worker.log_message.connect(self._append_log)
        self.worker.completed.connect(self._investigation_completed)
        self.worker.failed.connect(self._investigation_failed)
        self.worker_thread.started.connect(self.worker.run)
        self.worker_thread.start()

    def _append_log(self, text: str) -> None:
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)
        self.log_view.insertPlainText(text)
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)

    def _cleanup_worker(self) -> None:
        if self.worker_thread is not None:
            self.worker_thread.quit()
            self.worker_thread.wait()
        self.worker_thread = None
        self.worker = None
        self._set_controls_enabled(True)

    def _investigation_completed(
        self,
        results,
        analysis,
        preset,
        memory_image: str,
        memory_image_metadata,
    ) -> None:
        self._cleanup_worker()
        self.current_results = results
        self.current_analysis = analysis
        self.current_preset = preset
        self.current_memory_image = memory_image
        self.current_memory_image_metadata = memory_image_metadata

        if not results or not analysis:
            self.summary_view.setPlainText(
                "Investigation did not produce analysis results. Review the execution log for details."
            )
            self.findings_view.setPlainText("")
            self.timeline_view.set_timeline([])
            self.timeline_graph_view.set_timeline([])
            self.export_button.setEnabled(False)
            self.statusBar().showMessage("Investigation finished without results.", 5000)
            return

        report = build_analysis_report(
            analysis,
            case_metadata=build_report_case_metadata(
                memory_image,
                preset,
                memory_image_metadata=memory_image_metadata,
            ),
        )
        self._populate_report_views(report)
        self.export_button.setEnabled(True)
        self.statusBar().showMessage(
            f"Investigation completed with preset '{preset.name}'.",
            5000,
        )

    def _investigation_failed(self, error_text: str) -> None:
        self._cleanup_worker()
        self.summary_view.setPlainText(
            "An unexpected error interrupted the investigation. Review the execution log for details."
        )
        self.findings_view.setPlainText("")
        self.timeline_view.set_timeline([])
        self.timeline_graph_view.set_timeline([])
        self.export_button.setEnabled(False)
        self._append_log(error_text)
        QMessageBox.critical(
            self,
            "Investigation failed",
            "The investigation failed unexpectedly. Review the execution log for details.",
        )
        self.statusBar().showMessage("Investigation failed.", 5000)

    def _populate_report_views(self, report: Mapping[str, object]) -> None:
        risk_summary = report.get("risk_summary", {})
        executive_summary = report.get("executive_summary", [])
        findings = report.get("findings", [])

        summary_lines = [
            str(report.get("title", "Vol For SMEs Report")),
            "",
            f"Risk counts: High {risk_summary.get('high', 0)}, "
            f"Medium {risk_summary.get('medium', 0)}, "
            f"Low {risk_summary.get('low', 0)}, "
            f"Informational {risk_summary.get('none', 0)}.",
            "",
            "Executive summary:",
        ]
        summary_lines.extend(f"- {line}" for line in executive_summary)
        analyst_notice = str(report.get("analyst_notice", ANALYST_REVIEW_NOTICE))
        summary_lines.extend(["", "Analyst review notice:", analyst_notice])
        self.summary_view.setPlainText("\n".join(summary_lines))

        finding_lines = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            finding_lines.append(
                f"{finding.get('title', 'Finding')} "
                f"[{finding.get('severity_label', 'Unknown')} | Risk {finding.get('risk_score', 0)}]"
            )
            finding_lines.append(f"Category: {finding.get('category', 'Finding')}")
            if finding.get("affected_asset"):
                finding_lines.append(f"Affected asset: {finding.get('affected_asset')}")
            finding_lines.append(f"Summary: {finding.get('summary', '')}")
            finding_lines.append(f"What it means: {finding.get('meaning', '')}")
            mitre = finding.get("mitre", [])
            if mitre:
                finding_lines.append("MITRE ATT&CK:")
                finding_lines.extend(f"  - {item}" for item in mitre)
            evidence = finding.get("evidence", [])
            if evidence:
                finding_lines.append("Evidence:")
                finding_lines.extend(f"  - {item}" for item in evidence)
            remediations = finding.get("remediations", [])
            if remediations:
                finding_lines.append("Recommended remediation:")
                finding_lines.extend(f"  - {item}" for item in remediations)
            finding_lines.append("")

        if not finding_lines:
            finding_lines = [
                "No medium or high severity findings were generated by the current heuristics."
            ]

        self.findings_view.setPlainText("\n".join(finding_lines))
        timeline = report.get("timeline", [])
        self.timeline_view.set_timeline(timeline)
        self.timeline_graph_view.set_timeline(timeline)

    def _export_pdf_report(self) -> None:
        if not self.current_analysis or not self.current_preset:
            QMessageBox.information(
                self,
                "No analysis available",
                "Run an investigation before exporting a PDF report.",
            )
            return

        suggested_path = default_report_path(self.current_memory_image)
        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export PDF report",
            str(suggested_path),
            "PDF files (*.pdf)",
        )
        if not output_path:
            return

        try:
            written_path = export_analysis_to_pdf(
                self.current_analysis,
                output_path,
                case_metadata=build_report_case_metadata(
                    self.current_memory_image,
                    self.current_preset,
                    memory_image_metadata=self.current_memory_image_metadata,
                ),
            )
        except OSError as exc:
            QMessageBox.critical(
                self,
                "PDF export failed",
                f"Could not export the PDF report: {exc}",
            )
            return

        self.statusBar().showMessage(f"PDF report exported to {written_path}", 5000)
        QMessageBox.information(
            self,
            "PDF exported",
            f"Report exported to:\n{written_path}",
        )

    def closeEvent(self, event) -> None:
        if self.catalog_thread is not None:
            self.catalog_thread.quit()
            self.catalog_thread.wait()
            self.catalog_thread = None
            self.catalog_worker = None
        super().closeEvent(event)
