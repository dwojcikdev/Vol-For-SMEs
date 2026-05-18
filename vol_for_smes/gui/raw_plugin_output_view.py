"""
Raw per-plugin output viewer for the Vol For SMEs GUI.
"""

from __future__ import annotations

import json
from typing import Mapping

from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)


class RawPluginOutputView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._results: dict[str, object] = {}
        self._raw_outputs: dict[str, Mapping[str, object]] = {}

        layout = QVBoxLayout(self)
        control_row = QHBoxLayout()
        control_row.addWidget(QLabel("Plugin:", self))

        self.plugin_combo = QComboBox(self)
        self.plugin_combo.currentTextChanged.connect(self._update_output)
        control_row.addWidget(self.plugin_combo, stretch=1)
        layout.addLayout(control_row)

        self.summary_label = QLabel(self)
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        self.output_view = QPlainTextEdit(self)
        self.output_view.setReadOnly(True)
        self.output_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.output_view, stretch=1)

        self.clear()

    def clear(self) -> None:
        self._results = {}
        self._raw_outputs = {}
        self.plugin_combo.blockSignals(True)
        self.plugin_combo.clear()
        self.plugin_combo.blockSignals(False)
        self.summary_label.setText(
            "Exact per-plugin output will appear here after an investigation completes."
        )
        self.output_view.setPlainText(
            "No plugin output is available yet."
        )

    def set_results(
        self,
        results: Mapping[str, object] | None,
        raw_outputs: Mapping[str, Mapping[str, object]] | None = None,
    ) -> None:
        self._results = dict(results or {})
        self._raw_outputs = dict(raw_outputs or {})

        plugin_names = sorted(set(self._results) | set(self._raw_outputs))
        self.plugin_combo.blockSignals(True)
        self.plugin_combo.clear()
        self.plugin_combo.addItems(plugin_names)
        self.plugin_combo.blockSignals(False)

        if not plugin_names:
            self.clear()
            return

        self.summary_label.setText(
            f"Showing exact captured output for {len(plugin_names)} plugin(s)."
        )
        self.plugin_combo.setCurrentIndex(0)
        self._update_output(self.plugin_combo.currentText())

    def _format_raw_output(self, plugin_name: str) -> str:
        raw_output = self._raw_outputs.get(plugin_name)
        if raw_output:
            command = raw_output.get("command") or []
            command_text = " ".join(str(part) for part in command) if command else "Unknown"
            returncode = raw_output.get("returncode", "")
            stdout = str(raw_output.get("stdout", "") or "")
            stderr = str(raw_output.get("stderr", "") or "")

            sections = [
                f"Plugin: {plugin_name}",
                f"Return code: {returncode}",
                f"Command: {command_text}",
                "",
                "STDOUT:",
                stdout or "(empty)",
                "",
                "STDERR:",
                stderr or "(empty)",
            ]
            return "\n".join(sections)

        parsed_result = self._results.get(plugin_name)
        return "\n".join(
            [
                f"Plugin: {plugin_name}",
                "Exact raw stdout/stderr was not captured for this result.",
                "",
                "Parsed result fallback:",
                json.dumps(parsed_result, indent=2, ensure_ascii=True, default=str),
            ]
        )

    def _update_output(self, plugin_name: str) -> None:
        selected_plugin = str(plugin_name or "").strip()
        if not selected_plugin:
            self.output_view.setPlainText("No plugin output is available yet.")
            return
        self.output_view.setPlainText(self._format_raw_output(selected_plugin))
