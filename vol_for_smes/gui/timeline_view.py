"""
Timeline display widget for the Vol For SMEs GUI.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from .timeline_graph_view import _format_offset_seconds


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _execution_rows(
    entries: Iterable[Mapping[str, object]],
) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    ordered_entries = sorted(
        (
            entry
            for entry in entries
            if isinstance(entry, Mapping) and str(entry.get("plugin") or "").strip()
        ),
        key=lambda entry: (
            float(entry.get("started_offset_seconds") or 0.0),
            float(entry.get("finished_offset_seconds") or 0.0),
            str(entry.get("plugin") or ""),
        ),
    )

    for entry in ordered_entries:
        plugin_name = str(entry.get("plugin") or "").strip()
        started_offset = _safe_float(entry.get("started_offset_seconds"))
        finished_offset = _safe_float(entry.get("finished_offset_seconds"))
        elapsed_seconds = _safe_float(entry.get("elapsed_seconds"))
        if started_offset is None:
            started_offset = 0.0
        if finished_offset is None:
            finished_offset = started_offset
        if elapsed_seconds is None:
            elapsed_seconds = max(0.0, finished_offset - started_offset)

        status = "completed" if entry.get("success", True) else "failed"
        error_message = str(entry.get("error_message") or "").strip()

        rows.append((_format_offset_seconds(started_offset), f"{plugin_name} started"))

        finished_text = (
            f"{plugin_name} {status} "
            f"(runtime {_format_offset_seconds(elapsed_seconds)})"
        )
        if error_message:
            finished_text = f"{finished_text}: {error_message}"
        rows.append((_format_offset_seconds(finished_offset), finished_text))

    return rows


class TimelineView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 2, self)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        self.set_timeline([])

    def set_unavailable_message(self) -> None:
        self.table.setHorizontalHeaderLabels(["Timestamp", "Description"])
        self.table.setRowCount(0)
        self.table.insertRow(0)
        self.table.setItem(0, 0, QTableWidgetItem("Timeline unavailable"))
        self.table.setItem(
            0,
            1,
            QTableWidgetItem(
                "No memory-dump-derived timestamps were available for the current investigation."
            ),
        )
        self.table.resizeColumnsToContents()

    def set_execution_log(self, entries: Iterable[Mapping[str, object]]) -> None:
        self.table.setHorizontalHeaderLabels(["Time", "Plugin Execution"])
        rows = _execution_rows(entries or [])
        self.table.setRowCount(0)

        if not rows:
            self.set_unavailable_message()
            return

        for row_index, (time_text, description) in enumerate(rows):
            self.table.insertRow(row_index)
            self.table.setItem(row_index, 0, QTableWidgetItem(time_text))
            self.table.setItem(row_index, 1, QTableWidgetItem(description))

        self.table.resizeColumnsToContents()

    def set_timeline(self, events: Iterable[Mapping[str, object]]) -> None:
        events = list(events or [])
        self.table.setHorizontalHeaderLabels(["Timestamp", "Description"])
        self.table.setRowCount(0)

        if not events:
            self.set_unavailable_message()
            return

        for row_index, event in enumerate(events):
            self.table.insertRow(row_index)
            self.table.setItem(
                row_index,
                0,
                QTableWidgetItem(str(event.get("timestamp", "Unknown time"))),
            )
            self.table.setItem(
                row_index,
                1,
                QTableWidgetItem(str(event.get("description", ""))),
            )

        self.table.resizeColumnsToContents()
