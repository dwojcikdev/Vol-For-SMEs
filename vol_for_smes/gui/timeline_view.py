"""
Timeline display widget for the Vol For SMEs GUI.
"""

from __future__ import annotations

from typing import Iterable, Mapping

from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget


class TimelineView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 2, self)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Description"])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

    def set_timeline(self, events: Iterable[Mapping[str, object]]) -> None:
        events = list(events or [])
        self.table.setRowCount(0)

        if not events:
            self.table.insertRow(0)
            self.table.setItem(0, 0, QTableWidgetItem("No timeline events"))
            self.table.setItem(
                0,
                1,
                QTableWidgetItem(
                    "No timestamped artefacts were available for the current investigation."
                ),
            )
            self.table.resizeColumnsToContents()
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
