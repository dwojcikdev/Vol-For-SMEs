"""
Reusable PyQt6 widgets for the Vol For SMEs GUI.
"""

from __future__ import annotations

from typing import Mapping, Sequence

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..config import PluginPreset
from ..volatility import PluginInfo

SUPPORT_LABELS = {
    "scored": "Scored",
    "context": "Context",
    "runnable_only": "Runnable Only",
}

OS_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "mac": "macOS",
    "cross-platform": "Cross-Platform",
    "unknown": "Unknown",
}


def _plugin_sort_key(plugin_info: PluginInfo) -> tuple[int, str]:
    os_rank = {
        "windows": 0,
        "cross-platform": 1,
        "linux": 2,
        "mac": 3,
        "unknown": 4,
    }
    return (os_rank.get(plugin_info.os_family, 9), plugin_info.name)


class PluginTableWidget(QTableWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(0, 3, parent)
        self.setHorizontalHeaderLabels(["Plugin", "Support", "Description"])
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )

    def set_plugins(
        self,
        plugin_names: Sequence[str],
        plugin_catalog: Mapping[str, PluginInfo],
    ) -> None:
        self.setRowCount(0)
        for row_index, plugin_name in enumerate(plugin_names):
            plugin_info = plugin_catalog.get(plugin_name)
            description = plugin_info.description if plugin_info else ""
            support_level = plugin_info.support_level if plugin_info else "runnable_only"

            self.insertRow(row_index)
            self.setItem(row_index, 0, QTableWidgetItem(plugin_name))
            self.setItem(
                row_index,
                1,
                QTableWidgetItem(SUPPORT_LABELS.get(support_level, support_level)),
            )
            self.setItem(row_index, 2, QTableWidgetItem(description))

        self.resizeColumnsToContents()


class PluginSelectionDialog(QDialog):
    def __init__(
        self,
        plugin_catalog: Mapping[str, PluginInfo],
        *,
        initial_preset: PluginPreset | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.plugin_catalog = dict(plugin_catalog)
        self.initial_preset = initial_preset
        self._items_by_name: dict[str, QTreeWidgetItem] = {}

        self.setWindowTitle("Custom Plugin Preset")
        self.resize(960, 620)

        suggested_name = "custom_preset"
        if initial_preset is not None:
            suggested_name = (
                initial_preset.name
                if not initial_preset.built_in
                else f"{initial_preset.name}_custom"
            )

        layout = QVBoxLayout(self)
        note = QLabel(
            "Select the plugins to include in a custom preset. "
            "Only Windows plugins are shown because the current investigation workflow "
            "supports Windows memory images."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Preset name:"))
        self.name_edit = QLineEdit(suggested_name)
        name_row.addWidget(self.name_edit)
        layout.addLayout(name_row)

        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search plugins:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Filter by plugin name, support level, or description")
        self.search_edit.textChanged.connect(self._apply_filter)
        search_row.addWidget(self.search_edit)
        layout.addLayout(search_row)

        self.plugin_tree = QTreeWidget()
        self.plugin_tree.setHeaderLabels(["Plugin", "OS", "Support", "Description"])
        self.plugin_tree.setRootIsDecorated(False)
        self.plugin_tree.setAlternatingRowColors(True)
        self.plugin_tree.setUniformRowHeights(True)
        layout.addWidget(self.plugin_tree, stretch=1)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self._populate_plugin_tree(initial_preset.plugins if initial_preset else ())

    def _populate_plugin_tree(self, selected_plugins: Sequence[str]) -> None:
        self.plugin_tree.clear()
        self._items_by_name.clear()
        selected = set(selected_plugins)

        for plugin_info in sorted(self.plugin_catalog.values(), key=_plugin_sort_key):
            item = QTreeWidgetItem(
                [
                    plugin_info.name,
                    OS_LABELS.get(plugin_info.os_family, plugin_info.os_family),
                    SUPPORT_LABELS.get(plugin_info.support_level, plugin_info.support_level),
                    plugin_info.description,
                ]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, plugin_info.name)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(
                0,
                Qt.CheckState.Checked
                if plugin_info.name in selected
                else Qt.CheckState.Unchecked,
            )
            self.plugin_tree.addTopLevelItem(item)
            self._items_by_name[plugin_info.name] = item

        for column in range(3):
            self.plugin_tree.resizeColumnToContents(column)

    def _apply_filter(self, text: str) -> None:
        query = str(text or "").strip().lower()
        for plugin_name, item in self._items_by_name.items():
            plugin_info = self.plugin_catalog[plugin_name]
            haystack = " ".join(
                [
                    plugin_info.name,
                    plugin_info.description,
                    plugin_info.support_level.replace("_", " "),
                    plugin_info.os_family,
                ]
            ).lower()
            item.setHidden(bool(query and query not in haystack))

    def preset_name(self) -> str:
        return self.name_edit.text().strip()

    def selected_plugins(self) -> list[str]:
        selected = []
        for index in range(self.plugin_tree.topLevelItemCount()):
            item = self.plugin_tree.topLevelItem(index)
            if item.checkState(0) == Qt.CheckState.Checked:
                selected.append(str(item.data(0, Qt.ItemDataRole.UserRole)))
        return selected

    def accept(self) -> None:
        if not self.preset_name():
            QMessageBox.warning(self, "Preset name required", "Enter a name for the custom preset.")
            return
        if not self.selected_plugins():
            QMessageBox.warning(
                self,
                "Plugins required",
                "Select at least one plugin for the custom preset.",
            )
            return
        super().accept()
