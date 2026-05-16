"""
Interactive overview-and-detail timeline graph widget for the Vol For SMEs GUI.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from PyQt6.QtCore import QEvent, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QMouseEvent,
    QPainter,
    QPen,
    QWheelEvent,
)
from PyQt6.QtWidgets import (
    QComboBox,
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

_PID_FIELD_HINTS = ("pid", "PID", "Pid", "ProcessId", "OwnerPid")
_PPID_FIELD_HINTS = (
    "ppid",
    "PPID",
    "Ppid",
    "ParentPid",
    "InheritedFromUniqueProcessId",
    "InheritedFromPid",
    "Parent PID",
)
_PROCESS_GRAPH_PLUGINS = {
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.envars",
    "windows.sessions",
}
_NETWORK_GRAPH_PLUGINS = {
    "windows.netscan",
    "windows.sockets",
}
_SERVICE_GRAPH_PLUGINS = {
    "windows.svcscan",
}
_FOCUS_FIELD_HINTS = (
    "create",
    "start",
    "exit",
    "connect",
    "listen",
    "logon",
    "boot",
    "timecreated",
)
_LOW_VALUE_FIELD_HINTS = (
    "modified",
    "accessed",
    "lastwrite",
    "lastaccess",
    "changed",
)


def _safe_lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _find_first(values: Mapping[str, object], *keys: str) -> object | None:
    lowered = {_safe_lower(key): value for key, value in values.items()}
    for key in keys:
        lowered_key = _safe_lower(key)
        if lowered_key in lowered:
            return lowered[lowered_key]
    return None


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None

    cleaned = text.replace(" UTC", "+00:00").replace("Z", "+00:00")
    if "." in cleaned and "+" in cleaned:
        head, tail = cleaned.rsplit("+", 1)
        cleaned = f"{head.split('.', 1)[0]}+{tail}"

    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _identity_from_row(row: Mapping[str, object]) -> str:
    for key in (
        "name",
        "ImageFileName",
        "Name",
        "Process",
        "ProcessName",
        "Owner",
        "Path",
        "File",
        "ServiceName",
    ):
        value = row.get(key)
        if value:
            return str(value)

    pid = _find_first(row, *_PID_FIELD_HINTS)
    if pid not in (None, ""):
        return f"PID {pid}"
    return "artefact"


def _event_category(
    plugin_name: str,
    field_name: str,
    row: Mapping[str, object],
) -> str:
    plugin_key = _safe_lower(plugin_name)
    field_key = _safe_lower(field_name)

    if plugin_key in _PROCESS_GRAPH_PLUGINS:
        return "process"
    if plugin_key in _NETWORK_GRAPH_PLUGINS:
        return "network"
    if plugin_key in _SERVICE_GRAPH_PLUGINS:
        return "service"
    if "dll" in plugin_key or "module" in plugin_key:
        return "module"
    if any(token in field_key for token in ("create", "start", "exit", "logon")):
        return "process"
    if any(token in field_key for token in ("connect", "listen")):
        return "network"
    if any(token in _safe_lower(row.get(key)) for key in ("Path", "File")):
        return "file"
    return "other"


def _is_focus_event(event: Mapping[str, object]) -> bool:
    field_key = _safe_lower(event.get("field"))
    category = str(event.get("category") or "other")
    pid = event.get("pid")
    ppid = event.get("ppid")

    score = 0
    if pid is not None:
        score += 2
    if ppid is not None:
        score += 2
    if category in {"process", "network", "service"}:
        score += 2
    if any(token in field_key for token in _FOCUS_FIELD_HINTS):
        score += 2
    if any(token in field_key for token in _LOW_VALUE_FIELD_HINTS):
        score -= 1

    return score >= 4


def _format_timestamp_label(value: datetime, span: timedelta) -> str:
    if span >= timedelta(days=2):
        return value.strftime("%d %b %H:%M")
    if span >= timedelta(hours=1):
        return value.strftime("%H:%M:%S")
    if span >= timedelta(minutes=1):
        return value.strftime("%H:%M:%S")
    return value.strftime("%H:%M:%S.%f")[:12]


def _format_summary_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def _format_duration(span: timedelta) -> str:
    total_seconds = int(max(span.total_seconds(), 0))
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def _pluralize(value: int, singular: str, plural: str | None = None) -> str:
    plural = plural or f"{singular}s"
    return singular if value == 1 else plural


def _timeline_bounds(events: list[dict[str, Any]]) -> tuple[datetime, datetime] | None:
    if not events:
        return None
    return events[0]["timestamp"], events[-1]["timestamp"]


def _time_for_ratio(start: datetime, end: datetime, ratio: float) -> datetime:
    if end <= start:
        return start
    clamped_ratio = max(0.0, min(1.0, float(ratio)))
    return start + ((end - start) * clamped_ratio)


def _ratio_for_time(start: datetime, end: datetime, value: datetime) -> float:
    if end <= start:
        return 0.0
    span_seconds = (end - start).total_seconds()
    if span_seconds <= 0:
        return 0.0
    return max(
        0.0,
        min(1.0, (value - start).total_seconds() / span_seconds),
    )


def _category_color(category: str, palette) -> QColor:
    if category == "network":
        return palette.link().color()
    if category == "service":
        return palette.highlight().color().lighter(125)
    if category == "module":
        return palette.highlight().color().darker(115)
    if category == "file":
        return palette.highlight().color().lighter(140)
    return palette.highlight().color()


class TimelineNodeItem(QGraphicsEllipseItem):
    def __init__(
        self,
        rect: QRectF,
        events: list[dict[str, Any]],
        tooltip_text: str,
        activate_callback,
        pen: QPen,
        brush: QBrush,
    ) -> None:
        super().__init__(rect)
        self._events = list(events)
        self._activate_callback = activate_callback
        self.setPen(pen)
        self.setBrush(brush)
        self.setToolTip(tooltip_text)
        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setZValue(4)

    def mousePressEvent(self, event) -> None:
        if callable(self._activate_callback):
            self._activate_callback(self._events)
        super().mousePressEvent(event)


class TimelineOverviewWidget(QWidget):
    selection_changed = pyqtSignal(float, float)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._counts: list[int] = []
        self._selection = (0.0, 1.0)
        self._start_label = ""
        self._end_label = ""
        self._drag_anchor_ratio: float | None = None
        self.setMinimumHeight(132)
        self.setMouseTracking(True)

    def set_overview(
        self,
        counts: list[int],
        *,
        start_label: str,
        end_label: str,
    ) -> None:
        self._counts = list(counts)
        self._start_label = start_label
        self._end_label = end_label
        self.update()

    def set_selection(self, start_ratio: float, end_ratio: float) -> None:
        self._selection = self._normalize_selection(start_ratio, end_ratio)
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        palette = self.palette()

        painter.fillRect(self.rect(), palette.base().color())
        plot_rect = self._plot_rect()

        border_pen = QPen(palette.mid().color())
        border_pen.setWidthF(1.0)
        painter.setPen(border_pen)
        painter.drawRoundedRect(plot_rect, 8.0, 8.0)

        if not self._counts:
            painter.setPen(palette.text().color())
            painter.drawText(
                plot_rect.adjusted(12, 12, -12, -12),
                Qt.AlignmentFlag.AlignCenter,
                "No overview available",
            )
            return

        max_count = max(self._counts) or 1
        bar_gap = 2.0
        bar_width = max(
            3.0,
            (plot_rect.width() - ((len(self._counts) + 1) * bar_gap)) / len(self._counts),
        )
        highlight_color = palette.highlight().color()
        fill_color = QColor(highlight_color)
        fill_color.setAlpha(150)

        x = plot_rect.left() + bar_gap
        for count in self._counts:
            height_ratio = count / max_count
            bar_height = max(8.0, plot_rect.height() * height_ratio)
            painter.fillRect(
                QRectF(
                    x,
                    plot_rect.bottom() - bar_height,
                    bar_width,
                    bar_height,
                ),
                fill_color,
            )
            x += bar_width + bar_gap

        selection_start, selection_end = self._selection
        selection_left = plot_rect.left() + (plot_rect.width() * selection_start)
        selection_right = plot_rect.left() + (plot_rect.width() * selection_end)
        selection_rect = QRectF(
            selection_left,
            plot_rect.top(),
            max(8.0, selection_right - selection_left),
            plot_rect.height(),
        )
        selection_fill = QColor(palette.link().color())
        selection_fill.setAlpha(60)
        selection_pen = QPen(palette.link().color())
        selection_pen.setWidthF(1.4)
        painter.fillRect(selection_rect, selection_fill)
        painter.setPen(selection_pen)
        painter.drawRoundedRect(selection_rect, 6.0, 6.0)

        painter.setPen(palette.text().color())
        painter.drawText(
            QRectF(plot_rect.left(), plot_rect.bottom() + 6.0, 180.0, 18.0),
            self._start_label,
        )
        painter.drawText(
            QRectF(plot_rect.right() - 180.0, plot_rect.bottom() + 6.0, 180.0, 18.0),
            Qt.AlignmentFlag.AlignRight,
            self._end_label,
        )

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.MouseButton.LeftButton:
            super().mousePressEvent(event)
            return

        self._drag_anchor_ratio = self._ratio_for_x(event.position().x())
        self._update_selection_from_drag(self._drag_anchor_ratio, self._drag_anchor_ratio)
        event.accept()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._drag_anchor_ratio is None:
            super().mouseMoveEvent(event)
            return

        current_ratio = self._ratio_for_x(event.position().x())
        self._update_selection_from_drag(self._drag_anchor_ratio, current_ratio)
        event.accept()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if self._drag_anchor_ratio is None:
            super().mouseReleaseEvent(event)
            return

        current_ratio = self._ratio_for_x(event.position().x())
        if abs(current_ratio - self._drag_anchor_ratio) < 0.01:
            current_width = max(0.1, self._selection[1] - self._selection[0])
            half_width = current_width / 2.0
            start_ratio = max(0.0, current_ratio - half_width)
            end_ratio = min(1.0, current_ratio + half_width)
            if end_ratio - start_ratio < current_width:
                start_ratio = max(0.0, end_ratio - current_width)
                end_ratio = min(1.0, start_ratio + current_width)
            self._emit_selection(start_ratio, end_ratio)
        else:
            self._update_selection_from_drag(self._drag_anchor_ratio, current_ratio)

        self._drag_anchor_ratio = None
        event.accept()

    def _plot_rect(self) -> QRectF:
        return QRectF(
            14.0,
            18.0,
            max(120.0, self.width() - 28.0),
            max(40.0, self.height() - 44.0),
        )

    def _ratio_for_x(self, x_value: float) -> float:
        plot_rect = self._plot_rect()
        if plot_rect.width() <= 0:
            return 0.0
        return max(
            0.0,
            min(1.0, (float(x_value) - plot_rect.left()) / plot_rect.width()),
        )

    def _normalize_selection(self, start_ratio: float, end_ratio: float) -> tuple[float, float]:
        left = max(0.0, min(float(start_ratio), float(end_ratio)))
        right = min(1.0, max(float(start_ratio), float(end_ratio)))
        minimum_width = 0.02
        if right - left < minimum_width:
            midpoint = (left + right) / 2.0
            left = max(0.0, midpoint - (minimum_width / 2.0))
            right = min(1.0, midpoint + (minimum_width / 2.0))
            if right - left < minimum_width:
                left = max(0.0, right - minimum_width)
                right = min(1.0, left + minimum_width)
        return left, right

    def _emit_selection(self, start_ratio: float, end_ratio: float) -> None:
        self._selection = self._normalize_selection(start_ratio, end_ratio)
        self.update()
        self.selection_changed.emit(*self._selection)

    def _update_selection_from_drag(self, anchor_ratio: float, current_ratio: float) -> None:
        self._emit_selection(anchor_ratio, current_ratio)


class TimelineGraphicsView(QGraphicsView):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        self.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)

    def wheelEvent(self, event: QWheelEvent) -> None:
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            if delta == 0:
                event.accept()
                return

            scale_factor = 1.18 if delta > 0 else 1 / 1.18
            current_scale = self.transform().m11()
            next_scale = current_scale * scale_factor
            if 0.3 <= next_scale <= 8.0:
                self.scale(scale_factor, scale_factor)
            event.accept()
            return

        super().wheelEvent(event)

    def reset_view(self) -> None:
        self.resetTransform()
        self.horizontalScrollBar().setValue(self.horizontalScrollBar().minimum())
        midpoint = (
            self.verticalScrollBar().minimum() + self.verticalScrollBar().maximum()
        ) // 2
        self.verticalScrollBar().setValue(midpoint)


class TimelineGraphView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._all_events: list[dict[str, Any]] = []
        self._focus_events: list[dict[str, Any]] = []
        self._active_events: list[dict[str, Any]] = []
        self._selected_ratios = (0.0, 1.0)
        self._event_count = 0
        self._lane_count = 0
        self._relationship_count = 0
        self._current_mode = "focus"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.summary_label = QLabel(self)
        self.summary_label.setObjectName("supportingText")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        controls_row = QHBoxLayout()
        controls_row.addWidget(QLabel("View:"))
        self.filter_combo = QComboBox(self)
        self.filter_combo.addItem("Investigation Events", "focus")
        self.filter_combo.addItem("All Timestamped Events", "all")
        self.filter_combo.currentIndexChanged.connect(self._filter_mode_changed)
        controls_row.addWidget(self.filter_combo)
        self.reset_focus_button = QPushButton("Show Full Range", self)
        self.reset_focus_button.clicked.connect(self._show_full_range)
        controls_row.addWidget(self.reset_focus_button)
        controls_row.addStretch(1)
        layout.addLayout(controls_row)

        self.overview_label = QLabel(self)
        self.overview_label.setObjectName("supportingText")
        self.overview_label.setWordWrap(True)
        layout.addWidget(self.overview_label)

        self.overview_widget = TimelineOverviewWidget(self)
        self.overview_widget.selection_changed.connect(self._selection_changed)
        layout.addWidget(self.overview_widget)

        self.focus_label = QLabel(self)
        self.focus_label.setObjectName("supportingText")
        self.focus_label.setWordWrap(True)
        layout.addWidget(self.focus_label)

        detail_splitter = QSplitter(Qt.Orientation.Horizontal, self)
        self.graphics_view = TimelineGraphicsView(self)
        detail_splitter.addWidget(self.graphics_view)

        self.details_view = QPlainTextEdit(self)
        self.details_view.setReadOnly(True)
        self.details_view.setMinimumWidth(300)
        detail_splitter.addWidget(self.details_view)
        detail_splitter.setSizes([920, 340])
        layout.addWidget(detail_splitter, stretch=1)

        self.set_timeline([])

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def lane_count(self) -> int:
        return self._lane_count

    @property
    def relationship_count(self) -> int:
        return self._relationship_count

    def set_timeline(self, events: Iterable[Mapping[str, object]]) -> None:
        prepared_events = []
        for event in events or []:
            if not isinstance(event, Mapping):
                continue

            timestamp = _parse_timestamp(event.get("timestamp"))
            if timestamp is None:
                continue

            row = event.get("row")
            row_mapping = dict(row) if isinstance(row, Mapping) else {}

            event_pid = event.get("pid")
            if event_pid in (None, ""):
                event_pid = _find_first(row_mapping, *_PID_FIELD_HINTS)
            pid = _safe_int(event_pid)

            event_ppid = event.get("ppid")
            if event_ppid in (None, ""):
                event_ppid = _find_first(row_mapping, *_PPID_FIELD_HINTS)
            ppid = _safe_int(event_ppid)

            entity_label = str(
                event.get("entity_label")
                or _identity_from_row(row_mapping)
                or event.get("description")
                or "artefact"
            )
            lane_key = (
                f"pid:{pid}"
                if pid is not None
                else f"entity:{_safe_lower(entity_label)}"
            )
            display_label = entity_label
            if pid is not None and f"pid {pid}" not in _safe_lower(display_label):
                display_label = f"{display_label} (PID {pid})"

            plugin_name = str(event.get("plugin", ""))
            field_name = str(event.get("field", ""))
            category = _event_category(plugin_name, field_name, row_mapping)

            prepared_events.append(
                {
                    "timestamp": timestamp,
                    "timestamp_text": str(event.get("timestamp", "")),
                    "plugin": plugin_name,
                    "field": field_name,
                    "description": str(event.get("description", "")),
                    "entity_label": entity_label,
                    "display_label": display_label,
                    "lane_key": lane_key,
                    "pid": pid,
                    "ppid": ppid,
                    "category": category,
                    "raw_value": event.get("raw_value"),
                    "row": row_mapping,
                }
            )

        prepared_events.sort(
            key=lambda item: (
                item["timestamp"],
                item["lane_key"],
                item["description"],
                item["plugin"],
            )
        )

        self._all_events = prepared_events
        self._focus_events = [event for event in prepared_events if _is_focus_event(event)]
        self._configure_default_mode()
        self._refresh_view(reset_selection=True, reset_detail_view=True)

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() in {QEvent.Type.PaletteChange, QEvent.Type.StyleChange}:
            self._refresh_view(reset_selection=False, reset_detail_view=False)

    def _configure_default_mode(self) -> None:
        use_focus_mode = (
            len(self._focus_events) >= 2
            and len(self._focus_events) < len(self._all_events)
        )
        self._current_mode = "focus" if use_focus_mode else "all"

        self.filter_combo.blockSignals(True)
        self.filter_combo.setCurrentIndex(0 if self._current_mode == "focus" else 1)
        self.filter_combo.setEnabled(
            bool(self._focus_events) and len(self._focus_events) < len(self._all_events)
        )
        self.filter_combo.blockSignals(False)

    def _filter_mode_changed(self, index: int) -> None:
        selected_mode = str(self.filter_combo.itemData(index) or "all")
        self._current_mode = selected_mode
        self._refresh_view(reset_selection=True, reset_detail_view=True)

    def _selection_changed(self, start_ratio: float, end_ratio: float) -> None:
        self._selected_ratios = (start_ratio, end_ratio)
        self._refresh_view(reset_selection=False, reset_detail_view=True)

    def _show_full_range(self) -> None:
        self._selected_ratios = (0.0, 1.0)
        self._refresh_view(reset_selection=False, reset_detail_view=True)

    def _active_event_set(self) -> list[dict[str, Any]]:
        if self._current_mode == "focus" and self._focus_events:
            return self._focus_events
        return self._all_events

    def _refresh_view(
        self,
        *,
        reset_selection: bool,
        reset_detail_view: bool,
    ) -> None:
        self._active_events = self._active_event_set()
        self._event_count = len(self._active_events)

        if not self._active_events:
            self._lane_count = 0
            self._relationship_count = 0
            self.summary_label.setText(
                "No timeline graph is available for the current investigation. "
                "Run an investigation with timestamped artefacts to unlock the "
                "overview, detail view, and node inspection."
            )
            self.overview_label.setText(
                "When timeline data is available, the overview will let you brush "
                "across dense periods instead of reading every node at once."
            )
            self.focus_label.setText(
                "Hover will show quick summaries, and clicking a node will open "
                "full evidence in the panel on the right."
            )
            self.overview_widget.set_overview([], start_label="", end_label="")
            self.overview_widget.set_selection(0.0, 1.0)
            self.details_view.setPlainText(
                "No timeline details are available yet."
            )
            self._rebuild_detail_scene([], reset_view=reset_detail_view)
            return

        bounds = _timeline_bounds(self._active_events)
        assert bounds is not None
        timeline_start, timeline_end = bounds

        if reset_selection:
            self._selected_ratios = self._initial_selection_ratios(self._active_events)
        else:
            left_ratio, right_ratio = self._selected_ratios
            self._selected_ratios = (
                max(0.0, min(left_ratio, right_ratio)),
                min(1.0, max(left_ratio, right_ratio)),
            )

        overview_counts = self._build_overview_counts(self._active_events)
        self.overview_widget.set_overview(
            overview_counts,
            start_label=_format_timestamp_label(
                timeline_start,
                timeline_end - timeline_start,
            ),
            end_label=_format_timestamp_label(
                timeline_end,
                timeline_end - timeline_start,
            ),
        )
        self.overview_widget.set_selection(*self._selected_ratios)

        window_start = _time_for_ratio(
            timeline_start,
            timeline_end,
            self._selected_ratios[0],
        )
        window_end = _time_for_ratio(
            timeline_start,
            timeline_end,
            self._selected_ratios[1],
        )
        selected_events = [
            event
            for event in self._active_events
            if window_start <= event["timestamp"] <= window_end
        ]
        if not selected_events:
            midpoint = _time_for_ratio(
                timeline_start,
                timeline_end,
                (self._selected_ratios[0] + self._selected_ratios[1]) / 2.0,
            )
            nearest_event = min(
                self._active_events,
                key=lambda item: abs((item["timestamp"] - midpoint).total_seconds()),
            )
            selected_events = [nearest_event]

        visible_lane_count = len({event["lane_key"] for event in selected_events})
        mode_label = (
            "investigation events"
            if self._active_events is self._focus_events and self._focus_events
            else "all timestamped events"
        )
        total_bounds = _timeline_bounds(self._all_events)
        assert total_bounds is not None
        total_span = total_bounds[1] - total_bounds[0]

        self.summary_label.setText(
            f"Showing {len(self._active_events)} {mode_label} from "
            f"{len(self._all_events)} total timeline {_pluralize(len(self._all_events), 'event')}. "
            f"Observed range: {_format_summary_time(total_bounds[0])} to "
            f"{_format_summary_time(total_bounds[1])} ({_format_duration(total_span)}). "
            "Use the overview to select a dense period, then drag to pan and hold Ctrl "
            "+ mouse wheel to zoom the detailed graph."
        )
        self.overview_label.setText(
            "The overview compresses the full sample range into a density strip so "
            "you can brush a smaller investigation window instead of rendering every "
            "event at full scale."
        )
        self.focus_label.setText(
            f"Focused window: {_format_summary_time(selected_events[0]['timestamp'])} to "
            f"{_format_summary_time(selected_events[-1]['timestamp'])}. "
            f"{len(selected_events)} {_pluralize(len(selected_events), 'event')} across "
            f"{visible_lane_count} {_pluralize(visible_lane_count, 'lane')}. "
            "Hover a node for a quick summary or click it to inspect the underlying evidence."
        )

        if reset_detail_view:
            self.details_view.setPlainText(
                "Click a node to inspect its evidence.\n\n"
                f"Current window: {len(selected_events)} {_pluralize(len(selected_events), 'event')} "
                f"across {visible_lane_count} {_pluralize(visible_lane_count, 'lane')}."
            )

        self._rebuild_detail_scene(selected_events, reset_view=reset_detail_view)

    def _initial_selection_ratios(
        self,
        events: list[dict[str, Any]],
    ) -> tuple[float, float]:
        if len(events) <= 24:
            return (0.0, 1.0)

        bounds = _timeline_bounds(events)
        assert bounds is not None
        timeline_start, timeline_end = bounds
        overall_span = timeline_end - timeline_start
        if overall_span <= timedelta(0):
            return (0.0, 1.0)

        window_size = min(len(events), max(8, len(events) // 5))
        best_start = timeline_start
        best_end = timeline_end
        best_span = overall_span

        for index in range(0, len(events) - window_size + 1):
            candidate_start = events[index]["timestamp"]
            candidate_end = events[index + window_size - 1]["timestamp"]
            candidate_span = candidate_end - candidate_start
            if candidate_span < best_span:
                best_start = candidate_start
                best_end = candidate_end
                best_span = candidate_span

        padding = max(best_span * 0.5, overall_span * 0.05)
        focus_start = max(timeline_start, best_start - padding)
        focus_end = min(timeline_end, best_end + padding)

        if focus_end <= focus_start:
            return (0.0, 1.0)

        return (
            _ratio_for_time(timeline_start, timeline_end, focus_start),
            _ratio_for_time(timeline_start, timeline_end, focus_end),
        )

    def _build_overview_counts(self, events: list[dict[str, Any]]) -> list[int]:
        if not events:
            return []

        bounds = _timeline_bounds(events)
        assert bounds is not None
        timeline_start, timeline_end = bounds
        if timeline_end <= timeline_start:
            return [len(events)]

        bin_count = min(96, max(28, len(events) // 3))
        counts = [0 for _ in range(bin_count)]
        span_seconds = (timeline_end - timeline_start).total_seconds()
        for event in events:
            ratio = (event["timestamp"] - timeline_start).total_seconds() / span_seconds
            index = min(bin_count - 1, max(0, int(ratio * bin_count)))
            counts[index] += 1
        return counts

    def _rebuild_detail_scene(
        self,
        events: list[dict[str, Any]],
        *,
        reset_view: bool,
    ) -> None:
        scene = self.graphics_view.scene()
        if scene is None:
            return

        scene.clear()
        palette = self.palette()
        scene.setBackgroundBrush(QBrush(palette.base().color()))

        if not events:
            self._lane_count = 0
            self._relationship_count = 0
            placeholder = scene.addSimpleText("No events in the current focus window")
            placeholder.setBrush(QBrush(palette.text().color()))
            placeholder.setPos(28, 24)
            placeholder.setFlag(
                QGraphicsItem.GraphicsItemFlag.ItemIgnoresTransformations,
                True,
            )
            scene.setSceneRect(0, 0, 960, 300)
            if reset_view:
                self.graphics_view.reset_view()
            return

        grouped_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            grouped_events[event["lane_key"]].append(event)

        lane_items = []
        pid_to_lane_key: dict[int, str] = {}
        for lane_key, lane_events in grouped_events.items():
            first_event = lane_events[0]
            lane_items.append(
                {
                    "lane_key": lane_key,
                    "label": first_event["display_label"],
                    "pid": first_event["pid"],
                    "ppid": next(
                        (
                            event["ppid"]
                            for event in lane_events
                            if event["ppid"] is not None
                        ),
                        None,
                    ),
                    "events": lane_events,
                    "first_seen": min(event["timestamp"] for event in lane_events),
                }
            )
            if first_event["pid"] is not None:
                pid_to_lane_key[first_event["pid"]] = lane_key

        lane_items.sort(
            key=lambda item: (item["first_seen"], _safe_lower(item["label"]))
        )
        lane_positions = {
            item["lane_key"]: index for index, item in enumerate(lane_items)
        }

        detail_start = events[0]["timestamp"]
        detail_end = events[-1]["timestamp"]
        actual_span = detail_end - detail_start
        render_span = max(actual_span, timedelta(seconds=1))

        left_margin = 250.0
        right_margin = 120.0
        top_margin = 72.0
        lane_height = 68.0
        bottom_margin = 96.0
        content_width = max(1100.0, min(4200.0, 840.0 + (len(events) * 26.0)))
        axis_y = top_margin + ((len(lane_items) - 1) * lane_height) + 34.0
        scene_width = left_margin + content_width + right_margin
        scene_height = axis_y + bottom_margin

        axis_pen = QPen(palette.text().color())
        axis_pen.setWidthF(1.4)
        axis_pen.setCosmetic(True)

        guide_pen = QPen(palette.mid().color())
        guide_pen.setWidthF(1.0)
        guide_pen.setStyle(Qt.PenStyle.DashLine)
        guide_pen.setCosmetic(True)

        lane_pen = QPen(palette.mid().color())
        lane_pen.setWidthF(1.0)
        lane_pen.setCosmetic(True)

        sibling_pen = QPen(palette.highlight().color().lighter(150))
        sibling_pen.setWidthF(1.6)
        sibling_pen.setCosmetic(True)

        relationship_pen = QPen(palette.link().color())
        relationship_pen.setWidthF(1.4)
        relationship_pen.setStyle(Qt.PenStyle.DashLine)
        relationship_pen.setCosmetic(True)

        def x_for_timestamp(timestamp: datetime) -> float:
            if detail_end <= detail_start:
                return left_margin + (content_width / 2.0)
            offset = (timestamp - detail_start).total_seconds()
            return left_margin + ((offset / render_span.total_seconds()) * content_width)

        def lane_y(lane_key: str) -> float:
            return top_margin + (lane_positions[lane_key] * lane_height)

        tick_count = 1 if actual_span <= timedelta(0) else 6
        for tick_index in range(tick_count):
            fraction = tick_index / (tick_count - 1) if tick_count > 1 else 0.0
            tick_time = detail_start + (actual_span * fraction)
            x = x_for_timestamp(tick_time)
            scene.addLine(x, top_margin - 22.0, x, axis_y + 12.0, guide_pen)
            tick_label = scene.addSimpleText(
                _format_timestamp_label(tick_time, actual_span)
            )
            tick_label.setBrush(QBrush(palette.text().color()))
            tick_label.setPos(x - 34.0, axis_y + 18.0)
            tick_label.setFlag(
                QGraphicsItem.GraphicsItemFlag.ItemIgnoresTransformations,
                True,
            )

        scene.addLine(left_margin, axis_y, left_margin + content_width, axis_y, axis_pen)

        parent_child_links = []
        relationship_keys = set()
        max_drawn_x = left_margin + content_width

        for item in lane_items:
            lane_key = item["lane_key"]
            y = lane_y(lane_key)

            scene.addLine(left_margin, y, left_margin + content_width, y, lane_pen)
            label_item = scene.addSimpleText(item["label"])
            label_item.setBrush(QBrush(palette.text().color()))
            label_item.setPos(18.0, y - 12.0)
            label_item.setFlag(
                QGraphicsItem.GraphicsItemFlag.ItemIgnoresTransformations,
                True,
            )

            child_pid = item["pid"]
            parent_pid = item["ppid"]
            if (
                child_pid is not None
                and parent_pid is not None
                and parent_pid in pid_to_lane_key
                and pid_to_lane_key[parent_pid] != lane_key
            ):
                first_child_event = min(
                    item["events"],
                    key=lambda event: (
                        event["timestamp"],
                        event["description"],
                        event["plugin"],
                    ),
                )
                relationship_key = (
                    pid_to_lane_key[parent_pid],
                    lane_key,
                    first_child_event["timestamp"],
                )
                if relationship_key not in relationship_keys:
                    relationship_keys.add(relationship_key)
                    parent_child_links.append(
                        {
                            "parent_lane_key": pid_to_lane_key[parent_pid],
                            "child_lane_key": lane_key,
                            "timestamp": first_child_event["timestamp"],
                        }
                    )

            time_groups: dict[datetime, list[dict[str, Any]]] = defaultdict(list)
            for event in item["events"]:
                time_groups[event["timestamp"]].append(event)

            clusters = []
            ordered_groups = sorted(time_groups.items(), key=lambda grouped: grouped[0])
            minimum_gap = 22.0
            previous_x: float | None = None
            for timestamp, grouped in ordered_groups:
                x_position = x_for_timestamp(timestamp)
                if previous_x is not None and x_position - previous_x < minimum_gap:
                    x_position = previous_x + minimum_gap
                previous_x = x_position
                max_drawn_x = max(max_drawn_x, x_position)
                clusters.append(
                    {
                        "timestamp": timestamp,
                        "events": sorted(
                            grouped,
                            key=lambda event: (
                                event["description"],
                                event["plugin"],
                                event["field"],
                            ),
                        ),
                        "x": x_position,
                        "y": y,
                    }
                )

            for first_cluster, second_cluster in zip(clusters, clusters[1:]):
                scene.addLine(
                    first_cluster["x"],
                    first_cluster["y"],
                    second_cluster["x"],
                    second_cluster["y"],
                    sibling_pen,
                )

            for cluster in clusters:
                category = str(cluster["events"][0].get("category") or "other")
                color = _category_color(category, palette)
                node_pen = QPen(color.darker(120))
                node_pen.setWidthF(1.4)
                node_pen.setCosmetic(True)
                node_brush = QBrush(color)
                radius = 7.0 + min(7.0, float(len(cluster["events"]) - 1))

                tooltip_text = self._build_cluster_tooltip(cluster["events"])
                node_item = TimelineNodeItem(
                    QRectF(
                        cluster["x"] - radius,
                        cluster["y"] - radius,
                        radius * 2.0,
                        radius * 2.0,
                    ),
                    cluster["events"],
                    tooltip_text,
                    self._select_event_group,
                    node_pen,
                    node_brush,
                )
                scene.addItem(node_item)

                if len(cluster["events"]) > 1:
                    count_item = scene.addSimpleText(str(len(cluster["events"])))
                    count_item.setBrush(QBrush(palette.brightText().color()))
                    count_item.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
                    count_item.setZValue(5)
                    count_bounds = count_item.boundingRect()
                    count_item.setPos(
                        cluster["x"] - (count_bounds.width() / 2.0),
                        cluster["y"] - (count_bounds.height() / 2.0),
                    )

        for link in parent_child_links:
            x = x_for_timestamp(link["timestamp"])
            parent_y = lane_y(link["parent_lane_key"])
            child_y = lane_y(link["child_lane_key"])
            scene.addLine(x, parent_y, x, child_y, relationship_pen)

        self._lane_count = len(lane_items)
        self._relationship_count = len(parent_child_links)
        scene_width = max(scene_width, max_drawn_x + right_margin)
        scene.setSceneRect(0, 0, scene_width, scene_height)
        if reset_view:
            self.graphics_view.reset_view()

    def _build_cluster_tooltip(self, events: list[dict[str, Any]]) -> str:
        if len(events) == 1:
            event = events[0]
            lines = [
                event.get("timestamp_text") or str(event.get("timestamp") or ""),
                str(event.get("description") or ""),
            ]
            if event.get("plugin"):
                lines.append(f"Plugin: {event['plugin']}")
            if event.get("field"):
                lines.append(f"Field: {event['field']}")
            if event.get("pid") is not None:
                lines.append(f"PID: {event['pid']}")
            if event.get("ppid") is not None:
                lines.append(f"Parent PID: {event['ppid']}")
            lines.append("Click for full evidence.")
            return "\n".join(line for line in lines if line)

        sample_lines = [
            f"{len(events)} grouped events at "
            f"{events[0].get('timestamp_text') or str(events[0].get('timestamp') or '')}",
        ]
        for event in events[:4]:
            sample_lines.append(f"- {event.get('description') or 'Timeline event'}")
        if len(events) > 4:
            sample_lines.append(f"- ... and {len(events) - 4} more")
        sample_lines.append("Click for full evidence.")
        return "\n".join(sample_lines)

    def _select_event_group(self, events: list[dict[str, Any]]) -> None:
        if not events:
            self.details_view.setPlainText("No event details are available.")
            return

        ordered_events = sorted(
            events,
            key=lambda event: (
                event["timestamp"],
                event["description"],
                event["plugin"],
                event["field"],
            ),
        )
        if len(ordered_events) == 1:
            self.details_view.setPlainText(
                self._format_single_event_details(ordered_events[0])
            )
            return

        lines = [
            f"{len(ordered_events)} grouped events",
            "",
            f"Time: {ordered_events[0].get('timestamp_text') or str(ordered_events[0].get('timestamp') or '')}",
            f"Entity: {ordered_events[0].get('display_label') or ordered_events[0].get('entity_label') or 'Unknown'}",
            "",
            "Included events:",
        ]
        for index, event in enumerate(ordered_events, start=1):
            lines.append(
                f"{index}. {event.get('description') or 'Timeline event'} "
                f"[{event.get('plugin') or 'unknown plugin'} / {event.get('field') or 'unknown field'}]"
            )
        self.details_view.setPlainText("\n".join(lines))

    def _format_single_event_details(self, event: Mapping[str, Any]) -> str:
        lines = [
            "Selected timeline event",
            "",
            f"Time: {event.get('timestamp_text') or str(event.get('timestamp') or '')}",
            f"Entity: {event.get('display_label') or event.get('entity_label') or 'Unknown'}",
            f"Category: {event.get('category') or 'other'}",
            f"Plugin: {event.get('plugin') or 'Unknown'}",
            f"Field: {event.get('field') or 'Unknown'}",
            f"Description: {event.get('description') or ''}",
        ]

        if event.get("pid") is not None:
            lines.append(f"PID: {event['pid']}")
        if event.get("ppid") is not None:
            lines.append(f"Parent PID: {event['ppid']}")
        if event.get("raw_value") not in (None, ""):
            lines.append(f"Raw timestamp value: {event['raw_value']}")

        row = event.get("row")
        if isinstance(row, Mapping) and row:
            lines.extend(["", "Raw row:"])
            for key, value in list(row.items())[:20]:
                lines.append(f"{key}: {value}")
            if len(row) > 20:
                lines.append(f"... {len(row) - 20} more field(s)")

        return "\n".join(lines)
