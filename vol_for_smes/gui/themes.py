"""
Theme definitions for the Vol For SMEs GUI.
"""

from __future__ import annotations

from dataclasses import dataclass
from textwrap import dedent

from PyQt6.QtWidgets import QApplication

from ..config import DEFAULT_UI_THEME


@dataclass(frozen=True)
class ThemeDefinition:
    name: str
    label: str
    description: str
    background: str
    panel: str
    surface: str
    surface_alt: str
    text: str
    muted_text: str
    border: str
    accent: str
    accent_hover: str
    accent_pressed: str
    accent_text: str
    input_background: str
    selection: str
    selection_text: str
    warning_background: str
    warning_border: str
    warning_text: str

    @property
    def stylesheet(self) -> str:
        return dedent(
            f"""
            QWidget {{
                background-color: {self.background};
                color: {self.text};
            }}
            QWidget#controlPanel, QWidget#resultsPanel {{
                background-color: {self.panel};
            }}
            QLabel {{
                color: {self.text};
            }}
            QLabel#pageTitle {{
                color: {self.text};
                font-size: 20px;
                font-weight: 700;
            }}
            QLabel#supportingText, QLabel#catalogStatus {{
                color: {self.muted_text};
            }}
            QLabel#warningBanner {{
                background-color: {self.warning_background};
                color: {self.warning_text};
                border: 1px solid {self.warning_border};
                border-radius: 8px;
                padding: 8px;
            }}
            QGroupBox {{
                background-color: {self.surface};
                border: 1px solid {self.border};
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: 600;
            }}
            QGroupBox::title {{
                color: {self.text};
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 4px;
            }}
            QLineEdit,
            QPlainTextEdit,
            QComboBox,
            QTableWidget,
            QTreeWidget,
            QHeaderView::section {{
                background-color: {self.input_background};
                color: {self.text};
                border: 1px solid {self.border};
            }}
            QLineEdit,
            QPlainTextEdit,
            QComboBox {{
                border-radius: 8px;
                padding: 6px 8px;
            }}
            QLineEdit::placeholder {{
                color: {self.muted_text};
            }}
            QComboBox::drop-down {{
                border: none;
                width: 24px;
            }}
            QComboBox QAbstractItemView,
            QTreeWidget QAbstractItemView,
            QTableWidget QAbstractItemView {{
                background-color: {self.surface};
                color: {self.text};
                selection-background-color: {self.selection};
                selection-color: {self.selection_text};
                alternate-background-color: {self.surface_alt};
                border: 1px solid {self.border};
            }}
            QTableWidget,
            QTreeWidget {{
                alternate-background-color: {self.surface_alt};
                gridline-color: {self.border};
                border-radius: 8px;
            }}
            QTableWidget::item:selected,
            QTreeWidget::item:selected,
            QTabBar::tab:selected {{
                background-color: {self.selection};
                color: {self.selection_text};
            }}
            QHeaderView::section {{
                padding: 6px;
                font-weight: 600;
            }}
            QPushButton {{
                background-color: {self.accent};
                color: {self.accent_text};
                border: 1px solid {self.accent};
                border-radius: 8px;
                padding: 7px 12px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {self.accent_hover};
                border-color: {self.accent_hover};
            }}
            QPushButton:pressed {{
                background-color: {self.accent_pressed};
                border-color: {self.accent_pressed};
            }}
            QPushButton:disabled {{
                background-color: {self.surface_alt};
                color: {self.muted_text};
                border-color: {self.border};
            }}
            QTabWidget::pane {{
                border: 1px solid {self.border};
                background-color: {self.surface};
                border-radius: 10px;
            }}
            QTabBar::tab {{
                background-color: {self.surface_alt};
                color: {self.text};
                border: 1px solid {self.border};
                padding: 8px 12px;
                margin-right: 4px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }}
            QStatusBar {{
                background-color: {self.surface};
                color: {self.text};
                border-top: 1px solid {self.border};
            }}
            QSplitter::handle {{
                background-color: {self.border};
            }}
            QMessageBox,
            QDialog {{
                background-color: {self.panel};
                color: {self.text};
            }}
            """
        ).strip()


THEMES = {
    "cyber_ocean": ThemeDefinition(
        name="cyber_ocean",
        label="Cyber Ocean",
        description="Deep navy panels with cyan accents for a professional forensic workspace.",
        background="#07111F",
        panel="#0D1B2A",
        surface="#13293D",
        surface_alt="#18344C",
        text="#EAF6FF",
        muted_text="#A9C6D9",
        border="#2A4D69",
        accent="#00B4D8",
        accent_hover="#0096C7",
        accent_pressed="#007EA5",
        accent_text="#04131D",
        input_background="#0A1624",
        selection="#1F5F8B",
        selection_text="#F4FBFF",
        warning_background="#3A2A0A",
        warning_border="#F4A261",
        warning_text="#FFF1D6",
    ),
    "forensic_slate": ThemeDefinition(
        name="forensic_slate",
        label="Forensic Slate",
        description="A conservative enterprise security palette with blue-grey structure and crisp text.",
        background="#111827",
        panel="#1F2937",
        surface="#273449",
        surface_alt="#1E293B",
        text="#F8FAFC",
        muted_text="#CBD5E1",
        border="#475569",
        accent="#3B82F6",
        accent_hover="#2563EB",
        accent_pressed="#1D4ED8",
        accent_text="#F8FAFC",
        input_background="#16202E",
        selection="#35537B",
        selection_text="#F8FAFC",
        warning_background="#3E2A05",
        warning_border="#F59E0B",
        warning_text="#FFF3D1",
    ),
    "threat_intelligence_purple": ThemeDefinition(
        name="threat_intelligence_purple",
        label="Threat Intelligence Purple",
        description="A modern midnight palette with violet accents and bright blue highlights.",
        background="#0B1020",
        panel="#111827",
        surface="#1E1B3A",
        surface_alt="#17152E",
        text="#F5F3FF",
        muted_text="#C4B5FD",
        border="#4C1D95",
        accent="#8B5CF6",
        accent_hover="#7C3AED",
        accent_pressed="#6D28D9",
        accent_text="#F8F5FF",
        input_background="#14132A",
        selection="#4338CA",
        selection_text="#F8F6FF",
        warning_background="#3B2A05",
        warning_border="#FBBF24",
        warning_text="#FFF4D6",
    ),
    "incident_amber": ThemeDefinition(
        name="incident_amber",
        label="Incident Amber",
        description="A triage-focused dark theme that uses amber accents to foreground caution and review.",
        background="#111111",
        panel="#1A1A1A",
        surface="#222222",
        surface_alt="#2A2418",
        text="#FFF7ED",
        muted_text="#D6D3D1",
        border="#5C4520",
        accent="#F59E0B",
        accent_hover="#D97706",
        accent_pressed="#B45309",
        accent_text="#1A1204",
        input_background="#171717",
        selection="#7C5A12",
        selection_text="#FFF7ED",
        warning_background="#3B2A05",
        warning_border="#FBBF24",
        warning_text="#FFF1CC",
    ),
    "high_contrast_dark": ThemeDefinition(
        name="high_contrast_dark",
        label="High Contrast Dark",
        description="Accessibility-first dark mode with near-black panels and very strong text separation.",
        background="#000000",
        panel="#0A0A0A",
        surface="#111111",
        surface_alt="#181818",
        text="#FFFFFF",
        muted_text="#E5E7EB",
        border="#FFFFFF",
        accent="#00E5FF",
        accent_hover="#00B8D4",
        accent_pressed="#0097B2",
        accent_text="#001216",
        input_background="#050505",
        selection="#FFD60A",
        selection_text="#111111",
        warning_background="#2D1B00",
        warning_border="#FFD60A",
        warning_text="#FFF7CC",
    ),
    "cyber_ocean_light": ThemeDefinition(
        name="cyber_ocean_light",
        label="Cyber Ocean Light",
        description="A bright blue-and-teal light theme that keeps the cyber identity without beige tones.",
        background="#F3F8FB",
        panel="#FFFFFF",
        surface="#EAF4F8",
        surface_alt="#FFFFFF",
        text="#102A43",
        muted_text="#486581",
        border="#B7CEDA",
        accent="#0077B6",
        accent_hover="#005F8F",
        accent_pressed="#004C73",
        accent_text="#F8FCFF",
        input_background="#FFFFFF",
        selection="#B9E0F2",
        selection_text="#102A43",
        warning_background="#FFF3CD",
        warning_border="#D39E00",
        warning_text="#6B4E00",
    ),
    "clean_analyst_light": ThemeDefinition(
        name="clean_analyst_light",
        label="Clean Analyst Light",
        description="A polished reporting-style light theme with cooler neutrals and stronger accents.",
        background="#F8FAFC",
        panel="#FFFFFF",
        surface="#F1F5F9",
        surface_alt="#FFFFFF",
        text="#0F172A",
        muted_text="#475569",
        border="#CBD5E1",
        accent="#2563EB",
        accent_hover="#1D4ED8",
        accent_pressed="#1E40AF",
        accent_text="#F8FAFC",
        input_background="#FFFFFF",
        selection="#BFDBFE",
        selection_text="#0F172A",
        warning_background="#FEF3C7",
        warning_border="#F59E0B",
        warning_text="#7C4A03",
    ),
    "executive_report": ThemeDefinition(
        name="executive_report",
        label="Executive Report",
        description="A neutral business-friendly light theme designed to look strong in screenshots and reports.",
        background="#F6F7F9",
        panel="#FFFFFF",
        surface="#FFFFFF",
        surface_alt="#F3F4F6",
        text="#111827",
        muted_text="#4B5563",
        border="#D1D5DB",
        accent="#1F4E79",
        accent_hover="#173B5C",
        accent_pressed="#102B43",
        accent_text="#F9FBFF",
        input_background="#FFFFFF",
        selection="#D6E6F5",
        selection_text="#111827",
        warning_background="#FFF3E0",
        warning_border="#B45309",
        warning_text="#6C2E05",
    ),
    "muted_mint_analyst": ThemeDefinition(
        name="muted_mint_analyst",
        label="Muted Mint Analyst",
        description="A softer light theme with calm green-blue accents for a more approachable security feel.",
        background="#F4FBF8",
        panel="#FFFFFF",
        surface="#E8F5F0",
        surface_alt="#FFFFFF",
        text="#10231F",
        muted_text="#4B635C",
        border="#B7D8CE",
        accent="#0F766E",
        accent_hover="#115E59",
        accent_pressed="#0B4F4B",
        accent_text="#F3FFFC",
        input_background="#FFFFFF",
        selection="#CFE9DF",
        selection_text="#10231F",
        warning_background="#FFF1E2",
        warning_border="#D97706",
        warning_text="#6F3A03",
    ),
    "high_contrast_light": ThemeDefinition(
        name="high_contrast_light",
        label="High Contrast Light",
        description="Accessibility-first light mode with crisp borders and strong dark text for readability.",
        background="#FFFFFF",
        panel="#F5F5F5",
        surface="#FFFFFF",
        surface_alt="#FAFAFA",
        text="#000000",
        muted_text="#1F2937",
        border="#000000",
        accent="#0038FF",
        accent_hover="#0026B3",
        accent_pressed="#001D80",
        accent_text="#FFFFFF",
        input_background="#FFFFFF",
        selection="#FFD60A",
        selection_text="#000000",
        warning_background="#FFF4BF",
        warning_border="#B7791F",
        warning_text="#4A2C00",
    ),
}


def get_theme_definition(theme_name: str | None) -> ThemeDefinition:
    selected_name = str(theme_name or "").strip().lower()
    return THEMES.get(selected_name, THEMES[DEFAULT_UI_THEME])


def theme_choices() -> list[tuple[str, str]]:
    return [(theme.name, theme.label) for theme in THEMES.values()]


def apply_theme(application: QApplication, theme_name: str | None) -> ThemeDefinition:
    theme = get_theme_definition(theme_name)
    application.setStyleSheet(theme.stylesheet)
    return theme
