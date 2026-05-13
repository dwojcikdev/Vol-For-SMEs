"""
PyQt6 application entry point for Vol For SMEs.
"""

from __future__ import annotations

import sys

from PyQt6.QtWidgets import QApplication

from .main_window import MainWindow


def create_application(argv: list[str] | None = None) -> QApplication:
    app = QApplication.instance()
    if app is not None:
        return app

    app = QApplication(list(argv or sys.argv))
    app.setStyle("Fusion")
    app.setApplicationName("Vol For SMEs")
    app.setOrganizationName("Vol For SMEs")
    return app


def main(argv: list[str] | None = None) -> int:
    app = create_application(argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
