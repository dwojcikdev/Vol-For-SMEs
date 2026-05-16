"""
Startup entry point for packaged Windows GUI launchers.
"""

from __future__ import annotations

import sys
import traceback


def _show_error(message: str, title: str = "Vol For SMEs") -> None:
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)
    except Exception:
        sys.stderr.write(f"{title}\n{message}\n")


def main() -> int:
    try:
        from .app import main as run_app
    except Exception as exc:
        _show_error(
            "Vol For SMEs could not start.\n\n"
            "The bundled Python runtime or packaged dependencies could not be loaded.\n\n"
            f"{exc.__class__.__name__}: {exc}"
        )
        return 1

    try:
        result = run_app()
    except Exception:
        _show_error(
            "Vol For SMEs crashed during startup.\n\n"
            f"{traceback.format_exc()}"
        )
        return 1

    return 0 if result is None else int(result)


if __name__ == "__main__":
    raise SystemExit(main())
