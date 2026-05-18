"""
Startup entry point for packaged Windows GUI launchers.
"""

from __future__ import annotations

import sys
import traceback

from ..utils.crash_logging import write_crash_log


def _show_error(message: str, title: str = "Vol For SMEs") -> None:
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)
    except Exception:
        sys.stderr.write(f"{title}\n{message}\n")


def _append_log_path(message: str, log_path) -> str:
    if log_path is None:
        return message
    return f"{message}\n\nA crash log was written to:\n{log_path}"


def main() -> int:
    try:
        from .app import main as run_app
    except Exception as exc:
        message = (
            "Vol For SMEs could not start.\n\n"
            "The bundled Python runtime or packaged dependencies could not be loaded.\n\n"
            f"{exc.__class__.__name__}: {exc}"
        )
        log_path = write_crash_log(message, exc_info=sys.exc_info())
        _show_error(_append_log_path(message, log_path))
        return 1

    try:
        result = run_app()
    except Exception:
        message = (
            "Vol For SMEs crashed during startup.\n\n"
            f"{traceback.format_exc()}"
        )
        log_path = write_crash_log(message, exc_info=sys.exc_info())
        _show_error(_append_log_path(message, log_path))
        return 1

    return 0 if result is None else int(result)


if __name__ == "__main__":
    raise SystemExit(main())
