"""
Crash logging helpers for packaged application entry points.
"""

from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime
from pathlib import Path

from .file_utils import APP_NAME, get_logs_dir


def get_crash_log_path(app_name: str = APP_NAME) -> Path:
    return get_logs_dir(app_name) / "crash.log"


def write_crash_log(
    message: str,
    *,
    app_name: str = APP_NAME,
    exc_info: tuple[type[BaseException], BaseException, object] | None = None,
) -> Path | None:
    log_path = get_crash_log_path(app_name)

    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write("=" * 80 + "\n")
            handle.write(
                f"{datetime.now().astimezone().isoformat(timespec='seconds')} "
                f"{app_name} crash\n"
            )
            handle.write(f"Executable: {sys.executable}\n")
            handle.write(f"Working directory: {os.getcwd()}\n")
            handle.write(f"Arguments: {sys.argv}\n\n")
            handle.write(message.rstrip())
            handle.write("\n")

            if exc_info is not None and exc_info[0] is not None:
                handle.write("\nTraceback:\n")
                handle.write("".join(traceback.format_exception(*exc_info)).rstrip())
                handle.write("\n")
        return log_path
    except OSError:
        return None
