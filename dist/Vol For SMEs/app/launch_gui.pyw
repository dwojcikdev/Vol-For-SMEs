from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path


def _show_error(message: str, title: str = "Vol For SMEs") -> None:
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)
    except Exception:
        sys.stderr.write(f"{title}\n{message}\n")


def main() -> int:
    app_root = Path(__file__).resolve().parent
    bundle_root = app_root.parent
    os.chdir(bundle_root)
    sys.path.insert(0, str(app_root))

    try:
        from vol_for_smes.gui.app import main as run_app
        from vol_for_smes.utils.crash_logging import write_crash_log
    except Exception as exc:
        message = (
            "Vol For SMEs could not start.\n\n"
            "The bundled Python runtime or packaged dependencies could not be loaded.\n\n"
            f"{exc.__class__.__name__}: {exc}"
        )
        log_path = None
        try:
            from vol_for_smes.utils.crash_logging import write_crash_log
            log_path = write_crash_log(message, exc_info=sys.exc_info())
        except Exception:
            pass
        if log_path is not None:
            message = f"{message}\n\nA crash log was written to:\n{log_path}"
        _show_error(message)
        return 1

    try:
        result = run_app()
    except Exception:
        message = (
            "Vol For SMEs crashed during startup.\n\n"
            f"{traceback.format_exc()}"
        )
        log_path = write_crash_log(message, exc_info=sys.exc_info())
        if log_path is not None:
            message = f"{message}\n\nA crash log was written to:\n{log_path}"
        _show_error(message)
        return 1

    return 0 if result is None else int(result)


if __name__ == "__main__":
    raise SystemExit(main())
