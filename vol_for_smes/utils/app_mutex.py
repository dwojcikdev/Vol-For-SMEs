"""
Windows application mutex helpers.
"""

from __future__ import annotations

import ctypes
import sys

_MUTEX_NAMES = (
    "VolForSMEsAppMutex",
    r"Global\VolForSMEsAppMutex",
)
_mutex_handles: list[int] = []
_mutex_registered = False


def hold_app_mutex() -> None:
    global _mutex_registered

    if _mutex_registered or sys.platform != "win32":
        return

    create_mutex = ctypes.windll.kernel32.CreateMutexW
    create_mutex.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    create_mutex.restype = ctypes.c_void_p

    for mutex_name in _MUTEX_NAMES:
        try:
            handle = create_mutex(None, False, mutex_name)
        except Exception:
            continue
        if handle:
            _mutex_handles.append(handle)

    _mutex_registered = True
