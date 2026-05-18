"""
File and path utilities for the application.
"""

import hashlib
import os
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Callable, List, Optional, Union

APP_NAME = "Vol For SMEs"


def get_project_root() -> Path:
    """
    Get the project root directory.

    Returns:
        Path to project root
    """
    # Assuming this file is in vol_for_smes/utils/
    return Path(__file__).resolve().parents[2]


def get_app_data_dir(app_name: str = APP_NAME) -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / app_name

    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata) / app_name

    return Path.home() / app_name


def get_local_app_data_dir(app_name: str = APP_NAME) -> Path:
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        return Path(local_appdata) / app_name

    return get_app_data_dir(app_name)


def get_reports_dir(app_name: str = APP_NAME) -> Path:
    return get_local_app_data_dir(app_name) / "Reports"


def get_logs_dir(app_name: str = APP_NAME) -> Path:
    return get_local_app_data_dir(app_name) / "Logs"


def _ensure_writable_directory(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def get_volatility_cache_dir(app_name: str = APP_NAME) -> Path:
    preferred = get_local_app_data_dir(app_name) / "VolatilityCache"
    candidates = [preferred]

    if getattr(sys, "frozen", False):
        candidates.append(Path(tempfile.gettempdir()) / app_name / "VolatilityCache")
    else:
        candidates.append(get_project_root() / ".volatility-cache")
        candidates.append(Path(tempfile.gettempdir()) / app_name / "VolatilityCache")

    for candidate in candidates:
        if _ensure_writable_directory(candidate):
            return candidate
    return preferred


def build_memory_image_metadata(
    target_path: Union[str, Path],
    *,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> dict:
    path = Path(target_path).expanduser()
    resolved_path = path.resolve(strict=True)
    sha256 = hashlib.sha256()

    with resolved_path.open("rb") as handle:
        while True:
            if should_cancel is not None and should_cancel():
                raise InterruptedError("Operation cancelled.")
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)

    return {
        "path": str(path),
        "resolved_path": str(resolved_path),
        "sha256": sha256.hexdigest(),
        "size_bytes": resolved_path.stat().st_size,
    }


def get_runtime_python_executable(*, prefer_console: bool = False) -> Path:
    current_executable = Path(sys.executable).resolve()
    candidate_names = []

    if prefer_console:
        candidate_names.extend(
            [
                "python.exe",
                f"python{sys.version_info.major}.{sys.version_info.minor}.exe",
                "Vol For SMEs Console.exe",
            ]
        )
    else:
        candidate_names.extend(
            [
                "pythonw.exe",
                "python.exe",
                "Vol For SMEs.exe",
            ]
        )

    for candidate_name in candidate_names:
        candidate_path = current_executable.with_name(candidate_name)
        if candidate_path.is_file():
            return candidate_path

    return current_executable


def resolve_script_command(script_path: Path) -> Optional[List[str]]:
    """
    Resolve the command to run a Python script.

    Args:
        script_path: Path to the Python script

    Returns:
        Command list to execute the script, or None if not executable
    """
    launchers = []
    for candidate in ("py", "python", sys.executable):
        if candidate and candidate not in launchers:
            launchers.append(candidate)

    for launcher in launchers:
        command = [launcher, str(script_path)]
        # Import the helper function
        from .helpers import can_invoke_command
        if can_invoke_command(command):
            return command
    return None


def command_from_path_or_text(value: Union[str, List, tuple, None]) -> Optional[List[str]]:
    """
    Convert various input types to a command list.

    Args:
        value: Input value (path string, command list, etc.)

    Returns:
        Normalized command list, or None
    """
    if not value:
        return None

    if isinstance(value, (list, tuple)):
        command = [str(part) for part in value if str(part).strip()]
        return command if command else None

    text = str(value).strip()
    if not text:
        return None

    candidate_path = Path(text).expanduser()
    if candidate_path.is_file():
        if candidate_path.suffix.lower() == ".py":
            return resolve_script_command(candidate_path)
        return [str(candidate_path)]

    # Try to parse as shell command
    try:
        return shlex.split(text)
    except ValueError:
        return None
