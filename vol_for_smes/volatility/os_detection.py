import subprocess
from .command_resolver import build_volatility_command, resolve_volatility_command
from .command_resolver import (
    discover_volatility_commands,
    parse_json_output,
)

from ..utils.helpers import parse_info_rows, run_subprocess
from ..utils.file_utils import get_volatility_cache_dir


def _default_volatility_args() -> list[str]:
    return ["--cache-path", str(get_volatility_cache_dir())]


def _candidate_commands(volatility_path):
    commands = []

    if isinstance(volatility_path, (list, tuple)) and volatility_path:
        commands.append(list(volatility_path))

    try:
        for command in discover_volatility_commands():
            if command not in commands:
                commands.append(command)
    except RuntimeError:
        pass

    if not commands:
        commands.append(resolve_volatility_command(volatility_path))

    return commands


def _detect_with_windows_info(memory_path, volatility_command, cancel_event=None):
    used_plugin = "windows.info"
    command = build_volatility_command(
        volatility_command,
        _default_volatility_args() + ["--renderer", "json", "-f", memory_path, used_plugin],
    )
    result = run_subprocess(
        command,
        timeout=180,
        cancel_event=cancel_event,
    )
    if result.returncode != 0:
        error_text = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(error_text or "windows.info failed")

    result_data = parse_json_output(result.stdout)
    rows, parsed_values = parse_info_rows(result_data)
    if not rows:
        return {"os": "Unknown", "details": "No OS information found"}

    os_info = {
        "os": "Windows",
        "detected_with": used_plugin,
        "volatility_command": list(volatility_command),
        "volatility_args": _default_volatility_args(),
    }

    for key, value in parsed_values.items():
        if "kernel base" in key:
            os_info["kernel_base"] = value
        elif "is64bit" in key:
            os_info["architecture"] = "x64" if str(value).lower() == "true" else "x86"
        elif "ntmajorversion" in key:
            os_info["major_version"] = value
        elif "ntminorversion" in key:
            os_info["minor_version"] = value
        elif "ntproducttype" in key:
            os_info["product_type"] = value

    return os_info


def detect_os(memory_path, volatility_path="vol", cancel_event=None):
    """
    Attempts to detect the Windows version of a memory image
    using the Volatility windows.info plugin.

    Returns a dictionary containing detected OS information.
    """
    try:
        commands = _candidate_commands(volatility_path)
    except RuntimeError as exc:
        return {"os": "Unknown", "error": str(exc)}

    errors = []
    for volatility_command in commands:
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError("Operation cancelled.")
        try:
            return _detect_with_windows_info(
                memory_path,
                volatility_command,
                cancel_event=cancel_event,
            )
        except InterruptedError:
            raise
        except Exception as exc:
            errors.append(f"[{' '.join(volatility_command)}] {str(exc)}")
            continue

    return {
        "os": "Unknown",
        "error": "OS detection failed for all discovered Volatility commands:\n" + "\n".join(errors)
    }
