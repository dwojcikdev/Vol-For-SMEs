import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from ..utils.helpers import can_invoke_command, parse_json_output, build_command
from ..utils.file_utils import get_project_root, get_volatility_installation_root, command_from_path_or_text, resolve_script_command


def _project_root():
    return get_project_root()


def _volatility_installation_root():
    return get_volatility_installation_root()


def _resolve_script_command(script_path):
    return resolve_script_command(script_path)


def _command_from_path_or_text(value):
    return command_from_path_or_text(value)


def _resolve_configured_command(value):
    command = _command_from_path_or_text(value)
    if command and can_invoke_command(command):
        return command
    return None


def _discover_installation_command():
    commands = discover_volatility_commands()
    if commands:
        return commands[0]

    install_root = _volatility_installation_root()
    raise RuntimeError(
        f"No runnable Volatility executable was found under '{install_root}'. "
        "Expected Volatility 3 (vol.py/vol.exe) or Volatility 2 (.exe)."
    )


def discover_volatility_commands():
    install_root = _volatility_installation_root()
    if not install_root.is_dir():
        raise RuntimeError(
            f"Volatility installation folder was not found at '{install_root}'."
        )

    candidates = []

    # Prefer Volatility 3 entrypoints first.
    for binary_name in ("vol.exe", "vol"):
        for candidate in install_root.rglob(binary_name):
            if candidate.is_file():
                command = [str(candidate)]
                if can_invoke_command(command):
                    candidates.append(command)

    for candidate in install_root.rglob("vol.py"):
        if not candidate.is_file():
            continue
        command = _resolve_script_command(candidate)
        if command:
            candidates.append(command)

    # Add Volatility 2 standalone executables.
    for candidate in install_root.rglob("*.exe"):
        name = candidate.name.lower()
        if "volatility" not in name:
            continue
        if "volatility_2" not in name and "volatility2" not in name:
            continue
        command = [str(candidate)]
        if can_invoke_command(command):
            candidates.append(command)

    seen = set()
    unique = []
    for command in candidates:
        key = tuple(command)
        if key in seen:
            continue
        seen.add(key)
        unique.append(command)

    return unique


def resolve_volatility_command(volatility_path=None):
    configured_values = (
        volatility_path,
        os.environ.get("VOLATILITY_COMMAND"),
        os.environ.get("VOLATILITY_PATH"),
    )
    for value in configured_values:
        command = _resolve_configured_command(value)
        if command:
            return command

    try:
        return _discover_installation_command()
    except RuntimeError as installation_error:
        for command in (["vol"], ["volatility"]):
            if can_invoke_command(command):
                return command

        raise RuntimeError(
            f"{installation_error} Provide a Volatility command/path, set "
            "VOLATILITY_COMMAND or VOLATILITY_PATH, install Volatility on PATH, "
            "or include it in the project volatility_installation folder."
        ) from installation_error


def build_volatility_command(volatility_command, extra_args):
    return build_command(volatility_command, extra_args)


def detect_volatility_variant(volatility_command):
    try:
        result = subprocess.run(
            list(volatility_command) + ["--help"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired):
        return "unknown"

    output = f"{result.stdout}\n{result.stderr}".lower()
    if "volatility 3 framework" in output:
        return "vol3"
    if "volatility foundation volatility framework 2" in output:
        return "vol2"
    return "unknown"
