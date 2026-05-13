import json
import os
import shlex
import sys

from ..utils.helpers import can_invoke_command, parse_json_output, build_command
from ..utils.file_utils import get_project_root, command_from_path_or_text


def _project_root():
    return get_project_root()


def _command_from_path_or_text(value):
    return command_from_path_or_text(value)


def _resolve_configured_command(value):
    command = _command_from_path_or_text(value)
    if command and can_invoke_command(command):
        return command
    return None


def _discover_installed_command():
    commands = discover_volatility_commands()
    if commands:
        return commands[0]

    raise RuntimeError(
        "No runnable Volatility 3 command was found. "
        "Install the 'volatility3' package or configure VOLATILITY_COMMAND/VOLATILITY_PATH."
    )


def discover_volatility_commands():
    candidates = []

    # Prefer the package installed into the current Python environment.
    module_command = [sys.executable, "-m", "volatility3.cli"]
    if can_invoke_command(module_command):
        candidates.append(module_command)

    for command in (["vol"], ["volatility"]):
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
        return _discover_installed_command()
    except RuntimeError as installation_error:
        raise RuntimeError(
            f"{installation_error} Provide a Volatility command/path, set "
            "VOLATILITY_COMMAND or VOLATILITY_PATH, or install the 'volatility3' package."
        ) from installation_error


def build_volatility_command(volatility_command, extra_args):
    return build_command(volatility_command, extra_args)
