"""
File and path utilities for the application.
"""

import os
import sys
import shlex
from pathlib import Path
from typing import List, Optional, Union


def get_project_root() -> Path:
    """
    Get the project root directory.

    Returns:
        Path to project root
    """
    # Assuming this file is in vol_for_smes/utils/
    return Path(__file__).resolve().parents[2]


def get_volatility_installation_root() -> Path:
    """
    Get the volatility installation directory.

    Returns:
        Path to volatility installation
    """
    return get_project_root() / "volatility_installation"


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