"""
Utilities package for Vol For SMEs.

This package contains generic utility functions used throughout the application.
"""

# Import commonly used functions for easier access
from .helpers import (
    can_invoke_command,
    parse_json_output,
    build_command,
    parse_info_rows,
    extract_rows,
)

from .file_utils import (
    get_project_root,
    resolve_script_command,
    command_from_path_or_text,
)

__all__ = [
    # helpers
    'can_invoke_command', 'parse_json_output', 'build_command', 'parse_info_rows',
    'extract_rows',

    # file_utils
    'get_project_root', 'resolve_script_command',
    'command_from_path_or_text',
]
