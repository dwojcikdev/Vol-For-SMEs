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
    get_app_data_dir,
    get_local_app_data_dir,
    get_logs_dir,
    get_project_root,
    get_reports_dir,
    get_volatility_cache_dir,
    get_runtime_python_executable,
    resolve_script_command,
    command_from_path_or_text,
    build_memory_image_metadata,
)
from .crash_logging import get_crash_log_path, write_crash_log

__all__ = [
    # helpers
    'can_invoke_command', 'parse_json_output', 'build_command', 'parse_info_rows',
    'extract_rows',

    # file_utils
    'get_app_data_dir', 'get_local_app_data_dir', 'get_logs_dir', 'get_project_root',
    'get_reports_dir',
    'get_volatility_cache_dir',
    'get_runtime_python_executable', 'resolve_script_command',
    'command_from_path_or_text', 'build_memory_image_metadata',

    # crash_logging
    'get_crash_log_path', 'write_crash_log',
]
