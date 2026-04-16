"""
Generic helper functions used throughout the application.
"""

import json
import subprocess
from typing import List, Any


def can_invoke_command(command: List[str]) -> bool:
    """
    Check if a command can be invoked successfully.

    Args:
        command: List of command components

    Returns:
        True if command can be invoked, False otherwise
    """
    try:
        result = subprocess.run(
            command + ["-h"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
        )
    except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired):
        return False

    output = f"{result.stdout}\n{result.stderr}".lower()

    if "no module named" in output:
        return False
    if "is not recognized as an internal or external command" in output:
        return False
    if "can't open file" in output:
        return False

    if result.returncode == 0:
        return True

    return "usage" in output


def parse_json_output(output_text: str) -> Any:
    """
    Parse JSON output that may contain extra text before/after the JSON.

    Args:
        output_text: Text containing JSON data

    Returns:
        Parsed JSON data

    Raises:
        json.JSONDecodeError: If no valid JSON can be found
    """
    text = (output_text or "").strip()
    if not text:
        raise json.JSONDecodeError("No JSON data", "", 0)

    decoder = json.JSONDecoder()
    starts = [idx for idx, ch in enumerate(text) if ch in "[{"]

    for start in starts:
        try:
            data, _ = decoder.raw_decode(text[start:])
            return data
        except json.JSONDecodeError:
            continue
    raise json.JSONDecodeError("No JSON object could be decoded", text, 0)


def build_command(base_command: List[str], extra_args: List[str]) -> List[str]:
    """
    Build a complete command from base command and extra arguments.

    Args:
        base_command: Base command components
        extra_args: Additional arguments to append

    Returns:
        Complete command list
    """
    return list(base_command) + list(extra_args)


def parse_info_rows(data: Any) -> tuple:
    """
    Parse data rows that may be in dict or list format.

    Args:
        data: Data to parse (dict, list, or other)

    Returns:
        Tuple of (original_rows, parsed_dict)
    """
    if isinstance(data, dict):
        data = [{"Variable": key, "Value": value} for key, value in data.items()]

    if not isinstance(data, list):
        return [], {}

    parsed = {}
    for item in data:
        if not isinstance(item, dict):
            continue

        key = str(
            item.get("Variable", item.get("Name", item.get("Key", "")))
        ).strip()
        value = item.get("Value", item.get("value", ""))
        if not key:
            continue
        parsed[key.lower()] = value

    return data, parsed


def extract_rows(volatility_json: Any) -> List[Any]:
    """
    Extract rows from Volatility JSON output.

    Args:
        volatility_json: JSON data from Volatility

    Returns:
        List of row data
    """
    if isinstance(volatility_json, list):
        # For Volatility 3 JSON output, it's a list of row objects
        return volatility_json
    elif "rows" in volatility_json:
        # Legacy format
        return volatility_json["rows"]
    else:
        return []