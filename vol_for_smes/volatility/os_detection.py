import subprocess
import re
from .command_resolver import build_volatility_command, resolve_volatility_command
from .command_resolver import (
    detect_volatility_variant,
    discover_volatility_commands,
    parse_json_output,
)


def _parse_info_rows(data):
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


def _detect_with_vol3(memory_path, volatility_command):
    used_plugin = "windows.info"
    command = build_volatility_command(
        volatility_command,
        ["--renderer", "json", "-f", memory_path, used_plugin],
    )
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=180
    )
    if result.returncode != 0:
        error_text = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(error_text or "windows.info failed")

    result_data = parse_json_output(result.stdout)
    rows, parsed_values = _parse_info_rows(result_data)
    if not rows:
        return {"os": "Unknown", "details": "No OS information found"}

    os_info = {
        "os": "Windows",
        "detected_with": used_plugin,
        "volatility_command": list(volatility_command),
        "volatility_variant": "vol3",
        "volatility_args": [],
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


def _detect_with_vol2(memory_path, volatility_command):
    used_plugin = "imageinfo"
    command = build_volatility_command(
        volatility_command,
        ["-f", memory_path, used_plugin],
    )
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=600
    )
    output = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0:
        raise RuntimeError((output or "").strip() or "imageinfo failed")

    suggested_profile = None
    for line in output.splitlines():
        if "Suggested Profile(s)" in line:
            match = re.search(r"Suggested Profile\(s\)\s*:\s*(.+)$", line)
            if match:
                candidates = [item.strip() for item in match.group(1).split(",") if item.strip()]
                if candidates:
                    suggested_profile = candidates[0]
            break

    if not suggested_profile:
        raise RuntimeError("Volatility 2 imageinfo did not return a suggested profile.")

    return {
        "os": "Windows",
        "detected_with": used_plugin,
        "volatility_command": list(volatility_command),
        "volatility_variant": "vol2",
        "profile": suggested_profile,
        "volatility_args": [f"--profile={suggested_profile}"],
    }


def detect_os(memory_path, volatility_path="vol"):
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
        variant = detect_volatility_variant(volatility_command)
        try:
            if variant == "vol2":
                return _detect_with_vol2(memory_path, volatility_command)
            return _detect_with_vol3(memory_path, volatility_command)
        except Exception as exc:
            errors.append(f"[{' '.join(volatility_command)}] {str(exc)}")
            continue

    return {
        "os": "Unknown",
        "error": "OS detection failed for all discovered Volatility commands:\n" + "\n".join(errors)
    }
