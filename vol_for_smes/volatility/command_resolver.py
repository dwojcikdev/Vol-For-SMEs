import subprocess
import sys
from pathlib import Path
import json


def _can_invoke(command):
    try:
        result = subprocess.run(
            list(command) + ["-h"],
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

    return "usage" in output and "vol" in output


def _project_root():
    return Path(__file__).resolve().parents[2]


def _volatility_installation_root():
    return _project_root() / "volatility_installation"


def _resolve_script_command(script_path):
    launchers = []
    for candidate in ("py", "python", sys.executable):
        if candidate and candidate not in launchers:
            launchers.append(candidate)

    for launcher in launchers:
        command = [launcher, str(script_path)]
        if _can_invoke(command):
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
                if _can_invoke(command):
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
        if _can_invoke(command):
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


def resolve_volatility_command(_volatility_path=None):
    return _discover_installation_command()


def build_volatility_command(volatility_command, extra_args):
    return list(volatility_command) + list(extra_args)


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


def parse_json_output(output_text):
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
