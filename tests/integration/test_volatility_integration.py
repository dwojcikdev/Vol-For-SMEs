import os
from pathlib import Path

import pytest

from vol_for_smes.volatility import VolatilityRunner, detect_os, parse_processes
from vol_for_smes.volatility.command_resolver import resolve_volatility_command
from vol_for_smes.volatility.plugin_manager import PLUGIN_GROUPS


pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLE_MEMORY_IMAGES = (
    PROJECT_ROOT / "data" / "sample_memory_images" / "df2025sub.mem",
)


def _plugins_from_env():
    configured_plugins = os.environ.get("VOL_FOR_SMES_INTEGRATION_PLUGINS")
    if configured_plugins:
        return [plugin.strip() for plugin in configured_plugins.split(",") if plugin.strip()]
    return ["windows.pslist"]


def _resolve_memory_image_path():
    for candidate in DEFAULT_SAMPLE_MEMORY_IMAGES:
        if candidate.is_file():
            return candidate

    return None


@pytest.fixture(scope="session")
def memory_image_path():
    memory_path = _resolve_memory_image_path()
    if memory_path is None:
        pytest.skip("add a sample memory image under data/sample_memory_images")

    if not memory_path.is_file():
        pytest.fail(f"Integration memory image does not point to a file: {memory_path}")

    return str(memory_path)


@pytest.fixture(scope="session")
def volatility_command():
    configured_command = os.environ.get("VOLATILITY_COMMAND") or os.environ.get("VOLATILITY_PATH")

    try:
        return resolve_volatility_command(configured_command)
    except RuntimeError as exc:
        pytest.skip(f"no runnable Volatility command is available: {exc}")


@pytest.fixture(scope="session")
def detected_os(memory_image_path, volatility_command):
    os_info = detect_os(memory_image_path, volatility_command)
    if os_info.get("os") == "Unknown":
        pytest.fail(os_info.get("error") or str(os_info))
    return os_info


def test_volatility_command_resolves(volatility_command):
    assert isinstance(volatility_command, list)
    assert volatility_command


def test_detect_os_with_real_memory_image(detected_os, volatility_command):
    assert detected_os.get("os") == "Windows"
    assert detected_os.get("volatility_command") == volatility_command
    assert detected_os.get("volatility_variant") in {"vol2", "vol3"}


def test_configured_plugins_are_known_or_custom():
    known_plugins = set().union(*PLUGIN_GROUPS.values())
    plugins = _plugins_from_env()

    assert plugins
    assert all(isinstance(plugin, str) and plugin for plugin in plugins)
    assert "windows.pslist" in known_plugins


def test_plugin_commands_run_successfully(memory_image_path, detected_os):
    runner = VolatilityRunner(memory_image_path, os_context=detected_os)
    plugins = _plugins_from_env()

    results = runner.run_multiple({plugin: plugin for plugin in plugins}, max_workers=1)

    assert set(results) == set(plugins)
    for plugin, output in results.items():
        assert "error" not in output, f"{plugin} failed: {output.get('error')}"
        assert isinstance(output, list), f"{plugin} did not return JSON rows"


def test_process_listing_output_can_be_parsed(memory_image_path, detected_os):
    runner = VolatilityRunner(memory_image_path, os_context=detected_os)
    raw_processes = runner.run_plugin("windows.pslist")
    processes = parse_processes(raw_processes)

    assert isinstance(raw_processes, list)
    assert processes
    assert any(process.get("pid") is not None for process in processes)
