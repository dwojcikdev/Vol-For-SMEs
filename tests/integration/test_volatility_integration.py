import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from vol_for_smes.analysis import analyse_artefacts
from vol_for_smes.config import save_custom_plugin_preset
from vol_for_smes.investigation import (
    build_report_case_metadata,
    run_investigation,
)
from vol_for_smes.reporting import build_analysis_report, export_analysis_to_pdf
from vol_for_smes.volatility import (
    PluginInfo,
    VolatilityRunner,
    build_plugin_catalog,
    detect_os,
    discover_volatility_plugins,
    parse_processes,
)
from vol_for_smes.volatility.command_resolver import resolve_volatility_command


pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INTEGRATION_ARTIFACT_ROOT = PROJECT_ROOT / ".integration-artifacts"
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


def _make_artifact_dir(prefix: str) -> Path:
    INTEGRATION_ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    return Path(
        tempfile.mkdtemp(
            prefix=f"{prefix}-",
            dir=str(INTEGRATION_ARTIFACT_ROOT),
        )
    )


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


def test_real_plugin_discovery_lists_plugins_from_volatility(volatility_command):
    discovered_plugins = discover_volatility_plugins(volatility_command)
    plugin_catalog = build_plugin_catalog(volatility_command)

    assert "windows.pslist" in discovered_plugins
    assert discovered_plugins["windows.pslist"].source == "discovered"
    assert discovered_plugins["windows.pslist"].os_family == "windows"
    assert "windows.pslist" in plugin_catalog
    assert plugin_catalog["windows.pslist"].support_level == "context"
    assert plugin_catalog["windows.pslist"].description


def test_detect_os_with_real_memory_image(detected_os, volatility_command):
    assert detected_os.get("os") == "Windows"
    assert detected_os.get("volatility_command") == volatility_command


def test_plugin_commands_run_successfully(memory_image_path, detected_os):
    runner = VolatilityRunner(memory_image_path, os_context=detected_os)
    plugins = _plugins_from_env()

    results = runner.run_multiple({plugin: plugin for plugin in plugins}, max_workers=1)

    assert set(results) == set(plugins)
    for plugin, output in results.items():
        assert "error" not in output, f"{plugin} failed: {output.get('error')}"
        assert isinstance(output, list), f"{plugin} did not return JSON rows"


def test_run_investigation_builds_real_report_and_pdf(memory_image_path):
    artifact_dir = _make_artifact_dir("investigation")
    settings_path = artifact_dir / "user_settings.json"

    try:
        save_custom_plugin_preset(
            "integration_smoke",
            ["windows.pslist"],
            settings_path=settings_path,
            plugin_catalog={
                "windows.pslist": PluginInfo(name="windows.pslist"),
            },
        )

        results, preset = run_investigation(
            memory_image_path,
            "integration_smoke",
            settings_path=settings_path,
        )

        assert preset is not None
        assert preset.name == "integration_smoke"
        assert set(results) == {"windows.pslist"}
        assert "error" not in results["windows.pslist"]

        analysis = analyse_artefacts(results)
        report = build_analysis_report(
            analysis,
            case_metadata=build_report_case_metadata(memory_image_path, preset),
        )

        pdf_path = artifact_dir / "integration-report.pdf"
        written_path = export_analysis_to_pdf(
            analysis,
            pdf_path,
            case_metadata=build_report_case_metadata(memory_image_path, preset),
        )
        pdf_bytes = written_path.read_bytes()

        assert report["title"] == "Vol For SMEs Memory Analysis Report"
        assert report["case_metadata"]["plugin_preset"] == "integration_smoke"
        assert report["case_metadata"]["memory_image"] == memory_image_path
        assert written_path == pdf_path
        assert pdf_bytes.startswith(b"%PDF-1.4")
        assert b"Vol For SMEs Memory Analysis Report" in pdf_bytes
    finally:
        shutil.rmtree(artifact_dir, ignore_errors=True)


def test_windows_bundle_builds_and_bundled_runtime_cli_starts():
    build_result = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "build-windows-bundle.py")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build_result.returncode == 0, (
        build_result.stderr or build_result.stdout or "bundle build failed"
    )

    bundle_root = PROJECT_ROOT / "dist" / "Vol For SMEs"
    gui_launcher = bundle_root / "Vol For SMEs.exe"
    console_launcher = bundle_root / "Vol For SMEs Console.exe"
    bundled_python = bundle_root / "python.exe"

    assert gui_launcher.is_file()
    assert console_launcher.is_file()
    assert bundled_python.is_file()

    help_result = subprocess.run(
        [
            str(bundled_python),
            "-m",
            "vol_for_smes.volatility.runtime_cli",
            "-h",
        ],
        cwd=bundle_root,
        capture_output=True,
        text=True,
        check=False,
    )
    help_output = "\n".join(
        part for part in (help_result.stdout, help_result.stderr) if part
    ).lower()

    assert help_result.returncode == 0, help_output
    assert "usage:" in help_output
    assert "volatility" in help_output


def test_process_listing_output_can_be_parsed(memory_image_path, detected_os):
    runner = VolatilityRunner(memory_image_path, os_context=detected_os)
    raw_processes = runner.run_plugin("windows.pslist")
    processes = parse_processes(raw_processes)

    assert isinstance(raw_processes, list)
    assert processes
    assert any(process.get("pid") is not None for process in processes)
