from unittest.mock import patch

from vol_for_smes import investigation


@patch("builtins.print")
@patch("vol_for_smes.investigation.build_memory_image_metadata")
@patch("vol_for_smes.investigation.get_plugin_preset")
@patch("vol_for_smes.investigation.detect_os")
@patch("vol_for_smes.investigation.resolve_project_volatility_command")
@patch("vol_for_smes.investigation.VolatilityRunner")
def test_run_investigation_uses_selected_preset(
    mock_runner_class,
    mock_resolve_project_volatility_command,
    mock_detect_os,
    mock_get_plugin_preset,
    mock_build_memory_image_metadata,
    _print,
):
    preset = investigation.PluginPreset(
        name="malware_analysis",
        plugins=("windows.malfind", "windows.handles"),
        built_in=True,
    )
    mock_get_plugin_preset.return_value = preset
    mock_resolve_project_volatility_command.return_value = ["vol"]
    mock_detect_os.return_value = {"os": "Windows"}
    mock_build_memory_image_metadata.return_value = {
        "path": "memory.raw",
        "resolved_path": "C:\\evidence\\memory.raw",
        "sha256": "abc123",
        "size_bytes": 1024,
    }
    runner = mock_runner_class.return_value
    runner.run_multiple.return_value = {"windows.malfind": [], "windows.handles": []}

    results, selected_preset = investigation.run_investigation(
        "memory.raw",
        "malware_analysis",
    )

    assert results == {"windows.malfind": [], "windows.handles": []}
    assert selected_preset == preset
    mock_runner_class.assert_called_once_with(
        "memory.raw",
        ["vol"],
        os_context={"os": "Windows"},
    )
    runner.run_multiple.assert_called_once_with(["windows.malfind", "windows.handles"])


def test_build_report_case_metadata_includes_memory_image_metadata():
    preset = investigation.PluginPreset(
        name="process_analysis",
        plugins=("windows.pslist",),
        built_in=True,
    )

    case_metadata = investigation.build_report_case_metadata(
        "memory.raw",
        preset,
        memory_image_metadata={
            "path": "memory.raw",
            "resolved_path": "C:\\evidence\\memory.raw",
            "sha256": "abc123",
            "size_bytes": 1024,
        },
    )

    assert case_metadata["memory_image"] == "memory.raw"
    assert case_metadata["memory_image_resolved"] == "C:\\evidence\\memory.raw"
    assert case_metadata["memory_image_sha256"] == "abc123"
    assert case_metadata["memory_image_size_bytes"] == 1024
