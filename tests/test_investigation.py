from unittest.mock import patch

from vol_for_smes import investigation


@patch("builtins.print")
@patch("vol_for_smes.investigation.get_plugin_preset")
@patch("vol_for_smes.investigation.detect_os")
@patch("vol_for_smes.investigation.resolve_project_volatility_command")
@patch("vol_for_smes.investigation.VolatilityRunner")
def test_run_investigation_uses_selected_preset(
    mock_runner_class,
    mock_resolve_project_volatility_command,
    mock_detect_os,
    mock_get_plugin_preset,
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
