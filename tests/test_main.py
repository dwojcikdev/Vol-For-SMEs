from unittest.mock import patch

from vol_for_smes.config.settings import PluginPreset
from vol_for_smes import main


@patch("vol_for_smes.main.display_process_results")
@patch("vol_for_smes.main.display_analysis_results")
@patch("vol_for_smes.main.prompt_and_export_report")
@patch("vol_for_smes.main.analyse_artefacts")
@patch("vol_for_smes.main.run_investigation")
@patch("builtins.input", return_value="memory.raw")
@patch("builtins.print")
def test_main_runs_analysis_before_displaying_processes(
    _print,
    _input,
    mock_run_investigation,
    mock_analyse_artefacts,
    mock_prompt_and_export_report,
    mock_display_analysis_results,
    mock_display_process_results,
):
    results = {"windows.pslist": [{"PID": 4, "ImageFileName": "System"}]}
    preset = PluginPreset(
        name="default_investigation",
        plugins=("windows.pslist",),
        built_in=True,
    )
    analysis = {"plugin_findings": {}, "risk_summary": {}, "timeline": []}
    mock_run_investigation.return_value = (results, preset)
    mock_analyse_artefacts.return_value = analysis

    main.main()

    mock_analyse_artefacts.assert_called_once_with(results)
    mock_display_analysis_results.assert_called_once_with(analysis)
    mock_display_process_results.assert_called_once_with(results)
    mock_prompt_and_export_report.assert_called_once_with(analysis, "memory.raw", preset)


@patch("vol_for_smes.main.export_analysis_to_pdf")
@patch("builtins.input", side_effect=["", ""])
@patch("builtins.print")
def test_prompt_and_export_report_includes_preset_metadata(
    _print,
    _input,
    mock_export_analysis_to_pdf,
):
    analysis = {"plugin_findings": {}, "risk_summary": {}, "timeline": []}
    preset = PluginPreset(
        name="process_analysis",
        plugins=("windows.pslist", "windows.psscan"),
        built_in=True,
    )
    mock_export_analysis_to_pdf.return_value = main._default_report_path("memory.raw")

    main.prompt_and_export_report(analysis, "memory.raw", preset)

    mock_export_analysis_to_pdf.assert_called_once_with(
        analysis,
        main._default_report_path("memory.raw"),
        case_metadata={
            "memory_image": "memory.raw",
            "plugin_preset": "process_analysis",
            "plugin_count": 2,
            "plugins_run": "windows.pslist, windows.psscan",
        },
    )
