from pathlib import Path
from unittest.mock import patch

from vol_for_smes.config.settings import PluginPreset
from vol_for_smes import investigation
from vol_for_smes import main


@patch("vol_for_smes.main.display_process_results")
@patch("vol_for_smes.main.display_analysis_results")
@patch("vol_for_smes.main.prompt_and_export_report")
@patch("vol_for_smes.main.analyse_artefacts")
@patch("vol_for_smes.main.run_investigation")
@patch("vol_for_smes.main.build_memory_image_metadata")
@patch("builtins.input", return_value="memory.raw")
@patch("builtins.print")
def test_main_runs_analysis_before_displaying_processes(
    mock_print,
    _input,
    mock_build_memory_image_metadata,
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
    mock_build_memory_image_metadata.return_value = {
        "path": "memory.raw",
        "resolved_path": "C:\\evidence\\memory.raw",
        "sha256": "abc123",
        "size_bytes": 1024,
    }
    mock_run_investigation.return_value = (results, preset)
    mock_analyse_artefacts.return_value = analysis

    main.main()

    mock_print.assert_any_call(main.MEMORY_IMAGE_SELECTION_GUIDANCE)
    mock_analyse_artefacts.assert_called_once_with(results)
    mock_display_analysis_results.assert_called_once_with(analysis)
    mock_display_process_results.assert_called_once_with(results)
    mock_prompt_and_export_report.assert_called_once_with(
        analysis,
        "memory.raw",
        preset,
        memory_image_metadata={
            "path": "memory.raw",
            "resolved_path": "C:\\evidence\\memory.raw",
            "sha256": "abc123",
            "size_bytes": 1024,
        },
    )


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
            "analysis_backend": "volatility3",
        },
    )


def test_default_report_path_uses_reports_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(investigation, "get_reports_dir", lambda: tmp_path / "Reports")

    assert investigation.default_report_path("evidence\\memory.raw") == (
        tmp_path / "Reports" / "memory_report.pdf"
    )


@patch("vol_for_smes.main.export_analysis_to_pdf")
@patch("builtins.input", side_effect=["", "unsafe-report.pdf"])
@patch("builtins.print")
def test_prompt_and_export_report_prints_report_safety_guidance(
    mock_print,
    _input,
    mock_export_analysis_to_pdf,
):
    analysis = {"plugin_findings": {}, "risk_summary": {}, "timeline": []}
    mock_export_analysis_to_pdf.return_value = Path("unsafe-report.pdf")

    written_path = main.prompt_and_export_report(analysis, "memory.raw")

    assert written_path == Path("unsafe-report.pdf")
    mock_export_analysis_to_pdf.assert_called_once()
    mock_print.assert_any_call(main.REPORT_EXPORT_GUIDANCE)
