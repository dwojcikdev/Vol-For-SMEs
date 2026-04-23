from unittest.mock import patch

from vol_for_smes import main


@patch("builtins.print")
def test_display_analysis_results_shows_summary_findings_and_timeline(mock_print):
    main.display_analysis_results(
        {
            "plugin_findings": {
                "windows.cmdline": {
                    "plugin": "windows.cmdline",
                    "severity": "high",
                    "summary": "1 suspicious indicator(s) detected",
                    "indicators": ["Suspicious command line in powershell.exe | PID 1"],
                },
                "windows.pslist": {
                    "plugin": "windows.pslist",
                    "severity": "none",
                    "summary": "No obvious malicious indicators detected by current heuristics",
                    "indicators": [],
                },
            },
            "risk_summary": {"high": 1, "medium": 0, "low": 0, "none": 1},
            "timeline": [
                {
                    "timestamp": "2024-01-01T10:00:00+00:00",
                    "description": "powershell.exe reported by windows.pslist (CreateTime)",
                }
            ],
        }
    )

    printed = "\n".join(call.args[0] for call in mock_print.call_args_list if call.args)
    assert "Analysis Summary:" in printed
    assert "[HIGH] windows.cmdline" in printed
    assert "2024-01-01T10:00:00+00:00" in printed


@patch("vol_for_smes.main.display_process_results")
@patch("vol_for_smes.main.display_analysis_results")
@patch("vol_for_smes.main.analyse_artifacts")
@patch("vol_for_smes.main.run_default_investigation")
@patch("builtins.input", return_value="memory.raw")
@patch("builtins.print")
def test_main_runs_analysis_before_displaying_processes(
    _print,
    _input,
    mock_run_default_investigation,
    mock_analyse_artifacts,
    mock_display_analysis_results,
    mock_display_process_results,
):
    results = {"windows.pslist": [{"PID": 4, "ImageFileName": "System"}]}
    analysis = {"plugin_findings": {}, "risk_summary": {}, "timeline": []}
    mock_run_default_investigation.return_value = results
    mock_analyse_artifacts.return_value = analysis

    main.main()

    mock_analyse_artifacts.assert_called_once_with(results)
    mock_display_analysis_results.assert_called_once_with(analysis)
    mock_display_process_results.assert_called_once_with(results)
