from unittest.mock import patch

from vol_for_smes import main


@patch("builtins.print")
def test_display_os_detection_result_shows_human_readable_windows_summary(mock_print):
    main.display_os_detection_result(
        {
            "os": "Windows",
            "architecture": "x64",
            "major_version": 10,
            "minor_version": 0,
            "detected_with": "windows.info",
        }
    )

    printed = "\n".join(call.args[0] for call in mock_print.call_args_list if call.args)
    assert "Operating system: Windows" in printed
    assert "Architecture: x64" in printed
    assert "Version: 10.0" in printed
    assert "Detected using: windows.info" in printed


@patch("builtins.print")
def test_display_os_detection_result_shows_human_readable_error(mock_print):
    main.display_os_detection_result({"os": "Unknown", "error": "test error"})

    printed = "\n".join(call.args[0] for call in mock_print.call_args_list if call.args)
    assert "We could not identify the operating system" in printed
    assert "Reason: test error" in printed


@patch("builtins.print")
def test_display_analysis_results_shows_summary_findings_and_timeline(mock_print):
    main.display_analysis_results(
        {
            "plugin_findings": {
                "windows.cmdline": {
                    "plugin": "windows.cmdline",
                    "severity": "high",
                    "risk_score": 92,
                    "mitre_tags": [{"technique_id": "T1059.001", "name": "PowerShell"}],
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
            "process_analysis": {
                "summary": "1 suspicious process(es) identified",
                "risk_score": 95,
                "mitre_tags": [{"technique_id": "T1055", "name": "Process Injection"}],
                "suspicious_processes": [
                    {
                        "name": "powershell.exe",
                        "pid": "1",
                        "severity": "high",
                        "risk_score": 95,
                        "mitre_tags": [{"technique_id": "T1055", "name": "Process Injection"}],
                        "reasons": ["suspicious command-line execution pattern"],
                    }
                ],
            },
            "network_analysis": {
                "summary": "1 suspicious network connection(s) identified",
                "risk_score": 88,
                "mitre_tags": [{"technique_id": "T1071", "name": "Application Layer Protocol"}],
                "suspicious_connections": [
                    {
                        "owner": "powershell.exe",
                        "pid": "1",
                        "local_address": "10.0.0.5",
                        "local_port": "4444",
                        "remote_address": "8.8.8.8",
                        "remote_port": "443",
                        "severity": "high",
                        "risk_score": 88,
                        "mitre_tags": [{"technique_id": "T1071", "name": "Application Layer Protocol"}],
                        "reasons": ["interactive shell process communicating over the network"],
                    }
                ],
            },
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
    assert "Risk score: 92" in printed
    assert "MITRE ATT&CK: T1059.001 PowerShell" in printed
    assert "Process Analysis:" in printed
    assert "Network Analysis:" in printed
    assert "2024-01-01T10:00:00+00:00" in printed


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
    preset = main.PluginPreset(
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


@patch("builtins.print")
@patch("vol_for_smes.main.get_plugin_preset")
@patch("vol_for_smes.main.detect_os")
@patch("vol_for_smes.main.resolve_project_volatility_command")
@patch("vol_for_smes.main.VolatilityRunner")
def test_run_investigation_uses_selected_preset(
    mock_runner_class,
    mock_resolve_project_volatility_command,
    mock_detect_os,
    mock_get_plugin_preset,
    _print,
):
    preset = main.PluginPreset(
        name="malware_analysis",
        plugins=("windows.malfind", "windows.handles"),
        built_in=True,
    )
    mock_get_plugin_preset.return_value = preset
    mock_resolve_project_volatility_command.return_value = ["vol"]
    mock_detect_os.return_value = {"os": "Windows"}
    runner = mock_runner_class.return_value
    runner.run_multiple.return_value = {"windows.malfind": [], "windows.handles": []}

    results, selected_preset = main.run_investigation("memory.raw", "malware_analysis")

    assert results == {"windows.malfind": [], "windows.handles": []}
    assert selected_preset == preset
    mock_runner_class.assert_called_once_with(
        "memory.raw",
        ["vol"],
        os_context={"os": "Windows"},
    )
    runner.run_multiple.assert_called_once_with(["windows.malfind", "windows.handles"])


@patch("vol_for_smes.main.export_analysis_to_pdf")
@patch("builtins.input", side_effect=["", ""])
@patch("builtins.print")
def test_prompt_and_export_report_uses_default_path(
    mock_print,
    _input,
    mock_export_analysis_to_pdf,
):
    analysis = {"plugin_findings": {}, "risk_summary": {}, "timeline": []}
    mock_export_analysis_to_pdf.return_value = main._default_report_path("memory.raw")

    written_path = main.prompt_and_export_report(analysis, "memory.raw")

    assert written_path == main._default_report_path("memory.raw")
    mock_export_analysis_to_pdf.assert_called_once_with(
        analysis,
        main._default_report_path("memory.raw"),
        case_metadata={"memory_image": "memory.raw"},
    )
    printed = "\n".join(call.args[0] for call in mock_print.call_args_list if call.args)
    assert "PDF report exported to:" in printed


@patch("vol_for_smes.main.export_analysis_to_pdf")
@patch("builtins.input", side_effect=["", ""])
@patch("builtins.print")
def test_prompt_and_export_report_includes_preset_metadata(
    _print,
    _input,
    mock_export_analysis_to_pdf,
):
    analysis = {"plugin_findings": {}, "risk_summary": {}, "timeline": []}
    preset = main.PluginPreset(
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


@patch("vol_for_smes.main.export_analysis_to_pdf")
@patch("builtins.input", return_value="n")
@patch("builtins.print")
def test_prompt_and_export_report_allows_skipping(
    mock_print,
    _input,
    mock_export_analysis_to_pdf,
):
    written_path = main.prompt_and_export_report({}, "memory.raw")

    assert written_path is None
    mock_export_analysis_to_pdf.assert_not_called()
    printed = "\n".join(call.args[0] for call in mock_print.call_args_list if call.args)
    assert "PDF export skipped." in printed
