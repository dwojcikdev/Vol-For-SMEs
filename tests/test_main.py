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
            "volatility_variant": "vol3",
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
