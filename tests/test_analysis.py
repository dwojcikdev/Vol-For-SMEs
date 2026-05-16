from vol_for_smes.analysis import (
    analyse_artefacts,
    analyse_network_activity,
    analyse_plugin_output,
    analyse_process_activity,
    build_timeline,
    infer_mitre_techniques,
)


def test_analyse_plugin_output_flags_suspicious_cmdline():
    result = analyse_plugin_output(
        "windows.cmdline",
        [
            {
                "PID": 4321,
                "ImageFileName": "powershell.exe",
                "CommandLine": "powershell.exe -enc aQBlAHgA",
            }
        ],
    )

    assert result["severity"] == "high"
    assert result["risk_score"] > 0
    assert any(tag["technique_id"] == "T1059.001" for tag in result["mitre_tags"])
    assert result["indicators"]


def test_analyse_plugin_output_detects_hidden_processes_via_psscan():
    result = analyse_plugin_output(
        "windows.psscan",
        [{"PID": 99, "ImageFileName": "evil.exe"}],
        all_results={"windows.pslist": [{"PID": 4, "ImageFileName": "System"}]},
    )

    assert result["severity"] == "high"
    assert "psscan but not pslist" in result["indicators"][0]


def test_build_timeline_extracts_and_sorts_timestamp_events():
    timeline = build_timeline(
        {
            "windows.pslist": [
                {"PID": 100, "ImageFileName": "a.exe", "CreateTime": "2024-01-03 09:00:00 UTC"},
                {"PID": 101, "ImageFileName": "b.exe", "CreateTime": "2024-01-02 09:00:00 UTC"},
            ]
        }
    )

    assert [event["description"] for event in timeline] == [
        "b.exe reported by windows.pslist (CreateTime)",
        "a.exe reported by windows.pslist (CreateTime)",
    ]


def test_build_timeline_preserves_normalised_process_identifiers():
    timeline = build_timeline(
        {
            "windows.pslist": [
                {
                    "pid": "900",
                    "ppid": "400",
                    "name": "powershell.exe",
                    "CreateTime": "2024-01-03 09:00:00 UTC",
                }
            ]
        }
    )

    assert timeline[0]["entity_label"] == "powershell.exe"
    assert timeline[0]["pid"] == 900
    assert timeline[0]["ppid"] == 400


def test_analyse_artefacts_returns_findings_and_timeline():
    analysis = analyse_artefacts(
        {
            "windows.malfind": [{"PID": 444, "ImageFileName": "suspect.exe"}],
            "windows.pslist": [{"PID": 444, "ImageFileName": "suspect.exe", "CreateTime": "2024-01-01 10:00:00 UTC"}],
        }
    )

    assert analysis["plugin_findings"]["windows.malfind"]["severity"] == "high"
    assert analysis["risk_summary"]["high"] == 1
    assert analysis["process_analysis"]["severity"] == "medium"
    assert analysis["process_analysis"]["risk_score"] == 45
    assert any(tag["technique_id"] == "T1055" for tag in analysis["process_analysis"]["mitre_tags"])
    assert len(analysis["timeline"]) == 1


def test_analyse_process_activity_correlates_multiple_process_indicators():
    analysis = analyse_process_activity(
        {
            "windows.pslist": [
                {"PID": 900, "PPID": 4, "ImageFileName": "powershell.exe"},
            ],
            "windows.cmdline": [
                {"PID": 900, "ImageFileName": "powershell.exe", "CommandLine": "powershell.exe -enc AAAA"},
            ],
            "windows.dlllist": [
                {"PID": 900, "Path": r"C:\\Users\\Public\\payload.dll"},
            ],
            "windows.malfind": [
                {"PID": 900, "ImageFileName": "powershell.exe"},
            ],
        }
    )

    assert analysis["severity"] == "high"
    assert analysis["risk_score"] >= 80
    assert any(tag["technique_id"] == "T1055" for tag in analysis["mitre_tags"])
    assert analysis["suspicious_processes"][0]["pid"] == "900"
    assert analysis["suspicious_processes"][0]["risk_score"] >= 80
    assert any(
        "encoded powershell command" in reason.lower()
        for reason in analysis["suspicious_processes"][0]["reasons"]
    )


def test_analyse_process_activity_includes_hidden_process_findings():
    analysis = analyse_process_activity(
        {
            "windows.pslist": [
                {"PID": 4, "ImageFileName": "System"},
            ],
            "windows.psscan": [
                {"PID": 99, "ImageFileName": "evil.exe"},
            ],
        }
    )

    assert analysis["severity"] == "medium"
    assert analysis["summary"] == "1 suspicious process(es) identified"
    assert analysis["suspicious_processes"][0]["pid"] == "99"
    assert any(
        "psscan but not pslist" in reason.lower()
        for reason in analysis["suspicious_processes"][0]["reasons"]
    )


def test_analyse_network_activity_flags_shell_process_networking():
    analysis = analyse_network_activity(
        {
            "windows.netscan": [
                {
                    "PID": 333,
                    "Owner": "powershell.exe",
                    "LocalAddr": "10.0.0.5",
                    "LocalPort": 49152,
                    "ForeignAddr": "8.8.8.8",
                    "ForeignPort": 443,
                    "State": "ESTABLISHED",
                }
            ]
        }
    )

    assert analysis["severity"] == "high"
    assert analysis["risk_score"] >= 80
    assert any(tag["technique_id"] == "T1071" for tag in analysis["mitre_tags"])
    assert analysis["suspicious_connections"][0]["owner"] == "powershell.exe"
