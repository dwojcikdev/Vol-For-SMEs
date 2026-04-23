from vol_for_smes.analysis import analyse_artifacts, analyse_plugin_output, build_timeline


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


def test_analyse_artifacts_returns_findings_and_timeline():
    analysis = analyse_artifacts(
        {
            "windows.malfind": [{"PID": 444, "ImageFileName": "suspect.exe"}],
            "windows.pslist": [{"PID": 444, "ImageFileName": "suspect.exe", "CreateTime": "2024-01-01 10:00:00 UTC"}],
        }
    )

    assert analysis["plugin_findings"]["windows.malfind"]["severity"] == "high"
    assert analysis["risk_summary"]["high"] == 1
    assert len(analysis["timeline"]) == 1
