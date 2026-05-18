from pathlib import Path

from vol_for_smes.reporting import build_analysis_report, export_analysis_to_pdf


def _sample_analysis():
    return {
        "plugin_findings": {
            "windows.malfind": {
                "plugin": "windows.malfind",
                "severity": "high",
                "risk_score": 95,
                "mitre_tags": [{"technique_id": "T1055", "name": "Process Injection"}],
                "summary": "1 suspicious indicator(s) detected",
                "indicators": ["Injected or RWX memory candidate in powershell.exe | PID 900"],
            },
            "windows.pslist": {
                "plugin": "windows.pslist",
                "severity": "none",
                "risk_score": 0,
                "mitre_tags": [],
                "summary": "No obvious malicious indicators detected by current heuristics",
                "indicators": [],
            },
        },
        "risk_summary": {"high": 1, "medium": 0, "low": 0, "none": 1},
        "process_analysis": {
            "summary": "1 suspicious process(es) identified",
            "severity": "high",
            "risk_score": 97,
            "mitre_tags": [{"technique_id": "T1055", "name": "Process Injection"}],
            "suspicious_processes": [
                {
                    "name": "powershell.exe",
                    "pid": "900",
                    "severity": "high",
                    "risk_score": 97,
                    "mitre_tags": [{"technique_id": "T1055", "name": "Process Injection"}],
                    "reasons": [
                        "malfind identified suspicious injected or executable memory",
                        "suspicious command-line execution pattern",
                    ],
                    "command_line": r"\"C:\Users\Alice\Downloads\powershell.exe\" -enc AAAA",
                    "reference_hits": [
                        {
                            "pattern": "restore_files.txt",
                            "path": r"c:\users\alice\desktop\restore_files.txt",
                            "confidence": "medium",
                            "match_scope": "basename",
                        }
                    ],
                    "file_hits": [],
                    "handle_hits": [],
                    "evidence": {
                        "image_path": r"C:\Users\Alice\Downloads\powershell.exe",
                    },
                }
            ],
        },
        "network_analysis": {
            "summary": "1 suspicious network connection(s) identified",
            "severity": "high",
            "risk_score": 88,
            "mitre_tags": [{"technique_id": "T1071", "name": "Application Layer Protocol"}],
            "suspicious_connections": [
                {
                    "owner": "powershell.exe",
                    "pid": "900",
                    "local_address": "10.0.0.5",
                    "local_port": "49152",
                    "remote_address": "8.8.8.8",
                    "remote_port": "443",
                    "state": "established",
                    "severity": "high",
                    "risk_score": 88,
                    "mitre_tags": [{"technique_id": "T1071", "name": "Application Layer Protocol"}],
                    "reasons": ["interactive shell process communicating over the network"],
                }
            ],
        },
        "activity_chains": [
            {
                "chain_id": "chain-900",
                "title": "Correlated activity chain: powershell.exe (PID 900)",
                "summary": "powershell.exe (PID 900) formed a suspicious activity chain with 1 supporting artefact match.",
                "severity": "high",
                "risk_score": 100,
                "primary_process": {
                    "name": "powershell.exe",
                    "pid": "900",
                },
                "related_processes": [
                    {
                        "name": "powershell.exe",
                        "pid": "900",
                    }
                ],
                "reference_hits": [
                    {
                        "plugin": "windows.handles",
                        "path": r"c:\users\alice\desktop\restore_files.txt",
                        "pattern": "restore_files.txt",
                        "confidence": "medium",
                    }
                ],
                "timeline": [
                    {
                        "timestamp": "2024-01-01T10:00:00+00:00",
                        "description": "powershell.exe reported by windows.pslist (CreateTime)",
                    }
                ],
                "mitre_tags": [{"technique_id": "T1486", "name": "Data Encrypted for Impact"}],
                "evidence": [
                    "powershell.exe (PID 900): suspicious command-line execution pattern",
                    "windows.handles matched ransomware reference 'restore_files.txt' (medium, basename) for c:\\users\\alice\\desktop\\restore_files.txt",
                ],
            }
        ],
        "timeline": [
            {
                "timestamp": "2024-01-01T10:00:00+00:00",
                "description": "powershell.exe reported by windows.pslist (CreateTime)",
            }
        ],
        "suspicious_timeline": [
            {
                "timestamp": "2024-01-01T10:00:00+00:00",
                "description": "powershell.exe reported by windows.pslist (CreateTime)",
            }
        ],
        "plugin_execution_log": [
            {
                "plugin": "windows.pslist",
                "success": True,
                "status": "completed",
                "started_offset_seconds": 0.0,
                "finished_offset_seconds": 1.25,
                "elapsed_seconds": 1.25,
                "error_message": None,
            }
        ],
    }


def test_build_analysis_report_enriches_findings_with_explanations():
    report = build_analysis_report(
        _sample_analysis(),
        case_metadata={"memory_image": "sample.raw", "analyst": "Unit Test"},
    )

    assert report["title"] == "Vol For SMEs Memory Analysis Report"
    assert report["executive_summary"]
    assert report["findings"]
    assert report["findings"][0]["category"] == "Correlated Activity Chain"
    assert report["findings"][0]["attack"]
    assert report["findings"][0]["meaning"]
    assert report["findings"][0]["remediations"]
    assert report["analyst_notice"]
    assert report["case_metadata"]["memory_image"] == "sample.raw"
    assert report["timeline"] == _sample_analysis()["suspicious_timeline"]
    assert report["plugin_execution_log"] == _sample_analysis()["plugin_execution_log"]

    process_finding = next(
        f for f in report["findings"] if f["category"] == "Process Finding"
    )
    assert process_finding["affected_asset"] == "powershell.exe"
    assert process_finding["affected_pids"] == ["900"]
    assert process_finding["show_affected_asset"] is False
    assert process_finding["show_affected_pids"] is False

    network_finding = next(
        f for f in report["findings"] if f["category"] == "Network Finding"
    )
    assert network_finding["affected_asset"] == "powershell.exe"
    assert network_finding["affected_pids"] == ["900"]
    assert network_finding["show_affected_asset"] is False
    assert network_finding["show_affected_pids"] is False

    chain_finding = next(
        f for f in report["findings"] if f["category"] == "Correlated Activity Chain"
    )
    assert chain_finding["affected_asset"] == "powershell.exe"
    assert chain_finding["affected_pids"] == ["900"]
    assert chain_finding["show_affected_asset"] is False
    assert chain_finding["show_affected_pids"] is False


def test_build_analysis_report_hides_single_pid_when_title_uses_colon_format():
    analysis = _sample_analysis()
    analysis["activity_chains"][0]["title"] = "Correlated activity chain: powershell.exe (PID: 900)"

    report = build_analysis_report(analysis)
    chain_finding = next(
        finding
        for finding in report["findings"]
        if finding["category"] == "Correlated Activity Chain"
    )

    assert chain_finding["affected_pids"] == ["900"]
    assert chain_finding["show_affected_asset"] is False
    assert chain_finding["show_affected_pids"] is False


def test_build_analysis_report_process_findings_include_structured_reference_evidence():
    report = build_analysis_report(_sample_analysis())

    process_finding = next(
        finding
        for finding in report["findings"]
        if finding["category"] == "Process Finding"
    )

    assert any(
        line.startswith("Matched reference pattern: restore_files.txt")
        for line in process_finding["evidence"]
    )
    assert any(
        line == r"Matched path: c:\users\alice\desktop\restore_files.txt"
        for line in process_finding["evidence"]
    )
    assert any(
        line == r"Image path: C:\Users\Alice\Downloads\powershell.exe"
        for line in process_finding["evidence"]
    )
    assert any(
        line.startswith(r"Command line: \"C:\Users\Alice\Downloads\powershell.exe\" -enc AAAA")
        for line in process_finding["evidence"]
    )


def test_build_analysis_report_surfaces_related_pids_for_multi_process_chains():
    analysis = _sample_analysis()
    analysis["activity_chains"][0]["related_processes"] = [
        {"name": "powershell.exe", "pid": "900"},
        {"name": "cmd.exe", "pid": "901"},
    ]

    report = build_analysis_report(analysis)
    chain_finding = next(
        finding
        for finding in report["findings"]
        if finding["category"] == "Correlated Activity Chain"
    )

    assert chain_finding["affected_pids"] == ["900", "901"]
    assert chain_finding["show_affected_asset"] is False
    assert chain_finding["show_affected_pids"] is True
    assert chain_finding["affected_pid_label"] == "Related PIDs"


def test_export_analysis_to_pdf_writes_pdf_with_expected_sections(tmp_path: Path):
    output_path = tmp_path / "report.pdf"

    written_path = export_analysis_to_pdf(
        _sample_analysis(),
        output_path,
        case_metadata={"memory_image": "sample.raw"},
    )

    pdf_bytes = written_path.read_bytes()
    assert written_path == output_path
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"Vol For SMEs Memory Analysis Report" in pdf_bytes
    assert b"Analyst Review Notice" in pdf_bytes
    assert b"Detailed Findings" in pdf_bytes
    assert b"Recommended remediation" in pdf_bytes
    assert b"Affected asset: powershell.exe" not in pdf_bytes
