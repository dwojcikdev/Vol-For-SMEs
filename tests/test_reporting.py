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
        "timeline": [
            {
                "timestamp": "2024-01-01T10:00:00+00:00",
                "description": "powershell.exe reported by windows.pslist (CreateTime)",
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
    assert report["findings"][0]["attack"]
    assert report["findings"][0]["meaning"]
    assert report["findings"][0]["remediations"]
    assert report["analyst_notice"]
    assert report["case_metadata"]["memory_image"] == "sample.raw"


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
