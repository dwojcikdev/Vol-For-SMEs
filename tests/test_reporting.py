from pathlib import Path

from vol_for_smes.analysis import (
    ClamAVHit,
    MalwareTriageFinding,
    MalwareTriageReport,
    PluginRunResult,
    SuspiciousProcessFinding,
)
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


def _sample_triage_report():
    return MalwareTriageReport(
        memory_image="sample.raw",
        output_directory="reports/triage",
        clamav_available=True,
        volatility_results=[
            PluginRunResult(plugin="windows.pslist", success=True, rows=[]),
        ],
        clamav_hits=[
            ClamAVHit(
                file_path="volatility_dumps/malfind.pid_900.dmp",
                signature="Win.Test.Eicar",
            )
        ],
        process_findings=[
            SuspiciousProcessFinding(
                pid=900,
                name="powershell.exe",
                parent_pid=512,
                parent_name="winword.exe",
                score=105,
                severity="High",
                reasons=[
                    "malfind reported possible injected executable memory",
                    "Command line contains encoded PowerShell command",
                ],
                mitre_tags=[
                    {"technique_id": "T1055", "name": "Process Injection"},
                    {"technique_id": "T1059.001", "name": "PowerShell"},
                ],
                evidence={"command_line": "powershell.exe -enc AAAA"},
            )
        ],
        findings=[
            MalwareTriageFinding(
                severity="High",
                title="Known malware signature detected",
                description=(
                    "ClamAV detected a known malware signature in a file dumped "
                    "from memory."
                ),
                score=60,
                reasons=["ClamAV signature matched: Win.Test.Eicar"],
                evidence={
                    "file": "volatility_dumps/malfind.pid_900.dmp",
                    "signature": "Win.Test.Eicar",
                },
            ),
            MalwareTriageFinding(
                severity="High",
                title="High-risk suspicious process activity detected",
                description=(
                    "1 process(es) reached a High severity suspicion score based "
                    "on memory forensic indicators."
                ),
                score=70,
                reasons=[
                    "One or more processes had a suspicious score of 70 or above"
                ],
                mitre_tags=[
                    {"technique_id": "T1055", "name": "Process Injection"},
                    {"technique_id": "T1059.001", "name": "PowerShell"},
                ],
                evidence={"high_process_count": 1},
            ),
        ],
    )


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
    assert report["case_metadata"]["memory_image"] == "sample.raw"


def test_build_analysis_report_accepts_triage_report_objects():
    report = build_analysis_report(
        _sample_triage_report(),
        case_metadata={"analyst": "Unit Test"},
    )

    assert report["title"] == "Vol For SMEs Known Malware Triage Report"
    assert report["case_metadata"]["memory_image"] == "sample.raw"
    assert report["process_analysis"]["severity"] == "high"
    assert report["process_analysis"]["suspicious_processes"][0]["mitre_tags"]
    assert any(
        finding["category"] == "Process Finding"
        for finding in report["findings"]
    )
    assert any(
        "T1055 - Process Injection" in finding["mitre"]
        for finding in report["findings"]
        if finding["category"] == "Process Finding"
    )


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
    assert b"Detailed Findings" in pdf_bytes
    assert b"Recommended remediation" in pdf_bytes


def test_export_analysis_to_pdf_accepts_triage_report_objects(tmp_path: Path):
    output_path = tmp_path / "triage-report.pdf"

    written_path = export_analysis_to_pdf(
        _sample_triage_report(),
        output_path,
    )

    pdf_bytes = written_path.read_bytes()
    assert written_path == output_path
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"Vol For SMEs Known Malware Triage Report" in pdf_bytes
    assert b"Known malware signature detected" in pdf_bytes
