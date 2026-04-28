from pathlib import Path

from .volatility import (
    VolatilityRunner,
    PLUGIN_GROUPS,
    parse_processes,
    detect_os,
    resolve_volatility_command,
)
from .analysis import analyse_artifacts
from .reporting import export_analysis_to_pdf


def _format_mitre_tags(mitre_tags):
    if not mitre_tags:
        return "None"
    return ", ".join(
        f"{tag.get('technique_id')} {tag.get('name')}"
        for tag in mitre_tags[:5]
    )


def resolve_project_volatility_command():
    try:
        return resolve_volatility_command()
    except RuntimeError as exc:
        print(f"\nCould not resolve Volatility from the project installation folder: {exc}")
        return None


def display_os_detection_result(os_info):
    print("OS Detection Result:\n")

    if "error" in os_info:
        print("We could not identify the operating system from the memory image.")
        print(f"Reason: {os_info['error']}")
        return

    if os_info.get("os") != "Windows":
        print(f"Detected operating system: {os_info.get('os', 'Unknown')}")
        return

    detected_with = os_info.get("detected_with", "unknown plugin")
    variant = os_info.get("volatility_variant", "unknown")
    architecture = os_info.get("architecture")
    major_version = os_info.get("major_version")
    minor_version = os_info.get("minor_version")
    profile = os_info.get("profile")

    print("Operating system: Windows")
    if architecture:
        print(f"Architecture: {architecture}")
    if major_version is not None:
        version = str(major_version)
        if minor_version is not None:
            version = f"{version}.{minor_version}"
        print(f"Version: {version}")
    if profile:
        print(f"Profile: {profile}")
    print(f"Detected using: {detected_with}")
    print(f"Volatility version: {variant}")


def run_default_investigation(memory_image):
    volatility_command = resolve_project_volatility_command()
    if volatility_command is None:
        print("\nInvestigation could not start.")
        return

    print("\nVolatility command resolved:")
    print(" ".join(volatility_command))

    print("\nDetecting operating system...\n")

    os_info = detect_os(memory_image, volatility_command)

    display_os_detection_result(os_info)

    if "error" in os_info:
        print("\nInvestigation could not start.")
        return

    if os_info.get("os") != "Windows":
        print("\nUnsupported operating system.")
        return

    print("\nInitialising Volatility runner...\n")

    runner = VolatilityRunner(memory_image, volatility_command, os_context=os_info)

    plugins = PLUGIN_GROUPS["default_investigation"]

    print("Running default investigation plugins:\n")

    results = runner.run_multiple(plugins)

    print("\nPlugin execution complete.\n")

    return results


def display_analysis_results(analysis):
    plugin_findings = analysis.get("plugin_findings", {})
    risk_summary = analysis.get("risk_summary", {})
    process_analysis = analysis.get("process_analysis", {})
    network_analysis = analysis.get("network_analysis", {})
    timeline = analysis.get("timeline", [])

    print("\nAnalysis Summary:\n")
    print(
        "High: {high}  Medium: {medium}  Low: {low}  None: {none}".format(
            high=risk_summary.get("high", 0),
            medium=risk_summary.get("medium", 0),
            low=risk_summary.get("low", 0),
            none=risk_summary.get("none", 0),
        )
    )

    interesting_findings = [
        finding
        for finding in plugin_findings.values()
        if finding.get("severity") in {"high", "medium"}
    ]

    if interesting_findings:
        print("\nPotentially suspicious findings:\n")
        for finding in sorted(
            interesting_findings,
            key=lambda item: {"high": 0, "medium": 1}.get(item.get("severity"), 2),
        ):
            print(
                f"[{finding['severity'].upper()}] {finding['plugin']}: {finding['summary']}"
            )
            print(f"  Risk score: {finding.get('risk_score', 0)}")
            print(f"  MITRE ATT&CK: {_format_mitre_tags(finding.get('mitre_tags', []))}")
            for indicator in finding.get("indicators", [])[:5]:
                print(f"  - {indicator}")
    else:
        print("\nNo medium or high severity findings were identified.\n")

    process_summary = process_analysis.get("summary")
    suspicious_processes = process_analysis.get("suspicious_processes", [])
    if process_summary:
        print("\nProcess Analysis:\n")
        print(process_summary)
        print(f"Risk score: {process_analysis.get('risk_score', 0)}")
        print(f"MITRE ATT&CK: {_format_mitre_tags(process_analysis.get('mitre_tags', []))}")
        if suspicious_processes:
            for process in suspicious_processes[:5]:
                print(
                    f"[{process['severity'].upper()}] {process.get('name') or 'unknown'} "
                    f"(PID {process.get('pid') or '?'})"
                )
                print(f"  Risk score: {process.get('risk_score', 0)}")
                print(f"  MITRE ATT&CK: {_format_mitre_tags(process.get('mitre_tags', []))}")
                for reason in process.get("reasons", [])[:3]:
                    print(f"  - {reason}")

    network_summary = network_analysis.get("summary")
    suspicious_connections = network_analysis.get("suspicious_connections", [])
    if network_summary:
        print("\nNetwork Analysis:\n")
        print(network_summary)
        print(f"Risk score: {network_analysis.get('risk_score', 0)}")
        print(f"MITRE ATT&CK: {_format_mitre_tags(network_analysis.get('mitre_tags', []))}")
        if suspicious_connections:
            for connection in suspicious_connections[:5]:
                print(
                    f"[{connection['severity'].upper()}] "
                    f"{connection.get('owner') or 'unknown process'} "
                    f"(PID {connection.get('pid') or '?'}) "
                    f"{connection.get('local_address') or '?'}:{connection.get('local_port') or '?'} "
                    f"-> {connection.get('remote_address') or '?'}:{connection.get('remote_port') or '?'}"
                )
                print(f"  Risk score: {connection.get('risk_score', 0)}")
                print(f"  MITRE ATT&CK: {_format_mitre_tags(connection.get('mitre_tags', []))}")
                for reason in connection.get("reasons", [])[:3]:
                    print(f"  - {reason}")

    if timeline:
        print("\nTimeline preview:\n")
        for event in timeline[:10]:
            print(f"{event['timestamp']}  {event['description']}")
    else:
        print("No timestamped artefacts were available for the timeline.")


def display_process_results(results):

    if "windows.pslist" not in results:
        print("No process results available.")
        return

    raw = results["windows.pslist"]

    if "error" in raw:
        print("Error retrieving processes:", raw["error"])
        return

    processes = parse_processes(raw)

    print("\nRunning Processes:\n")

    for process in processes[:15]:

        print(
            f"PID: {process['pid']}  "
            f"PPID: {process['ppid']}  "
            f"Name: {process['name']}  "
            f"Threads: {process['threads']}"
        )


def _default_report_path(memory_image):
    memory_image_path = Path(memory_image).expanduser()
    stem = memory_image_path.stem or "memory_image"
    return Path.cwd() / f"{stem}_report.pdf"


def prompt_and_export_report(analysis, memory_image):
    response = input("Export analysis report to PDF? [Y/n]: ").strip().lower()
    if response not in {"", "y", "yes"}:
        print("PDF export skipped.")
        return None

    default_output_path = _default_report_path(memory_image)
    custom_output = input(
        f"Enter PDF output path [{default_output_path}]: "
    ).strip()
    output_path = Path(custom_output) if custom_output else default_output_path

    try:
        written_path = export_analysis_to_pdf(
            analysis,
            output_path,
            case_metadata={"memory_image": memory_image},
        )
    except OSError as exc:
        print(f"Could not export PDF report: {exc}")
        return None

    print(f"PDF report exported to: {written_path}")
    return written_path


def main():

    print("Vol For SMEs - Memory Forensics Tool\n")

    memory_image = input("Enter memory image path: ").strip()

    results = run_default_investigation(memory_image)

    if not results:
        return

    analysis = analyse_artifacts(results)

    display_analysis_results(analysis)
    display_process_results(results)
    prompt_and_export_report(analysis, memory_image)


if __name__ == "__main__":
    main()


