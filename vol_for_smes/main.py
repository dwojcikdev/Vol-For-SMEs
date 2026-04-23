from .volatility import (
    VolatilityRunner,
    PLUGIN_GROUPS,
    parse_processes,
    detect_os,
    resolve_volatility_command,
)
from .analysis import analyse_artifacts

def resolve_project_volatility_command():
    try:
        return resolve_volatility_command()
    except RuntimeError as exc:
        print(f"\nCould not resolve Volatility from the project installation folder: {exc}")
        return None


def run_default_investigation(memory_image):
    volatility_command = resolve_project_volatility_command()
    if volatility_command is None:
        print("\nInvestigation could not start.")
        return

    print("\nVolatility command resolved:")
    print(" ".join(volatility_command))

    print("\nDetecting operating system...\n")

    os_info = detect_os(memory_image, volatility_command)

    print("OS Detection Result:")
    print(os_info)

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
            for indicator in finding.get("indicators", [])[:5]:
                print(f"  - {indicator}")
    else:
        print("\nNo medium or high severity findings were identified.\n")

    if timeline:
        print("Timeline preview:\n")
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


def main():

    print("Vol For SMEs - Memory Forensics Tool\n")

    memory_image = input("Enter memory image path: ").strip()

    results = run_default_investigation(memory_image)

    if not results:
        return

    analysis = analyse_artifacts(results)

    display_analysis_results(analysis)
    display_process_results(results)


if __name__ == "__main__":
    main()


