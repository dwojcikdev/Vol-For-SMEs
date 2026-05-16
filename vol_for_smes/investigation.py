from pathlib import Path

from .config.settings import PluginPreset, get_plugin_preset
from .utils.file_utils import (
    build_memory_image_metadata,
    get_reports_dir,
)
from .volatility import (
    DEFAULT_VOLATILITY_BACKEND,
    DEFAULT_PLUGIN_GROUP_NAME,
    VolatilityRunner,
    detect_os,
    resolve_volatility_command,
)

MEMORY_IMAGE_SELECTION_GUIDANCE = (
    "Safety note: use a copied local .mem file in a dedicated analysis folder, "
    "not a live infected VM. Avoid cloud-synced folders and run the app as a normal user where possible."
)

REPORT_EXPORT_GUIDANCE = (
    "Safety note: save reports to a separate local folder and avoid cloud-synced locations. "
    "Do not upload memory images or related artefacts to online services."
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
    architecture = os_info.get("architecture")
    major_version = os_info.get("major_version")
    minor_version = os_info.get("minor_version")

    print("Operating system: Windows")
    if architecture:
        print(f"Architecture: {architecture}")
    if major_version is not None:
        version = str(major_version)
        if minor_version is not None:
            version = f"{version}.{minor_version}"
        print(f"Version: {version}")
    print(f"Detected using: {detected_with}")


def _display_memory_image_metadata(memory_image_metadata):
    print("Memory Image Evidence:\n")
    print(f"Path: {memory_image_metadata.get('path', '')}")
    print(f"Resolved path: {memory_image_metadata.get('resolved_path', '')}")
    print(f"SHA-256: {memory_image_metadata.get('sha256', '')}")
    print(f"Size: {memory_image_metadata.get('size_bytes', 0)} bytes")


def run_investigation(
    memory_image,
    preset_name=DEFAULT_PLUGIN_GROUP_NAME,
    settings_path=None,
    memory_image_metadata=None,
):
    volatility_command = resolve_project_volatility_command()
    if volatility_command is None:
        print("\nInvestigation could not start.")
        return None, None

    try:
        preset = get_plugin_preset(preset_name, settings_path)
    except KeyError:
        print(f"\nPlugin preset '{preset_name}' was not found.")
        print("\nInvestigation could not start.")
        return None, None

    try:
        if memory_image_metadata is None:
            memory_image_metadata = build_memory_image_metadata(memory_image)
    except OSError as exc:
        print(f"\nCould not prepare the memory image for analysis: {exc}")
        print("\nInvestigation could not start.")
        return None, preset

    print("\nVolatility command resolved:")
    print(" ".join(volatility_command))
    print()
    _display_memory_image_metadata(memory_image_metadata)

    print("\nDetecting operating system...\n")
    os_info = detect_os(memory_image, volatility_command)

    display_os_detection_result(os_info)

    if "error" in os_info:
        print("\nInvestigation could not start.")
        return None, preset

    if os_info.get("os") != "Windows":
        print("\nUnsupported operating system.")
        return None, preset

    print("\nInitialising Volatility runner...\n")

    runner = VolatilityRunner(memory_image, volatility_command, os_context=os_info)
    plugins = list(preset.plugins)

    print(
        f"Running plugin preset '{preset.name}' "
        f"with {len(plugins)} plugin(s):\n"
    )
    for plugin in plugins:
        print(f"- {plugin}")
    print()

    results = runner.run_multiple(plugins)

    print("\nPlugin execution complete.\n")

    return results, preset


def default_report_path(memory_image):
    memory_image_path = Path(memory_image).expanduser()
    stem = memory_image_path.stem or "memory_image"
    return get_reports_dir() / f"{stem}_report.pdf"


def build_report_case_metadata(
    memory_image,
    preset: PluginPreset | None = None,
    memory_image_metadata=None,
):
    case_metadata = {"memory_image": memory_image}
    if memory_image_metadata:
        case_metadata["memory_image"] = memory_image_metadata.get("path", memory_image)
        case_metadata["memory_image_resolved"] = memory_image_metadata.get("resolved_path", "")
        case_metadata["memory_image_sha256"] = memory_image_metadata.get("sha256", "")
        case_metadata["memory_image_size_bytes"] = memory_image_metadata.get("size_bytes", 0)
    if preset is not None:
        case_metadata["plugin_preset"] = preset.name
        case_metadata["plugin_count"] = len(preset.plugins)
        case_metadata["plugins_run"] = ", ".join(preset.plugins)
        case_metadata["analysis_backend"] = DEFAULT_VOLATILITY_BACKEND
    return case_metadata
