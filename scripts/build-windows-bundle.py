from __future__ import annotations

import importlib.metadata as metadata
import json
import os
import shutil
import stat
import sys
import tomllib
from pathlib import Path

try:
    from distlib.scripts import ScriptMaker
except ImportError:  # pragma: no cover - build-time fallback
    from pip._vendor.distlib.scripts import ScriptMaker

try:
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
except ImportError:  # pragma: no cover - build-time fallback
    from pip._vendor.packaging.markers import default_environment
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name


APP_NAME = "Vol For SMEs"
GUI_LAUNCHER_NAME = f"{APP_NAME}.exe"
CONSOLE_LAUNCHER_NAME = f"{APP_NAME} Console.exe"
REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
PYTHON_ROOT = Path(sys.base_prefix).resolve()
BUNDLE_ROOT = REPO_ROOT / "dist" / APP_NAME
APP_ROOT = BUNDLE_ROOT / "app"
SITE_PACKAGES_SOURCE = PYTHON_ROOT / "Lib" / "site-packages"
SITE_PACKAGES_DEST = BUNDLE_ROOT / "Lib" / "site-packages"


def _load_project_metadata() -> dict:
    with PYPROJECT_PATH.open("rb") as file:
        return tomllib.load(file)


def _project_version(pyproject: dict) -> str:
    return str(pyproject.get("project", {}).get("version", "0.0.0"))


def _runtime_dependency_names(pyproject: dict) -> list[str]:
    dependencies = pyproject.get("project", {}).get("dependencies", [])
    return [Requirement(dependency_text).name for dependency_text in dependencies]


def _handle_remove_readonly(function, path: str, _excinfo) -> None:
    os.chmod(path, stat.S_IWRITE)
    function(path)


def _reset_bundle_root() -> None:
    if BUNDLE_ROOT.exists():
        shutil.rmtree(BUNDLE_ROOT, onexc=_handle_remove_readonly)
    BUNDLE_ROOT.mkdir(parents=True, exist_ok=True)


def _copy_python_runtime() -> None:
    runtime_files = [
        "python.exe",
        "pythonw.exe",
        "python3.dll",
        f"python{sys.version_info.major}{sys.version_info.minor}.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "LICENSE.txt",
    ]
    for filename in runtime_files:
        source_path = PYTHON_ROOT / filename
        if source_path.is_file():
            shutil.copy2(source_path, BUNDLE_ROOT / filename)

    shutil.copytree(
        PYTHON_ROOT / "DLLs",
        BUNDLE_ROOT / "DLLs",
        ignore=shutil.ignore_patterns(
            "__pycache__",
            "*.pyc",
            "*.pyo",
            "*_test*.pyd",
            "_tkinter.pyd",
            "py.ico",
            "pyc.ico",
            "pyd.ico",
            "python_lib.cat",
            "tcl86t.dll",
            "tk86t.dll",
        ),
    )
    shutil.copytree(
        PYTHON_ROOT / "Lib",
        BUNDLE_ROOT / "Lib",
        ignore=shutil.ignore_patterns(
            "site-packages",
            "__pycache__",
            "*.pyc",
            "*.pyo",
            "test",
            "tests",
            "ensurepip",
            "idlelib",
            "tkinter",
            "turtledemo",
            "venv",
        ),
    )
    SITE_PACKAGES_DEST.mkdir(parents=True, exist_ok=True)


def _resolve_distribution_closure(root_names: list[str]) -> dict[str, metadata.Distribution]:
    environment = default_environment()
    resolved: dict[str, metadata.Distribution] = {}
    pending = [canonicalize_name(name) for name in root_names]

    while pending:
        distribution_name = pending.pop()
        if distribution_name in resolved:
            continue

        distribution = metadata.distribution(distribution_name)
        resolved[distribution_name] = distribution

        for dependency_text in distribution.requires or []:
            dependency = Requirement(dependency_text)
            if dependency.marker and not dependency.marker.evaluate(environment):
                continue

            normalized_name = canonicalize_name(dependency.name)
            if normalized_name not in resolved:
                pending.append(normalized_name)

    return resolved


def _copy_distribution_files(distribution: metadata.Distribution) -> None:
    if distribution.files is None:
        raise RuntimeError(
            f"Could not enumerate installed files for dependency '{distribution.metadata['Name']}'."
        )

    for relative_path in distribution.files:
        source_path = Path(distribution.locate_file(relative_path)).resolve()
        try:
            site_relative_path = source_path.relative_to(SITE_PACKAGES_SOURCE)
        except ValueError:
            continue

        if source_path.is_dir():
            continue
        if "__pycache__" in source_path.parts:
            continue
        if source_path.suffix.lower() in {".pyc", ".pyo"}:
            continue

        destination_path = SITE_PACKAGES_DEST / site_relative_path
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)


def _copy_application_files() -> None:
    shutil.copytree(
        REPO_ROOT / "vol_for_smes",
        APP_ROOT / "vol_for_smes",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    shutil.copy2(REPO_ROOT / "installer" / "launch_gui.pyw", APP_ROOT / "launch_gui.pyw")
    shutil.copy2(REPO_ROOT / "installer" / "LaunchVolForSMEs.vbs", BUNDLE_ROOT / "LaunchVolForSMEs.vbs")
    shutil.copy2(REPO_ROOT / "README.txt", BUNDLE_ROOT / "README.txt")
    if (REPO_ROOT / "LICENSE").is_file():
        shutil.copy2(REPO_ROOT / "LICENSE", BUNDLE_ROOT / "LICENSE")


def _write_python_path_files() -> None:
    pth_contents = "\n".join(
        [
            ".",
            "DLLs",
            "Lib",
            "Lib\\site-packages",
            "app",
            "",
        ]
    )
    filenames = [
        "python._pth",
        "pythonw._pth",
        f"python{sys.version_info.major}{sys.version_info.minor}._pth",
    ]
    for filename in filenames:
        (BUNDLE_ROOT / filename).write_text(pth_contents, encoding="utf-8")


def _rename_launcher(source_paths: list[str], destination_name: str) -> None:
    if len(source_paths) != 1:
        raise RuntimeError(
            f"Expected one generated launcher for '{destination_name}', got {source_paths!r}."
        )

    source_path = Path(source_paths[0])
    destination_path = BUNDLE_ROOT / destination_name
    source_path.replace(destination_path)


def _write_entrypoint_launchers() -> None:
    maker = ScriptMaker(str(REPO_ROOT), str(BUNDLE_ROOT))
    maker.clobber = True
    maker.variants = {""}
    # Use the bundled interpreter name so the generated stubs stay portable.
    maker.executable = "python.exe"

    gui_launcher = maker.make(
        "vol-for-smes = vol_for_smes.gui.runtime_launcher:main",
        options={"gui": True},
    )
    _rename_launcher(gui_launcher, GUI_LAUNCHER_NAME)

    console_launcher = maker.make(
        "vol-for-smes-cli = vol_for_smes.main:main",
    )
    _rename_launcher(console_launcher, CONSOLE_LAUNCHER_NAME)


def _write_bundle_manifest(
    *,
    app_version: str,
    distributions: dict[str, metadata.Distribution],
) -> None:
    manifest = {
        "app_name": APP_NAME,
        "app_version": app_version,
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "python_root": str(PYTHON_ROOT),
        "bundled_distributions": {
            distribution.metadata["Name"]: distribution.version
            for distribution in sorted(
                distributions.values(),
                key=lambda item: canonicalize_name(item.metadata["Name"]),
            )
        },
    }
    (BUNDLE_ROOT / "bundle-manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    pyproject = _load_project_metadata()
    app_version = _project_version(pyproject)
    dependency_names = _runtime_dependency_names(pyproject)

    _reset_bundle_root()
    _copy_python_runtime()

    distributions = _resolve_distribution_closure(dependency_names)
    for distribution_name in sorted(distributions):
        _copy_distribution_files(distributions[distribution_name])

    _copy_application_files()
    _write_python_path_files()
    _write_entrypoint_launchers()
    _write_bundle_manifest(
        app_version=app_version,
        distributions=distributions,
    )

    print(f"Built Windows app bundle at: {BUNDLE_ROOT}")
    print(f"Bundled Python runtime from: {PYTHON_ROOT}")
    print(
        "Bundled runtime dependencies: "
        + ", ".join(sorted(distribution.metadata["Name"] for distribution in distributions.values()))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
