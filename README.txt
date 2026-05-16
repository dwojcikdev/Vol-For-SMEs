# Vol For SMEs

A simplified memory forensics interface for small and medium enterprises.

## Requirements
- Python 3.12 or newer
- Volatility 3 is expected to be available from the Python environment or a compatible command on `PATH`

## Dependencies
- Runtime:
  `PyQt6>=6.7`
- Runtime memory-forensics dependency:
  `volatility3>=2.28.0`
- Development and testing:
  `pytest>=8`
- These are also listed in `requirements.txt` for local environment setup.

## Installation
- Install dependencies by running the following command:
  `python -m pip install -r requirements.txt`
- If you want the `vol-for-smes` and `vol-for-smes-cli` command entrypoints as well, install the package itself after that:
  `python -m pip install -e . --no-deps`

## Windows Installer
- The Windows installer is built with Inno Setup 6.
- The Windows build now creates a self-contained app bundle that includes a private Python runtime plus the packaged `PyQt6` and `volatility3` dependencies.
- The target machine does not need Python, `PyQt6`, or `volatility3` installed separately.
- Install Inno Setup 6, or note the full path to `ISCC.exe`.
- Build the installer from the repository root with:
  `.\scripts\build-installer.ps1`
- If Inno Setup is installed in a non-default location, pass the compiler path explicitly:
  `.\scripts\build-installer.ps1 -InnoCompilerPath "C:\Path\To\ISCC.exe"`
- To build only the self-contained app folder without creating the installer:
  `python .\scripts\build-windows-bundle.py`
- The Inno script lives at `installer\VolForSMEs.iss`.
- The generated installer is written to `dist\installer\`.
- The staged self-contained app bundle is written to `dist\Vol For SMEs\`.
- The installer packages that freshly built bundle, so it does not depend on a system Python install at runtime.
- The current installer is configured as a per-user install under `%LocalAppData%\Programs\Vol For SMEs` by default, with a Start Menu shortcut and an optional desktop shortcut.
- The setup wizard shows the normal destination-folder page, so the user can click `Browse...` and choose a different user-writable install location if needed.

## Launching
- Launch the GUI:
  `python -m vol_for_smes`
- Or use the installed GUI entrypoint:
  `vol-for-smes`
- Launch the CLI workflow:
  `vol-for-smes-cli`

## Features
- PyQt6 desktop GUI as the primary interface
- Persisted appearance themes including light, dark, and mint-accent variants
- Built-in and custom plugin presets with persistent storage
- Volatility plugin discovery to support larger preset selection
- Automated OS detection
- Multi-plugin investigation runs through selectable presets
- Timeline of artifacts
- PDF forensic reporting

## Notes
- The current investigation workflow is designed for Windows memory images.
- The app uses Volatility 3 with automatic OS detection for supported Windows images.
- Automated findings are heuristic indicators intended to support human review, not replace it.
- `vol-for-smes` launches the GUI. `vol-for-smes-cli` keeps the original CLI workflow available as a secondary entry point.
- Volatility command discovery prefers the installed `volatility3` package and then compatible commands such as `vol` or `volatility`.
- PDF reporting is implemented without an external PDF package dependency.

## Evidence Safety
- Treat memory images as sensitive evidence. The app hashes the selected memory image before analysis and records that metadata in the report output.
- Use a dedicated local analysis folder for `.mem` files and generated reports.
- Avoid cloud-synced folders, network shares, and the project repository for evidence or report output. The app shows checklist-based safety reminders when selecting evidence and report paths, but it does not inspect or block the chosen location.
- The standard investigation workflow reads the memory image and does not auto-open exported reports or extracted binaries.
- Run the app as a normal user unless a separate administrative task explicitly requires elevation.
