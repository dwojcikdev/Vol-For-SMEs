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
- Automated findings are heuristic indicators intended to support human review, not replace it.
- `vol-for-smes` launches the GUI. `vol-for-smes-cli` keeps the original CLI workflow available as a secondary entry point.
- Volatility command discovery prefers the installed `volatility3` package and then compatible commands such as `vol` or `volatility`.
- PDF reporting is implemented without an external PDF package dependency.
