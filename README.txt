# Vol for SMEs

a simplified memory forensics interface for small and medium enterprises.

## App bundle
Vol for SMEs comes with a setup.exe containing all dependencies, including Python, PyQt6 and volatility3
no dependencies are required if installed.

## Note for markers
if you do not wish to install the software, you may run the code through this alternative approach, although Python 3.12 will be required if doing so.
from project root:
  python -m pip install -r requirements.txt
  pyton -m vol_for_smes
optional:
  python -m pytest

pre-requisites for this route:
  https://www.python.org/downloads/latest/python3.12/

if testing app install:
  https://github.com/jrsoftware/issrc/releases/download/is-6_7_2/innosetup-6.7.2.exe
  run .\scripts\build-installer.ps1 #The submitted version will have the latest app built so this is optional if you want to make sure
  run dist/installer/VolForSMEs-Setup-0.1.0.exe and install 

sample memory images:
  https://livebournemouthac-my.sharepoint.com/:f:/g/personal/s5643193_bournemouth_ac_uk/IgDMAyjwgzL6Tb36JXDD8GAKAc1sm1pbDm89Uv8twaXMqAw?e=ejAw65
  

The bundled app includes an uninstaller with the option to remove user files so no registry keys or other traces will remain/

## Installation
the Windows installer is built with Inno Setup 6.
  run setup.exe

## Launching
Launch Vol For Smes.exe shortcut

## Features
- Desktop application for memory forensics investigations
- Alternative command-line workflow for running the tool without the GUI (Included for testing purposes, not the intended route)
- Integration with Volatility 3 for analysing Windows memory images
- Automatic operating system detection
- Built-in and custom plugin presets
- Multi-plugin investigation support
- Automated process and network analysis
- Timeline-based presentation of suspicious artefacts
- PDF report export for investigation findings
- Windows installer with bundled Python runtime and required dependencies

## Notes
the current investigation workflow is designed for Windows memory images only, windows versions 10 and 11 have been verified as working
any windows memory image that can run with vol 3 should work
automated findings are heuristic indicators intended to support human review and speed up investigations, not replace it.
treat the results as pointers, not facts
the tool may miss some artefacts and occasionally get false positives.


## Evidence Safety
treat memory images as sensitive evidence. The app hashes the selected memory image before analysis and records that metadata in the report output. Used to verify integrity of data
use a dedicated local analysis folder for `.mem` files and generated reports to keep evidence handling contained and traceable
memory images can contain sensitive date so avoid cloud-synced folders, network shares, and the project repository for evidence or report output.
the standard investigation workflow reads the memory image and does not auto-open exported extracted binaries, be careful when opening artefact dumps. The app does not currently have a dumping functionality but may in the future.
run the app as a normal user unless a separate administrative task explicitly requires elevation, assume least privelege principals.
