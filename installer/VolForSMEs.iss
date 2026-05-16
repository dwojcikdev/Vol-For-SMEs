#define AppName "Vol For SMEs"
#define AppPublisher "Vol For SMEs"
#define AppExeName "Vol For SMEs.exe"
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{A7C5F4D6-6B58-4F2D-9B5C-D4D4445D4A6E}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppMutex=VolForSMEsAppMutex
CloseApplications=yes
DefaultDirName={localappdata}\Programs\{#AppName}
DisableDirPage=no
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#AppExeName}
UninstallFilesDir={localappdata}\{#AppName}\Uninstall
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
OutputDir=..\dist\installer
OutputBaseFilename=VolForSMEs-Setup-{#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Installer
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
VersionInfoVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
Type: filesandordirs; Name: "{app}\vol_for_smes"
Type: files; Name: "{app}\launch_gui.pyw"
Type: files; Name: "{app}\LaunchVolForSMEs.vbs"
Type: filesandordirs; Name: "{app}\_internal"

[UninstallDelete]
; The bundled Python runtime may create bytecode caches inside these folders at runtime.
; Remove them recursively so uninstall does not leave behind non-empty internal directories.
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\Lib"
Type: dirifempty; Name: "{app}"

[Files]
Source: "..\dist\Vol For SMEs\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
