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
; Optionally remove saved user data when the user selects the checkbox in the uninstall prompt.
Type: files; Name: "{userappdata}\{#AppName}\user_settings.json"; Check: ShouldRemoveUserDataOnUninstall
Type: filesandordirs; Name: "{localappdata}\{#AppName}\Reports"; Check: ShouldRemoveUserDataOnUninstall
Type: filesandordirs; Name: "{localappdata}\{#AppName}\Logs"; Check: ShouldRemoveUserDataOnUninstall
Type: filesandordirs; Name: "{localappdata}\{#AppName}\VolatilityCache"; Check: ShouldRemoveUserDataOnUninstall
Type: dirifempty; Name: "{userappdata}\{#AppName}"; Check: ShouldRemoveUserDataOnUninstall
Type: dirifempty; Name: "{localappdata}\{#AppName}"; Check: ShouldRemoveUserDataOnUninstall

[Files]
Source: "..\dist\Vol For SMEs\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
var
  RemoveUserDataOnUninstall: Boolean;

function ShouldRemoveUserDataOnUninstall(): Boolean;
begin
  Result := RemoveUserDataOnUninstall;
end;

function ShowUninstallOptionsPrompt(): Boolean;
var
  Form: TSetupForm;
  IntroLabel, DetailLabel, NoteLabel: TNewStaticText;
  RemoveDataCheckBox: TNewCheckBox;
  UninstallButton, CancelButton: TNewButton;
  ButtonWidth: Integer;
begin
  Form := CreateCustomForm(ScaleX(440), ScaleY(190), True, False);
  try
    Form.Caption := 'Uninstall {#AppName}';

    IntroLabel := TNewStaticText.Create(Form);
    IntroLabel.Parent := Form;
    IntroLabel.Left := ScaleX(12);
    IntroLabel.Top := ScaleY(12);
    IntroLabel.Width := Form.ClientWidth - ScaleX(24);
    IntroLabel.WordWrap := True;
    IntroLabel.Caption := 'This will uninstall {#AppName} from this Windows account.';
    IntroLabel.AdjustHeight;

    DetailLabel := TNewStaticText.Create(Form);
    DetailLabel.Parent := Form;
    DetailLabel.Left := IntroLabel.Left;
    DetailLabel.Top := IntroLabel.Top + IntroLabel.Height + ScaleY(10);
    DetailLabel.Width := IntroLabel.Width;
    DetailLabel.WordWrap := True;
    DetailLabel.Caption :=
      'The app files will be removed either way. Use the checkbox below if you also want to remove saved settings, reports, logs, and cached data stored in AppData.';
    DetailLabel.AdjustHeight;

    RemoveDataCheckBox := TNewCheckBox.Create(Form);
    RemoveDataCheckBox.Parent := Form;
    RemoveDataCheckBox.Left := IntroLabel.Left;
    RemoveDataCheckBox.Top := DetailLabel.Top + DetailLabel.Height + ScaleY(12);
    RemoveDataCheckBox.Width := Form.ClientWidth - ScaleX(24);
    RemoveDataCheckBox.Height := ScaleY(17);
    RemoveDataCheckBox.Caption := 'Also remove saved settings, reports, logs, and cache data';
    RemoveDataCheckBox.Checked := False;

    NoteLabel := TNewStaticText.Create(Form);
    NoteLabel.Parent := Form;
    NoteLabel.Left := IntroLabel.Left;
    NoteLabel.Top := RemoveDataCheckBox.Top + RemoveDataCheckBox.Height + ScaleY(10);
    NoteLabel.Width := IntroLabel.Width;
    NoteLabel.WordWrap := True;
    NoteLabel.Caption :=
      'Any evidence files or exported reports you saved outside these AppData folders will not be removed.';
    NoteLabel.AdjustHeight;

    UninstallButton := TNewButton.Create(Form);
    UninstallButton.Parent := Form;
    UninstallButton.Caption := '&Uninstall';
    UninstallButton.Top := Form.ClientHeight - ScaleY(23 + 12);
    UninstallButton.Height := ScaleY(23);
    UninstallButton.ModalResult := mrOk;
    UninstallButton.Default := True;

    CancelButton := TNewButton.Create(Form);
    CancelButton.Parent := Form;
    CancelButton.Caption := 'Cancel';
    CancelButton.Top := UninstallButton.Top;
    CancelButton.Height := ScaleY(23);
    CancelButton.ModalResult := mrCancel;
    CancelButton.Cancel := True;

    ButtonWidth := Form.CalculateButtonWidth([UninstallButton.Caption, CancelButton.Caption]);
    UninstallButton.Width := ButtonWidth;
    CancelButton.Width := ButtonWidth;
    CancelButton.Left := Form.ClientWidth - CancelButton.Width - ScaleX(12);
    UninstallButton.Left := CancelButton.Left - UninstallButton.Width - ScaleX(6);

    Form.ActiveControl := RemoveDataCheckBox;

    Result := Form.ShowModal() = mrOk;
    RemoveUserDataOnUninstall := Result and RemoveDataCheckBox.Checked;
  finally
    Form.Free();
  end;
end;

function InitializeUninstall(): Boolean;
begin
  RemoveUserDataOnUninstall := False;

  if UninstallSilent then begin
    Log('Silent uninstall detected; saved user data will be kept because no uninstall options prompt is shown.');
    Result := True;
    exit;
  end;

  Result := ShowUninstallOptionsPrompt();
end;
