; Inno Setup script for Packhound (per-user install, no admin rights needed).
; The AppId is unchanged from when the app was called "Supply Chain Scanner", so this upgrades that install.
; Called by build_windows.ps1 with /DAppVersion, /DSourceDir, /DOutputDir.
#define AppName "Packhound"

[Setup]
AppId={{6F3C2B7E-1D0A-4F7B-9C55-5C2A1E0B7D11}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Packhound
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=Packhound-{#AppVersion}-setup
UsePreviousGroup=no
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#AppName}.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName}

[InstallDelete]
; leftovers of the old name
Type: files; Name: "{app}\Supply Chain Scanner.exe"
Type: filesandordirs; Name: "{userprograms}\Supply Chain Scanner"
Type: files; Name: "{userdesktop}\Supply Chain Scanner.lnk"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppName}.exe"
Name: "{userdesktop}\{#AppName}"; Filename: "{app}\{#AppName}.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\{#AppName}.exe"; Description: "Open {#AppName}"; Flags: nowait postinstall skipifsilent
