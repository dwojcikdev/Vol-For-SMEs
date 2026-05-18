Option Explicit

Dim fileSystem
Dim appDirectory
Dim pythonPath
Dim launcherPath
Dim shell

Set fileSystem = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

appDirectory = fileSystem.GetParentFolderName(WScript.ScriptFullName)
pythonPath = appDirectory & "\pythonw.exe"
launcherPath = appDirectory & "\app\launch_gui.pyw"

If Not fileSystem.FileExists(pythonPath) Then
    shell.Popup _
        "Vol For SMEs is missing its bundled Python runtime." & vbCrLf & vbCrLf & _
        "Please reinstall the application.", _
        0, _
        "Vol For SMEs", _
        16
    WScript.Quit 1
End If

shell.CurrentDirectory = appDirectory
shell.Run """" & pythonPath & """ """ & launcherPath & """", 0, False
