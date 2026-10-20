' autostart_skill_compat.vbs - silent launcher (no popup)
' Startup folder holds ONLY this file. The ps1 must live in
' %LOCALAPPDATA%\N.E.K.O\scripts\ (absolute path, never opened by editor)
' NOTE: keep this file pure ASCII; WSH parses .vbs as ANSI, UTF-8 comments
' become mojibake and raise "Object required" popups (v0.1.24 regression).
Set sh = CreateObject("WScript.Shell")
ps1 = sh.ExpandEnvironmentStrings("%LOCALAPPDATA%\N.E.K.O\scripts\autostart_skill_compat.ps1")
sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ps1 & """", 0, False
