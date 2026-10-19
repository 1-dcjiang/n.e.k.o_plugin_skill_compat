' autostart_skill_compat.vbs — 静默启动器（无窗口、无弹窗）
' 部署：启动文件夹只放本文件；autostart_skill_compat.ps1 放
' %LOCALAPPDATA%\N.E.K.O\scripts\（绝对路径引用，ps1 不会出现在启动文件夹被打开）
Set sh = CreateObject("WScript.Shell")
ps1 = sh.ExpandEnvironmentStrings("%LOCALAPPDATA%\N.E.K.O\scripts\autostart_skill_compat.ps1")
sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ps1 & """", 0, False
