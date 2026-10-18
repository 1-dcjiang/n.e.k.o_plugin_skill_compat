@echo off
REM Autostart skill_compat plugin (silent, no window)
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0autostart_skill_compat.ps1"
exit /b %ERRORLEVEL%
