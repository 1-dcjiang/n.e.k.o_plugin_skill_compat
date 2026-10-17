@echo off
rem 自动开启 skill_compat 插件（静默，无窗口）
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0autostart_skill_compat.ps1"
