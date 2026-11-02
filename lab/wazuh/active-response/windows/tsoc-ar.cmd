@echo off
rem tiny-agenticsoc active response launcher: wazuh-execd runs this; stdin/stdout pass through to PowerShell.
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0tsoc-ar.ps1"
