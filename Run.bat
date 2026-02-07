@echo off
title ShieldGuard
:: ShieldGuard - Windows Security Hardening Tool

:: Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Change to script directory
cd /d "%~dp0"

:: Set temporary execution policy and run
powershell -ExecutionPolicy Bypass -NoProfile -File ".\src\Main.ps1"

pause
