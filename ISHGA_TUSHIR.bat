@echo off
title HW-DETECTOR - Hardware Fraud Detection Tool
color 0A
echo.
echo   Starting HW-Detector...
echo   (Administrator huquqi talab qilinadi)
echo.

:: Admin tekshiruvi va ko'tarish
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo   Admin huquqi yo'q, ko'tarish...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d \"%~dp0\" && powershell -NoProfile -ExecutionPolicy Bypass -File \"%~dp0HW-Detector.ps1\"' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0HW-Detector.ps1"
pause
