@echo off
title mhr-cfw Proxy
cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not added to PATH.
    pause
    exit /b 1
)

if not exist "venv\" (
    echo [*] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    call venv\Scripts\activate.bat
    echo [*] Installing dependencies...
    if exist "requirements.txt" ( pip install -r requirements.txt ) else ( pip install rich )
) else (
    call venv\Scripts\activate.bat
)

echo [*] Starting mhr-cfw (logs shown in console and saved to mhr-cfw.log)
python main.py 2>&1 | powershell -Command "$input | Tee-Object -FilePath mhr-cfw.log"

echo.
echo [*] mhr-cfw has stopped.
pause