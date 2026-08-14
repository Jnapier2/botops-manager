@echo off
REM Copyright 2026 Gateway Information Group LLC. All rights reserved.
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0" || (
    echo ERROR: The BotOps Manager project folder could not be opened.
    exit /b 2
)

title BotOps Manager
set "BOTOPS_SCRIPT=%~dp0bot_manager.py"
if not exist "%BOTOPS_SCRIPT%" (
    echo ERROR: bot_manager.py is missing beside this BAT file.
    exit /b 2
)

set "BOTOPS_RUNNER="
set "BOTOPS_PYTHON="

if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
    if not errorlevel 1 (
        set "BOTOPS_RUNNER=PYTHON"
        set "BOTOPS_PYTHON=%~dp0.venv\Scripts\python.exe"
    )
)

if not defined BOTOPS_RUNNER (
    where py.exe >nul 2>&1
    if not errorlevel 1 (
        py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
        if not errorlevel 1 set "BOTOPS_RUNNER=PYLAUNCHER"
    )
)

if not defined BOTOPS_RUNNER (
    where python.exe >nul 2>&1
    if not errorlevel 1 (
        python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
        if not errorlevel 1 (
            set "BOTOPS_RUNNER=PYTHON"
            set "BOTOPS_PYTHON=python"
        )
    )
)

if not defined BOTOPS_RUNNER (
    echo ERROR: Python 3.10 or newer was not found.
    echo Install a current Python 3 release, then reopen this launcher.
    echo No bots were started, stopped, or modified.
    exit /b 3
)

if "%BOTOPS_RUNNER%"=="PYLAUNCHER" (
    py -3 "%BOTOPS_SCRIPT%" menu
) else (
    "%BOTOPS_PYTHON%" "%BOTOPS_SCRIPT%" menu
)
exit /b %errorlevel%
