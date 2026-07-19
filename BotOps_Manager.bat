@echo off
REM Copyright 2026 Gateway Information Group LLC. All rights reserved.
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
title BotOps Manager v1.13.0

set "BOTOPS_SCRIPT=%~dp0bot_manager.py"
if not exist "%BOTOPS_SCRIPT%" (
    echo ERROR: bot_manager.py is missing beside this BAT file.
    pause
    exit /b 2
)

set "BOTOPS_PY="
where py.exe >nul 2>&1
if not errorlevel 1 (
    py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
    if not errorlevel 1 set "BOTOPS_PY=PYLAUNCHER"
)
if not defined BOTOPS_PY (
    where python.exe >nul 2>&1
    if not errorlevel 1 (
        python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
        if not errorlevel 1 set "BOTOPS_PY=PYTHON"
    )
)
if not defined BOTOPS_PY (
    echo.
    echo Python 3.10 or newer was not found.
    echo Install a current Python 3 release, then reopen this file.
    echo No bots were started, stopped, or modified.
    pause
    exit /b 3
)

:menu
cls
echo ================================================================
echo                     BOTOPS MANAGER v1.13.0
echo ================================================================
if defined BOTOPS_BOTS_ROOT (
    set "BOTOPS_DISPLAY_ROOT=%BOTOPS_BOTS_ROOT%"
) else (
    set "BOTOPS_DISPLAY_ROOT=C:\Bots"
)
echo Root monitored: %BOTOPS_DISPLAY_ROOT%
echo Force termination: disabled in the public portfolio edition
echo Retarget root: set BOTOPS_BOTS_ROOT before launch, or edit state\bot_manager_config.json
echo.
echo   1  Dashboard / current status
echo   2  Full interactive bot manager
echo   3  Rescan + launcher safety audit
echo   4  Live dashboard ^(Ctrl+C returns here^)
echo   5  Preflight / self-test
echo   6  Export safe support ZIP
echo   7  Open monitored root
echo   8  Open manager logs
echo   9  Show config, state, metrics, and export paths
echo   0  Exit
echo.
choice /c 1234567890 /n /m "Select [0-9]: "
set "BOTOPS_CHOICE=%errorlevel%"

if "%BOTOPS_CHOICE%"=="10" goto :done
if "%BOTOPS_CHOICE%"=="9"  call :run config
if "%BOTOPS_CHOICE%"=="8"  call :run open-logs
if "%BOTOPS_CHOICE%"=="7"  call :run open-root
if "%BOTOPS_CHOICE%"=="6"  call :run export
if "%BOTOPS_CHOICE%"=="5"  call :run selftest
if "%BOTOPS_CHOICE%"=="4"  call :run watch
if "%BOTOPS_CHOICE%"=="3"  call :run audit
if "%BOTOPS_CHOICE%"=="2"  call :run menu
if "%BOTOPS_CHOICE%"=="1"  call :run status

if not "%BOTOPS_CHOICE%"=="2" (
    echo.
    pause
)
goto :menu

:run
if "%BOTOPS_PY%"=="PYLAUNCHER" (
    py -3 "%BOTOPS_SCRIPT%" %*
) else (
    python "%BOTOPS_SCRIPT%" %*
)
exit /b %errorlevel%

:done
endlocal
exit /b 0
