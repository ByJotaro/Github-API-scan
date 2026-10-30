@echo off
setlocal
cd /d "%~dp0"

title Secret Scanner Pro - TUI
echo.
echo  Secret Scanner Pro - Operator TUI
echo  Working dir: %CD%
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] python not found in PATH
  echo Install Python 3.11+ and retry.
  pause
  exit /b 1
)

if not exist "config_local.py" (
  if exist "config_local.py.example" (
    echo [WARN] config_local.py missing.
    echo        Copy config_local.py.example -^> config_local.py and add GitHub tokens.
    echo        Path: %CD%\config_local.py
    echo.
  )
)

python main_optimized.py %*
set EXITCODE=%ERRORLEVEL%
if not %EXITCODE%==0 (
  echo.
  echo [ERROR] TUI exited with code %EXITCODE%
  pause
)
endlocal & exit /b %EXITCODE%
