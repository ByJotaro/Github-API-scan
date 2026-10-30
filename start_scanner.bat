@echo off
setlocal
cd /d "%~dp0"

title Secret Scanner Pro - Headless
echo.
echo  Secret Scanner Pro - Headless scanner (all sources)
echo  Operator UI: start_tui.bat
echo  Working dir: %CD%
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] python not found in PATH
  pause
  exit /b 1
)

python main_optimized.py --all-sources %*
set EXITCODE=%ERRORLEVEL%
if not %EXITCODE%==0 (
  echo.
  echo [ERROR] Scanner exited with code %EXITCODE%
  pause
)
endlocal & exit /b %EXITCODE%
