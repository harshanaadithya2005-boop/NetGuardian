@echo off
echo ============================================================
echo   Starting NetGuardian Security System...
echo ============================================================
cd /d "%~dp0"

IF EXIST ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" run.py
) ELSE (
    python run.py
)
pause
