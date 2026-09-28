@echo off
rem Launch SecureMailScope web dashboard on Windows
setlocal enabledelayedexpansion

cd /d "%~dp0"

if exist .venv\Scripts\python.exe (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo [*] Starting SecureMailScope web dashboard at http://localhost:8000
"%PYTHON_EXE%" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
