# Launch SecureMailScope web dashboard on Windows (PowerShell)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$PythonExe = "python"
if (Test-Path ".venv\Scripts\python.exe") {
    $PythonExe = ".venv\Scripts\python.exe"
}

Write-Host "[*] Starting SecureMailScope web dashboard at http://localhost:8000" -ForegroundColor Cyan
& $PythonExe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
