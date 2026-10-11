$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host 'Starting QuantumTrace...'

# Stop any stale server already bound to port 8000
$pids = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique

if ($pids) {
    foreach ($procId in $pids) {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
}

$python = Join-Path $root '.venv\Scripts\python.exe'
$server = Join-Path $root 'server.py'

if (-not (Test-Path $python)) {
    throw "Python virtual environment not found at: $python"
}

if (-not (Test-Path $server)) {
    throw "server.py not found at: $server"
}

# Start the backend in a separate process
$proc = Start-Process -FilePath $python -ArgumentList $server -WorkingDirectory $root -PassThru
Start-Sleep -Seconds 2

# Open the browser to the app
Start-Process 'http://localhost:8000/Script'

Write-Host "QuantumTrace is running."
Write-Host "Open: http://localhost:8000/Script"
Write-Host "Server PID: $($proc.Id)"
Write-Host "To stop it: Stop-Process -Id $($proc.Id)"
