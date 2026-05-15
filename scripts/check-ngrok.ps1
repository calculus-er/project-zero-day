# Quick ngrok status check for Project Zero-Day
$NgrokExe = if ($env:NGROK_EXE) { $env:NGROK_EXE } else { "C:\ngrok\ngrok.exe" }

Write-Host "=== ngrok install ==="
if (Test-Path $NgrokExe) {
    Write-Host "OK  $NgrokExe"
    & $NgrokExe version
    & $NgrokExe config check
} else {
    Write-Host "MISSING  $NgrokExe"
}

Write-Host ""
Write-Host "=== active tunnel (port 8000) ==="
try {
    $data = Invoke-RestMethod -Uri "http://127.0.0.1:4040/api/tunnels" -TimeoutSec 2
    $found = $false
    foreach ($t in $data.tunnels) {
        if ($t.config.addr -match "8000") {
            $found = $true
            Write-Host "PUBLIC URL:  $($t.public_url)"
            Write-Host "WEBHOOK URL: $($t.public_url)/webhook/github"
        }
    }
    if (-not $found) {
        Write-Host "No tunnel to port 8000. Run: .\scripts\start-ngrok.ps1"
    }
} catch {
    Write-Host "ngrok not running. Start it with: .\scripts\start-ngrok.ps1"
}
