# Starts ngrok tunnel for Project Zero-Day backend (port 8000)
$NgrokExe = $env:NGROK_EXE
if (-not $NgrokExe) {
    $NgrokExe = "C:\ngrok\ngrok.exe"
}

if (-not (Test-Path $NgrokExe)) {
    Write-Host "ngrok not found at: $NgrokExe"
    Write-Host "Install from https://ngrok.com or set NGROK_EXE in your environment."
    exit 1
}

Write-Host "Using ngrok: $NgrokExe"
& $NgrokExe config check
Write-Host ""
Write-Host "Starting tunnel -> http://localhost:8000"
Write-Host "Webhook URL will be: https://YOUR-SUBDOMAIN.ngrok-free.app/webhook/github"
Write-Host "Dashboard checks http://127.0.0.1:4040/api/tunnels for the green dot."
Write-Host ""
& $NgrokExe http 8000
