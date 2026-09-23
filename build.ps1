# =============================================================================
# build.ps1 — Biên dịch WinCheck (Wails + React) và chạy kiểm thử.
#
# Yêu cầu: Go 1.23+, Node.js + npm, và Wails CLI
#   go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
#
# Cách dùng:
#   .\build.ps1              # build app native ra .\build\bin\WinCheck.exe
#   .\build.ps1 -Test        # chạy test Go trước khi build
#   .\build.ps1 -Dev         # chạy chế độ phát triển (hot-reload frontend)
# =============================================================================
param(
    [switch]$Test,
    [switch]$Dev
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if ($Test) {
    Write-Host '==> Chạy kiểm thử Go...' -ForegroundColor Cyan
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Kiểm thử thất bại.' }
}

if ($Dev) {
    Write-Host '==> Chế độ phát triển (wails dev)...' -ForegroundColor Cyan
    wails dev
    return
}

Write-Host '==> Build ứng dụng (wails build)...' -ForegroundColor Cyan
wails build
if ($LASTEXITCODE -ne 0) { throw 'wails build thất bại.' }

Write-Host ''
Write-Host '✔ Hoàn tất: build\bin\WinCheck.exe (một tệp .exe duy nhất)' -ForegroundColor Green
Get-Item 'build\bin\WinCheck.exe' | Select-Object Name, Length, LastWriteTime
