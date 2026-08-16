# KeyLink Emergency Rollback & Uninstaller Script
# Removes all registry entries for the custom Credential Provider.

# Ensure script is running with Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script must be run as an Administrator. Re-launching with elevation..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

$clsid = "{5E0B49B8-0F14-4B2D-868C-A6305C0130FA}"
$clsidPath = "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid"
$providerPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"

Write-Host "=== KEYLINK EMERGENCY UNINSTALLER ===" -ForegroundColor Cyan

# 1. Remove from Credential Providers list
if (Test-Path $providerPath) {
    Write-Host "[Registry] Removing Credential Provider key..." -ForegroundColor Yellow
    Remove-Item -Path $providerPath -Recurse -Force
    Write-Host "[Registry] Credential Provider key removed." -ForegroundColor Green
} else {
    Write-Host "[Registry] Credential Provider registry key not found (already uninstalled)." -ForegroundColor White
}

# 2. Remove CLSID registration
if (Test-Path $clsidPath) {
    Write-Host "[Registry] Removing COM CLSID key..." -ForegroundColor Yellow
    Remove-Item -Path $clsidPath -Recurse -Force
    Write-Host "[Registry] COM CLSID key removed." -ForegroundColor Green
} else {
    Write-Host "[Registry] COM CLSID registry key not found." -ForegroundColor White
}

Write-Host "`n[Success] KeyLink Credential Provider has been completely uninstalled and rolled back." -ForegroundColor Green
Write-Host "You can now safely restart or lock your PC." -ForegroundColor Green
Read-Host "`nPress Enter to exit"
