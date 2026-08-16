# KeyLink Credential Provider - Deploy Script
# Run this as Administrator

$DllSrc  = "$PSScriptRoot\build\KeyLinkProvider.dll"
$DllDest = "C:\Windows\System32\KeyLinkProvider.dll"

Write-Host "[KeyLink Deploy] Copying DLL..." -ForegroundColor Cyan
Copy-Item -Force $DllSrc $DllDest
if ($?) {
    Write-Host "[KeyLink Deploy] DLL copied successfully." -ForegroundColor Green
} else {
    Write-Host "[KeyLink Deploy] ERROR: Failed to copy DLL. Are you running as Administrator?" -ForegroundColor Red
    exit 1
}

Write-Host "[KeyLink Deploy] Registering DLL..." -ForegroundColor Cyan
regsvr32 /s $DllDest
if ($LASTEXITCODE -eq 0) {
    Write-Host "[KeyLink Deploy] DLL registered successfully." -ForegroundColor Green
} else {
    Write-Host "[KeyLink Deploy] WARNING: regsvr32 returned $LASTEXITCODE (may already be registered)." -ForegroundColor Yellow
}

$info = Get-Item $DllDest
Write-Host ""
Write-Host "[KeyLink Deploy] Deployed: $($info.FullName)" -ForegroundColor Green
Write-Host "[KeyLink Deploy] Size:     $($info.Length) bytes" -ForegroundColor Green
Write-Host "[KeyLink Deploy] Modified: $($info.LastWriteTime)" -ForegroundColor Green
Write-Host ""
Write-Host "[KeyLink Deploy] Done! Lock your PC (Win+L) and test the auto-unlock." -ForegroundColor Cyan
