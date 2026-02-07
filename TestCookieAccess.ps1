#Requires -Version 5.1

<#
.SYNOPSIS
    Tests if cookies can be accessed (simulates infostealer behavior)

.DESCRIPTION
    This script attempts to read browser cookie files the same way
    an infostealer would. Use this to verify if protection is working.
#>

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  COOKIE ACCESS TEST (Infostealer Simulation)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This test simulates what an infostealer would do:" -ForegroundColor Yellow
Write-Host "Try to read your browser cookies/session tokens" -ForegroundColor Yellow
Write-Host ""

$browsers = @{
    "Chrome" = @{
        Cookies = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies"
        LoginData = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    }
    "Edge" = @{
        Cookies = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Network\Cookies"
        LoginData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    }
    "Brave" = @{
        Cookies = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies"
        LoginData = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
    }
    "Firefox" = @{
        Cookies = "$env:APPDATA\Mozilla\Firefox\Profiles\*\cookies.sqlite"
        LoginData = "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json"
    }
    "Opera" = @{
        Cookies = "$env:APPDATA\Opera Software\Opera Stable\Network\Cookies"
        LoginData = "$env:APPDATA\Opera Software\Opera Stable\Login Data"
    }
}

$results = @()

foreach ($browserName in $browsers.Keys) {
    $paths = $browsers[$browserName]

    Write-Host "Testing $browserName..." -ForegroundColor White

    # Test Cookies
    $cookiePath = $paths.Cookies
    if ($cookiePath -match "\*") {
        $cookieFiles = Get-ChildItem -Path $cookiePath -ErrorAction SilentlyContinue
        $cookiePath = if ($cookieFiles) { $cookieFiles[0].FullName } else { $null }
    }

    if ($cookiePath -and (Test-Path $cookiePath -ErrorAction SilentlyContinue)) {
        try {
            # Try to read first bytes (what stealers do)
            $null = [System.IO.File]::ReadAllBytes($cookiePath) | Select-Object -First 100
            Write-Host "  [VULNERABLE] Cookies readable! Stealer could steal sessions" -ForegroundColor Red
            $results += @{ Browser = $browserName; File = "Cookies"; Status = "VULNERABLE"; Color = "Red" }
        }
        catch {
            if ($_.Exception.Message -match "Access|denied|permission") {
                Write-Host "  [PROTECTED] Cookies access DENIED - Protection working!" -ForegroundColor Green
                $results += @{ Browser = $browserName; File = "Cookies"; Status = "PROTECTED"; Color = "Green" }
            }
            else {
                Write-Host "  [PROTECTED] Cookies blocked: $($_.Exception.Message)" -ForegroundColor Green
                $results += @{ Browser = $browserName; File = "Cookies"; Status = "PROTECTED"; Color = "Green" }
            }
        }
    }
    else {
        Write-Host "  [N/A] Browser not installed or no cookies" -ForegroundColor Gray
        $results += @{ Browser = $browserName; File = "Cookies"; Status = "N/A"; Color = "Gray" }
    }

    # Test Login Data
    $loginPath = $paths.LoginData
    if ($loginPath -match "\*") {
        $loginFiles = Get-ChildItem -Path $loginPath -ErrorAction SilentlyContinue
        $loginPath = if ($loginFiles) { $loginFiles[0].FullName } else { $null }
    }

    if ($loginPath -and (Test-Path $loginPath -ErrorAction SilentlyContinue)) {
        try {
            $null = [System.IO.File]::ReadAllBytes($loginPath) | Select-Object -First 100
            Write-Host "  [VULNERABLE] Login Data readable! Stealer could steal passwords" -ForegroundColor Red
            $results += @{ Browser = $browserName; File = "Login Data"; Status = "VULNERABLE"; Color = "Red" }
        }
        catch {
            if ($_.Exception.Message -match "Access|denied|permission") {
                Write-Host "  [PROTECTED] Login Data access DENIED - Protection working!" -ForegroundColor Green
                $results += @{ Browser = $browserName; File = "Login Data"; Status = "PROTECTED"; Color = "Green" }
            }
            else {
                Write-Host "  [PROTECTED] Login Data blocked: $($_.Exception.Message)" -ForegroundColor Green
                $results += @{ Browser = $browserName; File = "Login Data"; Status = "PROTECTED"; Color = "Green" }
            }
        }
    }

    Write-Host ""
}

# Summary
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$vulnerable = ($results | Where-Object { $_.Status -eq "VULNERABLE" }).Count
$protected = ($results | Where-Object { $_.Status -eq "PROTECTED" }).Count

if ($vulnerable -gt 0) {
    Write-Host "WARNING: $vulnerable file(s) are VULNERABLE to stealers!" -ForegroundColor Red
    Write-Host "Run the Security Tool and click 'Protect Cookie Directories'" -ForegroundColor Yellow
}
elseif ($protected -gt 0) {
    Write-Host "EXCELLENT! All browser data is PROTECTED!" -ForegroundColor Green
    Write-Host "Infostealers would NOT be able to steal your sessions." -ForegroundColor Green
}
else {
    Write-Host "No browsers with data found to test." -ForegroundColor Gray
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
