#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Browser Protection Module

.DESCRIPTION
    Functions to protect browser cookies and session tokens
    against theft by infostealers/malware.

.NOTES
    This module was created after a real experience with an infostealer attack
    that stole browser session tokens, allowing access to accounts
    without needing password or 2FA.

    Browser data directories:
    - Chrome: %LOCALAPPDATA%\Google\Chrome\User Data
    - Edge: %LOCALAPPDATA%\Microsoft\Edge\User Data
    - Firefox: %APPDATA%\Mozilla\Firefox\Profiles
    - Brave: %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data
    - Opera: %APPDATA%\Opera Software\Opera Stable
#>

# Browser paths definition
$Script:BrowserPaths = @{
    Chrome = @{
        Name = "Google Chrome"
        DataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        CookiesPath = "Default\Network\Cookies"
        LoginDataPath = "Default\Login Data"
        LocalStatePath = "Local State"
        ProcessName = "chrome"
    }

    Edge = @{
        Name = "Microsoft Edge"
        DataPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        CookiesPath = "Default\Network\Cookies"
        LoginDataPath = "Default\Login Data"
        LocalStatePath = "Local State"
        ProcessName = "msedge"
    }

    Firefox = @{
        Name = "Mozilla Firefox"
        DataPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        CookiesPath = "cookies.sqlite"
        LoginDataPath = "logins.json"
        KeyPath = "key4.db"
        ProcessName = "firefox"
    }

    Brave = @{
        Name = "Brave Browser"
        DataPath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        CookiesPath = "Default\Network\Cookies"
        LoginDataPath = "Default\Login Data"
        LocalStatePath = "Local State"
        ProcessName = "brave"
    }

    Opera = @{
        Name = "Opera"
        DataPath = "$env:APPDATA\Opera Software\Opera Stable"
        CookiesPath = "Network\Cookies"
        LoginDataPath = "Login Data"
        LocalStatePath = "Local State"
        ProcessName = "opera"
    }

    OperaGX = @{
        Name = "Opera GX"
        DataPath = "$env:APPDATA\Opera Software\Opera GX Stable"
        CookiesPath = "Network\Cookies"
        LoginDataPath = "Login Data"
        LocalStatePath = "Local State"
        ProcessName = "opera"
    }
}

function Get-InstalledBrowsers {
    <#
    .SYNOPSIS
        Detects installed browsers on the system
    #>

    $installed = @{}

    foreach ($browserName in $Script:BrowserPaths.Keys) {
        $browser = $Script:BrowserPaths[$browserName]
        $installed[$browserName] = Test-Path $browser.DataPath
    }

    return $installed
}

function Get-BrowserDataPath {
    <#
    .SYNOPSIS
        Returns the data path for a browser
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser
    )

    if ($Script:BrowserPaths.ContainsKey($Browser)) {
        return $Script:BrowserPaths[$Browser].DataPath
    }
    return $null
}

function Stop-Browser {
    <#
    .SYNOPSIS
        Closes a specific browser
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser
    )

    if (-not $Script:BrowserPaths.ContainsKey($Browser)) {
        return @{
            Success = $false
            Error = "Unknown browser: $Browser"
        }
    }

    $processName = $Script:BrowserPaths[$Browser].ProcessName

    try {
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($processes) {
            $processes | Stop-Process -Force -ErrorAction Stop
            Start-Sleep -Seconds 2  # Wait for complete closure
        }

        return @{
            Success = $true
            Message = "Browser closed: $Browser"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Protect-BrowserCookies {
    <#
    .SYNOPSIS
        Protects browser cookies/data using ACLs

    .DESCRIPTION
        Applies restrictive permissions to the browser data directory,
        allowing only access from the browser itself and the current user.
        This makes it harder (but not impossible) for malware to steal data.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser
    )

    if (-not $Script:BrowserPaths.ContainsKey($Browser)) {
        return @{
            Success = $false
            Error = "Unknown browser: $Browser"
        }
    }

    $browserInfo = $Script:BrowserPaths[$Browser]
    $dataPath = $browserInfo.DataPath

    if (-not (Test-Path $dataPath)) {
        return @{
            Success = $false
            Error = "Browser directory not found: $dataPath"
        }
    }

    try {
        # First, close the browser
        Stop-Browser -Browser $Browser | Out-Null

        # Get current ACLs
        $acl = Get-Acl $dataPath

        # Remove inheritance and clear existing ACLs
        $acl.SetAccessRuleProtection($true, $false)

        # Add permission only for current user
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($userRule)

        # Add SYSTEM (required for Windows operation)
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($systemRule)

        # Apply ACLs
        Set-Acl -Path $dataPath -AclObject $acl -ErrorAction Stop

        return @{
            Success = $true
            Message = "Protection applied to $Browser"
            Path = $dataPath
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Restore-BrowserPermissions {
    <#
    .SYNOPSIS
        Restores default permissions to browser directory
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser
    )

    if (-not $Script:BrowserPaths.ContainsKey($Browser)) {
        return @{
            Success = $false
            Error = "Unknown browser: $Browser"
        }
    }

    $browserInfo = $Script:BrowserPaths[$Browser]
    $dataPath = $browserInfo.DataPath

    if (-not (Test-Path $dataPath)) {
        return @{
            Success = $false
            Error = "Browser directory not found: $dataPath"
        }
    }

    try {
        # Restore permission inheritance
        $acl = Get-Acl $dataPath
        $acl.SetAccessRuleProtection($false, $true)
        Set-Acl -Path $dataPath -AclObject $acl -ErrorAction Stop

        return @{
            Success = $true
            Message = "Permissions restored for $Browser"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Clear-BrowserSessions {
    <#
    .SYNOPSIS
        Clears cookies and sessions from a browser

    .DESCRIPTION
        Removes cookie files, effectively logging the user out
        of all accounts. Useful after a compromise.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser
    )

    if (-not $Script:BrowserPaths.ContainsKey($Browser)) {
        return @{
            Success = $false
            Error = "Unknown browser: $Browser"
        }
    }

    $browserInfo = $Script:BrowserPaths[$Browser]
    $dataPath = $browserInfo.DataPath

    # Close browser first
    Stop-Browser -Browser $Browser | Out-Null

    try {
        $deletedFiles = @()

        if ($Browser -eq "Firefox") {
            # Firefox uses different structure
            $profiles = Get-ChildItem -Path $dataPath -Directory -ErrorAction SilentlyContinue

            foreach ($profile in $profiles) {
                $cookiesFile = Join-Path $profile.FullName $browserInfo.CookiesPath
                if (Test-Path $cookiesFile) {
                    Remove-Item $cookiesFile -Force -ErrorAction Stop
                    $deletedFiles += $cookiesFile
                }
            }
        }
        else {
            # Chromium-based browsers
            # Search in all profiles (Default, Profile 1, Profile 2, etc.)
            $profiles = Get-ChildItem -Path $dataPath -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match "^(Default|Profile \d+)$" }

            foreach ($profile in $profiles) {
                # Cookies
                $cookiesFile = Join-Path $profile.FullName "Network\Cookies"
                if (Test-Path $cookiesFile) {
                    Remove-Item $cookiesFile -Force -ErrorAction Stop
                    $deletedFiles += $cookiesFile
                }

                # Session Storage
                $sessionPath = Join-Path $profile.FullName "Session Storage"
                if (Test-Path $sessionPath) {
                    Remove-Item $sessionPath -Recurse -Force -ErrorAction Stop
                    $deletedFiles += $sessionPath
                }
            }
        }

        return @{
            Success = $true
            Message = "Sessions cleared for $Browser"
            DeletedFiles = $deletedFiles
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Backup-BrowserData {
    <#
    .SYNOPSIS
        Backs up browser data
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser,

        [string]$BackupPath = "$env:USERPROFILE\Desktop\BrowserBackup"
    )

    if (-not $Script:BrowserPaths.ContainsKey($Browser)) {
        return @{
            Success = $false
            Error = "Unknown browser: $Browser"
        }
    }

    $browserInfo = $Script:BrowserPaths[$Browser]
    $dataPath = $browserInfo.DataPath

    if (-not (Test-Path $dataPath)) {
        return @{
            Success = $false
            Error = "Browser directory not found"
        }
    }

    # Close browser
    Stop-Browser -Browser $Browser | Out-Null

    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFolder = Join-Path $BackupPath "${Browser}_$timestamp"

        # Create backup directory
        New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null

        # Copy data
        Copy-Item -Path "$dataPath\*" -Destination $backupFolder -Recurse -Force -ErrorAction Stop

        return @{
            Success = $true
            Message = "Backup created for $Browser"
            BackupPath = $backupFolder
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Enable-CookieAccessMonitoring {
    <#
    .SYNOPSIS
        Enables access auditing for cookie files

    .DESCRIPTION
        Configures Windows auditing to log access
        to browser cookie files.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser
    )

    if (-not $Script:BrowserPaths.ContainsKey($Browser)) {
        return @{
            Success = $false
            Error = "Unknown browser: $Browser"
        }
    }

    $browserInfo = $Script:BrowserPaths[$Browser]
    $dataPath = $browserInfo.DataPath

    try {
        # Enable object auditing
        auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null

        # Configure auditing on directory
        $acl = Get-Acl $dataPath

        # Add audit rule
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            "ReadData",
            "ContainerInherit,ObjectInherit",
            "None",
            "Success,Failure"
        )
        $acl.AddAuditRule($auditRule)

        Set-Acl -Path $dataPath -AclObject $acl -ErrorAction Stop

        return @{
            Success = $true
            Message = "Access monitoring enabled for $Browser"
            Note = "Events will be logged in Event Viewer > Security"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-SensitiveBrowserFiles {
    <#
    .SYNOPSIS
        Lists sensitive browser files that are targeted by stealers
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser
    )

    if (-not $Script:BrowserPaths.ContainsKey($Browser)) {
        return @{
            Success = $false
            Error = "Unknown browser: $Browser"
        }
    }

    $browserInfo = $Script:BrowserPaths[$Browser]
    $dataPath = $browserInfo.DataPath

    $sensitiveFiles = @()

    if ($Browser -eq "Firefox") {
        $profiles = Get-ChildItem -Path $dataPath -Directory -ErrorAction SilentlyContinue

        foreach ($profile in $profiles) {
            $files = @(
                @{ Name = "cookies.sqlite"; Type = "Cookies/Sessions"; Risk = "High" }
                @{ Name = "logins.json"; Type = "Passwords (encrypted)"; Risk = "Critical" }
                @{ Name = "key4.db"; Type = "Encryption key"; Risk = "Critical" }
                @{ Name = "places.sqlite"; Type = "History/Bookmarks"; Risk = "Medium" }
                @{ Name = "formhistory.sqlite"; Type = "Form data"; Risk = "High" }
            )

            foreach ($file in $files) {
                $path = Join-Path $profile.FullName $file.Name
                if (Test-Path $path) {
                    $sensitiveFiles += @{
                        Browser = $Browser
                        Profile = $profile.Name
                        File = $file.Name
                        Path = $path
                        Type = $file.Type
                        Risk = $file.Risk
                        Size = (Get-Item $path).Length
                    }
                }
            }
        }
    }
    else {
        # Chromium browsers
        $profiles = Get-ChildItem -Path $dataPath -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match "^(Default|Profile \d+)$" }

        foreach ($profile in $profiles) {
            $files = @(
                @{ Path = "Network\Cookies"; Type = "Cookies/Sessions"; Risk = "High" }
                @{ Path = "Login Data"; Type = "Passwords (encrypted)"; Risk = "Critical" }
                @{ Path = "Web Data"; Type = "Credit cards/Forms"; Risk = "Critical" }
                @{ Path = "History"; Type = "History"; Risk = "Medium" }
                @{ Path = "Bookmarks"; Type = "Bookmarks"; Risk = "Low" }
            )

            foreach ($file in $files) {
                $path = Join-Path $profile.FullName $file.Path
                if (Test-Path $path) {
                    $sensitiveFiles += @{
                        Browser = $Browser
                        Profile = $profile.Name
                        File = Split-Path $file.Path -Leaf
                        Path = $path
                        Type = $file.Type
                        Risk = $file.Risk
                        Size = (Get-Item $path).Length
                    }
                }
            }
        }

        # Local State contains encryption key
        $localStatePath = Join-Path $dataPath $browserInfo.LocalStatePath
        if (Test-Path $localStatePath) {
            $sensitiveFiles += @{
                Browser = $Browser
                Profile = "Global"
                File = "Local State"
                Path = $localStatePath
                Type = "Encryption key (encrypted_key)"
                Risk = "Critical"
                Size = (Get-Item $localStatePath).Length
            }
        }
    }

    return $sensitiveFiles
}

function Test-BrowserCompromise {
    <#
    .SYNOPSIS
        Checks for signs of browser compromise

    .DESCRIPTION
        Looks for indicators that browser data
        may have been accessed by malware.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Browser
    )

    $indicators = @()

    if (-not $Script:BrowserPaths.ContainsKey($Browser)) {
        return @{
            Success = $false
            Error = "Unknown browser: $Browser"
        }
    }

    $browserInfo = $Script:BrowserPaths[$Browser]
    $dataPath = $browserInfo.DataPath

    # Check recent access to Local State (contains encryption key)
    if ($Browser -ne "Firefox") {
        $localStatePath = Join-Path $dataPath $browserInfo.LocalStatePath
        if (Test-Path $localStatePath) {
            $file = Get-Item $localStatePath
            $lastAccess = $file.LastAccessTime
            $lastWrite = $file.LastWriteTime

            # If accessed in last 10 minutes without browser running
            $recentAccess = (Get-Date) - $lastAccess
            if ($recentAccess.TotalMinutes -lt 10) {
                $browserRunning = Get-Process -Name $browserInfo.ProcessName -ErrorAction SilentlyContinue
                if (-not $browserRunning) {
                    $indicators += @{
                        Type = "SuspiciousAccess"
                        File = $localStatePath
                        Message = "Local State was accessed recently without browser running"
                        Time = $lastAccess
                        Severity = "High"
                    }
                }
            }
        }
    }

    # Check for suspicious processes that may be stealers
    $suspiciousProcesses = @(
        "stealer", "lumma", "redline", "raccoon", "vidar",
        "stealc", "aurora", "mars", "meta", "rhadamanthys"
    )

    foreach ($proc in $suspiciousProcesses) {
        $found = Get-Process -Name "*$proc*" -ErrorAction SilentlyContinue
        if ($found) {
            $indicators += @{
                Type = "SuspiciousProcess"
                ProcessName = $found.Name
                Message = "Process with suspicious name found"
                Severity = "Critical"
            }
        }
    }

    return @{
        Success = $true
        Browser = $Browser
        Indicators = $indicators
        IsCompromised = ($indicators | Where-Object { $_.Severity -eq "Critical" }).Count -gt 0
        IndicatorCount = $indicators.Count
    }
}

# Available functions:
# - Get-InstalledBrowsers
# - Get-BrowserDataPath
# - Stop-Browser
# - Protect-BrowserCookies
# - Restore-BrowserPermissions
# - Clear-BrowserSessions
# - Backup-BrowserData
# - Enable-CookieAccessMonitoring
# - Get-SensitiveBrowserFiles
# - Test-BrowserCompromise
