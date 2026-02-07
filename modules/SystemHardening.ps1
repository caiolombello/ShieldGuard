#Requires -RunAsAdministrator

<#
.SYNOPSIS
    System Hardening Module

.DESCRIPTION
    Functions to harden Windows system settings that work
    regardless of which antivirus is installed.

.NOTES
    These protections use native Windows features and do not
    depend on Windows Defender.
#>

# ============================================================================
# STARTUP PROGRAMS SCANNER
# ============================================================================

function Get-StartupPrograms {
    <#
    .SYNOPSIS
        Lists all startup programs from multiple locations
    #>

    $startupItems = @()

    # Registry Run keys (Current User)
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $startupItems += @{
                    Name = $_.Name
                    Command = $_.Value
                    Location = $path
                    Type = "Registry"
                }
            }
        }
    }

    # Startup folders
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem -Path $folder -ErrorAction SilentlyContinue | ForEach-Object {
                $startupItems += @{
                    Name = $_.Name
                    Command = $_.FullName
                    Location = $folder
                    Type = "Folder"
                }
            }
        }
    }

    return @{
        Success = $true
        Items = $startupItems
        Count = $startupItems.Count
    }
}

function Find-SuspiciousStartupItems {
    <#
    .SYNOPSIS
        Identifies potentially suspicious startup entries
    #>

    $startupData = Get-StartupPrograms
    $suspicious = @()

    # Suspicious patterns
    $suspiciousPatterns = @(
        "powershell.*-enc",
        "powershell.*-e ",
        "powershell.*hidden",
        "cmd.*/c.*&",
        "wscript",
        "cscript",
        "mshta",
        "regsvr32",
        "rundll32.*javascript",
        "\\temp\\",
        "\\tmp\\",
        "%temp%",
        "%appdata%.*\.exe",
        "\\downloads\\.*\.exe"
    )

    foreach ($item in $startupData.Items) {
        $isSuspicious = $false
        $reasons = @()

        foreach ($pattern in $suspiciousPatterns) {
            if ($item.Command -match $pattern) {
                $isSuspicious = $true
                $reasons += "Matches suspicious pattern: $pattern"
            }
        }

        # Check if executable exists
        $exePath = $item.Command -replace '"', '' -replace ' .*$', ''
        if ($exePath -match "\.exe$" -and -not (Test-Path $exePath -ErrorAction SilentlyContinue)) {
            $isSuspicious = $true
            $reasons += "Executable not found: $exePath"
        }

        if ($isSuspicious) {
            $suspicious += @{
                Name = $item.Name
                Command = $item.Command
                Location = $item.Location
                Reasons = $reasons
            }
        }
    }

    return @{
        Success = $true
        SuspiciousItems = $suspicious
        Count = $suspicious.Count
    }
}

function Remove-StartupItem {
    <#
    .SYNOPSIS
        Removes a startup item
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Location
    )

    try {
        if ($Location -match "^HK") {
            # Registry entry
            Remove-ItemProperty -Path $Location -Name $Name -ErrorAction Stop
        }
        else {
            # File in startup folder
            $filePath = Join-Path $Location $Name
            if (Test-Path $filePath) {
                Remove-Item $filePath -Force -ErrorAction Stop
            }
        }

        return @{
            Success = $true
            Message = "Startup item removed: $Name"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# ============================================================================
# SCHEDULED TASKS SCANNER
# ============================================================================

function Get-SuspiciousScheduledTasks {
    <#
    .SYNOPSIS
        Scans scheduled tasks for suspicious entries
    #>

    $suspicious = @()

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.State -ne "Disabled"
        }

        $suspiciousPatterns = @(
            "powershell.*-enc",
            "powershell.*-e ",
            "powershell.*hidden",
            "cmd.*/c",
            "wscript",
            "cscript",
            "mshta",
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\.*\.exe"
        )

        foreach ($task in $tasks) {
            try {
                $actions = $task.Actions
                foreach ($action in $actions) {
                    $execute = $action.Execute
                    $arguments = $action.Arguments

                    $fullCommand = "$execute $arguments"

                    foreach ($pattern in $suspiciousPatterns) {
                        if ($fullCommand -match $pattern) {
                            $suspicious += @{
                                TaskName = $task.TaskName
                                TaskPath = $task.TaskPath
                                Command = $fullCommand
                                State = $task.State.ToString()
                                Pattern = $pattern
                            }
                            break
                        }
                    }
                }
            }
            catch {
                # Skip tasks we can't read
            }
        }

        return @{
            Success = $true
            SuspiciousTasks = $suspicious
            Count = $suspicious.Count
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Disable-ScheduledTask-Safe {
    <#
    .SYNOPSIS
        Safely disables a scheduled task
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskName,

        [Parameter(Mandatory = $true)]
        [string]$TaskPath
    )

    try {
        Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop

        return @{
            Success = $true
            Message = "Task disabled: $TaskPath$TaskName"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# ============================================================================
# USB AUTORUN PROTECTION
# ============================================================================

function Get-USBAutorunStatus {
    <#
    .SYNOPSIS
        Checks if USB autorun is disabled
    #>

    try {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        $value = Get-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue

        # 255 = All drives disabled, 128 = Unknown drives, 4 = Removable drives
        $disabled = $value.NoDriveTypeAutoRun -ge 128

        return @{
            Success = $true
            AutorunDisabled = $disabled
            CurrentValue = $value.NoDriveTypeAutoRun
            Status = if ($disabled) { "Protected" } else { "Vulnerable" }
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Disable-USBAutorun {
    <#
    .SYNOPSIS
        Disables autorun for USB and removable drives
    #>

    try {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }

        # 255 = Disable autorun on all drive types
        Set-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force

        # Also disable AutoPlay
        Set-ItemProperty -Path $path -Name "NoAutorun" -Value 1 -Type DWord -Force

        return @{
            Success = $true
            Message = "USB autorun disabled for all drive types"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Enable-USBAutorun {
    <#
    .SYNOPSIS
        Re-enables autorun (not recommended)
    #>

    try {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

        Remove-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $path -Name "NoAutorun" -ErrorAction SilentlyContinue

        return @{
            Success = $true
            Message = "USB autorun re-enabled (not recommended)"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# ============================================================================
# POWERSHELL HARDENING
# ============================================================================

function Get-PowerShellSecurityStatus {
    <#
    .SYNOPSIS
        Checks PowerShell security settings
    #>

    $status = @{}

    # Execution Policy
    $status.ExecutionPolicy = Get-ExecutionPolicy -Scope LocalMachine

    # Script Block Logging
    $sbLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $sbLog = Get-ItemProperty -Path $sbLogPath -ErrorAction SilentlyContinue
    $status.ScriptBlockLogging = if ($sbLog.EnableScriptBlockLogging -eq 1) { $true } else { $false }

    # Module Logging
    $modLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $modLog = Get-ItemProperty -Path $modLogPath -ErrorAction SilentlyContinue
    $status.ModuleLogging = if ($modLog.EnableModuleLogging -eq 1) { $true } else { $false }

    # Transcription
    $transPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $trans = Get-ItemProperty -Path $transPath -ErrorAction SilentlyContinue
    $status.Transcription = if ($trans.EnableTranscripting -eq 1) { $true } else { $false }

    # Constrained Language Mode check
    $status.LanguageMode = $ExecutionContext.SessionState.LanguageMode.ToString()

    return @{
        Success = $true
        Status = $status
    }
}

function Enable-PowerShellLogging {
    <#
    .SYNOPSIS
        Enables PowerShell script block logging
    #>

    try {
        # Script Block Logging
        $sbLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $sbLogPath)) {
            New-Item -Path $sbLogPath -Force | Out-Null
        }
        Set-ItemProperty -Path $sbLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

        # Module Logging
        $modLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (-not (Test-Path $modLogPath)) {
            New-Item -Path $modLogPath -Force | Out-Null
        }
        Set-ItemProperty -Path $modLogPath -Name "EnableModuleLogging" -Value 1 -Type DWord

        # Log all modules
        $modNamesPath = "$modLogPath\ModuleNames"
        if (-not (Test-Path $modNamesPath)) {
            New-Item -Path $modNamesPath -Force | Out-Null
        }
        Set-ItemProperty -Path $modNamesPath -Name "*" -Value "*" -Type String

        return @{
            Success = $true
            Message = "PowerShell logging enabled. Events will be logged to Event Viewer."
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-PowerShellExecutionPolicy {
    <#
    .SYNOPSIS
        Sets PowerShell execution policy
    #>
    param(
        [ValidateSet("Restricted", "AllSigned", "RemoteSigned", "Unrestricted")]
        [string]$Policy = "RemoteSigned"
    )

    try {
        Set-ExecutionPolicy -ExecutionPolicy $Policy -Scope LocalMachine -Force

        return @{
            Success = $true
            Message = "Execution policy set to: $Policy"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# ============================================================================
# HOSTS FILE PROTECTION
# ============================================================================

function Get-HostsFileStatus {
    <#
    .SYNOPSIS
        Checks hosts file for suspicious entries
    #>

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $suspicious = @()

    try {
        $content = Get-Content $hostsPath -ErrorAction Stop

        # Known malicious redirects patterns
        $maliciousPatterns = @(
            "google\.com",
            "facebook\.com",
            "microsoft\.com",
            "windowsupdate",
            "kaspersky",
            "avast",
            "norton",
            "mcafee",
            "malwarebytes"
        )

        $lineNum = 0
        foreach ($line in $content) {
            $lineNum++
            # Skip comments and empty lines
            if ($line -match "^\s*#" -or $line -match "^\s*$") { continue }

            foreach ($pattern in $maliciousPatterns) {
                if ($line -match $pattern -and $line -notmatch "^\s*#") {
                    $suspicious += @{
                        Line = $lineNum
                        Content = $line
                        Pattern = $pattern
                    }
                }
            }
        }

        # Check if file is writable (should be protected)
        $acl = Get-Acl $hostsPath
        $isProtected = $acl.AreAccessRulesProtected

        return @{
            Success = $true
            Path = $hostsPath
            SuspiciousEntries = $suspicious
            SuspiciousCount = $suspicious.Count
            IsProtected = $isProtected
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Protect-HostsFile {
    <#
    .SYNOPSIS
        Sets restrictive permissions on the hosts file
    #>

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"

    try {
        # Take ownership first using takeown and icacls (more reliable than Set-Acl)
        $takeown = Start-Process -FilePath "takeown" -ArgumentList "/f `"$hostsPath`"" -Wait -PassThru -WindowStyle Hidden

        # Reset permissions using icacls
        $icacls1 = Start-Process -FilePath "icacls" -ArgumentList "`"$hostsPath`" /reset" -Wait -PassThru -WindowStyle Hidden

        # Set restrictive permissions: SYSTEM and Administrators full, Users read only
        $icacls2 = Start-Process -FilePath "icacls" -ArgumentList "`"$hostsPath`" /inheritance:r" -Wait -PassThru -WindowStyle Hidden
        $icacls3 = Start-Process -FilePath "icacls" -ArgumentList "`"$hostsPath`" /grant:r `"NT AUTHORITY\SYSTEM:(F)`"" -Wait -PassThru -WindowStyle Hidden
        $icacls4 = Start-Process -FilePath "icacls" -ArgumentList "`"$hostsPath`" /grant:r `"BUILTIN\Administrators:(F)`"" -Wait -PassThru -WindowStyle Hidden
        $icacls5 = Start-Process -FilePath "icacls" -ArgumentList "`"$hostsPath`" /grant:r `"BUILTIN\Users:(R)`"" -Wait -PassThru -WindowStyle Hidden

        # Set file as read-only as extra protection
        Set-ItemProperty -Path $hostsPath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue

        return @{
            Success = $true
            Message = "Hosts file protected with restrictive permissions"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# ============================================================================
# WINDOWS FEATURES HARDENING
# ============================================================================

function Get-RemoteDesktopStatus {
    <#
    .SYNOPSIS
        Checks Remote Desktop status
    #>

    try {
        $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        $rdp = Get-ItemProperty -Path $rdpPath -ErrorAction SilentlyContinue

        $enabled = $rdp.fDenyTSConnections -eq 0

        return @{
            Success = $true
            Enabled = $enabled
            Status = if ($enabled) { "Enabled (potential risk)" } else { "Disabled (secure)" }
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Disable-RemoteDesktop {
    <#
    .SYNOPSIS
        Disables Remote Desktop
    #>

    try {
        $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        Set-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -Value 1 -Type DWord

        # Disable through firewall too
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

        return @{
            Success = $true
            Message = "Remote Desktop disabled"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-SMBv1Status {
    <#
    .SYNOPSIS
        Checks if SMBv1 is enabled (security risk)
    #>

    try {
        $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue

        return @{
            Success = $true
            Enabled = $smb1.State -eq "Enabled"
            Status = if ($smb1.State -eq "Enabled") { "Enabled (VULNERABLE!)" } else { "Disabled (secure)" }
            Recommendation = "SMBv1 should be disabled - it was exploited by WannaCry ransomware"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Disable-SMBv1 {
    <#
    .SYNOPSIS
        Disables SMBv1 protocol
    #>

    try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop

        return @{
            Success = $true
            Message = "SMBv1 disabled. A restart may be required."
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Available functions:
# Startup:
# - Get-StartupPrograms
# - Find-SuspiciousStartupItems
# - Remove-StartupItem
#
# Scheduled Tasks:
# - Get-SuspiciousScheduledTasks
# - Disable-ScheduledTask-Safe
#
# USB:
# - Get-USBAutorunStatus
# - Disable-USBAutorun
# - Enable-USBAutorun
#
# PowerShell:
# - Get-PowerShellSecurityStatus
# - Enable-PowerShellLogging
# - Set-PowerShellExecutionPolicy
#
# Hosts File:
# - Get-HostsFileStatus
# - Protect-HostsFile
#
# Windows Features:
# - Get-RemoteDesktopStatus
# - Disable-RemoteDesktop
# - Get-SMBv1Status
# - Disable-SMBv1
