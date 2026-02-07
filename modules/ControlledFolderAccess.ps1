#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Controlled Folder Access Module

.DESCRIPTION
    Functions to manage Windows Defender Controlled Folder Access,
    which protects folders against unauthorized modifications (ransomware).
#>

function Get-ControlledFolderAccessStatus {
    <#
    .SYNOPSIS
        Checks the current status of Controlled Folder Access
    #>

    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $enabled = $preference.EnableControlledFolderAccess -eq 1

        return @{
            Success = $true
            Enabled = $enabled
            Status = if ($enabled) { "Enabled" } else { "Disabled" }
            Mode = switch ($preference.EnableControlledFolderAccess) {
                0 { "Disabled" }
                1 { "Enabled" }
                2 { "AuditMode" }
                default { "Unknown" }
            }
        }
    }
    catch {
        return @{
            Success = $false
            Enabled = $false
            Status = "Error checking status"
            Error = $_.Exception.Message
        }
    }
}

function Enable-ControlledFolderAccess {
    <#
    .SYNOPSIS
        Enables Controlled Folder Access
    #>

    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop

        return @{
            Success = $true
            Message = "Controlled Folder Access enabled successfully"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Disable-ControlledFolderAccess {
    <#
    .SYNOPSIS
        Disables Controlled Folder Access
    #>

    try {
        Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction Stop

        return @{
            Success = $true
            Message = "Controlled Folder Access disabled"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Set-ControlledFolderAccessAuditMode {
    <#
    .SYNOPSIS
        Sets CFA to audit mode (logs but does not block)
    #>

    try {
        Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction Stop

        return @{
            Success = $true
            Message = "Controlled Folder Access set to audit mode"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-ProtectedFolders {
    <#
    .SYNOPSIS
        Lists folders protected by CFA
    #>

    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $folders = $preference.ControlledFolderAccessProtectedFolders

        # Default folders always protected
        $defaultFolders = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Pictures",
            "$env:USERPROFILE\Videos",
            "$env:USERPROFILE\Music",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Favorites"
        )

        $allFolders = @()
        $allFolders += $defaultFolders | ForEach-Object { "$_ (Default)" }

        if ($folders) {
            $allFolders += $folders | ForEach-Object { "$_ (Custom)" }
        }

        return $allFolders
    }
    catch {
        return @("Error listing folders: $($_.Exception.Message)")
    }
}

function Add-ProtectedFolder {
    <#
    .SYNOPSIS
        Adds a folder to CFA protection
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if (-not (Test-Path $Path -PathType Container)) {
            return @{
                Success = $false
                Error = "Folder not found: $Path"
            }
        }

        Add-MpPreference -ControlledFolderAccessProtectedFolders $Path -ErrorAction Stop

        return @{
            Success = $true
            Message = "Folder added to protection: $Path"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Remove-ProtectedFolder {
    <#
    .SYNOPSIS
        Removes a folder from CFA protection
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        Remove-MpPreference -ControlledFolderAccessProtectedFolders $Path -ErrorAction Stop

        return @{
            Success = $true
            Message = "Folder removed from protection: $Path"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-AllowedApplications {
    <#
    .SYNOPSIS
        Lists allowed applications in CFA
    #>

    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $apps = $preference.ControlledFolderAccessAllowedApplications

        if ($apps) {
            return $apps
        }
        else {
            return @()
        }
    }
    catch {
        return @("Error listing applications: $($_.Exception.Message)")
    }
}

function Add-AllowedApplication {
    <#
    .SYNOPSIS
        Adds an application to the CFA allowed list
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if (-not (Test-Path $Path -PathType Leaf)) {
            return @{
                Success = $false
                Error = "File not found: $Path"
            }
        }

        Add-MpPreference -ControlledFolderAccessAllowedApplications $Path -ErrorAction Stop

        return @{
            Success = $true
            Message = "Application added to allowed list: $Path"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Remove-AllowedApplication {
    <#
    .SYNOPSIS
        Removes an application from the CFA allowed list
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        Remove-MpPreference -ControlledFolderAccessAllowedApplications $Path -ErrorAction Stop

        return @{
            Success = $true
            Message = "Application removed from allowed list: $Path"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-CFABlockedHistory {
    <#
    .SYNOPSIS
        Gets CFA block history
    #>
    param(
        [int]$MaxEvents = 50
    )

    try {
        # Event ID 1123 = CFA blocked an app
        # Event ID 1124 = CFA audited an app (audit mode)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'
            Id = 1123, 1124
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

        if ($events) {
            return $events | ForEach-Object {
                @{
                    Time = $_.TimeCreated
                    EventId = $_.Id
                    Type = if ($_.Id -eq 1123) { "Blocked" } else { "Audited" }
                    Message = $_.Message
                }
            }
        }
        else {
            return @()
        }
    }
    catch {
        return @()
    }
}

# Available functions:
# - Get-ControlledFolderAccessStatus
# - Enable-ControlledFolderAccess
# - Disable-ControlledFolderAccess
# - Set-ControlledFolderAccessAuditMode
# - Get-ProtectedFolders
# - Add-ProtectedFolder
# - Remove-ProtectedFolder
# - Get-AllowedApplications
# - Add-AllowedApplication
# - Remove-AllowedApplication
# - Get-CFABlockedHistory
