#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Attack Surface Reduction (ASR) Rules Module

.DESCRIPTION
    Functions to manage Windows Defender ASR rules,
    which block common malicious behaviors used by malware.

.NOTES
    ASR rule GUIDs documented by Microsoft:
    https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
#>

# ASR Rules definition with their GUIDs
$Script:ASRRules = @{
    # Block credential stealing from Windows local security authority subsystem (lsass.exe)
    CredentialStealing = @{
        GUID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
        Name = "Block credential stealing from LSASS"
        Description = "Blocks attempts to steal Windows credentials (LSASS)"
        Impact = "Low - Rarely affects normal use"
    }

    # Block Office from creating child processes
    OfficeChildProcess = @{
        GUID = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
        Name = "Block Office applications from creating child processes"
        Description = "Prevents Office documents from executing malware"
        Impact = "Medium - May affect legitimate macros"
    }

    # Block Office from creating executable content
    OfficeExecutable = @{
        GUID = "3b576869-a4ec-4529-8536-b80a7769e899"
        Name = "Block Office applications from creating executable content"
        Description = "Prevents Office from creating/saving executable files"
        Impact = "Low - Rarely needed in normal use"
    }

    # Block execution of potentially obfuscated scripts
    ScriptObfuscation = @{
        GUID = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
        Name = "Block execution of potentially obfuscated scripts"
        Description = "Blocks obfuscated PowerShell/JS/VBS scripts"
        Impact = "Medium - May block legitimate scripts"
    }

    # Block untrusted processes from USB
    UntrustedUSB = @{
        GUID = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
        Name = "Block untrusted and unsigned processes from USB"
        Description = "Blocks unsigned executables from USB devices"
        Impact = "Medium - Affects some USB installers"
    }

    # Block executable content from email and webmail clients
    ExecutableEmail = @{
        GUID = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
        Name = "Block executable content from email client and webmail"
        Description = "Blocks execution of email attachments"
        Impact = "Low - Good protection without significant impact"
    }

    # Block Adobe Reader from creating child processes
    AdobeReader = @{
        GUID = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
        Name = "Block Adobe Reader from creating child processes"
        Description = "Prevents malicious PDFs from executing code"
        Impact = "Low - Normal PDFs work fine"
    }

    # Block JavaScript or VBScript from launching downloaded executable
    JSVBSExecutable = @{
        GUID = "d3e037e1-3eb8-44c8-a917-57927947596d"
        Name = "Block JavaScript or VBScript from launching downloaded executable"
        Description = "Prevents web scripts from downloading and executing malware"
        Impact = "Low - Good protection for browsing"
    }

    # Block Win32 API calls from Office macros
    OfficeWin32API = @{
        GUID = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
        Name = "Block Win32 API calls from Office macro"
        Description = "Prevents macros from calling dangerous APIs"
        Impact = "Medium - May affect advanced macros"
    }

    # Block persistence through WMI event subscription
    WMIPersistence = @{
        GUID = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
        Name = "Block persistence through WMI event subscription"
        Description = "Prevents malware from using WMI for persistence"
        Impact = "Low - Technique mainly used by malware"
    }

    # Block process creations from PSExec and WMI commands
    PSExecWMI = @{
        GUID = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
        Name = "Block process creations from PSExec and WMI commands"
        Description = "Blocks lateral movement via PSExec/WMI"
        Impact = "High - May affect remote administration"
    }

    # Use advanced protection against ransomware
    AdvancedRansomware = @{
        GUID = "c1db55ab-c21a-4637-bb3f-a12568109d35"
        Name = "Use advanced protection against ransomware"
        Description = "Additional protection against ransomware behaviors"
        Impact = "Low - Good extra protection"
    }

    # Block executable files from running unless they meet criteria
    ExecutableCriteria = @{
        GUID = "01443614-cd74-433a-b99e-2ecdc07bfc25"
        Name = "Block executable files from running unless they meet criteria"
        Description = "Only allows trusted executables (prevalence, age, list)"
        Impact = "High - May block new/rare software"
    }
}

function Get-ASRRulesStatus {
    <#
    .SYNOPSIS
        Checks the status of all ASR rules
    #>

    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $asrIds = $preference.AttackSurfaceReductionRules_Ids
        $asrActions = $preference.AttackSurfaceReductionRules_Actions

        $status = @{}

        foreach ($ruleName in $Script:ASRRules.Keys) {
            $rule = $Script:ASRRules[$ruleName]
            $guid = $rule.GUID

            $index = if ($asrIds) { [array]::IndexOf($asrIds, $guid) } else { -1 }

            if ($index -ge 0 -and $asrActions) {
                $action = $asrActions[$index]
                $status[$ruleName] = switch ($action) {
                    0 { $false }  # Disabled
                    1 { $true }   # Block
                    2 { $false }  # Audit (considered as not blocking)
                    6 { $true }   # Warn (still blocks, but with bypass option)
                    default { $false }
                }
            }
            else {
                $status[$ruleName] = $false
            }
        }

        return $status
    }
    catch {
        # Return all as false on error
        $status = @{}
        foreach ($ruleName in $Script:ASRRules.Keys) {
            $status[$ruleName] = $false
        }
        return $status
    }
}

function Get-ASRRuleDetails {
    <#
    .SYNOPSIS
        Returns details of a specific ASR rule
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleName
    )

    if ($Script:ASRRules.ContainsKey($RuleName)) {
        return $Script:ASRRules[$RuleName]
    }
    else {
        return $null
    }
}

function Set-ASRRules {
    <#
    .SYNOPSIS
        Applies ASR rules configuration
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Rules,

        [ValidateSet("Block", "Audit", "Warn")]
        [string]$Mode = "Block"
    )

    $actionValue = switch ($Mode) {
        "Block" { 1 }
        "Audit" { 2 }
        "Warn"  { 6 }
    }

    $applied = @()
    $errors = @()

    foreach ($ruleName in $Rules.Keys) {
        if (-not $Rules[$ruleName]) { continue }

        if (-not $Script:ASRRules.ContainsKey($ruleName)) {
            $errors += "Unknown rule: $ruleName"
            continue
        }

        $rule = $Script:ASRRules[$ruleName]

        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.GUID `
                            -AttackSurfaceReductionRules_Actions $actionValue `
                            -ErrorAction Stop

            $applied += $rule.Name
        }
        catch {
            $errors += "Error applying $ruleName : $($_.Exception.Message)"
        }
    }

    return @{
        Success = ($errors.Count -eq 0)
        Applied = $applied
        Errors = $errors
        Error = if ($errors.Count -gt 0) { $errors -join "; " } else { $null }
    }
}

function Enable-ASRRule {
    <#
    .SYNOPSIS
        Enables a specific ASR rule
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleName,

        [ValidateSet("Block", "Audit", "Warn")]
        [string]$Mode = "Block"
    )

    $rules = @{ $RuleName = $true }
    return Set-ASRRules -Rules $rules -Mode $Mode
}

function Disable-ASRRule {
    <#
    .SYNOPSIS
        Disables a specific ASR rule
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleName
    )

    if (-not $Script:ASRRules.ContainsKey($RuleName)) {
        return @{
            Success = $false
            Error = "Unknown rule: $RuleName"
        }
    }

    $rule = $Script:ASRRules[$RuleName]

    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.GUID `
                        -AttackSurfaceReductionRules_Actions 0 `
                        -ErrorAction Stop

        return @{
            Success = $true
            Message = "Rule disabled: $($rule.Name)"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Reset-ASRRules {
    <#
    .SYNOPSIS
        Removes all ASR Rules configurations
    #>

    try {
        foreach ($ruleName in $Script:ASRRules.Keys) {
            $rule = $Script:ASRRules[$ruleName]
            try {
                Remove-MpPreference -AttackSurfaceReductionRules_Ids $rule.GUID -ErrorAction SilentlyContinue
            }
            catch {
                # Ignore individual removal errors
            }
        }

        return @{
            Success = $true
            Message = "All ASR rules have been reset"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-ASRExclusions {
    <#
    .SYNOPSIS
        Lists ASR exclusions
    #>

    try {
        $preference = Get-MpPreference -ErrorAction Stop

        return @{
            Files = $preference.AttackSurfaceReductionOnlyExclusions
        }
    }
    catch {
        return @{
            Files = @()
        }
    }
}

function Add-ASRExclusion {
    <#
    .SYNOPSIS
        Adds an ASR exclusion
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions $Path -ErrorAction Stop

        return @{
            Success = $true
            Message = "Exclusion added: $Path"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-RecommendedASRRules {
    <#
    .SYNOPSIS
        Returns recommended rules for infostealer protection
    #>

    return @{
        Essential = @(
            "CredentialStealing",
            "ExecutableEmail",
            "JSVBSExecutable",
            "AdvancedRansomware"
        )

        Recommended = @(
            "OfficeChildProcess",
            "OfficeExecutable",
            "AdobeReader",
            "ScriptObfuscation"
        )

        Advanced = @(
            "OfficeWin32API",
            "WMIPersistence",
            "UntrustedUSB"
        )

        Enterprise = @(
            "PSExecWMI",
            "ExecutableCriteria"
        )
    }
}

function Get-ASRBlockedHistory {
    <#
    .SYNOPSIS
        Gets ASR block history
    #>
    param(
        [int]$MaxEvents = 50
    )

    try {
        # Event ID 1121 = ASR rule blocked
        # Event ID 1122 = ASR rule in audit mode
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'
            Id = 1121, 1122
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

        if ($events) {
            return $events | ForEach-Object {
                @{
                    Time = $_.TimeCreated
                    EventId = $_.Id
                    Type = if ($_.Id -eq 1121) { "Blocked" } else { "Audited" }
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
# - Get-ASRRulesStatus
# - Get-ASRRuleDetails
# - Set-ASRRules
# - Enable-ASRRule
# - Disable-ASRRule
# - Reset-ASRRules
# - Get-ASRExclusions
# - Add-ASRExclusion
# - Get-RecommendedASRRules
# - Get-ASRBlockedHistory
