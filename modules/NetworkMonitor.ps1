#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Network Monitoring Module

.DESCRIPTION
    Functions to monitor network connections and detect possible
    data exfiltration by malware/stealers.

.NOTES
    Infostealers typically send data to C2 (Command & Control) servers
    using HTTP/HTTPS. This module helps identify suspicious connections.
#>

# List of known C2 domains/IPs from stealers
# This list should be updated regularly
$Script:KnownMaliciousDomains = @(
    # Common stealer patterns
    "*.top",
    "*.xyz",
    "*.tk",
    "*.ml",
    "*.ga",
    "*.cf",
    "*.gq",
    "*.pw",
    # Some known C2 (generic examples)
    "*stealer*",
    "*c2*",
    "*panel*",
    "*gate*"
)

# Ports commonly used by stealers for exfiltration
$Script:SuspiciousPorts = @(
    4444,   # Metasploit
    5555,   # Common in RATs
    6666,   # Various malware
    7777,   # RATs
    8888,   # Various
    9999,   # Various
    1337,   # "leet" - common in malware
    31337,  # "eleet"
    12345,  # NetBus
    23456,  # Evil FTP
    54321   # Various
)

function Get-ActiveConnections {
    <#
    .SYNOPSIS
        Lists active network connections
    #>
    param(
        [switch]$IncludeProcessName,
        [switch]$ExcludeLocal
    )

    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

        if ($ExcludeLocal) {
            $connections = $connections | Where-Object {
                $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0|::)"
            }
        }

        $result = $connections | ForEach-Object {
            $conn = $_
            $processInfo = $null

            if ($IncludeProcessName) {
                try {
                    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    $processInfo = $process.Name
                }
                catch {
                    $processInfo = "Unknown"
                }
            }

            @{
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                ProcessId = $conn.OwningProcess
                ProcessName = $processInfo
                State = $conn.State
            }
        }

        return @{
            Success = $true
            Connections = $result
            Count = ($result | Measure-Object).Count
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Find-SuspiciousConnections {
    <#
    .SYNOPSIS
        Identifies suspicious connections that may indicate exfiltration

    .DESCRIPTION
        Analyzes active connections looking for:
        - Ports commonly used by malware
        - Non-browser process connections to HTTPS
        - Connections to suspicious IPs/domains
    #>

    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                       Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0|::)" }

        $suspicious = @()

        # Browser processes (HTTPS connections are expected)
        $browserProcesses = @("chrome", "msedge", "firefox", "brave", "opera", "iexplore")

        foreach ($conn in $connections) {
            $isSuspicious = $false
            $reasons = @()

            try {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $processName = if ($process) { $process.Name } else { "Unknown" }
                $processPath = if ($process) { $process.Path } else { "Unknown" }
            }
            catch {
                $processName = "Unknown"
                $processPath = "Unknown"
            }

            # Check suspicious port
            if ($conn.RemotePort -in $Script:SuspiciousPorts) {
                $isSuspicious = $true
                $reasons += "Suspicious port: $($conn.RemotePort)"
            }

            # Check HTTPS connection from non-browser process
            if ($conn.RemotePort -eq 443 -and $processName -notin $browserProcesses) {
                # Some legitimate processes that make HTTPS connections
                $legitimateHTTPS = @(
                    "svchost", "OneDrive", "Dropbox", "Spotify",
                    "Teams", "Slack", "Discord", "Code", "pwsh",
                    "powershell", "WindowsTerminal", "explorer",
                    "SearchHost", "RuntimeBroker", "SystemSettings"
                )

                if ($processName -notin $legitimateHTTPS) {
                    $isSuspicious = $true
                    $reasons += "HTTPS connection from unusual process: $processName"
                }
            }

            # Check if connecting to many different IPs (indicator of scanning/exfil)
            $processConnections = $connections | Where-Object { $_.OwningProcess -eq $conn.OwningProcess }
            $uniqueRemoteIPs = ($processConnections | Select-Object -ExpandProperty RemoteAddress -Unique).Count

            if ($uniqueRemoteIPs -gt 10 -and $processName -notin $browserProcesses) {
                $isSuspicious = $true
                $reasons += "Process connecting to $uniqueRemoteIPs different IPs"
            }

            if ($isSuspicious) {
                $suspicious += @{
                    ProcessName = $processName
                    ProcessId = $conn.OwningProcess
                    ProcessPath = $processPath
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    LocalPort = $conn.LocalPort
                    Reasons = $reasons
                }
            }
        }

        return @{
            Success = $true
            SuspiciousConnections = $suspicious
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

function Block-SuspiciousIPs {
    <#
    .SYNOPSIS
        Blocks suspicious IPs in Windows Firewall

    .DESCRIPTION
        Creates firewall rules to block connections to IPs identified as suspicious.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$IPAddresses,

        [string]$RuleName = "BlockSuspiciousIPs_SecurityTool"
    )

    try {
        # Remove existing rule if any
        $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        if ($existingRule) {
            Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        }

        # Create new rule blocking the IPs
        New-NetFirewallRule -DisplayName $RuleName `
                           -Direction Outbound `
                           -Action Block `
                           -RemoteAddress $IPAddresses `
                           -Profile Any `
                           -ErrorAction Stop | Out-Null

        return @{
            Success = $true
            Message = "Blocked $($IPAddresses.Count) IPs"
            BlockedIPs = $IPAddresses
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Unblock-SuspiciousIPs {
    <#
    .SYNOPSIS
        Removes suspicious IP blocking
    #>
    param(
        [string]$RuleName = "BlockSuspiciousIPs_SecurityTool"
    )

    try {
        Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop

        return @{
            Success = $true
            Message = "Blocking rule removed"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Enable-ConnectionLogging {
    <#
    .SYNOPSIS
        Enables connection logging in Windows Firewall
    #>

    try {
        # Enable logging for blocked and allowed connections
        Set-NetFirewallProfile -Profile Domain,Public,Private `
                               -LogBlocked True `
                               -LogAllowed True `
                               -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" `
                               -LogMaxSizeKilobytes 32767 `
                               -ErrorAction Stop

        return @{
            Success = $true
            Message = "Connection logging enabled"
            LogPath = "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-RecentFirewallBlocks {
    <#
    .SYNOPSIS
        Lists recent firewall blocks
    #>
    param(
        [int]$MaxEvents = 50
    )

    try {
        # Event ID 5152 = Windows Filtering Platform blocked a packet
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 5152
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

        if ($events) {
            return @{
                Success = $true
                Events = $events | ForEach-Object {
                    @{
                        Time = $_.TimeCreated
                        Message = $_.Message
                    }
                }
                Count = $events.Count
            }
        }
        else {
            return @{
                Success = $true
                Events = @()
                Count = 0
                Note = "No block events found or auditing is not enabled"
            }
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-ProcessNetworkUsage {
    <#
    .SYNOPSIS
        Shows network usage by process
    #>

    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

        $processStats = @{}

        foreach ($conn in $connections) {
            try {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $processName = if ($process) { $process.Name } else { "Unknown (PID: $($conn.OwningProcess))" }

                if (-not $processStats.ContainsKey($processName)) {
                    $processStats[$processName] = @{
                        ConnectionCount = 0
                        UniqueRemoteIPs = @()
                        RemotePorts = @()
                    }
                }

                $processStats[$processName].ConnectionCount++

                if ($conn.RemoteAddress -notin $processStats[$processName].UniqueRemoteIPs) {
                    $processStats[$processName].UniqueRemoteIPs += $conn.RemoteAddress
                }

                if ($conn.RemotePort -notin $processStats[$processName].RemotePorts) {
                    $processStats[$processName].RemotePorts += $conn.RemotePort
                }
            }
            catch {
                # Ignore process errors
            }
        }

        $result = $processStats.GetEnumerator() | ForEach-Object {
            @{
                ProcessName = $_.Key
                Connections = $_.Value.ConnectionCount
                UniqueIPs = $_.Value.UniqueRemoteIPs.Count
                Ports = ($_.Value.RemotePorts | Sort-Object -Unique) -join ", "
            }
        } | Sort-Object -Property Connections -Descending

        return @{
            Success = $true
            Processes = $result
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Start-ConnectionMonitor {
    <#
    .SYNOPSIS
        Starts real-time connection monitoring

    .DESCRIPTION
        Creates a background job that monitors new connections
        and alerts about suspicious connections.
    #>
    param(
        [string]$LogPath = "$env:USERPROFILE\Desktop\ConnectionLog.txt"
    )

    try {
        $scriptBlock = {
            param($LogPath, $SuspiciousPorts)

            $knownConnections = @{}

            while ($true) {
                $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

                foreach ($conn in $connections) {
                    $key = "$($conn.RemoteAddress):$($conn.RemotePort)-$($conn.OwningProcess)"

                    if (-not $knownConnections.ContainsKey($key)) {
                        $knownConnections[$key] = $true

                        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                        $processName = if ($process) { $process.Name } else { "Unknown" }

                        $isSuspicious = $conn.RemotePort -in $SuspiciousPorts

                        $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] "
                        $logEntry += if ($isSuspicious) { "[SUSPICIOUS] " } else { "[INFO] " }
                        $logEntry += "$processName (PID: $($conn.OwningProcess)) -> $($conn.RemoteAddress):$($conn.RemotePort)"

                        Add-Content -Path $LogPath -Value $logEntry
                    }
                }

                Start-Sleep -Seconds 5
            }
        }

        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $LogPath, $Script:SuspiciousPorts

        return @{
            Success = $true
            JobId = $job.Id
            LogPath = $LogPath
            Message = "Monitoring started. Use Stop-Job -Id $($job.Id) to stop."
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Stop-ConnectionMonitor {
    <#
    .SYNOPSIS
        Stops connection monitoring
    #>
    param(
        [int]$JobId
    )

    try {
        Stop-Job -Id $JobId -ErrorAction Stop
        Remove-Job -Id $JobId -ErrorAction Stop

        return @{
            Success = $true
            Message = "Monitoring stopped"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Test-DNSLeakage {
    <#
    .SYNOPSIS
        Checks for DNS leakage
    #>

    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 |
                      Where-Object { $_.ServerAddresses } |
                      Select-Object -ExpandProperty ServerAddresses -Unique

        $publicDNS = @(
            "8.8.8.8",      # Google
            "8.8.4.4",      # Google
            "1.1.1.1",      # Cloudflare
            "1.0.0.1",      # Cloudflare
            "9.9.9.9",      # Quad9
            "208.67.222.222", # OpenDNS
            "208.67.220.220"  # OpenDNS
        )

        $usingPublicDNS = $dnsServers | Where-Object { $_ -in $publicDNS }

        return @{
            Success = $true
            ConfiguredDNS = $dnsServers
            UsingPublicDNS = ($usingPublicDNS.Count -gt 0)
            PublicDNSUsed = $usingPublicDNS
            Recommendation = if ($usingPublicDNS.Count -eq 0) {
                "Consider using public DNS with DoH (DNS over HTTPS) for better privacy"
            } else {
                "Public DNS configured. Consider enabling DoH to encrypt DNS queries"
            }
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
# - Get-ActiveConnections
# - Find-SuspiciousConnections
# - Block-SuspiciousIPs
# - Unblock-SuspiciousIPs
# - Enable-ConnectionLogging
# - Get-RecentFirewallBlocks
# - Get-ProcessNetworkUsage
# - Start-ConnectionMonitor
# - Stop-ConnectionMonitor
# - Test-DNSLeakage
