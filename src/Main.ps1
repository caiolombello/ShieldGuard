#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    ShieldGuard - Windows Security Hardening Tool

.DESCRIPTION
    Tool to simplify Windows security configurations.
    Works with any antivirus (Kaspersky, Norton, Avast, etc.)

.LICENSE
    MIT License - Open Source
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Import modules
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulesPath = Join-Path (Split-Path -Parent $ScriptPath) "modules"

. "$ModulesPath\ControlledFolderAccess.ps1"
. "$ModulesPath\ASRRules.ps1"
. "$ModulesPath\BrowserProtection.ps1"
. "$ModulesPath\NetworkMonitor.ps1"
. "$ModulesPath\SystemHardening.ps1"

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

[xml]$XAML = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="ShieldGuard - Windows Security Hardening"
    Height="750"
    Width="950"
    WindowStartupLocation="CenterScreen"
    Background="#1a1a2e">

    <Window.Resources>
        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background" Value="#4a4e69"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="15,8"/>
            <Setter Property="Margin" Value="5"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="5" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#6c757d"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="GreenButton" TargetType="Button" BasedOn="{StaticResource ModernButton}">
            <Setter Property="Background" Value="#28a745"/>
        </Style>

        <Style x:Key="RedButton" TargetType="Button" BasedOn="{StaticResource ModernButton}">
            <Setter Property="Background" Value="#dc3545"/>
        </Style>

        <Style x:Key="ModernCheckBox" TargetType="CheckBox">
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="Margin" Value="10,5"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>

        <Style x:Key="ModernGroupBox" TargetType="GroupBox">
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderBrush" Value="#4a4e69"/>
            <Setter Property="Margin" Value="10"/>
            <Setter Property="Padding" Value="10"/>
        </Style>

        <Style TargetType="TabItem">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Border x:Name="Border" Background="#16213e" BorderBrush="#4a4e69" BorderThickness="1,1,1,0" CornerRadius="4,4,0,0" Padding="12,6" Margin="2,0">
                            <ContentPresenter x:Name="ContentSite" ContentSource="Header" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#4a4e69"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="#3a3e59"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Setter Property="Foreground" Value="White"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="120"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Background="#16213e" Padding="15">
            <StackPanel>
                <TextBlock Text="ShieldGuard" FontSize="22" FontWeight="Bold" Foreground="#e94560"/>
                <TextBlock Text="Protection against Infostealers, Ransomware and Malware" FontSize="12" Foreground="#a0a0a0" Margin="0,3,0,0"/>
            </StackPanel>
        </Border>

        <TabControl Grid.Row="1" Margin="10" Background="#1a1a2e" BorderBrush="#4a4e69">

            <!-- Tab: System Hardening (NEW - Works with any AV) -->
            <TabItem Header="System Hardening">
                <ScrollViewer VerticalScrollBarVisibility="Auto" Background="#1a1a2e">
                    <StackPanel Margin="15">
                        <Border Background="#1e5128" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                            <TextBlock Text="These features work with ANY antivirus (Kaspersky, Norton, etc.)" Foreground="White" FontWeight="Bold"/>
                        </Border>

                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>

                            <GroupBox Header="USB Protection" Style="{StaticResource ModernGroupBox}" Grid.Column="0">
                                <StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                                        <TextBlock Text="Autorun Status: " Foreground="White"/>
                                        <TextBlock x:Name="txtUSBStatus" Text="Checking..." Foreground="#ffc107"/>
                                    </StackPanel>
                                    <Button x:Name="btnDisableUSB" Content="Disable USB Autorun" Style="{StaticResource GreenButton}"/>
                                    <Button x:Name="btnEnableUSB" Content="Enable USB Autorun" Style="{StaticResource RedButton}"/>
                                </StackPanel>
                            </GroupBox>

                            <GroupBox Header="SMBv1 Protocol" Style="{StaticResource ModernGroupBox}" Grid.Column="1">
                                <StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                                        <TextBlock Text="SMBv1 Status: " Foreground="White"/>
                                        <TextBlock x:Name="txtSMBStatus" Text="Checking..." Foreground="#ffc107"/>
                                    </StackPanel>
                                    <TextBlock Text="SMBv1 was exploited by WannaCry ransomware" Foreground="#ff6b6b" FontSize="11" Margin="0,0,0,5"/>
                                    <Button x:Name="btnDisableSMB" Content="Disable SMBv1" Style="{StaticResource GreenButton}"/>
                                </StackPanel>
                            </GroupBox>
                        </Grid>

                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>

                            <GroupBox Header="PowerShell Security" Style="{StaticResource ModernGroupBox}" Grid.Column="0">
                                <StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                                        <TextBlock Text="Execution Policy: " Foreground="White"/>
                                        <TextBlock x:Name="txtPSPolicy" Text="..." Foreground="#ffc107"/>
                                    </StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                                        <TextBlock Text="Script Logging: " Foreground="White"/>
                                        <TextBlock x:Name="txtPSLogging" Text="..." Foreground="#ffc107"/>
                                    </StackPanel>
                                    <Button x:Name="btnEnablePSLogging" Content="Enable PowerShell Logging" Style="{StaticResource GreenButton}"/>
                                </StackPanel>
                            </GroupBox>

                            <GroupBox Header="Remote Desktop" Style="{StaticResource ModernGroupBox}" Grid.Column="1">
                                <StackPanel>
                                    <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                                        <TextBlock Text="RDP Status: " Foreground="White"/>
                                        <TextBlock x:Name="txtRDPStatus" Text="Checking..." Foreground="#ffc107"/>
                                    </StackPanel>
                                    <Button x:Name="btnDisableRDP" Content="Disable Remote Desktop" Style="{StaticResource GreenButton}"/>
                                </StackPanel>
                            </GroupBox>
                        </Grid>

                        <GroupBox Header="Hosts File Protection" Style="{StaticResource ModernGroupBox}">
                            <StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                                    <TextBlock Text="Suspicious entries: " Foreground="White"/>
                                    <TextBlock x:Name="txtHostsStatus" Text="Checking..." Foreground="#ffc107"/>
                                </StackPanel>
                                <Button x:Name="btnCheckHosts" Content="Scan Hosts File" Style="{StaticResource ModernButton}"/>
                                <Button x:Name="btnProtectHosts" Content="Protect Hosts File (Restrict Permissions)" Style="{StaticResource GreenButton}"/>
                            </StackPanel>
                        </GroupBox>

                        <GroupBox Header="Startup Programs Scanner" Style="{StaticResource ModernGroupBox}">
                            <StackPanel>
                                <Button x:Name="btnScanStartup" Content="Scan for Suspicious Startup Items" Style="{StaticResource ModernButton}"/>
                                <ListBox x:Name="lstStartupItems" Background="#0f0f23" Foreground="White" Height="80" BorderThickness="0" Margin="0,10,0,0"/>
                            </StackPanel>
                        </GroupBox>

                        <GroupBox Header="Scheduled Tasks Scanner" Style="{StaticResource ModernGroupBox}">
                            <StackPanel>
                                <Button x:Name="btnScanTasks" Content="Scan for Suspicious Scheduled Tasks" Style="{StaticResource ModernButton}"/>
                                <ListBox x:Name="lstScheduledTasks" Background="#0f0f23" Foreground="White" Height="80" BorderThickness="0" Margin="0,10,0,0"/>
                            </StackPanel>
                        </GroupBox>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>

            <!-- Tab: Browser Protection -->
            <TabItem Header="Browser Protection">
                <ScrollViewer VerticalScrollBarVisibility="Auto" Background="#1a1a2e">
                    <StackPanel Margin="15">
                        <Border Background="#1e5128" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                            <TextBlock Text="Works with ANY antivirus - Protects against session token theft" Foreground="White" FontWeight="Bold"/>
                        </Border>

                        <Border Background="#2d132c" CornerRadius="5" Padding="15" Margin="0,0,0,15">
                            <StackPanel>
                                <TextBlock Text="HOW INFOSTEALERS WORK:" FontWeight="Bold" Foreground="#ffc107"/>
                                <TextBlock TextWrapping="Wrap" Foreground="White" Margin="0,5,0,0">
                                    Malware steals browser cookies/tokens, allowing attackers to access your accounts WITHOUT needing your password or 2FA. This protection makes it harder for malware to read those files.
                                </TextBlock>
                            </StackPanel>
                        </Border>

                        <GroupBox Header="Detected Browsers" Style="{StaticResource ModernGroupBox}">
                            <StackPanel>
                                <CheckBox x:Name="chkChrome" Content="Google Chrome" Style="{StaticResource ModernCheckBox}"/>
                                <CheckBox x:Name="chkEdge" Content="Microsoft Edge" Style="{StaticResource ModernCheckBox}"/>
                                <CheckBox x:Name="chkFirefox" Content="Mozilla Firefox" Style="{StaticResource ModernCheckBox}"/>
                                <CheckBox x:Name="chkBrave" Content="Brave Browser" Style="{StaticResource ModernCheckBox}"/>
                                <CheckBox x:Name="chkOpera" Content="Opera/Opera GX" Style="{StaticResource ModernCheckBox}"/>
                            </StackPanel>
                        </GroupBox>

                        <GroupBox Header="Protection Actions" Style="{StaticResource ModernGroupBox}">
                            <StackPanel>
                                <Button x:Name="btnProtectCookies" Content="Protect Cookie Directories (ACL)" Style="{StaticResource GreenButton}"/>
                                <Button x:Name="btnClearSessions" Content="Clear All Sessions (Logout Everywhere)" Style="{StaticResource RedButton}"/>
                                <Button x:Name="btnRestorePermissions" Content="Restore Default Permissions" Style="{StaticResource ModernButton}"/>
                            </StackPanel>
                        </GroupBox>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>

            <!-- Tab: Network Monitor -->
            <TabItem Header="Network Monitor">
                <ScrollViewer VerticalScrollBarVisibility="Auto" Background="#1a1a2e">
                    <StackPanel Margin="15">
                        <TextBlock Text="Exfiltration Detection" FontSize="16" FontWeight="Bold" Foreground="White"/>
                        <TextBlock Text="Monitors network connections for suspicious activity" Foreground="#a0a0a0" Margin="0,5,0,15"/>

                        <GroupBox Header="Actions" Style="{StaticResource ModernGroupBox}">
                            <StackPanel>
                                <Button x:Name="btnFindSuspicious" Content="Find Suspicious Connections" Style="{StaticResource ModernButton}"/>
                                <Button x:Name="btnViewConnections" Content="View All Active Connections" Style="{StaticResource ModernButton}"/>
                                <Button x:Name="btnEnableFirewallLog" Content="Enable Firewall Logging" Style="{StaticResource GreenButton}"/>
                            </StackPanel>
                        </GroupBox>

                        <GroupBox Header="Results" Style="{StaticResource ModernGroupBox}">
                            <ListBox x:Name="lstNetworkResults" Background="#0f0f23" Foreground="White" Height="200" BorderThickness="0"/>
                        </GroupBox>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>

            <!-- Tab: Defender Features (CFA/ASR) -->
            <TabItem Header="Defender (CFA/ASR)">
                <ScrollViewer VerticalScrollBarVisibility="Auto" Background="#1a1a2e">
                    <StackPanel Margin="15">
                        <Border Background="#5c1a1a" CornerRadius="5" Padding="10" Margin="0,0,0,10">
                            <StackPanel>
                                <TextBlock Text="REQUIRES WINDOWS DEFENDER" FontWeight="Bold" Foreground="#ff6b6b"/>
                                <TextBlock x:Name="txtDefenderWarning" Text="If you use Kaspersky/Norton/etc, these features are disabled." Foreground="#ffaa00" FontSize="11"/>
                            </StackPanel>
                        </Border>

                        <GroupBox Header="Controlled Folder Access" Style="{StaticResource ModernGroupBox}">
                            <StackPanel>
                                <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                                    <TextBlock Text="Status: " Foreground="White"/>
                                    <TextBlock x:Name="txtCFAStatus" Text="Checking..." Foreground="#ffc107"/>
                                </StackPanel>
                                <Button x:Name="btnEnableCFA" Content="Enable CFA" Style="{StaticResource GreenButton}"/>
                                <Button x:Name="btnDisableCFA" Content="Disable CFA" Style="{StaticResource RedButton}"/>
                            </StackPanel>
                        </GroupBox>

                        <GroupBox Header="ASR Rules" Style="{StaticResource ModernGroupBox}">
                            <StackPanel>
                                <CheckBox x:Name="chkBlockCredentialStealing" Content="Block credential stealing (LSASS)" Style="{StaticResource ModernCheckBox}"/>
                                <CheckBox x:Name="chkBlockOfficeChildProcess" Content="Block Office child processes" Style="{StaticResource ModernCheckBox}"/>
                                <CheckBox x:Name="chkBlockScriptObfuscation" Content="Block obfuscated scripts" Style="{StaticResource ModernCheckBox}"/>
                                <CheckBox x:Name="chkBlockExecutableEmail" Content="Block email executables" Style="{StaticResource ModernCheckBox}"/>
                                <StackPanel Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,10,0,0">
                                    <Button x:Name="btnApplyASR" Content="Apply ASR Rules" Style="{StaticResource GreenButton}"/>
                                    <Button x:Name="btnResetASR" Content="Reset All" Style="{StaticResource RedButton}"/>
                                </StackPanel>
                            </StackPanel>
                        </GroupBox>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>

            <!-- Tab: Quick Actions -->
            <TabItem Header="Quick Actions">
                <ScrollViewer VerticalScrollBarVisibility="Auto" Background="#1a1a2e">
                    <StackPanel Margin="15">
                        <Border Background="#1e3a5f" CornerRadius="10" Padding="20" Margin="0,10">
                            <StackPanel>
                                <TextBlock Text="FULL SYSTEM HARDENING" FontSize="18" FontWeight="Bold" Foreground="White"/>
                                <TextBlock TextWrapping="Wrap" Foreground="#a0a0a0" Margin="0,10,0,0">
                                    Applies all protections that work with your current antivirus:
                                    - Disable USB Autorun
                                    - Disable SMBv1
                                    - Enable PowerShell Logging
                                    - Protect Browser Cookies
                                    - Protect Hosts File
                                </TextBlock>
                                <Button x:Name="btnFullHarden" Content="APPLY ALL PROTECTIONS" Style="{StaticResource GreenButton}" FontSize="14" Margin="0,15,0,0"/>
                            </StackPanel>
                        </Border>

                        <Border Background="#3d1a1a" CornerRadius="10" Padding="20" Margin="0,10">
                            <StackPanel>
                                <TextBlock Text="REVERT ALL CHANGES" FontSize="16" FontWeight="Bold" Foreground="White"/>
                                <TextBlock Text="Restores all settings to defaults" Foreground="#a0a0a0" Margin="0,10,0,0"/>
                                <Button x:Name="btnRevertAll" Content="REVERT EVERYTHING" Style="{StaticResource RedButton}" Margin="0,15,0,0"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>
        </TabControl>

        <Border Grid.Row="2" Background="#16213e" Padding="8">
            <TextBlock x:Name="txtStatus" Text="Ready" Foreground="#a0a0a0"/>
        </Border>

        <Border Grid.Row="3" Background="#0f0f23" Margin="10">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
                <TextBox x:Name="txtLog" Background="Transparent" Foreground="#00ff00" FontFamily="Consolas" FontSize="11" IsReadOnly="True" BorderThickness="0" TextWrapping="Wrap"/>
            </ScrollViewer>
        </Border>
    </Grid>
</Window>
"@

$Reader = New-Object System.Xml.XmlNodeReader $XAML
$Window = [Windows.Markup.XamlReader]::Load($Reader)

# Get all controls
$txtStatus = $Window.FindName("txtStatus")
$txtLog = $Window.FindName("txtLog")

# System Hardening controls
$txtUSBStatus = $Window.FindName("txtUSBStatus")
$txtSMBStatus = $Window.FindName("txtSMBStatus")
$txtPSPolicy = $Window.FindName("txtPSPolicy")
$txtPSLogging = $Window.FindName("txtPSLogging")
$txtRDPStatus = $Window.FindName("txtRDPStatus")
$txtHostsStatus = $Window.FindName("txtHostsStatus")
$btnDisableUSB = $Window.FindName("btnDisableUSB")
$btnEnableUSB = $Window.FindName("btnEnableUSB")
$btnDisableSMB = $Window.FindName("btnDisableSMB")
$btnEnablePSLogging = $Window.FindName("btnEnablePSLogging")
$btnDisableRDP = $Window.FindName("btnDisableRDP")
$btnCheckHosts = $Window.FindName("btnCheckHosts")
$btnProtectHosts = $Window.FindName("btnProtectHosts")
$btnScanStartup = $Window.FindName("btnScanStartup")
$btnScanTasks = $Window.FindName("btnScanTasks")
$lstStartupItems = $Window.FindName("lstStartupItems")
$lstScheduledTasks = $Window.FindName("lstScheduledTasks")

# Browser controls
$chkChrome = $Window.FindName("chkChrome")
$chkEdge = $Window.FindName("chkEdge")
$chkFirefox = $Window.FindName("chkFirefox")
$chkBrave = $Window.FindName("chkBrave")
$chkOpera = $Window.FindName("chkOpera")
$btnProtectCookies = $Window.FindName("btnProtectCookies")
$btnClearSessions = $Window.FindName("btnClearSessions")
$btnRestorePermissions = $Window.FindName("btnRestorePermissions")

# Network controls
$btnFindSuspicious = $Window.FindName("btnFindSuspicious")
$btnViewConnections = $Window.FindName("btnViewConnections")
$btnEnableFirewallLog = $Window.FindName("btnEnableFirewallLog")
$lstNetworkResults = $Window.FindName("lstNetworkResults")

# Defender controls
$txtCFAStatus = $Window.FindName("txtCFAStatus")
$txtDefenderWarning = $Window.FindName("txtDefenderWarning")
$btnEnableCFA = $Window.FindName("btnEnableCFA")
$btnDisableCFA = $Window.FindName("btnDisableCFA")
$chkBlockCredentialStealing = $Window.FindName("chkBlockCredentialStealing")
$chkBlockOfficeChildProcess = $Window.FindName("chkBlockOfficeChildProcess")
$chkBlockScriptObfuscation = $Window.FindName("chkBlockScriptObfuscation")
$chkBlockExecutableEmail = $Window.FindName("chkBlockExecutableEmail")
$btnApplyASR = $Window.FindName("btnApplyASR")
$btnResetASR = $Window.FindName("btnResetASR")

# Quick actions
$btnFullHarden = $Window.FindName("btnFullHarden")
$btnRevertAll = $Window.FindName("btnRevertAll")

# Helper functions
function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $prefix = switch ($Type) {
        "SUCCESS" { "[+]" }
        "ERROR"   { "[-]" }
        "WARNING" { "[!]" }
        default   { "[*]" }
    }
    $txtLog.AppendText("$timestamp $prefix $Message`r`n")
    $txtLog.ScrollToEnd()
}

function Update-Status { param([string]$Message) $txtStatus.Text = $Message }

function Test-DefenderService {
    try {
        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
        return ($svc -and $svc.Status -eq "Running")
    } catch { return $false }
}

# Window Loaded
$Window.Add_Loaded({
    Write-Log "ShieldGuard started" "SUCCESS"

    # Check Defender
    $defenderOK = Test-DefenderService
    if (-not $defenderOK) {
        Write-Log "Windows Defender is not running (3rd party AV detected)" "WARNING"
        $txtCFAStatus.Text = "Defender Not Active"
        $txtCFAStatus.Foreground = "#ff6600"
        $txtDefenderWarning.Text = "Kaspersky/Norton/etc detected. CFA/ASR features disabled."
    } else {
        $cfaStatus = Get-ControlledFolderAccessStatus
        $txtCFAStatus.Text = $cfaStatus.Status
        $txtCFAStatus.Foreground = if ($cfaStatus.Enabled) { "#28a745" } else { "#dc3545" }
    }

    # USB Status
    $usbStatus = Get-USBAutorunStatus
    $txtUSBStatus.Text = $usbStatus.Status
    $txtUSBStatus.Foreground = if ($usbStatus.AutorunDisabled) { "#28a745" } else { "#dc3545" }

    # SMB Status
    $smbStatus = Get-SMBv1Status
    $txtSMBStatus.Text = if ($smbStatus.Enabled) { "ENABLED (Vulnerable!)" } else { "Disabled (Secure)" }
    $txtSMBStatus.Foreground = if ($smbStatus.Enabled) { "#dc3545" } else { "#28a745" }

    # PowerShell Status
    $psStatus = Get-PowerShellSecurityStatus
    $txtPSPolicy.Text = $psStatus.Status.ExecutionPolicy
    $txtPSLogging.Text = if ($psStatus.Status.ScriptBlockLogging) { "Enabled" } else { "Disabled" }
    $txtPSLogging.Foreground = if ($psStatus.Status.ScriptBlockLogging) { "#28a745" } else { "#ffc107" }

    # RDP Status
    $rdpStatus = Get-RemoteDesktopStatus
    $txtRDPStatus.Text = $rdpStatus.Status
    $txtRDPStatus.Foreground = if ($rdpStatus.Enabled) { "#dc3545" } else { "#28a745" }

    # Hosts Status
    $hostsStatus = Get-HostsFileStatus
    $txtHostsStatus.Text = "$($hostsStatus.SuspiciousCount) found"
    $txtHostsStatus.Foreground = if ($hostsStatus.SuspiciousCount -gt 0) { "#dc3545" } else { "#28a745" }

    # Browsers
    $browsers = Get-InstalledBrowsers
    $chkChrome.IsChecked = $browsers.Chrome
    $chkEdge.IsChecked = $browsers.Edge
    $chkFirefox.IsChecked = $browsers.Firefox
    $chkBrave.IsChecked = $browsers.Brave
    $chkOpera.IsChecked = $browsers.Opera

    Write-Log "Initial scan completed" "SUCCESS"
})

# System Hardening Events
$btnDisableUSB.Add_Click({
    $result = Disable-USBAutorun
    if ($result.Success) {
        Write-Log "USB Autorun disabled" "SUCCESS"
        $txtUSBStatus.Text = "Protected"
        $txtUSBStatus.Foreground = "#28a745"
    } else { Write-Log "Error: $($result.Error)" "ERROR" }
})

$btnEnableUSB.Add_Click({
    $result = Enable-USBAutorun
    if ($result.Success) {
        Write-Log "USB Autorun enabled (not recommended)" "WARNING"
        $txtUSBStatus.Text = "Vulnerable"
        $txtUSBStatus.Foreground = "#dc3545"
    }
})

$btnDisableSMB.Add_Click({
    Update-Status "Disabling SMBv1..."
    $result = Disable-SMBv1
    if ($result.Success) {
        Write-Log "SMBv1 disabled. Restart required." "SUCCESS"
        $txtSMBStatus.Text = "Disabled (Restart needed)"
        $txtSMBStatus.Foreground = "#28a745"
    } else { Write-Log "Error: $($result.Error)" "ERROR" }
    Update-Status "Ready"
})

$btnEnablePSLogging.Add_Click({
    $result = Enable-PowerShellLogging
    if ($result.Success) {
        Write-Log "PowerShell logging enabled" "SUCCESS"
        $txtPSLogging.Text = "Enabled"
        $txtPSLogging.Foreground = "#28a745"
    } else { Write-Log "Error: $($result.Error)" "ERROR" }
})

$btnDisableRDP.Add_Click({
    $result = Disable-RemoteDesktop
    if ($result.Success) {
        Write-Log "Remote Desktop disabled" "SUCCESS"
        $txtRDPStatus.Text = "Disabled (secure)"
        $txtRDPStatus.Foreground = "#28a745"
    } else { Write-Log "Error: $($result.Error)" "ERROR" }
})

$btnCheckHosts.Add_Click({
    Write-Log "Scanning hosts file..." "INFO"
    $result = Get-HostsFileStatus
    $txtHostsStatus.Text = "$($result.SuspiciousCount) found"
    $txtHostsStatus.Foreground = if ($result.SuspiciousCount -gt 0) { "#dc3545" } else { "#28a745" }
    if ($result.SuspiciousCount -gt 0) {
        Write-Log "Found $($result.SuspiciousCount) suspicious entries in hosts file" "WARNING"
        foreach ($entry in $result.SuspiciousEntries) {
            Write-Log "  - $entry" "WARNING"
        }
    } else {
        Write-Log "Hosts file is clean" "SUCCESS"
    }
})

$btnProtectHosts.Add_Click({
    $result = Protect-HostsFile
    if ($result.Success) { Write-Log "Hosts file protected" "SUCCESS" }
    else { Write-Log "Error: $($result.Error)" "ERROR" }
})

$btnScanStartup.Add_Click({
    $lstStartupItems.Items.Clear()
    Write-Log "Scanning startup items..." "INFO"
    $result = Find-SuspiciousStartupItems
    if ($result.Count -eq 0) {
        $lstStartupItems.Items.Add("No suspicious startup items found")
        Write-Log "No suspicious startup items found" "SUCCESS"
    } else {
        foreach ($item in $result.SuspiciousItems) {
            $lstStartupItems.Items.Add("$($item.Name): $($item.Reasons -join ', ')")
        }
        Write-Log "Found $($result.Count) suspicious startup items" "WARNING"
    }
})

$btnScanTasks.Add_Click({
    $lstScheduledTasks.Items.Clear()
    Write-Log "Scanning scheduled tasks..." "INFO"
    $result = Get-SuspiciousScheduledTasks
    if ($result.Count -eq 0) {
        $lstScheduledTasks.Items.Add("No suspicious tasks found")
        Write-Log "No suspicious scheduled tasks found" "SUCCESS"
    } else {
        foreach ($task in $result.SuspiciousTasks) {
            $lstScheduledTasks.Items.Add("$($task.TaskName): $($task.Pattern)")
        }
        Write-Log "Found $($result.Count) suspicious tasks" "WARNING"
    }
})

# Browser Events
$btnProtectCookies.Add_Click({
    Update-Status "Protecting browser cookies..."
    $browsers = @()
    if ($chkChrome.IsChecked) { $browsers += "Chrome" }
    if ($chkEdge.IsChecked) { $browsers += "Edge" }
    if ($chkFirefox.IsChecked) { $browsers += "Firefox" }
    if ($chkBrave.IsChecked) { $browsers += "Brave" }
    if ($chkOpera.IsChecked) { $browsers += "Opera" }

    foreach ($browser in $browsers) {
        $result = Protect-BrowserCookies -Browser $browser
        if ($result.Success) { Write-Log "$browser cookies protected" "SUCCESS" }
        else { Write-Log "Error protecting ${browser}: $($result.Error)" "ERROR" }
    }
    Update-Status "Ready"
})

$btnClearSessions.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show("This will log you out of ALL accounts. Continue?", "Confirm", "YesNo", "Warning")
    if ($confirm -eq "Yes") {
        $browsers = @()
        if ($chkChrome.IsChecked) { $browsers += "Chrome" }
        if ($chkEdge.IsChecked) { $browsers += "Edge" }
        if ($chkFirefox.IsChecked) { $browsers += "Firefox" }
        if ($chkBrave.IsChecked) { $browsers += "Brave" }
        if ($chkOpera.IsChecked) { $browsers += "Opera" }

        foreach ($browser in $browsers) {
            $result = Clear-BrowserSessions -Browser $browser
            if ($result.Success) { Write-Log "$browser sessions cleared" "SUCCESS" }
        }
    }
})

$btnRestorePermissions.Add_Click({
    $browsers = @()
    if ($chkChrome.IsChecked) { $browsers += "Chrome" }
    if ($chkEdge.IsChecked) { $browsers += "Edge" }
    if ($chkFirefox.IsChecked) { $browsers += "Firefox" }
    if ($chkBrave.IsChecked) { $browsers += "Brave" }
    if ($chkOpera.IsChecked) { $browsers += "Opera" }

    foreach ($browser in $browsers) {
        $result = Restore-BrowserPermissions -Browser $browser
        if ($result.Success) { Write-Log "$browser permissions restored" "SUCCESS" }
    }
})

# Network Events
$btnFindSuspicious.Add_Click({
    $lstNetworkResults.Items.Clear()
    Write-Log "Scanning for suspicious connections..." "INFO"
    $result = Find-SuspiciousConnections
    if ($result.Count -eq 0) {
        $lstNetworkResults.Items.Add("No suspicious connections found")
        Write-Log "No suspicious connections found" "SUCCESS"
    } else {
        foreach ($conn in $result.SuspiciousConnections) {
            $lstNetworkResults.Items.Add("$($conn.ProcessName) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($conn.Reasons -join ', ')]")
        }
        Write-Log "Found $($result.Count) suspicious connections" "WARNING"
    }
})

$btnViewConnections.Add_Click({
    $lstNetworkResults.Items.Clear()
    $result = Get-ActiveConnections -IncludeProcessName -ExcludeLocal
    foreach ($conn in $result.Connections) {
        $lstNetworkResults.Items.Add("$($conn.ProcessName) -> $($conn.RemoteAddress):$($conn.RemotePort)")
    }
    Write-Log "Listed $($result.Count) active connections" "INFO"
})

$btnEnableFirewallLog.Add_Click({
    $result = Enable-ConnectionLogging
    if ($result.Success) { Write-Log "Firewall logging enabled" "SUCCESS" }
    else { Write-Log "Error: $($result.Error)" "ERROR" }
})

# Defender Events
$btnEnableCFA.Add_Click({
    if (-not (Test-DefenderService)) {
        [System.Windows.MessageBox]::Show("Windows Defender is not running. Cannot enable CFA.", "Error", "OK", "Error")
        return
    }
    $result = Enable-ControlledFolderAccess
    if ($result.Success) {
        Write-Log "CFA enabled" "SUCCESS"
        $txtCFAStatus.Text = "Enabled"
        $txtCFAStatus.Foreground = "#28a745"
    }
})

$btnDisableCFA.Add_Click({
    if (Test-DefenderService) {
        $result = Disable-ControlledFolderAccess
        if ($result.Success) {
            Write-Log "CFA disabled" "WARNING"
            $txtCFAStatus.Text = "Disabled"
            $txtCFAStatus.Foreground = "#dc3545"
        }
    }
})

$btnApplyASR.Add_Click({
    if (-not (Test-DefenderService)) {
        [System.Windows.MessageBox]::Show("Windows Defender is not running.", "Error", "OK", "Error")
        return
    }
    $rules = @{
        CredentialStealing = $chkBlockCredentialStealing.IsChecked
        OfficeChildProcess = $chkBlockOfficeChildProcess.IsChecked
        ScriptObfuscation = $chkBlockScriptObfuscation.IsChecked
        ExecutableEmail = $chkBlockExecutableEmail.IsChecked
    }
    $result = Set-ASRRules -Rules $rules
    if ($result.Success) { Write-Log "ASR rules applied" "SUCCESS" }
    else { Write-Log "Error: $($result.Error)" "ERROR" }
})

$btnResetASR.Add_Click({
    if (Test-DefenderService) {
        Reset-ASRRules | Out-Null
        Write-Log "ASR rules reset" "SUCCESS"
        $chkBlockCredentialStealing.IsChecked = $false
        $chkBlockOfficeChildProcess.IsChecked = $false
        $chkBlockScriptObfuscation.IsChecked = $false
        $chkBlockExecutableEmail.IsChecked = $false
    }
})

# Quick Actions
$btnFullHarden.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show("Apply all protections?", "Confirm", "YesNo", "Question")
    if ($confirm -eq "Yes") {
        Write-Log "=== APPLYING FULL HARDENING ===" "INFO"

        Disable-USBAutorun | Out-Null
        Write-Log "USB Autorun disabled" "SUCCESS"

        Enable-PowerShellLogging | Out-Null
        Write-Log "PowerShell logging enabled" "SUCCESS"

        Protect-HostsFile | Out-Null
        Write-Log "Hosts file protected" "SUCCESS"

        $browsers = Get-InstalledBrowsers
        foreach ($b in $browsers.Keys | Where-Object { $browsers[$_] }) {
            Protect-BrowserCookies -Browser $b | Out-Null
            Write-Log "$b cookies protected" "SUCCESS"
        }

        Write-Log "=== HARDENING COMPLETE ===" "SUCCESS"
        [System.Windows.MessageBox]::Show("All protections applied!", "Success", "OK", "Information")
    }
})

$btnRevertAll.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show("Revert ALL changes?", "Confirm", "YesNo", "Warning")
    if ($confirm -eq "Yes") {
        Write-Log "=== REVERTING CHANGES ===" "WARNING"

        Enable-USBAutorun | Out-Null

        $browsers = Get-InstalledBrowsers
        foreach ($b in $browsers.Keys | Where-Object { $browsers[$_] }) {
            Restore-BrowserPermissions -Browser $b | Out-Null
        }

        if (Test-DefenderService) {
            Disable-ControlledFolderAccess | Out-Null
            Reset-ASRRules | Out-Null
        }

        Write-Log "=== CHANGES REVERTED ===" "SUCCESS"
    }
})

$Window.ShowDialog() | Out-Null
