# ShieldGuard

[![Security Scan](https://github.com/caiolombello/ShieldGuard/actions/workflows/security-scan.yml/badge.svg)](https://github.com/YOUR_USERNAME/ShieldGuard/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)

**Windows Security Hardening Tool** - Open source tool to protect against infostealers, ransomware, and malware.

> **Trust but verify**: All code is open source, automatically scanned for malicious patterns, and releases include SHA256 checksums. See [SECURITY.md](SECURITY.md) for details.

## About

ShieldGuard simplifies Windows security configurations that most users don't know exist. It enables native protections that make it significantly harder for malware to steal your data.

### Key Features

- **Browser Cookie Protection** - Restricts access to session tokens and saved passwords
- **System Hardening** - Disables vulnerable protocols and enables security logging
- **Network Monitoring** - Detects suspicious connections and potential data exfiltration
- **Startup/Task Scanner** - Identifies malware persistence mechanisms
- **Works with ANY antivirus** - Kaspersky, Norton, Avast, or Windows Defender

## Why This Tool?

Traditional antivirus is **reactive** - it detects threats after they run. By then, an infostealer may have already:

- Stolen browser session tokens (bypassing 2FA)
- Extracted saved passwords
- Exfiltrated data to attacker servers

ShieldGuard adds **proactive layers** that block these attacks before damage is done.

## Installation

### Requirements
- Windows 10/11
- PowerShell 5.1+
- Administrator privileges

### Quick Start

1. Download or clone this repository
2. Right-click `Run.bat` → **Run as administrator**

Or via PowerShell (as Admin):
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\src\Main.ps1
```

## Features

### System Hardening (Works with any AV)

| Feature | Description |
|---------|-------------|
| USB Autorun Protection | Blocks malware spread via USB drives |
| SMBv1 Disable | Removes WannaCry vulnerability |
| PowerShell Logging | Records all script execution for forensics |
| Remote Desktop Disable | Closes common attack vector |
| Hosts File Protection | Prevents DNS hijacking |
| Startup Scanner | Detects suspicious autorun entries |
| Scheduled Tasks Scanner | Finds malware persistence |

### Browser Protection

| Feature | Description |
|---------|-------------|
| Cookie Directory ACL | Restricts access to session tokens |
| Login Data Protection | Protects saved passwords |
| Session Clearing | Logout everywhere after compromise |
| Multi-browser Support | Chrome, Edge, Firefox, Brave, Opera |

### Network Monitor

| Feature | Description |
|---------|-------------|
| Suspicious Connection Detection | Identifies potential C2 connections |
| Process Network Analysis | Shows which apps are connecting where |
| Firewall Logging | Enables detailed connection logs |

### Windows Defender Features (Requires Defender)

| Feature | Description |
|---------|-------------|
| Controlled Folder Access | Ransomware protection |
| ASR Rules | Blocks credential theft, malicious scripts |

## Project Structure

```
ShieldGuard/
├── src/
│   └── Main.ps1                    # Main GUI (WPF)
├── modules/
│   ├── SystemHardening.ps1         # System protections
│   ├── BrowserProtection.ps1       # Browser security
│   ├── NetworkMonitor.ps1          # Network analysis
│   ├── ControlledFolderAccess.ps1  # Ransomware protection
│   └── ASRRules.ps1                # Attack Surface Reduction
├── TestCookieAccess.ps1            # Test if protection works
├── Run.bat                         # Quick launcher
└── README.md
```

## Testing Protection

Run the included test script to verify cookie protection:

```powershell
.\TestCookieAccess.ps1
```

This simulates what an infostealer would do and shows if your browsers are protected.

## Command Line Usage

```powershell
# Import modules
. .\modules\SystemHardening.ps1
. .\modules\BrowserProtection.ps1

# Protect Chrome cookies
Protect-BrowserCookies -Browser "Chrome"

# Disable USB autorun
Disable-USBAutorun

# Find suspicious connections
Find-SuspiciousConnections

# Scan startup items
Find-SuspiciousStartupItems
```

## Limitations

This tool **is not an antivirus** and does not replace one. It:

- Makes attacks harder, not impossible
- Cannot protect against malware running as Administrator
- May cause false positives with some legitimate software
- Some features require Windows Defender

## If You Were Compromised

1. **Immediately:** Disconnect from internet, change ALL passwords from a clean device
2. **Revoke sessions:** Gmail, Discord, GitHub, etc. have "Sign out all devices" options
3. **Enable 2FA:** On all accounts that support it
4. **Scan:** Full antivirus scan, consider Windows reinstall
5. **Report:** File a police report if financial loss occurred

## Contributing

Contributions welcome! Please:

1. Fork the project
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This software is provided "as is" without warranty. Use at your own risk. The author is not responsible for any damages caused by using this tool.

---

**Protecting what matters.**
