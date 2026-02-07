# Security Policy

## Why Trust This Project?

ShieldGuard is designed with transparency in mind. Here's how you can verify it's safe:

### 1. Open Source Code

All code is publicly visible. You can read every line before running:

- `src/Main.ps1` - GUI interface
- `modules/*.ps1` - All security functions

### 2. Automated Security Scanning

Every commit and release is automatically scanned for:

| Check | Description |
|-------|-------------|
| PSScriptAnalyzer | PowerShell best practices and security rules |
| Secret Detection | Scans for hardcoded passwords, API keys, tokens |
| Malicious Patterns | Detects download-and-execute, encoded commands |
| Syntax Validation | Ensures all scripts are valid PowerShell |

See our [GitHub Actions](../../actions) for scan results.

### 3. Verified Releases

Each release includes:

- `SHA256SUMS.txt` - Hashes of all source files
- `RELEASE-SHA256.txt` - Hash of the ZIP package

**Verify before running:**

```powershell
# After downloading, check the hash
$expected = "HASH_FROM_RELEASE_PAGE"
$actual = (Get-FileHash "ShieldGuard-v1.0.0.zip" -Algorithm SHA256).Hash

if ($expected -eq $actual) {
    Write-Host "Verified!" -ForegroundColor Green
} else {
    Write-Host "WARNING: Hash mismatch!" -ForegroundColor Red
}
```

### 4. No Network Calls

ShieldGuard does NOT:

- Connect to the internet
- Send telemetry
- Download additional code
- Phone home to any server

All functionality is local and offline.

### 5. No Obfuscation

The code contains:

- No encoded/encrypted strings
- No minification
- No packed executables
- Clear, readable PowerShell

## What This Tool Does

ShieldGuard modifies Windows security settings:

| Action | Registry/System Change |
|--------|----------------------|
| Disable USB Autorun | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` |
| Disable SMBv1 | Windows Optional Feature |
| PowerShell Logging | Group Policy registry keys |
| Browser ACLs | File system permissions on cookie directories |
| Hosts Protection | File permissions on `%SystemRoot%\System32\drivers\etc\hosts` |

All changes are reversible via the "Revert" button or manually.

## Reporting Security Issues

Found a vulnerability? Please report responsibly:

1. **DO NOT** open a public issue
2. Email: [Create a private security advisory](../../security/advisories/new)
3. Include:
   - Description of the issue
   - Steps to reproduce
   - Potential impact

We will respond within 48 hours.

## Code Review Checklist

Before running, you can verify:

```powershell
# 1. Check for network calls
Select-String -Path .\**\*.ps1 -Pattern "WebRequest|WebClient|Invoke-RestMethod|DownloadString|DownloadFile" -Recurse

# 2. Check for encoded commands
Select-String -Path .\**\*.ps1 -Pattern "-enc|-EncodedCommand|FromBase64String" -Recurse

# 3. Check for execution of external code
Select-String -Path .\**\*.ps1 -Pattern "Invoke-Expression|IEX|\.Invoke\(" -Recurse
```

If any of these return suspicious results, do not run the tool.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## License

MIT License - You can audit, modify, and redistribute freely.
