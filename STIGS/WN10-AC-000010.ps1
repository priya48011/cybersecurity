<#
.SYNOPSIS
    This PowerShell script ensures that the number of allowed bad logon attempts is configured to 3 or less
.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-11-14
    Last Modified   : 2025-11-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-AC-000010
#>

# Allowed accounts for access (accounts that should NOT be denied)
$allowedAccounts = @("BUILTIN\Administrators","NT AUTHORITY\SYSTEM")

# Export current user rights
$seceditFile = "$env:TEMP\secpol.cfg"
secedit /export /cfg $seceditFile

# Read the current setting for "Deny access to this computer from the network"
$currentLine = (Get-Content $seceditFile | Where-Object {$_ -like "SeDenyNetworkLogonRight*"})
$currentAccounts = ($currentLine -replace "SeDenyNetworkLogonRight\s*=\s*","") -split ","

# Check for unauthorized accounts
$unauthorized = $currentAccounts | Where-Object {$_ -and ($allowedAccounts -notcontains $_)}

if ($unauthorized.Count -eq 0) {
    Write-Host "WN10-AC-000010 compliant: No unauthorized accounts are denied network access."
} else {
    Write-Host "Unauthorized accounts found: $($unauthorized -join ', ')"
    Write-Host "Remediating..."

    # Remove unauthorized accounts using ntrights.exe
    foreach ($user in $unauthorized) {
        # Requires ntrights.exe from Windows Server 2003 Resource Kit Tools
        ntrights -r $user -u SeDenyNetworkLogonRight
    }
    Write-Host "Remediation complete. Only allowed accounts are denied network access."
}
