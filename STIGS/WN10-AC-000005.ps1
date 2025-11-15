<#
.SYNOPSIS
    This PowerShell script ensures that the Window 10 account lockout duration is configured to 15 minutes or longer
.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-11-14
    Last Modified   : 2025-11-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-AC-000005
#>

# Allowed accounts/groups for SeSystemtimePrivilege
$allowedAccounts = @("BUILTIN\Administrators","NT AUTHORITY\LOCAL SERVICE","NT SERVICE\W32Time")

# Export current user rights
$seceditFile = "$env:TEMP\secpol.cfg"
secedit /export /cfg $seceditFile

# Read the current setting
$currentLine = (Get-Content $seceditFile | Where-Object {$_ -like "SeSystemtimePrivilege*"})
$currentAccounts = ($currentLine -replace "SeSystemtimePrivilege\s*=\s*","") -split ","

# Check for unauthorized accounts
$unauthorized = $currentAccounts | Where-Object {$_ -and ($allowedAccounts -notcontains $_)}

if ($unauthorized.Count -eq 0) {
    Write-Host "WN10-AC-000005 compliant: No unauthorized accounts have 'Change the system time'."
} else {
    Write-Host "Unauthorized accounts found: $($unauthorized -join ', ')"
    Write-Host "Remediating..."

    # Remove unauthorized accounts using ntrights.exe
    foreach ($user in $unauthorized) {
        # Requires ntrights.exe from Windows Server 2003 Resource Kit Tools
        ntrights -r $user +r SeSystemtimePrivilege
    }
    Write-Host "Remediation complete. Only allowed accounts have the privilege."
}

