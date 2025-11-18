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

# Export current local security policy
secedit.exe /export /cfg C:\Windows\Temp\secpol.cfg

# Set Account Lockout Threshold to 3 attempts
(Get-Content C:\Windows\Temp\secpol.cfg) `
    -replace 'LockoutBadCount = \d+', 'LockoutBadCount = 3' |
    Set-Content C:\Windows\Temp\secpol.cfg

# Apply updated security policy
secedit.exe /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY

# Cleanup
Remove-Item C:\Windows\Temp\secpol.cfg -Force
