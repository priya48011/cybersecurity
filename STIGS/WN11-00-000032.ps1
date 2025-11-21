<#
.SYNOPSIS
    This PowerShell script ensures that the Windows 11 systems use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.

.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-11-21
    Last Modified   : 2025-11-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000032

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN11-00-000032
#>

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
    -Name "MinimumPIN" -Value 6 -PropertyType DWord -Force

