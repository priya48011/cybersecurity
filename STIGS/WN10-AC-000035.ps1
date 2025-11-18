<#
.SYNOPSIS
    This PowerShell script ensures that the Passwords are, at a minimum, of 14 characters.
.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-11-17
    Last Modified   : 2025-11-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000035

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-AC-000035
#>


# Set Minimum Password Length to 14
net accounts /minpwlen:14

Write-Host "WN10-AC-000035 remediated: Minimum password length set to 14 characters."

