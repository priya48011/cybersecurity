<#
.SYNOPSIS
    This PowerShell script ensures that the minimum password age is configured to at least 1 day.
.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-11-17
    Last Modified   : 2025-11-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000030

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-AC-000030
#>


# Set Minimum Password Age to 1 day
net accounts /minpwage:1

Write-Host "WN10-AC-000030 remediated: Minimum password age set to 1 day."
