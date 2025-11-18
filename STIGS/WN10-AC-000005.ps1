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

# Enable Failure auditing for Credential Validation
auditpol /set /subcategory:"Credential Validation" /failure:enable

Write-Host "WN10-AU-000005 remediated: 'Credential Validation' now audits Failure events."
