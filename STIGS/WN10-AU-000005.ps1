<#
.SYNOPSIS
    This PowerShell script ensures that system is configured to audit Account Logon - Credential Validation failures.
.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-11-17
    Last Modified   : 2025-11-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-AU-000005
#>


# Enable Failure auditing for Credential Validation
auditpol /set /subcategory:"Credential Validation" /failure:enable

Write-Host "WN10-AU-000005 remediated: 'Credential Validation' now audits Failure events."
