<#
.SYNOPSIS
    This PowerShell script ensures that the enhanced diagnostic data is limited to the minimum required to support Windows Analytics.
.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-11-21
    Last Modified   : 2025-11-21
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000204

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN11-CC-000204
#>


New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
    -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Value 1 -PropertyType DWord -Force


