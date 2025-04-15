<#
.SYNOPSIS
    This PowerShell script ensures that the WDigest Authentication is disabled.

.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-04-15
    Last Modified   : 2025-04-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000038

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-CC-000038
#>

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest"
$valName = "UseLogonCredential"
$desiredValue = 0

if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

$currentValue = (Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue).$valName

if ($null -eq $currentValue -or $currentValue -ne $desiredValue) {
    Set-ItemProperty -Path $regPath -Name $valName -Value $desiredValue -Type DWord
    Write-Host "Fixed: UseLogonCredential set to 0 (disabled)."
} else {
    Write-Host "Compliant: UseLogonCredential is already set to 0."
}
