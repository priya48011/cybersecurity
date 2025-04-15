<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Security event log is at least 1024000 KB.

.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-04-15
    Last Modified   : 2025-04-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000505

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-AU-000505
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$valName = "MaxSize"
$minSize = 1024000

if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

$current = (Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue).$valName

if ($null -eq $current -or $current -lt $minSize) {
    Set-ItemProperty -Path $regPath -Name $valName -Value $minSize -Type DWord
    Write-Host "Fixed: MaxSize set to $minSize KB."
} else {
    Write-Host "Compliant: MaxSize is $current KB."
}
