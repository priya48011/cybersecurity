<#
.SYNOPSIS
    This PowerShell script ensures that the display of slide shows on the lock screen is disabled.
.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-CC-000010
#>

# Define registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$valueName = "NoLockScreenSlideshow"
$valueData = 1

# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

# Set the registry value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Host "STIG WN10-CC-000010 has been remediated. NoLockScreenSlideshow set to 1."
