<#
.SYNOPSIS
    This PowerShell script ensures that the Camera access from the lock screen is disabled.

.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-04-18
    Last Modified   : 2025-04-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-CC-000005
#>

# Define the base registry path
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"

# Ensure the registry path exists
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force
}

# STIG: WN10-CC-000010 - Disable Lock Screen Slideshow
Set-ItemProperty -Path $registryPath -Name "NoLockScreenSlideshow" -Value 1 -Type DWord

# STIG: WN10-CC-000005 - Disable Lock Screen Camera
Set-ItemProperty -Path $registryPath -Name "NoLockScreenCamera" -Value 1 -Type DWord

Write-Host "STIGs WN10-CC-000010 and WN10-CC-000005 have been remediated."
