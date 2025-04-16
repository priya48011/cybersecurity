<#
.SYNOPSIS
    This PowerShell script ensures that the Windows 10 is configured to prevent users from receiving suggestions for 
    third-party or additional applications.

.NOTES
    Author          : Priya
    LinkedIn        : https://www.linkedin.com/in/priya-priya-a36a94222/ 
    GitHub          : https://github.com/priya48011/cybersecurity
    Date Created    : 2025-04-16
    Last Modified   : 2025-04-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000390

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  
    PS C:\> .\STIG-ID-WN10-CC-000390

#>

# Define the registry path and values for current user
$registryPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$valueName = "DisableThirdPartySuggestions"
$valueData = 1
$valueType = "DWord"

# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the registry value
New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType $valueType -Force

# Confirm the value was set
Get-ItemProperty -Path $registryPath -Name $valueName
