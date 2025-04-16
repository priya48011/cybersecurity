
# Define the registry path and values
$registryPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
$valueName = "AutoConnectAllowedOEM"
$valueData = 0
$valueType = "DWord"

# Create the registry key if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the registry value
New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType $valueType -Force

# Confirm the value was set
Get-ItemProperty -Path $registryPath -Name $valueName
