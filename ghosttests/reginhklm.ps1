# Define the registry path
$regPath = "HKLM:\Software\PTITestLA"

# Create the registry key (requires admin)
New-Item -Path $regPath -Force | Out-Null

# Add a string value inside the key
New-ItemProperty -Path $regPath -Name "Message" -Value "PTI WFI was here as admin" -PropertyType String -Force | Out-Null

# Optional: confirm
Write-Host "Registry key and value created at $regPath"