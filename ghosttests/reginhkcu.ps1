# Define the registry path
$regPath = "HKCU:\Software\PTITest"

# Create the registry key (if it doesn't exist)
New-Item -Path $regPath -Force | Out-Null

# Add a string value inside the key
New-ItemProperty -Path $regPath -Name "Message" -Value "PTI WFI was here" -PropertyType String -Force | Out-Null

# Optional: confirm
Write-Host "Registry key and value created at $regPath"