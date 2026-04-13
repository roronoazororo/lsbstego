# Create key
New-Item -Path "HKCU:\Software\MyTestKey" -Force

# Add a string value
New-ItemProperty -Path "HKCU:\Software\MyTestKey" `
  -Name "TestValue" `
  -Value "pti wrote this" `
  -PropertyType String `
  -Force
