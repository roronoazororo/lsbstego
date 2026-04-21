# Get the path to the current user's Desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")

# Define the file path with the desired name
$filePath = Join-Path $desktopPath "haha.txt"

# Write content to the file
"PTI WFI was here." | Out-File -FilePath $filePath -Encoding UTF8

# Optional: confirm
Write-Host "File created at: $filePath"