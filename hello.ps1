Start-Process notepad.exe
Start-Sleep -Seconds 1

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.SendKeys]::SendWait("pti wrote this")
