# cscript C:\Windows\System32\slmgr.vbs /ipk 9MTR9-VND24-6T76X-W4M24-Q9KCM

New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name PowerShell -PropertyType String -Value "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe"

# Enable-PSRemoting -Force

