
if (!(Test-Path "D:\Scheduled Tasks")) { New-Item -Path "D:\Scheduled Tasks" -ItemType Directory }
if (!(Test-Path "D:\SCRIPTS"        )) { New-Item -Path "D:\SCRIPTS"         -ItemType Directory }
if (!(Test-Path "D:\TEMP"           )) { New-Item -Path "D:\TEMP"            -ItemType Directory }
if (!(Test-Path "E:\NTDS\Data"      )) { New-Item -Path "E:\NTDS\Data"       -ItemType Directory }
if (!(Test-Path "E:\NTDS\Log"       )) { New-Item -Path "E:\NTDS\Log"        -ItemType Directory }
if (!(Test-Path "E:\Sysvol"         )) { New-Item -Path "E:\Sysvol"          -ItemType Directory }
if (!(Test-Path "Q:\BACKUP"         )) { New-Item -Path "Q:\BACKUP"          -ItemType Directory }
