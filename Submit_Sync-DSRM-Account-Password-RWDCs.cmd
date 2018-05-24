Schtasks.exe /Create /TN "Sync-DSRM-Account-Password-RWDCs"  /TR "\"%~dp0Sync-DSRM-Account-Password-RWDCs.cmd\"" /RU "NT Authority\System" /SC Daily /ST 01:00
