<#
.Synopsis
   Sets the NTP server on PDC emulation role
.DESCRIPTION
   Sets the NTP server on PDC emulation role
.EXAMPLE
   .\Set-NtpServer.ps1
.EXAMPLE
   Set-NtpServer.ps1 -NtpServer "172.17.69.122,0x8 10.243.24.108,0x8"
.NOTES
   General notes
#>
[CmdletBinding(SupportsShouldProcess=$true)]

    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Parameter Set 1')]
        [string[]]$NtpServer=@("172.17.69.122","10.243.24.108")

    )

    Begin
    {
        [string[]]$NtpServerList=$NtpServer | % { "$_,0x8" }
        [string]$NtpServers = $NtpServerList -join " "
        $NtpServers
    }
    Process
    {
        $DomainRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
        Switch ($DomainRole) {
          5 {  # PDC emulator role on local machine.  But: is it also DC in the forest root?
                if ((Get-ADDomain).DNSRoot -eq (Get-ADForest).Name) {
                    if ($pscmdlet.ShouldProcess("PDC", "Update Sync to NTP server"))  {
                        W32TM /Config /Manualpeerlist:$NtpServers /SyncFromFlags:Manual /Reliable:Yes /Update
                    }
                } else {
                    if ($pscmdlet.ShouldProcess("PDC", "Update Sync to Domain hierarchy"))  {
                        W32TM /Config /SyncFromFlags:DOMHIER /Reliable:No /Update
                    }
                }
            }
        Default {
                    if ($pscmdlet.ShouldProcess("Non-PDC", "Update Sync to Domain hierarchy"))  {
                        W32TM /Config /SyncFromFlags:DOMHIER /Reliable:No /Update
                    }
            }
        }
    }
    End
    {
        W32TM /Query /Source
        W32TM /Query /Configuration
    }
