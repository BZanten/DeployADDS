<#
.Synopsis
   Sets Static IP address
.DESCRIPTION
.EXAMPLE
.NOTES
   Author : Ben van Zanten
   Company: Rabobank International
   Date   : Dec 2015
   Version: 1.0

   History:  1.0  Initial version
#>

[CmdletBinding(SupportsShouldProcess=$true, 
                  ConfirmImpact='High')]

    Param
    (
        # Name of the network adapter, for instance: Ethernet
        [Parameter(Mandatory=$true,Position=1, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false)]
        [string]$AdapterName,

    # local IPv4 address
    [Parameter(Mandatory=$true,Position=2)]
    [string]$IP,

    [Parameter(Mandatory=$true,Position=3)]
    [ValidateRange(8,30)]
    [string]$MaskBits,

    [Parameter(Mandatory=$true,Position=4)]
    [string]$GateWay,

    [Parameter(Mandatory=$false,Position=5)]
    [string[]]$DNSServer,

    [Parameter(Mandatory=$false)]
    [ValidateSet("IPv4","IPv6")]
    [string]$IpType="IPv4"
    )


Get-NetIPAddress -interfacealias ethernet
Get-NetAdapter
$Adapter = Get-NetAdapter -Name $AdapterName | Where-Object { $_.Status -eq "Up" }

# Remove existing IP address, gateway from our IPv4 adapter
if (($Adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
    $Adapter | Remove-NetIPAddress -AddressFamily $IpType
}
if (($Adapter | Get-NetIPConfiguration).IPv4DefaultGateway) {
    $Adapter | Remove-NetRoute -AddressFamily $IpType
}

$Adapter | New-NetIPAddress -AddressFamily $IpType -IPAddress $IP -PrefixLength $MaskBits -DefaultGateway $GateWay

if ($DNSServer) {
    $Adapter | Set-DnsClientServerAddress  -ServerAddresses $DNS
}

