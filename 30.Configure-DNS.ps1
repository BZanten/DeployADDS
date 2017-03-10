<#
.Synopsis
.DESCRIPTION
 This script configures DNS Zones, by creating DNS zones where needed, it configures Aging on the DNS zones
 And it configures Server Scavenging on the DNS server that is also PDC for the domain.

 It does not configure DNS forwarding.
.EXAMPLE
.\Configure-DNS.ps1 -XmlFile .\ADStructure_RaboSvc.com.xml -Verbose
.NOTES
   Author : Ben van Zanten
   Company: Rabobank International
   Date   : Dec 2015
   Version: 1.0

   History:  1.0  Initial version
#>

[CmdletBinding(SupportsShouldProcess=$true, 
                  ConfirmImpact='Medium')]

    Param
    (
        # Name of the input file, default is: ADStructure.xml
        [Parameter(Mandatory=$false,Position=1, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false, 
                   ValueFromRemainingArguments=$false)]
                   [ValidateScript({Test-Path $_})]
        [string]$XmlFile='.\ADStructure_RaboSvc.com.xml',

    # Name of the domain. For instance  rabonet,  eu, am, ap or oc. If not given, the domain from the XML is used. The XML file supports multiple domains.
    [Parameter(Mandatory=$False,Position=2)]
    [string]$DomainName
    )

    Begin {
        Import-Module .\DeployAdLib.psd1
        # Test for elevation :
        if (-not(Test-AdminStatus)) {
            Write-Error "Run this script elevated! This script requires administrative permissions."
            break
        }
        $domName = Get-DomainName -XmlFile $XmlFile -DomainName $DomainName
        [xml]$forXML = Get-Content $XmlFile
        $domXML = $forXML.forest.domains.domain | Where-Object { $_.name -eq $domName }
        $dcXML = $domXML.DCs.DC | Where-Object { $_.Name -eq $Env:ComputerName }
    }

    Process
    {

        #
        #  Create & Configure Domain DNS zones.
        #
        #  (Todo: onderscheid maken tussen forest en domain based zones?
        #
#       Set-DnsServerZoneAging -Name "$($domXML.dnsname)"        -Aging $True -RefreshInterval "7.00:00:00" -NoRefreshInterval "7.00:00:00"
#       Set-DnsServerZoneAging -Name "_MSDCS.$($domXML.dnsname)" -Aging $True -RefreshInterval "7.00:00:00" -NoRefreshInterval "7.00:00:00"
        ForEach ($Zone in $domXML.DNS.zones.zone) {
            $ZoneHT = Convert-XmlToHT $Zone
            $ZoneHT.Remove("Aging")
            $ZoneAgingHT = Convert-XmlToHT $Zone.Aging
            $ExistingZone = Get-DnsServerZone -Name $Zone.name -ErrorAction SilentlyContinue
            if ($ExistingZone) {
                Write-Verbose "Zone $($Zone.name) already exists. Setting aging."
                $ZoneAgingHT["name"] = $Zone.name
                Set-DnsServerZoneAging @ZoneAgingHT
            } else {
                if ($ZoneHT.NetworkID) {
                    Write-Verbose "Adding zone $($Zone.NetworkID)"
                    $ZoneHT.Remove("name")
                } else {
                    Write-Verbose "Adding zone $($Zone.name)"
                }
                $DnsRevZone = Add-DnsServerPrimaryZone @ZoneHT -PassThru -ErrorAction SilentlyContinue
                if ($DnsRevZone) {
                    $ZoneAgingHT["name"] = $DnsRevZone.ZoneName
                    Set-DnsServerZoneAging @ZoneAgingHT
                }
            }
        }

        #
        # Add Reverse lookup zones.. NOT done using subnets... a /25 subnet cannot be used in DNS rev lookup zone, must be converted to /24
        #
    #     ForEach ($Subnet in $forXML.forest.subnets.subnet) {
    #         Write-Verbose "Adding zone $($Subnet.name)"
    #         $DnsRevZone = Add-DnsServerPrimaryZone -NetworkId $Subnet.name -ReplicationScope Domain -DynamicUpdate Secure -PassThru -ErrorAction SilentlyContinue
    #         if ($DnsRevZone) {
    #             Set-DnsServerZoneAging -Name $DnsRevZone.ZoneName -Aging $True -RefreshInterval "7.00:00:00" -NoRefreshInterval "7.00:00:00"
    #         }
    #     }

        #
        # Configure all remaining DNS zones with Aging
        #   Uitgezet.. de Zones hebben in de XML al Aging informatie... dan moeten ze allemaal maar in de XML komen.
        #
        # Get-DnsServerZone | Where-Object { $_.ZoneName -notin "0.in-addr.arpa","127.in-addr.arpa","255.in-addr.arpa" } | Set-DnsServerZoneAging -Aging $True -RefreshInterval "7.00:00:00"  -NoRefreshInterval "7.00:00:00"


        #
        # Configure Server scavenging on the First DC (PDC FSMO) in the domain
        #
        if ($Env:ComputerName -eq $domXML.parameters.FSMO.PDC) {
            Write-Verbose "Enabling DNS Server scavenging on the local machine..."
            Set-DnsServerScavenging -ScavengingState $True -ApplyOnAllZones -ScavengingInterval "7.00:00:00"
        }

        Write-Host  "`nCurrent Zone & Aging settings:"
        Get-DnsServerZone | Where-Object { $_.ZoneType -eq 'Primary' } | Get-DnsServerZoneAging | Format-Table ZoneName,AgingEnabled,RefreshInterval,NoRefreshInterval -AutoSize
        Write-Host  "Current Scavenging settings:"
        Get-DnsServerScavenging

        #
        # Configure Server (Conditional) Forwarding...
        #
        Write-Output "Enabling Forwarders..."
        ForEach ($Forwarder in $dcXML.DNS.Forwarders) {
            $ForwHT = Convert-XmlToHT $Forwarder
            $ForwHT.Remove("name")
            # Convert IPAddress  (comma separated) to an array...
            $IPs = $ForwHT["IPAddress"]
            $ForwHT.Remove("IPAddress")
            $ForwHT["IPAddress"]=$IPs.Split(',')
            $ForwHT | FT *

            Set-DnsServerForwarder @ForwHT
        }

        Write-Output "Enabling Conditional Forwarders..."
        ForEach ($CF in $dcXML.DNS.ConditionalForwarders.ConditionalForwarder) {
            $ForwHT = Convert-XmlToHT $CF
            $ForwHT.Remove("#comment")
            # Convert IPAddress  (comma separated) to an array...
            $IPs = $ForwHT["MasterServers"]
            $ForwHT.Remove("MasterServers")
            $ForwHT["MasterServers"]=$IPs.Split(',')
            Write-Output "Enabling Conditional Forwarder with properties:"
            $ForwHT | FT *

            if ($ForwHT.ReplicationScope -match 'Custom') {
                Try {
                    $DnsPart = Get-DnsServerDirectoryPartition -Name $ForwHT.DirectoryPartitionName -ErrorAction SilentlyContinue
                } catch { }
                if (!($DnsPart)) {
                    "DNS partition $($ForwHT.DirectoryPartitionName) does not exist.. creating it"
                    Add-DnsServerDirectoryPartition -Name "$($ForwHT.DirectoryPartitionName)"
                }
                if (!((Get-DnsServerDirectoryPartition  -Name $ForwHT.DirectoryPartitionName ).Flags -Match 'Enlisted')) {
                    Register-DnsServerDirectoryPartition -Name "$($ForwHT.DirectoryPartitionName)"
                }
            }
            
            Try {
                $ForwarderZone = Get-DnsServerZone -Name $ForwHT.Name -ErrorAction SilentlyContinue
            } catch { }
            if (!($ForwarderZone)) {
                Add-DnsServerConditionalForwarderZone @ForwHT
            }
        }

    }
