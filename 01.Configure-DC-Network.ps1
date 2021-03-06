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
        [string]$XmlFile='.\ADStructure.xml',

    # Name of the domain. For instance  rabonet,  eu, am, ap or oc. If not given, the domain from the XML is used
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
	$domXML = $forXML.forest.domains.domain | ? { $_.name -eq $domName }

	Write-Verbose "Extracted domain name from $XmlFile  is : $domName"
}

Process {
	Get-NetAdapter

	$ComputerName = [System.Environment]::MachineName
	$MyXML = $domXML.DCs.DC | Where-Object { $_.Name -eq $ComputerName }
        if (!($MyXML)) {
          $MyMacs = ( Get-NetAdapter | Select-Object -Property MacAddress ).MacAddress
          $MyXML = $domXML.DCs.DC | Where-Object { $_.Nics.nic.MacAddress -in ( $MyMacs ) }
          if ($MyXML) {
            $NewComputerName = $MyXML.Name
            Write-Host "DC name $ComputerName not found in XML, Computername $NewComputerName found from MAC address. Renaming computer..."
            Rename-Computer -ComputerName . -NewName $NewComputerName
          }
        }

	if ($MyXML) {
		ForEach ($Nic in ($MyXML.NICS.NIC)) {
			$Nic
			$NicAdapter = Get-NetAdapter | Where-Object { $_.MacAddress -eq $Nic.MacAddress }
			if ($NicAdapter) {
			    Write-Verbose "Adapter $($Nic.MacAddress) found"
			    if ($NicAdapter.Name -ne $Nic.Name) {
				Write-Verbose "Renaming.. NIC from $($NicAdapter.Name) to $($Nic.Name)"
				Rename-NetAdapter -Name $NicAdapter.Name -NewName $Nic.Name
			        Write-Verbose "Renaming Done"
			    } else {
				Write-Verbose "Not Renaming NIC: $($Nic.Name) ..."
			    }

			    $ParamsHT = Convert-XmlToHT $myxml.NICS.NIC.NetIPAddress
			    $ParamsHT["InterfaceIndex"] = $NicAdapter.ifIndex
			    $ParamsHT.Remove("Name")
                            Write-Verbose "NetIPAddress hashtable:"
			    $ParamsHT
			    New-NetIPAddress @ParamsHT
			    $ParamsHT.Remove("DefaultGateway")
			    Set-NetIPAddress @ParamsHT

			    $ParamsHT = Convert-XmlToHT $myxml.NICS.NIC.DnsClient
			    $ParamsHT["InterfaceIndex"] = $NicAdapter.ifIndex
			    $ParamsHT.Remove("Name")
                            Write-Verbose "DnsClient hashtable:"
			    $ParamsHT
			    Set-DnsClient @ParamsHT

			    $ParamsHT = Convert-XmlToHT $myxml.NICS.NIC.DnsClientServerAddress
			    $ParamsHT["InterfaceIndex"] = $NicAdapter.ifIndex
			    $ParamsHT.Remove("Name")
                            Write-Verbose "DnsClient hashtable:"
			    $ParamsHT
			    Set-DnsClientServerAddress @ParamsHT

			} else {
			    Write-Output "Adapter $($Nic.MacAddress) not found !"
			}
		}
	} else { 
	  Write-Error " DC $ComputerName not found in XML - Domains - Domain - DCs - DC"
	}

	# Enable Ping and filesharing...
	# netsh advfirewall firewall set rule group="File and Printer Sharing" New Enable=yes
	# Enable RDP...
	# netsh advfirewall firewall set rule group="Remote Desktop" New Enable=yes
	Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
	Enable-NetFirewallRule -DisplayGroup "Windows Firewall Remote Management"
	Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
	Enable-NetFirewallRule -DisplayGroup "Remote Event Monitor"
	Enable-NetFirewallRule -DisplayGroup "Remote Event Log Management"
	Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
	Enable-NetFirewallRule -DisplayGroup "Remote Volume Management"
	Enable-NetFirewallRule -DisplayGroup "Remote Service Management"

	#
	# Enable RDP Remote Desktop
	#
	$RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
	(Get-ItemProperty $RegPath -Name fDenyTSConnections).fDenyTSConnections
	Set-ItemProperty $RegPath -Name fDenyTSConnections -Value 0
	(Get-ItemProperty $RegPath -Name fDenyTSConnections).fDenyTSConnections

	$RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
	(Get-ItemProperty $RegPath -Name UserAuthentication).UserAuthentication
 	 Set-ItemProperty $RegPath -Name UserAuthentication -Value 0
	(Get-ItemProperty $RegPath -Name UserAuthentication).UserAuthentication

	Get-NetAdapter

	ipconfig /all

}
