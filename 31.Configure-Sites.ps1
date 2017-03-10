<#
.Synopsis
.DESCRIPTION
.EXAMPLE
.\Configure-Sites.ps1 -XmlFile ADStructure_RaboSvc.com.xml -Verbose
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
        [string]$XmlFile='.\ADStructure.xml',

    # Name of the domain. For instance  rabonet,  eu, am, ap or oc. If not given, the domain from the XML is used
    [Parameter(Mandatory=$False,Position=2)]
    [string]$DomainName
    )

    Begin {
        Import-Module .\DeployAdLib.psd1
        # Test for elevation :
        if (-not(Test-AdminStatus)) {
#           Write-Error "Run this script elevated! This script requires administrative permissions."
#           break
        }
        $domName = Get-DomainName -XmlFile $XmlFile -DomainName $DomainName
        [xml]$forXML = Get-Content $XmlFile
        $domXML = $forXML.forest.domains.domain | ? { $_.name -eq $domName }

    }

    Process
    {

        #
        #  Sites : Rename Default-First-Site-Name  to EUBXT
        #
        If (Get-ADObject -SearchBase "CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -LDAPFilter "(&(objectClass=site)(name=Default-First-Site-Name))") {
            $SchemaServer = $forXML.forest.parameters.FSMO.Schema
            $FirstSite = $forXML.forest.sites.site | Where-Object { $_.servers.server.name -eq $SchemaServer }
            Write-Verbose "Renaming Default-First-Site-Name to site: $($FirstSite.name)"

            Rename-ADObject "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -NewName $FirstSite.name
            Start-Sleep -Seconds 5
        }

        #
        # Process the Sites...
        #
        ForEach ($Site in $forxml.forest.sites.site) {
            #
            # Create the site if it doesn't exist yet...
            #
            If (!(Get-ADObject -SearchBase "CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -LDAPFilter "(&(objectClass=site)(name=$($Site.name)))")) {
                Write-Verbose "Creating new site: $($Site.name)"
                New-ADObject -Name "$($Site.name)" -Type site -Path "CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)"
            } else {
                Write-Verbose "Site: $($Site.name) already exists."
            }


            if ($Site.NTDSSiteSettings -is [object]) {
                if (!(Get-ADObject -SearchBase "CN=$($Site.name),CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -LDAPFilter "(objectClass=nTDSSiteSettings)" -ErrorAction SilentlyContinue)) {
                    New-ADObject -Name "NTDS Site Settings" -Type nTDSSiteSettings -Path "CN=$($Site.name),CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)"
                }
            }
            if ($Site.LicensingSiteSettings -is [object]) {
                if (!(Get-ADObject -SearchBase "CN=$($Site.name),CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -LDAPFilter "(objectClass=licensingSiteSettings)" -ErrorAction SilentlyContinue)) {
                    New-ADObject -Name "Licensing Site Settings" -Type licensingSiteSettings -Path "CN=$($Site.name),CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)"
                }
            }
            if ($Site.servers -is [object]) {
                if (!(Get-ADObject -SearchBase "CN=$($Site.name),CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -LDAPFilter "(objectClass=serversContainer)" -ErrorAction SilentlyContinue)) {
                    New-ADObject -Name "Servers" -Type serversContainer -Path "CN=$($Site.name),CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)"
                }
            }

            #
            # Move DC's in this site...
            #
            ForEach ($DCServer in $Site.servers.server) {
                Write-Verbose "Moving Site Server $($Site.name)  to site $($Site.name)... "
                Move-ADDirectoryServer -Identity $DCServer.name -Site $Site.name
            }

        }


        #
        # Process the subnets...
        #
        ForEach ($Subnet in $forxml.forest.subnets.subnet) {

            #
            # Create the site if it doesn't exist yet...
            #
            If (!(Get-ADObject -SearchBase "CN=Subnets,CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -LDAPFilter "(&(objectClass=subnet)(name=$($Subnet.name)))")) {
                Write-Verbose "Creating new subnet: $($Subnet.name)"
                $SubnetHT = Convert-XmlToHT $Subnet
                $SubnetHT["Path"]="CN=Subnets,CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)"
                $SubnetHT["type"]='subnet'
                $SubnetHT
                New-ADObject @SubnetHT
            } else {
                Write-Verbose "Subnet: $($Subnet.name) already exists."
            }
        }

        #
        # Site Links...
        #
        if (Get-ADObject -SearchBase "CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -LDAPFilter "(&(objectClass=siteLink)(name=DEFAULTIPSITELINK))") {
            Rename-ADObject "CN=DEFAULTIPSITELINK,CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)"  -NewName @($forxml.forest.sites.sitelinks.sitelink)[0].name
        }

        ForEach ($SiteLink in $forxml.forest.sites.sitelinks.sitelink) {
            #
            # Get the properties...
            #
            $siteLinkHT = Convert-XmlToHT $siteLink

            #
            # Create the site if it doesn't exist yet..., modify if it exists
            #
            $ADSiteLink = Get-ADObject -SearchBase "CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -LDAPFilter "(&(objectClass=siteLink)(name=$($SiteLink.name)))"
            If (!($ADSiteLink)) {
                Write-Verbose "Creating new siteLink: $($SiteLink.name)"
                $siteLinkHT["Path"]="CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)"
                $siteLinkHT["type"]='siteLink'
                New-ADObject @siteLinkHT
            } else {
                Write-Verbose "siteLink: $($SiteLink.name) already exists."
                # Change some CmdLet Parameters..  in New-ADObject : -OtherAttributes  is in Set-ADObject : -Replace
                $siteLinkHT["Replace"] = $siteLinkHT["OtherAttributes"]
                $siteLinkHT.Remove("OtherAttributes")
                #    in New-ADObject  -Path  -name  is now -Identity
                $siteLinkHT.Remove("Path")
                $siteLinkHT.Remove("name")
                $siteLinkHT["Identity"] = $ADSiteLink
                Set-ADObject  @siteLinkHT
            }

        }

        Get-ADObject -SearchBase "CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,$($forxml.forest.distinguishedName)" -LDAPFilter "(objectClass=siteLink)" -Properties siteList,replInterval,cost,options,Description | Format-Table -Property Name,replInterval,cost,options,siteList -AutoSize

    }
