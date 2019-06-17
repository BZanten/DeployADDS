<#
.Synopsis
.DESCRIPTION
.EXAMPLE
.\Export-ADStructure.ps1 -XmlFile ADStructure_RaboSvc.com.xml -Verbose
.NOTES
   Author : Ben van Zanten
   Company: Rabobank International
   Date   : Dec 2015 - Mar 2016
   Version: 1.4

   History:  1.0  Initial version
             1.1  Create Output folder if not exists.
             1.2  Added DNS Partitions DnsServerDirectoryPartition
             1.3  Added support of exporting groups + members, added support for $DCCredential to connect to remote DC
             1.4  Made DNS inventory optional since DNS is not used any more on our DCs
#>


#Requires -Version 4
#Requires -Modules ActiveDirectory   # , DnsServer


[CmdletBinding(SupportsShouldProcess=$true, 
                  ConfirmImpact='High')]

    Param
    (
        # Name of the input file, default is: ADStructure.xml
        [Parameter(Mandatory=$false,Position=1, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false, 
                   ValueFromRemainingArguments=$false)]
                   [ValidateScript({Test-Path $_})]
        [string]$XmlFile,

        # Also inventory hosts in the Domain structure
        [switch]$Hosts,

	    # Also inventory OU in the Domain structure
        [switch]$OUs,

	    # Also inventory users in the Domain structure (will imply OUs as well)
        [switch]$Users,

        # Also inventory groups in the Domain structure (will imply OUs as well)
        [switch]$Groups,

	    # Also inventory DNS on the Domain Controllers
        [switch]$DNS,

        # Credentials to connect to remote DC to retrieve registry information
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$DCCredential
    )


# .... https://msdn.microsoft.com/en-us/library/aa772263(v=vs.85).aspx  ADS_GROUP_TYPE_ENUM enumeration
$ADS_GROUP_TYPE_GLOBAL_GROUP        = 0x00000002
$ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP  = 0x00000004
$ADS_GROUP_TYPE_LOCAL_GROUP         = 0x00000004
$ADS_GROUP_TYPE_UNIVERSAL_GROUP     = 0x00000008
$ADS_GROUP_TYPE_SECURITY_ENABLED    = 0x80000000


Function Get-SubOUs  ($DN) {

    $DN.distinguishedName

    # Start Elementname depends on the type of object...
    switch($DN.distinguishedName.Split('=')[0]) {
      "DC" {
            # $xmlWriter.WriteStartElement('domain')
            # $XmlWriter.WriteAttributeString('name', $DN.name)
            # $XmlWriter.WriteAttributeString('distinguishedName', $DN.distinguishedName)
            $xmlWriter.WriteStartElement('OUs')
            break
            }
      "OU" {
            $xmlWriter.WriteStartElement('OU')
            $XmlWriter.WriteAttributeString('name', $DN.name)
            $XmlWriter.WriteAttributeString('description', $DN.description)
            break
            }
      "CN" {
            $xmlWriter.WriteStartElement('CN')
            $XmlWriter.WriteAttributeString('name', $DN.name)
            $XmlWriter.WriteAttributeString('description', $DN.description)
            break
            }
      default { $xmlWriter.WriteStartElement($DN.distinguishedName.Split('=')[0]); break; }
    }
    

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://' + $DN.distinguishedName)
    $Searcher.PageSize = 200
    $Searcher.SearchScope = "oneLevel"

    $Searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
    $Searcher.PropertiesToLoad.Add("Name")              | Out-Null
    $Searcher.PropertiesToLoad.Add("Description")       | Out-Null

    # Search for OU or Containers.. (Unix resources OU contains AD containers)
    $Searcher.Filter = "(|(objectCategory=organizationalUnit)(objectCategory=container))"
    $AllOUs = $Searcher.FindAll()

    ForEach ($OU In $AllOUs) {
        $OUDN = $OU.Properties.Item("distinguishedName")
        $OUBase = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$OUDN"

        Get-SubOUs $OUBase

        if ($Hosts) {
            $Searcher.SearchRoot = $OUBase
            $Searcher.SearchScope = "OneLevel"
    
            $Searcher.Filter = "(objectCategory=computer)"
            $Computers = $Searcher.FindAll()
            ForEach ($Computer In $Computers) {
                "  Computer: " + $Computer.Properties.Item("Name")
            }
        }

        if ($Users) {
            # Use the table from http://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
            #   to translate between AD properties, and PowerShell Arguments
            $Searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
            $Usrs = $Searcher.FindAll()
            ForEach ($User In $Usrs) {
                "  User: " + $User.Properties.Item("Name")
            }
        }

        if ($Groups) {
            # Use the table from http://social.technet.microsoft.com/wiki/contents/articles/12037.active-directory-get-aduser-default-and-extended-properties.aspx
            #   to translate between AD properties, and PowerShell Arguments
            #
            # Howto build this information:
            #  Properties should match the New-AdGroup paramters since we want to use splatting:
            #  PS D:\Scripts\Active Directory\Sites> help New-ADGroup
            #  SYNTAX
            #      New-ADGroup [-Name] <string> [-GroupScope] <ADGroupScope> {DomainLocal | Global | Universal} [-WhatIf] [-Confirm] [-AuthType
            #      <ADAuthType> {Negotiate | Basic}] [-Credential <pscredential>] [-Description <string>] [-DisplayName <string>] [-GroupCategory
            #      <ADGroupCategory> {Distribution | Security}] [-HomePage <string>] [-Instance <ADGroup>] [-ManagedBy <ADPrincipal>] [-OtherAttributes
            #      <hashtable>] [-PassThru] [-Path <string>] [-SamAccountName <string>] [-Server <string>]  [<CommonParameters>]
            #
            #
            $GrpSearcher = New-Object System.DirectoryServices.DirectorySearcher
            $GrpSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://' + $DN.distinguishedName)
            $GrpSearcher.PageSize = 200
            $GrpSearcher.SearchScope = "oneLevel"
            $GrpSearcher.Filter = "(&(objectCategory=Group)(objectClass=group))"
            $GrpSearcher.SearchScope = "OneLevel"
            $GrpSearcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("Name")              | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("description")       | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("groupType")         | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("displayName")       | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("wWWHomePage")       | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("managedBy")         | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("sAMAccountName")    | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("mail")              | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("proxyAddresses")    | Out-Null

            $GrpSearcher.PropertiesToLoad.Add("info")              | Out-Null
            $GrpSearcher.PropertiesToLoad.Add("member")              | Out-Null

            $Grps = $GrpSearcher.FindAll()
            ForEach ($Group In $Grps) {
                "  Group: " + $Group.Properties.Item("Name")
                $xmlWriter.WriteStartElement('Group')
                $XmlWriter.WriteAttributeString('name', $Group.Properties.Item("Name"))
                $GroupType = $Group.Properties.Item("groupType")
                
                $grpType = 'Global'
                if (([int]$Group.Properties.Item("groupType")[0] -band $ADS_GROUP_TYPE_GLOBAL_GROUP) -eq $ADS_GROUP_TYPE_GLOBAL_GROUP) {
                    $grpType = 'Global'
                }
                if (([int]$Group.Properties.Item("groupType")[0] -band $ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP) -eq $ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP) {
                    $grpType = 'DomainLocal'
                }
                if (([int]$Group.Properties.Item("groupType")[0] -band $ADS_GROUP_TYPE_UNIVERSAL_GROUP) -eq $ADS_GROUP_TYPE_UNIVERSAL_GROUP) {
                    $grpType = 'Universal'
                }
                $xmlWriter.WriteElementString('GroupScope', $grpType)

                if (([int]$Group.Properties.Item("groupType")[0] -band $ADS_GROUP_TYPE_SECURITY_ENABLED) -eq $ADS_GROUP_TYPE_SECURITY_ENABLED) {
                    $xmlWriter.WriteElementString('GroupCategory', 'Security')
                } else {
                    $xmlWriter.WriteElementString('GroupCategory', 'Distribution')
                }

                if (!([string]::IsNullOrEmpty($Group.Properties.Item("displayName")))) { $xmlWriter.WriteElementString('DisplayName',$Group.Properties.Item("displayName")) }
                if (!([string]::IsNullOrEmpty($Group.Properties.Item("description")))) { $xmlWriter.WriteElementString('Description',$Group.Properties.Item("description")) }
                if (!([string]::IsNullOrEmpty($Group.Properties.Item("managedBy")))) { $xmlWriter.WriteElementString('ManagedBy',$Group.Properties.Item("managedBy")) }
                if (!([string]::IsNullOrEmpty($Group.Properties.Item("wWWHomePage")))) { $xmlWriter.WriteElementString('HomePage',$Group.Properties.Item("wWWHomePage")) }
                if (!([string]::IsNullOrEmpty($Group.Properties.Item("sAMAccountName")))) { $xmlWriter.WriteElementString('SamAccountName',$Group.Properties.Item("sAMAccountName")) }

                # Todo... Other properties export?  should go into hashtable in OtherAttributes
                #   <OtherAttributes>@{adminDescription="PowerShell created account";info=notes onderin;mail=DemoGroup@rabosvc.com}</OtherAttributes>
                $OtherAttribsHT=@{}
                ForEach ($Prp in $Group.Properties.PropertyNames | Where-Object { $_ -in "info","mail","proxyAddresses" }) { $OtherAttribsHT[$Prp]= ($Group.Properties.Item($Prp) -Join ',') }
                [string]$OtherAttribs = '@{' + ($OtherAttribsHT | Convert-HtToString ) + '}'
                Write-Verbose $OtherAttribs
                if ($OtherAttribs -ne '@{}') { $xmlWriter.WriteElementString('OtherAttributes', $OtherAttribs) } 

                #
                # Todo MemberOf....  (Members ? Although Members = MemberOf in the users/groups)
                #
                if (!([string]::IsNullOrEmpty($Group.Properties.Item("member")))) {
                    $xmlWriter.WriteStartElement('Members')
                    ForEach ($Member in $Group.Properties.Item("member")) {
                        $xmlWriter.WriteElementString('member', $Member)
                    }
                    $xmlWriter.WriteEndElement()
                }
                # close the "Group" node:
                $xmlWriter.WriteEndElement()

            }

        }
    }

    # close the "OU" node:
    $xmlWriter.WriteEndElement()

}


    Import-Module .\DeployAdLib.psd1
    # Test for elevation :
    if (-not(Test-AdminStatus)) {
#           Write-Error "Run this script elevated! This script requires administrative permissions."
#           break
    }
    # $domName = Get-DomainName -XmlFile $XmlFile -DomainName $DomainName
    # [xml]$forXML = Get-Content $XmlFile
    # $domXML = $forXML.forest.domains.domain | ? { $_.name -eq $domName }

    $Forest = Get-ADForest
    $ForDomain = Get-ADDomain $Forest.RootDomain
    $ForDN = $ForDomain.DistinguishedName

    $MyFolder = Split-Path $MyInvocation.MyCommand.Path -Parent


        # this is where the document will be saved:
    If (!($XmlFile)) {
        $Path = "{0}\Output\Forest_Inventory_{1}_{2}.xml" -f $MyFolder, $Forest.Name, (Get-Date -Format "yyyyMMdd" )
    } else { $Path = $XmlFile }

    $XmlFolder = Split-Path $Path -Parent
    if (!(Test-Path $XMlFolder)) { New-Item $XmlFolder -ItemType Directory }

    Write-Verbose $Path
    $LogFile = "{0}\Log\Forest_Inventory_{1}_{2}.log" -f $MyFolder, $Forest.Name, (Get-Date -Format "yyyyMMdd" )
    $XmlFolder = Split-Path $LogFile -Parent
    if (!(Test-Path $XMlFolder)) { New-Item $XmlFolder -ItemType Directory }
    Start-Transcript -Path $LogFile


    # get an XMLTextWriter to create the XML
    $XmlWriter = New-Object System.XMl.XmlTextWriter($Path,$Null)

    # choose a pretty formatting:
    $xmlWriter.Formatting = 'Indented'
    $xmlWriter.Indentation = 4
    $XmlWriter.IndentChar =  " "       #  "`t"

    # write the header
    $xmlWriter.WriteStartDocument()

    # # set XSL statements
    # $xmlWriter.WriteProcessingInstruction("xml-stylesheet", "type='text/xsl' href='style.xsl'")

    # create root element "machines" and add some attributes to it
    $XmlWriter.WriteComment('  Active Directory Forest and Domain Inventory  ')

    $xmlWriter.WriteStartElement('forest')
    $xmlWriter.WriteAttributeString('name', $Forest.Name)
    $xmlWriter.WriteAttributeString('distinguishedName', $ForDN)


    $xmlWriter.WriteStartElement('parameters')

        $xmlWriter.WriteElementString('FFL',($Forest.ForestMode -as [int]))
        $XmlWriter.WriteComment(("FFL {0} is forestmode: {1}" -f ($Forest.ForestMode -as [int]),$Forest.ForestMode))

        $xmlWriter.WriteStartElement('FSMO')
            $xmlWriter.WriteElementString('Schema', $Forest.SchemaMaster.Replace($Forest.Name,'').Trim('.'))
            $xmlWriter.WriteElementString('Naming', $Forest.DomainNamingMaster.Replace($Forest.Name,'').Trim('.'))
        $xmlWriter.WriteEndElement()   # End FSMO
    $xmlWriter.WriteEndElement()   # End Parameters
        

    $xmlWriter.WriteStartElement('sites')



    #
    # Process the Sites...
    #
    $Forest.Sites
    $Sites = Get-ADObject -SearchBase "CN=Sites,CN=Configuration,$ForDN" -LDAPFilter "(objectClass=site)" -SearchScope OneLevel

    ForEach ($Site in $Sites) {
        #
        # Create the site if it doesn't exist yet...
        #
        $xmlWriter.WriteStartElement('site')
        $xmlWriter.WriteAttributeString('name', $Site.Name)

        $xmlWriter.WriteStartElement('NTDSSiteSettings')
        $xmlWriter.WriteEndElement()

            $xmlWriter.WriteStartElement('servers')
            $Servers = Get-ADObject -SearchBase "CN=Servers,$($Site.DistinguishedName)" -LDAPFilter "(objectClass=server)" -SearchScope OneLevel
            ForEach ($Server in $Servers) {
                $xmlWriter.WriteStartElement('server')
                $xmlWriter.WriteAttributeString('name',$Server.name)
                $xmlWriter.WriteEndElement()
            }
            $xmlWriter.WriteEndElement() # End of servers

        $xmlWriter.WriteStartElement('LicensingSiteSettings')
        $xmlWriter.WriteEndElement()

        $xmlWriter.WriteEndElement()  # End of site


    }

    #
    # Site Links...
    #
    $xmlWriter.WriteStartElement('sitelinks')
    $ADSiteLinks = Get-ADObject -SearchBase "CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,$ForDN" -LDAPFilter "(objectClass=siteLink)"  -Properties Description,siteList,replInterval,cost,options
    ForEach ($ADSiteLink in $ADSiteLinks) {
        $xmlWriter.WriteStartElement('sitelink')
        $xmlWriter.WriteAttributeString('name', $ADSiteLink.Name)
        $xmlWriter.WriteElementString('Description', $ADSiteLink.Description)
        [string]$OtherAttribs = '@{' + ($ADSiteLink | Select-Object -Property sitelist,replInterval,cost,options |  ConvertTo-Hashtable -NoNulls | Convert-HTToString ) + '}'
        $xmlWriter.WriteElementString('OtherAttributes', $OtherAttribs)
        $xmlWriter.WriteEndElement()
    }
    $xmlWriter.WriteEndElement()  # End sitelinks

    # close the "sites" node:
    $xmlWriter.WriteEndElement()

    #
    # Process the subnets...
    # 
    $xmlWriter.WriteStartElement('subnets')
    $Subnets = Get-ADObject -SearchBase "CN=Subnets,CN=Sites,CN=Configuration,$ForDN" -LDAPFilter "(objectClass=subnet)"  -Properties Description,siteObject
    ForEach ($Subnet in $Subnets) {
        $xmlWriter.WriteStartElement('subnet')
        $xmlWriter.WriteAttributeString('name', $Subnet.Name)
        $xmlWriter.WriteElementString('Description', $Subnet.Description)
        [string]$OtherAttribs = '@{' + ($Subnet | Select-Object -Property siteObject |  ConvertTo-Hashtable -NoNulls | Convert-HTToString ) + '}'
        $xmlWriter.WriteElementString('OtherAttributes', $OtherAttribs)
        $xmlWriter.WriteEndElement()  # End subnet
    }

    $xmlWriter.WriteEndElement()  # End subnets

    #
    # Domains
    #
    $xmlWriter.WriteStartElement('domains')

    ForEach ($Dom in $Forest.Domains) {

        $Domain = Get-ADDomain -Identity $Dom

        $xmlWriter.WriteStartElement('domain')
        $xmlWriter.WriteAttributeString('name', $Domain.Name)
        $xmlWriter.WriteAttributeString('NetBIOSName', $Domain.NetBIOSName)
        $xmlWriter.WriteAttributeString('distinguishedName', $Domain.DistinguishedName)
        $xmlWriter.WriteAttributeString('dnsName', $Domain.DNSRoot)

        $xmlWriter.WriteStartElement('parameters')

            $xmlWriter.WriteElementString('DFL',($Domain.DomainMode -as [int]))
            $XmlWriter.WriteComment(("DFL {0} is domainmode: {1}" -f ($Domain.DomainMode -as [int]),$Domain.DomainMode))

            $xmlWriter.WriteStartElement('FSMO')
                $xmlWriter.WriteElementString('InfrastructureMaster', $Domain.InfrastructureMaster.Replace($Domain.DNSRoot,'').Trim('.'))
                $xmlWriter.WriteElementString('PDCEmulator'         , $Domain.PDCEmulator.Replace($Domain.DNSRoot,'').Trim('.'))
                $xmlWriter.WriteElementString('RIDMaster'           , $Domain.RIDMaster.Replace($Domain.DNSRoot,'').Trim('.'))
            $xmlWriter.WriteEndElement()   # End FSMO
        $xmlWriter.WriteEndElement()   # End Parameters

        $xmlWriter.WriteStartElement('DCs')

        ForEach ($DCName in $Domain.ReplicaDirectoryServers ) {
            $DCName

            $xmlWriter.WriteStartElement('DC')
                $xmlWriter.WriteAttributeString('name', $DCName)

                $xmlWriter.WriteStartElement('ReplicationSourceDC')
            $xmlWriter.WriteEndElement()

            $xmlWriter.WriteStartElement('DNS')
            if ($DNS) {
                $xmlWriter.WriteStartElement('Forwarders')
                    $DnsFwd = Get-DnsServerForwarder -ComputerName $DCName
                    $xmlWriter.WriteElementString('IPAddress', $DnsFwd.IPAddress -Join ',')

                    $xmlWriter.WriteElementString('UseRootHint',      $DnsFwd.UseRootHint)
                    $xmlWriter.WriteElementString('TimeOut',          $DnsFwd.Timeout)
                    $xmlWriter.WriteElementString('EnableReordering', $DnsFwd.EnableReordering)
                $xmlWriter.WriteEndElement()  # End Forwarders

                $xmlWriter.WriteStartElement('ConditionalForwarders')
                $xmlWriter.WriteEndElement()  # ConditionalForwarders

                $xmlWriter.WriteStartElement('DnsServerDirectoryPartition')
                ForEach ($Part in ( Get-DnsServerDirectoryPartition -ComputerName $DCName | Where-Object { $_.Flags -eq 'Enlisted ' } ) ) {
                    $xmlWriter.WriteStartElement('Partition')
                    $xmlWriter.WriteAttributeString('Flags', $Part.Flags )
                    $xmlWriter.WriteName($part.DirectoryPartitionName)
                    $xmlWriter.WriteEndElement()  # End Partition
                }
                $xmlWriter.WriteEndElement()  # DnsServerDirectoryPartition

            }
            $xmlWriter.WriteEndElement()  # End DNS

            #
            #  Parameters are read from the Remote machine registry
            #
<#
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $DCName)
            $RegKey = $Reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters")
            $DSDbPath = $RegKey.GetValue("DSA Working Directory")
            $DSLgPath = $RegKey.GetValue("Database log files path")
            $RegKey = $Reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters")
            $SysVol = $RegKey.GetValue("SysVol")
#>
            $Reg = Get-WmiObject -List -Namespace 'root\default' -ComputerName $DCName -Credential $DCCredential | Where-Object {$_.Name -eq "StdRegProv"}
            $HKLM = 2147483650

            $DSDbPath = $Reg.GetStringValue($HKLM,"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",    "DSA Working Directory").sValue
            $DSLgPath = $Reg.GetStringValue($HKLM,"SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",    "Database log files path").sValue
            $SysVol   = $Reg.GetStringValue($HKLM,"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters","SysVol").sValue

            # $Params = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
            # $SysVol = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name SysVol).SysVol
            #
            # $SysVol = E:\SYSVOL\sysvol   should become E:\SYSVOL
            $SysVol = $SysVol.Substring(0, $SysVol.LastIndexOf('\sysvol'))

            $xmlWriter.WriteStartElement('parameters')
                $xmlWriter.WriteElementString('DatabasePath', $DSDbPath)
                $xmlWriter.WriteElementString('LogPath',      $DSLgPath)
                $xmlWriter.WriteElementString('SysvolPath',   $SysVol)
            $xmlWriter.WriteEndElement()   # End Parameters

            $xmlWriter.WriteEndElement()  # End DC

        }

        $xmlWriter.WriteEndElement()  # End DCs

        #
        # Write OU structure... recursive
        #    if $Users  is set, will also inventory all users...
		#
		if ($OUs) {
            Get-SubOUs  ( New-Object System.DirectoryServices.DirectoryEntry ('LDAP://' + $Domain.DistinguishedName) )
		}

        #
        # DNS zones
        #

<#
           Add-DnsServerPrimaryZone [-Name] <string> [-ReplicationScope] <string> {Forest | Domain | Legacy | Custom} [[-DirectoryPartitionName] <string>] [-ResponsiblePerson <string>] [-DynamicUpdate <string> {None | Secure | NonsecureAndSecure}]
           [-LoadExisting] [-ComputerName <string>] [-PassThru] [-CimSession <CimSession[]>] [-ThrottleLimit <int>] [-AsJob] [-WhatIf] [-Confirm]  [<CommonParameters>]

           Add-DnsServerPrimaryZone -NetworkId <string> -ZoneFile <string> [-ResponsiblePerson <string>] [-DynamicUpdate <string> {None | Secure | NonsecureAndSecure}] [-LoadExisting] [-ComputerName <string>] [-PassThru] [-CimSession <CimSession[]>]
           [-ThrottleLimit <int>] [-AsJob] [-WhatIf] [-Confirm]  [<CommonParameters>]

           Add-DnsServerPrimaryZone [-Name] <string> -ZoneFile <string> [-ResponsiblePerson <string>] [-DynamicUpdate <string> {None | Secure | NonsecureAndSecure}] [-LoadExisting] [-ComputerName <string>] [-PassThru] [-CimSession <CimSession[]>]
           [-ThrottleLimit <int>] [-AsJob] [-WhatIf] [-Confirm]  [<CommonParameters>]

           Add-DnsServerPrimaryZone [-ReplicationScope] <string> {Forest | Domain | Legacy | Custom} [[-DirectoryPartitionName] <string>] -NetworkId <string> [-ResponsiblePerson <string>] [-DynamicUpdate <string> {None | Secure | NonsecureAndSecure}]
           [-LoadExisting] [-ComputerName <string>] [-PassThru] [-CimSession <CimSession[]>] [-ThrottleLimit <int>] [-AsJob] [-WhatIf] [-Confirm]  [<CommonParameters>]
#>

        if ($DNS) {
        $xmlWriter.WriteStartElement('DNS')
        $xmlWriter.WriteStartElement('zones')
        ForEach ($DnsZone in (Get-DnsServerZone -ComputerName $DCName | Where-Object { !($_.isAutoCreated) } )) {
        
          $ZoneName = $DnsZone.ZoneName
          if ($ZoneName) {
          Switch ($DnsZone.ZoneType) {
            'Primary'  {
                    $xmlWriter.WriteStartElement('zone')
                    if ($DnsZone.IsReverseLookupZone) {
                        # TODO:  name 7.168.192.in-addr.arpa  omzetten in NetworkID  192.168.7.0/24  but where can the /24 be retrieved?
                        $xmlWriter.WriteAttributeString('NetworkId', $ZoneName)
                    } else {
                        $xmlWriter.WriteAttributeString('name', $ZoneName)
                    }

                    Try {
                        $Aging = Get-DnsServerZoneAging -Name $ZoneName  -ComputerName $DCName  -ErrorAction Stop
                        $xmlWriter.WriteStartElement('Aging')
                            $xmlWriter.WriteElementString('Aging',   $Aging.AgingEnabled)
                            $xmlWriter.WriteElementString('RefreshInterval',   $Aging.RefreshInterval)
                            $xmlWriter.WriteElementString('NoRefreshInterval',   $Aging.NoRefreshInterval)
                        $xmlWriter.WriteEndElement()  # End Aging
                    }
                    Catch { "Aging not found for zone: $ZoneName" }

                    $xmlWriter.WriteElementString('ReplicationScope',   $DnsZone.ReplicationScope)
                    $xmlWriter.WriteElementString('DynamicUpdate',   $DnsZone.DynamicUpdate)
                    $xmlWriter.WriteElementString('DirectoryPartitionName',   $DnsZone.DirectoryPartitionName)
                    $xmlWriter.WriteEndElement()  # End zone

                        Break
            }
                { $_ -in ('Forwarder','Stub')}  {
                    $xmlWriter.WriteStartElement('zone')
                    $xmlWriter.WriteAttributeString('ZoneType', $DnsZone.ZoneType)
                        if ($DnsZone.IsReverseLookupZone) {
                            # TODO:  name 7.168.192.in-addr.arpa  omzetten in NetworkID  192.168.7.0/24  but where can the /24 be retrieved?
                            $xmlWriter.WriteAttributeString('NetworkId', $ZoneName)
                        } else {
                            $xmlWriter.WriteAttributeString('name', $ZoneName)
                        }

                    $xmlWriter.WriteElementString('MasterServers', $DnsZone.MasterServers -Join ',')
                    $xmlWriter.WriteElementString('ForwarderTimeout', $DnsZone.ForwarderTimeout)
                    
                    $xmlWriter.WriteElementString('ReplicationScope',   $DnsZone.ReplicationScope)
                    $xmlWriter.WriteElementString('DynamicUpdate',   $DnsZone.DynamicUpdate)
                    $xmlWriter.WriteElementString('DirectoryPartitionName',   $DnsZone.DirectoryPartitionName)
                    $xmlWriter.WriteEndElement()  # End zone

                        Break
             }

                 Default { "DNS zone type not yet scripted: $($DnsZone.ZoneType)" }
          }
        
        }
        }

        $xmlWriter.WriteEndElement()  # End zones
        $xmlWriter.WriteEndElement()  # End DNS
        }

        $xmlWriter.WriteEndElement()  # End Domain

    }


    $xmlWriter.WriteEndElement()  # End Domains

    # close the "forest" node:
    $xmlWriter.WriteEndElement()
 
    # finalize the document:
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()


    # Get-ADObject -SearchBase "CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,$ForDN" -LDAPFilter "(objectClass=siteLink)" -Properties siteList,replInterval,cost,options,Description | Format-Table -Property Name,replInterval,cost,options,siteList -AutoSize

    Stop-Transcript

