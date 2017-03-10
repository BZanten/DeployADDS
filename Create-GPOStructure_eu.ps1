<#
.Synopsis
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
                  ConfirmImpact='Medium')]

    Param
    (
        # Name of the input file, default is: ADStructure.xml
        [Parameter(Mandatory=$true,Position=1, 
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
        Import-Module GroupPolicy
        # Test for elevation :
        if (-not(Test-AdminStatus)) {
#           Write-Error "Run this script elevated! This script requires administrative permissions."
#           break
        }
        $domName = Get-DomainName -XmlFile $XmlFile -DomainName $DomainName
        [xml]$forXML = Get-Content $XmlFile
        $domXML = $forXML.forest.domains.domain | ? { $_.name -eq $domName }


        $DomainName

    }
    Process
    {
        #
        #  Here starts the real work...
        #
        if (!(Get-GPO -Name "eu.mcp.DomainSettings"                 -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.mcp.DomainSettings"                 -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.mup.DomainSettings"                 -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.mup.DomainSettings"                 -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.fcp.DomainControllers"              -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.fcp.DomainControllers"              -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.fcp.WritableDomainControllers"      -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.fcp.WritableDomainControllers"      -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.fcp.PDC-FSMO-AuthTimeSource"        -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.fcp.PDC-FSMO-AuthTimeSource"        -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.fup.AccountsSettings"               -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.fup.AccountsSettings"               -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.bup.AccountsSettings-GCS"           -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.bup.AccountsSettings-GCS"           -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.bup.AccountsSettings-TFS"           -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.bup.AccountsSettings-TFS"           -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.fup.AdministrationAccountsSettings" -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.fup.AdministrationAccountsSettings" -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.fcp.ServerSettings"                 -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.fcp.ServerSettings"                 -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.bcp.ServerSettings-GCS"             -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.bcp.ServerSettings-GCS"             -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.bcp.ServerSettings-TFS"             -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.bcp.ServerSettings-TFS"             -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.fcp.SystemSettings"                 -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.fcp.SystemSettings"                 -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.fcp.TerminalSettings"               -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.fcp.TerminalSettings"               -Domain "$($domXML.dnsname)" }
        if (!(Get-GPO -Name "eu.fcp.ServerBitLocker"                -ErrorAction SilentlyContinue )) { New-GPO -Name "eu.fcp.ServerBitLocker"                -Domain "$($domXML.dnsname)" }

        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.mcp.DomainSettings))"                 | Set-ADObject -Replace @{flags=1}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.mup.DomainSettings))"                 | Set-ADObject -Replace @{flags=2}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fcp.DomainControllers))"              | Set-ADObject -Replace @{flags=1}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fcp.WritableDomainControllers))"      | Set-ADObject -Replace @{flags=1}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fcp.PDC-FSMO-AuthTimeSource))"        | Set-ADObject -Replace @{flags=1}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fup.AccountsSettings))"               | Set-ADObject -Replace @{flags=2}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.bcp.ServerSettings-GCS))"             | Set-ADObject -Replace @{flags=1}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.bup.AccountsSettings-GCS))"           | Set-ADObject -Replace @{flags=2}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.bup.AccountsSettings-TFS))"           | Set-ADObject -Replace @{flags=2}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fup.AdministrationAccountsSettings))" | Set-ADObject -Replace @{flags=2}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fcp.ServerSettings))"                 | Set-ADObject -Replace @{flags=1}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.bp.ServerSettings-GCS))"              | Set-ADObject -Replace @{flags=1}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fcp.SystemSettings))"                 | Set-ADObject -Replace @{flags=1}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fcp.TerminalSettings))"               | Set-ADObject -Replace @{flags=1}
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fcp.ServerBitLocker))"                | Set-ADObject -Replace @{flags=1}

        New-GPLink -Name "eu.mcp.DomainSettings"                  -Order 2 -Target "$($domXML.distinguishedName)"                               -Domain "$($domXML.dnsname)" -Enforced Yes -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.mup.DomainSettings"                  -Order 3 -Target "$($domXML.distinguishedName)"                               -Domain "$($domXML.dnsname)" -Enforced Yes -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.DomainControllers"               -Order 2 -Target "OU=Domain Controllers,$($domXML.distinguishedName)"         -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.WritableDomainControllers"       -Order 3 -Target "OU=Domain Controllers,$($domXML.distinguishedName)"         -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.PDC-FSMO-AuthTimeSource"         -Order 4 -Target "OU=Domain Controllers,$($domXML.distinguishedName)"         -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.ServerBitLocker"                 -Order 5 -Target "OU=Domain Controllers,$($domXML.distinguishedName)"                                   -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fup.AccountsSettings"                -Order 1 -Target "OU=Accounts,OU=GCS,OU=Global Services,$($domXML.distinguishedName)"                   -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.bup.AccountsSettings-GCS"            -Order 2 -Target "OU=Accounts,OU=GCS,OU=Global Services,$($domXML.distinguishedName)"                   -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fup.AdministrationAccountsSettings"  -Order 1 -Target "OU=Administration,OU=Accounts,OU=GCS,OU=Global Services,$($domXML.distinguishedName)" -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.ServerSettings"                  -Order 1 -Target "OU=Servers,OU=GCS,OU=Global Services,$($domXML.distinguishedName)"                    -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.bcp.ServerSettings-GCS"              -Order 2 -Target "OU=Servers,OU=GCS,OU=Global Services,$($domXML.distinguishedName)"                    -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.ServerBitLocker"                 -Order 3 -Target "OU=Servers,OU=GCS,OU=Global Services,$($domXML.distinguishedName)"                    -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.SystemSettings"                  -Order 1 -Target "OU=System,OU=Servers,OU=GCS,OU=Global Services,$($domXML.distinguishedName)"          -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.TerminalSettings"                -Order 1 -Target "OU=Terminal,OU=Servers,OU=GCS,OU=Global Services,$($domXML.distinguishedName)"        -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue

        New-GPLink -Name "eu.fup.AccountsSettings"                -Order 1 -Target "OU=Accounts,OU=TFS,OU=RI Mgmt Orgs,$($domXML.distinguishedName)"                   -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.bup.AccountsSettings-TFS"            -Order 2 -Target "OU=Accounts,OU=TFS,OU=RI Mgmt Orgs,$($domXML.distinguishedName)"                   -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fup.AdministrationAccountsSettings"  -Order 1 -Target "OU=Administration,OU=Accounts,OU=TFS,OU=RI Mgmt Orgs,$($domXML.distinguishedName)" -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.ServerSettings"                  -Order 1 -Target "OU=Servers,OU=TFS,OU=RI Mgmt Orgs,$($domXML.distinguishedName)"                    -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.bcp.ServerSettings-TFS"              -Order 2 -Target "OU=Servers,OU=TFS,OU=RI Mgmt Orgs,$($domXML.distinguishedName)"                    -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.ServerBitLocker"                 -Order 3 -Target "OU=Servers,OU=TFS,OU=RI Mgmt Orgs,$($domXML.distinguishedName)"                    -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.SystemSettings"                  -Order 1 -Target "OU=System,OU=Servers,OU=TFS,OU=RI Mgmt Orgs,$($domXML.distinguishedName)"          -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue
        New-GPLink -Name "eu.fcp.TerminalSettings"                -Order 1 -Target "OU=Terminal,OU=Servers,OU=TFS,OU=RI Mgmt Orgs,$($domXML.distinguishedName)"        -Domain "$($domXML.dnsname)" -Enforced No  -LinkEnabled Yes  -ErrorAction SilentlyContinue

        $Guid = "{BFDCBDE3-F8E3-440F-BC7F-E728D5840CB1}"
        if (!( Get-ADObject -Filter "Name -eq '$Guid'" -searchbase  "CN=SOM, CN=WMIPolicy,CN=System,$($domXML.distinguishedName)" )) {
            New-ADObject -Name $Guid -Type msWMI-Som -OtherAttributes @{'msWMI-Name'="PDC FSMO of AD Domain"; 'msWMI-ID'=$Guid; 'msWMI-Parm1'="Finds the PDC FSMO Role"; 'msWMI-Parm2'="1;3;10;55;WQL;root\CIMv2;Select * from Win32_ComputerSystem where DomainRole = 5;"} -Path "CN=SOM, CN=WMIPolicy,CN=System,$($domXML.distinguishedName)"
        }
        Get-ADObject -LDAPFilter "(&(objectClass=groupPolicyContainer)(displayName=eu.fcp.PDC-FSMO-AuthTimeSource))" | Set-ADObject -Add @{ 'gPCWQLFilter'= "[$($domXML.dnsname);$Guid;0]"}

        #
        # GPO Permissions
        #
        Set-GPPermission -Name "eu.fcp.WritableDomainControllers" -PermissionLevel GpoRead  -TargetName "Domain Controllers"           -TargetType Group
        Set-GPPermission -Name "eu.fcp.WritableDomainControllers" -PermissionLevel GpoApply -TargetName "Domain Controllers"           -TargetType Group
        Set-GPPermission -Name "eu.fcp.WritableDomainControllers" -PermissionLevel GpoRead  -TargetName "Authenticated Users"          -TargetType Group -Replace

        #
        # Backup Default Domain Controller GPO and import the settings into eu.fcp.DomainControllers
        #
        if (!(Test-Path E:\Backups\GPO\DefaultDCs  )) { MD E:\Backups\GPO\DefaultDCs }
        $BckResult = Backup-GPO -Name "Default Domain Controllers Policy" -Path E:\Backups\GPO\DefaultDCs -Comment "Initial Backup" -Domain $domXML.dnsname
        Import-GPO -BackupId $BckResult.Id -Path E:\Backups\GPO\DefaultDCs -TargetName "eu.fcp.DomainControllers"
    }
