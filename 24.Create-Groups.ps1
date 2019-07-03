<#
.Synopsis
   Creates Groups in the OU structure
.DESCRIPTION
   Reads the AD Configuration XML (Default: ADStructure.xml)  and creates all groups within it.
.EXAMPLE
.NOTES
   Author : Ben van Zanten
   Company: Valid
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

    # Name of the domain. For instance  Contoso. If not given, the domain from the XML is used
    [Parameter(Mandatory=$False,Position=2)]
    [string]$DomainName,

    # If set, will change a group (Set-ADGroup) if the group already exists. Otherwise the script will only create new groups and skip existing groups.
    [switch]$ChangeExisting
    )

Function New-GroupsFromXML ($Element) {
    [string]$Path = ConvertFrom-ADXmlToDN $Element
    [string]$name=$Element.name

    ForEach ($Group in $Element.Group) {
        $GroupHT = Convert-XmlToHT $Group

        # Add the server name so we can also do remote domains
        $GroupHT.Add("Server",$DomainFQDN)

        if (Get-ADGroup -Filter "Name -eq '$($Group.name)'" -SearchBase "$($domXML.distinguishedName)" -SearchScope Subtree -Server $DomainFQDN ) {
            #
            #  Existing Group... update the properties.
            #
            Write-Output "Group already exists ""$($Group.name)"" -Path ""$Path"""
            $GroupHT.Remove("name")
            $GroupHT["Identity"]=$Group.name
            # Remove some extra fields that come from XML and are irrelevant for the Set-* CmdLet
            $GroupHT.Remove("#comment")
            $GroupHT.Remove("type")
            $GroupHT.Remove("OtherAttributes")
            # $GroupHT | FT Key,Value
            if ($ChangeExisting) {
                Set-ADGroup @GroupHT
            }
        } else {
            #
            # New Group, create it.
            #
            Write-Output "New-ADGroup -Name ""$($Group.name)"" -Path ""$Path"""
            $GroupHT["Path"]=$Path
            # Fill in some final properties if not yet given.
            # Remove some extra fields
            $GroupHT.Remove("#comment")
            # $GroupHT | FT Key,Value
            New-ADGroup @GroupHT
        }


    }

    # Use recursion to get all sub-OUs
    ForEach ($OU in $Element.OU) {
        New-GroupsFromXML $OU
    }
    # Use recursion to get all sub-Containers
    ForEach ($OU in $Element.CN) {
        New-GroupsFromXML $OU
    }
}



Import-Module .\DeployAdLib.psd1
Import-Module ActiveDirectory

# Test for elevation :
if (-not(Test-AdminStatus)) {
    Write-Error "Run this script elevated! This script requires administrative permissions."
    break
}

$domName = Get-DomainName -XmlFile $XmlFile -DomainName $DomainName
[xml]$forXML = Get-Content $XmlFile
$domXML = $forXML.forest.domains.domain | ? { $_.name -eq $domName }

$DomainFQDN = $domxml.dnsname

#
#  Here starts the real work...
#


$domXML.OUs.OU |  ForEach-Object { 
    $OU = $_
        New-GroupsFromXML $OU
}

