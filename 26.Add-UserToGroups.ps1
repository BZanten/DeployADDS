<#
.Synopsis
   Adds User accounts to groups
.DESCRIPTION
   Reads the AD Configuration XML (Default: ADStructure.xml)  and adds user accounts to groups.
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

Function Add-User2GroupsFromXML ($Element) {
    [string]$Path = ConvertFrom-ADXmlToDN $Element
    [string]$name=$Element.name

    ForEach ($User in $Element.User) {
        $ExistingUser = Get-ADUser -Filter "Name -eq '$($User.name)'" -SearchBase "$($domXML.distinguishedName)" -SearchScope Subtree  -ErrorAction SilentlyContinue
        if ($ExistingUser) {
            Write-Host "User found: $($ExistingUser.DistinguishedName)" -ForegroundColor Green
            ForEach( $Group in $User.GroupMembership.MemberOf ) {
                $ADGroup = Get-ADGroup -Filter "Name -eq '$($Group.name)'" -SearchBase "$($domXML.distinguishedName)" -SearchScope Subtree 
                if ($ADGroup) {
                    Write-Output "  adding user $($User.name) to group $($Group.name)..."
                    Add-ADGroupMember -Identity $ADGroup -Members $ExistingUser 
                } else {
                    # Group not found, use empty Searchbase, connecto to GC to make this work
                    $ADGroup = Get-ADGroup -Filter "Name -eq '$($Group.name)'" -SearchBase "" -SearchScope Subtree -Server Localhost:3268
                    if ($ADGroup) {
                        Write-Output "  adding user $($User.name) to group $($Group.name)..."
                        Add-ADGroupMember -Identity $ADGroup -Members $ExistingUser 
                    } else {
                        Write-Host "Group:  $($Group.name) not found! Check syntax or create group first." -ForegroundColor Red
                    }

                }
            }
        } else {
            Write-Host "User is not found: $($User.name)"  -ForegroundColor Red
        }

    }

    # Use recursion to get all sub-OUs
    ForEach ($OU in $Element.OU) {
        Add-User2GroupsFromXML $OU
    }
    # Use recursion to get all sub-Containers
    ForEach ($OU in $Element.CN) {
        Add-User2GroupsFromXML $OU
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


#
#  Here starts the real work...
#


$domXML.OUs.OU |  ForEach-Object { 
    $OU = $_
        Add-User2GroupsFromXML $OU
}

