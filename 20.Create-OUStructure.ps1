<#
.Synopsis
   Creates OU structure, according to an XML input file.
.DESCRIPTION
   Creates OU structure, according to an XML input file.
.EXAMPLE
  .\Create-OUStructure.ps1 -XmlFile .\ADStructure_Contoso.com.xml -WhatIf
  Performs a -WhatIf on the script, the XML file is parsed, for each OU found it is shown whether the OU already exists, and if the OU would be created.
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
        [Parameter(Mandatory=$true,Position=1, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false, 
                   ValueFromRemainingArguments=$false)]
                   [ValidateScript({Test-Path $_})]
        [string]$XmlFile='.\ADStructure.xml',

    # Name of the domain. For instance  Contoso. If not given, the domain from the XML is used
    [Parameter(Mandatory=$False,Position=2)]
    [string]$DomainName
    )


Function New-OUfromXML ($Element) {
    [string]$DC = ConvertFrom-ADXmlToDN $Element
    [string]$name=$Element.name

    # Special case for OU creation: we need the parent OU for the current OU in order to create the current OU as its child.
    if ($Element.ParentNode.name -eq 'OUs') {
        $Path = "$(ConvertFrom-ADXmlToDN $Element.ParentNode.ParentNode)"
    } else {
        $Path = "$(ConvertFrom-ADXmlToDN $Element.ParentNode)"
    }

    try { $ExistingOU = Get-ADOrganizationalUnit -Filter "Name -eq '$name'" -SearchBase "$Path" -SearchScope OneLevel -ErrorAction SilentlyContinue  }
    catch { }

    if ($ExistingOU) {
        Write-Output "OU already exists ""$name"" -Path ""$Path"""
    } else {
        Write-Output "New-ADOrganizationalUnit -Name ""$name"" -Path ""$Path"""
        New-ADOrganizationalUnit -Name $name -Description "$($Element.description)" -Path $Path
    }

    # Use recursion to get all sub-OUs
    ForEach ($OU in $Element.OU) {
        New-OUfromXML $OU
    }
    # Use recursion to get all sub-Containers
    ForEach ($OU in $Element.CN) {
        New-OUfromXML $OU
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
        New-OUfromXML $OU
}

#
#  Protect all OU's from accidental deletion.
#
Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion | where {$_.ProtectedFromAccidentalDeletion -eq $false} | Select DistinguishedName,ProtectedFromAccidentalDeletion | Format-Table
Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion | where {$_.ProtectedFromAccidentalDeletion -eq $false} | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $True
Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion | Select DistinguishedName,ProtectedFromAccidentalDeletion | Format-Table


