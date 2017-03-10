<#
.Synopsis
   Creates User accounts in the OU
.DESCRIPTION
   Reads the AD Configuration XML (Default: ADStructure.xml)  and creates all useraccounts within it.
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

    # If set, will change a user (Set-ADUser) if the group already exists. Otherwise the script will only create new groups and skip existing groups.
    [switch]$ChangeExisting
    )

Function New-UsersfromXML ($Element) {
    [string]$Path = ConvertFrom-ADXmlToDN $Element
    [string]$name=$Element.name

    ForEach ($User in $Element.User) {
        $UserHT = Convert-XmlToHT $User

        $ExistingUser = Get-ADUser -Filter "Name -eq '$($User.name)'" -SearchBase "$($domXML.distinguishedName)" -SearchScope Subtree  -ErrorAction SilentlyContinue
        if ($ExistingUser) {
            #
            #  Existing user... update the properties.
            #
            Write-Output "User already exists ""$($User.name)"" -Path ""$Path"""
            $UserHT.Remove("name")
            $UserHT["Identity"]=$ExistingUser
            # Remove some extra fields that come from XML and are irrelevant for the Set-* CmdLet
            $UserHT.Remove("#comment")
            $UserHT.Remove("type")
            $UserHT.Remove("AccountPassword")
            $UserHT.Remove("Password")
            $UserHT.Remove("OtherAttributes")
            $UserHT.Remove("GroupMembership")
            # $UserHT | FT Key,Value
            if ($ChangeExisting) {
                Set-ADUser @UserHT
            }
        } else {
            #
            # New user, create it.
            #
            Write-Output "New-ADUser -Name ""$($User.name)"" -Path ""$Path"""
            if ($User.Password)     { $Pwd = $User.Password }
            elseif ($User.UserPassword) { $Pwd = $User.UserPassword }

            if (!($Pwd)) { $Pwd = "svc@[[0untDfltP@$$wd" }
            if (!([string]::IsNullOrEmpty($Pwd))) {
                if ($Pwd -eq '*') {
                    Write-Host "Password for User: $($User.name)  is *  please enter here"
                    $Pwd = Read-Host -Prompt "Password:" –AsSecureString
                } else {
                    $Pwd = ConvertTo-SecureString $Pwd -AsPlaintext –Force
                }
                $UserHT["AccountPassword"]=$Pwd
                $Pwd = $Null
            }
            $UserHT["Path"]=$Path
            # Fill in some final properties if not yet given.
            if (!($UserHT["UserPrincipalName"])) { $UserHT["UserPrincipalName"]="$($User.name)@$($domXML.dnsName)" }
            # Remove some extra fields
            $UserHT.Remove("#comment")
            $UserHT.Remove("GroupMembership")
            $UserHT | FT Key,Value -AutoSize
            New-ADUser @UserHT
        }


    }

    # Use recursion to get all sub-OUs
    ForEach ($OU in $Element.OU) {
        New-UsersfromXML $OU
    }
    # Use recursion to get all sub-Containers
    ForEach ($OU in $Element.CN) {
        New-UsersfromXML $OU
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
        New-UsersfromXML $OU
}
