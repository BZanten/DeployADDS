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


#       $DomainName
    }

    Process
    {

        #
        #  Here starts the real work...
        #

    }
