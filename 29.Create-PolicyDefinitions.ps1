<#
.Synopsis
Creates the PolicyDefinitions folder in SYSVOL in order to store shared ADMX/ADML files.
.DESCRIPTION
Creates the PolicyDefinitions folder in SYSVOL in order to store shared ADMX/ADML files.
.EXAMPLE
.\Create-PolicyDefinitions -XmlFile ADStructure_RaboSvc.com.xml -Verbose
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
        # Create the GPO Central store.  (PolicyDefinitions folder in E:\SYSVOL\sysvol\<DnsDomainName>\Policies  )
        #
        $PolDefDir = "{0}\{1}\Policies\PolicyDefinitions" -f ( $domXML.DCs.parameters.SysvolPath,$domXML.dnsname )
        if (!(Test-Path $PolDefDir)) {
            Write-Verbose "Creating GPO Central store.  (PolicyDefinitions folder: $PolDefDir)"
            New-Item $PolDefDir -ItemType Directory
            #
            #.. and fill it.  (/xo = do not overwrite newer files)
            #
            Robocopy $Env:SystemRoot\PolicyDefinitions $PolDefDir /e /xo

        } else {
            Write-Verbose "GPO Central store already exists.  (PolicyDefinitions folder: $PolDefDir )"
        }

    }
