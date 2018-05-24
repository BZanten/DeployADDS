<#
.Synopsis
   Checks whether the ConfigMgr (SCCM) AD schema extensions are present in the current AD schema
.DESCRIPTION
   Checks whether the ConfigMgr (SCCM) AD schema extensions are present in the current AD schema
.EXAMPLE
   .\Check-AD-ConfigMgr-Attribute.ps1
.NOTES
   Author : Ben van Zanten
   Company: Rabobank International
   Date   : Dec 2015
   Version: 1.0

   History:  1.0  Initial version
   
#>

Function Check-AdAttribute {
  PARAM (
    [string]$AtrName
  )
    # Get the domain context from RootDSE
    $RootDSE=[ADSI]"LDAP://RootDSE"
    $dc=$RootDSE.rootDomainNamingContext

    $attrb=[ADSI]"LDAP://cn=$AtrName,CN=Schema,CN=Configuration,$dc"

    if ( $attrb.adminDisplayName -eq "$AtrName" ) {
        Write-Host -ForegroundColor Green "$AtrName found."
    } else {
        Write-Host -ForegroundColor Red "$AtrName NOT found."
    }
}

# Classes ...
Check-AdAttribute "MS-SMS-Management-Point"
Check-AdAttribute "MS-SMS-Server-Locator-Point"
Check-AdAttribute "MS-SMS-Site"
Check-AdAttribute "MS-SMS-Roaming-Boundary-Range"
# Attributes ...
Check-AdAttribute "MS-SMS-Site-Code"
Check-AdAttribute "mS-SMS-Assignment-Site-Code"
Check-AdAttribute "MS-SMS-Site-Boundaries"
Check-AdAttribute "MS-SMS-Roaming-Boundaries"
Check-AdAttribute "MS-SMS-Default-MP"
Check-AdAttribute "mS-SMS-Device-Management-Point"
Check-AdAttribute "MS-SMS-MP-Name"
Check-AdAttribute "MS-SMS-MP-Address"
Check-AdAttribute "mS-SMS-Health-State"
Check-AdAttribute "mS-SMS-Source-Forest"
Check-AdAttribute "MS-SMS-Ranged-IP-Low"
Check-AdAttribute "MS-SMS-Ranged-IP-High"
Check-AdAttribute "mS-SMS-Version"
Check-AdAttribute "mS-SMS-Capabilities"

