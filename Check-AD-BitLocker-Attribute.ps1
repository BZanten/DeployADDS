<#
.Synopsis
   Checks whether the BitLocker AD schema extensions are present in the current AD schema
.DESCRIPTION
   Checks whether the BitLocker AD schema extensions are present in the current AD schema
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

    if ( $attrb.cn -eq $AtrName ) {
        Write-Host -ForegroundColor Green "$AtrName found."
    } else {
        Write-Host -ForegroundColor Red "$AtrName NOT found."
    }
}

# Attributes ...
Check-AdAttribute "ms-FVE-KeyPackage"
Check-AdAttribute "ms-FVE-RecoveryGuid"
Check-AdAttribute "ms-FVE-RecoveryInformation"
Check-AdAttribute "ms-FVE-RecoveryPassword"
Check-AdAttribute "ms-FVE-VolumeGuid"
Check-AdAttribute "ms-TPM-OwnerInformation"
