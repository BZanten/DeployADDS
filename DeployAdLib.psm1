<#
.Synopsis
   Library of reusable functions for AD Domain and DC deployment
.DESCRIPTION
   Library of reusable functions for AD Domain and DC deployment
.NOTES
   Author : Ben van Zanten
   Company: Valid
   Date   : Dec 2015
   Version: 1.1

   History:  1.0  Initial version
             1.1  Added Convert-HtToString
#>

Function Test-AdminStatus {
    process {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal $identity
        return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }
}


Function Get-DomainName {
    Param
    (
        # Name of the input file, default is: ADStructure.xml
        [Parameter(Mandatory=$false,Position=1, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false, 
                   ValueFromRemainingArguments=$false)]
                   [ValidateScript({Test-Path $_})]
        [string]$XmlFile='.\ADStructure.xml',

    # Name of the domain. For instance  contoso.local. If not given, the domain from the XML is used
    [Parameter(Mandatory=$False,Position=2)]
    [string]$DomainName
    )

    Process {
        [xml]$forXML = Get-Content $XmlFile
        if ([string]::IsNullOrEmpty($DomainName)) {
            # DomainName is not given. Test the XML file. If that contains only 1 domain, this is the domain.
            if (@($forXML.forest.domains.domain).count -eq 1) {
                $DomainName = $forXML.forest.domains.domain.name
                Write-Verbose "Domainname '$DomainName' is determined from single domain mentioned in $XmlFile"
            } else {
                # Now DomainName is empty AND the XML contains more than one... We can only assume the currentdomain, otherwise fail the job
                $ComputerName = [System.Environment]::MachineName
                $Domain = $forxml.forest.domains.domain | ? { $_.DCs.DC.name -eq $ComputerName }
                if ( $Domain -is [System.Xml.XmlLinkedNode] ) {
                    $DomainName = $Domain.name
                    Write-Verbose "Domainname '$DomainName' is determined from DC mentioned in $XmlFile"
                } else {
                    Write-Error "Domain cannot be determined... please enter the local computer as DCs\DC in the XML file, or specify -DomainName as a parameter"
                    break
                }
            }
        } else {
            # allow both name  and dnsname to be specified...  rework to name.
            if ( @( $forXML.forest.domains.domain | Where-Object { $_.dnsname -eq $DomainName } ).Count -eq 1 ) {
                $DomainName = ( $forXML.forest.domains.domain | Where-Object { $_.dnsname -eq $DomainName } ).name
                Write-Verbose "Domainname '$DomainName' is determined from parameter."
            } else {
                if ( @( $forXML.forest.domains.domain | Where-Object { $_.name -eq $DomainName } ).Count -eq 1 ) {
                    $DomainName = ( $forXML.forest.domains.domain | Where-Object { $_.name -eq $DomainName } ).name
                    Write-Verbose "Domainname '$DomainName' is determined from parameter."
                } else {
                    Write-Error "Domain cannot be found in the input file $XmlFile... please specify the correct -DomainName as a parameter, or do not use the -DomainName parameter"
                    break
                }
            }
        }
        # Now DomainName must be determined.
        return $DomainName
    }
}


<#
.Synopsis
  Recursively walks a OU structure up from the leaf OU to the root. Builds a DN string on the way.
.DESCRIPTION
  Recursively walks a OU structure up from the leaf OU to the root. Builds a DN string on the way up.
.LINK
  Original code from:
  http://stackoverflow.com/questions/26403915/powershell-xml-iterating-through-parent-nodes
.NOTES
  Author : Ben van Zanten
  Company: Rabobank International
  Date   : Dec 2015
  Version: 1.0

   History:  1.0  Initial version
#>
Function ConvertFrom-ADXmlToDN ($Element) {

    $DNparent = ""

    #Get parent DN - Recursion
    #    -and ($Element.ParentNode.LocalName -ne 'OUs') -and ($Element.ParentNode.LocalName -ne 'forest')
    if (($Element.ParentNode -ne $null) -and ($Element.ParentNode.LocalName -ne 'domains'  -and ($Element.ParentNode.LocalName -ne 'forest') )) { 
        $DNparent = ",$(ConvertFrom-ADXmlToDN -Element $Element.ParentNode)"
    }

    if (($Element.ParentNode.LocalName -eq 'OUs') ) { 
        $DNparent = ",$(ConvertFrom-ADXmlToDN -Element $Element.ParentNode.ParentNode)"
    }

    #Convert to LDAP path  
    switch($Element.LocalName) {
        "host"   { "CN=$($Element.GetAttribute("name"))$DNparent" }
        "CN"     { "CN=$($Element.GetAttribute("name"))$DNparent" }
        "OU"     { "OU=$($Element.GetAttribute("name"))$DNparent" }
        "domain" {
                    if ($Element.GetAttribute("distinguishedName") -match "DC=") {
                        $Element.GetAttribute("distinguishedName")
                    } elseif ($Element.GetAttribute("name") -match "DC=") {
                        $Element.GetAttribute("name")
                    } elseif ($Element.GetAttribute("name").Contains('.')) {
                        "DC=$($Element.GetAttribute("name") -split '\.' -join ',DC=')$DNparent"
                    }
                }
    }
}

<#
.Synopsis
   Recursively walks a OU structure down from the root to the lowest leaf OU.
.DESCRIPTION
   Recursively walks a OU structure down from the root to the lowest leaf OU.
   Retrieves the DN of each OU and CN (Container) using another recursive function.
.LINK
  Original code from:
  http://stackoverflow.com/questions/26403915/powershell-xml-iterating-through-parent-nodes
.NOTES
   Author : Ben van Zanten
   Company: Rabobank International
   Date   : Dec 2015
   Version: 1.0

   History:  1.0  Initial version
#>
Function Get-ADXmlOU ($Element) {
    ConvertFrom-ADXmlToDN $Element
    # Use recursion to get all sub-OUs
    ForEach ($OU in $Element.OU) {
        Get-ADXmlOU $OU
    }
    # Use recursion to get all sub-Containers
    ForEach ($OU in $Element.CN) {
        Get-ADXmlOU $OU
    }
}


<#
.Synopsis
  Converts an XML Element to a Hash table
.Description
  Converts an XML Element to a Hash table
#>
Function Convert-XmlToHT {
    PARAM([System.Xml.XmlElement]$XmlObject)

    $newHT = @{}
    $XmlObject.PSObject.Properties | ? { $_.TypeNameOfValue -notmatch 'System.Xml'} | ? { $_.Name -notin "BaseURI","OuterXML","IsReadOnly","HasChildnodes", "Value","InnerText","InnerXml","HasAttributes","IsEmpty","Prefix","NamespaceURI","LocalName","Password" }  | ForEach-Object {
        #
        # Translate "True" and "False" into booleans, but [System.Boolean]"False"  returns: True
        #
        # Save the $_ values since the switch statement will have its own new $_
        #
        $KeyName=$_.Name
        $Value=$_.Value

        switch -Regex ($Value) {
            "true"  { $newHT[$KeyName] = $True }
            "false" { $newHT[$KeyName] = $False }
            #
            # Hashtable:  the Property OtherAttributes requires a hashtable, (so we get a hashtable within a hashtable)
            #             however the  property seems to require a string in the form of a hashtable - that doesn't work. Has to be a hashtable as well.
            # ? Match @{...}  ?
            {$_ -match '^\s*@\s*\{.*\}\s*$'} {
                    if ($KeyName -in 'OtherAttributes','ServicePrincipalNames') {
                        # Run the -match  once again so we get a $matches[] collection...
                        $Value -match '^\s*@\s*\{.*\}\s*$' | Out-Null
                        $newValue = ($matches[0]) -Replace '^\s*@\s*\{','' -Replace '}\s*$',''
                        $subHT= @{}
                        $newValue -Split ';' | ForEach-Object {
                            $Line = $_
                            $SubKeyName = $Line.Substring(0, $Line.IndexOf('='))
                            $SubValue   = $Line.Substring($Line.IndexOf('=')+1)
                            #  sometimes $SubValue is an array of "...","..."   lets recreate the array
                            if ($SubValue -match '^\s*".*",".*"\s*$') {
                                $SubValue = ($SubValue -split '","').Replace('"','')
                            }
                            $subHT[$SubKeyName] = $SubValue
                        }
                        $newHT[$KeyName] = $subHT
                    } else {
                        $newHT[$KeyName] = $Value
                    }
                    }
            default { $newHT[$KeyName] = $Value }
        }
    }

    return $newHT
}


<#
.Synopsis
  Converts a Hash table to a string (for use in XML)
.Description
  Converts a Hash table to a string (for use in XML)
#>
Function Convert-HtToString {
    PARAM([System.Collections.Hashtable]$HTInput)

    Function Quote-String  {
    PARAM ([string]$InputStr)
        if ($InputStr -match '=') {
            Write-Output """$InputStr"""
        } else {
            Write-Output $InputStr
        }
    }

    Function Quote-Array  {
    PARAM ($InputStr)

        [string]$OutString=""

        $i=0
        ForEach ($Regel in $InputStr) {
        $i++
          $OutString += Quote-String $Regel
          $OutString += ','
        }

        $OutString.TrimEnd(',')
    }

    $OFS =';'
    [string]($HTInput.GetEnumerator() | ForEach-Object {
            if (($_.Value -is [array]) -or ($_.Value -is [System.Collections.CollectionBase])) {
                "{0}={1}" -f ($_.Key, (Quote-Array $_.Value ))
            } else {
                "{0}={1}" -f ($_.Key, (Quote-String $_.Value))
            }
        }
      )

}


#
# https://gallery.technet.microsoft.com/scriptcenter/Convert-subnet-mask-7b501479
#  Convert subnet mask (255.255.255.0 -> 24) from classes to classless (CIDR)
#

Function Convert-Ipv4ToInt64 {
<#
.DESCRIPTION
  Converts an IPv4 address ###.###.###.### to its corresponding numeric value (32-bit integer)
  The return value is an int64 however, since 2147483648 cannot be converted to Int32 (128.0.0.0).  (Int32 is -2147483648 to 2147483647, not 0 to 4294967295)
.Example
Convert-Ipv4ToInt64 "192.168.20.14"
3232240654
.Notes
    Developer
        Developer: Rudolf Vesely, http://rudolfvesely.com/
        Copyright (c) Rudolf Vesely. All rights reserved
        License: Free for private use only
#>

    Param
    (
        [string]
        $IpAddress
    )

    $ipAddressParts = $IpAddress.Split('.') # IP to it's octets

    # Return
    [int64]([int64]$ipAddressParts[0] * 16777216 +
            [int64]$ipAddressParts[1] * 65536 +
            [int64]$ipAddressParts[2] * 256 +
            [int64]$ipAddressParts[3] )
}

Function Convert-IPv4ClassToCidr {
<#
.DESCRIPTION
  Converts an IPv4 subnetmask (255.255.255.0) to its Cidr notation number : /24
.Example
Convert-IPv4ClassToCidr -SubnetMask 255.255.255.128
25
#>

    Param
    (
        [string]
        $SubnetMask
    )

    [int64]$subnetMaskInt64 = Convert-Ipv4ToInt64 -IpAddress $SubnetMask

    $subnetMaskCidr32Int = 2147483648 # 0x80000000 - Same as Convert-Ipv4ToInt64 -IpAddress '128.0.0.0'

    $subnetMaskCidr = 0
    for ($i = 0; $i -lt 32; $i++) {
        if (!($subnetMaskInt64 -band $subnetMaskCidr32Int) -eq $subnetMaskCidr32Int) { break } # Bitwise and operator - Same as "&" in C#

        $subnetMaskCidr++
        $subnetMaskCidr32Int = $subnetMaskCidr32Int -shr 1 # Bit shift to the right - Same as ">>" in C#
    }

    # Return
    $subnetMaskCidr
}


Function Convert-CidrToIpv4Int64 {
<#
.DESCRIPTION
  Converts a Cidr (f.i. /8 or /24) to an Int64 number
.Example
Convert-CidrToIpv4Int64 -Bits 8
4278190080
Convert-Int64toIpv4 4278190080
255.0.0.0
.Example
Convert-Int64toIpv4 (Convert-CidrToIpv4Int64 -Bits 25)
255.255.255.128
#>
    Param (
      [ValidateRange(0,32)]
      [int]$Bits=8
    )

    $CountBits = $Bits

    # shift left 32x.  Add a 1 for the number of bits we need to add.
    [int64]$bitarray=0
    for ($i=0; $i -lt 32; $i++) {
        #  Add a '1' to our array if bits are to be added.
        if ($CountBits -gt 0) { $bitarray++ }

        # decrease the number of bits to add
        $CountBits--

        # Shift left the array, except for the last step.
        if ($i -lt 31) {
            $bitarray = $bitarray -shl 1
        }
    }

    # Return
    $BitArray
}


Function Convert-Int64toIpv4 {
<#
.DESCRIPTION
  Converts a 32-bit integer ([int64]) into a human readable IPv4 address.
.Example
  Convert-CidrToRvNetSubnetMaskClasses -Bits 24
  4294967040
  Convert-Int64toIpv4 4294967040
  255.255.255.0
.Example
  Convert-Int64toIpv4 ( Convert-CidrToIpv4Int64 -Bits 16 )
  255.255.0.0
.Notes
    Developer
        Developer: Ben van Zanten
        Copyright (c) Ben van Zanten. All rights reserved
        License: Free for my use only
#>
    Param (
      [ValidateRange(0,4294967295)]
      [int64]$LongNumber
    )

    [int64]$antw=0
    [string[]]$IpAddress= [string[]]@(0,0,0,0)
    
    $IpAddress[0] = [system.math]::DivRem($LongNumber,16777216,[ref]$antw)
    $IpAddress[1] = [system.math]::DivRem($antw,65536,[ref]$antw)
    $IpAddress[2] = [system.math]::DivRem($antw,256,[ref]$antw)
    $IpAddress[3] = $antw

    # Return
    Return [string]::Join('.',$IpAddress)
}


Function Convert-IPv4MaskToNetwork {
<#
.DESCRIPTION
  Converts an IPv4 address (1.2.3.4) and subnetmask (255.255.255.0) to its IPv4 Network id: 1.2.3.0
.Example
Convert-IPv4MaskToNetwork -IP 1.2.3.4 -SubnetMask 255.255.255.128
1.2.3.0
.Example
Convert-IPv4MaskToNetwork -IPAddress 57.192.223.221 "255.255.192.0"
57.192.192.0
#>

    Param
    (
        [string]
        $IPAddress,
        [string]
        $SubnetMask
    )

    [int64]$subnetMaskInt64 = Convert-Ipv4ToInt64 -IpAddress $SubnetMask
    [int64]$ipAddressInt64 = Convert-Ipv4ToInt64 -IpAddress $IPAddress


    # Return
    Convert-Int64toIpv4 ($subnetMaskInt64 -band $ipAddressInt64)
}
