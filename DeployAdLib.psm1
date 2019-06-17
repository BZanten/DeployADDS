<#
.Synopsis
   Library of reusable functions for AD Domain and DC deployment
.DESCRIPTION
   Library of reusable functions for AD Domain and DC deployment
.NOTES
   Author : Ben van Zanten
   Company: Rabobank International
   Date   : Dec 2015
   Version: 1.3

   History:  1.0  Initial version
             1.1  Added Convert-HtToString
             1.2  Added Get-FileEncoding
             1.3  Added ConvertTo-Hashtable
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
    Begin {
        $ComputerName = [System.Environment]::MachineName
        $ComputerFQDN = ( [System.Net.Dns]::GetHostByName($Computername) ).HostName
        Write-Verbose "Computername: $ComputerName / $ComputerFQDN"
    }

    Process {
        [xml]$forXML = Get-Content $XmlFile
        if ([string]::IsNullOrEmpty($DomainName)) {
            Write-Verbose "DomainName is not given. Test the XML file. If that contains only 1 domain, this is the domain."
            if (@($forXML.forest.domains.domain).count -eq 1) {
                $DomainName = $forXML.forest.domains.domain.name
                Write-Verbose "Domainname '$DomainName' is determined from single domain mentioned in $XmlFile"
            } else {
                Write-Verbose "DomainName is empty AND the XML contains more than one... We can only assume the currentdomain, otherwise fail the job"
                $Domain = $forxml.forest.domains.domain | Where-Object { $_.DCs.DC.name -eq $ComputerFQDN }
                if (!($Domain)) { $Domain = $forxml.forest.domains.domain | Where-Object { $_.DCs.DC.name -eq $ComputerName } }
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
                    Write-Error "Domain cannot be found in the input file $XmlFile... please specify -DomainName as a parameter"
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
    PARAM(
        [System.Xml.XmlElement]$XmlObject,
        [System.Collections.Hashtable]$HashTable = @{}
    )

    $XmlObject.PSObject.Properties | Where-Object { $_.TypeNameOfValue -notmatch 'System.Xml'} | Where-Object { $_.Name -notin "BaseURI","OuterXML","IsReadOnly","HasChildnodes", "Value","InnerText","InnerXml","HasAttributes","IsEmpty","Prefix","NamespaceURI","LocalName","Password" }  | ForEach-Object {
        #
        # Translate "True" and "False" into booleans, but [System.Boolean]"False"  returns: True
        #
        # Save the $_ values since the switch statement will have its own new $_
        #
        $KeyName=$_.Name
        $Value=$_.Value

        switch -Regex ($Value) {
            "true"  { $HashTable[$KeyName] = $True }
            "false" { $HashTable[$KeyName] = $False }
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
                        $HashTable[$KeyName] = $subHT
                    } else {
                        $HashTable[$KeyName] = $Value
                    }
                    }
            default { $HashTable[$KeyName] = $Value }
        }
    }

    return $HashTable
}

<#
.Synopsis
  Converts a Hash table to an XML element
.Description
  Converts a Hash table to an XML element
.LINK 
  from: https://gallery.technet.microsoft.com/scriptcenter/Export-Hashtable-to-xml-in-122fda31
#>
Function Convert-HashTableToXml {
[cmdletbinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [System.String]$Root,
        
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        [System.Collections.Hashtable]$InputObject,
        
        [ValidateScript({Test-Path $_ -IsValid})]
        [System.String]$Path
    )
    Begin {
        $ScriptBlock = {
            Param($Elem, $Root)
            if ($Elem.Value -is [Array]) {
                $Elem.Value | Foreach-Object {
                    $ScriptBlock.Invoke(@(@{$Elem.Key=$_}, $Root))
                }
            }
            if ( $Elem.Value -is [System.Collections.Hashtable] ) {
                $RootNode = $Root.AppendChild($Doc.CreateNode([System.Xml.XmlNodeType]::Element,$Elem.Key,$Null))
                $Elem.Value.GetEnumerator() | ForEach-Object {
                    $Scriptblock.Invoke( @($_, $RootNode) )
                }
            }
            else {
                $Element = $Doc.CreateElement($Elem.Key)
                $Element.InnerText = if ($Elem.Value -is [Array]) {
                    $Elem.Value -join ','
                }
                else {
                    $Elem.Value | Out-String
                }
                $Root.AppendChild($Element) | Out-Null	
            }
        }	
    }
    Process {
        $Doc = [xml]"<$($Root)></$($Root)>"
        $InputObject.GetEnumerator() | ForEach-Object {
            $scriptblock.Invoke( @($_, $doc.DocumentElement) )
        }
        $doc.Save($Path)
    }
}


<#
.Synopsis
  Converts a Hash table to a string (for use in XML)
.Description
  Converts a Hash table to a string (for use in XML)
#>
Function Convert-HtToString {
    PARAM(
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [System.Collections.Hashtable]$HTInput
    )


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

Function ConvertTo-Hashtable {
  #.Synopsis
  #   Converts an object to a hashtable of property-name = value 
  # .LINK
  #  http://poshcode.org/4968
  # .LINK
  #  
  PARAM(
    # The object to convert to a hashtable
    [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
    $InputObject,

    # Excludes certain properties if required
    [string[]]$Exclude,

    # Forces the values to be strings and converts them by running them through Out-String
    [switch]$AsString,  

    # If set, allows each hashtable to have it's own set of properties, otherwise, 
    # each InputObject is normalized to the properties on the first object in the pipeline
    [switch]$jagged,

    # If set, empty properties are ommitted
    [switch]$NoNulls
  )
  BEGIN { 
    $headers = @() 
  }
  PROCESS {
    if(!$headers -or $jagged) {
      $headers = $InputObject | get-member -type Properties | select -expand name
    }
    $output = @{}
    if($AsString) {
      foreach($col in $headers) {
        if ($Exclude -notcontains $col) {
          if(!$NoNulls -or ($InputObject.$col -is [bool] -or ($InputObject.$col))) {
            $output.$col = $InputObject.$col | out-string -Width 9999 | % { $_.Trim() }
          }
        }
      }
    } else {
      foreach($col in $headers) {
        if ($Exclude -notcontains $col) {
          if(!$NoNulls -or ($InputObject.$col -is [bool] -or ($InputObject.$col))) {
            $output.$col = $InputObject.$col
          }
        }
      }
    }
    $output
  }
}

<#
.SYNOPSIS
  Gets file encoding.
.DESCRIPTION
  The Get-FileEncoding function determines encoding by looking at Byte Order Mark (BOM).
  Based on port of C# code from http://www.west-wind.com/Weblog/posts/197245.aspx
.EXAMPLE
  Get-ChildItem  *.ps1 | select FullName, @{n='Encoding';e={Get-FileEncoding $_.FullName}} | where {$_.Encoding -ne 'ASCII'}
  This command gets ps1 files in current directory where encoding is not ASCII
.EXAMPLE
  Get-ChildItem  *.ps1 | select FullName, @{n='Encoding';e={Get-FileEncoding $_.FullName}} | where {$_.Encoding -ne 'ASCII'} | foreach {(get-content $_.FullName) | set-content $_.FullName -Encoding ASCII}
  Same as previous example but fixes encoding using set-content
.LINK
  http://poshcode.org/2059
#>
function Get-FileEncoding
{
    [CmdletBinding()] Param (
     [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)] [string]$Path
    )

    [byte[]]$byte = get-content -Encoding byte -ReadCount 4 -TotalCount 4 -Path $Path

    if ( $byte[0] -eq 0xef -and $byte[1] -eq 0xbb -and $byte[2] -eq 0xbf )
    { Write-Output 'UTF8' }
    elseif ($byte[0] -eq 0xfe -and $byte[1] -eq 0xff)
    { Write-Output 'Unicode' }
    elseif ($byte[0] -eq 0 -and $byte[1] -eq 0 -and $byte[2] -eq 0xfe -and $byte[3] -eq 0xff)
    { Write-Output 'UTF32' }
    elseif ($byte[0] -eq 0x2b -and $byte[1] -eq 0x2f -and $byte[2] -eq 0x76)
    { Write-Output 'UTF7'}
    else
    { Write-Output 'ASCII' }
}

<#
.Example

 Format-XML ([xml](cat c:\ps\r_and_j.xml)) -indent 4
#>
function Format-XML ([xml]$xml, $indent=2) 
{ 
    $StringWriter = New-Object System.IO.StringWriter 
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
    $xmlWriter.Formatting = “indented” 
    $xmlWriter.Indentation = $Indent 
    $xml.WriteContentTo($XmlWriter) 
    $XmlWriter.Flush() 
    $StringWriter.Flush() 
    Write-Output $StringWriter.ToString() 
}



# -----------------------------------------------------------------------------
# Script: Get-FileMetaDataReturnObject.ps1
# Author: ed wilson, msft
# Date: 01/24/2014 12:30:18
# Keywords: Metadata, Storage, Files
# comments: Uses the Shell.APplication object to get file metadata
# Gets all the metadata and returns a custom PSObject
# it is a bit slow right now, because I need to check all 266 fields
# for each file, and then create a custom object and emit it.
# If used, use a variable to store the returned objects before attempting
# to do any sorting, filtering, and formatting of the output.
# To do a recursive lookup of all metadata on all files, use this type
# of syntax to call the function:
# Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName
# note: this MUST point to a folder, and not to a file.
# -----------------------------------------------------------------------------
Function Get-FileMetaData
{
  <#
   .Synopsis
    This function gets file metadata and returns it as a custom PS Object 
   .Description
    This function gets file metadata using the Shell.Application object and
    returns a custom PSObject object that can be sorted, filtered or otherwise
    manipulated.
   .Example
    Get-FileMetaData -folder "e:\music"
    Gets file metadata for all files in the e:\music directory
   .Example
    Get-FileMetaData -folder (gci e:\music -Recurse -Directory).FullName
    This example uses the Get-ChildItem cmdlet to do a recursive lookup of 
    all directories in the e:\music folder and then it goes through and gets
    all of the file metada for all the files in the directories and in the 
    subdirectories.  
   .Example
    Get-FileMetaData -folder "c:\fso","E:\music\Big Boi"
    Gets file metadata from files in both the c:\fso directory and the
    e:\music\big boi directory.
   .Example
    $meta = Get-FileMetaData -folder "E:\music"
    This example gets file metadata from all files in the root of the
    e:\music directory and stores the returned custom objects in a $meta 
    variable for later processing and manipulation.
   .Parameter Folder
    The folder that is parsed for files 
   .Notes
    NAME:  Get-FileMetaData
    AUTHOR: ed wilson, msft
    LASTEDIT: 01/24/2014 14:08:24
    KEYWORDS: Storage, Files, Metadata
    HSG: HSG-2-5-14
   .Link
     Http://www.ScriptingGuys.com
 #Requires -Version 2.0
 #>

 Param([string]$File)

    $Folder = Split-Path $File -Parent
    $FileName = Split-Path $File -Leaf

   $a = 0
   $objShell = New-Object -ComObject Shell.Application
   $objFolder = $objShell.namespace($Folder)

   foreach ($oFile in ($objfolder.Items() | Where-Object { $_.Name -eq $FileName }))  { 
     $FileMetaData = New-Object PSOBJECT
      for ($a ; $a  -le 266; $a++) { 
         if($objFolder.getDetailsOf($oFile, $a)) {
             $hash += @{$($objFolder.getDetailsOf($objFolder.items, $a))  =
                   $($objFolder.getDetailsOf($oFile, $a)) }
            $FileMetaData | Add-Member $hash
            $hash.clear() 
           } #end if
       } #end for 
     $a=0
     $FileMetaData
    } #end foreach $file
} #end Get-FileMetaData



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
        [string]$IPAddress,
        [string]$SubnetMask
    )

    [int64]$subnetMaskInt64 = Convert-Ipv4ToInt64 -IpAddress $SubnetMask
    [int64]$ipAddressInt64 = Convert-Ipv4ToInt64 -IpAddress $IPAddress


    # Return
    Convert-Int64toIpv4 ($subnetMaskInt64 -band $ipAddressInt64)
}
