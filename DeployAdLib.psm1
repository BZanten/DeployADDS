<#
.Synopsis
   Library of reusable functions for AD Domain and DC deployment
.DESCRIPTION
   Library of reusable functions for AD Domain and DC deployment
.NOTES
   Author : Ben van Zanten
   Company: Rabobank International
   Date   : Dec 2015
   Version: 2.0

   History:  1.0  Initial version
             1.1  Added Convert-HtToString
             1.2  Added Get-FileEncoding
             1.3  Added ConvertTo-Hashtable
             2.0  Added WMIFilter features, now requires ActiveDirectory PowerShell module
#>
[CmdletBinding(SupportsShouldProcess=$true)]
PARAM()

#Requires -Modules ActiveDirectory
#Requires -Version 4

Import-Module ActiveDirectory -Verbose:$False

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
  PARAM (
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
Function Get-FileEncoding {
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
Function Format-XML ([xml]$xml, $indent=2) { 
    $StringWriter = New-Object System.IO.StringWriter 
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
    $xmlWriter.Formatting = "indented" 
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
Function Get-FileMetaData {
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

 Param ([string]$File)

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

# From: https://github.com/jdhitsolutions/DNSSuffix
Function Set-PrimaryDNSSuffix {
  [cmdletbinding(SupportsShouldProcess)]
  Param(
      [Parameter(Position = 0, HelpMessage = "Enter the new primary DNS Suffix name e.g. company.pri")]
      [string]$DNSSuffix,
      [switch]$SynchronizeSuffix
  )
  
  Process {
    Write-Verbose "[$((Get-Date).TimeofDay) PROCESS] Setting Primary DNS Suffix"
    if ($PSCmdlet.ShouldProcess("Change DNSSuffix")) {
        Try {
          if ($SynchronizeSuffix) {
              $Synch = 1
          }
          else {
              $Synch = 0
          }
          Set-ItemProperty -path HKLM:\system\CurrentControlSet\Services\tcpip\parameters -Name Domain -Value $DNSSuffix
          Set-ItemProperty -path HKLM:\system\CurrentControlSet\Services\tcpip\parameters -Name 'NV Domain' -Value $DNSSuffix
          Set-ItemProperty -path HKLM:\system\CurrentControlSet\Services\tcpip\parameters -Name SyncDomainWithMembership -Value $Synch
        }
        Catch {
            Write-Warning "[$((Get-Date).TimeofDay) PROCESS] Error with command. $($_.Exception.Message)"
        }
    }
  } #process

} #close Set-PrimaryDNSSuffix

Function Get-PrimaryDNSSuffix {
  [cmdletbinding()]
  [OutputType("PSCustomObject")]

  Param(  )

  Process {
      
    Write-Verbose "[$((Get-Date).TimeofDay) PROCESS] Getting Primary DNS Suffix settings."

    Try {
      $reg = Get-ItemProperty  HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters 
      [pscustomobject]@{
          Computername = $reg.hostname
          Domain       = $reg.Domain
          'NV Domain'  = $reg.'NV Domain'
          SynchronizeSuffix = $reg.SyncDomainWithMembership -as [Bool]
      }
    }
    Catch {
        write-warning "[$((Get-Date).TimeofDay) PROCESS] Error with command. $($_.Exception.Message)"
    }

  } #process
} #close Get-PrimaryDNSSuffix

<#
.Description
  Retrieves info whether the computer is domain joined yes or no
.Link
  https://docs.microsoft.com/en-us/windows/desktop/cimwin32prov/win32-computersystem
#>
Function Get-DomainRole {

  $ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem -Namespace Root\CIMV2

  Switch ($ComputerInfo.DomainRole)  {
    0 { $DomainRoleString = 'Standalone Workstation' }
    1 { $DomainRoleString = 'Member Workstation' }
    2 { $DomainRoleString = 'Standalone Server' }
    3 { $DomainRoleString = 'Member Server' }
    4 { $DomainRoleString = 'Backup Domain Controller' }
    5 { $DomainRoleString = 'Primary Domain Controller' }
    default { $DomainRoleString = 'Unknown' }
  }

  [pscustomobject]@{
    Name         = $ComputerInfo.Name
    DNSHostName  = $ComputerInfo.DNSHostName
    Domain       = $ComputerInfo.Domain
    DomainRole   = $ComputerInfo.DomainRole
    DomainRoleStr= $DomainRoleString
    PartOfDomain = $ComputerInfo.PartOfDomain
    Workgroup    = $ComputerInfo.Workgroup
    SynchronizeSuffix = $reg.SyncDomainWithMembership -as [Bool]
  }
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
        [string]$IPAddress,
        [string]$SubnetMask
    )

    [int64]$subnetMaskInt64 = Convert-Ipv4ToInt64 -IpAddress $SubnetMask
    [int64]$ipAddressInt64 = Convert-Ipv4ToInt64 -IpAddress $IPAddress


    # Return
    Convert-Int64toIpv4 ($subnetMaskInt64 -band $ipAddressInt64)
}



#  https://gallery.technet.microsoft.com/scriptcenter/f1491111-9f5d-4c83-b436-537eca9e8d94
#  https://github.com/darkoperator/powershell_scripts/blob/master/install-wmifilters.ps1
#  https://sdmsoftware.com/group-policy-blog/gpmc/digging-into-group-policy-wmi-filters-and-managing-them-through-powershell/


<#
.Synopsis
   Script for creating WMI Filters for use with Group Policy Manager.
.DESCRIPTION
   The Script will create several WMI Filters for filtering based on:
   - Processor Architecture.
   - If the Hosts is a Virtual Machine
   - Operating System Version.
   - Type of Operating System.
   - If Java is installed
   - If Version 6 or 7 of Java JRE is installed.
   - Version of IE
.EXAMPLE
   Running script if verbose output

   .\install-wmifilters.ps1 -Verbose
.NOTES
   Author: Carlos Perez carlos_perez[at]darkoperator.com
   Date: 1/13/13
   Requirements: Execution policy should be RemoteSigned since script is not signed.
#>

class WMIFilter {

    [string]$Name
    [string]$Query
    [string]$Description
    [string]$NameSpace = 'Root\CIMV2'

    # Constructors
    WMIFilter (){
    }
    
    # Constructor Name
    WMIFilter ([string]$Name) {
        $this.Name = $Name
        $this.Description = $Name
    }

    # Constructor Name, Query
    WMIFilter ([string]$Name, [string]$Query) {
        $this.Name = $Name
        $this.Query = $Query
        $this.Description = $Name
    }

    # Constructor Name, Query, Description
    WMIFilter ([string]$Name, [string]$Query, [string]$Description) {
        $this.Name = $Name
        $this.Query = $Query
        $this.Description = $Description
    }
        
}

Function Set-DCAllowSystemOnlyChange {
    param ([switch]$Set)
    if ($Set) {
        Write-Verbose "Checking if registry key is set to allow changes to AD System Only Attributes is set."
        $ntds_vals = (Get-Item HKLM:\System\CurrentControlSet\Services\NTDS\Parameters).GetValueNames()
        if ( $ntds_vals -eq "Allow System Only Change")  {
            $kval = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -name "Allow System Only Change"
            if ($kval -eq "1") {
                Write-Verbose "Allow System Only Change key is already set"    
            } else {
                Write-Verbose "Allow System Only Change key is not set"
                Write-Verbose "Creating key and setting value to 1"
                Set-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -name "Allow System Only Change" -Value 0 | Out-Null
            }
        } else {
            New-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -name "Allow System Only Change" -Value 1 -PropertyType "DWord" | Out-Null
        }
    } else {
        $ntds_vals = (Get-Item HKLM:\System\CurrentControlSet\Services\NTDS\Parameters).GetValueNames()
        if ( $ntds_vals -eq "Allow System Only Change") {
            Write-Verbose "Disabling Allow System Only Change Attributes on server"
            Set-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -name "Allow System Only Change" -Value 0 | Out-Null
        }
    }
}

Function New-WMIFilter {
    # Based on function from http://gallery.technet.microsoft.com/scriptcenter/f1491111-9f5d-4c83-b436-537eca9e8d94
    # WMIFilter: custom object with: Name,Query,Description,NameSpace
    PARAM (
        [Parameter(Mandatory=$true, ValueFromPipeline=$True)]
        [WMIFilter]$WMIFilter,

        [Parameter(Mandatory=$true, ValueFromPipeline=$False)]
        $Domain = (Get-ADDomain -Current LocalComputer)
    )

    $DomainADSI = Get-ADDomain -Identity $Domain
    if ($DomainADSI) {

        # $defaultNamingContext = (Get-ADRootDSE).defaultNamingContext
        $NamingContext = $DomainADSI.DistinguishedName

        $msWMIAuthor = "Administrator@" + $DomainADSI.DNSRoot
        $Soms = Get-ADObject -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$($DomainADSI.DistinguishedName)" -SearchScope Subtree -Properties *  -Filter "ObjectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$($WMIFilter.Name)'" -Server $DomainADSI.PDCEmulator
        if ($Soms) {
            Write-Error "WMI Filter $($WMIFilter.Name) in Domain $($DomainADSI.Name) already exists, use Set-WMIFilter to change"
        } else {

            Write-Verbose "Starting creation of WMI Filter"
            $WMIGUID = [string]"{"+([System.Guid]::NewGuid())+"}"   
            $WMIDN = "CN="+$WMIGUID+",CN=SOM,CN=WMIPolicy,CN=System,"+$NamingContext
            $WMICN = $WMIGUID
            $WMIdistinguishedname = $WMIDN
            $WMIID = $WMIGUID

            $now = (Get-Date).ToUniversalTime()
            $msWMICreationDate = ($now.Year).ToString("0000") + ($now.Month).ToString("00") + ($now.Day).ToString("00") + ($now.Hour).ToString("00") + ($now.Minute).ToString("00") + ($now.Second).ToString("00") + "." + ($now.Millisecond * 1000).ToString("000000") + "-000"

            $msWMIName = $WMIFilter.Name
        
            $Attr = @{
                "msWMI-Name"             = $msWMIName;
                "msWMI-Parm1"            = $msWMIParm1 = $WMIFilter.Description;
                "msWMI-Parm2"            = "1;3;10;" + $WMIFilter.Query.Length.ToString() + ";WQL;$($WMIFilter.NameSpace);" + $WMIFilter.Query.ToString() + ";"  ;
                "msWMI-Author"           = $msWMIAuthor;
                "msWMI-ID"               = $WMIID;
                "instanceType"           = 4;
                "showInAdvancedViewOnly" = "TRUE";
                "distinguishedname"      = $WMIdistinguishedname;
                "msWMI-ChangeDate"       = $msWMICreationDate;
                "msWMI-CreationDate"     = $msWMICreationDate
            }
            $WMIPath = ("CN=SOM,CN=WMIPolicy,CN=System,"+$NamingContext)

            $ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem -Namespace Root\CIMV2
            if ($ComputerInfo.DomainRole -in (4,5)) {
                Write-Verbose "Local machine is a DC, then we need to (Temp) enable local system change!"
                Set-DCAllowSystemOnlyChange -Set

                Write-Verbose "Adding WMI Filter for: $msWMIName"
                New-ADObject -name $WMICN -type "msWMI-Som" -Path $WMIPath -OtherAttributes $Attr -Server $DomainADSI.PDCEmulator # | Out-Null

                Set-DCAllowSystemOnlyChange
            } else {
                Write-Verbose "Adding WMI Filter for: $msWMIName"
                New-ADObject -name $WMICN -type "msWMI-Som" -Path $WMIPath -OtherAttributes $Attr -Server $DomainADSI.PDCEmulator # | Out-Null
            }
        } # end if WMI filter already exists
    }
    Write-Verbose "Finished adding WMI Filter"
}

Function Remove-WMIFilter {
    # Based on function from http://gallery.technet.microsoft.com/scriptcenter/f1491111-9f5d-4c83-b436-537eca9e8d94
    # WMIFilter: custom object with: Name,Query,Description,NameSpace
    PARAM (
        [Parameter(Mandatory=$true, ValueFromPipeline=$True)]
        [WMIFilter]$WMIFilter,

        [Parameter(Mandatory=$true, ValueFromPipeline=$False)]
        $Domain = (Get-ADDomain -Current LocalComputer)
    )

    $DomainADSI = Get-ADDomain -Identity $Domain
    if ($DomainADSI) {

        # $defaultNamingContext = (Get-ADRootDSE).defaultNamingContext
        $NamingContext = $DomainADSI.DistinguishedName

        $Soms = Get-ADObject -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$($DomainADSI.DistinguishedName)" -SearchScope Subtree -Properties *  -Filter "ObjectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$($WMIFilter.Name)'" -Server $DomainADSI.PDCEmulator
        if ( @($Soms).Count -eq 0) {
            Write-Error "WMI Filter $($WMIFilter.Name) in Domain $($DomainADSI.Name) cannot be found, use New-WMIFilter to Create one"
        }
        elseif ( @($Soms).Count -gt 1) {
            Write-Error "Multiple WMI Filters $($WMIFilter.Name) in Domain $($DomainADSI.Name) found, not continuing."
        } else {

            Write-Verbose "Removing WMI Filter $($Soms.ObjectGUID)"
            $ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem -Namespace Root\CIMV2
            if ($ComputerInfo.DomainRole -in (4,5)) {
                Write-Verbose "Local machine is a DC, then we need to (Temp) enable local system change!"
                Set-DCAllowSystemOnlyChange -Set

                Write-Verbose "Removing WMI Filter: $($WMIFilter.Name)"
                Remove-ADObject -Identity $Soms -Server $DomainADSI.PDCEmulator

                Set-DCAllowSystemOnlyChange
            } else {
                Write-Verbose "Removing WMI Filter: $($WMIFilter.Name)"
                Remove-ADObject -Identity $Soms -Server $DomainADSI.PDCEmulator
            }
        } # end if WMI filter already exists
    }
    Write-Verbose "Finished removing WMI Filter"
}

Function Set-WMIFilter {
    # Based on function from http://gallery.technet.microsoft.com/scriptcenter/f1491111-9f5d-4c83-b436-537eca9e8d94
    # WMIFilter: custom object with: Name,Query,Description,NameSpace
    PARAM (
        [Parameter(Mandatory=$true, ValueFromPipeline=$True)]
        [WMIFilter]$WMIFilter,

        [Parameter(Mandatory=$true, ValueFromPipeline=$False)]
        $Domain = (Get-ADDomain -Current LocalComputer)
    )

    $DomainADSI = Get-ADDomain -Identity $Domain
    if ($DomainADSI) {

        # $defaultNamingContext = (Get-ADRootDSE).defaultNamingContext
        $NamingContext = $DomainADSI.DistinguishedName

        $Soms = Get-ADObject -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$($DomainADSI.DistinguishedName)" -SearchScope Subtree -Properties *  -Filter "ObjectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$($WMIFilter.Name)'" -Server $DomainADSI.PDCEmulator
        if ( @($Soms).Count -eq 0) {
            Write-Error "WMI Filter $($WMIFilter.Name) in Domain $($DomainADSI.Name) cannot be found, use New-WMIFilter to Create one"
        }
        elseif ( @($Soms).Count -gt 1) {
            Write-Error "Multiple WMI Filters $($WMIFilter.Name) in Domain $($DomainADSI.Name) found, not continuing."
        } else {

            Write-Verbose "Changing WMI Filter $($Soms.ObjectGUID)"

            $now = (Get-Date).ToUniversalTime()
            $msWMICreationDate = ($now.Year).ToString("0000") + ($now.Month).ToString("00") + ($now.Day).ToString("00") + ($now.Hour).ToString("00") + ($now.Minute).ToString("00") + ($now.Second).ToString("00") + "." + ($now.Millisecond * 1000).ToString("000000") + "-000"

            $Attr = @{
                "msWMI-Parm1"            = $msWMIParm1 = $WMIFilter.Description;
                "msWMI-Parm2"            = "1;3;10;" + $WMIFilter.Query.Length.ToString() + ";WQL;$($WMIFilter.NameSpace);" + $WMIFilter.Query.ToString() + ";"  ;
                "msWMI-ChangeDate"       = $msWMICreationDate;
            }

            $ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem -Namespace Root\CIMV2
            if ($ComputerInfo.DomainRole -in (4,5)) {
                Write-Verbose "Local machine is a DC, then we need to (Temp) enable local system change!"
                Set-DCAllowSystemOnlyChange -Set

                Write-Verbose "modifying WMI Filter for: $($WMIFilter.Name)"
                Set-ADObject -Identity $Soms -Replace $Attr -Server $DomainADSI.PDCEmulator

                Set-DCAllowSystemOnlyChange
            } else {
                Write-Verbose "modifying WMI Filter for: $($WMIFilter.Name)"
                Set-ADObject -Identity $Soms -Replace $Attr -Server $DomainADSI.PDCEmulator
            }
        } # end if WMI filter already exists
    }
    Write-Verbose "Finished modifying WMI Filter"
}

Function Get-WMIFilter {
    PARAM (
        [Parameter(Mandatory=$false, ValueFromPipeline=$False)]
        $Domain = (Get-ADDomain -Current LocalComputer),

        [Parameter(Mandatory=$false, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$true, ParameterSetName='WMIFilter')]
        [WMIFilter]$WMIFilter,

        [Parameter(Mandatory=$false, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$true, ParameterSetName='Name')]
        [string]$Name,

        [Parameter(Mandatory=$false, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$true, ParameterSetName='All')]
        [switch]$All
    )

    $DomainADSI = Get-ADDomain -Identity $Domain
    if ($DomainADSI) {
    if ($WMIFIlter) { 
        $SearchFilter = "ObjectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$($WMIFilter.Name)'"
    } elseif ($Name) {
        $SearchFilter = "ObjectClass -eq 'msWMI-Som' -and msWMI-Name -eq '$Name'"
    } else {
        $SearchFilter = "ObjectClass -eq 'msWMI-Som'"
    }
    $Soms = Get-ADObject -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$($DomainADSI.DistinguishedName)" -SearchScope Subtree -Properties *  -Filter $SearchFilter -Server $DomainADSI.PDCEmulator

    ForEach ($Som in $Soms) {
        [pscustomobject]@{
        Name         = $Som.'msWMI-Name'
        Query        = (($Som.'msWMI-Parm2') -Split ';')[6]
        NameSpace    = (($Som.'msWMI-Parm2') -Split ';')[5]
        Author       = $Som.'msWMI-Author'
        ChangeDate   = $Som.'msWMI-ChangeDate'
        CreationDate = $Som.'msWMI-CreationDate'
        Description  = $Som.'msWMI-Parm1'
        ID           = $Som.'msWMI-ID'
        }
    }
    } else {
        Write-Error "Cannot find domain $Domain"
    }
}


<#
.Example
$WMIFilters = @(
  [pscustomobject]@{
    Name         = 'Check for Operating System Windows 2016'
    Query        = 'Select * from Win32_OperatingSystem where (Version = "10.0.14393" and (ProductType="2" or ProductType = "3" ) )'
    NameSpace    = 'root\CIMv2'
    Description  = 'Check for Operating System Windows 2016'
  },
  [pscustomobject]@{
    Name         = 'Check for Operating System Windows 2019'
    Query        = 'Select * from Win32_OperatingSystem where (Version = "10.0.17763" and (ProductType="2" or ProductType = "3" ) )'
    NameSpace    = 'root\CIMv2'
    Description  = 'Check for Operating System Windows 2019'
  }
)

forEach ($WmiFilter in $WMIFilters) {  New-WMIFilter -Domain 'rabotest.com'    -WMIFilter $WmiFilter -Verbose }
forEach ($WmiFilter in $WMIFilters) {  New-WMIFilter -Domain 'am.rabotest.com' -WMIFilter $WmiFilter -Verbose }
forEach ($WmiFilter in $WMIFilters) {  New-WMIFilter -Domain 'ap.rabotest.com' -WMIFilter $WmiFilter -Verbose }
forEach ($WmiFilter in $WMIFilters) {  New-WMIFilter -Domain 'eu.rabotest.com' -WMIFilter $WmiFilter -Verbose }
forEach ($WmiFilter in $WMIFilters) {  New-WMIFilter -Domain 'oc.rabotest.com' -WMIFilter $WmiFilter -Verbose }

get-adcomputer -filter * -properties operatingsystem,operatingsystemversion | sort OperatingSystem,Name | ft DNSHostName,OperatingSystemVersion,OperatingSystem
get-adcomputer -filter * -properties operatingsystem,operatingsystemversion | Select-Object -Property OperatingSystemVersion,OperatingSystem -Unique | Sort-Object -Property OperatingSystemVersion | ft OperatingSystemVersion,OperatingSystem

   $WMIFilter2019 =  [pscustomobject]@{
    Name         = 'Check for Operating System Windows 2019'
    Query        = 'Select * from Win32_OperatingSystem where (Version = "10.0.17763" and (ProductType="2" or ProductType = "3" ) )'
    NameSpace    = 'root\CIMv2'
    Description  = 'Check for Operating System Windows 2019'
  }

$WMIFilter2016 = New-Object -TypeName wmifilter -ArgumentList 'Check for Operating System Windows 2016','Select * from Win32_OperatingSystem where (Version = "10.0.14393" and (ProductType="2" or ProductType = "3" ) )'
$WMIFilter2019 = New-Object -TypeName wmifilter -ArgumentList 'Check for Operating System Windows 2019','Select * from Win32_OperatingSystem where (Version = "10.0.17763" and (ProductType="2" or ProductType = "3" ) )'



  New-WMIFilter -Domain 'rabotest.com'    -WMIFilter $WmiFilter2019 -Verbose
  New-WMIFilter -Domain 'am.rabotest.com' -WMIFilter $WmiFilter2019 -Verbose
  New-WMIFilter -Domain 'ap.rabotest.com' -WMIFilter $WmiFilter2019 -Verbose
  New-WMIFilter -Domain 'eu.rabotest.com' -WMIFilter $WmiFilter2019 -Verbose
  New-WMIFilter -Domain 'oc.rabotest.com' -WMIFilter $WmiFilter2019 -Verbose

  Set-WMIFilter -Domain 'rabotest.com'    -WMIFilter $WmiFilter2016 -Verbose
  Set-WMIFilter -Domain 'am.rabotest.com' -WMIFilter $WmiFilter2016 -Verbose
  Set-WMIFilter -Domain 'ap.rabotest.com' -WMIFilter $WmiFilter2016 -Verbose
  Set-WMIFilter -Domain 'eu.rabotest.com' -WMIFilter $WmiFilter2016 -Verbose
  Set-WMIFilter -Domain 'oc.rabotest.com' -WMIFilter $WmiFilter2016 -Verbose

.Example
    $WMIFilters = @(
     $WMIFilter2016 = New-Object -TypeName wmifilter -ArgumentList  ('Hyper-V Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model = "Virtual Machine"', 
                        'Microsoft Hyper-V 2.0 AND 3.0'),
                    ('VMware Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "VMware%"', 
                        'VMware Fusion, WORkstation AND ESXi'),
                    ('Parallels Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "Parallels%"', 
                        'OSX Parallels Virtual Machine'),
                    ('VirtualBox Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "VirtualBox%"', 
                        'Oracle VirtualBox Virtual Machine'),
                    ('Xen Virtual Machines', 
                        'SELECT * FROM Win32_ComputerSystem WHERE Model LIKE "HVM dom%"', 
                        'Citrix Xen Server Virtual Machine'),
                    ('Virtual Machines',
                        'SELECT * FROM Win32_ComputerSystem WHERE (Model LIKE "Parallels%" OR Model LIKE "HVM dom% OR Model LIKE "VirtualBox%" OR Model LIKE "Parallels%" OR Model LIKE "VMware%" OR Model = "Virtual Machine")',
                        'Virtual Machine from Hyper-V, VMware, Xen, Parallels OR VirtualBox'),
                    ('Java is Installed', 
                        'SELECT * FROM win32_DirectORy WHERE (name="c:\\Program Files\\Java" OR name="c:\\Program Files (x86)\\Java")', 
                        'Oracle Java'),
                    ('Java JRE 7 is Installed', 
                        'SELECT * FROM win32_DirectORy WHERE (name="c:\\Program Files\\Java\\jre7" OR name="c:\\Program Files (x86)\\Java\\jre7")', 
                        'Oracle Java JRE 7'),
                    ('Java JRE 6 is Installed', 
                        'SELECT * FROM win32_DirectORy WHERE (name="c:\\Program Files\\Java\\jre6" OR name="c:\\Program Files (x86)\\Java\\jre6")', 
                        'Oracle Java JRE 6'),
                    ('Workstation 32-bit', 
                        'Select * from WIN32_OperatingSystem WHERE ProductType=1 Select * from Win32_Processor WHERE AddressWidth = "32"', 
                        ''),
                    ('Workstation 64-bit', 
                        'Select * from WIN32_OperatingSystem WHERE ProductType=1 Select * from Win32_Processor WHERE AddressWidth = "64"', 
                        ''),
                    ('Workstations', 
                        'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "1"', 
                        ''),
                    ('Domain Controllers', 
                        'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "2"', 
                        ''),
                    ('Servers', 
                        'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "3"', 
                        ''),
                    ('Windows XP', 
                        'SELECT * FROM Win32_OperatingSystem WHERE (Version LIKE "5.1%" OR Version LIKE "5.2%") AND ProductType = "1"', 
                        ''),
                    ('Windows Vista', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.0%" AND ProductType = "1"', 
                        ''),
                    ('Windows 7', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.1%" AND ProductType = "1"', 
                        ''),
                    ('Windows 8', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.2%" AND ProductType = "1"', 
                        ''),
                    ('Windows Server 2003', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "5.2%" AND ProductType = "3"', 
                        ''),
                    ('Windows Server 2008', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.0%" AND ProductType = "3"', 
                        ''),
                    ('Windows Server 2008 R2', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.1%" AND ProductType = "3"', 
                        ''),
                    ('Windows Server 2012', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.2%" AND ProductType = "3"', 
                        ''),
                    ('Windows Vista AND Windows Server 2008', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.0%" AND ProductType<>"2"', 
                        ''),
                    ('Windows Server 2003 AND Windows Server 2008', 
                        'SELECT * FROM Win32_OperatingSystem WHERE (Version LIKE "5.2%" OR Version LIKE "6.0%") AND ProductType="3"', 
                        ''),
                    ('Windows XP AND 2003', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "5.%" AND ProductType<>"2"', 
                        ''),
                    ('Windows 8 AND 2012', 
                        'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "6.2%" AND ProductType<>"2"', 
                        ''),
                    ('Internet Explorer 10', 
                        'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iExplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iExplore.exe") AND version LIKE "10.%"'),
                    ('Internet Explorer 9', 
                        'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iExplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iExplore.exe") AND version LIKE "9.%"'),
                    ('Internet Explorer 8', 
                        'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iExplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iExplore.exe") AND version LIKE "8.%"'),
                    ('Internet Explorer 7', 
                        'SELECT * FROM CIM_Datafile WHERE (Name="c:\\Program Files (x86)\\Internet Explorer\\iExplore.exe" OR Name="c:\\Program Files\\Internet Explorer\\iExplore.exe") AND version LIKE "7.%"')
                )


#>

# SIG # Begin signature block
# MIINCgYJKoZIhvcNAQcCoIIM+zCCDPcCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUsQat7tEbWVZiNq6q8ZCJ2+jm
# ojWgggp2MIIFEjCCA/qgAwIBAgITVwAD8K8q0U/LIB3mcAABAAPwrzANBgkqhkiG
# 9w0BAQsFADBGMR8wHQYDVQQKExZSYWJvYmFuayBJbnRlcm5hdGlvbmFsMSMwIQYD
# VQQDExpSSSBJbnRyYW5ldCBJc3N1aW5nIENBMiAwMTAeFw0xOTA2MjAwOTQ4MzFa
# Fw0yMTA2MTkwOTQ4MzFaMIGTMQswCQYDVQQGEwJOTDEQMA4GA1UECBMHVXRyZWNo
# dDEQMA4GA1UEBxMHVXRyZWNodDERMA8GA1UEChMIUmFib2JhbmsxLTArBgNVBAsT
# JENPTyBJbmZyYXN0cnVjdHVyZSBCV0EgQ29yZSBJZGVudGl0eTEeMBwGA1UEAxMV
# WmFudGVuIHZhbiwgQkFNIChCZW4pMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEA2nJ8XYcvaO9jrJcuLx4vVSS+X79F0ay3YUHGuZf7OhbEotLbyc6d/xfL
# bch0qLAwojGwNwMp0eb4hxLFtB2oaVg+GdE3rE+4zy8IDeGIHajOn3GNkyEj2obg
# VSBJv8aU55Xjizj+ww2NfWN8Hclp9eouzJSsYufdK6+k7vo/OCLveYSLMN6aSsO7
# ThEhaUNmM5GpRRAqtPLYP63OXkGUgRBcoUemnlM2H5qyZyJsyFakTRUTBzXNjWhh
# YckivsU9DT0kmr/JTvM94s8zsXJPLnfy52L+v5f2p5vBII6xDvT73cR/N1hO3L0F
# l5+rWgfF1wmoITfMD3a23YL//6HclQIDAQABo4IBqTCCAaUwHQYDVR0OBBYEFAPG
# 2skcWj0ilaYlGoyLM4kbeGhkMB8GA1UdIwQYMBaAFOdamPMB8kMaIylmJwHFujf/
# 2UX/MFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9wa2kyLnJhYm9uZXQuY29tL0NS
# TC9SSSUyMEludHJhbmV0JTIwSXNzdWluZyUyMENBMiUyMDAxLmNybDCBjQYIKwYB
# BQUHAQEEgYAwfjBRBggrBgEFBQcwAoZFaHR0cDovL3BraTIucmFib25ldC5jb20v
# QUlBL1JJJTIwSW50cmFuZXQlMjBJc3N1aW5nJTIwQ0EyJTIwMDEoMSkuY3J0MCkG
# CCsGAQUFBzABhh1odHRwOi8vb2NzcDIucmFib25ldC5jb20vb2NzcDAOBgNVHQ8B
# Af8EBAMCB4AwPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGCNxUIhqmZGIT16xqG+ZUj
# sctWhMXNCn+Ep9wGhrPsaAIBZAIBAzATBgNVHSUEDDAKBggrBgEFBQcDAzAbBgkr
# BgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4IBAQCugm6X
# 6mggbO+dBEsnZiWmzHe+3O6xD6kvsxeCxY8OJRIzcrcQHpCTTZtAE/lQ5Ba0o+tt
# 9tvAMiSaPNpFq+4L72b3ZcP+yxaQbcRwdNqxdGEYmwy4yzprUVjx4oVD+YXDB7Dx
# kE2MnxmNCe7ojrZoD4zCby0MnwtRXbtEzv6iG7ZB1DSdsc9OkJbZh5cniBJ7PLSN
# G6BrelRZv0OeUgvehmW/hpMVha84OBhR/crN51Bg9cXF6rQEFn/rDzR398H45Fp3
# vdaw7l6DrcCJWssZ6FMT9b6vVb/Wt3Hm0bKB4IKc08/I5AfddCm5WKbmSJOOJnUo
# RqCNJtlLyskvshsOMIIFXDCCA0SgAwIBAgITGgAAAAUjgNUwgCMNxgAAAAAABTAN
# BgkqhkiG9w0BAQsFADBBMR8wHQYDVQQKExZSYWJvYmFuayBJbnRlcm5hdGlvbmFs
# MR4wHAYDVQQDExVSSSBDb3Jwb3JhdGUgUm9vdCBDQTIwHhcNMTcwMzAyMDg1NDM0
# WhcNMjIwMzAyMDkwNDM0WjBGMR8wHQYDVQQKExZSYWJvYmFuayBJbnRlcm5hdGlv
# bmFsMSMwIQYDVQQDExpSSSBJbnRyYW5ldCBJc3N1aW5nIENBMiAwMTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBALT5b5/XXyXFSFM1JXxzMaBW4gGFkLyx
# y55RCXVUu00LrhfUcxk3p4fNYsNlYzm9swkbp2HThgFFp5RaB2UsI2VyeqQDlXpf
# w3Sqco1191ijnk7+J1UqWCoKdVzOymaaUIPLCWLdXzymqsubPB0HdyI1Zjsn9Tjl
# YV4wEX160fHZK8BCkTLXAG9ugDtc8ol01mPsQzxE0p+p90EsT6bFIKBOKgHgEzua
# AQU8X1kVzfRg1Lr3Gb79mnX+yltgz5Yh9bAfJEMWnP0kdJcx4IBPYdnNmvkP1pan
# 42dzsO+R6C0kIbh9moZ7Ae4MvLpEBuMwDiHHANjQBH32LdXm5XqK0n0CAwEAAaOC
# AUYwggFCMBAGCSsGAQQBgjcVAQQDAgEBMCMGCSsGAQQBgjcVAgQWBBQiNPkmKQcc
# Hr3YQYj7NP2IwJDzxDAdBgNVHQ4EFgQU51qY8wHyQxojKWYnAcW6N//ZRf8wGQYJ
# KwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHwYDVR0jBBgwFoAUmP9e7gl3oEI+6PNNJ/7f7UdGTvIwPgYDVR0f
# BDcwNTAzoDGgL4YtaHR0cDovL3BraTIucmFib25ldC5jb20vY3JsL1JJQ29ycFJv
# b3RDQTIuY3JsME0GCCsGAQUFBwEBBEEwPzA9BggrBgEFBQcwAoYxaHR0cDovL3Br
# aTIucmFib25ldC5jb20vQUlBL1JJQ29ycFJvb3RDQTJDZXJ0LmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAhUymSSqxDQknB3A0uutzonpL0GYzz6/ncIdZboFfZ0lk73bj
# yMdPeKOHUevjhkMVMnWkUHGREcNJGPRrop9LTijl4kExNHdPl2iaBx0ELIzfYCHd
# SuHXv4GiaCBrvAoefzYNfdsbK8bVkak/BtVorFyqYg4zhRf5e1D07bxsbpwF9/kD
# ZnPuqKxxgsEteLAyCYKd5kK4zU1sldJ/ff37uVyUlF6RzHGeS9tpDDp/oS/wYxvD
# 3uI8t0/FgaldgTNqLBYtrPVG/ZxbCn7GzcTCBxc4pedqwklwulStBc8QcA47qe8S
# uR8s+z0jS0whVo8AUB203jqhdDdACZWzh6oYF6pJAnSXv7A5S9CzycbOsC5Qoglh
# X/0G58igT4axQNder4Qb6u1zDlfz7QqwgYpkiMiQ4gzWIqntLtRkFIJJlfxmPT6B
# cncLVWUfL4SCR9abR2aSgDAKEIpChkxFvJ6su6WhodTXEo+3utcn38zb2JOXUYaA
# nGkDKWOSPO38f3tlY95fI//zhF5sWTvFSJv+EWM8AtAbRAGn1tM+3rMlcXWBUS2l
# djD7+L8oyQGeImIdMbYrpAvF713rzYa9lKGx+9ElzK6VhRIZ+78iL+E9Ef/+RU5q
# 5dUhx6v6+/FvGG7dXcTcl+4s8u4Tqffc0QlJ0PwzDTHt1YTMk8rLZvPnwdsxggH+
# MIIB+gIBATBdMEYxHzAdBgNVBAoTFlJhYm9iYW5rIEludGVybmF0aW9uYWwxIzAh
# BgNVBAMTGlJJIEludHJhbmV0IElzc3VpbmcgQ0EyIDAxAhNXAAPwryrRT8sgHeZw
# AAEAA/CvMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTjgYMAK3/coKbKBSM2U8nRT2J8BTANBgkq
# hkiG9w0BAQEFAASCAQDXa3Iywd+mEpxlILpR1KFcFfcDzkrzAZVrjmmVSmBIuk3f
# 6dgOsTUEMLKlEjLO3KRUp7VuX7GK/KcgbTu0V2cl9WRHFVVZuNf7MzsBSIkAZ8BY
# c5tP/lEBqENwjmhj6AgxL43KKLFpY0yJEOnGmRNHYbIfwPkccOWyqio6OL2NnWYw
# CX+5Pu8sYfQij8m+MFAx09nqkSXgjiVhjgbn2acI25yvsLlZ5E1bbFt37JWnkQLv
# qMXwwvkZcT2+XZq5TivHATr9So+jdTJhPlbirN4Ff0rbzVx+7jKV1p8hg96+/c+t
# GwPiRt/x9ndS7QiH5EQtwKneleTBHczbPMQojR38
# SIG # End signature block
