<#
.Synopsis
   Class definition to script Windows Advanced Firewall rules, and load/save them in a GPO
.DESCRIPTION
   Class definition to script Windows Advanced Firewall rules, and load/save them in a GPO
.EXAMPLE

    # Write all FirewallRules of a GPO to XML :
    $Domain = 'rabotest.com'
    $GpoName = 'ri.fcp.Tier0Servers'

    $GpoSession = Open-NetGPO -PolicyStore "$Domain\$GpoName"

    Import-Module NetSecurity -Verbose:$False
    . .\Read-Firewall.ps1
    Get-NetFirewallRule -GPOSession $GpoSession | ForEach-Object {
        $MyFWRule = (New-Object -TypeName FWRule -ArgumentList $_,$GpoSession )
        $MyFwRule.ToXMLString()
    }

    Save-NetGPO -GPOSession $GpoSession

.EXAMPLE
      # Read all FirewallRules from XML and write to a GPO :
    $Domain = 'rabotest.com'
    $GpoName = 'ri.fcp.Tier0ServersTESTGPO'
    
    New-Gpo -Name $GpoName -Domain $Domain
    Import-Module .\DeployAdLib.psd1
    
    [xml]$FwRules = Get-Content .\NewRules.xml
    
    $GpoSession = Open-NetGPO -PolicyStore "$Domain\$GpoName"
    
    ForEach( $FWRule in $FwRules.FirewallRules.FWRule ) {
        $FWHT = Convert-XmlToHT -XmlObject $FWRule
        $FWHT.Enabled       = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]$FWHT.Enabled.ToString()
        $FWHT.LocalPort     = $FWHT.LocalPort     -split ' ' -split '-'
        $FWHT.RemotePort    = $FWHT.RemotePort    -split ' ' -split '-'
        $FWHT.LocalAddress  = $FWHT.LocalAddress  -split ' ' 
        $FWHT.RemoteAddress = $FWHT.RemoteAddress -split ' ' 
    
        if ([string]::IsNullOrEmpty($FWHT.Platform)) { $FWHT.Remove('Platform') }
        $FWHT.Add('GPOSession',$GpoSession)

        New-NetFirewallRule @FWHT
    }
    
    Save-NetGPO -GPOSession $GpoSession


.EXAMPLE
    Import-Module NetSecurity -Verbose:$False
    . .\Read-Firewall.ps1
    $MyFWRule = (New-Object -TypeName FWRule -ArgumentList "{755998e7-8d36-4a6e-9f06-5f6c8f720d34}" )
    $MyFWRule
    $MyFWRule = (New-Object -TypeName FWRule -ArgumentList "CoreNet-Teredo-In" )
     (New-Object -TypeName FWRule -ArgumentList "CoreNet-Teredo-In" )
     (New-Object -TypeName FWRule -ArgumentList "CoreNet-Teredo-In",$GpoSession )
.EXAMPLE
    Import-Module NetSecurity -Verbose:$False
    . .\Read-Firewall.ps1
    $MyFWRule = (New-Object -TypeName FWRule -ArgumentList "{755998e7-8d36-4a6e-9f06-5f6c8f720d34}" )
    $MyFWRule
.EXAMPLE
    [enum]::GetNames("Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile")
    [enum]::GetName("Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile",0)
    [enum]::GetName("Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile",1)
    [enum]::GetName("Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile",2)
    [enum]::GetName("Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile",4)
    [enum]::GetName("Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile",65535)

    [enum]::GetNames("Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled")
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   Author : Zanten van, BAM (Ben)


#>

Import-Module NetSecurity -Verbose:$False

class FWRule {

    [string]$DisplayName
#   [string]$PolicyStore 
#   [string]$GPOSession 
    [string]$Name 
    [string]$Description 
    [string]$Group 

    [ValidateSet("True", "False")]
    [string]$Enabled

#   hidden [uint16]$profiles
#   get=[Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]($this.PSBase.CimInstanceProperties['Profiles'].Value + 0)

#   [ValidateSet("Any", "Domain", "Private", "Public", "NotApplicable")]
#   [string]$Profile

    # PS D:\Scripts\InstallDC> $MyGPOAdminRule | gm profile| Select-Object -ExpandProperty Definition
    # System.Object Profile {get=[Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]($this.PSBase.CimInstanceProperties['Profiles'].Value + 0);
    #                        set=param($x); $this.PSBase.CimInstanceProperties['Profiles'].Value = [System.Uint16][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]$x;}

    # $this.PSBase.CimInstanceProperties['Profiles'].Value
    hidden [System.Uint16]$_Profile = $($this | Add-Member ScriptProperty 'Profile' {
            # get
            # Write-verbose "Getting data, just a moment: $($this._Profile)"
           [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]($this._Profile)
        }  {
            # set
            param ( $arg )
            # Write-Verbose $arg.gettype()
            $this._Profile = [System.Uint16][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Profile]$arg;
        }
    )


    [string[]]$Platform 

    [ValidateSet("Inbound", "Outbound")]
    [string]$Direction

    [ValidateSet("NotConfigured", "Allow", "Block")]
    [string]$Action

    [ValidateSet("Block", "Allow", "DeferToUser", "DeferToApp")]
    [string]$EdgeTraversalPolicy

    [bool]$LooseSourceMapping 
    [bool]$LocalOnlyMapping 
    [string]$Owner 
    [string[]]$LocalAddress
    [string[]]$RemoteAddress 
    [string]$Protocol 
    [string[]]$LocalPort 
    [string[]]$RemotePort 
    [string[]]$IcmpType

    [ValidateSet("Any", "ProximityApps", "ProximitySharing", "WifiDirectPrinting", "WifiDirectDisplay", "WifiDirectDevices")]
    [string]$DynamicTarget

    [string]$Program 
    [string]$Package 
    [string]$Service 
    [string[]]$InterfaceAlias

    [ValidateSet("Any", "Wired", "Wireless", "RemoteAccess")]
    [string]$InterfaceType

    [string]$LocalUser 
    [string]$RemoteUser 
    [string]$RemoteMachine 

    [ValidateSet("NotRequired", "Required", "NoEncap")]
    [string]$Authentication

    [ValidateSet("NotRequired", "Required", "Dynamic")]
    [string]$Encryption

    [bool]$OverrideBlockRules 

    hidden [string]$GPOSession=$Null
    hidden [hashtable]$htGPOSession=@{}

    #
    # hidden init constructors to compensate for the lack of constructor chaining.
    #

    hidden init ([string]$Name )  {
#       Write-Verbose "Init 1: $name - $($Name.GetType())"
        $ExistingFWRule = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue

        if ($ExistingFWRule) {
            $this.init($ExistingFWRule)
        }
    }

    hidden init ([string]$Name, [string]$GPOSession )  {
#       Write-Verbose "Init 2"
        $this.htGPOSession.Add("GPOSession", $GPOSession)
        $tmphtGPOSession = $this.htGPOSession

        $ExistingFWRule = Get-NetFirewallRule -Name $Name @tmphtGPOSession -ErrorAction SilentlyContinue

        if ($ExistingFWRule) {
            $this.init($ExistingFWRule)
       }
    }

    hidden init ([Microsoft.Management.Infrastructure.CimInstance] $ExistingFWRule, [string]$GPOSession )  {
#       Write-Verbose "Init3"
        $this.htGPOSession.Add("GPOSession", $GPOSession)

        $this.init($ExistingFWRule)
    }

    hidden init ([Microsoft.Management.Infrastructure.CimInstance] $ExistingFWRule )  {
#       Write-Verbose "Init4"
        $tmphtGPOSession = $this.htGPOSession
        $this.Name               = $ExistingFWRule.Name
        $this.DisplayName        = $ExistingFWRule.DisplayName
        $this.Description        = $ExistingFWRule.Description
        $this.Group              = $ExistingFWRule.Group
        $this.Enabled            = $ExistingFWRule.Enabled
        $this.Profile            = $ExistingFWRule.Profile
        $this.Platform           = $ExistingFWRule.Platform
        $this.Direction          = $ExistingFWRule.Direction
        $this.Action             = $ExistingFWRule.Action
        $this.EdgeTraversalPolicy= $ExistingFWRule.EdgeTraversalPolicy
        $this.LooseSourceMapping = $ExistingFWRule.LooseSourceMapping
        $this.LocalOnlyMapping   = $ExistingFWRule.LocalOnlyMapping
        $this.Owner              = $ExistingFWRule.Owner
        $this.LocalAddress       = (Get-NetFirewallAddressFilter       -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).LocalAddress
        $this.RemoteAddress      = (Get-NetFirewallAddressFilter       -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).RemoteAddress
        $this.Protocol           = (Get-NetFirewallPortFilter          -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).Protocol
        $this.LocalPort          = (Get-NetFirewallPortFilter          -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).LocalPort
        $this.RemotePort         = (Get-NetFirewallPortFilter          -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).RemotePort
        $this.IcmpType           = (Get-NetFirewallPortFilter          -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).IcmpType
        $this.DynamicTarget      = (Get-NetFirewallPortFilter          -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).DynamicTarget
        $this.Program            = (Get-NetFirewallApplicationFilter   -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).Program
        $this.Package            = (Get-NetFirewallApplicationFilter   -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).Package
        $this.Service            = (Get-NetFirewallServiceFilter       -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).Service
        $this.InterfaceAlias     = (Get-NetFirewallInterfaceFilter     -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).InterfaceAlias
        $this.InterfaceType      = (Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).InterfaceType
        $this.LocalUser          = (Get-NetFirewallSecurityFilter      -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).LocalUser
        $this.RemoteUser         = (Get-NetFirewallSecurityFilter      -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).RemoteUser
        $this.RemoteMachine      = (Get-NetFirewallSecurityFilter      -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).RemoteMachine
        $this.Authentication     = (Get-NetFirewallSecurityFilter      -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).Authentication
        $this.Encryption         = (Get-NetFirewallSecurityFilter      -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).Encryption
        $this.OverrideBlockRules = (Get-NetFirewallSecurityFilter      -AssociatedNetFirewallRule $ExistingFWRule @tmphtGPOSession ).OverrideBlockRules
#       Write-Verbose "End Init4"
    }


    # Constructor Name
    FWRule ([string]$Name) {
#       Write-Verbose "$name - $($Name.GetType())"
        $this.init($Name)
    }

    # Constructor Name, GPOSession
    FWRule ([string]$Name, [string]$GPOSession) {
        $this.init($Name, $GPOSession)
    }

    # Constructor CimInstance
    FWRule ([Microsoft.Management.Infrastructure.CimInstance]$ExistingFWRule) {
        $this.init($ExistingFWRule)
    }
    # Constructor CimInstance, GPOSession
    FWRule ([Microsoft.Management.Infrastructure.CimInstance]$ExistingFWRule, [string]$GPOSession) {
        $this.init($ExistingFWRule, $GPOSession)
    }


   # Instance method ToXML
   [System.XML.XMLElement] ToXml() {

        [System.XML.XMLDocument]$Output=New-Object System.XML.XMLDocument
        $FWRule = $Output.CreateElement('FWRule')
        $FWRule.SetAttribute('name',$this.name)
        $this | Get-Member -MemberType *Property | ForEach-Object { 
            if ($_.name -ne 'name') {
                $Element = $Output.CreateElement($_.name)
                $Element.InnerText = $($this.($_.name))
                $FWRule.AppendChild($Element)
            }
        }
        return $FWRule
    }

    [string]ToXMLString() {
        [int]$Indent=2
        $output="<FWRule name=""$($this.name)"">`r`n"
        $this | Get-Member -MemberType *Property | ForEach-Object { 
            if ($_.name -ne 'name') {
                $output += (" " * $Indent) + "<$($_.name)>$($this.($_.name))</$($_.name)>`r`n"
            }         }
        $output+="</FWRule>"
        return $output
    }

    [string]ToXMLString2() {
        $Indent=2
        $StringWriter = New-Object System.IO.StringWriter
        $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
        $xmlWriter.Formatting = “indented”
        $xmlWriter.Indentation = $Indent
        $this.ToXml().WriteContentTo($XmlWriter)
        $XmlWriter.Flush()
        $StringWriter.Flush()
        return $StringWriter.ToString()
    }

   # Instance method ToHashTable
   [hashtable] ToHashTable() {

        $output = @{}; 
        $this | Get-Member -MemberType *Property | ForEach-Object { 
            $output[$_.name] = $this.($_.name); 
        } 
        return $output; 
    }

}
