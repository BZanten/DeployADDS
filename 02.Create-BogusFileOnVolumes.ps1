<#
.Synopsis
   Places a bogus 2 GB file on the root of each local volume.
.DESCRIPTION
   In theory a runaway process may have its log fill out a Disk volume.
   If that happens on the Windows Drive, windows may freeze. If that happens on an application drive, the application may freeze.
   The application or process may need to be fixed, but in order to quickly free some extra diskspace, a 2GB bogus file is created on each local volume.
.EXAMPLE
   .\Create-BogusFileOnVolumes.ps1
.EXAMPLE
   .\Create-BogusFileOnVolumes.ps1 -Size 500MB
   Overrides the default 2GB filesize. User PowerShell built-in sizes.
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
        # Size of the bogus files, default 2G
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false, 
                   ValueFromRemainingArguments=$false, 
                   Position=0)]
        [int64]$Size=2GB
    )

    Begin {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal $identity
        if (-not($principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) {
            Write-Error "Run this script elevated! This script requires administrative permissions."
            break
        }
    }
    Process
    {
        ForEach ($Drive in (Get-WmiObject -Class Win32_Volume -Filter "DriveType=3"))
        {
            if (-not([string]::IsNullOrEmpty($Drive.DriveLetter))) 
            {
                if (!(Test-Path "$($Drive.DriveLetter)\PlaceholderFile.bogus")) {
                    if ($pscmdlet.ShouldProcess($Drive.DriveLetter, "Create $($Size/1MB) MB file"))
                    {
                        FSUTIL FILE CREATENEW "$($Drive.DriveLetter)\PlaceholderFile.bogus" $Size
                        if (!(Test-Path "$($Drive.DriveLetter)\PlaceholderFile.bogus")) {
                            Write-Error "File $($Drive.DriveLetter)\PlaceholderFile.bogus is not present, command failed !"
                        } else {
                        }
                    }
                } else {
                    "Bogus file: $($Drive.DriveLetter)\PlaceholderFile.bogus already exists."
                }
            }
        }
    }
