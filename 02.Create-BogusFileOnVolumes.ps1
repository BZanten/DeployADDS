<#
.Synopsis
   Places a (number of) bogus file(s) on the root of each local volume.
.DESCRIPTION
   In theory a runaway process may have its log fill out a Disk volume.
   If that happens on the Windows Drive, windows may freeze. If that happens on an application drive, the application may freeze.
   The application or process may need to be fixed, but in order to quickly free some extra diskspace, a 2GB bogus file is created on each local volume.
.EXAMPLE
   .\Create-BogusFileOnVolumes.ps1
.EXAMPLE
   .\Create-BogusFileOnVolumes.ps1 -Size 500MB
   Overrides the default 2GB filesize. Uses specified size.
.EXAMPLE
   .\Create-BogusFileOnVolumes.ps1 -Size 500MB -NumberOfFiles 4
   Overrides the default 2GB filesize. Creates 4 files of 500MB
.NOTES
   Author : Ben van Zanten
   Company: Valid
   Date   : Dec 2015
   Version: 1.1

   History:  1.0  Initial version
             1.1  Allows to create multiple files instead of one
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
        [int64]$Size=500MB,

        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   ValueFromPipelineByPropertyName=$false, 
                   ValueFromRemainingArguments=$false, 
                   Position=0)]
        [int]$NumberOfFiles=4

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
                for ($i=1;$i -le $NumberOfFiles; $i++) {
                    $i
                    if (!(Test-Path "$($Drive.DriveLetter)\PlaceholderFile_$i.bogus")) {
                        if ($pscmdlet.ShouldProcess($Drive.DriveLetter, "Create $($Size/1MB) MB file"))
                        {
                            FSUTIL FILE CREATENEW "$($Drive.DriveLetter)\PlaceholderFile_$i.bogus" $Size
                            if (!(Test-Path "$($Drive.DriveLetter)\PlaceholderFile_$i.bogus")) {
                                Write-Error "File $($Drive.DriveLetter)\PlaceholderFile_$i.bogus is not present, command failed !"
                            } else {
                            }
                        }
                    } else {
                        "Bogus file: $($Drive.DriveLetter)\PlaceholderFile_$i.bogus already exists."
                    }
                }
            }
        }
    }
