<#
.Synopsis
   Creates SMB file shares to act as Domain based DFS roots.
.DESCRIPTION
   Creates SMB file shares to act as Domain based DFS roots.

    Todo

This script should be made generic...
like take the configuration info from xml

.EXAMPLE
   04.Configure-DFS.ps1
#>


if (!(Test-Path C:\DFSRoots\Public)) { New-Item -Path C:\DFSRoots\Public -ItemType Directory }

New-SmbShare -Name Public -Path C:\DFSRoots\Public -ReadAccess "Everyone" -FullAccess "Administrators"

