#Requires -version 7

<#
.SYNOPSIS
    PowerShell script for PowerShell 7 to install modules under the current user
.DESCRIPTION
    This script uses PowerShell 7 to install PS modules from the PSGallery under the current user scope
.NOTES
  PowerShell7Modules.ps1
  Marco Janse
  v0.1
  2022-12-04

  Version History:

  1.0 - Initial tested version
.LINK
    https://github.com/MarcoJanse/ProfilesAndSettings/WindowsDeployment/PowerShell7Modules.ps1
.EXAMPLE
    ./PowerShell7Modules.ps1
    
    Runs the script witoout any parameters
#>

### Hashtable with modules

$Modules = @(
    @{ name = "Az" },
    @{ name = "Microsoft.Graph.Authentication" },
    @{ name = "MicrosoftTeams" },
    @{ name = "Microsoft.PowerShell.SecretManagement" },
    @{ name = "Microsoft.PowerShell.SecretStore" },
    @{ name = "Pester" },
    @{ name = "platyPS" },
    @{ name = "posh-git" },
    @{ name = "PSFolderSize" },
    @{ name = "PSFramework" },
    @{ name = "PSFunctionTools" },
    @{ name = "PSKoans" },
    @{ name = "PSScriptTools" },
    @{ name = "PSReleaseTools" },
    @{ name = "PSScriptTools" },
    @{ name = "SecretManagement.KeePass" },
    @{ name = "Terminal-Icons" }
)

Write-Output "Starting installation of PowerShell 7 modules from the PSGallery..."
Write-Output "Setting the PSGallery repository as trusted if not already so"

if ((Get-PSRepository -Name PSGallery).installationpolicy -ne 'trusted') {
    Set-pSRepository -Name PSGallery -InstallationPolicy Trusted
}

foreach ($Module in $Modules) {
    Write-Host -ForegroundColor Yellow "installing $($Module.Name)..."
    Install-Module -Name $Module.name -Repository PSGallery -Scope CurrentUser -Verbose
}