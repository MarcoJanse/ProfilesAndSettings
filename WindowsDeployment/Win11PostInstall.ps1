#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Post-install script for Windows 11
.DESCRIPTION
    Post-install script for Windows 11 to install applications and configure settings
.NOTES
  Win11PostInstall.ps1
  Marco Janse
  v1.0
  2022-12-04

  Version History:

  1.0 - Tested version on my work laptop
  0.1 - Initial draft
.LINK
    https://github.com/MarcoJanse/ProfilesAndSettings/WindowsDeployment/Win11Postinstall.ps1
.EXAMPLE
    .\Win11PostInstall.ps1

    Runs the script without any parameters
#>

## Check if OS is Windows 10 or 11
### Windows 11 currently still shows Windows 10 as ProductName in the registry for compatibility issues.

if  ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName -notmatch 'Windows 10' -or 
    (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName -notmatch 'Windows 11') {
    Write-Output "This Windows version is not Windows 10 or 11, and therefore will not proceed"
    exit
 }

## Check if OS is 22H2 build

if  ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion -ne '22H2') {
    Write-Output "This Windows version build is not 22H2, and therefore will not proceed"
    exit
 }

## Install WSL

Write-Output "Installing WSL, this might take a while..."
wsl --install

## WinGet

### Hashtable with apps

$apps = @(
    @{ name = "7zip.7zip" },
    @{ name = "Apple.iTunes" },
    @{ name = "Docker.DockerDesktop" },
    @{ name = "dropbox.dropbox" },
    @{ name = "flux.flux" },
    @{ name = "Foxit.FoxitReader" },
    @{ name = "git.git" },
    @{ name = "GnuPG.Gpg4win" },
    @{ name = "Google.Chrome" },
    @{ name = "JAMSoftware.TreeSize.Free" },
    @{ name = "JanDeDobbeleer.OhMyPosh" },
    @{ name = "KeePassXCTeam.KeePassXC" },
    @{ name = "Microsoft.AzureCLI" },
    @{ name = "Microsoft.AzureStorageExplorer" },
    @{ name = "Microsoft.Bicep" },
    @{ name = "Microsoft.GitCredentialManagerCore" },
    @{ name = "Microsoft.PowerToys" },
    @{ name = "Microsoft.SQLServerManagementStudio" },
    @{ name = "Microsoft.VisualStudioCode" },
    @{ name = "OpenSight.FlashFXP" },
    @{ name = "Rizonesoft.Notepad3" },
    @{ name = "Sonos.Controller" },
    @{ name = "WinSCP.WinSCP" },
    @{ name = "Yubico.Authenticator" },
    @{ name = "Yubico.YubikeyManager" }
)

Write-Output "Installing application using WinGet"

Foreach ($app in $apps) {
    #check if the app is already installed
    $listApp = winget list --exact -q $app.name
    if (![String]::Join("", $listApp).Contains($app.name)) {
        Write-host "Installing:" $app.name
        if ($null -ne $app.source) {
            winget install --exact --silent $app.name --source $app.source
         }
        else {
            winget install --exact --silent $app.name 
         }
     }
    else {
        Write-host "Skipping Install of " $app.name
     }
 }
