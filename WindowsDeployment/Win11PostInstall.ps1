#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Post-install script for Windows 11
.DESCRIPTION
    Post-install script for Windows 11 to install applications and configure settings
.NOTES
  Win11PostInstall.ps1
  Marco Janse
  v2.0
  2024-08-19

  Version History:

  2.0 - Updated to Windows 11 23H2 and updated apps
  1.1 - Added apps
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

## Check if OS is 23H2 build

if  ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion -ne '23H2') {
    Write-Output "This Windows version build is not 22H2, and therefore will not proceed"
    exit
 }

## Install WSL

Write-Output "Installing WSL, this might take a while..."
wsl --install

## WinGet

### Hashtable with apps

$apps = @(
    # .NET SDK
    @{ name = "Microsoft.DotNet.SDK.8" },
    # 7Zip
    @{ name = "7zip.7zip" },
    # Docker Desktop
    @{ name = "Docker.DockerDesktop" },
    # paint.net
    @{ name = "dotPDN.PaintDotNet" },
    # Dropbox
    @{ name = "dropbox.dropbox" },
    # Foxit PDF Reader
    @{ name = "Foxit.FoxitReader" },
    # Total Commander
    @{ name = "Ghisler.TotalCommander" },
    # GIMP
    @{ name = "GIMP.GIMP" },
    # Git
    @{ name = "git.git" },
    # GNU Privacy Guard
    @{ name = "GnuPG.GnuPG" },
    # Gpg4win
    @{ name = "GnuPG.Gpg4win" },
    # Google Chrome
    @{ name = "Google.Chrome" },
    # TreeSize Free
    @{ name = "JAMSoftware.TreeSize.Free" },
    # Draw.io
    @{ name = "JGraph.Draw"},
    # Oh My Posh
    @{ name = "JanDeDobbeleer.OhMyPosh" },
    # KeePassXC
    @{ name = "KeePassXCTeam.KeePassXC" },
    # Azure Functions Core Tools
    @{ name = "Microsoft.Azure.FunctionsCoreTools" },
    # Microsoft Azure Storage Explorer
    @{ name = "Microsoft.Azure.StorageExplorer" },
    # Microsoft Azure CLI
    @{ name = "Microsoft.AzureCLI" },
    # Bicep CLI
    @{ name = "Microsoft.Bicep" },
    # Microsoft Dev Home
    @{ name = "Microsoft.DevHome" },
    # PowerToys
    @{ name = "Microsoft.PowerToys" },
    # Sqlcmd Tools
    @{ name = "Microsoft.SqlCmd" },
    # SQL Server Management Studio
    @{ name = "Microsoft.SQLServerManagementStudio" },
    # Visual Studio Code
    @{ name = "Microsoft.VisualStudioCode" },
    # Windows Terminal
    @{ name = "Microsoft.WindowsTerminal" },
    # Winget Create
    @{ name = "Microsoft.WingetCreate" },
    # FlashFXP
    @{ name = "OpenSight.FlashFXP" },
    # Postman
    @{ name = "Postman.Postman"},
    # Notepad3
    @{ name = "Rizonesoft.Notepad3" },
    # Sonos S2 Controller
    @{ name = "Sonos.Controller" },
    # WinSCP
    @{ name = "WinSCP.WinSCP" },
    # Yubico Authenticator
    @{ name = "Yubico.Authenticator" },
    # YubiKey Manager
    @{ name = "Yubico.YubikeyManager" },
    # YubiKey Smart Card Minidriver
    @{ name = "Yubico.YubiKeySmartCardMinidriver" }
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
