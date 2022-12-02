#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Post-install script for Windows 11
.DESCRIPTION
    Post-install script for Windows 11 to install applications and configure settings
.NOTES
  Win11PostInstall.ps1
  Marco Janse
  v0.1
  2022-11-30

  Version History:

  0.1 - Initial draft
.LINK
    https://github.com/MarcoJanse/ProfilesAndSettings/WindowsDeployment/Win11Postinstall.ps1
.EXAMPLE
    Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
#>

## Check if OS is Windows 11 

if  ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName -notmatch 'Windows 11') {
    Write-Output "This Windows version is not Windows 11, and therefore will not proceed"
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
    @{name = "7zip.7zip"},
    @{name = "dropbox.dropbox"},
    @{name = "Foxit.FoxitReader"},
    @{name = "git.git"},
    @{name = "KeePassXCTeam.KeePassXC"},
    @{name = "Microsoft.AzureCLI"},
    @{name = "Microsoft.GitCredentialManagerCore"},
    @{name = "Microsoft.VisualStudioCode"},
    @{name = "Rizonesoft.Notepad3"}
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
