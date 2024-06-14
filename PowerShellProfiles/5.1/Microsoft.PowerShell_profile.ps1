<#
  Windows PowerShell Profile
  Marco Janse
  v2.0
  2024-06-14

  Version History:

  2.0 - Optimized and stripped version for Windows PowerShell
  1.0 - Initial profile based on PS7 profile

#>
 
 ### Aliases ###

# Custom Variables #

$Git = 'X:\Git\'
$GitHub = 'X:\Git\GitHub\MarcoJanse\'
$AzDevOps = 'X:\Git\AzDevOps'

 
# Modules #
 
# Functions #

## PowerShell Core

## Get dynamic parameters
function Get-DynamicParameters {
  param ($Cmdlet, $PSDrive)
     (Get-Command -Name $Cmdlet -ArgumentList $PSDrive).ParameterSets |
      ForEach-Object { $_.Parameters } |
        Where-Object { $_.IsDynamic } |
          Select-Object -Property Name -Unique
}


## Remove old modules
function Remove-OldModules {
  <#
    Author: Luke Murray (Luke.Geek.NZ)
    Version: 0.1
    Purpose: Basic function to remove old PowerShell modules which are installed
  #>
  
    $Latest = Get-InstalledModule 
    foreach ($module in $Latest) { 
      
      Write-Verbose -Message "Uninstalling old versions of $($module.Name) [latest is $( $module.Version)]" -Verbose
      Get-InstalledModule -Name $module.Name -AllVersions | Where-Object { $_.Version -ne $module.Version } | Uninstall-Module -Verbose 
    }
  }


## Find Module Updates
<#
  Author: Harm Veenstra
  Version: 2023-09-25
  Source: https://github.com/HarmVeenstra/Powershellisfun/blob/main/Check%20for%20PowerShell%20modules%20updates/Find-ModuleUpdates.ps1
#>

function Find-ModuleUpdates {
  [CmdletBinding()]

  # Parameter for filtering modules for specific pattern, e.g. *Graph*
  param (
    [Parameter(Mandatory = $false)][string]$NameFilter = '*'
  )

  #Retrieve all installed modules
  Write-Host ("Retrieving installed PowerShell modules") -ForegroundColor Green
  $InstalledModules = Get-InstalledModule -Name $NameFilter -ErrorAction SilentlyContinue

  #Start checking for updates if $InstalledModules is greater than 1
  if ($InstalledModules.Count -gt 0) {
    $number = 1
    #Loop through all modules and check for newer versions and add those to $total
    Write-Host ("Checking for updated versions") -ForegroundColor Green
    $total = foreach ($module in $InstalledModules) {
      Write-Progress ("[{0}/{1} Checking module {2}" -f $number, $InstalledModules.count, $module.name)
      try {
        $PsgalleryModule = Find-Module -Name $Module.Name -ErrorAction Stop
        if ([version]$module.version -lt [version]$PsgalleryModule.version) {
          [PSCustomObject]@{
            Repository          = $module.Repository
            'Module name'       = $module.Name
            'Installed version' = $module.Version
            'Latest version'    = $PsgalleryModule.version
            'Published on'      = $PsgalleryModule.PublishedDate
          }
        }
      }
      catch {
        Write-Warning ("Could not find module {0}" -f $module.Name)
      }
      $number++
    }
  }
  else {
    Write-Warning ("No modules were found to check for updates, please check yourNameFilter. Exiting...")
    return
  }

  #Output $total to display updates for installed modules if any
  if ($total.Count -gt 0) {
    Write-Host ("Found {0} updated modules" -f $total.Count) -ForegroundColor Green
    $total | Format-Table -AutoSize
  }
  else {
    Write-Host ("No updated modules were found")
  }
} 


## Edit Hosts File   
function Edit-HostsFile {
  param($ComputerName = $env:COMPUTERNAME)
   
  Start-Process notepad.exe -ArgumentList \\$ComputerName\admin$\System32\drivers\etc\hosts -Verb RunAs
}


## Test SSL Protocols ##
<#
 .DESCRIPTION
   Outputs the SSL protocols that the client is able to successfully use to connect to a server.

 .NOTES

   Copyright 2014 Chris Duck
   http://blog.whatsupduck.net

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

 .PARAMETER ComputerName
   The name of the remote computer to connect to.

 .PARAMETER Port
   The remote port to connect to. The default is 443.

 .EXAMPLE
   Test-SslProtocols -ComputerName "www.google.com"

   ComputerName       : www.google.com
   Port               : 443
   KeyLength          : 2048
   SignatureAlgorithm : rsa-sha1
   Ssl2               : False
   Ssl3               : True
   Tls                : True
   Tls11              : True
   Tls12              : True
 #>
 function Test-SslProtocols {
  param(
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
    $ComputerName,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [int]$Port = 443
  )
  begin {
    $ProtocolNames = [System.Security.Authentication.SslProtocols] | Get-Member -static -MemberType Property | Where-Object { $_.Name -notin @("Default", "None") } | ForEach-Object { $_.Name }
  }
  process {
    $ProtocolStatus = [Ordered]@{}
    $ProtocolStatus.Add("ComputerName", $ComputerName)
    $ProtocolStatus.Add("Port", $Port)
    $ProtocolStatus.Add("KeyLength", $null)
    $ProtocolStatus.Add("SignatureAlgorithm", $null)

    $ProtocolNames | ForEach-Object {
      $ProtocolName = $_
      $Socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
      $Socket.Connect($ComputerName, $Port)
      try {
        $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
        $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true)
        $SslStream.AuthenticateAsClient($ComputerName, $null, $ProtocolName, $false )
        $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
        $ProtocolStatus["KeyLength"] = $RemoteCertificate.PublicKey.Key.KeySize
        $ProtocolStatus["SignatureAlgorithm"] = $RemoteCertificate.PublicKey.Key.SignatureAlgorithm.Split("#")[1]
        $ProtocolStatus.Add($ProtocolName, $true)
      }
      catch {
        $ProtocolStatus.Add($ProtocolName, $false)
      }
      finally {
        $SslStream.Close()
      }
    }
    [PSCustomObject] $ProtocolStatus
  }
}


## Get-MailDomain Info
##
## By Harm Veenstra
## Source: https://github.com/HarmVeenstra/Powershellisfun/blob/main/Retrieve%20Email%20DNS%20Records/Get-MailDomainInfo.ps1
##

function Get-MailDomainInfo {
  param(
    [parameter(Mandatory = $true)][string[]]$DomainName,
    [parameter(Mandatory = $false)][string]$DNSserver
  )
     
  #Use DNS server 1.1.1.1 when parameter DNSserver is not used
  if (-not ($DNSserver)) {
    $DNSserver = '1.1.1.1'
  }

  $info = foreach ($domain in $DomainName) {
 
    #Retrieve all mail DNS records
    $autodiscoverA = (Resolve-DnsName -Name "autodiscover.$($domain)" -Type A -Server $DNSserver -ErrorAction SilentlyContinue).IPAddress
    $autodiscoverCNAME = (Resolve-DnsName -Name "autodiscover.$($domain)" -Type CNAME -Server $DNSserver -ErrorAction SilentlyContinue).NameHost
    $dkim1 = Resolve-DnsName -Name "selector1._domainkey.$($domain)" -Type CNAME -Server $DNSserver -ErrorAction SilentlyContinue
    $dkim2 = Resolve-DnsName -Name "selector2._domainkey.$($domain)" -Type CNAME -Server $DNSserver -ErrorAction SilentlyContinue
    $domaincheck = Resolve-DnsName -Name $domain -Server $DNSserver -ErrorAction SilentlyContinue
    $dmarc = (Resolve-DnsName -Name "_dmarc.$($domain)" -Type TXT -Server $DNSserver -ErrorAction SilentlyContinue | Where-Object Strings -Match 'DMARC').Strings
    $mx = (Resolve-DnsName -Name $domain -Type MX -Server $DNSserver -ErrorAction SilentlyContinue).NameExchange
    $spf = (Resolve-DnsName -Name $domain -Type TXT -Server $DNSserver -ErrorAction SilentlyContinue | Where-Object Strings -Match 'v=spf').Strings
 
    #Set variables to Not enabled or found if they can't be retrieved
    #and stop script if domaincheck is not valid 
    $errorfinding = 'Not enabled'
    if ($null -eq $domaincheck) {
      Write-Warning ("{0} not found" -f $domaincheck)
      return
    }
 
    if ($null -eq $dkim1 -and $null -eq $dkim2) {
      $dkim = $errorfinding
    }
    else {
      $dkim = "$($dkim1.Name) , $($dkim2.Name)"
    }
 
    if ($null -eq $dmarc) {
      $dmarc = $errorfinding
    }
 
    if ($null -eq $mx) {
      $mx = $errorfinding
    }
 
    if ($null -eq $spf) {
      $spf = $errorfinding
    }
 
    if (($autodiscoverA).count -gt 1) {
      $autodiscoverA = $errorfinding
    }
 
    if ($null -eq $autodiscoverCNAME) {
      $autodiscoverCNAME = $errorfinding
    }
 
    [PSCustomObject]@{
      'Domain Name'             = $domain
      'Autodiscover IP-Address' = $autodiscoverA
      'Autodiscover CNAME '     = $autodiscoverCNAME
      'DKIM Record'             = $dkim
      'DMARC Record'            = "$($dmarc)"
      'MX Record(s)'            = $mx -join ', '
      'SPF Record'              = "$($spf)"
    }
  }
         
  return $info
      
}


## Search EvenLog
##
## By Harm Veenstra
## Source:
##

#-Requires RunAsAdministrator
function Search-Eventlog {
  [CmdletBinding(DefaultParameterSetName = 'All')]
  param (
    [Parameter(Mandatory = $false, HelpMessage = "Name of remote computer")][string]$ComputerName = $env:COMPUTERNAME,
    [Parameter(Mandatory = $false, HelpMessage = "Number of hours to search back for")][double]$Hours = 1 ,
    [Parameter(Mandatory = $false, HelpMessage = "EventID number")][int[]]$EventID,
    [Parameter(Mandatory = $false, HelpMessage = "The name of the eventlog to search in")][string[]]$EventLogName,
    [Parameter(Mandatory = $false, HelpMessage = "Output results in a gridview", parameterSetName = "GridView")][switch]$Gridview,
    [Parameter(Mandatory = $false, HelpMessage = "String to search for")][string]$Filter,
    [Parameter(Mandatory = $false, HelpMessage = "Output path, e.g. c:\data\events.csv", parameterSetName = "CSV")][string]$OutCSV,
    [Parameter(Mandatory = $false, HelpMessage = "Exclude specific logs, e.g. security or application, security")][string[]]$ExcludeLog
  )

  #Convert $Hours to equivalent date value
  [DateTime]$hours = (Get-Date).AddHours(-$hours)

  #Set EventLogName if available
  if ($EventLogName) {
    try {
      $EventLogNames = Get-WinEvent -ListLog $EventLogName -ErrorAction Stop | Where-Object LogName -NotIn $ExcludeLog
      Write-Host ("Specified EventLog name {0} is valid on {1}, continuing..." -f $($EventLogName), $ComputerName) -ForegroundColor Green
    }
    catch {
      Write-Warning ("Specified EventLog name {0} is not valid or can't access {1}, exiting..." -f $($EventLogName), $ComputerName)
      return
    }
  }

  #Create array of logs for Eventlogname if not specified, exclude specific EventLogs if specified by Excludelog parameter
  if (-not $EventLogName) {
    try {
      $EventLogNames = Get-WinEvent -ListLog * -ComputerName $ComputerName | Where-Object LogName -NotIn $ExcludeLog
    }
    catch {
      Write-Warning ("Can't retrieve Eventlogs on {0}, exiting..." -f $ComputerName)
      return
    }
  }

  #Retrieve events
  $lognumber = 1
  $total = foreach ($log in $EventLogNames) {
    $foundevents = 0
    Write-Host ("[Eventlog {0}/{1}] - Retrieving events from the {2} Event log on {3}..." -f $lognumber, $EventLogNames.count, $log.LogName, $ComputerName) -ForegroundColor Green  
    try {
      #Specify different type of filters
      $FilterHashtable = @{
        LogName   = $log.LogName
        StartTime = $hours
      } 

      if ($EventID) {
        $FilterHashtable.Add('ID', $EventID)
      }

      #Retrieve events
      $events = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction Stop

      #Loop through events
      foreach ($event in $events) {
        if (-not $Filter -or $event.Message -match $Filter) {
          [PSCustomObject]@{
            Time         = $event.TimeCreated.ToString('dd-MM-yyy HH:mm')
            Computer     = $ComputerName
            LogName      = $event.LogName
            ProviderName = $event.ProviderName
            Level        = $event.LevelDisplayName
            User         = if ($event.UserId) {
              "$($event.UserId)"
            }
            else {
              "N/A"
            }
            EventID      = $event.ID
            Message      = $event.Message
          }
          $foundevents++
        }
      }  
      Write-Host ("{0} events found in the {1} Event log on {2}" -f $foundevents, $log.LogName, $ComputerName) -ForegroundColor Green
      $lognumber++
    }
    catch {
      Write-Host ("No events found in {0} within the specified time-frame (After {1}), EventID or Filter on {2}, skipping..." -f $log.LogName, $Hours, $ComputerName)
    }
  }

  #Output results to GridView
  if ($Gridview -and $total) {
    return $total | Sort-Object Time, LogName | Out-GridView -Title 'Retrieved events...'
  }

  #Output results to specified file location
  if ($OutCSV -and $total) {
    try {
      $total | Sort-Object Time, LogName | 
      export-csv -NoTypeInformation -Delimiter ';' -Encoding UTF8 -Path $OutCSV -ErrorAction Stop
      Write-Host ("Exported results to {0}" -f $OutCSV) -ForegroundColor Green
    }
    catch {
      Write-Warning ("Error saving results to {0}, check path or permissions. Exiting...")
      return
    }
  }
    
  #Output to screen is Gridview or Output were not specified
  if (-not $OutCSV -and -not $Gridview -and $total) {
    return $total | Sort-Object Time, LogName
  }

  #Return warning if no results were found
  if (-not $total) {
    Write-Warning ("No results were found on {0}..." -f $ComputerName)
  }
}


# Functions End #


# Console #
 
# Enable Oh-My-Posh Theme, font and Terminal Icons
# Requires the following:
# 1. Download and install 'CaskaydiaCove Nerd Font' from https://www.nerdfonts.com/font-downloads
# 2. winget install oh-my-posh
# 3. Add the following line to PS profile: oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\slim.omp.json" | Invoke-Expression
# 4. Install-Module PSReadLine -Scope CurrentUser  (for PS7)
# 5. Install-Module Terminal-Icons -Scope CurrentUser

## Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}

## Posh and git

Import-Module posh-git
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\atomic.omp.json" | Invoke-Expression
Import-Module Terminal-Icons

## PSReadline
Set-PSReadLineKeyHandler -Chord UpArrow -Function HistorySearchBackward
Set-PSReadLineOption -PredictionViewStyle InlineView

## Visual check
Write-Host -ForegroundColor Yellow "Windows PowerShell Profile Loaded"