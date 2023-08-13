<#
  PowerShell 7 Profile
  Marco Janse
  v2.9
  2023-08-13

  Version History:

  2.9 - Revert back to Inline view of PSReadLine predictionViewStyle
  2.8 - Added some new functions and some housekeeping
  2.7 - Added/changed git variables for workdirs and formatting changes
  2.6 - Changed starting working dir and removed FormatEnumerationLimit settings
  2.5 - Added Get-DynamicParameters function
  2.4 - Updated Oh-My-Posh from PS module to the Winget package
  2.3 - Changed posh theme to slim
  2.2 - Cleaned up version
  2.1 - Minor reordering and tidy-up
  2.0 - Font and PoshGui theme changes + cleanup + uniformation
  1.1 - simplified the Get-Uptime function for modern PS and OS versions
  1.0 - Copied some things from my PowerShell 5.1 profile and added some stuff
        from other sources

 #>
 
 # Aliases #

 # Custom Variables #

 $Git = 'C:\Git\'
 $GitHub = 'C:\Git\GitHub\MarcoJanse\'
 $AzDevOps = 'C:\Git\AzDevOps'

 
 # Modules #
 
 # Functions #
 
 ## PowerShell Core

 function Get-DynamicParameters
 {
     param ($Cmdlet, $PSDrive)
     (Get-Command -Name $Cmdlet -ArgumentList $PSDrive).ParameterSets |
       ForEach-Object {$_.Parameters} |
         Where-Object { $_.IsDynamic } |
           Select-Object -Property Name -Unique
 }

 ## VMware PowerCli
 
 function Get-SnapShotOverview {
   Get-VM | Get-SnapShot | Format-Table name,VM,Created,SizeGB -AutoSize
 }
 
 Function Get-VMConnectedIso {
 
   Get-VM | Where-Object { $_ | Get-CDDrive | Where-Object { $_.ConnectionState.Connected -eq "true" -And $_.ISOPath -Like "*.iso*"} } | Select-Object Name, @{Name=".ISO Path";Expression={(Get-CDDrive $_).isopath }}
 }
 
 function Set-VMNotes {
   $VM = Read-Host -Prompt 'Enter the Virtual Machine name'
   $Notes = Read-Host -Prompt 'Enter the notes for the VM'
   Set-VM -VM $VM -Notes $Notes
 }
 
 function Get-VMToolsVersion {
   $VM = Read-Host -Prompt 'Enter the Virtual Machine name'
   (Get-VM $VM).Guest.ToolsVersion
 }

 function Add-VMtagProperty
 {
    New-VIProperty -Name Tag -ObjectType VirtualMachine -Value { Get-TagAssignment -Entity $args[0] | Select-Object -ExpandProperty Tag }
    }
 
 ## End VMware PowerCli
   
   function Edit-HostsFile
   {
    param($ComputerName=$env:COMPUTERNAME)
   
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
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
    $ComputerName,

    [Parameter(ValueFromPipelineByPropertyName=$true)]
    [int]$Port = 443
  )
  begin {
    $ProtocolNames = [System.Security.Authentication.SslProtocols] | Get-Member -static -MemberType Property | Where-Object {$_.Name -notin @("Default","None")} | ForEach-Object {$_.Name}
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
        $SslStream.AuthenticateAsClient($ComputerName,  $null, $ProtocolName, $false )
        $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
        $ProtocolStatus["KeyLength"] = $RemoteCertificate.PublicKey.Key.KeySize
        $ProtocolStatus["SignatureAlgorithm"] = $RemoteCertificate.PublicKey.Key.SignatureAlgorithm.Split("#")[1]
        $ProtocolStatus.Add($ProtocolName, $true)
      } catch  {
        $ProtocolStatus.Add($ProtocolName, $false)
      } finally {
        $SslStream.Close()
      }
    }
    [PSCustomObject] $ProtocolStatus
  }
}

## Test SSL Protocols End ##

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

## Get-MailDomainInfo End

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

## Search EventLog End

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
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
Set-PSReadLineOption -PredictionViewStyle InlineView

## AzToolsPredictor
Import-Module Az.Tools.Predictor

## Visual check
Write-Host -ForegroundColor Yellow "PowerShell 7 Profile Loaded"