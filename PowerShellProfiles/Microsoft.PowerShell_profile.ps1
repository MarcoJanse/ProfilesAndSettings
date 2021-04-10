<#
  PowerShell 7 Profile
  Marco Janse
  v2.0
  2021-04-10

  Version History:

  2.0 - Font and PoshGui theme changes + cleanup + uniformation
  1.1 - simplified the Get-Uptime function for modern PS and OS versions
  1.0 - Copied some things from my PowerShell 5.1 profile and added some stuff
        from other sources

 #>
 
 ### Aliases ###

 $Git = 'C:\Git\GitHub\MarcoJanse\'

 
 ### Modules ###
 
 ### Functions ###
 
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
 
 
 ## Console
 
 # Enable PoshGui Theme, font and Terminal Icons
 # Requires the following:
 # 1. Download and install 'CaskaydiaCove Nerd Font' from https://www.nerdfonts.com/font-downloads
 # 2. Install-Module posh-git -Scope CurrentUser
 # 3. Install-Module oh-my-posh -Scope CurrentUser
 # 4. Install-Module PSReadLine -Scope CurrentUser  (for PS7)
 # 5. Install-Module Terminal-Icons -Scope CurrentUser

 Import-Module posh-git
 Import-Module oh-my-posh
 Set-PoshPrompt paradox
 Import-Module Terminal-Icons
 
 
# Get-Uptime Function
Function Get-Uptime {
  Param ( [string] $ComputerName = $env:COMPUTERNAME )
  $os = Get-CimInstance win32_operatingsystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
  if ($os.LastBootUpTime) {
      $uptime = (Get-Date) - $os.LastBootUpTime
      Write-Host ("Last boot: " + $($os.LastBootUpTime) )
      Write-Host ("Uptime   : " + $uptime.Days + " Days " + $uptime.Hours + " Hours " + $uptime.Minutes + " Minutes" )
}
  else {
      Write-Warning "Unable to connect to $computername"
}
}
# Get-Uptime
   
   function Get-FortisslIPAddress {
   
     Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq 'fortissl' }
   
   }
   
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

    $ProtocolNames | %{
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
    [PSCustomObject]$ProtocolStatus
  }
}

## Test SSL Protocols End ##


 ### Functions End ###
 

# Set formatting Enumeration Unlimited

$FormatEnumerationLimit = -1

# STARTING POINT
Set-Location $HOME

# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}
 # Visual check
 Write-Host -ForegroundColor Yellow "PowerShell 7 Profile Loaded"