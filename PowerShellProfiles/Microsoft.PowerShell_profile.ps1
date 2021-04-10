<#
  PowerShell 7 Profile
  Marco Janse
  v1.1
  2020-08-26

  Version History:

  1.1 - simplified the Get-Uptime function for modern PS and OS versions
  1.0 - Copied some things from my PowerShell 5.1 profile and added some stuff
        from other sources

 #>
 
 ### Aliases ###

$Git = 'C:\Git\GitHub\MarcoJanse\PowerShellTraining\PowershellToolmaking\Labs\'
$TFS = 'C:\Git\ReferitTFS\Powershell'
$LocalScripts = 'C:\Users\JanseMarco\OneDrive - Referit B.V\Scripts\PowerShell'

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


## End VMware PowerCli

## Console

# Enable PoshGui Theme

Import-Module posh-git
Import-Module oh-my-posh
Set-Theme Paradox

# Get-Uptime Function
Function Get-Uptime {
    Param ( [string] $ComputerName = $env:COMPUTERNAME )
    $os = Get-Ciminstance -ClassName win32_operatingsystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
    if (Test-Connection -TargetName $ComputerName) {
        $os.LastBootUpTime
    }
    else {
        Write-Warning "Unable to connect to $computername"
    }
  } # Get-Uptime
  
  function Get-FortisslIPAddress {
  
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq 'fortissl' }
  
  }
  
  function Edit-HostsFile
  {
   param($ComputerName=$env:COMPUTERNAME)
  
   Start-Process notepad.exe -ArgumentList \\$ComputerName\admin$\System32\drivers\etc\hosts -Verb RunAs
  }

### Functions End ###

# Visual check
Write-Host -ForegroundColor Yellow "Microsoft PowerShell 7 Profile Loaded"