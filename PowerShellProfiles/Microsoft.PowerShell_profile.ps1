<#
  PowerShell 7 Profile
  Marco Janse
  v5.1
  2025-08-21

  Version History:

  5.1 - re-add visual check
  5.0 - Back to basics - less is more
  4.2 - Add function Uninstall-OldPsResourceModules
      - Updated Find-PsModuleUpdates to exclude prerelease modules
  4.1 - Add function Find-PsModuleUpdates
  4.0 - Refactor:
    - Remove PowerShellGet related functions Find-ModuleUpdates/Remove-OldModules, as PS7 now uses PSResourceGet
    - Remove PowerCli related functions, as I don't use PowerCli anymore
    - Formatting changes
  3.2 - Git path changes
  3.1 - added function Find-ModuleUpdates
  3.0 - added function Remove-OldModules
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
 
$Git = 'X:\Git\'
$GitHub = 'X:\Git\GitHub\MarcoJanse\'
$AzDevOps = 'X:\Git\AzDevOps'

## Posh and git

Import-Module posh-git
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\atomic.omp.json" | Invoke-Expression
Import-Module Terminal-Icons

## PSReadline
Set-PSReadLineKeyHandler -Chord UpArrow -Function HistorySearchBackward
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
Set-PSReadLineOption -PredictionViewStyle InlineView

## Visual check
Write-Host -ForegroundColor Yellow "PowerShell 7 Profile Loaded"