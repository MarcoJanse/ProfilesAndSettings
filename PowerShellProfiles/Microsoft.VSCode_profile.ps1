<#
  PowerShell 7 VSCode Profile
  Marco Janse
  v5.0
  2025-08-21

  Version History:

  5.0 - Back to basics - less is more
  4.0 - Refactor to make it minimalistic
  3.0 - Git var updates to Dev drive
  2.9 - Revert back to Inline view of PSReadLine predictionViewStyle
  2.8 - Added some new functions and some housekeeping
  2.7 - Added/changed git variables for workdirs and formatting changes
  2.6 - Removed starting working dir and FormatEnumerationLimit settings
  2.5 - Added Get-DynamicParameters function
  2.4 - Updated Oh-My-Posh from PS module to the Winget package
  2.3 - Changed poshprompt to slim
  2.2 - Cleaned up version July 2021
  2.1 - Minor reordering and tidy-up
  2.0 - Font and PoshGui theme changes + cleanup + uniformation
  1.0 - first version for PowerShell 7
#>

# Custom Variables #

$Git = 'X:\Git\'
$GitHub = 'X:\Git\GitHub\MarcoJanse\'
$AzDevOps = 'X:\Git\AzDevOps'

## Posh and git

Import-Module posh-git
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\dracula.omp.json" | Invoke-Expression
Import-Module Terminal-Icons

## PSReadline
Set-PSReadLineKeyHandler -Chord UpArrow -Function HistorySearchBackward
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
Set-PSReadLineOption -PredictionViewStyle InlineView

# Visual check
Write-Host -ForegroundColor Yellow "PowerShell 7 VSCode Profile Loaded"