<#
  Windows PowerShell Profile
  Marco Janse
  v3.0
  2025-08-21

  Version History:

  3.0 - Back to basics - less is more
  2.0 - Optimized and stripped version for Windows PowerShell
  1.0 - Initial profile based on PS7 profile

#>

# Custom Variables #

$Git = 'X:\Git\'
$GitHub = 'X:\Git\GitHub\MarcoJanse\'
$AzDevOps = 'X:\Git\AzDevOps'

 
## Posh and git

Import-Module posh-git
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\atomic.omp.json" | Invoke-Expression
Import-Module Terminal-Icons

## PSReadline
Set-PSReadLineKeyHandler -Chord UpArrow -Function HistorySearchBackward
Set-PSReadLineOption -PredictionViewStyle InlineView

## Visual check
Write-Host -ForegroundColor Yellow "Windows PowerShell Profile Loaded"