<#
  Windows PowerShell Profile
  Marco Janse
  v3.5
  2026-02-23

  Version History:

  3.5 - Updated Oh-My-Posh to the latest version and changed theme to Atomic
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
oh-my-posh init pwsh --config 'atomic' | Invoke-Expression
Import-Module Terminal-Icons

## PSReadline
Set-PSReadLineKeyHandler -Chord UpArrow -Function HistorySearchBackward
Set-PSReadLineOption -PredictionViewStyle InlineView

## Visual check
Write-Host -ForegroundColor Yellow "Windows PowerShell Profile Loaded"