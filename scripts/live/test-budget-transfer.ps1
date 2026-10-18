# Pure parser tests: no downloads, services or network changes.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'budget-transfer.ps1')
function Assert([bool]$ok,[string]$name) {if(-not $ok){throw $name};Write-Host "PASS: $name"}
$good="200 25000000 1`n"+("200 25000000 0`n"*11)
$r=Read-SieveBudgetTransfer $good 0 $false
Assert ($r.Valid -and $r.Bytes -eq 300000000 -and $r.Connections -eq 1) 'exact 300 MB on one reused connection passes'
Assert (-not (Read-SieveBudgetTransfer '403 1 1' 22 $false).Valid) 'HTTP rejection never becomes a performance pass'
Assert (-not (Read-SieveBudgetTransfer ($good.Replace('25000000','24999999')) 0 $false).Valid) 'short bodies fail'
Assert (-not (Read-SieveBudgetTransfer ($good.Replace(' 0',' 1')) 0 $false).Valid) 'multiple connections cannot satisfy the single-flow budget'
Assert (-not (Read-SieveBudgetTransfer $good 0 $true).Valid) 'deadline expiry fails even if output looks complete'
Assert (-not (Read-SieveBudgetTransfer $good 1 $false).Valid) 'nonzero exit fails'
Assert (-not (Read-SieveBudgetTransfer ($good+"200 25000000 0`n") 0 $false).Valid) 'unexpected response count fails'
