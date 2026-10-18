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
$custom="200 123 1`r`n200 123 0`r`n200 123 0`r`n"
$r=Read-SieveBudgetTransfer $custom 0 $false -Count 3 -Size 123
Assert ($r.Valid -and $r.Bytes -eq (3*123) -and $r.Responses -eq 3) 'custom count and size with CRLF pass'
Assert (-not (Read-SieveBudgetTransfer $custom 0 $false -Count 2 -Size 123).Valid) 'custom count mismatch fails'
Assert (-not (Read-SieveBudgetTransfer $custom 0 $false -Count 3 -Size 124).Valid) 'custom size mismatch fails'
$old='--silent --show-error --fail --fail-early --noproxy "*" --http1.1 --max-time 60 --write-out "%{http_code} %{size_download} %{num_connects}\n"'+(' -o NUL "https://speed.cloudflare.com/__down?bytes=25000000"'*12)
Assert ((Get-SieveBudgetArguments) -ceq $old) 'default curl command is unchanged'
$args=Get-SieveBudgetArguments -Seconds 17 -Url 'https://example.test/file' -Count 3 -Size 123 -Proxy 'http://127.0.0.1:4321'
Assert ($args.Contains('-x "http://127.0.0.1:4321"') -and -not $args.Contains('--noproxy')) 'explicit proxy uses -x and drops --noproxy'
Assert ([regex]::Matches($args,'-o NUL "https://example.test/file"').Count -eq 3) 'custom URL is repeated for the requested count'
Assert ((Get-SieveBudgetArguments -Size 123).Contains('__down?bytes=123')) 'default endpoint derives its size from Size'
$threw=$false
try {Get-SieveBudgetArguments -Url 'https://example.test/" --output bad' | Out-Null} catch {$threw=$true}
Assert $threw 'URL cannot inject curl options'
