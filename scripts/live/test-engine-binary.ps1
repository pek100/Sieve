# Mocked file and service operations: no installed engine is touched.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'engine-binary.ps1')
$script:copies=0;$script:status='Stopped';$script:failures=2
function Get-Service {[pscustomobject]@{Status=$script:status}}
function Start-Sleep {}
function Copy-Item {$script:copies++;if($script:copies -le $script:failures){throw [IO.IOException]::new('Executable still mapped')}}
Copy-SieveStoppedEngine 'source' 'destination'
if($script:copies -ne 3){throw 'Did not retry the transient image lock'}
Write-Host 'PASS: a stopped service with a briefly mapped executable is retried'
$script:status='Running';$before=$script:copies;$threw=$false
try {Copy-SieveStoppedEngine 'source' 'destination'} catch {$threw=$true}
if(-not $threw -or $script:copies -ne $before){throw 'Touched a running engine'}
Write-Host 'PASS: a running engine is never overwritten'
$script:status='Stopped';$script:failures=[int]::MaxValue;$threw=$false
try {Copy-SieveStoppedEngine 'source' 'destination' 0.01} catch {$threw=$true}
if(-not $threw){throw 'Permanent image lock did not time out'}
Write-Host 'PASS: a persistent lock fails within the bounded retry window'
