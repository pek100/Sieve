# Process/file-only tests; no service, network, policy or elevation calls.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'live-lease.ps1')
$scratch=Join-Path $PSScriptRoot ('lease-test-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($scratch)
$path=Join-Path $scratch 'runner.lock'
$helper=Join-Path $PSScriptRoot 'live-lease.ps1'
$child=Join-Path $scratch 'child.ps1'
@'
param([string]$Helper,[string]$Path,[string]$Mode,[string]$Ready)
$ErrorActionPreference='Stop'
. $Helper
if ($Mode -eq 'contend') {$env:SIEVE_LIVE_RUN_TOKEN=$null; $env:SIEVE_LIVE_RUN_OWNER=$null}
try {
  if ($Mode -eq 'inherit-gate') {[IO.File]::WriteAllText($Ready,'attempting')}
  $lease=Enter-SieveLiveLease $Path
  if ($Mode -like 'inherit*' -and -not $lease.Inherited) {throw 'Child did not inherit'}
  if ($Mode -eq 'contend') {throw 'Competing root acquired the lock'}
  if ($Mode -in @('hold','inherit-hold')) {
    [IO.File]::WriteAllText($Ready,'ready')
    Start-Sleep -Seconds 30
  }
  Exit-SieveLiveLease $lease
  exit 0
} catch {
  if ($Mode -eq 'contend' -and $_.Exception.Message -like 'Another Sieve live runner*') {exit 0}
  Write-Error $_
  exit 1
}
'@ | Set-Content -LiteralPath $child -Encoding UTF8
function Run-Child([string]$mode) {
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $child -Helper $helper -Path $path -Mode $mode
  if ($LASTEXITCODE -ne 0) {throw "Child test failed: $mode"}
}
$lease=$null; $holder=$null; $testGate=$null
try {
  $originalToken=$env:SIEVE_LIVE_RUN_TOKEN
  $lease=Enter-SieveLiveLease $path
  Run-Child 'contend'
  Write-Host 'PASS: competing root refused while lease is active'
  Run-Child 'inherit'
  Write-Host 'PASS: real child inherits without releasing parent handle'
  $ready=Join-Path $scratch 'ready.txt'
  $testGate=[IO.File]::Open($path+'.gate',[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  $args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$child+'"'),'-Helper',('"'+$helper+'"'),'-Path',('"'+$path+'"'),'-Mode','inherit-gate','-Ready',('"'+$ready+'"'))
  $holder=Start-Process powershell.exe -WindowStyle Hidden -ArgumentList $args -PassThru
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while (-not (Test-Path -LiteralPath $ready) -and $clock.Elapsed.TotalSeconds -lt 10) {Start-Sleep -Milliseconds 50}
  if (-not (Test-Path -LiteralPath $ready)) {throw 'Gate waiter did not become ready'}
  Start-Sleep -Milliseconds 200
  if ($holder.HasExited) {throw 'Child failed instead of waiting for the acquisition gate'}
  $testGate.Dispose();$testGate=$null
  if (-not $holder.WaitForExit(5000) -or $holder.ExitCode -ne 0) {throw 'Child did not acquire after temporary gate contention'}
  Remove-Item -LiteralPath $ready
  Write-Host 'PASS: temporary gate contention waits without rejecting a legitimate child'
  Run-Child 'contend'
  $ready=Join-Path $scratch 'ready.txt'
  $args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$child+'"'),'-Helper',('"'+$helper+'"'),'-Path',('"'+$path+'"'),'-Mode','inherit-hold','-Ready',('"'+$ready+'"'))
  $holder=Start-Process powershell.exe -WindowStyle Hidden -ArgumentList $args -PassThru
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while (-not (Test-Path -LiteralPath $ready) -and $clock.Elapsed.TotalSeconds -lt 10) {Start-Sleep -Milliseconds 50}
  if (-not (Test-Path -LiteralPath $ready)) {throw 'Inherited holder did not become ready'}
  Exit-SieveLiveLease $lease; $lease=$null
  Run-Child 'contend'
  Write-Host 'PASS: surviving child keeps the lease after parent releases its handle'
  Stop-Process -Id $holder.Id -Force
  $holder.WaitForExit()
  Remove-Item -LiteralPath $ready
  if ($env:SIEVE_LIVE_RUN_TOKEN -ne $originalToken) {throw 'Environment not restored'}
  $lease=Enter-SieveLiveLease $path
  Exit-SieveLiveLease $lease; $lease=$null
  Write-Host 'PASS: normal release permits a new run and restores environment'
  $ready=Join-Path $scratch 'ready.txt'
  $args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$child+'"'),'-Helper',('"'+$helper+'"'),'-Path',('"'+$path+'"'),'-Mode','hold','-Ready',('"'+$ready+'"'))
  $holder=Start-Process powershell.exe -WindowStyle Hidden -ArgumentList $args -PassThru
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while (-not (Test-Path -LiteralPath $ready) -and $clock.Elapsed.TotalSeconds -lt 10) {Start-Sleep -Milliseconds 50}
  if (-not (Test-Path -LiteralPath $ready)) {throw 'Holder did not become ready'}
  Stop-Process -Id $holder.Id -Force
  $holder.WaitForExit()
  $lease=Enter-SieveLiveLease $path
  Exit-SieveLiveLease $lease; $lease=$null
  Write-Host 'PASS: killing the test holder releases the OS file lock'
} finally {
  if ($testGate) {$testGate.Dispose()}
  if ($lease) {Exit-SieveLiveLease $lease}
  if ($holder -and -not $holder.HasExited) {Stop-Process -Id $holder.Id -Force}
  # Only known test files; no recursive delete or computed external paths.
  foreach($file in @($child,$path,($path+'.gate'),(Join-Path $scratch 'ready.txt'))) {if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file}}
  Remove-Item -LiteralPath $scratch
}
