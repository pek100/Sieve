# No network, relay, cargo, service, route or real lease calls. All process and
# machine boundaries are mocked; the workload parser and runner execute for real.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'p0-relay-floor.ps1')
function Assert([bool]$Ok,[string]$Name) {if(-not $Ok){throw "FAIL: $Name"};Write-Host "PASS: $Name"}
function Must-Throw([scriptblock]$Action,[string]$Pattern,[string]$Name) {
  $message=''
  try {& $Action | Out-Null} catch {$message=$_.Exception.Message}
  Assert ($message -like $Pattern) $Name
}

# Poison every effect boundary before executing the actual dry-run entry point.
function Assert-P0Unelevated {throw 'dry run read identity'}
function Enter-SieveLiveLease {throw 'dry run acquired lease'}
function Exit-SieveLiveLease {throw 'dry run released lease'}
function New-P0EvidenceDirectory {throw 'dry run created directory'}
function Write-P0Evidence {throw 'dry run wrote evidence'}
function Get-P0RoutingState {throw 'dry run read routing'}
function Get-P0AdGuardState {throw 'dry run read service'}
function Build-P0Relay {throw 'dry run built relay'}
function Start-P0Relay {throw 'dry run launched relay'}
function Stop-P0Relay {throw 'dry run stopped relay'}
function Invoke-SieveBudgetTransfer {throw 'dry run launched curl'}
function Start-Sleep {throw 'dry run slept'}
Invoke-SieveP0 -DryRun
Assert $true 'DryRun touches no machine, process, lease, sleep or file boundary'

function Off-State {
  [pscustomobject]@{Routes=@();RoutesError=$null;Status=[pscustomobject]@{routes_up=$false;engine=$false};StatusError=$null}
}
$state=Off-State
$state.Routes=@([pscustomobject]@{DestinationPrefix='fe80::/64';InterfaceAlias='Sieve'})
Must-Throw {Assert-P0RoutingOff $state -AssumeRoutingOff} '*routes exist*' 'any Sieve route refuses, even with assumption'
$state=Off-State;$state.Status.engine=$true
Must-Throw {Assert-P0RoutingOff $state -AssumeRoutingOff} '*engine reports routing on*' 'engine routing intent refuses without installed routes'
$state=Off-State;$state.Status.routes_up=$true
Must-Throw {Assert-P0RoutingOff $state} '*engine reports routing on*' 'engine routes_up refuses'
$state=Off-State;$state.RoutesError='access denied'
Must-Throw {Assert-P0RoutingOff $state -AssumeRoutingOff} '*Cannot read Sieve routes*' 'assumption cannot override unreadable route table'
$state=Off-State;$state.Status=$null;$state.StatusError='access denied'
Must-Throw {Assert-P0RoutingOff $state} '*require -AssumeRoutingOff*' 'unreadable status requires explicit assumption'
Assert-P0RoutingOff $state -AssumeRoutingOff
Assert $true 'explicit assumption permits unreadable status with observed empty routes'
Assert ((Get-P0Median @(9,1,3)) -eq 3 -and (Get-P0Median @(9,1,3,5)) -eq 4 -and $null -eq (Get-P0Median @())) 'median sorts odd and even sets and leaves empty sets unscored'
$mixed=@(
  [pscustomobject]@{Kind='baseline';Valid=$true;Mbps=100;CpuCoresPer100Mbit=$null},
  [pscustomobject]@{Kind='candidate';Valid=$true;Mbps=100;CpuCoresPer100Mbit=0.025},
  [pscustomobject]@{Kind='candidate';Valid=$false;Mbps=999;CpuCoresPer100Mbit=999}
)
$comparison=Get-P0Comparison $mixed 2
Assert ($comparison.CandidateMedianMbps -eq 100 -and $comparison.MedianCpuCoresPer100Mbit -eq 0.025 -and $null -eq $comparison.Pass) 'invalid outliers are excluded from medians and incomplete sets have no verdict'
$mixed[1].Mbps=80
$comparison=Get-P0Comparison $mixed[0..1] 1
Assert (-not $comparison.Pass) 'throughput outside the research tolerance fails'
$mixed[1].Mbps=100;$mixed[1].CpuCoresPer100Mbit=0.1
$comparison=Get-P0Comparison $mixed[0..1] 1
Assert (-not $comparison.Pass) 'CPU above the research limit fails'

$script:trace=New-Object 'Collections.Generic.List[string]'
$script:fixtures=New-Object 'Collections.Generic.Queue[object]'
$script:routeUp=$false;$script:missingStatus=$false;$script:badRelay=$false;$script:curlThrows=$false;$script:rejected=$false;$script:midRoute=$false
$script:lastTransfer=$null;$script:saved=$null
function Assert-P0Unelevated {$script:trace.Add('identity')}
function Enter-SieveLiveLease {$script:trace.Add('lease');return 'mock-lease'}
function Exit-SieveLiveLease {$script:trace.Add('release')}
function New-P0EvidenceDirectory {$script:trace.Add('directory');return 'mock-directory'}
function Write-P0Evidence($Directory,$Evidence) {$script:trace.Add('save');$script:saved=$Evidence | ConvertTo-Json -Depth 12 | ConvertFrom-Json}
function Get-P0RoutingState {
  $script:trace.Add('routing');$s=Off-State
  if($script:routeUp){$s.Routes=@('mock-route')}
  if($script:missingStatus){$s.Status=$null;$s.StatusError='mock access denied'}
  return $s
}
function Get-P0AdGuardState {$script:trace.Add('adguard');[pscustomobject]@{State='Running';Error=$null}}
function Build-P0Relay {$script:trace.Add('build');return 'mock-relay.exe'}
function Start-P0Relay {param($Exe,$Seconds);$script:trace.Add('start-relay');[pscustomobject]@{Port=4321}}
function Stop-P0Relay {
  param($Relay,$Seconds)
  $script:trace.Add('stop-relay')
  # Deliberately larger socket bytes check that normalization uses body bytes.
  $s=[pscustomobject]@{user_cpu_seconds=0.1;kernel_cpu_seconds=0.1;bytes_up=123;bytes_down=200000000;tunnels=1;cancelled_connections=0;failed_connections=0;rejected_connections=0}
  if ($script:badRelay) {$s.cancelled_connections=1}
  if ($script:rejected) {$s.rejected_connections=1}
  [pscustomobject]@{Summary=$s;ExitCode=0;TimedOut=$false;ParseError=$null;Error='';Raw=($s | ConvertTo-Json -Compress)}
}
function Start-Sleep {param($Seconds);$script:trace.Add("pause:$Seconds")}
function Invoke-SieveBudgetTransfer {
  param($Seconds,$Url,$Count,$Size,$Proxy,$WhileRunning)
  $script:trace.Add($(if($Proxy){'curl-proxy'}else{'curl-direct'}))
  if ($script:curlThrows) {throw 'mock curl launch failure'}
  if (-not $WhileRunning) {throw 'transfer is not watched while it runs'}
  # Routing that is up only mid-transfer, invisible to the before/after reads.
  if ($script:midRoute) {$script:routeUp=$true;& $WhileRunning;$script:routeUp=$false}
  else {& $WhileRunning}
  if ($Proxy -and $Proxy -ne 'http://127.0.0.1:4321') {throw 'Wrong proxy argument'}
  $fixture=$script:fixtures.Dequeue()
  $raw="200 $Size 1`r`n"+(("200 $Size 0`r`n")*($Count-1))
  if (-not $fixture.Valid) {$raw='429 0 1'}
  $r=Read-SieveBudgetTransfer $raw 0 $false -Count $Count -Size $Size
  $r | Add-Member NoteProperty Seconds $fixture.Seconds
  $script:lastTransfer=$r
  return $r
}
function Add-Fixture([double]$Seconds,[bool]$Valid=$true) {$script:fixtures.Enqueue([pscustomobject]@{Seconds=$Seconds;Valid=$Valid})}

# Body is 100 million bytes, hence 800 Mbit. The chosen wall times give
# unsorted baseline throughput 80, 200, 100 and candidate 100, 160, 80.
foreach($seconds in @(10,8,4,5,8,10)){Add-Fixture $seconds}
$result=Invoke-SieveP0 -Runs 3 -PauseSeconds 7 -Count 2 -Size 50000000
$comparison=$result.Comparison
Assert ($comparison.BaselineMedianMbps -eq 100 -and $comparison.CandidateMedianMbps -eq 100 -and $comparison.Pass) 'mock runner compares valid medians, not final runs'
Assert ([decimal]$comparison.MedianCpuCoresPer100Mbit -eq [decimal]0.025) 'CPU normalization includes user plus kernel and uses application bytes'
Assert (($script:trace | Where-Object {$_ -like 'curl-*'}) -join ',' -eq 'curl-direct,curl-proxy,curl-direct,curl-proxy,curl-direct,curl-proxy') 'baseline and candidate alternate'
Assert (@($script:trace | Where-Object {$_ -eq 'pause:7'}).Count -eq (2*3-1)) 'pause occurs between every run, never before the first'
Assert ($script:trace.IndexOf('lease') -lt $script:trace.IndexOf('routing') -and $script:trace[$script:trace.Count-1] -eq 'release') 'lease encloses machine reads and all measurement work'
Assert ($result.AdGuardStart.State -eq 'Running' -and $result.AdGuardEnd.State -eq 'Running' -and @($script:trace | Where-Object {$_ -eq 'adguard'}).Count -eq 2) 'AdGuard state is recorded at start and end'

$script:trace.Clear();Add-Fixture 8;Add-Fixture 1 $false
$result=Invoke-SieveP0 -Runs 1 -PauseSeconds 0 -Count 2 -Size 50000000
Assert (-not $result.Rows[1].Valid -and $null -eq $result.Rows[1].Mbps -and $null -eq $result.Rows[1].CpuCoresPer100Mbit) 'invalid curl response is never scored'
Assert (-not $result.Comparison.Complete -and $null -eq $result.Comparison.Pass -and $null -eq $result.Comparison.MedianCpuCoresPer100Mbit) 'invalid run cannot produce an overall pass or candidate median'
Assert (@($script:trace | Where-Object {$_ -eq 'stop-relay'}).Count -eq 1) 'relay is closed after invalid workload'

$script:badRelay=$true;Add-Fixture 8
$row=Invoke-P0Sample -Kind candidate -Iteration 1 -Exe mock -Workload @{Seconds=60;Count=2;Size=50000000;Url='https://example.test/file'}
Assert (-not $row.Valid -and $null -eq $row.CpuCoresPer100Mbit) 'cancelled relay evidence is never scored even with a valid download'
$script:badRelay=$false;$script:rejected=$true;Add-Fixture 8
$row=Invoke-P0Sample -Kind candidate -Iteration 1 -Exe mock -Workload @{Seconds=60;Count=2;Size=50000000;Url='https://example.test/file'}
Assert (-not $row.Valid -and $null -eq $row.CpuCoresPer100Mbit) 'a relay that also answered rejected connections is never scored'
$script:rejected=$false;$script:midRoute=$true;Add-Fixture 8
$row=Invoke-P0Sample -Kind baseline -Iteration 1 -Exe mock -Workload @{Seconds=60;Count=2;Size=50000000;Url='https://example.test/file'}
Assert (-not $row.Valid -and $row.Reason -like 'Routing changed during the transfer*') 'routing seen only mid-transfer invalidates the sample'
$script:midRoute=$false;$script:curlThrows=$true;$script:trace.Clear()
$row=Invoke-P0Sample -Kind candidate -Iteration 1 -Exe mock -Workload @{Seconds=60;Count=2;Size=50000000;Url='https://example.test/file'}
Assert (-not $row.Valid -and $script:trace.Contains('stop-relay')) 'relay cleanup runs when curl throws'
$script:curlThrows=$false;$script:routeUp=$true;$script:trace.Clear()
Must-Throw {Invoke-SieveP0 -Runs 1 -PauseSeconds 0} '*routes exist*' 'runner refuses routes before building or measuring'
Assert (-not $script:trace.Contains('build') -and -not $script:trace.Contains('curl-direct') -and $script:trace.Contains('release')) 'routing refusal still releases the lease'
$script:routeUp=$false;$script:missingStatus=$true;Add-Fixture 8;Add-Fixture 8
$result=Invoke-SieveP0 -Runs 1 -PauseSeconds 0 -Count 2 -Size 50000000 -AssumeRoutingOff
Assert ($script:saved.AssumeRoutingOff -and $script:saved.Preflight.StatusError -eq 'mock access denied') 'evidence records the routing assumption and unreadable source'
Write-Host 'P0 contract tests passed (mock data only; no live performance evidence).'
