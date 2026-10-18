param(
  [int]$Runs=3,
  [int]$PauseSeconds=300,
  [int]$Seconds=60,
  [string]$Url='',
  [int]$Count=12,
  [long]$Size=25000000,
  [switch]$AssumeRoutingOff,
  [switch]$DryRun
)

$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'budget-transfer.ps1')
. (Join-Path $PSScriptRoot 'live-lease.ps1')

function Assert-P0Unelevated {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try {
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'P0 must run UNELEVATED'}
  } finally {$identity.Dispose()}
}

function Get-P0RoutingState {
  $state=[ordered]@{Routes=@();RoutesError=$null;Status=$null;StatusError=$null;StatusWrittenUtc=$null}
  try {
    # Match the engine's adapter identity, with no destination-prefix exception.
    $state.Routes=@(Get-NetRoute -ErrorAction Stop | Where-Object InterfaceAlias -eq 'Sieve' |
      Select-Object InterfaceAlias,InterfaceIndex,DestinationPrefix,NextHop,PolicyStore)
  } catch {$state.RoutesError=$_.Exception.Message}
  try {
    $path=Join-Path $env:ProgramData 'Sieve\engine\status.json'
    $status=Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($status.routes_up -isnot [bool] -or $status.policy.engine -isnot [bool]) {throw 'Engine status lacks boolean routes_up or policy.engine'}
    $state.Status=[pscustomobject]@{routes_up=$status.routes_up;engine=$status.policy.engine}
    $state.StatusWrittenUtc=(Get-Item -LiteralPath $path -ErrorAction Stop).LastWriteTimeUtc.ToString('o')
  } catch {$state.StatusError=$_.Exception.Message}
  [pscustomobject]$state
}

function Assert-P0RoutingOff($State,[switch]$AssumeRoutingOff) {
  if ($State.RoutesError) {throw "Cannot read Sieve routes: $($State.RoutesError)"}
  if (@($State.Routes).Count) {throw 'Refusing P0: routes exist on the Sieve adapter'}
  if ($State.Status -and ($State.Status.routes_up -or $State.Status.engine)) {throw 'Refusing P0: engine reports routing on'}
  if (($State.StatusError -or -not $State.Status) -and -not $AssumeRoutingOff) {
    throw "Cannot read engine routing state; require -AssumeRoutingOff and controller confirmation: $($State.StatusError)"
  }
}

function Get-P0AdGuardState {
  try {
    $service=Get-Service -Name 'Adguard Service' -ErrorAction Stop
    try {[pscustomobject]@{State=$service.Status.ToString();Error=$null}}
    finally {$service.Dispose()}
  } catch {[pscustomobject]@{State='Unreadable';Error=$_.Exception.Message}}
}

function Build-P0Relay {
  $engine=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\engine'))
  # Explicit target directory keeps CARGO_TARGET_DIR from selecting a host checkout.
  & cargo build --release --manifest-path (Join-Path $engine 'Cargo.toml') --target-dir (Join-Path $engine 'target') -p sieve-engine --example connect_relay | Out-Host
  if ($LASTEXITCODE -ne 0) {throw "connect_relay release build failed: $LASTEXITCODE"}
  return Join-Path $engine 'target\release\examples\connect_relay.exe'
}

function Start-P0Relay([string]$Exe,[int]$Seconds) {
  $p=New-Object Diagnostics.Process
  $p.StartInfo=New-Object Diagnostics.ProcessStartInfo
  $p.StartInfo.FileName=$Exe
  # One workload deadline plus one equally bounded setup/shutdown allowance.
  # Seconds is bounded by the existing budget helper, so this fits the proxy cap.
  $p.StartInfo.Arguments='--port 0 --seconds '+($Seconds*2)
  $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
  $p.StartInfo.RedirectStandardInput=$true;$p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
  $started=$false
  try {
    [void]$p.Start();$started=$true
    $stderr=$p.StandardError.ReadToEndAsync()
    $line=$p.StandardOutput.ReadLineAsync()
    if (-not $line.Wait($Seconds*1000)) {throw 'Relay did not print a port before the setup deadline'}
    $port=0
    if (-not [int]::TryParse($line.Result,[ref]$port) -or $port -lt 1 -or $port -gt [uint16]::MaxValue) {throw 'Invalid relay port line'}
    [pscustomobject]@{Process=$p;Port=$port;Output=$p.StandardOutput.ReadToEndAsync();ErrorOutput=$stderr}
  } catch {
    if ($started -and -not $p.HasExited) {$p.Kill();$p.WaitForExit()}
    $p.Dispose()
    throw
  }
}

function Stop-P0Relay($Relay,[int]$Seconds) {
  $p=$Relay.Process
  try {
    $p.StandardInput.Close()
    $timedOut=-not $p.WaitForExit($Seconds*1000)
    if ($timedOut) {$p.Kill()}
    $p.WaitForExit()
    $raw=$Relay.Output.Result
    $lines=@($raw -split '\r?\n' | Where-Object {$_ -ne ''})
    $summary=$null;$parseError=$null
    try {
      if ($lines.Count -ne 1) {throw 'Expected exactly one final relay JSON line'}
      $summary=$lines[0] | ConvertFrom-Json -ErrorAction Stop
    } catch {$parseError=$_.Exception.Message}
    [pscustomobject]@{Summary=$summary;ExitCode=$p.ExitCode;TimedOut=$timedOut;Raw=$raw;Error=$Relay.ErrorOutput.Result;ParseError=$parseError}
  } finally {
    if (-not $p.HasExited) {$p.Kill();$p.WaitForExit()}
    $p.Dispose()
  }
}

function Assert-P0RelayEvidence($Relay,$Transfer) {
  if (-not $Relay -or $Relay.ExitCode -ne 0 -or $Relay.TimedOut -or $Relay.ParseError -or -not $Relay.Summary) {throw 'Relay exit or JSON evidence is invalid'}
  $s=$Relay.Summary
  foreach($name in @('user_cpu_seconds','kernel_cpu_seconds','bytes_up','bytes_down','tunnels','cancelled_connections','failed_connections','rejected_connections')) {
    $value=$s.$name
    if ($null -eq $value -or $value -is [string] -or $value -is [bool] -or
        [double]::IsNaN([double]$value) -or [double]::IsInfinity([double]$value) -or [double]$value -lt 0) {throw "Invalid relay field: $name"}
  }
  foreach($name in @('bytes_up','bytes_down','tunnels','cancelled_connections','failed_connections','rejected_connections')) {
    if ([decimal]::Truncate([decimal]$s.$name) -ne [decimal]$s.$name) {throw "Non-integral relay field: $name"}
  }
  # TLS and HTTP framing make socket bytes larger than validated body bytes.
  if ($s.tunnels -ne $Transfer.Connections -or $s.bytes_up -le 0 -or $s.bytes_down -lt $Transfer.Bytes -or
      $s.cancelled_connections -ne 0 -or $s.failed_connections -ne 0 -or $s.rejected_connections -ne 0) {throw 'Relay did not complete the validated single tunnel, or served other connections'}
}

function Get-P0Median([double[]]$Values) {
  if (-not $Values.Count) {return $null}
  $sorted=@($Values | Sort-Object)
  $middle=[int][Math]::Floor($sorted.Count/2)
  if ($sorted.Count % 2) {return $sorted[$middle]}
  return ($sorted[$middle-1]+$sorted[$middle])/2
}

function Invoke-P0Sample([string]$Kind,[int]$Iteration,[string]$Exe,$Workload,[switch]$AssumeRoutingOff) {
  $row=[pscustomobject]@{Kind=$Kind;Iteration=$Iteration;Valid=$false;Reason=$null;Mbps=$null;CpuCoresPer100Mbit=$null;Transfer=$null;Relay=$null;Before=$null;After=$null}
  $relay=$null
  try {
    $row.Before=Get-P0RoutingState
    Assert-P0RoutingOff $row.Before -AssumeRoutingOff:$AssumeRoutingOff
    # Not $args: that is PowerShell's automatic variable.
    $transfer=@{};foreach($key in $Workload.Keys){$transfer[$key]=$Workload[$key]}
    if ($Kind -eq 'candidate') {
      $relay=Start-P0Relay -Exe $Exe -Seconds $Workload.Seconds
      $transfer.Proxy='http://127.0.0.1:'+$relay.Port
    }
    # Before/after snapshots miss routing that turns on and off mid-transfer,
    # so watch throughout and latch any sighting.
    $watch=@{Seen=$null}
    $transfer.WhileRunning={
      try {Assert-P0RoutingOff (Get-P0RoutingState) -AssumeRoutingOff:$AssumeRoutingOff}
      catch {if(-not $watch.Seen){$watch.Seen=$_.Exception.Message}}
    }
    try {$row.Transfer=Invoke-SieveBudgetTransfer @transfer}
    finally {
      if ($relay) {
        $stopping=$relay;$relay=$null
        $row.Relay=Stop-P0Relay $stopping -Seconds $Workload.Seconds
      }
    }
    $row.After=Get-P0RoutingState
    Assert-P0RoutingOff $row.After -AssumeRoutingOff:$AssumeRoutingOff
    if ($watch.Seen) {throw "Routing changed during the transfer: $($watch.Seen)"}
    if (-not $row.Transfer.Valid -or $row.Transfer.Seconds -le 0) {throw 'Invalid workload; no performance score'}
    if ($Kind -eq 'candidate') {Assert-P0RelayEvidence $row.Relay $row.Transfer}
    # Same application-byte normalization as run-slice-3-auto.ps1's budget:
    # bits = bytes * 8, decimal Mbit = bits / 10^6, cores = CPU seconds / wall.
    $mbps=[double]$row.Transfer.Bytes*8/$row.Transfer.Seconds/1e6
    if ($Kind -eq 'candidate') {
      $cpu=$row.Relay.Summary.user_cpu_seconds+$row.Relay.Summary.kernel_cpu_seconds
      $row.CpuCoresPer100Mbit=($cpu/$row.Transfer.Seconds)/($mbps/100)
    }
    $row.Mbps=$mbps;$row.Valid=$true
  } catch {$row.Reason=$_.Exception.Message}
  finally {if($relay){$row.Relay=Stop-P0Relay $relay -Seconds $Workload.Seconds}}
  return $row
}

function Get-P0Comparison($Rows,[int]$Runs) {
  $baseline=@($Rows | Where-Object {$_.Kind -eq 'baseline' -and $_.Valid})
  $candidate=@($Rows | Where-Object {$_.Kind -eq 'candidate' -and $_.Valid})
  $direct=Get-P0Median @($baseline | ForEach-Object {$_.Mbps})
  $proxied=Get-P0Median @($candidate | ForEach-Object {$_.Mbps})
  $cpu=Get-P0Median @($candidate | ForEach-Object {$_.CpuCoresPer100Mbit})
  $ratio=$null;$pass=$null
  if ($direct -gt 0 -and $null -ne $proxied) {$ratio=$proxied/$direct}
  $complete=$baseline.Count -eq $Runs -and $candidate.Count -eq $Runs
  # P0 acceptance limits are specified by the approved research note's Prototype.
  $cpuLimit=0.05;$throughputTolerance=10/100
  if ($complete) {$pass=$cpu -le $cpuLimit -and [Math]::Abs($ratio-1) -le $throughputTolerance}
  [pscustomobject]@{Complete=$complete;Pass=$pass;ValidBaselineRuns=$baseline.Count;ValidCandidateRuns=$candidate.Count;BaselineMedianMbps=$direct;CandidateMedianMbps=$proxied;MedianCpuCoresPer100Mbit=$cpu;ThroughputRatio=$ratio;CpuLimit=$cpuLimit;ThroughputTolerance=$throughputTolerance}
}

function New-P0EvidenceDirectory {
  $root='C:\Users\Public\sieve-engine-live'
  $path=Join-Path $root ('p0-relay-floor-'+(Get-Date -Format 'yyyyMMddTHHmmss')+'-'+[guid]::NewGuid().ToString('N'))
  [void][IO.Directory]::CreateDirectory($path)
  return $path
}

function Write-P0Evidence([string]$Directory,$Evidence) {
  [IO.File]::WriteAllText((Join-Path $Directory 'evidence.json'),($Evidence | ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($false)))
}

function Invoke-SieveP0([int]$Runs=3,[int]$PauseSeconds=300,[int]$Seconds=60,[string]$Url='',[int]$Count=12,[long]$Size=25000000,[switch]$AssumeRoutingOff,[switch]$DryRun) {
  # Defaults and pause are the approved P0/C0 protocol, not inferred tuning.
  if ($Runs -lt 1 -or $PauseSeconds -lt 0) {throw 'Runs must be positive and PauseSeconds nonnegative'}
  [void](Get-SieveBudgetArguments -Seconds $Seconds -Url $Url -Count $Count -Size $Size)
  if (-not $Url) {$Url='https://speed.cloudflare.com/__down?bytes='+$Size}
  if ([uri]$Url -and ([uri]$Url).Scheme -ne 'https') {throw 'P0 requires HTTPS so curl uses CONNECT'}
  if ($DryRun) {
    Write-Host "PLAN ONLY: unelevated; take live lease; refuse Sieve routes or engine routing on. Unreadable status requires -AssumeRoutingOff (requested=$AssumeRoutingOff)."
    Write-Host "Read AdGuard start/end without changing it; cargo build --release -p sieve-engine --example connect_relay."
    Write-Host "Alternate baseline then candidate, $Runs runs each; $PauseSeconds seconds between all runs; curl deadline $Seconds seconds; $Count responses of $Size bytes from $Url."
    Write-Host 'Candidate uses only explicit curl -x to an ephemeral loopback port. Close relay stdin after curl; reject invalid workload or relay evidence.'
    Write-Host 'Score valid-run medians against P0 limits; incomplete sets cannot pass. Write timestamped evidence.json under C:\Users\Public\sieve-engine-live. No state read, lease, build, process, sleep or file write in DryRun.'
    return
  }
  Assert-P0Unelevated
  $lease=$null;$directory=$null
  $evidence=[ordered]@{StartedUtc=[datetime]::UtcNow.ToString('o');EndedUtc=$null;AssumeRoutingOff=[bool]$AssumeRoutingOff;Runs=$Runs;PauseSeconds=$PauseSeconds;Workload=@{Seconds=$Seconds;Url=$Url;Count=$Count;Size=$Size};AdGuardStart=$null;AdGuardEnd=$null;Preflight=$null;Rows=@();Comparison=$null;Error=$null}
  try {
    $lease=Enter-SieveLiveLease -Path 'C:\Users\Public\sieve-engine-live\runner.lock'
    $directory=New-P0EvidenceDirectory
    $evidence.AdGuardStart=Get-P0AdGuardState
    $evidence.Preflight=Get-P0RoutingState
    Assert-P0RoutingOff $evidence.Preflight -AssumeRoutingOff:$AssumeRoutingOff
    $exe=Build-P0Relay
    for($iteration=1;$iteration -le $Runs;$iteration++) {
      foreach($kind in @('baseline','candidate')) {
        if ($evidence.Rows.Count) {Start-Sleep -Seconds $PauseSeconds}
        $row=Invoke-P0Sample -Kind $kind -Iteration $iteration -Exe $exe -Workload $evidence.Workload -AssumeRoutingOff:$AssumeRoutingOff
        $evidence.Rows+= $row
        Write-Host "$kind $iteration valid=$($row.Valid) Mbps=$($row.Mbps) cores/100Mbit=$($row.CpuCoresPer100Mbit) $($row.Reason)"
        Write-P0Evidence $directory $evidence
        # A routing change aborts further traffic, even when an assumption was given.
        if ($row.After) {Assert-P0RoutingOff $row.After -AssumeRoutingOff:$AssumeRoutingOff}
        if ($row.Before) {Assert-P0RoutingOff $row.Before -AssumeRoutingOff:$AssumeRoutingOff}
      }
    }
  } catch {$evidence.Error=$_.Exception.Message;throw}
  finally {
    try {
      if ($directory) {
        $evidence.AdGuardEnd=Get-P0AdGuardState
        $evidence.EndedUtc=[datetime]::UtcNow.ToString('o')
        $evidence.Comparison=Get-P0Comparison $evidence.Rows $Runs
        Write-P0Evidence $directory $evidence
        Write-Host "P0 complete=$($evidence.Comparison.Complete) pass=$($evidence.Comparison.Pass); direct median=$($evidence.Comparison.BaselineMedianMbps) Mbps; relay median=$($evidence.Comparison.CandidateMedianMbps) Mbps; CPU median=$($evidence.Comparison.MedianCpuCoresPer100Mbit) cores/100Mbit. Evidence: $directory"
      }
    } finally {Exit-SieveLiveLease $lease}
  }
  [pscustomobject]$evidence
}

# Dot sourcing loads definitions for contract tests without executing the runner.
if ($MyInvocation.InvocationName -ne '.') {Invoke-SieveP0 @PSBoundParameters}
