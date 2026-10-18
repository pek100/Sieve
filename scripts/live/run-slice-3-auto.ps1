<#
.SYNOPSIS
  Unattended slice 3 check for a person in Terminal (Admin). No installer or prompts.
  Agents may run -DryRun only. See docs/live/engine-slice-3.md.
#>
param(
  # The slice 3 acceptance soak is half an hour (engine-route.ps1).
  [ValidateScript({ $_ -gt 0 -and -not [double]::IsInfinity($_) })]
  [double]$SoakMinutes = 30,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$Service = "sieve-engine"
$Adguard = "Adguard Service"
$EngineDir = Join-Path $env:ProgramData "Sieve\engine"
$PolicyFile = Join-Path $EngineDir "policy.json"
$StatusFile = Join-Path $EngineDir "status.json"
$Out = Join-Path $env:PUBLIC "sieve-engine-live"
$Results = Join-Path $Out "results-route.txt"
$StallBuild = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\engine\target\stall\release\sieve-engine.exe"))
$Utf8 = New-Object Text.UTF8Encoding($false)
# User-requested polling, close grace, and short HTTPS timeout respectively.
$PollMs = 250
$CloseSeconds = 60
$CurlSeconds = 3
# Existing live check limits, not new acceptance thresholds.
$RouteSeconds = 30
$AdguardSeconds = 90
$KillSeconds = 5
$BudgetSeconds = 60
$AttributionMinimum = 0.95
$IdleCpuMaximum = 0.01
$RelayCpuMaximum = 0.15
$MemoryMaximum = 300MB
$DownloadBytes = 300000000
$ReferenceMbps = 100
# service::STOP_WAIT, control::STATUS_FILE_EVERY_MS, and routing::STALL_AFTER.
$StopSeconds = 20
$StatusSeconds = 30
$StallSeconds = 30
# watchdog::STALL_MS and CHECK_EVERY_MS, converted to seconds.
$WatchdogSeconds = 5
$WatchdogPollSeconds = 1
$Target = "https://www.cloudflare.com"
# What to do by hand when AdGuard's service hangs between states (live 2026-10-18 19:55:
# it sat in StopPending for over 10 minutes). The runner never kills AdGuard's process itself.
$AdguardRecovery = "AdGuard's service is stuck; this is AdGuard, not Sieve. In Terminal (Admin): taskkill /F /IM AdguardSvc.exe ; Start-Service 'Adguard Service' (or reboot)."
$script:Failed = 0
$script:Rows = New-Object 'System.Collections.Generic.List[object]'
$script:Step = "preflight"
$script:Logging = $false
$script:Changed = $false
$script:AdguardWasRunning = $false
$script:OriginalBackup = $null
$script:EngineExe = $null
$script:Revision = [decimal]0
$script:Cleaning = $false
$script:EvidenceDir = $null
$script:LiveLease = $null

function Log([string]$text) {
  Write-Host $text
  if ($script:Logging) {
    try { [IO.File]::AppendAllText($Results, "$text`r`n", $Utf8) }
    catch {
      # A full/unwritable evidence drive must not interrupt the finally recovery.
      $script:Logging = $false
      $script:Failed++
      Write-Host "FAIL  results logging stopped: $($_.Exception.Message)" -ForegroundColor Red
    }
  }
}

function Record([string]$result, [string]$name, [string]$detail) {
  if ($result -eq "FAIL") { $script:Failed++ }
  $script:Rows.Add([pscustomobject]@{ Step = $script:Step; Result = $result; Check = $name })
  Log ("{0,-4}  {1}  ({2}: {3})" -f $result, $name, $script:Step, $detail)
}

function Check([string]$name, [bool]$ok, [string]$detail = "") {
  Record $(if ($ok) { "PASS" } else { "FAIL" }) $name $detail
}

function Require([string]$name, [bool]$ok, [string]$detail = "") {
  if (-not $ok) { throw "$name`: $detail" }
  Check $name $true $detail
}

function Save([string]$name, [string]$text) {
  [IO.File]::WriteAllText((Join-Path $script:EvidenceDir $name), $text, $Utf8)
}

function Assert-AppClosed {
  if (@(Get-Process -Name sieve -ErrorAction SilentlyContinue).Count) {
    throw "sieve.exe is running. Keep Sieve closed: its controller overwrites the test policy."
  }
}

function Wait-For([scriptblock]$condition, [double]$seconds) {
  $clock = [Diagnostics.Stopwatch]::StartNew()
  do {
    if (-not $script:Cleaning) { Assert-AppClosed }
    if (& $condition) { return $true }
    Start-Sleep -Milliseconds $PollMs
  } while ($clock.Elapsed.TotalSeconds -lt $seconds)
  return $false
}

function Service-State([string]$name, [string]$state, [double]$seconds) {
  $hint = if ($name -eq $Adguard) { " $AdguardRecovery" } else { "" }
  # A service between states rejects controls (1061) or answers misleadingly: a start sent
  # to a StopPending service returned 1056 "already running" at 19:55 and cleanup gave up.
  # Let any Pending state settle first.
  if (-not (Wait-For { (Get-Service -Name $name).Status.ToString() -notlike '*Pending' } $seconds)) {
    throw "'$name' is stuck in $((Get-Service -Name $name).Status) (not settled within $seconds s).$hint"
  }
  if ((Get-Service -Name $name).Status.ToString() -eq $state) { return }
  $verb = if ($state -eq "Running") { "start" } else { "stop" }
  $output = & sc.exe $verb $name
  $code = $LASTEXITCODE
  Log ("sc.exe {0} '{1}': exit {2}; {3}" -f $verb, $name, $code, ($output -join " "))
  # 1056 ERROR_SERVICE_ALREADY_RUNNING on start and 1062 ERROR_SERVICE_NOT_ACTIVE on stop
  # mean the service reached the wanted state by itself between the read and the control.
  $already = ($verb -eq "start" -and $code -eq 1056) -or ($verb -eq "stop" -and $code -eq 1062)
  if ($code -ne 0 -and -not $already) { throw "sc.exe $verb '$name' failed: $code.$hint" }
  if (-not (Wait-For { (Get-Service -Name $name).Status.ToString() -eq $state } $seconds)) {
    throw "'$name' did not become $state within $seconds seconds (now $((Get-Service -Name $name).Status)).$hint"
  }
}

function Read-Status {
  if (-not (Test-Path -LiteralPath $StatusFile)) { return $null }
  # Engine uses atomic rename; a malformed or unreadable present file is an error.
  Get-Content -LiteralPath $StatusFile -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Policy-Revision($policy) {
  # Decimal preserves every u64 value in Windows PowerShell's JSON reader.
  $r = [decimal]$policy.revision
  if ($null -eq $policy.revision -or $policy.engine -isnot [bool] -or
      $r -lt 0 -or $r -gt [decimal][uint64]::MaxValue -or [decimal]::Truncate($r) -ne $r) {
    throw "Invalid policy: expected {revision: u64, engine: boolean}"
  }
  return $r
}

function Write-Policy([bool]$on) {
  # Caller stops the service first: no competing writer or stale in-memory policy.
  $revision = $script:Revision
  if (Test-Path -LiteralPath $PolicyFile) {
    $disk = Policy-Revision (Get-Content -LiteralPath $PolicyFile -Raw -Encoding UTF8 | ConvertFrom-Json)
    $revision = [Math]::Max($revision, $disk)
  }
  $status = Read-Status
  if ($status) { $revision = [Math]::Max($revision, (Policy-Revision $status.policy)) }
  if ($revision -ge [decimal][uint64]::MaxValue) { throw "Policy revision exhausted" }
  # accept() requires strictly increasing revisions; successor is the smallest valid one.
  $revision++
  $json = '{"revision":' + $revision.ToString([Globalization.CultureInfo]::InvariantCulture) +
    ',"engine":' + $on.ToString().ToLowerInvariant() + '}'
  $tmp = "$PolicyFile.auto-$([guid]::NewGuid().ToString('N')).tmp"
  try {
    [IO.File]::WriteAllText($tmp, $json, $Utf8)
    # NullString avoids PowerShell 5.1 converting $null to an invalid empty backup path.
    if (Test-Path -LiteralPath $PolicyFile) { [IO.File]::Replace($tmp, $PolicyFile, [NullString]::Value) }
    else { [IO.File]::Move($tmp, $PolicyFile) }
  } finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp }
  }
  $script:Revision = $revision
  Log "policy.json = $json (service stopped, atomic UTF-8 without BOM)"
}

function Set-Routing([bool]$on) {
  Assert-AppClosed
  $script:Changed = $true
  Service-State $Service "Stopped" $StopSeconds
  Write-Policy $on
  Service-State $Service "Running" $StopSeconds
  Require "engine loaded this policy revision" (Wait-For {
    $s = Read-Status
    $s -and (Policy-Revision $s.policy) -eq $script:Revision -and $s.policy.engine -eq $on
  } $RouteSeconds) "revision $script:Revision, engine $on"
}

function Sieve-Routes { @(Get-NetRoute | Where-Object InterfaceAlias -eq "Sieve") }
function Sieve-Adapters { @(Get-NetAdapter -IncludeHidden | Where-Object Name -eq "Sieve") }
function Engine-Pid { (Get-CimInstance Win32_Service -Filter "Name='sieve-engine'").ProcessId }

# Windows can report its three IPv6 fallback addresses on an interface with
# no configured resolver. Keep both the reported addresses and the read-only
# registry evidence; never classify an unreadable snapshot as unconfigured.
function Adapter-DnsEvidence {
  $evidence = [ordered]@{ Rows = @(); Registry = @(); Error = $null }
  try {
    $adapter = @(Sieve-Adapters)
    if ($adapter.Count -ne 1) { throw "Expected one Sieve adapter" }
    $guid = ([guid]$adapter[0].InterfaceGuid).ToString('B')
    $evidence.Rows = @(Get-DnsClientServerAddress -InterfaceIndex $adapter[0].ifIndex |
      Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses)
    $evidence.Registry = @(foreach ($family in 'Tcpip', 'Tcpip6') {
      $path = "SYSTEM\CurrentControlSet\Services\$family\Parameters\Interfaces\$guid"
      $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $false)
      try {
        [pscustomobject]@{
          Family = $family; Path = $path; KeyExists = ($null -ne $key)
          NameServer = $(if ($key) { $key.GetValue('NameServer', $null) } else { $null })
          DhcpNameServer = $(if ($key) { $key.GetValue('DhcpNameServer', $null) } else { $null })
          Dhcpv6DNSServers = $(if ($key) { $key.GetValue('Dhcpv6DNSServers', $null) } else { $null })
        }
      } finally { if ($key) { $key.Dispose() } }
    })
  } catch { $evidence.Error = $_.Exception.Message }
  [pscustomobject]$evidence
}

function Adapter-DnsUnconfigured($evidence) {
  if ($evidence.Error -or @($evidence.Rows).Count -eq 0 -or @($evidence.Registry).Count -ne 2) { return $false }
  if (@(Compare-Object @('Tcpip', 'Tcpip6') @($evidence.Registry | ForEach-Object Family)).Count) { return $false }
  foreach ($entry in $evidence.Registry) {
    foreach ($value in @($entry.NameServer) + @($entry.DhcpNameServer) + @($entry.Dhcpv6DNSServers)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$value)) { return $false }
    }
  }
  $defaults = @('fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3')
  foreach ($row in $evidence.Rows) {
    if ($row.AddressFamily -notin @(2, 23)) { return $false }
    $addresses = @($row.ServerAddresses | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if (-not $addresses.Count) { continue }
    if ($row.AddressFamily -ne 23 -or $addresses.Count -ne 3) { return $false }
    try { $canonical = @($addresses | ForEach-Object { ([Net.IPAddress]$_).ToString() }) }
    catch { return $false }
    if (@(Compare-Object $defaults $canonical).Count) { return $false }
  }
  return $true
}

function Require-Routing {
  Require "routes on the Sieve adapter" (Wait-For {
    $s = Read-Status
    if ($s -and $s.blocker.kind -eq "crash_loop") {
      throw "Crash-loop stop: runs.json is preserved. Use the installed app's off/on recovery separately, then close it."
    }
    $engineProcess = Get-Process -Id (Engine-Pid)
    try {
      $s -and $s.routes_up -and $s.policy.engine -and
        (Policy-Revision $s.policy) -eq $script:Revision -and @(Sieve-Routes).Count -gt 0 -and
        (Get-Item $StatusFile).LastWriteTimeUtc -ge $engineProcess.StartTime.ToUniversalTime()
    } finally { $engineProcess.Dispose() }
  } $RouteSeconds) ((Read-Status | ConvertTo-Json -Compress) + "")
}

function Listings {
  $routes = Get-NetRoute | Where-Object InterfaceAlias -ne "Sieve" |
    Sort-Object AddressFamily, DestinationPrefix, InterfaceAlias, NextHop |
    ForEach-Object { "$($_.DestinationPrefix) via $($_.NextHop) on $($_.InterfaceAlias)" }
  $persistent = Get-NetRoute -PolicyStore PersistentStore |
    Sort-Object DestinationPrefix |
    ForEach-Object { "$($_.DestinationPrefix) via $($_.NextHop) on $($_.InterfaceAlias)" }
  $dns = Get-DnsClientServerAddress | Where-Object InterfaceAlias -ne "Sieve" |
    Sort-Object InterfaceAlias, AddressFamily |
    ForEach-Object { "$($_.InterfaceAlias) $($_.AddressFamily): $($_.ServerAddresses -join ',')" }
  $proxy = & netsh.exe winhttp show proxy
  if ($LASTEXITCODE -ne 0) { throw "netsh winhttp show proxy failed" }
  $firewall = Get-NetFirewallRule -PolicyStore ActiveStore | Sort-Object Name | ForEach-Object Name
  [ordered]@{ routes = $routes -join "`n"; persistent = $persistent -join "`n";
    dns = $dns -join "`n"; proxy = $proxy -join "`n"; firewall = $firewall -join "`n" }
}

function Save-Listings([string]$tag) {
  $l = Listings
  foreach ($key in $l.Keys) { Save "route-$tag-$key.txt" $l[$key] }
  return $l
}

function Compare-Listings([string]$tag) {
  $now = Save-Listings $tag
  foreach ($key in $script:Before.Keys) {
    Check "$key listing matches the before-listing ($tag)" ($now[$key] -eq $script:Before[$key]) "see route-$tag-$key.txt"
  }
}

function Start-Probe {
  $p = New-Object Diagnostics.Process
  $p.StartInfo = New-Object Diagnostics.ProcessStartInfo
  $p.StartInfo.FileName = "curl.exe"
  # A new direct curl resolves the target itself, then verifies TLS and HTTP. No proxy DNS.
  $p.StartInfo.Arguments = '-sS --noproxy "*" -I ' + $Target + ' -m ' + $CurlSeconds +
    ' -o NUL -w "%{http_code} %{remote_ip} %{time_namelookup}"'
  $p.StartInfo.UseShellExecute = $false
  $p.StartInfo.CreateNoWindow = $true
  $p.StartInfo.RedirectStandardOutput = $true
  $p.StartInfo.RedirectStandardError = $true
  try {
    [void]$p.Start()
    [pscustomobject]@{ Process = $p; Output = $p.StandardOutput.ReadToEndAsync(); Error = $p.StandardError.ReadToEndAsync() }
  } catch { $p.Dispose(); throw }
}

function Close-Probe($probe) {
  try {
    if (-not $probe.Process.HasExited) { $probe.Process.Kill() }
    $probe.Process.WaitForExit()
  } finally { $probe.Process.Dispose() }
}

function Network-Until([Diagnostics.Stopwatch]$clock, [double]$seconds) {
  $pending = New-Object 'System.Collections.Generic.List[object]'
  $success = $false
  $first = $null
  $detail = ""
  try {
    # First launch at t=0, then one per requested polling tick. Requests overlap so
    # a slow timeout cannot postpone discovering recovery. Every child is reaped.
    do {
      $pending.Add((Start-Probe))
      for ($i = $pending.Count - 1; $i -ge 0; $i--) {
        $q = $pending[$i]
        if (-not $q.Process.HasExited) { continue }
        $text = $q.Output.Result.Trim()
        $detail = "exit $($q.Process.ExitCode), $text, $($q.Error.Result.Trim())"
        # HTTP success plus remote address proves the same request resolved and connected.
        if ($q.Process.ExitCode -eq 0 -and $text -match '\A[23][0-9]{2}\s+\S+\s+[0-9.]+\z') {
          $success = $true
          $first = $clock.Elapsed.TotalSeconds
          break
        }
        Log "lookup + HTTPS attempt: $detail"
        Close-Probe $q
        $pending.RemoveAt($i)
      }
      if ($success) { break }
      Start-Sleep -Milliseconds $PollMs
    } while ($clock.Elapsed.TotalSeconds -lt $seconds)
  } finally {
    foreach ($q in $pending) {
      try { Close-Probe $q }
      catch { Record "FAIL" "probe process cleanup" $_.Exception.Message }
    }
  }
  [pscustomobject]@{ Ok = $success; Seconds = $first; Detail = "$Target; $detail" }
}

function Check-Network([string]$tag) {
  $n = Network-Until ([Diagnostics.Stopwatch]::StartNew()) ($KillSeconds + $CurlSeconds)
  Check "lookup plus HTTPS works ($tag)" $n.Ok $n.Detail
}

function Counter-Delta($baseline, $current) {
  $delta = [ordered]@{}
  foreach ($p in $baseline.PSObject.Properties) {
    $value = [decimal]$current.($p.Name) - [decimal]$p.Value
    if ($null -eq $current.($p.Name) -or $value -lt 0) { throw "Counter reset or missing: $($p.Name)" }
    $delta[$p.Name] = $value
  }
  return [pscustomobject]$delta
}

function Restore-Binary {
  if ($script:OriginalBackup) {
    Service-State $Service "Stopped" $StopSeconds
    Copy-Item -LiteralPath $script:OriginalBackup -Destination $script:EngineExe -Force
    Require "normal engine binary restored" ((Get-FileHash $script:EngineExe).Hash -eq $script:OriginalHash) $script:EngineExe
    Remove-Item -LiteralPath $script:OriginalBackup
    $script:OriginalBackup = $null
  }
}

function Restore-State {
  $script:Cleaning = $true
  $script:Step = "finally"
  if ($script:Changed) {
    # Independent attempts: a policy/binary failure must never suppress AdGuard recovery.
    $offWritten = $false
    try {
      Service-State $Service "Stopped" $StopSeconds
      Write-Policy $false
      $offWritten = $true
    } catch { Record "FAIL" "routing OFF cleanup" $_.Exception.Message }
    try { Restore-Binary } catch { Record "FAIL" "normal binary cleanup" $_.Exception.Message }
    try {
      # Do not restart an on-policy or un-restored Stall binary after a cleanup failure.
      if ($offWritten -and -not $script:OriginalBackup) {
        # A reopened UI would immediately undo OFF. Leave the service stopped in that case.
        Assert-AppClosed
        Service-State $Service "Running" $StopSeconds
        Require "routing OFF after cleanup" (Wait-For {
          $s = Read-Status
          $s -and -not $s.policy.engine -and -not $s.routes_up -and
            (Policy-Revision $s.policy) -eq $script:Revision -and @(Sieve-Routes).Count -eq 0
        } $RouteSeconds) "fresh status and route table"
      }
    } catch { Record "FAIL" "engine cleanup verification" $_.Exception.Message }
  }
  if ($script:AdguardWasRunning) {
    try {
      Service-State $Adguard "Running" $AdguardSeconds
      Check "AdGuard restored to RUNNING" $true "was running at preflight"
    } catch { Record "FAIL" "AdGuard cleanup" $_.Exception.Message }
  }
}

function Step([string]$name, [string]$plan, [scriptblock]$action) {
  $script:Step = $name
  if ($DryRun) { Log "PLAN $name`: $plan"; return }
  Log "=== $name ==="
  & $action
}

function Run-Auto {
  Step "preflight" "Assert admin; request sieve.exe close, wait up to $CloseSeconds s, refuse if still open; require running sieve-engine; record AdGuard state, runs.json and service image. Append AUTO header to $Results; save evidence in a unique run directory." {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run from Terminal (Admin), or use -DryRun unelevated." }
    . (Join-Path $PSScriptRoot 'live-lease.ps1')
    $script:LiveLease = Enter-SieveLiveLease
    foreach ($app in @(Get-Process -Name sieve -ErrorAction SilentlyContinue)) {
      Log "Requesting sieve.exe PID $($app.Id) to close. Keep Sieve closed until the summary."
      [void]$app.CloseMainWindow()
    }
    $closeClock = [Diagnostics.Stopwatch]::StartNew()
    while (@(Get-Process -Name sieve -ErrorAction SilentlyContinue).Count -and $closeClock.Elapsed.TotalSeconds -lt $CloseSeconds) {
      Start-Sleep -Milliseconds $PollMs
    }
    Assert-AppClosed
    if ((Get-Service $Service).Status -ne "Running") { throw "Installed sieve-engine service must already be running." }
    $script:AdguardWasRunning = (Get-Service $Adguard -ErrorAction SilentlyContinue).Status -eq "Running"
    $image = (Get-CimInstance Win32_Service -Filter "Name='sieve-engine'").PathName.Trim()
    # The installed service has no arguments. Anchors handle CRLF explicitly via Trim().
    if ($image -match '\A"([^"\r\n]+\.exe)"\z') { $script:EngineExe = $Matches[1] }
    elseif ($image -match '\A[^"\r\n]+\.exe\z') { $script:EngineExe = $image }
    else { throw "Unexpected service ImagePath: $image" }
    $id = (Get-Date -Format "yyyyMMddTHHmmss") + "-" + [guid]::NewGuid().ToString("N")
    $script:EvidenceDir = Join-Path $Out "auto-$id"
    [void](New-Item -ItemType Directory -Path $script:EvidenceDir -Force)
    $script:Logging = $true
    Log "==== AUTO $id as $([Security.Principal.WindowsIdentity]::GetCurrent().Name); evidence $script:EvidenceDir"
    Save "runs-before.json" (Get-Content -LiteralPath (Join-Path $EngineDir "runs.json") -Raw -Encoding UTF8)
    Log "Installed engine: $script:EngineExe; AdGuard initially running: $script:AdguardWasRunning"
  }
  Step "before" "Stop engine, atomically write the successor policy revision with engine=false, start and verify it; save routes/DNS/proxy/firewall, check no Sieve adapter/routes and lookup plus HTTPS ($Target)." {
    Set-Routing $false
    $script:Before = Save-Listings "before"
    Check "no adapter named Sieve before routing" (@(Sieve-Adapters).Count -eq 0)
    Require "no route on an interface named Sieve before routing" (@(Sieve-Routes).Count -eq 0)
    Check-Network "before"
  }
  Step "adguard" "Set policy ON through stop/write/start; while AdGuard runs verify blocker=adguard and no routes, then sc.exe stop 'Adguard Service'; wait for routing. If initially stopped/absent, SKIP refusal and leave it stopped/absent." {
    Set-Routing $true
    if ($script:AdguardWasRunning) {
      Require "the engine refuses while AdGuard runs (blocker adguard)" (Wait-For {
        $s = Read-Status
        $s -and $s.blocker.kind -eq "adguard" -and -not $s.routes_up
      } $RouteSeconds) "status.json"
      Save "route-adguard-status.json" (Read-Status | ConvertTo-Json)
      Require "no route on Sieve while AdGuard runs" (@(Sieve-Routes).Count -eq 0)
      Service-State $Adguard "Stopped" $AdguardSeconds
      Check "pausing AdGuard stops its service" $true "sc.exe stop"
    } else { Record "SKIP" "AdGuard refusal and pause" "Adguard Service was not running at preflight" }
    Require-Routing
  }
  Step "on" "Verify routing/status and unchanged listings, no persistent Sieve routes or adapter DNS; check direct HTTPS and LAN HTTP; save THIS run's counter/PID baseline. UI checks: SKIP (UI, covered by e2e: tests/e2e/engine.spec.ts)." {
    Require-Routing
    $s = Read-Status
    $script:Baseline = $s.counters
    $script:BaselinePid = Engine-Pid
    $script:SoakClock = [Diagnostics.Stopwatch]::StartNew()
    Save "route-on-status.json" ($s | ConvertTo-Json)
    Save "route-on-sieve-routes.txt" ((Sieve-Routes | Format-Table -AutoSize | Out-String).Trim())
    Check "no Sieve route in the persistent store" (@(Get-NetRoute -PolicyStore PersistentStore | Where-Object InterfaceAlias -eq "Sieve").Count -eq 0)
    $adapterDns = Adapter-DnsEvidence
    Save "route-on-sieve-dns.json" ($adapterDns | ConvertTo-Json -Depth 5)
    Check "no DNS server set on the Sieve adapter" (Adapter-DnsUnconfigured $adapterDns) "addresses and explicit/DHCP registry values: route-on-sieve-dns.json; error: $($adapterDns.Error)"
    Compare-Listings "on"
    Check-Network "on"
    $gateway = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object InterfaceAlias -ne "Sieve" | Sort-Object RouteMetric | Select-Object -First 1
    if ($gateway) {
      $http = & curl.exe -s --noproxy '*' -I "http://$($gateway.NextHop)/" -m $CurlSeconds -o NUL -w '%{http_code}'
      Check "LAN router UI reachable" ($LASTEXITCODE -eq 0 -and $http -match '\A[1-5][0-9]{2}\z') "HTTP $($gateway.NextHop): $http; page rendering not observed"
    } else { Record "SKIP" "LAN router UI reachable" "no IPv4 default gateway" }
    foreach ($name in @("the app shows the AdGuard refusal", "the app offers to pause AdGuard", "the app says Routing traffic")) {
      Record "SKIP" $name "UI, covered by e2e: tests/e2e/engine.spec.ts (fixtures; not live UI evidence)"
    }
  }
  Step "soak" "Countdown for $SoakMinutes minutes of normal PC use; each minute log counters and check same PID/revision, fresh routing status and HTTPS; compute counter deltas from on. UI: SKIP (UI, covered by e2e: tests/e2e/home.spec.ts, tests/e2e/apps.spec.ts)." {
    $duration = [TimeSpan]::FromMinutes($SoakMinutes).TotalSeconds
    do {
      Assert-AppClosed
      Require "same engine process throughout soak" ((Engine-Pid) -eq $script:BaselinePid) "counter baseline belongs to this process"
      $s = Read-Status
      Require "routing stays on during sampled soak" ($s -and $s.routes_up -and $s.policy.engine -and (Policy-Revision $s.policy) -eq $script:Revision) "status.json"
      Check "status counters are fresh" (((Get-Date).ToUniversalTime() - (Get-Item $StatusFile).LastWriteTimeUtc).TotalSeconds -le ($StatusSeconds + $WatchdogPollSeconds)) "status publication period plus one watchdog tick"
      $remaining = [Math]::Max(0, $duration - $script:SoakClock.Elapsed.TotalSeconds)
      Log ("Soak remaining {0}; counters {1}" -f ([TimeSpan]::FromSeconds($remaining).ToString('hh\:mm\:ss')), ($s.counters | ConvertTo-Json -Compress))
      Check-Network "soak"
      if ($remaining -le 0) { break }
      # One minute is the requested report cadence; short overrides end on their deadline.
      $minute = [TimeSpan]::FromMinutes(1).TotalSeconds
      $next = [Math]::Min($duration, ([Math]::Floor($script:SoakClock.Elapsed.TotalSeconds / $minute) + 1) * $minute)
      while ($script:SoakClock.Elapsed.TotalSeconds -lt $next) { Assert-AppClosed; Start-Sleep -Milliseconds $PollMs }
    } while ($true)
    $delta = Counter-Delta $script:Baseline $s.counters
    Save "route-soak-status.json" ($s | ConvertTo-Json)
    Save "route-soak-deltas.json" ($delta | ConvertTo-Json)
    $rate = if ($delta.flows -gt 0) { $delta.attributed / $delta.flows } else { 0 }
    Check "attribution of at least 0.95 from the engine's counters" ($delta.flows -gt 0 -and $rate -ge $AttributionMinimum) "$($delta.attributed) / $($delta.flows) since on = $rate"
    Check "the engine refused none of its own flows" ($delta.own_refused -eq 0) "delta $($delta.own_refused)"
    Check "DNS was answered on the TUN" ($delta.dns_answers -gt 0) "delta $($delta.dns_answers)"
    Record "SKIP" "30 minutes of normal use without a failure" "sampled engine/network checks cannot certify a person's video call or game launcher"
    Record "SKIP" "Home and Apps show the apps you used" "UI, covered by e2e: tests/e2e/home.spec.ts, tests/e2e/apps.spec.ts (fixtures only)"
    Compare-Listings "soak"
  }
  Step "kill" "Kill only the service PID; start lookup+HTTPS probes immediately, every $PollMs ms, each timeout $CurlSeconds s, target $Target. Record FIRST success against the existing $KillSeconds s bound; verify routes/adapter removed and SCM recovery." {
    Require-Routing
    $enginePid = Engine-Pid
    Require "service PID exists before kill" ($enginePid -gt 0) "PID $enginePid"
    $clock = [Diagnostics.Stopwatch]::StartNew()
    Stop-Process -Id $enginePid -Force
    $n = Network-Until $clock ($KillSeconds + $CurlSeconds)
    Check "network checked within 5 s of the kill" ($n.Ok -and $n.Seconds -le $KillSeconds) "first successful lookup + HTTPS observed at $($n.Seconds) s; $($n.Detail); includes kill call, no initial sleep"
    Check "no route on an interface named Sieve after the kill" (@(Sieve-Routes).Count -eq 0) "sample after first success, before slow listings"
    Check "the Sieve adapter is gone after the kill" (@(Sieve-Adapters).Count -eq 0)
    Require "the service manager restarted the engine" (Wait-For {
      (Get-Service $Service).Status -eq "Running" -and (Engine-Pid) -gt 0 -and (Engine-Pid) -ne $enginePid
    } $StopSeconds) "new PID, no manual start"
    Require-Routing
    Compare-Listings "kill"
  }
  Step "stall" "If $StallBuild is missing, SKIP with reason. Otherwise stop engine, back up installed binary beside it, swap Stall build, start, verify routes then watchdog reason/route removal/network; always restore normal binary. Preserve runs.json and prior last-error.txt." {
    if (-not (Test-Path -LiteralPath $StallBuild)) { Record "SKIP" "the watchdog removed the routes" "Stall build missing: $StallBuild"; return }
    Service-State $Service "Stopped" $StopSeconds
    $script:OriginalHash = (Get-FileHash -LiteralPath $script:EngineExe).Hash
    $backup = "$script:EngineExe.auto-$([guid]::NewGuid().ToString('N')).original"
    Copy-Item -LiteralPath $script:EngineExe -Destination $backup
    $script:OriginalBackup = $backup
    try {
      Save "route-stall-build.txt" ("$((Get-FileHash $StallBuild).Hash) $StallBuild")
      Copy-Item -LiteralPath $StallBuild -Destination $script:EngineExe -Force
      $errorFile = Join-Path $EngineDir "last-error.txt"
      $oldError = if (Test-Path $errorFile) { (Get-Item $errorFile).LastWriteTimeUtc } else { [datetime]::MinValue }
      Service-State $Service "Running" $StopSeconds
      Require-Routing
      $stallClock = [Diagnostics.Stopwatch]::StartNew()
      # Stall activation, the unanswered ping's bound, the watchdog's sampling
      # tick, and our observation tick. No extra routing-start allowance after routes are up.
      $stallBound = $StallSeconds + $WatchdogSeconds + $WatchdogPollSeconds + [TimeSpan]::FromMilliseconds($PollMs).TotalSeconds
      $tripped = Wait-For {
        @(Sieve-Routes).Count -eq 0 -and (Test-Path $errorFile) -and (Get-Item $errorFile).LastWriteTimeUtc -gt $oldError
      } $stallBound
      Check "the watchdog removed the routes" $tripped "observed $($stallClock.Elapsed.TotalSeconds) s after routing observed"
      $reason = if (Test-Path $errorFile) { Get-Content -LiteralPath $errorFile -Raw -Encoding UTF8 } else { "missing last-error.txt" }
      Save "route-stall-last-error.txt" $reason
      Check "the watchdog says why" ($tripped -and $reason -match 'watchdog') $reason
      Check-Network "stall"
    } finally { Restore-Binary }
    Service-State $Service "Running" $StopSeconds
    Require-Routing
  }
  Step "budget" "With normal engine routing: measure CPU for $BudgetSeconds s, report idle CPU as ADVISORY because unattended activity is uncontrolled; download $DownloadBytes bytes to NUL within the same sample bound; check relay CPU per $ReferenceMbps Mbit/s and memory." {
    Require-Routing
    $enginePid = Engine-Pid
    $p = Get-Process -Id $enginePid
    try {
      $cpuStart = $p.TotalProcessorTime.TotalSeconds
      $clock = [Diagnostics.Stopwatch]::StartNew()
      while ($clock.Elapsed.TotalSeconds -lt $BudgetSeconds) { Assert-AppClosed; Start-Sleep -Milliseconds $PollMs }
      $p.Refresh()
      $idle = ($p.TotalProcessorTime.TotalSeconds - $cpuStart) / $clock.Elapsed.TotalSeconds
      Record "ADVISORY" "idle CPU under 1 percent of one core" "measured $idle cores; limit $IdleCpuMaximum; unattended input and background traffic are uncontrolled, so idle is not established"
      $cpuStart = $p.TotalProcessorTime.TotalSeconds
      $clock.Restart()
      $meta = & curl.exe -s --noproxy '*' -o NUL -m $BudgetSeconds -w '%{http_code} %{size_download} %{speed_download}' "https://speed.cloudflare.com/__down?bytes=$DownloadBytes"
      $code = $LASTEXITCODE
      $wall = $clock.Elapsed.TotalSeconds
      Assert-AppClosed
      $p.Refresh()
      Require "same engine process throughout budget" ((Engine-Pid) -eq $enginePid) "PID $enginePid"
      Require-Routing
      $fields = "$meta" -split '\s+'
      Require "budget download completed" ($code -eq 0 -and $fields.Count -eq 3 -and $fields[0] -eq "200" -and [double]::Parse($fields[1], [Globalization.CultureInfo]::InvariantCulture) -eq $DownloadBytes) "curl exit $code; $meta"
      # Bytes/s * bits/byte / decimal megabit, the existing budget's unit conversion.
      $mbps = [double]::Parse($fields[2], [Globalization.CultureInfo]::InvariantCulture) * 8 / 1e6
      Require "budget transfer has nonzero duration and speed" ($wall -gt 0 -and $mbps -gt 0) "$wall s; $mbps Mbit/s"
      $cpu = ($p.TotalProcessorTime.TotalSeconds - $cpuStart) / $wall
      $per100 = $cpu / ($mbps / $ReferenceMbps)
      Check "relay CPU at most 15 percent of one core per 100 Mbit/s" ($per100 -le $RelayCpuMaximum) "$per100 cores per $ReferenceMbps Mbit/s; $mbps Mbit/s; $wall s"
      Check "engine memory at most 300 MB" ($p.WorkingSet64 -le $MemoryMaximum) "$($p.WorkingSet64) bytes working set"
      Save "route-budget.txt" "idle=$idle cores (advisory); download=$meta; wall=$wall s; relay=$per100 cores per $ReferenceMbps Mbit/s; workingSet=$($p.WorkingSet64) bytes"
    } finally { $p.Dispose() }
  }
  Step "adguard-back" "If initially running, sc.exe start 'Adguard Service'; check blocker=adguard, no routes and lookup+HTTPS. Otherwise SKIP. Finally always restore policy OFF and normal binary, and restore AdGuard if initially running, even on failure." {
    if ($script:AdguardWasRunning) {
      Service-State $Adguard "Running" $AdguardSeconds
      Require "the engine steps aside when AdGuard runs again" (Wait-For {
        $s = Read-Status
        $s -and $s.blocker.kind -eq "adguard" -and -not $s.routes_up -and @(Sieve-Routes).Count -eq 0
      } $RouteSeconds) "status.json and route table"
      Check-Network "adguard-back"
    } else { Record "SKIP" "starting AdGuard again runs its service" "was not running at preflight" }
  }
}

function Summary {
  Log "=== AUTO summary ==="
  if ($DryRun) { Log "PLAN ONLY: no checks executed, no files written, no processes or services changed." }
  else {
    Log (($script:Rows | Format-Table Step, Result, Check -AutoSize -Wrap | Out-String).Trim())
    Log "Failed checks: $script:Failed; evidence: $script:EvidenceDir"
  }
  Log "Reboot test stays separate. AUTO restores routing OFF, so first enable routing in the installed app, then close it."
  Log "The existing reboot workflow is interactive; crash-loop expectations depend on the retained runs.json history."
  $rebootOut = if ($DryRun) { '<AUTO evidence directory printed by the live run>' } else { $script:EvidenceDir }
  Log ('powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\engine-route.ps1 -Step reboot-prep -Out "' + $rebootOut + '"')
  Log '(reboot, then)'
  Log ('powershell -NoProfile -ExecutionPolicy Bypass -File scripts\live\engine-route.ps1 -Step after-reboot -Out "' + $rebootOut + '"')
}

# As in engine-install.ps1: unexpected termination is never silent, even if logging failed.
trap {
  $script:Failed++
  $message = "ERROR AUTO $script:Step at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
  Write-Host $message -ForegroundColor Red
  if ($script:Logging) {
    try { [IO.File]::AppendAllText($Results, "$message`r`n", $Utf8) }
    catch { Write-Host "ERROR writing results: $($_.Exception.Message)" -ForegroundColor Red }
  }
  Write-Host "Failed checks: $script:Failed"
  exit $script:Failed
}

try { Run-Auto }
catch { Record "FAIL" "AUTO stopped" "line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)" }
finally {
  if (-not $DryRun) {
    try { Restore-State }
    finally {
      if ($script:LiveLease -and -not $script:LiveLease.Inherited) {
        $script:LiveLease.Stream.Dispose()
        $env:SIEVE_LIVE_RUN_TOKEN=$script:LiveLease.PreviousToken
        $env:SIEVE_LIVE_RUN_OWNER=$script:LiveLease.PreviousOwner
      }
    }
  }
}
Summary
exit $script:Failed
