<#
.SYNOPSIS
  Live check for engine slice 3 (docs/plans/2026-10-17-https-filtering.md, slice 3):
  `live_engine_full_route_relays_and_restores`. The engine routes this
  computer's traffic through its Wintun adapter "Sieve", relays every flow,
  answers DNS by forwarding it, and gives the network back on every off path.

.DESCRIPTION
  Run by a person, never by an agent, in an elevated PowerShell (Terminal
  (Admin)). Every step writes its evidence to -Out and prints PASS or FAIL per
  check; results-route.txt collects them. Order (docs/live/engine-slice-3.md):
  before, adguard, on, soak (after 30 minutes of normal use), kill, stall,
  reboot-prep, (reboot), after-reboot, budget, adguard-back.

  The engine's own facts come from C:\ProgramData\Sieve\engine\status.json,
  which it rewrites while routing (the pipe admits only the installed app).
  The check names below are read by the Rust test of the same name as the
  live check, which passes only when every one of them passed.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\live\engine-route.ps1 -Step before
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("before", "adguard", "on", "soak", "kill", "stall", "reboot-prep", "after-reboot", "budget", "adguard-back")]
  [string]$Step,
  [string]$StallBuild = "",
  [string]$Out = (Join-Path $env:PUBLIC "sieve-engine-live")
)

$ErrorActionPreference = "Stop"
if (-not $StallBuild) {
  $StallBuild = Join-Path $PSScriptRoot "..\..\engine\target\release\sieve-engine.exe"
}
$Service = "sieve-engine"
$Adapter = "Sieve"
$AdguardService = "Adguard Service"
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\sieve-engine"
$EngineDir = Join-Path $env:ProgramData "Sieve\engine"
$StatusFile = Join-Path $EngineDir "status.json"
$Results = Join-Path $Out "results-route.txt"
$script:Failed = 0
. (Join-Path $PSScriptRoot 'live-lease.ps1')
$liveLease = Enter-SieveLiveLease
try {

New-Item -ItemType Directory -Force $Out | Out-Null

function Write-Evidence([string]$name, [string]$text) {
  $text | Out-File -Encoding utf8 (Join-Path $Out $name)
}

function Check([string]$what, [bool]$ok, [string]$detail = "") {
  $line = "{0}  {1}{2}" -f ($(if ($ok) { "PASS" } else { "FAIL" })), $what, $(if ($detail) { "  ($detail)" } else { "" })
  if (-not $ok) { $script:Failed++ }
  Write-Host $line -ForegroundColor $(if ($ok) { "Green" } else { "Red" })
  $line | Out-File -Append -Encoding utf8 $Results
}

function Assert-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Step '$Step' needs an elevated PowerShell (Terminal (Admin))."
  }
}

function Get-EngineExe {
  $imagePath = (Get-ItemProperty $ServiceKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
  if (-not $imagePath) { throw "the sieve-engine service is not installed (run engine-install.ps1 first)" }
  $imagePath.Trim().Trim('"').Split('"')[0]
}

# The listings of the network rule, without the Sieve adapter's own rows
# (they exist only while routing, which is the point of the check).
function Get-Listings {
  $routes = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne $Adapter } |
    Sort-Object AddressFamily, DestinationPrefix, InterfaceAlias, NextHop |
    ForEach-Object { "{0} via {1} on {2}" -f $_.DestinationPrefix, $_.NextHop, $_.InterfaceAlias }
  $persistent = Get-NetRoute -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
    Sort-Object DestinationPrefix | ForEach-Object { "{0} via {1} on {2}" -f $_.DestinationPrefix, $_.NextHop, $_.InterfaceAlias }
  $dns = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne $Adapter } |
    Sort-Object InterfaceAlias, AddressFamily | ForEach-Object { "{0} {1}: {2}" -f $_.InterfaceAlias, $_.AddressFamily, ($_.ServerAddresses -join ",") }
  $proxy = (netsh winhttp show proxy) -join "`n"
  $firewall = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { $_.Name }
  [ordered]@{
    routes     = ($routes -join "`n")
    persistent = ($persistent -join "`n")
    dns        = ($dns -join "`n")
    proxy      = $proxy
    firewall   = ($firewall -join "`n")
  }
}

function Save-Listings([string]$tag) {
  $l = Get-Listings
  foreach ($k in $l.Keys) { Write-Evidence "route-$tag-$k.txt" $l[$k] }
  Write-Evidence "route-$tag-route-print.txt" ((route print) -join "`n")
  $l
}

function Compare-WithBefore([string]$tag, [string[]]$keys = @("routes", "persistent", "dns", "proxy", "firewall")) {
  $now = Save-Listings $tag
  foreach ($k in $keys) {
    $beforeFile = Join-Path $Out "route-before-$k.txt"
    if (-not (Test-Path $beforeFile)) { Check "$k listing has a before-listing" $false "run -Step before first"; continue }
    $before = (Get-Content -Raw -Encoding utf8 $beforeFile).Trim()
    $same = $before -eq $now[$k].Trim()
    if (-not $same) {
      $diff = Compare-Object ($before -split "`n") ($now[$k].Trim() -split "`n") | ForEach-Object { "{0} {1}" -f $_.SideIndicator, $_.InputObject }
      Write-Evidence "route-$tag-$k-diff.txt" ($diff -join "`n")
    }
    Check "$k listing matches the before-listing ($tag)" $same $(if (-not $same) { "see route-$tag-$k-diff.txt" })
  }
}

function Get-SieveRoutes { @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq $Adapter }) }
function Get-SieveAdapter { Get-NetAdapter -Name $Adapter -ErrorAction SilentlyContinue }

# Name lookup and HTTPS, timed at the test itself.
function Test-Network([string]$tag) {
  $dnsOk = $false
  try { $dnsOk = @(Resolve-DnsName example.com -DnsOnly -ErrorAction Stop).Count -gt 0 } catch { }
  $code = (& curl.exe -s -o NUL -m 10 -w "%{http_code}" -I https://example.com) 2>$null
  Check "name lookup works ($tag)" $dnsOk
  Check "HTTPS works ($tag)" ($code -match "^[23]") "curl -I https://example.com gave $code"
  $dnsOk -and ($code -match "^[23]")
}

function Read-Status {
  if (-not (Test-Path $StatusFile)) { return $null }
  Get-Content -Raw $StatusFile | ConvertFrom-Json
}

function Wait-For([scriptblock]$condition, [int]$seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    if (& $condition) { return $true }
    Start-Sleep -Milliseconds 500
  }
  & $condition
}

function Get-EnginePid { (Get-CimInstance Win32_Service -Filter "Name='$Service'").ProcessId }

function Ask([string]$question) { (Read-Host "$question (y/n)") -eq "y" }

Write-Host "Sieve engine route check, step '$Step'. Evidence: $Out"
"==== $(Get-Date -Format s) step $Step as $(whoami)" | Out-File -Append -Encoding utf8 $Results

# Never stop silently: an error that ends a step is an ERROR line and a failure.
trap {
  $msg = "ERROR  step '$Step' stopped at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message
  Write-Host $msg -ForegroundColor Red
  $msg | Out-File -Append -Encoding utf8 $Results
  $script:Failed++
  Write-Host ("{0} check(s) failed. Evidence in {1}" -f $script:Failed, $Out) -ForegroundColor Red
  exit $script:Failed
}

switch ($Step) {
  "before" {
    Assert-Admin
    Save-Listings "before" | Out-Null
    Test-Network "before" | Out-Null
    Check "the engine service runs" ((Get-Service $Service).Status -eq "Running")
    Check "no adapter named Sieve before routing" ($null -eq (Get-SieveAdapter))
    Check "no route on an interface named Sieve before routing" ((Get-SieveRoutes).Count -eq 0)
    $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).NextHop
    Write-Evidence "route-gateway.txt" $gw
  }

  "adguard" {
    Assert-Admin
    $svc = Get-Service $AdguardService -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne "Running") { throw "AdGuard's service is not running; this step needs it running" }
    Write-Host "In the installed Sieve app: Settings > Filtering, turn on 'Route traffic through the engine'."
    $null = Read-Host "Press Enter once it is on"
    Start-Sleep -Seconds 6
    $s = Read-Status
    Write-Evidence "route-adguard-status.json" ((Get-Content -Raw $StatusFile -ErrorAction SilentlyContinue) + "")
    Check "the engine refuses while AdGuard runs (blocker adguard)" ($s -and $s.blocker.kind -eq "adguard") "status.json blocker: $($s.blocker.kind)"
    Check "no route on Sieve while AdGuard runs" ((Get-SieveRoutes).Count -eq 0)
    Check "the app shows the AdGuard refusal" (Ask "Does Settings > Filtering > Engine say 'Waiting for AdGuard' with the reason?")
    Check "the app offers to pause AdGuard" (Ask "Is there a 'Pause AdGuard' button, with the text that it asks AdGuard's Windows service to stop and Windows asks you first?")
    Write-Host "Click 'Pause AdGuard' and approve the Windows prompt."
    # AdGuard's service stays StopPending after a pause, so the engine's verdict is what to wait for.
    $cleared = Wait-For { $now = Read-Status; $now -and $now.blocker.kind -ne "adguard" } 90
    Check "the engine's AdGuard blocker clears after the pause" $cleared
    Write-Evidence "route-adguard-paused-service.txt" ((Get-Service $AdguardService).Status.ToString())
    $routed = Wait-For { (Get-SieveRoutes).Count -gt 0 } 30
    Check "the engine routes once AdGuard stopped filtering" $routed
    Check "the app says AdGuard is paused, with no Start button" (Ask "Does the Engine block say 'AdGuard is paused' and how to turn it back on, with no 'Start AdGuard again' button?")
  }

  "on" {
    Assert-Admin
    $up = Wait-For { (Get-SieveRoutes).Count -gt 0 } 30
    Check "routes on the Sieve adapter" $up "$((Get-SieveRoutes).Count) routes"
    Write-Evidence "route-on-sieve-routes.txt" ((Get-SieveRoutes | ForEach-Object { $_.DestinationPrefix }) -join "`n")
    $persist = @(Get-NetRoute -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq $Adapter })
    Check "no Sieve route in the persistent store" ($persist.Count -eq 0)
    Compare-WithBefore "on"
    $sieveDns = @(Get-DnsClientServerAddress -InterfaceAlias $Adapter -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 })
    Check "no DNS server set on the Sieve adapter" ($sieveDns.Count -eq 0)
    Test-Network "on" | Out-Null
    $gw = (Get-Content -Raw (Join-Path $Out "route-gateway.txt")).Trim()
    $lan = Test-NetConnection $gw -Port 80 -WarningAction SilentlyContinue
    Check "LAN router UI reachable" ($lan.TcpTestSucceeded) "TCP $gw`:80"
    Check "the router UI loads in a browser" (Ask "Open http://$gw/ in a browser. Does the router's page load?")
    $s = Read-Status
    Check "the engine reports routing" ($s -and $s.routes_up) "status.json routes_up $($s.routes_up)"
    Check "the app says Routing traffic" (Ask "Does Settings > Filtering > Engine say 'Routing traffic', and Home's Engine tile the same?")
  }

  "soak" {
    Assert-Admin
    Write-Host "This step reads the result of 30 minutes of normal use with routing on:"
    Write-Host "browsing, a video call and a game launcher, without a failure."
    Check "30 minutes of normal use without a failure" (Ask "Did 30 minutes of browsing, a video call and a game launcher all work?")
    $s = Read-Status
    Write-Evidence "route-soak-status.json" ((Get-Content -Raw $StatusFile) + "")
    $rate = if ($s.counters.flows -gt 0) { $s.counters.attributed / $s.counters.flows } else { 0 }
    Check "attribution of at least 0.95 from the engine's counters" ($rate -ge 0.95) ("{0} of {1} flows ({2:P1})" -f $s.counters.attributed, $s.counters.flows, $rate)
    Check "the engine refused none of its own flows" ($s.counters.own_refused -eq 0) "own_refused $($s.counters.own_refused)"
    Check "DNS was answered on the TUN" ($s.counters.dns_answers -gt 0) "dns_answers $($s.counters.dns_answers)"
    Check "Home and Apps show the apps you used" (Ask "Do Home and Apps show the apps you used in these 30 minutes?")
    Compare-WithBefore "soak" @("persistent", "dns", "proxy")
  }

  "kill" {
    Assert-Admin
    Check "routes up before the kill" ((Get-SieveRoutes).Count -gt 0)
    $enginePid = Get-EnginePid
    taskkill.exe /F /PID $enginePid | Out-Null
    $killedAt = Get-Date
    Start-Sleep -Seconds 1
    Test-Network "kill +1s" | Out-Null
    # Timed at the network test itself, not the slower listings below.
    $elapsed = ((Get-Date) - $killedAt).TotalSeconds
    Check "network checked within 5 s of the kill" ($elapsed -le 5) ("{0:N1} s" -f $elapsed)
    Check "no route on an interface named Sieve after the kill" ((Get-SieveRoutes).Count -eq 0)
    Check "the Sieve adapter is gone after the kill" ($null -eq (Get-SieveAdapter))
    Compare-WithBefore "kill" @("routes", "persistent", "dns", "proxy")
    $back = Wait-For { (Get-Service $Service).Status -eq "Running" } 20
    Check "the service manager restarted the engine" $back
  }

  "stall" {
    Assert-Admin
    # Build first, unelevated, in the worktree: cargo build --release -p sieve-engine --features stall
    $exe = Get-EngineExe
    $stall = (Resolve-Path $StallBuild).Path
    Write-Evidence "route-stall-build.txt" ("{0}  {1}" -f (Get-FileHash $stall).Hash, $stall)
    Stop-Service $Service
    Copy-Item $exe "$exe.normal" -Force
    . (Join-Path $PSScriptRoot 'engine-binary.ps1')
    try {
    Copy-SieveStoppedEngine $stall $exe
    Remove-Item (Join-Path $EngineDir "last-error.txt") -ErrorAction SilentlyContinue
    Start-Service $Service
      $up = Wait-For { (Get-SieveRoutes).Count -gt 0 } 30
      Check "the Stall build routes first" $up
      $upAt = Get-Date
      # 30 s until it stalls, 5 s stall bound, 1 s check period, plus slack.
      $tripped = Wait-For { (Get-SieveRoutes).Count -eq 0 } 60
      $elapsed = ((Get-Date) - $upAt).TotalSeconds
      Check "the watchdog removed the routes" $tripped ("{0:N0} s after the routes came up" -f $elapsed)
      $err = Get-Content -Raw (Join-Path $EngineDir "last-error.txt") -ErrorAction SilentlyContinue
      Write-Evidence "route-stall-last-error.txt" "$err"
      Check "the watchdog says why" ("$err" -match "watchdog") "$err"
      Test-Network "stall" | Out-Null
    } finally {
      Stop-Service $Service -ErrorAction SilentlyContinue
      Copy-SieveStoppedEngine "$exe.normal" $exe
      if ((Get-FileHash "$exe.normal").Hash -ne (Get-FileHash $exe).Hash) {throw 'Normal engine restore hash mismatch; backup retained'}
      Remove-Item "$exe.normal"
      Start-Service $Service
      Write-Host "The normal engine is back."
    }
  }

  "reboot-prep" {
    Assert-Admin
    sc.exe config $Service start= demand | Out-Null
    Check "routes up before the kill and reboot" ((Get-SieveRoutes).Count -gt 0)
    taskkill.exe /F /PID (Get-EnginePid) | Out-Null
    Check "start type set to manual for the reboot test" (((sc.exe qc $Service) -join "`n") -match "DEMAND_START")
    Write-Host "Now reboot. After signing in, run -Step after-reboot in an elevated PowerShell."
  }

  "after-reboot" {
    Assert-Admin
    Test-Network "after reboot" | Out-Null
    Check "no route on an interface named Sieve after the reboot" ((Get-SieveRoutes).Count -eq 0)
    Check "no Sieve adapter after the reboot" ($null -eq (Get-SieveAdapter))
    Compare-WithBefore "after-reboot" @("routes", "persistent", "dns", "proxy")
    sc.exe config $Service start= auto | Out-Null
    Start-Service $Service
    Check "start type back to automatic and running" ((((sc.exe qc $Service) -join "`n") -match "AUTO_START") -and ((Get-Service $Service).Status -eq "Running"))
    # The kill, the watchdog's exit and the kill before the reboot: three unclean ends within the hour.
    Start-Sleep -Seconds 6
    $s = Read-Status
    Write-Evidence "route-after-reboot-status.json" ((Get-Content -Raw $StatusFile -ErrorAction SilentlyContinue) + "")
    Check "the crash-loop stop engaged after three unclean ends within the hour" ($s -and $s.blocker.kind -eq "crash_loop") "status.json blocker: $($s.blocker.kind)"
    Check "no route while in the crash-loop stop" ((Get-SieveRoutes).Count -eq 0)
    Write-Host "Now turn 'Route traffic through the engine' off and on again in the app."
    $null = Read-Host "Press Enter once it is on again"
    Check "turning routing off and on ends the crash-loop stop" (Wait-For { (Get-SieveRoutes).Count -gt 0 } 30)
  }

  "budget" {
    Assert-Admin
    Check "routes up for the budget" ((Get-SieveRoutes).Count -gt 0)
    $p = Get-Process -Id (Get-EnginePid)
    Write-Host "Leave the computer idle for 60 s (no downloads, no video)."
    $c0 = $p.TotalProcessorTime.TotalSeconds; Start-Sleep -Seconds 60; $p.Refresh()
    $idle = ($p.TotalProcessorTime.TotalSeconds - $c0) / 60
    Check "idle CPU under 1 percent of one core" ($idle -lt 0.01) ("{0:P2}" -f $idle)
    . (Join-Path $PSScriptRoot 'budget-transfer.ps1')
    $c0 = $p.TotalProcessorTime.TotalSeconds; $t0 = Get-Date
    $transfer = Invoke-SieveBudgetTransfer 60
    $wall = ((Get-Date) - $t0).TotalSeconds; $p.Refresh()
    Write-Evidence "route-budget-transfer.json" ($transfer | ConvertTo-Json)
    $valid=$transfer.Valid -and $wall -gt 0 -and (Get-EnginePid) -eq $p.Id -and (Get-SieveRoutes).Count -gt 0
    Check "budget download completed on one connection with same routing engine" $valid "12 responses, 300 MB total; see route-budget-transfer.json"
    if ($valid) {
    $cpu = ($p.TotalProcessorTime.TotalSeconds - $c0) / $wall
    $mbps = $transfer.Bytes * 8 / $wall / 1e6
    $per100 = if ($mbps -gt 0) { $cpu / ($mbps / 100) } else { 1 }
    Write-Evidence "route-budget.txt" ("download: 300 MB on one connection`nwall {0:N1} s, {1:N1} Mbit/s, engine CPU {2:P1} of one core, {3:P1} per 100 Mbit/s`nworking set {4:N0} MB, private {5:N0} MB" -f $wall, $mbps, $cpu, $per100, ($p.WorkingSet64 / 1MB), ($p.PrivateMemorySize64 / 1MB))
    Check "relay CPU at most 15 percent of one core per 100 Mbit/s" ($per100 -le 0.15) ("{0:P1} at {1:N0} Mbit/s" -f $cpu, $mbps)
    } else {Write-Host 'SKIP relay CPU: invalid workload; download failure recorded above.'}
    Check "engine memory at most 300 MB" ($p.WorkingSet64 -le 300MB) ("{0:N0} MB working set" -f ($p.WorkingSet64 / 1MB))
    $p.Dispose()
  }

  "adguard-back" {
    Assert-Admin
    # A paused AdGuard stays StopPending, where sc start cannot resume it (the app shows no button then).
    if ((Get-Service $AdguardService).Status -eq "Stopped") {
      Write-Host "In Settings > Filtering > Engine, click 'Start AdGuard again' and approve the Windows prompt."
    } else {
      Write-Host "Turn protection on in AdGuard's own window."
    }
    $back = Wait-For { $now = Read-Status; $now -and $now.blocker.kind -eq "adguard" } 90
    Check "the engine sees AdGuard filter again (blocker adguard)" $back
    Write-Evidence "route-adguard-back-service.txt" ((Get-Service $AdguardService).Status.ToString())
    $down = Wait-For { (Get-SieveRoutes).Count -eq 0 } 30
    Check "the engine steps aside when AdGuard filters again" $down
    Test-Network "adguard-back" | Out-Null
  }
}

Write-Host ""
Write-Host ("{0} check(s) failed. Evidence in {1}" -f $script:Failed, $Out) -ForegroundColor $(if ($script:Failed -eq 0) { "Green" } else { "Red" })
exit $script:Failed
} finally { Exit-SieveLiveLease $liveLease }
