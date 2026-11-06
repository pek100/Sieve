# Unelevated contract tests. Load definitions via AST, never the live entry point.
$ErrorActionPreference = "Stop"
$path = Join-Path $PSScriptRoot "run-slice-3-auto.ps1"
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$functions = @{}
foreach ($statement in $ast.EndBlock.Statements) {
  if ($statement -is [Management.Automation.Language.FunctionDefinitionAst]) {
    $body = $statement.Body.Extent.Text
    $parameters = @($statement.Parameters | ForEach-Object { $_.Extent.Text }) -join ','
    $functions[$statement.Name] = 'param(' + $parameters + ') ' + $body.Substring(1, $body.Length - 2)
  }
}
function Load-Function([string]$name) {
  $body = $functions[$name]
  Set-Item -Path "Function:script:$name" -Value ([scriptblock]::Create($body))
}
foreach ($name in $functions.Keys) { Load-Function $name }
# Only the constant/state initializers preceding the first function, not any entry-point code.
$runnerRoot = $PSScriptRoot
foreach ($statement in $ast.EndBlock.Statements) {
  if ($statement -is [Management.Automation.Language.FunctionDefinitionAst]) { break }
  . ([scriptblock]::Create($statement.Extent.Text.Replace('$PSScriptRoot', '$runnerRoot')))
}
function Assert([bool]$ok, [string]$name) {
  if (-not $ok) { throw "FAIL TEST: $name" }
  Write-Output "PASS TEST: $name"
}
function Must-Throw([scriptblock]$action, [string]$name) {
  $threw = $false
  try { & $action | Out-Null } catch { $threw = $true }
  Assert $threw $name
}

# A dry run must not even read machine state. All relevant entry points are poisoned.
function Get-Service { throw "dry run touched service" }
function Get-Process { throw "dry run touched process" }
function Get-CimInstance { throw "dry run touched CIM" }
function Get-NetRoute { throw "dry run touched routes" }
function sc.exe { throw "test touched sc.exe" }
function curl.exe { throw "test touched curl.exe" }
function Stop-Process { throw "test touched a process" }
$DryRun = $true
$SoakMinutes = $ast.ParamBlock.Parameters[0].DefaultValue.Value
Run-Auto
Assert ($script:Rows.Count -eq 0 -and -not $script:Changed -and -not $script:Logging) "dry run bypasses machine access and never records PASS"
$DryRun = $false

function Dns-Fixture($v4, $v6) {
  [pscustomobject]@{
    Error = $null
    Rows = @([pscustomobject]@{ AddressFamily = 2; ServerAddresses = $v4 }, [pscustomobject]@{ AddressFamily = 23; ServerAddresses = $v6 })
    Registry = @([pscustomobject]@{ Family = 'Tcpip'; NameServer = $null; DhcpNameServer = '' }, [pscustomobject]@{ Family = 'Tcpip6'; NameServer = ''; DhcpNameServer = $null })
  }
}
$fallbackDns = @('fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3')
Assert (Adapter-DnsUnconfigured (Dns-Fixture @() @())) "empty DNS with readable registry evidence passes"
Assert (Adapter-DnsUnconfigured (Dns-Fixture @() $fallbackDns)) "only Windows IPv6 fallback defaults with empty configuration pass"
$evidence = Dns-Fixture @() $fallbackDns
$evidence.Registry[1].NameServer = $fallbackDns -join ','
Assert (-not (Adapter-DnsUnconfigured $evidence)) "explicitly configured fallback addresses still fail"
$evidence = Dns-Fixture @() $fallbackDns
$evidence.Registry[0].DhcpNameServer = '1.1.1.1'
Assert (-not (Adapter-DnsUnconfigured $evidence)) "configured DHCP DNS fails even when only fallback addresses are reported"
$evidence = Dns-Fixture @() $fallbackDns
$evidence.Registry[1] | Add-Member NoteProperty Dhcpv6DNSServers ([byte[]]@(0, 1))
Assert (-not (Adapter-DnsUnconfigured $evidence)) "binary DHCPv6 DNS configuration fails"
Assert (-not (Adapter-DnsUnconfigured (Dns-Fixture @('1.1.1.1') @()))) "any IPv4 DNS fails"
Assert (-not (Adapter-DnsUnconfigured (Dns-Fixture @() @('fe80::1')))) "other IPv6 DNS fails"
$evidence = Dns-Fixture @() $fallbackDns
$evidence.Error = 'Access denied'
Assert (-not (Adapter-DnsUnconfigured $evidence)) "unreadable DNS evidence fails"
$evidence = Dns-Fixture @() @()
$evidence.Rows = @()
Assert (-not (Adapter-DnsUnconfigured $evidence)) "missing adapter DNS rows fail"
$evidence = Dns-Fixture @() $fallbackDns
$evidence.Registry = @()
Assert (-not (Adapter-DnsUnconfigured $evidence)) "missing registry evidence fails"

$scratch = Join-Path (Split-Path -Parent $PSScriptRoot) ("auto-test-" + [guid]::NewGuid().ToString("N"))
[void](New-Item -ItemType Directory -Path $scratch)
$PolicyFile = Join-Path $scratch "policy.json"
$StatusFile = Join-Path $scratch "status.json"
try {
  # Above IEEE-754's exact integer range: no accidental double-rounding of u64 revisions.
  [IO.File]::WriteAllText($PolicyFile, '{"revision":9007199254740993,"engine":false}', $Utf8)
  [IO.File]::WriteAllText($StatusFile, '{"policy":{"revision":9007199254740995,"engine":false}}', $Utf8)
  Write-Policy $true
  $text = [IO.File]::ReadAllText($PolicyFile)
  Assert ($text -ceq '{"revision":9007199254740996,"engine":true,"sieving":true}') "atomic policy uses exact successor of maximum disk/status revision"
  $bytes = [IO.File]::ReadAllBytes($PolicyFile)
  Assert ($bytes[0] -eq [byte][char]'{') "policy is UTF-8 without BOM"
  Write-Policy $false
  Assert ([IO.File]::ReadAllText($PolicyFile) -ceq '{"revision":9007199254740997,"engine":false,"sieving":true}') "OFF is boolean with an increasing revision"
  Assert (@(Get-ChildItem -LiteralPath $scratch -Filter '*.tmp').Count -eq 0) "atomic write removes temporary files"
  [IO.File]::WriteAllText($PolicyFile, '{"revision":18446744073709551615,"engine":false}', $Utf8)
  Must-Throw { Write-Policy $true } "u64 overflow refuses to write"
  Assert ([IO.File]::ReadAllText($PolicyFile).Contains('18446744073709551615')) "overflow preserves existing policy"
  Must-Throw { Policy-Revision ([pscustomobject]@{ revision = -1; engine = $false }) } "negative revision rejected"
  Must-Throw { Policy-Revision ([pscustomobject]@{ revision = 0; engine = 'false' }) } "string boolean rejected"

  $delta = Counter-Delta ([pscustomobject]@{ flows = 100; attributed = 90 }) ([pscustomobject]@{ flows = 120; attributed = 109 })
  Assert ($delta.flows -eq 20 -and $delta.attributed -eq 19) "attribution subtracts THIS run baseline"
  Must-Throw { Counter-Delta ([pscustomobject]@{ flows = 100 }) ([pscustomobject]@{ flows = 1 }) } "counter reset rejected"
  $split = [pscustomobject]@{ flows = 100; attributed = 95; forwarded = 10; forwarded_named = 5 }
  Assert ((Host-Rate $split) -eq 1) "host-only rate leaves forwarded flows out of both sides"
  Assert ((Host-Rate ([pscustomobject]@{ flows = 10; attributed = 6; forwarded = 10; forwarded_named = 6 })) -eq "n/a") "host-only rate of nothing but forwarded flows divides by nothing"

  $script:Calls = New-Object 'System.Collections.Generic.List[string]'
  [IO.File]::WriteAllText($PolicyFile, '{"revision":0,"engine":false}', $Utf8)
  [IO.File]::WriteAllText($StatusFile, '{"policy":{"revision":0,"engine":false}}', $Utf8)
  $script:Revision = [decimal]0
  function Get-Process { @() }
  function Wait-For([scriptblock]$condition) { & $condition }
  function Service-State([string]$name, [string]$state) {
    $script:Calls.Add("$name $state")
    if ($state -eq "Running") {
      # Simulated engine startup publishes exactly the file it just loaded.
      $policy = Get-Content -Raw -Encoding UTF8 -LiteralPath $PolicyFile | ConvertFrom-Json
      [IO.File]::WriteAllText($StatusFile, (@{ policy = $policy } | ConvertTo-Json), $Utf8)
    }
  }
  Set-Routing $true
  Assert (($script:Calls -join ',') -eq "$Service Stopped,$Service Running" -and $script:Changed -and (Read-Status).policy.engine) "policy restart handshake loads new revision only after stop/write/start"
  function Service-State { }
  Must-Throw { Set-Routing $false } "unchanged stale status cannot acknowledge a new policy revision"

  $script:Calls.Clear()
  function Service-State([string]$name, [string]$state, [double]$seconds) { $script:Calls.Add("$name $state") }
  function Write-Policy([bool]$on) { $script:Calls.Add("policy $on"); throw "injected disk failure" }
  function Restore-Binary { $script:Calls.Add("restore binary"); throw "injected copy failure" }
  $script:Changed = $true
  $script:AdguardWasRunning = $true
  $failures = $script:Failed
  Restore-State
  Assert ($script:Failed -eq $failures + 2) "cleanup counts independent policy and binary failures"
  Assert ($script:Calls -contains "$Adguard Running") "AdGuard restoration survives policy AND binary failures"
  Assert ($script:Calls -notcontains "$Service Running") "cleanup does not restart unsafe engine after failed OFF write"

  $script:Calls.Clear()
  $script:AdguardWasRunning = $false
  function Write-Policy([bool]$on) { $script:Calls.Add("policy $on") }
  function Restore-Binary { $script:Calls.Add("restore binary"); $script:OriginalBackup = $null }
  function Wait-For { $true }
  function Get-Process { @() }
  Restore-State
  Assert (($script:Calls -join ',') -eq "$Service Stopped,policy False,restore binary,$Service Running") "cleanup order is stop, OFF, normal binary, start; initially stopped AdGuard stays stopped"

  $script:Calls.Clear()
  function Get-Process { [pscustomobject]@{ Id = 1 } }
  Restore-State
  Assert ($script:Calls -notcontains "$Service Running") "reopened Sieve leaves engine stopped with policy OFF"

  # A disk failure in logging must not throw out of the cleanup sequence.
  $Results = Join-Path $scratch "nonexistent\results.txt"
  $script:Logging = $true
  $failures = $script:Failed
  Log "injected logging test"
  Assert (-not $script:Logging -and $script:Failed -eq $failures + 1) "logging failure is visible and cannot abort recovery"

  $script:Attempts = 0
  $script:Closed = 0
  function Start-Probe {
    $script:Attempts++
    [pscustomobject]@{
      Process = [pscustomobject]@{ HasExited = $true; ExitCode = $(if ($script:Attempts -eq 1) { 6 } else { 0 }) }
      Output = [pscustomobject]@{ Result = $(if ($script:Attempts -eq 1) { '000  0' } else { '200 1.1.1.1 0.001' }) }
      Error = [pscustomobject]@{ Result = '' }
    }
  }
  function Close-Probe { $script:Closed++ }
  function Start-Sleep { if ($script:Attempts -eq 0) { throw "slept before first probe" } }
  $n = Network-Until ([Diagnostics.Stopwatch]::StartNew()) $KillSeconds
  Assert ($n.Ok -and $script:Attempts -eq 2 -and $script:Closed -eq 2) "kill probe begins before sleep, retries failed DNS, stops on first success, closes all probes"
  Assert ($n.Detail.Contains($Target) -and $null -ne $n.Seconds) "kill observation records target and completion time"

  # Service-State against a scripted service (live 2026-10-18 19:55: AdGuard hung in StopPending,
  # then cleanup's start got 1056 and gave up). The real helpers, a fake service manager.
  Load-Function "Service-State"
  Load-Function "Wait-For"
  $script:Cleaning = $true
  function Start-Sleep { }
  function Get-Process { @() }
  function Log { }
  $script:Statuses = New-Object 'System.Collections.Generic.Queue[string]'
  $script:Last = "Running"
  function Get-Service([string]$Name) {
    if ($script:Statuses.Count) { $script:Last = $script:Statuses.Dequeue() }
    [pscustomobject]@{ Status = $script:Last }
  }
  $script:Sc = New-Object 'System.Collections.Generic.List[string]'
  $script:ScCode = 0
  function sc.exe { $script:Sc.Add(($args -join ' ')); $global:LASTEXITCODE = $script:ScCode; "fake sc" }

  # Cleanup's case: AdGuard still StopPending, then it finishes stopping, then start works.
  foreach ($s in "StopPending", "StopPending", "Stopped", "Stopped", "Running") { $script:Statuses.Enqueue($s) }
  $script:Sc.Clear(); $script:ScCode = 0
  Service-State $Adguard "Running" 5
  Assert (($script:Sc -join '|') -eq "start $Adguard") "a Pending service settles before the control is sent, then start succeeds"

  # A start answered 1056 (already running) is success, not a failure.
  $script:Statuses.Clear(); foreach ($s in "Stopped", "Stopped", "Running") { $script:Statuses.Enqueue($s) }
  $script:Sc.Clear(); $script:ScCode = 1056
  Service-State $Adguard "Running" 5
  Assert ($script:Sc.Count -eq 1) "start answered 1056 already-running counts as reaching Running"

  # A stop answered 1062 (not active) is success.
  $script:Statuses.Clear(); foreach ($s in "Running", "Running", "Stopped") { $script:Statuses.Enqueue($s) }
  $script:Sc.Clear(); $script:ScCode = 1062
  Service-State $Service "Stopped" 5
  Assert ($script:Sc.Count -eq 1) "stop answered 1062 not-active counts as reaching Stopped"

  # The 19:55 case: stuck in StopPending for good. No control is sent, and the error names the recovery.
  $script:Statuses.Clear(); $script:Last = "StopPending"
  $script:Sc.Clear(); $script:ScCode = 0
  $msg = ""
  try { Service-State $Adguard "Running" 0.01 } catch { $msg = $_.Exception.Message }
  Assert ($script:Sc.Count -eq 0 -and $msg -like "*stuck in StopPending*" -and $msg -like "*taskkill /F /IM AdguardSvc.exe*") "a service stuck Pending sends no control and names AdGuard's manual recovery"

  # Any other sc.exe failure still fails, with the hint for AdGuard.
  $script:Statuses.Clear(); $script:Last = "Stopped"
  $script:Sc.Clear(); $script:ScCode = 5
  $msg = ""
  try { Service-State $Adguard "Running" 1 } catch { $msg = $_.Exception.Message }
  Assert ($msg -like "*failed: 5*" -and $msg -like "*AdguardSvc.exe*") "other sc.exe errors still fail loudly"
} finally {
  # Only files in the directory this test created; no recursive delete or junction traversal.
  Get-ChildItem -LiteralPath $scratch -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName }
  Remove-Item -LiteralPath $scratch
}
Write-Output "PASS: all unattended runner contract tests (no live services or network used)"
