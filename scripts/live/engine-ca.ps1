<#
.SYNOPSIS
  Live check for engine slice 5 (docs/plans/2026-10-17-https-filtering.md, slice 5):
  `live_root_ca_trust_and_removal`. The engine owns one root CA: a CNG key it
  cannot export, a root with the plan's limits, trusted by Windows and Firefox,
  and gone on every off path.

.DESCRIPTION
  Run by a person, never by an agent, in an elevated PowerShell (Terminal
  (Admin)), with Sieve installed and the app CLOSED: the app sends `https: false`
  whenever it runs, because the switch stays hidden until slice 6. So this script
  drives the switch itself: it stops the service, writes policy.json with a higher
  revision and starts it again. No new verb, build or production surface.

  Every step writes its evidence to -Out and prints PASS or FAIL per check;
  results-ca.txt collects them. Order (docs/live/engine-slice-5.md): before, on,
  restart, off, on, uninstall. The check names are read by the Rust test
  `live_root_ca_trust_and_removal`, which passes only when each passed.

  `-Step intercept` is the route of slice 6 and later (docs/live/engine-slice-6.md):
  `-Step on` changes only `https` and moves no traffic, while this one also turns
  `engine` and `sieving` on, so flows reach interception.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\live\engine-ca.ps1 -Step before
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("before", "on", "intercept", "restart", "off", "uninstall")]
  [string]$Step,
  [string]$Out = (Join-Path $env:PUBLIC "sieve-engine-live")
)

$ErrorActionPreference = "Stop"
$Service = "sieve-engine"
$EngineDir = Join-Path $env:ProgramData "Sieve\engine"
$SieveDir = Join-Path $env:ProgramData "Sieve"
$CaFile = Join-Path $EngineDir "ca.json"
$PolicyFile = Join-Path $EngineDir "policy.json"
$StatusFile = Join-Path $EngineDir "status.json"
$FirefoxKey = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Certificates"
$Results = Join-Path $Out "results-ca.txt"
$ServerAuthOid = "1.3.6.1.5.5.7.3.1"
$WaitSeconds = 20
$script:Failed = 0
. (Join-Path $PSScriptRoot 'live-lease.ps1')
. (Join-Path $PSScriptRoot 'engine-ca-checks.ps1')
$liveLease = Enter-SieveLiveLease
try {

New-Item -ItemType Directory -Force $Out | Out-Null

function Write-Evidence([string]$name, [string]$text) {
  $text | Out-File -Encoding utf8 (Join-Path $Out $name)
}

function Check([string]$name, [bool]$ok, [string]$detail = "") {
  $word = if ($ok) { "PASS" } else { "FAIL" }
  if (-not $ok) { $script:Failed++ }
  $line = "$word  $name$(if ($detail) { "  ($detail)" })"
  Write-Host $line
  Add-Content -Encoding utf8 $Results $line
}

function Read-Record {
  if (-not (Test-Path $CaFile)) { return $null }
  return Get-Content -Raw -Encoding UTF8 $CaFile | ConvertFrom-Json
}

function Recorded-Thumbprints($record) {
  $list = @()
  if ($record.active) { $list += $record.active.thumbprint }
  foreach ($entry in @($record.retiring)) { if ($entry.thumbprint) { $list += $entry.thumbprint } }
  return $list
}

function Recorded-Keys($record) {
  $list = @()
  if ($record.active) { $list += $record.active.key_name }
  foreach ($entry in @($record.retiring)) { $list += $entry.key_name }
  return $list
}

function Stop-Engine {
  Stop-Service $Service -ErrorAction SilentlyContinue
  (Get-Service $Service).WaitForStatus("Stopped", [TimeSpan]::FromSeconds($WaitSeconds))
}

function Start-Engine {
  Start-Service $Service
  (Get-Service $Service).WaitForStatus("Running", [TimeSpan]::FromSeconds($WaitSeconds))
}

# Written with no BOM: the engine's JSON reader refuses one, and a refused file reads as off.
function Write-PolicyWith([scriptblock]$json) {
  Stop-Engine
  $policy = if (Test-Path $PolicyFile) { Get-Content -Raw -Encoding UTF8 $PolicyFile | ConvertFrom-Json } else { [pscustomobject]@{ revision = 0; engine = $false } }
  $encoding = New-Object Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($PolicyFile, (& $json $policy), $encoding)
  Start-Engine
}

function Set-HttpsSwitch([bool]$on) {
  Write-PolicyWith { param($policy) New-HttpsPolicyJson $policy $on }
}

# The engine rewrites the file by rename, so a read can miss it for a moment.
function Read-Status {
  try { return Get-Content -Raw -Encoding UTF8 $StatusFile | ConvertFrom-Json } catch { return $null }
}

function Wait-Until([scriptblock]$test) {
  $clock = [Diagnostics.Stopwatch]::StartNew()
  while ($clock.Elapsed.TotalSeconds -lt $WaitSeconds) {
    if (& $test) { return $true }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function Save-Store([string]$name) {
  Write-Evidence $name (cmd /c "certutil -store Root 2>&1" | Out-String)
}

function Key-Listing {
  return (cmd /c "certutil -csp `"Microsoft Software Key Storage Provider`" -key 2>&1" | Out-String)
}

function Check-Root($thumbprint) {
  $text = cmd /c "certutil -v -store Root $thumbprint 2>&1" | Out-String
  Write-Evidence "root-$thumbprint.txt" $text
  $cert = Get-Item "Cert:\LocalMachine\Root\$thumbprint" -ErrorAction SilentlyContinue
  Check "the root is in LocalMachine Root with its thumbprint" ($null -ne $cert) $thumbprint
  if ($null -eq $cert) { return }
  $basic = $cert.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
  Check "the root has CA true and path length 0" ($basic.CertificateAuthority -and $basic.HasPathLengthConstraint -and $basic.PathLengthConstraint -eq 0)
  $eku = $cert.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
  $oids = @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
  Check "the root has Server Authentication only" ($oids.Count -eq 1 -and $oids[0] -eq $ServerAuthOid) ($oids -join ",")
  $property = @($cert.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
  Check "the store property is Server Authentication" ($property.Count -eq 1 -and $property[0] -eq $ServerAuthOid) ($property -join ",")
}

function Check-Key($keyName) {
  $listing = Key-Listing
  Write-Evidence "keys.txt" $listing
  Check "the key is a machine CNG key of the software provider" ($listing -match [regex]::Escape($keyName)) $keyName
  $detail = cmd /c "certutil -csp `"Microsoft Software Key Storage Provider`" -key `"$keyName`" 2>&1" | Out-String
  $answer = Get-KeyAnswer $detail $LASTEXITCODE
  Write-Evidence "key-detail.txt" $detail
  Check "an admin is refused the key" ($answer -eq "refused") "certutil's answer: $answer"
  $facts = Read-KeyFactsAsSystem $keyName
  Check "the key is not exportable and its DACL lists SYSTEM only" (Test-KeyFacts $facts) "read as SYSTEM: $(if ($facts) { $facts | ConvertTo-Json -Compress } else { 'no answer' })"
}

# Only SYSTEM can open the key, so a one-shot task asks as SYSTEM and is deleted.
function Read-KeyFactsAsSystem($keyName) {
  $probe = Join-Path $Out "key-probe.ps1"
  $result = Join-Path $Out "key-facts.json"
  Remove-Item $result -ErrorAction SilentlyContinue
  New-KeyProbeScript $keyName $result | Out-File -Encoding utf8 $probe
  $task = "SieveLiveKeyProbe"
  try {
    cmd /c "schtasks /Create /TN $task /SC ONCE /ST 00:00 /RU SYSTEM /F /TR `"powershell -NoProfile -ExecutionPolicy Bypass -File \`"$probe\`"`" 2>&1" | Out-Null
    cmd /c "schtasks /Run /TN $task 2>&1" | Out-Null
    if (-not (Wait-Until { Test-Path $result })) { return $null }
    Start-Sleep -Milliseconds 500
    return Get-Content -Raw -Encoding UTF8 $result | ConvertFrom-Json
  } finally {
    cmd /c "schtasks /Delete /TN $task /F 2>&1" | Out-Null
  }
}

function Check-NoKeyMaterial {
  $bad = @()
  foreach ($file in Get-ChildItem -Recurse -File $SieveDir) {
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    $derAtStart = $bytes.Length -gt 2 -and $bytes[0] -eq 0x30 -and $bytes[1] -eq 0x82
    if ($derAtStart -or $text -match "-----BEGIN" -or $text -match "MII[A-Za-z0-9+/]{40}") { $bad += $file.FullName }
  }
  Write-Evidence "programdata-files.txt" (Get-ChildItem -Recurse -File $SieveDir | Select-Object FullName, Length | Out-String)
  Check "no file in ProgramData holds key material" ($bad.Count -eq 0) ($bad -join ", ")
}

function Firefox-Value {
  $key = Get-ItemProperty $FirefoxKey -ErrorAction SilentlyContinue
  if ($null -eq $key) { return $null }
  return $key.ImportEnterpriseRoots
}

function Check-Firefox($record) {
  $value = Firefox-Value
  Write-Evidence "firefox-policy.txt" "value=$value; recorded=$($record.firefox_policy_set)"
  $ok = if ($record.firefox_policy_set) { $value -eq 1 } else { $true }
  Check "the Firefox policy follows the record" $ok "value=$value, Sieve set it: $($record.firefox_policy_set)"
}

switch ($Step) {
  "before" {
    Set-Content -Encoding utf8 $Results "==== engine-ca before $(Get-Date -Format s)"
    if ((Get-Process sieve -ErrorAction SilentlyContinue)) { throw "Close the Sieve app first: it sends https false whenever it runs." }
    Save-Store "store-before.txt"
    Write-Evidence "keys-before.txt" (Key-Listing)
    Write-Evidence "firefox-before.txt" "value=$(Firefox-Value)"
    Write-Host "Saved the store, the key listing and the Firefox value."
  }
  "on" {
    if ((Get-Process sieve -ErrorAction SilentlyContinue)) { throw "Close the Sieve app first: it sends https false whenever it runs." }
    Set-HttpsSwitch $true
    if (-not (Wait-Until { $r = Read-Record; $r -and $r.active })) { throw "The engine recorded no active root within $WaitSeconds s. See $EngineDir." }
    $record = Read-Record
    Save-Store "store-on.txt"
    Check-Root $record.active.thumbprint
    Check-Key $record.active.key_name
    Check-NoKeyMaterial
    Check-Firefox $record
  }
  "intercept" {
    if ((Get-Process sieve -ErrorAction SilentlyContinue)) { throw "Close the Sieve app first: it sends https false whenever it runs." }
    Write-PolicyWith { param($policy) New-InterceptionPolicyJson $policy }
    if (-not (Wait-Until { $r = Read-Record; $r -and $r.active })) { throw "The engine recorded no active root within $WaitSeconds s. See $EngineDir." }
    $up = Wait-Until { $s = Read-Status; $s -and $s.routes_up -and $s.policy.https -and $s.policy.sieving }
    $status = Read-Status
    Check "the engine holds interception on with routes up" $up "routes_up: $($status.routes_up), blocker: $($status.blocker | ConvertTo-Json -Compress), intercepted: $($status.https.intercepted)"
    Write-Host "Next: step 0 of docs/live/engine-slice-6.md. Nothing else there counts until https.intercepted grows."
  }
  "restart" {
    $record = Read-Record
    if (-not $record.active) { throw "Run -Step on first." }
    $thumbprint = $record.active.thumbprint
    Stop-Engine
    Start-Engine
    Start-Sleep -Seconds 3
    $after = Read-Record
    Check "the root stays through a restart" ($after.active.thumbprint -eq $thumbprint -and (Test-Path "Cert:\LocalMachine\Root\$thumbprint")) $thumbprint
  }
  "off" {
    $record = Read-Record
    $thumbprints = @(Recorded-Thumbprints $record)
    $keys = @(Recorded-Keys $record)
    $wasSet = $record.firefox_policy_set
    Set-HttpsSwitch $false
    $gone = Wait-Until { -not (@($thumbprints | Where-Object { Test-Path "Cert:\LocalMachine\Root\$_" })) }
    Start-Sleep -Seconds 2
    Save-Store "store-off.txt"
    $listing = Key-Listing
    Write-Evidence "keys-off.txt" $listing
    $leftKeys = @($keys | Where-Object { $listing -match [regex]::Escape($_) })
    $policyGone = if ($wasSet) { $null -eq (Firefox-Value) } else { $true }
    Check "turning HTTPS off removes root, key and policy" ($gone -and $leftKeys.Count -eq 0 -and $policyGone) "roots gone: $gone, keys left: $($leftKeys.Count), policy gone: $policyGone"
  }
  "uninstall" {
    $record = Read-Record
    if (-not $record -or -not $record.active) { throw "Run -Step on first, so uninstall has a root to remove." }
    $thumbprints = @(Recorded-Thumbprints $record)
    $keys = @(Recorded-Keys $record)
    $wasSet = $record.firefox_policy_set
    $image = (Get-CimInstance Win32_Service -Filter "Name='$Service'").PathName.Trim('"')
    $text = cmd /c "`"$image`" uninstall 2>&1" | Out-String
    Write-Evidence "uninstall.txt" $text
    Write-Host $text
    Save-Store "store-uninstalled.txt"
    $listing = Key-Listing
    Write-Evidence "keys-uninstalled.txt" $listing
    $leftRoots = @($thumbprints | Where-Object { Test-Path "Cert:\LocalMachine\Root\$_" })
    $leftKeys = @($keys | Where-Object { $listing -match [regex]::Escape($_) })
    $policyGone = if ($wasSet) { $null -eq (Firefox-Value) } else { $true }
    $service = Get-Service $Service -ErrorAction SilentlyContinue
    $ok = $leftRoots.Count -eq 0 -and $leftKeys.Count -eq 0 -and $policyGone -and $null -eq $service -and -not (Test-Path $SieveDir)
    Check "uninstall removes root, key, policy, service and ProgramData" $ok "roots left: $($leftRoots.Count), keys left: $($leftKeys.Count), policy gone: $policyGone, service: $($null -ne $service), folder: $(Test-Path $SieveDir)"
  }
}

Write-Host ("{0} check(s) failed. Evidence in {1}" -f $script:Failed, $Out) -ForegroundColor $(if ($script:Failed -eq 0) { "Green" } else { "Red" })
exit $script:Failed
} finally { Exit-SieveLiveLease $liveLease }
