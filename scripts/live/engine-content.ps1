<#
.SYNOPSIS
  Live check for engine slice 9 (docs/plans/2026-10-17-https-filtering.md, slice 9):
  `live_content_injects_into_test_page`. Decrypted pages get the rules' cosmetics.

.DESCRIPTION
  Run by a person, never by an agent, in an elevated PowerShell, with Sieve installed
  and the app CLOSED: the app sends `content: false` whenever it runs, because the
  switch stays hidden until this check has run. So this script drives the switch: it
  stops the engine's service, writes policy.json with a higher revision and starts it
  again. It touches nothing but policy.json and the engine's own service.

  Steps, in order (docs/live/engine-slice-9.md):
    before  saves the policy and the status, and refuses while the app runs.
    on      https and content on, with one user rule that hides the test page's heading.
    arm     reads status.json.content now, for the delta around one page load.
    off     content off and the test rule gone; https stays as the runbook left it.
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("before", "on", "arm", "off")]
  [string]$Step,
  [string]$Out = (Join-Path $env:PUBLIC "sieve-engine-live"),
  # With -Step on: the catalogue ids to hold, comma separated, for an arm of slice 10.
  [string[]]$Lists
)

$ErrorActionPreference = "Stop"
$Service = "sieve-engine"
$EngineDir = Join-Path $env:ProgramData "Sieve\engine"
$PolicyFile = Join-Path $EngineDir "policy.json"
$StatusFile = Join-Path $EngineDir "status.json"
# The test page: an RFC 2606 name, public so its chain anchors in a public root.
$TestRule = "example.com##h1"
$WaitSeconds = 20
. (Join-Path $PSScriptRoot 'live-lease.ps1')
. (Join-Path $PSScriptRoot 'engine-content-checks.ps1')
$liveLease = Enter-SieveLiveLease
try {

New-Item -ItemType Directory -Force $Out | Out-Null

function Assert-AppClosed {
  if (Get-Process sieve -ErrorAction SilentlyContinue) { throw "Close the Sieve app first: it sends content false whenever it runs." }
}

function Read-Policy {
  return Get-Content -Raw $PolicyFile | ConvertFrom-Json
}

# Written with no BOM: the engine's JSON reader refuses one, and a refused file reads as off.
function Write-Policy($policy) {
  (Get-Service $Service) | Stop-Service -ErrorAction SilentlyContinue
  (Get-Service $Service).WaitForStatus("Stopped", [TimeSpan]::FromSeconds($WaitSeconds))
  $policy | Add-Member -Force -NotePropertyName revision -NotePropertyValue ([int64]$policy.revision + 1)
  [IO.File]::WriteAllText($PolicyFile, ($policy | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))
  Start-Service $Service
  (Get-Service $Service).WaitForStatus("Running", [TimeSpan]::FromSeconds($WaitSeconds))
}

function Show-Content {
  $status = Get-Content -Raw $StatusFile | ConvertFrom-Json
  return $status.content | ConvertTo-Json -Depth 5
}

switch ($Step) {
  "before" {
    Assert-AppClosed
    Copy-Item $PolicyFile (Join-Path $Out "policy-before-content.json") -Force
    Show-Content | Out-File -Encoding utf8 (Join-Path $Out "content-before.json")
    Write-Host "Saved the policy and status.json's content section to $Out."
  }
  "on" {
    Assert-AppClosed
    $policy = Read-Policy
    $policy | Add-Member -Force -NotePropertyName https -NotePropertyValue $true
    $policy | Add-Member -Force -NotePropertyName content -NotePropertyValue $true
    $policy | Add-Member -Force -NotePropertyName user_rules -NotePropertyValue @(@($policy.user_rules) + $TestRule | Where-Object { $_ } | Select-Object -Unique)
    if ($Lists) { Set-PolicyLists $policy $Lists }
    Write-Policy $policy
    Write-Host "Content is on with the rule $TestRule. Run -Step arm, then load the page."
  }
  "arm" {
    Show-Content | Out-File -Encoding utf8 (Join-Path $Out "content-armed.json")
    Write-Host (Show-Content)
  }
  "off" {
    Assert-AppClosed
    $policy = Read-Policy
    $policy | Add-Member -Force -NotePropertyName content -NotePropertyValue $false
    $policy | Add-Member -Force -NotePropertyName user_rules -NotePropertyValue @(@($policy.user_rules) | Where-Object { $_ -and $_ -ne $TestRule })
    Write-Policy $policy
    Write-Host "Content is off and the test rule is gone."
  }
}

} finally { Exit-SieveLiveLease $liveLease }
