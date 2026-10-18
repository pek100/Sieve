<#
.SYNOPSIS
  Runs the whole engine slice 3 live check in order, in one elevated PowerShell:
  update the install, verify it, then the engine-route steps (before, adguard, on,
  soak, kill, stall, budget, adguard-back). The reboot test is separate (it needs
  a restart): -Step reboot-prep, reboot, -Step after-reboot in engine-route.ps1.

.DESCRIPTION
  Run by a person, never by an agent, from Terminal (Admin):
    powershell -ExecutionPolicy Bypass -File scripts\live\run-slice-3.ps1
  It pauses where you act in Sieve or use the computer. A failed step does not stop
  the run; the summary at the end lists every step's result. Evidence for each step
  is in C:\Users\Public\sieve-engine-live (results.txt).
  Emergency at any point: Start menu "Sieve - restore network", or
  E:\Sieve\sieve-engine.exe restore (wherever Sieve is installed).
#>
param(
  # Skip the installer if this version is already installed.
  [switch]$SkipUpdate
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $here "..\..")).Path
$installer = Join-Path $repo "src-tauri\target\release\bundle\nsis\Sieve_0.1.0_x64-setup.exe"
$stall = Join-Path $repo "engine\target\stall\release\sieve-engine.exe"

$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Run this from Terminal (Admin)." -ForegroundColor Red
  exit 1
}

$results = [ordered]@{}
. (Join-Path $PSScriptRoot 'live-lease.ps1')
$liveLease = Enter-SieveLiveLease
try {

function Pause-For([string]$what) {
  Write-Host ""
  Write-Host $what -ForegroundColor Cyan
  Read-Host "Press Enter when done (or type s and Enter to skip the next step)"
}

function Run([string]$label, [string]$script, [string[]]$stepArgs) {
  Write-Host ""
  Write-Host "=== $label ===" -ForegroundColor Yellow
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here $script) @stepArgs
  $code = $LASTEXITCODE
  $results[$label] = $(if ($code -eq 0) { "PASS" } else { "FAIL ($code check(s))" })
}

function Skip([string]$label) { $results[$label] = "skipped" }

# 1. Update the install (the installer relaunches itself elevated; wait for its window to close).
if (-not $SkipUpdate) {
  if (-not (Test-Path $installer)) { Write-Host "Installer not found: $installer" -ForegroundColor Red; exit 1 }
  Write-Host "Running the installer. Keep the same folder (for example E:\Sieve) and click through." -ForegroundColor Cyan
  Start-Process -FilePath $installer -Wait
  $answer = Pause-For "Wait until the installer says it has finished and its window is closed."
  if ($answer -eq "s") { Skip "verify install" } else { Run "verify install" "engine-install.ps1" @("-Step", "verify") }
} else { Skip "update" }

# 2. Before-listings, with routing off.
Run "before" "engine-route.ps1" @("-Step", "before")

# 3. AdGuard refusal and the pause offer (the step itself tells you what to click).
Run "adguard (refusal and pause)" "engine-route.ps1" @("-Step", "adguard")

# 4. Routing on.
Run "on" "engine-route.ps1" @("-Step", "on")

# 5. Soak: 30 minutes of normal use.
$answer = Pause-For "Use the computer normally for about 30 minutes with routing on (browse, a video call, a game launcher). Leave this window open."
if ($answer -eq "s") { Skip "soak" } else { Run "soak (attribution)" "engine-route.ps1" @("-Step", "soak") }

# 6. Crash tests.
Run "kill" "engine-route.ps1" @("-Step", "kill")
if (Test-Path $stall) {
  Run "stall (watchdog)" "engine-route.ps1" @("-Step", "stall", "-StallBuild", $stall)
} else {
  Write-Host "Stall build not found at $stall (build it: cargo build --release -p sieve-engine --features stall --target-dir target\stall in engine\)." -ForegroundColor Red
  Skip "stall (watchdog)"
}

# 7. Budget: idle CPU and a 300 MB download through the engine.
$answer = Pause-For "Next is the CPU and speed budget: keep the computer idle for about 2 minutes (no downloads, no video). It downloads 300 MB."
if ($answer -eq "s") { Skip "budget" } else { Run "budget (CPU, memory)" "engine-route.ps1" @("-Step", "budget") }

# 8. AdGuard back on.
Run "adguard-back" "engine-route.ps1" @("-Step", "adguard-back")

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Yellow
foreach ($k in $results.Keys) {
  $v = $results[$k]
  $color = if ($v -eq "PASS") { "Green" } elseif ($v -eq "skipped") { "DarkGray" } else { "Red" }
  Write-Host ("{0,-30} {1}" -f $k, $v) -ForegroundColor $color
}
Write-Host ""
Write-Host "Evidence: C:\Users\Public\sieve-engine-live\results.txt"
Write-Host "Reboot test (separate, at a restart that suits you):"
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\live\engine-route.ps1 -Step reboot-prep"
Write-Host "  (reboot, then)"
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\live\engine-route.ps1 -Step after-reboot"
} finally { Exit-SieveLiveLease $liveLease }
