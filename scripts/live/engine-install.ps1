<#
.SYNOPSIS
  Live check for engine slice 2 (docs/plans/2026-10-17-https-filtering.md, slice 2):
  the per-machine installer, the sieve-engine service, its pipe, uninstall, and
  the kill and reboot tests of "Sieve off means a normal network".

.DESCRIPTION
  Run by a person, never by an agent. Most steps need an elevated PowerShell
  (Terminal (Admin)); `pipe-open` must run as a second, standard Windows user.
  Every step writes its evidence to -Out and prints PASS or FAIL per check.
  Order: before, install, app, pipe-open (as the other user), kill,
  reboot-prep, (reboot), after-reboot, uninstall. See docs/live/engine-slice-2.md.

  The engine changes nothing about traffic in slice 2, so the network listings
  must match the before-listing at every step.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\live\engine-install.ps1 -Step before
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("before", "install", "verify", "app", "pipe-open", "kill", "reboot-prep", "after-reboot", "uninstall")]
  [string]$Step,
  [string]$Installer = "",
  [string]$Out = (Join-Path $env:PUBLIC "sieve-engine-live")
)

$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 leaves $PSScriptRoot empty while parameter defaults are
# evaluated, so the default installer path is resolved here, in the body.
if (-not $Installer) {
  $Installer = Join-Path $PSScriptRoot "..\..\src-tauri\target\release\bundle\nsis\Sieve_0.1.0_x64-setup.exe"
}
$Service = "sieve-engine"
$Pipe = "\\.\pipe\sieve-engine"
$PipeShort = "sieve-engine"
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\sieve-engine"
# The install folder is the user's choice (E:\Sieve in the 2026-10-18 run), so it is
# read from where the service points, again after the installer ran.
function Get-InstallDir {
  $imagePath = (Get-ItemProperty $ServiceKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
  if ($imagePath) { return Split-Path -Parent ($imagePath.Trim().Trim('"').Split('"')[0]) }
  Join-Path $env:ProgramFiles "Sieve"
}
$InstallDir = Get-InstallDir
$EngineExe = Join-Path $InstallDir "sieve-engine.exe"
$Marker = "sieve-install.marker"
$ProgramDataSieve = Join-Path $env:ProgramData "Sieve"
# SYSTEM, Administrators, TrustedInstaller: the only principals that may change the engine's files.
$TrustedSids = @("S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
$script:Failed = 0

New-Item -ItemType Directory -Force $Out | Out-Null

function Write-Evidence([string]$name, [string]$text) {
  $text | Out-File -Encoding utf8 (Join-Path $Out $name)
}

function Check([string]$what, [bool]$ok, [string]$detail = "") {
  $line = "{0}  {1}{2}" -f ($(if ($ok) { "PASS" } else { "FAIL" })), $what, $(if ($detail) { "  ($detail)" } else { "" })
  if (-not $ok) { $script:Failed++ }
  Write-Host $line -ForegroundColor $(if ($ok) { "Green" } else { "Red" })
  $line | Out-File -Append -Encoding utf8 (Join-Path $Out "results.txt")
}

function Assert-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Step '$Step' needs an elevated PowerShell (Terminal (Admin))."
  }
}

# The four listings of the network rule, as comparable text.
function Get-Listings {
  $routes = Get-NetRoute -ErrorAction SilentlyContinue | Sort-Object AddressFamily, DestinationPrefix, InterfaceAlias, NextHop |
    ForEach-Object { "{0} via {1} on {2} metric {3}" -f $_.DestinationPrefix, $_.NextHop, $_.InterfaceAlias, $_.RouteMetric }
  $dns = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Sort-Object InterfaceAlias, AddressFamily |
    ForEach-Object { "{0} {1}: {2}" -f $_.InterfaceAlias, $_.AddressFamily, ($_.ServerAddresses -join ",") }
  $proxy = (netsh winhttp show proxy) -join "`n"
  $firewall = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { $_.Name }
  [ordered]@{
    routes   = ($routes -join "`n")
    dns      = ($dns -join "`n")
    proxy    = $proxy
    firewall = ($firewall -join "`n")
  }
}

function Save-Listings([string]$tag) {
  $l = Get-Listings
  foreach ($k in $l.Keys) { Write-Evidence "$tag-$k.txt" $l[$k] }
  Write-Evidence "$tag-route-print.txt" ((route print) -join "`n")
  $l
}

function Compare-WithBefore([string]$tag) {
  $now = Save-Listings $tag
  foreach ($k in $now.Keys) {
    $beforeFile = Join-Path $Out "before-$k.txt"
    if (-not (Test-Path $beforeFile)) { Check "$k listing has a before-listing" $false "run -Step before first"; continue }
    $before = (Get-Content -Raw -Encoding utf8 $beforeFile).Trim()
    $same = $before -eq $now[$k].Trim()
    if (-not $same) {
      $diff = Compare-Object ($before -split "`n") ($now[$k].Trim() -split "`n") | ForEach-Object { "{0} {1}" -f $_.SideIndicator, $_.InputObject }
      Write-Evidence "$tag-$k-diff.txt" ($diff -join "`n")
    }
    Check "$k listing matches the before-listing ($tag)" $same $(if (-not $same) { "see $tag-$k-diff.txt" })
  }
  $sieveRoutes = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq "Sieve" }
  Check "no route on an interface named Sieve ($tag)" (@($sieveRoutes).Count -eq 0)
}

function Test-Network([string]$tag) {
  $dnsOk = $false; $httpsOk = $false
  try { $dnsOk = @(Resolve-DnsName example.com -ErrorAction Stop).Count -gt 0 } catch { }
  $code = (& curl.exe -s -o NUL -m 10 -w "%{http_code}" -I https://example.com) 2>$null
  $httpsOk = $code -match "^[23]"
  Check "name lookup works ($tag)" $dnsOk
  Check "HTTPS works ($tag)" $httpsOk "curl -I https://example.com gave $code"
}

function Get-ServiceFacts {
  $qc = (sc.exe qc $Service) -join "`n"
  $query = (sc.exe queryex $Service) -join "`n"
  $failure = (sc.exe qfailure $Service) -join "`n"
  $privs = (sc.exe qprivs $Service) -join "`n"
  [ordered]@{ qc = $qc; queryex = $query; qfailure = $failure; qprivs = $privs }
}

# Who besides SYSTEM, Administrators and TrustedInstaller can change $path: its owner
# when untrusted, and every allow rule that grants a write, delete or ACL right. By SID,
# so the answer does not depend on the Windows display language.
$WriteRights = [System.Security.AccessControl.FileSystemRights]"WriteData, AppendData, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles, WriteAttributes, Delete, ChangePermissions, TakeOwnership"
function Get-NonAdminWriters([string]$path) {
  $acl = Get-Acl -LiteralPath $path
  $sidOf = { param($id) try { $id.Translate([Security.Principal.SecurityIdentifier]).Value } catch { "$id" } }
  $found = @()
  $owner = & $sidOf (New-Object Security.Principal.NTAccount($acl.Owner))
  if ($TrustedSids -notcontains $owner) { $found += "owner $($acl.Owner)" }
  foreach ($r in $acl.Access) {
    if ($r.AccessControlType -ne "Allow") { continue }
    $sid = & $sidOf $r.IdentityReference
    if ($TrustedSids -contains $sid) { continue }
    $inheritOnly = ($r.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
    # CREATOR OWNER on children only becomes whoever creates a file, who needs write here first.
    if ($inheritOnly -and $sid -eq "S-1-3-0") { continue }
    if (($r.FileSystemRights -band $WriteRights) -ne 0 -or ([int]$r.FileSystemRights -band 0x50000000) -ne 0) {
      $found += "{0} {1}{2}" -f $r.IdentityReference, $r.FileSystemRights, $(if ($inheritOnly) { " (inherit only)" } else { "" })
    }
  }
  $found
}

function Test-PipeOpen {
  # Opens the engine's pipe as the current user and reports what Windows said.
  $client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $PipeShort, [System.IO.Pipes.PipeDirection]::InOut)
  try {
    $client.Connect(3000)
    "CONNECTED"
  } catch [System.UnauthorizedAccessException] {
    "ACCESS DENIED"
  } catch [System.TimeoutException] {
    "TIMEOUT (pipe not there or busy)"
  } catch {
    "ERROR: $($_.Exception.Message)"
  } finally {
    $client.Dispose()
  }
}

Write-Host "Sieve engine live check, step '$Step'. Evidence: $Out"
"==== $(Get-Date -Format s) step $Step as $(whoami)" | Out-File -Append -Encoding utf8 (Join-Path $Out "results.txt")

# The install step's checks on what the installer left: used by `install` and by `verify`
# (verify checks an existing install without running the installer again).
function Test-Installed([string]$tag) {
  $InstallDir = Get-InstallDir
  $EngineExe = Join-Path $InstallDir "sieve-engine.exe"
  $f = Get-ServiceFacts
  foreach ($k in $f.Keys) { Write-Evidence "$tag-sc-$k.txt" $f[$k] }
  Check "sc qc: runs as LocalSystem" ($f.qc -match "SERVICE_START_NAME\s*:\s*LocalSystem")
  Check "sc qc: automatic start" ($f.qc -match "START_TYPE\s*:\s*2\s+AUTO_START")
  Check "sc qc: binary is the engine in the chosen folder" ($f.qc -match [regex]::Escape($EngineExe)) $EngineExe
  Check "sc queryex: running" ($f.queryex -match "STATE\s*:\s*4\s+RUNNING")
  Check "sc queryex: did not refuse its folder (exit code 3)" (-not ($f.queryex -match "SERVICE_EXIT_CODE\s*:\s*3\b"))
  # The install folder (2026-10-18 finding: E:\Sieve inherited Authenticated Users Modify).
  $dirAcl = Get-Acl -LiteralPath $InstallDir
  Write-Evidence "$tag-folder-acl.txt" (((icacls $InstallDir) -join "`n") + "`n`nSDDL: " + $dirAcl.Sddl)
  Write-Evidence "$tag-engine-acl.txt" ((icacls $EngineExe) -join "`n")
  $inherited = @($dirAcl.Access | Where-Object { $_.IsInherited })
  Check "install folder DACL is protected (no inherited ACEs)" ($dirAcl.AreAccessRulesProtected -and $inherited.Count -eq 0) "$InstallDir, $($inherited.Count) inherited"
  $writers = @(Get-NonAdminWriters $InstallDir)
  Check "install folder grants write only to SYSTEM and Administrators" ($writers.Count -eq 0) ($writers -join "; ")
  $fileWriters = @(Get-ChildItem -LiteralPath $InstallDir -Force | ForEach-Object {
      $name = $_.Name
      Get-NonAdminWriters $_.FullName | ForEach-Object { "${name}: $_" }
    })
  Check "binary folder grants no write to non-admins (every file in it, the engine included)" ($fileWriters.Count -eq 0) ($fileWriters -join "; ")
  Check "the installer's marker is in the folder" (Test-Path -LiteralPath (Join-Path $InstallDir $Marker))
  Check "no last-error.txt (the engine did not refuse to start)" (-not (Test-Path (Join-Path $ProgramDataSieve "engine\last-error.txt")))
  Check "sc qfailure: restart twice, reset after 3600 s" (($f.qfailure -match "RESET_PERIOD \(in seconds\)\s*:\s*3600") -and (([regex]::Matches($f.qfailure, "RESTART -- Delay = 5000")).Count -eq 2))
  Check "sc qprivs: only SeChangeNotifyPrivilege" (($f.qprivs -match "SeChangeNotifyPrivilege") -and -not ($f.qprivs -match "SeDebugPrivilege|SeTcbPrivilege|SeLoadDriverPrivilege"))
  $acl = (icacls $ProgramDataSieve) -join "`n"
  Write-Evidence "$tag-programdata-acl.txt" $acl
  Check "ProgramData\Sieve: SYSTEM and Administrators only" (($acl -match "NT AUTHORITY\\SYSTEM:\(OI\)\(CI\)\(F\)") -and ($acl -match "BUILTIN\\Administrators:\(OI\)\(CI\)\(F\)") -and -not ($acl -match "Users:|Everyone:|Authenticated Users:|CREATOR OWNER:"))
  $state = Get-Content -Raw (Join-Path $ProgramDataSieve "engine\state.json") | ConvertFrom-Json
  $me = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
  Check "state.json records the installing user" ($state.owner_sid -eq $me) "recorded $($state.owner_sid), you are $me"
  try {
    $pipeAcl = (Get-Acl $Pipe).Access | ForEach-Object { "{0} {1} {2}" -f $_.IdentityReference, $_.AccessControlType, $_.FileSystemRights }
    Write-Evidence "$tag-pipe-acl.txt" ($pipeAcl -join "`n")
    Check "pipe DACL lists SYSTEM, Administrators and the installing user only" (@($pipeAcl).Count -eq 3) ($pipeAcl -join "; ")
  } catch {
    Check "pipe DACL readable" $false $_.Exception.Message
  }
  Compare-WithBefore $tag
  Test-Network $tag
}

# Never stop silently (seen live 2026-10-18: steps ended with no PASS/FAIL lines). Any error that
# ends a step is printed and recorded in results.txt as an ERROR line, and counts as a failure.
trap {
  $msg = "ERROR  step '$Step' stopped at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message
  Write-Host $msg -ForegroundColor Red
  $msg | Out-File -Append -Encoding utf8 (Join-Path $Out "results.txt")
  $script:Failed++
  Write-Host ("{0} check(s) failed. Evidence in {1}" -f $script:Failed, $Out) -ForegroundColor Red
  exit $script:Failed
}

switch ($Step) {
  "before" {
    Assert-Admin
    Save-Listings "before" | Out-Null
    Test-Network "before"
    Check "the service is not installed yet" ($null -eq (Get-Service $Service -ErrorAction SilentlyContinue)) "uninstall any earlier Sieve first"
  }

  "install" {
    Assert-Admin
    $installer = (Resolve-Path $Installer).Path
    Write-Host "Running $installer. Approve the UAC prompt and click through the installer."
    Write-Evidence "installer-hash.txt" ("{0}  {1}" -f (Get-FileHash $installer).Hash, $installer)
    Start-Process -FilePath $installer -Wait
    # The NSIS installer relaunches itself elevated, so -Wait can return before anything is
    # installed (seen live 2026-10-18). Wait for the service itself, up to 5 minutes.
    $deadline = (Get-Date).AddMinutes(5)
    while (-not (Get-Service $Service -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    Check "the service appeared after the installer" ([bool](Get-Service $Service -ErrorAction SilentlyContinue))
    Start-Sleep -Seconds 3
    Test-Installed "install"
  }

  "verify" {
    # The install step's checks against an existing install, without running the installer.
    Assert-Admin
    Check "the service is installed" ([bool](Get-Service $Service -ErrorAction SilentlyContinue))
    Test-Installed "verify"
  }

  "app" {
    Write-Host "Open Sieve from the Start menu (the installed one, not pnpm tauri dev),"
    Write-Host "go to Settings > Filtering and look at the Engine block."
    $answer = Read-Host "Does it say 'Installed, not filtering' with 'Engine version 0.1.0'? (y/n)"
    Check "the app shows Installed, not filtering" ($answer -eq "y")
    Write-Host "Now start pnpm tauri dev (a copy outside Program Files) and look at the same block."
    $answer = Read-Host "Does the dev copy say 'Installed' with 'This copy of Sieve is not the installed one'? (y/n, or s to skip)"
    if ($answer -ne "s") { Check "a copy outside Program Files is refused by the engine" ($answer -eq "y") }
  }

  "pipe-open" {
    # Run as a SECOND, standard Windows user, not elevated, for example:
    #   runas /user:<other user> "powershell -ExecutionPolicy Bypass -File <repo>\scripts\live\engine-install.ps1 -Step pipe-open -Out C:\Users\Public\sieve-engine-live"
    $who = whoami
    $result = Test-PipeOpen
    Write-Evidence "pipe-open-$($env:USERNAME).txt" "$who`n$result"
    Check "pipe open as $who is denied" ($result -eq "ACCESS DENIED") $result
  }

  "kill" {
    Assert-Admin
    $svcPid = (Get-CimInstance Win32_Service -Filter "Name='$Service'").ProcessId
    Check "the service runs before the kill" ($svcPid -gt 0) "pid $svcPid"
    taskkill.exe /F /PID $svcPid | Out-Null
    $killedAt = Get-Date
    Start-Sleep -Seconds 1
    Test-Network "kill +1s"
    # Timed at the network check itself; the listing comparison below is slow (firewall dump)
    # and is not part of "the network works within 5 s" (live 2026-10-18 measured 5.3 s with it).
    $elapsed = ((Get-Date) - $killedAt).TotalSeconds
    Check "network checked within 5 s of the kill" ($elapsed -le 5) ("{0:N1} s" -f $elapsed)
    Compare-WithBefore "kill"
    Start-Sleep -Seconds 10
    $state = (Get-Service $Service).Status
    Check "the SCM restarted the engine after 5 s (recovery)" ($state -eq "Running") "$state"
  }

  "reboot-prep" {
    Assert-Admin
    sc.exe config $Service start= demand | Out-Null
    Check "start type set to manual for the reboot test" (((sc.exe qc $Service) -join "`n") -match "DEMAND_START")
    Write-Host "Now reboot. After signing in, run -Step after-reboot in an elevated PowerShell."
  }

  "after-reboot" {
    Assert-Admin
    Test-Network "after reboot"
    Compare-WithBefore "after-reboot"
    $state = (Get-Service $Service).Status
    Check "the engine did not start (manual start type)" ($state -eq "Stopped") "$state"
    sc.exe config $Service start= auto | Out-Null
    Start-Service $Service
    Check "start type back to automatic and running" ((((sc.exe qc $Service) -join "`n") -match "AUTO_START") -and ((Get-Service $Service).Status -eq "Running"))
  }

  "uninstall" {
    Assert-Admin
    # The verb twice first (idempotent), then the NSIS uninstaller, whose hook runs it a third time.
    $first = (& $EngineExe uninstall) -join "`n"; $firstCode = $LASTEXITCODE
    $second = (& $EngineExe uninstall) -join "`n"; $secondCode = $LASTEXITCODE
    Write-Evidence "uninstall-verb-1.txt" "exit $firstCode`n$first"
    Write-Evidence "uninstall-verb-2.txt" "exit $secondCode`n$second"
    Check "sieve-engine.exe uninstall succeeds" ($firstCode -eq 0) "see uninstall-verb-1.txt"
    Check "sieve-engine.exe uninstall again succeeds (idempotent)" ($secondCode -eq 0) "see uninstall-verb-2.txt"
    $uninstaller = Join-Path $InstallDir "uninstall.exe"
    Write-Host "Running $uninstaller. Approve the UAC prompt and click through."
    Start-Process -FilePath $uninstaller -Wait
    Start-Sleep -Seconds 3
    $sc = (sc.exe query $Service) -join "`n"
    Write-Evidence "uninstall-sc-query.txt" $sc
    Check "no service left" ($sc -match "1060")
    Check "no ProgramData\Sieve left" (-not (Test-Path $ProgramDataSieve))
    Check "nothing under HKLM\SYSTEM\CurrentControlSet\Services\sieve-engine" (-not (Test-Path $ServiceKey))
    Check "no sieve-engine.exe left in the install folder" (-not (Test-Path $EngineExe)) $EngineExe
    Check "no install folder left" (-not (Test-Path -LiteralPath $InstallDir)) $InstallDir
    Compare-WithBefore "uninstall"
    Test-Network "uninstall"
  }
}

Write-Host ""
Write-Host ("{0} check(s) failed. Evidence in {1}" -f $script:Failed, $Out) -ForegroundColor $(if ($script:Failed -eq 0) { "Green" } else { "Red" })
exit $script:Failed
