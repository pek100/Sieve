<#
.SYNOPSIS
  The parts of engine-ca.ps1 that decide something and touch nothing, so a law
  (tests/laws/live-ca-script.test.ts) can run them without elevation.
#>

# The policy with only the switch and the revision changed: every other field is
# the user's. The depth keeps the nested list entries, which the default of 2 flattens.
function New-HttpsPolicyJson($policy, [bool]$on) {
  $policy | Add-Member -Force -NotePropertyName revision -NotePropertyValue ([int64]$policy.revision + 1)
  $policy | Add-Member -Force -NotePropertyName https -NotePropertyValue $on
  return $policy | ConvertTo-Json -Depth 10
}

# The policy of the slice 6 route: with `sieving` off `wanted()` in tls/intercept.rs
# is false, and with `engine` off no flow reaches the relay, so the floor checks would
# pass with nothing intercepted. These two, the switch and the revision change;
# every other field is the user's.
function New-InterceptionPolicyJson($policy) {
  $policy | Add-Member -Force -NotePropertyName engine -NotePropertyValue $true
  $policy | Add-Member -Force -NotePropertyName sieving -NotePropertyValue $true
  return New-HttpsPolicyJson $policy $true
}

# The revision of the policy file as just written.
function Get-PolicyRevision([string]$json) {
  return [int64]($json | ConvertFrom-Json).revision
}

# True only for a status of this run: a run that ended uncleanly leaves its file, and a
# new service reports Running before it writes one, so routes and switches alone can be
# the last run's. A policy file the engine refused loads at another revision and fails too.
function Test-InterceptionUp($status, [int64]$revision) {
  if ($null -eq $status) { return $false }
  return [bool]($status.routes_up -and $status.policy.https -and $status.policy.sieving -and [int64]$status.policy.revision -eq $revision)
}

# What certutil's answer about the key says: "refused", "missing", "readable" or "error".
function Get-KeyAnswer([string]$text, [int]$exitCode) {
  if ($exitCode -eq 0) { return "readable" }
  if ($text -match "(?i)NTE_BAD_KEYSET|0x80090016") { return "missing" }
  if ($text -match "(?i)access (is )?denied|E_ACCESSDENIED|NTE_PERM|0x80070005|0x80090010") { return "refused" }
  return "error"
}

# True only when the facts read as SYSTEM positively show no export and a DACL of
# SYSTEM alone. No facts, or an empty DACL, is not observed, and not a pass.
function Test-KeyFacts($facts) {
  if ($null -eq $facts) { return $false }
  $sids = @($facts.dacl_sids)
  if ($sids.Count -eq 0) { return $false }
  return $facts.export_policy -eq "None" -and -not ($sids | Where-Object { $_ -ne "S-1-5-18" })
}

# What the one-shot SYSTEM task runs: the key's export policy and DACL, as JSON.
function New-KeyProbeScript([string]$keyName, [string]$resultFile) {
  return @"
Add-Type -AssemblyName System.Core
`$provider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
`$key = [Security.Cryptography.CngKey]::Open('$keyName', `$provider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)
`$daclOnly = [Enum]::ToObject([Security.Cryptography.CngPropertyOptions], 4)
`$bytes = `$key.GetProperty('Security Descr', `$daclOnly).GetValue()
`$descriptor = New-Object Security.AccessControl.RawSecurityDescriptor(`$bytes, 0)
`$sids = @(`$descriptor.DiscretionaryAcl | ForEach-Object { `$_.SecurityIdentifier.Value })
[pscustomobject]@{ export_policy = [string]`$key.ExportPolicy; dacl_sids = `$sids } | ConvertTo-Json | Out-File -Encoding utf8 '$resultFile'
"@
}
