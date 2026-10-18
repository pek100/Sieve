# SERVICE_STOPPED can precede the process releasing its executable image.
# Retry only transient file I/O failures, while the service remains stopped.
function Copy-SieveStoppedEngine([string]$Source,[string]$Destination,[double]$Seconds=5) {
  if ($Seconds -le 0 -or $Seconds -gt 20) {throw 'Invalid binary copy deadline'}
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while ($true) {
    if ((Get-Service -Name 'sieve-engine').Status -ne 'Stopped') {throw 'Refusing binary replacement while sieve-engine is not stopped'}
    try {Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop;return}
    catch [IO.IOException] {
      if ($clock.Elapsed.TotalSeconds -ge $Seconds) {throw}
      Start-Sleep -Milliseconds 100
    }
  }
}
