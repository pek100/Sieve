# Shared by live runners. The open file handle is the lock, so a killed
# PowerShell releases it automatically. The JSON is diagnostic metadata,
# never executable input. Children may inherit only from an active ancestor.
function Enter-SieveLiveLease([string]$Path = (Join-Path $env:PUBLIC 'sieve-engine-live\runner.lock')) {
  $previousToken = $env:SIEVE_LIVE_RUN_TOKEN
  $previousOwner = $env:SIEVE_LIVE_RUN_OWNER
  if ($previousToken -and $previousOwner -match '^\d+$') {
    try {
      $reader = $null
      $read = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
      try { $reader = New-Object IO.StreamReader($read); $owner = $reader.ReadToEnd() | ConvertFrom-Json }
      finally { if ($reader) {$reader.Dispose()} else {$read.Dispose()} }
      if ($owner.Token -eq $previousToken -and "$($owner.Pid)" -eq $previousOwner) {
        $ancestor = $PID
        for ($depth=0; $depth -lt 16 -and $ancestor -gt 0; $depth++) {
          $ancestor = (Get-CimInstance Win32_Process -Filter "ProcessId=$ancestor" -ErrorAction Stop).ParentProcessId
          if ("$ancestor" -eq $previousOwner) {
            # The ancestor must still hold the file, not just stale metadata.
            $probe=$null
            try { $probe=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
            catch [IO.IOException] { return [pscustomobject]@{Inherited=$true;Stream=$null} }
            finally { if($probe){$probe.Dispose()} }
            break
          }
        }
      }
    } catch { # Fall through to an ordinary exclusive acquisition.
    }
  }
  [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
  try { $stream=[IO.File]::Open($Path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read) }
  catch [IO.IOException] { throw 'Another Sieve live runner holds the test lock. Let that run finish before starting another.' }
  try {
    $token=[guid]::NewGuid().ToString('N')
    $bytes=[Text.Encoding]::UTF8.GetBytes((@{Pid=$PID;Token=$token;Started=(Get-Date).ToString('o')} | ConvertTo-Json -Compress))
    $stream.SetLength(0)
    $stream.Write($bytes,0,$bytes.Length)
    $stream.Flush()
    $env:SIEVE_LIVE_RUN_TOKEN=$token
    $env:SIEVE_LIVE_RUN_OWNER="$PID"
    return [pscustomobject]@{Inherited=$false;Stream=$stream;PreviousToken=$previousToken;PreviousOwner=$previousOwner}
  } catch { $stream.Dispose(); throw }
}

function Exit-SieveLiveLease($Lease) {
  if ($Lease -and -not $Lease.Inherited) {
    $Lease.Stream.Dispose()
    $env:SIEVE_LIVE_RUN_TOKEN=$Lease.PreviousToken
    $env:SIEVE_LIVE_RUN_OWNER=$Lease.PreviousOwner
  }
}
