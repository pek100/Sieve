# The short-lived gate serializes acquisitions; the long-lived file handles
# keep the run leased. Children retain a read handle, so killing their parent
# cannot unlock an active child. The JSON is metadata, never executable input.
function Enter-SieveLiveLease([string]$Path = (Join-Path $env:PUBLIC 'sieve-engine-live\runner.lock')) {
  $previousToken=$env:SIEVE_LIVE_RUN_TOKEN
  $previousOwner=$env:SIEVE_LIVE_RUN_OWNER
  $busy='Another Sieve live runner holds the test lock. Let that run finish before starting another.'
  [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
  $gate=$null;$gateClock=[Diagnostics.Stopwatch]::StartNew()
  while (-not $gate) {
    try {$gate=[IO.File]::Open($Path+'.gate',[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    catch [IO.IOException] {
      if ($gateClock.Elapsed.TotalSeconds -ge 2) {throw $busy}
      Start-Sleep -Milliseconds 50
    }
  }
  try {
    if ($previousToken -and $previousOwner -match '^\d+$') {
      try {
        $reader=$null
        $read=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        try {$reader=New-Object IO.StreamReader($read);$owner=$reader.ReadToEnd() | ConvertFrom-Json}
        finally {if($reader){$reader.Dispose()}else{$read.Dispose()}}
        if ($owner.Token -eq $previousToken -and "$($owner.Pid)" -eq $previousOwner) {
          $ancestor=$PID
          for ($depth=0;$depth -lt 16 -and $ancestor -gt 0;$depth++) {
            $ancestor=(Get-CimInstance Win32_Process -Filter "ProcessId=$ancestor" -ErrorAction Stop).ParentProcessId
            if ("$ancestor" -eq $previousOwner) {
              $probe=$null;$active=$false
              try {$probe=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
              catch [IO.IOException] {$active=$true}
              finally {if($probe){$probe.Dispose()}}
              if ($active) {
                $hold=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                return [pscustomobject]@{Inherited=$true;Stream=$hold}
              }
              break
            }
          }
        }
      } catch { # Invalid inheritance falls through to ordinary acquisition.
      }
    }
    # Share=None also detects surviving child read handles. The gate prevents
    # a competing acquisition between this probe and the owner's shared handle.
    try {$probe=[IO.File]::Open($Path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    catch [IO.IOException] {throw $busy}
    $probe.Dispose()
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
      $token=[guid]::NewGuid().ToString('N')
      $bytes=[Text.Encoding]::UTF8.GetBytes((@{Pid=$PID;Token=$token;Started=(Get-Date).ToString('o')} | ConvertTo-Json -Compress))
      $stream.SetLength(0);$stream.Write($bytes,0,$bytes.Length);$stream.Flush()
      $env:SIEVE_LIVE_RUN_TOKEN=$token;$env:SIEVE_LIVE_RUN_OWNER="$PID"
      return [pscustomobject]@{Inherited=$false;Stream=$stream;PreviousToken=$previousToken;PreviousOwner=$previousOwner}
    } catch {$stream.Dispose();throw}
  } finally {$gate.Dispose()}
}

function Exit-SieveLiveLease($Lease) {
  if ($Lease) {
    $Lease.Stream.Dispose()
    if (-not $Lease.Inherited) {
      $env:SIEVE_LIVE_RUN_TOKEN=$Lease.PreviousToken
      $env:SIEVE_LIVE_RUN_OWNER=$Lease.PreviousOwner
    }
  }
}
