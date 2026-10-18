# Cloudflare refuses a single 300 MB response (HTTP 403, observed 2026-10-18).
# Keep the same total workload: twelve 25 MB responses on one reused TCP
# connection, with one wall-clock deadline for the entire curl process.
function Read-SieveBudgetTransfer([string]$Text,[int]$ExitCode,[bool]$TimedOut,[int]$Count=12,[long]$Size=25000000) {
  if ($Count -lt 1 -or $Size -lt 1) {throw 'Count and Size must be positive'}
  $rows=@($Text -split '\r?\n' | Where-Object {$_ -ne ''})
  $bytes=[decimal]0;$connections=[long]0;$valid=$rows.Count -eq $Count -and $ExitCode -eq 0 -and -not $TimedOut
  foreach($row in $rows) {
    if ($row -notmatch '\A200 ([0-9]+) ([0-9]+)\z') {$valid=$false;continue}
    $body=[decimal]$Matches[1]
    if ($body -ne $Size) {$valid=$false}
    $bytes+=$body;$connections+=[long]$Matches[2]
  }
  [pscustomobject]@{Valid=($valid -and $connections -eq 1 -and $bytes -eq ([decimal]$Count*$Size));Bytes=$bytes;Connections=$connections;Responses=$rows.Count;ExitCode=$ExitCode;TimedOut=$TimedOut;Raw=$Text}
}

function Get-SieveBudgetArguments([int]$Seconds=60,[string]$Url='', [int]$Count=12,[long]$Size=25000000,[string]$Proxy='') {
  if ($Seconds -lt 1 -or $Seconds -gt 300) {throw 'Invalid transfer deadline'}
  if ($Count -lt 1 -or $Size -lt 1) {throw 'Count and Size must be positive'}
  if (-not $Url) {$Url='https://speed.cloudflare.com/__down?bytes='+$Size}
  # ProcessStartInfo on Windows PowerShell accepts a command line, not argv.
  # URLs may contain spaces, but never a quote, backslash or control character.
  foreach($value in @($Url,$Proxy)) {
    if ($value -match '["\\\x00-\x1f]') {throw 'Unsafe URL or proxy argument'}
  }
  $uri=$null
  if (-not [uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -notin @('http','https')) {throw 'Url must be HTTP or HTTPS'}
  $proxyArgs=if($Proxy){'-x "'+$Proxy+'"'}else{'--noproxy "*"'}
  return '--silent --show-error --fail --fail-early '+$proxyArgs+' --http1.1 --max-time '+$Seconds+' --write-out "%{http_code} %{size_download} %{num_connects}\n"'+((' -o NUL "'+$Url+'"')*$Count)
}

# WhileRunning, when given, runs every PollMs while curl runs, so a caller can
# watch for state that would contaminate the sample (it must not block).
function Invoke-SieveBudgetTransfer([int]$Seconds=60,[string]$Url='', [int]$Count=12,[long]$Size=25000000,[string]$Proxy='',[scriptblock]$WhileRunning=$null,[int]$PollMs=500) {
  $arguments=Get-SieveBudgetArguments -Seconds $Seconds -Url $Url -Count $Count -Size $Size -Proxy $Proxy
  $p=New-Object Diagnostics.Process
  $p.StartInfo=New-Object Diagnostics.ProcessStartInfo
  $p.StartInfo.FileName='curl.exe'
  $p.StartInfo.Arguments=$arguments
  $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
  $p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
  # An explicit proxy must not be bypassed by an inherited NO_PROXY setting.
  if ($Proxy) {$p.StartInfo.EnvironmentVariables['NO_PROXY']='';$p.StartInfo.EnvironmentVariables['no_proxy']=''}
  $started=$false;$clock=[Diagnostics.Stopwatch]::StartNew()
  try {
    [void]$p.Start();$started=$true
    $output=$p.StandardOutput.ReadToEndAsync();$errorText=$p.StandardError.ReadToEndAsync()
    $timedOut=$false
    while ($true) {
      $remaining=[Math]::Max(0,[int](1000*$Seconds-$clock.Elapsed.TotalMilliseconds))
      $slice=if($WhileRunning){[Math]::Min($remaining,$PollMs)}else{$remaining}
      if ($p.WaitForExit($slice)) {break}
      if ($slice -ge $remaining) {$timedOut=$true;break}
      & $WhileRunning
    }
    if ($timedOut) {$p.Kill()}
    $p.WaitForExit()
    $result=Read-SieveBudgetTransfer $output.Result $p.ExitCode $timedOut -Count $Count -Size $Size
    $result | Add-Member NoteProperty Seconds $clock.Elapsed.TotalSeconds
    $result | Add-Member NoteProperty Error $errorText.Result
    return $result
  } finally {
    if ($started -and -not $p.HasExited) {$p.Kill();$p.WaitForExit()}
    $p.Dispose()
  }
}
