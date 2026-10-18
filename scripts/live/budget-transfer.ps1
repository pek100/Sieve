# Cloudflare refuses a single 300 MB response (HTTP 403, observed 2026-10-18).
# Keep the same total workload: twelve 25 MB responses on one reused TCP
# connection, with one wall-clock deadline for the entire curl process.
function Read-SieveBudgetTransfer([string]$Text,[int]$ExitCode,[bool]$TimedOut) {
  $rows=@($Text -split '\r?\n' | Where-Object {$_ -ne ''})
  $bytes=[long]0;$connections=0;$valid=$rows.Count -eq 12 -and $ExitCode -eq 0 -and -not $TimedOut
  foreach($row in $rows) {
    if ($row -notmatch '^200 25000000 ([0-9]+)$') {$valid=$false;continue}
    $bytes+=25000000;$connections+=[int]$Matches[1]
  }
  [pscustomobject]@{Valid=($valid -and $connections -eq 1);Bytes=$bytes;Connections=$connections;Responses=$rows.Count;ExitCode=$ExitCode;TimedOut=$TimedOut;Raw=$Text}
}

function Invoke-SieveBudgetTransfer([int]$Seconds=60) {
  if ($Seconds -lt 1 -or $Seconds -gt 300) {throw 'Invalid transfer deadline'}
  $p=New-Object Diagnostics.Process
  $p.StartInfo=New-Object Diagnostics.ProcessStartInfo
  $p.StartInfo.FileName='curl.exe'
  $p.StartInfo.Arguments='--silent --show-error --fail --fail-early --noproxy "*" --http1.1 --max-time '+$Seconds+' --write-out "%{http_code} %{size_download} %{num_connects}\n"'+(' -o NUL "https://speed.cloudflare.com/__down?bytes=25000000"'*12)
  $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
  $p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
  $started=$false;$clock=[Diagnostics.Stopwatch]::StartNew()
  try {
    [void]$p.Start();$started=$true
    $output=$p.StandardOutput.ReadToEndAsync();$errorText=$p.StandardError.ReadToEndAsync()
    $remaining=[Math]::Max(0,[int](1000*$Seconds-$clock.Elapsed.TotalMilliseconds))
    $timedOut=-not $p.WaitForExit($remaining)
    if ($timedOut) {$p.Kill()}
    $p.WaitForExit()
    $result=Read-SieveBudgetTransfer $output.Result $p.ExitCode $timedOut
    $result | Add-Member NoteProperty Seconds $clock.Elapsed.TotalSeconds
    $result | Add-Member NoteProperty Error $errorText.Result
    return $result
  } finally {
    if ($started -and -not $p.HasExited) {$p.Kill();$p.WaitForExit()}
    $p.Dispose()
  }
}
