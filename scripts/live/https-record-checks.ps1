<#
.SYNOPSIS
  The parts of https-record.ps1 that decide something and touch nothing, so a law
  (tests/laws/live-ca-script.test.ts) can run them with no network.
#>

$script:TYPE_HTTPS = 65
$script:CLASS_IN = 1
$script:HEADER_BYTES = 12
$script:PARAM_ECH = 5
$script:COMPRESSED = 0xC0

# One question, recursion desired, no EDNS: a stripped answer is possible only with no DO.
function New-HttpsQuery([string]$name, [int]$id) {
  $bytes = New-Object Collections.Generic.List[byte]
  $bytes.AddRange([byte[]](($id -shr 8), ($id -band 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
  foreach ($label in $name.TrimEnd(".").Split(".")) {
    $bytes.Add([byte]$label.Length)
    $bytes.AddRange([Text.Encoding]::ASCII.GetBytes($label))
  }
  $bytes.Add(0)
  $bytes.AddRange([byte[]](0, $script:TYPE_HTTPS, 0, $script:CLASS_IN))
  return , $bytes.ToArray()
}

function Read-U16([byte[]]$bytes, [int]$at) {
  return [int]$bytes[$at] * 256 + [int]$bytes[$at + 1]
}

# The position after a name: its labels, up to the end or a compression pointer.
function Skip-DnsName([byte[]]$bytes, [int]$at) {
  while ($true) {
    $length = [int]$bytes[$at]
    if ($length -eq 0) { return $at + 1 }
    if (($length -band $script:COMPRESSED) -eq $script:COMPRESSED) { return $at + 2 }
    $at += 1 + $length
  }
}

# Each HTTPS record of a reply: its priority, its parameter keys, and whether `ech` is one.
function Read-HttpsAnswers([byte[]]$reply) {
  $questions = Read-U16 $reply 4
  $answers = Read-U16 $reply 6
  $at = $script:HEADER_BYTES
  for ($i = 0; $i -lt $questions; $i++) { $at = (Skip-DnsName $reply $at) + 4 }
  for ($i = 0; $i -lt $answers; $i++) {
    $at = Skip-DnsName $reply $at
    $type = Read-U16 $reply $at
    $length = Read-U16 $reply ($at + 8)
    $data = $at + 10
    $at = $data + $length
    if ($type -ne $script:TYPE_HTTPS) { continue }
    $keys = @()
    $param = Skip-DnsName $reply ($data + 2)
    while ($param -lt $at) {
      $keys += Read-U16 $reply $param
      $param += 4 + (Read-U16 $reply ($param + 2))
    }
    [pscustomobject]@{ Priority = (Read-U16 $reply $data); Keys = $keys; Ech = ($keys -contains $script:PARAM_ECH) }
  }
}
