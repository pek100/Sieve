<#
.SYNOPSIS
  Asks one HTTPS (type 65) question over UDP and says whether the answer holds an
  `ech` parameter, for docs/live/dns-extras.md. Windows' own tools cannot: Resolve-DnsName
  refuses -Type HTTPS and nslookup does not know type 65.

.DESCRIPTION
  Changes nothing. The question goes to the first DNS server of this machine unless
  -Server says another, so with the engine on it reaches the engine's DNS service as a
  plain question with no DO bit. It does not go through the DNS Client service, so a
  browser's own path is another check (row 4 of the runbook).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\live\https-record.ps1 crypto.cloudflare.com
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Name,
  [string]$Server,
  [int]$Port = 53,
  [int]$TimeoutMs = 5000
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "https-record-checks.ps1")

if (-not $Server) {
  $Server = @(Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -and $_ -notlike "127.*" })[0]
  if (-not $Server) { throw "This machine lists no IPv4 DNS server. Name one with -Server." }
}

$client = New-Object Net.Sockets.UdpClient
try {
  $client.Client.ReceiveTimeout = $TimeoutMs
  $query = New-HttpsQuery $Name (Get-Random -Maximum 65536)
  $client.Connect($Server, $Port)
  [void]$client.Send($query, $query.Length)
  $from = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
  $reply = $client.Receive([ref]$from)
} finally {
  $client.Close()
}

$records = @(Read-HttpsAnswers $reply)
Write-Host "Asked $Server for $Name, type 65: $($records.Count) record(s)."
foreach ($record in $records) {
  Write-Host "  priority $($record.Priority), parameters $($record.Keys -join ', '), ech: $(if ($record.Ech) { 'yes' } else { 'no' })"
}
if ($records.Count -eq 0) { Write-Host "  No HTTPS record in the answer, so this name says nothing about ech." }
