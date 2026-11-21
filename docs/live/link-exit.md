# Live check: exiting through another device (Sieve link)

The first real use of "Exit through another device": the data-centre test VM
(Windows, Sieve's engine running) sends its sieved apps' traffic out through a
hub on the owner's home PC, so sites (YouTube first) see a residential
address. Nothing here has run on a real network yet; every step below is the
plan for the first run.

Roles:

- **VM = device.** Sieve's engine, paired with the hub, "exit through" on,
  route **listen** (the VM is publicly reachable; the home PC is behind a
  router and dials out, so the home needs no open port).
- **Home PC = hub.** `sieve-hub` (from `engine/crates/sieve-link`), one
  user-mode process started by hand, dialling OUT to the VM. Sieve's own engine
  stays off on the home PC for this run.

## Needs the owner's approval first

Each of these is the owner's decision; an agent must not do them unasked.

1. Running `sieve-hub` on the home PC at all, and for how long (the home
   network is otherwise off limits to agents).
2. That the VM's test traffic exits from the home's public address (sites see
   it; the home ISP's terms apply), and the allow-list of domains for the VM
   (step H3).
3. The GCP firewall rule: one TCP port (7443 below), source = the home's public
   IPv4 only.
4. A Windows Firewall inbound rule on the VM for that port (Sieve never writes
   firewall rules; the law `tests/laws/normal-network.test.ts` forbids it).
5. Whether AdGuard on the home PC excludes `sieve-hub.exe` for the run (its
   HTTPS filtering would otherwise break the VM's end-to-end TLS through the
   hub), or that this is recorded as a known difference.
6. What happens to the hub's folder (its key and audit log) afterwards.

## What is opened, exactly

- On the VM, while "exit through" is on AND Sieve routes AND the route is
  listen: TCP port 7443 on the address of the adapter Windows uses for the
  internet (the status line's `listening` names it exactly). Anyone who can
  reach it may start a TLS handshake; only the paired hub's key completes it
  (raw-public-key pinning); a stranger's connection is dropped within 3 s. The
  port closes when exit is turned off, when Sieve stops routing, when the
  engine stops or crashes. Sieve adds no firewall rule: the owner's GCP rule
  and Windows rule decide who can reach it.
- On the home PC: nothing listens. `sieve-hub` makes one outbound TCP
  connection to the VM's port 7443 and one outbound connection per stream to
  the targets the VM asks for, after resolving names with the home PC's
  resolver.

## Prepare

Home PC (hub):

- H1. Build: `cargo build --release -p sieve-link` (from `engine/`). Note the
  binaries `sieve-hub.exe` and `sieve-link.exe`.
- H2. `sieve-hub init --name home` (default folder
  `%LOCALAPPDATA%\sieve-link\hub`, owner-only).
- H3. Pair code, no address (the hub dials): `sieve-hub pair` prints
  `SL1-...`. Restrict the VM before it ever links:
  `sieve-hub rule <vm> allow-suffix youtube.com`, `... googlevideo.com`,
  `... ytimg.com`, `... ggpht.com`, `... google.com`, `... gstatic.com`,
  `... googleapis.com`, the what-is-my-IP site used in V1, and the DNS
  resolver's name (Sieve's encrypted DNS asks the hub for the resolver by
  name, e.g. `dns.google` or `cloudflare-dns.com`; a resolver given as an IP
  address needs `allow-cidr <ip>/32` instead). Limits: a device paired now
  gets 128 concurrent and 600 per minute, also from a hub made before
  2026-11-22 (its stored default of 64 now reads as the built-in default). A
  device already paired keeps its stored limit until raised: run 9's VM,
  paired under the old default of 64, hit 64 while browsing, so raise it with
  `sieve-hub limit <vm> concurrent 128`. (`<vm>` is the name
  or fingerprint `sieve-hub devices` shows after pairing; the rules can be set
  right after pairing, before "exit through" is turned on.)

VM (device), with Sieve installed and routing:

- V0. GCP firewall: allow TCP 7443 from the home IPv4 only (approval 3).
  Windows Firewall inbound rule for TCP 7443, remote address = the home IPv4
  (approval 4), e.g. `New-NetFirewallRule -DisplayName "Sieve link (test)"
  -Direction Inbound -Protocol TCP -LocalPort 7443 -RemoteAddress <home IP>
  -Action Allow`, deleted after the run.
- V1. In Sieve: Settings, "Exit through another device": paste the code,
  choose "the other device dials this computer", port 7443, Pair. The state
  reads "pairing" and the status's `listening` shows `<VM address>:7443`.
- H4. On the home PC: `sieve-hub run --dial <VM public IP>:7443`. The VM's
  state turns "paired, off". `sieve-hub devices` lists the VM; compare the
  fingerprints with the ones Sieve shows. Set the rules of H3 now.
- V2. Turn "Exit through home" on (hub-down: Stop, UDP: Drop, the defaults).
  The state turns "up" within seconds (the hub redials every few seconds at
  most 30).

## Verify

Record each with its evidence (screenshots, `status.json` from
`ProgramData\Sieve\engine`, the hub's `audit.log` lines).

1. **Exit address.** In a browser on the VM, a what-is-my-IP page shows the
   home's public address, not the VM's. With "exit through" off it shows the
   VM's own address again.
2. **DNS path.** The hub's `audit.log` has `stream` rows to the resolver's
   name on 443 (DoH) or 853 (DoT); the VM's `dns-status.json` shows answers.
   A DNS over QUIC resolver, if configured, is not in the audit (it stays on
   the VM's own connection, as the UI says).
3. **QUIC fallback.** Sieve's log on the VM shows `exit` rows `dropped` with
   "QUIC is refused" for the browser's UDP 443, and the same sites' TCP flows
   as `exit` rows `hub`. `chrome://net-internals` (or Edge's) shows the
   sessions on TCP.
4. **YouTube plays** for 10 minutes at 1080p; the log's rows for
   `*.googlevideo.com` read `hub`; nothing for the browser reads `stopped` or
   `refused` unless a rule says so.
5. **Hub audit matches.** For a few flows, the VM log's `target` equals the
   hub's audit `target` (the name, not the VM's resolved address), and bytes
   are counted on both.
6. **Filtering still first.** A blocked ad domain is blocked on the VM (log
   row `blocked`) and never appears in the hub's audit. With HTTPS filtering
   on, a decrypted site still shows Sieve's certificate in the browser while
   the hub's audit shows the real site's name: the engine validated the
   real certificate through the hub.
7. **Per-app Off.** Turn one app Off in Sieve: its connections leave from the
   VM's own address (what-is-my-IP in that app) and are absent from the audit.
8. **Hub down, Stop.** Stop `sieve-hub` (Ctrl-C). The VM's state turns
   "down"; Home shows the notice that new connections are being stopped; a
   page load fails; the log shows `exit` rows `stopped`; the what-is-my-IP
   page never shows the VM's own address. Start `sieve-hub run --dial ...`
   again: the state returns to "up" and pages load.
9. **Hub down, Direct.** Set "go direct when the other device cannot be
   reached", stop the hub: pages load from the VM's own address and the log
   says `direct`. Set it back to Stop.
10. **Turning it off.** "Exit through" off: the VM's own address again at
    once for new connections; the listening port is closed (from the home PC:
    `Test-NetConnection <VM IP> -Port 7443` fails).
11. **Fail-open.** With exit on: kill `sieve-engine.exe` (Task Manager, end
    task): within seconds the VM browses from its own address (the watchdog
    removes the routes; the link dies with the process), port 7443 is closed.
    Reboot the VM with the engine set to start: no route, no port, no DNS
    setting remains before Sieve starts; after it starts, the state comes
    back as it was (paired, exit on), never the code.
12. **Unpair.** Unpair in Sieve: `ProgramData\Sieve\engine\link` holds no
    `link.json` and no `identity.key`; on the home PC `sieve-hub revoke <vm>`.

## Afterwards

- Delete the VM's Windows Firewall rule and the GCP firewall rule.
- Stop `sieve-hub`; keep or delete its folder (approval 6).
- Note for the record: UDP to public addresses was dropped during the run
  (games, calls, WebRTC, torrents' uTP/DHT break while exiting), which is the
  default and what the UI says.
