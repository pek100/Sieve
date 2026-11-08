# Live check: Sieve must not break other apps

The owner's experience with AdGuard: some app updaters failed, Windows drivers crashed, localhost broke, torrents did not always work, and its SOCKS mode had bugs, above all with program updaters. Sieve must do none of this. Every check runs with Sieve off, then with routing and filtering on, then with HTTPS interception on, and compares. A check passes only when Sieve on behaves as Sieve off.

## What to run

1. **Updaters.** Windows Update (scan and one download), Microsoft Store app update, Defender signature update, winget upgrade of one package, Edge, Chrome and Firefox self-update, VS Code, Steam client and one game update, Discord, Node's npm install, pip install, git clone and fetch over HTTPS and SSH, a Chocolatey or Scoop install if present. Each completes, with its time against Sieve off. Updaters often pin certificates, use BITS or Delivery Optimization (peer to peer, UDP, LAN discovery) and resume partial downloads: watch for each.
2. **Localhost and LAN.** A local web server on 127.0.0.1 and on [::1], a dev server with websockets and hot reload, a local database port, an app that talks to its own helper over loopback (VS Code language servers), Docker or WSL port forwarding if present, SMB and printer discovery on the LAN, mDNS and SSDP. Nothing on loopback or the LAN may enter Sieve's adapter.
3. **Torrents.** qBittorrent downloading and seeding a large legal torrent (a Linux ISO): many simultaneous peers, TCP and uTP (UDP), DHT, peer exchange, and incoming connections on its listening port (with the port allowed in the firewall). Compare peers connected, download and upload speed, and whether incoming peers connect at all. Incoming connections are the risk to watch: a peer that connects in on the physical adapter must get its replies back the same way, not through Sieve's tunnel.
4. **Proxies and SOCKS.** An app set to use an HTTP proxy and one set to use a SOCKS5 proxy (a local test proxy), the system proxy setting, PAC files, and an updater that uses the system proxy. Sieve must relay their traffic untouched.
5. **Long and unusual connections.** A 2-hour idle SSH session, a large download resumed after a pause, an RDP session, a video call app if installable, an online game client's UDP, IPv6-only hosts, and very many connections at once (2,000 or more).
6. **Drivers and system health.** Through all of the above: no new errors in the System event log from Wintun, tcpip, NDIS or WFP, no bluescreen, no adapter left behind. Then kill, reboot and uninstall, and repeat a few checks to confirm the network is exactly as before.

## Record

For each item: works with Sieve off, works with Sieve on, works with interception on, timing or speed difference, any error, and the engine's log rows for that app (attributed correctly, never decrypted when it pins).
