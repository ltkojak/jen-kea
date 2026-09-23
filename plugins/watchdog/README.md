# Host Watchdog — Jen Plugin

Probes chosen hosts on a schedule and alerts when one stops answering, and again when it comes back. [Network Discovery](https://github.com/ltkojak/jen-plugin-network-discovery) alerts when an *unknown* host appears; nothing alerts when a *known* host disappears — this plugin fills that gap.

> **IPv4 only.** Probing targets an IPv4 address. This isn't a bug or a gap to report — it's a deliberate scope decision, the same one every other bundled plugin makes.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v5.57.0 or later
- `ping` on the Jen host for ICMP targets — Ubuntu's `/usr/bin/ping` (package `iputils-ping`) carries `cap_net_raw`, so a single unprivileged `ping -c 1` works the same way Network Discovery's neighbour-table read does; Settings → Plugins offers an **Install** button on a systemd host (through Jen's root-run plugin service)

## Why ping works unprivileged

Jen runs as an unprivileged service user. Sending a raw ICMP echo request normally needs `CAP_NET_RAW` — but Ubuntu's own `/usr/bin/ping` binary already carries that capability (`getcap /usr/bin/ping`), so running it as a *subprocess* (`ping -c 1 -W 1 <ip>`) needs no privilege from Jen itself, the same trick Network Discovery relies on for its own neighbour-table read. A `tcp:<port>` target skips ping entirely and does a plain TCP connect, which never needs any capability.

## Features

- **Targets** from a Kea reservation, an IPAM Lite entry (when that plugin is installed), or any bare IP — the Add Target picker offers the first two, and always accepts a manual address
- **Two probe types**: `ping` (ICMP) or `tcp:<port>[,<port>]` (any one port answering counts as up)
- **Configurable per target**: check interval (1–60 min) and how many consecutive failures before it counts as down (1–10)
- **State machine**: `unknown` until the first result, `up` on any success, `down` only after the configured run of consecutive failures — a single blip doesn't flip a healthy target down early. Every *transition* — not every check — sends an alert and writes an event
- **7-day uptime %** and per-target history (last 50 checks, with RTT) on every row
- **"Watch this host"** row action on Jen's Reservations page
- Discovered in Jen's global search by label or IP
- **JSON API**: `GET /api/v1/plugins/watchdog/targets` (read key), `POST …/targets` (write key), both scoped to the calling key's accessible subnets
- Respects Jen subnet access control: a target on an address inside a Kea subnet is visible only to users who can see that subnet; a target on an address in *no* Kea subnet at all (an unmanaged network) is visible only to unrestricted users, the same rule IPAM Lite's own unmanaged subnets use. Adding, pausing, resuming and deleting targets all need admin — viewers are read-only

## Probing budget

Every due target is probed through one shared 8-thread pool, one run at a time, budgeted at 30 seconds total per periodic tick (which runs once a minute). A run that takes longer than its budget just leaves the slowest targets for the next tick rather than blocking it — a watchdog that hangs waiting on itself would be a poor watchdog.

## Installation

Open Jen → **Settings → Plugins** and click **Install** next to Host Watchdog. Jen downloads the release pinned in its plugin registry, verifies its checksum, and enables it; restart Jen when prompted.

To install by hand instead (a checkout without registry access), unzip `plugin.zip` from the release tag you want into `/var/lib/jen/plugins/watchdog/`, then enable it from Settings → Plugins and restart Jen.

## Development

`python3 tools/verify.py --build` rebuilds `plugin.zip` deterministically from the tree and runs the same checks CI runs on every push and tag: the zip matches the tree byte-for-byte, no template carries an inline event handler or an un-nonce'd `<script>` (Jen's CSP executes neither), `manifest.json`'s version matches the top `CHANGELOG.md` entry, and `plugin.py` compiles and passes ruff. The committed `plugin.zip` is the artifact Jen installs, so rebuild it in the same commit as any change.

`python3 tools/test_plugin.py` exercises every pure function (the probe-string parser, the ping-output parser, the state machine, due-target selection, uptime maths) against hand-built inputs — no Jen, database, or network access needed.

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
