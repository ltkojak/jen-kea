# Switch Port Locator — Jen Plugin

Answers the one question [Jen](https://github.com/ltkojak/jen-kea)'s own Client Investigation can't: which switch port is this MAC on? Polls managed switches' MAC address tables over SNMP every 10 minutes, resolves the port's name and alias, auto-detects uplinks so a trunk port never looks like where a device "lives", and alerts when a known MAC's port changes.

> **IPv4 only.** Switch Port Locator identifies devices by MAC, resolved against Jen's IPv4 leases/reservations/devices for subnet visibility. This isn't a bug or a gap to report — it's a deliberate scope decision, the same one every other bundled plugin makes.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v5.57.0 or later
- `snmpbulkwalk` (package `snmp`) on the Jen host — Settings → Plugins offers an **Install** button on a systemd host
- Switches that answer SNMPv2c and implement standard BRIDGE-MIB / Q-BRIDGE-MIB / IF-MIB (almost every managed switch does; SNMPv3 with auth/priv is a later release, not this one)

## How it reads a switch's MAC table

Two strategies, picked per switch:

- **None** (most non-Cisco gear, e.g. HP/Aruba ProCurve) — one Q-BRIDGE-MIB `dot1qTpFdbPort` walk with the plain community string covers every VLAN's table at once.
- **Community** (Cisco's `community@vlan` indexing) — BRIDGE-MIB `dot1dTpFdbPort` is walked once per VLAN configured for the switch, each with community `<community>@<vlan>`; each walk only ever sees that one VLAN's table.

Every OID this plugin uses is quoted in `plugin.py`'s own module docstring against the actual MIB text it was verified against (BRIDGE-MIB, Q-BRIDGE-MIB, IF-MIB), with the date it was read — not a blog post or a guess.

## Features

- **Auto-detected uplinks**: a port carrying more than 8 MACs (an admin can pin any port's classification by hand) is treated as a trunk to another switch, not a device's own port — none of the MACs seen through it are "located" there
- **Moved alerts**: `emit("plugin.switchport.moved", ...)` fires when a known MAC's non-uplink port changes, whether that's a different port on the same switch or a hop to a different switch entirely
- **Locate page** (nav Network → Switch Ports): search a MAC to see its switch, port, alias, VLAN, and when it was last seen; a per-switch port table shows live MAC counts and the uplink override
- **"Find switch port"** row action on lease, reservation, and device rows — jumps straight to the locate page for that MAC
- Discovered in Jen's global search by MAC or port name
- **JSON API**: `GET /api/v1/plugins/switchport/locate/<mac>` (read key), scoped to the calling key's accessible subnets
- Respects Jen's subnet access control the same way Client Investigation does: a MAC is shown only if its *current* lease, reservation, or device placement is on a subnet the caller can see — never its port-table history, which has no subnet of its own. Adding, pausing, and removing switches, and overriding a port's uplink classification, all need admin — viewers are read-only

## Installation

Open Jen → **Settings → Plugins** and click **Install** next to Switch Port Locator. Jen downloads the release pinned in its plugin registry, verifies its checksum, and enables it; restart Jen when prompted.

To install by hand instead (a checkout without registry access), unzip `plugin.zip` from the release tag you want into `/var/lib/jen/plugins/switchport/`, then enable it from Settings → Plugins and restart Jen.

## Development

`python3 tools/verify.py --build` rebuilds `plugin.zip` deterministically from the tree and runs the same checks CI runs on every push and tag: the zip matches the tree byte-for-byte, no template carries an inline event handler, an un-nonce'd `<script>`, or a POST form missing `csrf_token`, `manifest.json`'s version matches the top `CHANGELOG.md` entry, and `plugin.py` compiles and passes ruff. The committed `plugin.zip` is the artifact Jen installs, so rebuild it in the same commit as any change.

`python3 tools/test_plugin.py` exercises every pure function — the walk-line parser, OID-index MAC decoding, both FDB-reading strategies against synthesised Cisco-style and HP-style walk fixtures, bridge-port-to-ifIndex resolution, the VLAN list parser, the uplink heuristic (including manual pins), and move detection — against hand-built inputs, no Jen, database, or network access needed.

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
