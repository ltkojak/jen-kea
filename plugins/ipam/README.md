# IPAM Lite — Jen Plugin

Full IP address space management for Jen. See every IP in each subnet at a glance — available, dynamic DHCP lease, Kea reservation, or statically noted. Add labels, owners, and notes to any address. Replaces Netbox for simple static IP tracking.

> **IPv4 only.** As of Jen v5.0's IPv6 rollout, IPAM Lite covers IPv4 subnets exclusively — full-address-space enumeration doesn't extend to IPv6's /64s (see Jen's `docs/ARCHITECTURE.md` for why). For IPv6 lease and reservation counts, use Jen's own Subnets/Leases/Reservations pages instead. This isn't a bug or a gap to report — it's a deliberate v5.0 scope decision.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v3.6.0 or later

## Features

- **Overview page** — all subnets as cards with stacked utilisation bars (dynamic / reserved / static / available)
- **Subnet detail** — every IP in the pool with its current status and any annotations
- **Edit modal** — context-aware per IP status:
  - Dynamic / Reserved: notes only (Kea controls identity)
  - Available / Static: label, owner, notes, and status toggle
- **Static designation** — mark IPs as statically assigned (router, NAS, printer, etc.) without touching Kea
- **Filter** by status — All / Available / Dynamic / Reserved / Static
- **CSV export** per subnet
- **Assignment history** logged with user and timestamp
- Respects Jen subnet access control

## Installation

Open Jen → Settings → Plugins and click **Install** next to IPAM Lite.

Or manually:
```bash
cd /opt/jen/plugins
mkdir ipam && cd ipam
curl -LO https://github.com/ltkojak/jen-plugin-ipam/raw/main/plugin.zip
unzip plugin.zip
touch .enabled
sudo systemctl restart jen
```

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
