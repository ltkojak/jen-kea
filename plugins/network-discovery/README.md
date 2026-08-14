# Network Discovery — Jen Plugin

Scan your subnets for devices not in the Kea DHCP lease table. Detects rogue devices, shows discovered hostnames and MAC addresses, and fires alerts through your configured Jen notification channels when unknown devices are found.

> **IPv4 only.** As of Jen v5.0's IPv6 rollout, active scanning (nmap/arp-scan) here only covers IPv4 subnets — there's no IPv6 equivalent of an address-space sweep at homelab scale. IPv6 devices are visible on Jen's own Devices page (read from Kea's lease table directly, not scanned) instead. This isn't a bug or a gap to report — it's a deliberate v5.0 scope decision.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v3.6.0 or later
- `nmap` on the Jen host:
  ```bash
  sudo apt install nmap
  ```
  arp-scan is supported as a fallback if nmap is not available.

## Features

- Per-subnet scan cards showing last scan time, total hosts found, and rogue count
- Manual scan trigger per subnet — runs in the background, auto-refreshes when done
- Results page with full host table: IP, hostname, MAC, Kea status (known/rogue)
- Filter results by All / Rogue / Known
- Fires a Jen alert on all configured channels when rogue devices are detected
- Respects Jen subnet access control — restricted users only scan their assigned subnets

## Installation

Open Jen → Settings → Plugins and click **Install** next to Network Discovery.

Or manually:
```bash
cd /opt/jen/plugins
mkdir network-discovery && cd network-discovery
curl -LO https://github.com/ltkojak/jen-plugin-network-discovery/raw/main/plugin.zip
unzip plugin.zip
touch .enabled
sudo systemctl restart jen
```

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
