<div align="center">
  <img src="docs/images/jen-logo.png" alt="Jen" width="320">
</div>

# Jen — Kea DHCP Management Console

A full-featured web-based management interface for [ISC Kea DHCP Server](https://www.isc.org/kea/), built with Python and Flask. Jen provides a comprehensive UI for managing DHCP leases, reservations, subnets, and infrastructure — accessible from any browser including mobile and iPad.

[![Version](https://img.shields.io/badge/Version-5.7.0-blue?style=flat)](https://github.com/ltkojak/jen-kea/releases)
[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1+-green?style=flat)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-GPL_v3-blue?style=flat)](LICENSE)


---

![Jen dashboard preview](docs/images/dashboard-preview.svg)
*Mock preview for illustration — not a live screenshot.*

---

## Features

### Dashboard
- Live subnet utilisation cards with dynamic/reserved breakdown and gateway/DNS display
- Recently issued leases with time filter
- Server status and HA state
- Alert summary feed
- Auto-refresh with configurable interval
- Customisable widget layout

### Lease & Reservation Management
- Browse active leases with subnet, search, and time filters
- Manual lease release, stale lease cleanup
- One-click convert dynamic lease to reservation
- Full reservation add/edit/delete with notes
- Bulk CSV import and export
- Duplicate detection (IP and MAC)

### Subnet Management
- Edit pool ranges, lease times, gateway, and DNS directly from the UI
- Changes applied via SSH to Kea with config validation before restart
- Auto-backup before every change with rollback on failure
- Gateway and DNS visible on subnet cards

### IPv6 (DHCPv6)
- Off by default; enable per-deployment from Settings → Infrastructure
- Leases, Devices, Reservations, Subnets, Dashboard, and global Search
  all support an IPv4/IPv6 view
- Add, edit, and delete IPv6 reservations (address, delegated prefix,
  or both) and subnet pools/timers from the UI, with the same
  validate-before-apply safety as IPv4 subnet edits
- Author a starting `kea-dhcp4.conf`/`kea-dhcp6.conf` from Jen when one
  doesn't exist yet — pulls interfaces and database settings from the
  other protocol's config when it's already running, so adding IPv6 to
  an existing IPv4 deployment doesn't mean re-entering everything by hand
- `/metrics` gains dedicated `jen_subnet6_*`/`jen_kea6_up` series

### Device Management
- Device inventory with type detection (OUI fingerprinting)
- Filter by type, subnet, search, stale status
- Custom device icons

### Notifications
- Multi-channel alerts: Pushover, Telegram, Slack, ntfy, Discord, Email, Generic Webhook
- Alert types: Kea up/down, new lease, new device, rogue device, daily summary, subnet utilisation threshold
- Per-channel configuration and test

### Security & Access Control
- Three-tier role system: SuperAdmin / Admin / Viewer
- Subnet-level access control per user
- MFA — TOTP authenticator apps (secrets encrypted at rest); WebAuthn/passkey support is planned
- Trusted device management
- Login rate limiting
- Session timeout (global default with per-user override)
- Full audit log with configurable retention
- HTTPS via SSL certificate upload

### Database & Backup
- Scheduled backups (Jen DB + Kea reservations)
- Manual backup and restore
- Database export/import

### Plugin System
- Install optional add-ins from Settings → Plugins
- Plugin registry fetched live from GitHub
- Enable/disable/update/uninstall from the UI
- Available plugins: Network Discovery, IPAM Lite

---

## How Jen talks to Kea

Jen is **agentless** — nothing runs on your Kea servers. One Flask
process reaches out to each Kea box over three channels:

| Channel | Used for | Direction |
|---------|----------|-----------|
| **Kea Control Agent HTTP API** | Live status, config reads, HA state, lease statistics | Jen → Kea, read-mostly |
| **Kea database (MySQL/MariaDB)** | Lease and reservation data, written only through the same tables/commands Kea's own tooling uses (mostly the `host_cmds` hook, never raw schema changes) | Jen ↔ Kea DB |
| **SSH** | Applying subnet/pool edits to `kea-dhcp*.conf`, validating the new config, restarting the service, reading logs | Jen → Kea host |

Every config change is validated against Kea before the service is
restarted, with an automatic backup and rollback on failure. Jen never
modifies Kea's database schema — only its data.

The tradeoff: this is deliberately built for a homelab-to-small-business
operator running a handful of servers, not a fleet. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and
threat model.

---

## Requirements

- Ubuntu 22.04 or 24.04 (bare metal or Docker)
- Python 3.10+
- ISC Kea DHCP 3.0+ with MySQL backend and Control Agent
- MySQL or MariaDB

---

## Installation

### Guided Installer (recommended)

```bash
tar xzf jen-v5.7.0.tar.gz
cd jen
sudo ./install.sh
```

The installer checks requirements, walks through configuration interactively, tests Kea API and database connections, and starts the service.

### Docker

Docker is configured entirely through `.env` (`JEN_*` variables) — `run.py`
generates `jen.config` inside the container on first start. The guided
installer writes `.env` for you:

```bash
cd jen
sudo ./install.sh --docker
```

Or by hand — **external** database (Jen's own DB lives on a server you run):

```bash
cd jen
cp .env.example .env      # fill in JEN_* (Kea + Jen DB + JEN_INITIAL_ADMIN_PASSWORD)
docker compose up -d
```

**Bundled** database (Docker runs MariaDB for Jen):

```bash
cd jen
cp .env.example .env      # fill in the Kea section, MYSQL_ROOT_PASSWORD,
                          # JEN_MYSQL_PASSWORD, JEN_INITIAL_ADMIN_PASSWORD
                          # (leave the JEN_DB_* lines blank)
docker compose -f docker-compose.mysql.yml up -d
```

---

## First Login

Open `http://your-server:5050` and sign in as **`admin`**.

- If you set an admin password during install (`JEN_INITIAL_ADMIN_PASSWORD`,
  or the bare-metal wizard), use that.
- Otherwise the password is `admin` and Jen will require you to change it
  immediately.

---

## Upgrading

```bash
tar xzf jen-v5.7.0.tar.gz
cd jen
sudo ./install.sh
```

The installer detects the existing version and upgrades in place. Config, SSL certificates, SSH keys, and user accounts are always preserved.

---

## Plugins

Jen supports optional plugins installable from **Settings → Plugins**.

| Plugin | Description | Repo |
|--------|-------------|------|
| Network Discovery | Scan subnets for devices not in Kea. Detects rogue devices, fires alerts. Requires nmap. | [jen-plugin-network-discovery](https://github.com/ltkojak/jen-plugin-network-discovery) |
| IPAM Lite | Full IP address space view. See every IP — available, dynamic, reserved, or static. Add labels, owners, notes. CSV export. | [jen-plugin-ipam](https://github.com/ltkojak/jen-plugin-ipam) |

---

## Jen compared to ISC Stork

[ISC Stork](https://www.isc.org/stork/) is the official monitoring
dashboard for Kea and BIND. It and Jen solve overlapping problems from
opposite directions.

| | **Jen** | **ISC Stork** |
|---|---|---|
| Architecture | Agentless — one process connects out to each server | Agent (`stork-agent`) on every managed server |
| Primary focus | Day-to-day **management**: edit subnets/pools/reservations, manage leases and devices | **Monitoring** and metrics, with configuration editing added more recently |
| Config changes | Validated SSH push to `kea-dhcp*.conf`, backup + rollback | Kea config-management API |
| Scale target | Homelab to small business, a handful of servers | Small to large fleets |
| Access control | Three roles + per-subnet scoping, built-in MFA (TOTP) | RBAC; auth via LDAP or local |
| Database | MySQL / MariaDB | PostgreSQL |
| Extras | Device inventory & OUI fingerprinting, multi-channel alerting, plugin system, custom branding | Grafana/Prometheus integration, BIND 9 support |
| License | GPL v3 | MPL 2.0 |

If you run a fleet, want Prometheus/Grafana dashboards, or also manage
BIND, use Stork. If you want a single-process console to *operate* a
small number of Kea servers from any browser, that's what Jen is for.

---

## Background

Jen was built by Matthew Thibodeau, an IT engineer with over two decades of experience. After deploying ISC Kea DHCP in his home lab, he found that ISC Stork fell short of what he needed — so he built Jen to fill that gap. It has grown from a homelab tool into a full-featured open-source DHCP management console.

---

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
