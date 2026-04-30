# Jen — The Kea DHCP Management Console

A full-featured web management interface for [ISC Kea DHCP Server](https://www.isc.org/kea/) — built for homelabs and small infrastructure where ISC Stork falls short.

Stork is designed for large enterprise deployments with teams of network engineers. It lacks the day-to-day conveniences that matter in smaller environments: one-click lease conversion, bulk reservation management, device tracking, multi-channel alerts, and a UI that doesn't require a manual to navigate. Jen fills that gap.

![Version](https://img.shields.io/badge/Version-3.3.10-blue?style=flat)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat)
![Flask](https://img.shields.io/badge/Flask-3.0-green?style=flat)
![License](https://img.shields.io/badge/License-GPL%20v3-blue?style=flat)

---

## Features

**📊 Dashboard**
- Live subnet utilization with dynamic/reserved breakdown and color-coded utilization bars
- Recently issued leases with configurable time filter (30min to 24h)
- Configurable auto-refresh (5s / 10s / 15s / 30s / 60s / off) — remembered per browser
- Kea health indicator in nav bar

**📋 Lease Management**
- Browse active and expired leases with subnet, time, and search filters
- Manual lease release and stale lease cleanup
- One-click conversion of dynamic lease to static reservation
- Visual IP address map — free/dynamic/reserved at a glance

**📌 Reservations**
- Add, edit, delete with per-reservation notes
- Duplicate detection on IP and MAC
- Per-reservation DNS override
- Bulk select, delete, and export to CSV
- CSV import with per-row validation
- Stale reservation detection — flags MACs not seen in configurable number of days

**🌐 Subnets**
- Live subnet configuration pulled from Kea API
- Edit pool ranges, lease times, and scope options via UI
- Changes applied via SSH with auto-backup and rollback on failure
- Per-subnet notes/descriptions

**📱 Device Inventory**
- Automatically tracks every MAC address seen via DHCP
- Editable device name, owner, and notes per device
- Stale device detection and filtering
- Quick-reserve button for unregistered devices

**📈 Reports**
- Lease history charts per subnet (area charts — dynamic, reserved, pool size)
- Configurable snapshot interval and retention period
- Time range selector: 24h / 3d / 7d / 14d / 30d / 90d
- Summary cards with current, peak, and free address counts

**🔔 Alerts**
- Multiple independent alert channels: Telegram, Email (SMTP), Slack, Generic Webhook
- 12 alert types: Kea down/up, new lease, unknown device, high utilization, utilization recovery, pool exhaustion, reservation added/deleted, stale reservation, config changed, daily summary
- Custom message templates with variable substitution
- Per-channel enable/disable with independent alert type selection
- Alert delivery log

**🖥️ Kea Servers**
- Single server status with version, role, and SSH restart
- Multi-server / HA support — connect to primary, standby, and peer servers
- HA state visibility (hot-standby, load-balancing, partner-down, etc.)
- Subnet config changes applied to all servers simultaneously
- Configure additional servers via UI — no manual config file editing required

**🔗 DDNS Status**
- Recent Technitium DNS update log (read via SSH from Kea server)
- Hostname lookup via Technitium API

**📝 Audit Log**
- Every change tracked with user, timestamp, and source IP

**🧭 Navigation & UX**
- Grouped dropdown nav — Network, Management, Admin menus replace the flat nav bar
- User avatar bubble — top right corner with initials or profile picture, click for profile/security/logout
- Profile picture upload (JPG/PNG/GIF/WebP, stored per-user, shown in nav bubble)
- Global search across leases, reservations, and devices from the nav bar
- Saved searches and filters on Leases and Reservations pages (up to 20 per user)
- Dashboard customization — show/hide widgets, saved per user
- Keyboard shortcuts: G+D/L/R/V/S to navigate, / for search, ? for shortcut help
- Bulk import dry-run mode — preview CSV import results before committing
- Mobile-optimized views with responsive tables, better tap targets, hide-on-mobile columns
- Hamburger nav on mobile (≤768px) with flat link list — no dropdowns
- User profile page — account info, MFA status, change password in one place
- Custom branding — set a custom app name, subtitle, and nav color via Settings UI
- Nav bar shows app name and version number cleanly

**🔌 REST API**
- Read-only REST API at `/api/v1/` for integrations with Home Assistant, Zabbix, and custom scripts
- API key management in Settings — generate, name, and revoke keys
- Endpoints: health, subnets, leases, devices, reservations
- Live API documentation at `/api/docs` with pre-filled examples and copy-paste Home Assistant YAML and Zabbix HTTP agent config
- Keys use `Authorization: Bearer` header, prefixed with `jen_` for easy identification

**🔐 Security & MFA**
- TOTP two-factor authentication — works with Google Authenticator, Authy, 1Password, Bitwarden, and any TOTP app
- Backup recovery codes — 8 single-use codes generated at enrollment
- Trusted device remembering — skip MFA for 24h, 30 days, 60 days, 90 days, or forever
- MFA policy — Off, Optional, Required for Admins, or Required for All
- Admin can reset any user's MFA from the Users page
- Passkeys (WebAuthn/FIDO2) coming in a future release

**⚙️ Settings**
- **System** — HTTPS/SSL certificate upload, session timeout, login rate limiting, MFA policy, custom icon
- **Alerts** — All alert channel configuration and message templates
- **Infrastructure** — Kea API, databases, SSH, subnet map, DDNS — all editable via UI without touching config files

**ℹ️ About**
- System info, Kea version, subnet summary with live lease counts

**Infrastructure**
- Prometheus metrics at `/metrics`
- Docker support — external or bundled MySQL modes
- Guided installer with bare metal and Docker paths
- Automatic config migration on upgrade

---

## Requirements

- Ubuntu 22.04 or 24.04 (bare metal) or any Docker-capable host
- Python 3.10+ (handled automatically by installer on bare metal)
- ISC Kea DHCP 3.0+ with MySQL backend and Control Agent running
- MySQL/MariaDB for both Kea database and Jen database

---

## Installation

### Option 1 — Guided Installer (recommended)

```bash
tar xzf jen-v3.3.10.tar.gz
cd jen
sudo ./install.sh
```

The installer checks system requirements, offers bare metal or Docker, walks through configuration, tests connections live, and verifies Jen is running before finishing.

### Option 2 — Docker (external MySQL)

```bash
cd jen
cp jen.config.example jen.config
nano jen.config
docker compose up -d
```

### Option 3 — Docker (bundled MySQL)

```bash
cd jen
cp jen.config.example jen.config
# Set [jen_db] host = jen-mysql
cp .env.example .env
nano .env
docker compose -f docker-compose.mysql.yml up -d
```

### Option 4 — Manual bare metal

```bash
sudo apt install -y python3-pip mariadb-client-core openssh-client
sudo pip3 install flask flask-login pymysql requests pyotp "qrcode[pil]" authlib --break-system-packages

tar xzf jen-v3.3.10.tar.gz && cd jen
sudo mkdir -p /opt/jen /opt/jen/static /etc/jen /etc/jen/ssl /etc/jen/ssh
sudo cp jen.py /opt/jen/jen.py
sudo cp -r templates /opt/jen/templates
sudo cp jen.service /etc/systemd/system/jen.service
sudo cp jen-sudoers /etc/sudoers.d/jen && sudo chmod 440 /etc/sudoers.d/jen
sudo cp jen.config.example /etc/jen/jen.config
sudo nano /etc/jen/jen.config
sudo chown -R www-data:www-data /opt/jen /etc/jen
sudo systemctl daemon-reload && sudo systemctl enable --now jen
```

### Uninstall

```bash
sudo ./uninstall.sh
```

---

## First Login

Open `http://your-server:5050`

| Username | Password |
|---|---|
| admin | admin |

**Change your password immediately** — Users → Change My Password.

---

## Configuration

All configuration lives in `/etc/jen/jen.config`. After initial setup, most settings can also be changed via **Settings → Infrastructure** in the UI without editing the file directly.

```ini
[kea]
api_url  = http://YOUR-KEA-SERVER:8000
api_user = kea-api
api_pass = your-password

[kea_db]
host     = YOUR-KEA-SERVER
user     = kea
password = your-password
database = kea

[jen_db]
host     = YOUR-DB-SERVER
user     = jen
password = your-password
database = jen

[server]
http_port  = 5050
https_port = 8443

[kea_ssh]
host     = YOUR-KEA-SERVER
user     = your-ssh-user
key_path = /etc/jen/ssh/jen_rsa
kea_conf = /etc/kea/kea-dhcp4.conf

[subnets]
# Format: subnet_id = Friendly Name, CIDR
1  = Production, 192.168.1.0/24
30 = IoT, 192.168.30.0/24

[ddns]
log_path    = /var/log/kea/kea-ddns-technitium.log
api_url     = https://your-technitium-server/api
api_token   = your-token
forward_zone = your.domain.com
```

---

## Upgrading

```bash
tar xzf jen-v3.3.10.tar.gz
cd jen
sudo ./install.sh
```

Select bare metal → keep existing config. Your config, SSL certificates, SSH keys, and user accounts are always preserved. A backup of the previous `jen.py` is saved to `/etc/jen/backups/` before every upgrade.

---

## Updating from Git

```bash
cd ~/jen-kea  # or wherever you cloned the repo
git pull
sudo cp jen.py /opt/jen/jen.py
sudo cp -r templates/* /opt/jen/templates/
sudo systemctl restart jen
```

Or run `sudo ./install.sh` for a full guided upgrade.

---

## SSH Setup for Subnet Editing

1. Go to **Settings → Infrastructure → SSH Configuration → Generate SSH Key** (or Regenerate SSH Key if already exists)
2. Copy the public key shown
3. On your Kea server: `echo "ssh-rsa AAAA... jen@your-jen-server" >> ~/.ssh/authorized_keys`
4. Add sudoers on your Kea server:

```bash
echo "youruser ALL=(ALL) NOPASSWD: /usr/sbin/kea-dhcp4, /usr/bin/systemctl restart isc-kea-dhcp4-server, /bin/cp, /usr/bin/tee, /usr/bin/python3, /usr/bin/tail" | sudo tee /etc/sudoers.d/jen-kea
sudo chmod 440 /etc/sudoers.d/jen-kea
```

---

## Jen Database Setup

```sql
CREATE DATABASE jen;
CREATE USER 'jen'@'YOUR-JEN-SERVER-IP' IDENTIFIED BY 'your-password';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'YOUR-JEN-SERVER-IP';
FLUSH PRIVILEGES;
```

Jen creates all required tables automatically on first start.

---

## Troubleshooting

**Service won't start:**
```bash
sudo journalctl -u jen -n 30 --no-pager
```

**Lost admin password:**
```bash
mysql -u jen -p -h your-db-server jen -e "UPDATE users SET password=SHA2('newpassword',256) WHERE username='admin';"
```

**Subnet editing fails:** Verify SSH key is generated in Settings → Infrastructure, added to Kea server authorized_keys, and sudoers entry includes `python3`, `tee`, `cp`, and `tail`.

**DDNS log not showing:** Check the log path in Settings → Infrastructure → DDNS matches the actual path on your Kea server.

---

## Background

Jen was built by Matthew Thibodeau, an IT engineer with over two decades of experience, with the assistance of Claude (Anthropic). After deploying ISC Kea DHCP in his home lab, he found that ISC Stork fell short of what he needed for day-to-day management — so he built Jen to fill that gap.

Jen is actively developed and versioned. See [Releases](https://github.com/ltkojak/jen-kea/releases) for the full changelog.

---

## License

Copyright (C) 2026 Matthew Thibodeau

This program is free software: you can redistribute it and/or modify it under
the terms of the **GNU General Public License v3** as published by the Free
Software Foundation.

This means you are free to use, copy, modify, and distribute Jen — including
for personal and commercial use — as long as any distributed modifications are
also released under GPL v3 with source code available.

See the [LICENSE](LICENSE) file or [gnu.org/licenses/gpl-3.0](https://www.gnu.org/licenses/gpl-3.0.txt) for full terms.
