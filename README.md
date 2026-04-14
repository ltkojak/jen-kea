# Jen — The Kea DHCP Management Console

> *"Have you tried turning it off and on again?"*

A web-based DHCP management interface for [ISC Kea DHCP Server](https://www.isc.org/kea/), built as a Python Flask application. Jen provides a full-featured UI closer to Windows DHCP Server — accessible from any browser including mobile.

![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=flat)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat)
![Flask](https://img.shields.io/badge/Flask-3.0-green?style=flat)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat)

---

## Features

**Dashboard**
- Live subnet utilization with dynamic/reserved breakdown
- Recently issued leases with time filter (30min / 1h / 4h / 8h / 12h / 24h)
- Auto-refresh every 30 seconds
- Kea health indicator in nav bar

**Lease Management**
- Browse active and expired leases with subnet/time/search filters
- Manual lease release
- Delete stale leases from database
- One-click convert dynamic lease to reservation
- Visual IP address map — free/dynamic/reserved at a glance

**Reservations**
- Full add/edit/delete with per-reservation notes
- Duplicate detection (IP and MAC)
- Bulk CSV import and export
- Per-reservation DNS override support

**Subnet Editing**
- Edit pool ranges, lease times, and scope options directly from the UI
- Changes applied via SSH to the Kea server
- Auto-backup before every change with rollback on validation failure

**Alerts (Telegram)**
- Kea goes down or comes back up
- New device gets a DHCP lease (IP, MAC, hostname in message)
- Subnet utilization exceeds configurable threshold
- All toggleable per-alert-type in Settings UI

**Security**
- Login rate limiting — configurable max attempts, lockout duration, and mode (IP / username / both)
- HTTPS via SSL certificate upload in Settings UI (ZeroSSL compatible)
- Session timeout — global default with per-user override
- Full audit log of all changes

**Audit Log**
- Every add/edit/delete tracked with user, timestamp, and source IP
- Paginated log page

**DDNS Status**
- Recent Technitium DNS update log activity
- Hostname lookup via Technitium API

**Infrastructure**
- Prometheus metrics at `/metrics`
- SSH key generation for subnet editing in Settings UI
- Dark/light mode toggle
- Sortable columns, pagination everywhere
- Docker support (external or bundled MySQL)

---

## Requirements

- Ubuntu 22.04 or 24.04 (bare metal) or any Docker-capable host
- Python 3.10+ (bare metal only — handled automatically by installer)
- ISC Kea DHCP 3.0+ with MySQL backend and Control Agent running
- MySQL/MariaDB accessible for both the Kea database and Jen database

---

## Installation

### Option 1 — Guided Installer (recommended)

```bash
tar xzf jen-v1.0.0.tar.gz
cd jen
sudo ./install.sh
```

The installer will:
- Check all system requirements (OS, Python, disk space, dependencies)
- Offer bare metal/systemd or Docker install
- Walk you through all configuration values interactively
- Test Kea API and database connections live
- Install all files, set permissions, enable and start the service
- Verify Jen is responding before finishing

### Option 2 — Docker (external MySQL for Jen DB)

Jen connects to your existing MySQL server for both the Kea database and the Jen database.

```bash
cd jen
cp jen.config.example jen.config
nano jen.config        # fill in your values
docker compose up -d
```

### Option 3 — Docker (bundled MySQL for Jen DB)

Docker manages a local MariaDB container for the Jen database. Kea database still connects externally.

```bash
cd jen
cp jen.config.example jen.config
nano jen.config        # set [jen_db] host = jen-mysql
cp .env.example .env
nano .env              # set MySQL passwords
docker compose -f docker-compose.mysql.yml up -d
```

### Option 4 — Manual bare metal

```bash
# Install dependencies
sudo apt install -y python3-pip mariadb-client-core openssh-client
sudo pip3 install flask flask-login pymysql requests --break-system-packages

# Extract and install
tar xzf jen-v1.0.0.tar.gz
cd jen
sudo mkdir -p /opt/jen /opt/jen/static /etc/jen /etc/jen/ssl /etc/jen/ssh
sudo cp jen.py /opt/jen/jen.py
sudo cp -r templates /opt/jen/templates
sudo cp jen.service /etc/systemd/system/jen.service
sudo cp jen-sudoers /etc/sudoers.d/jen
sudo chmod 440 /etc/sudoers.d/jen

# Configure
sudo cp jen.config.example /etc/jen/jen.config
sudo nano /etc/jen/jen.config    # fill in your values

# Start
sudo chown -R www-data:www-data /opt/jen /etc/jen
sudo systemctl daemon-reload
sudo systemctl enable --now jen
```

### Uninstall

```bash
sudo ./uninstall.sh
```

---

## First Login

Open `http://your-server:5050` in your browser.

| Username | Password |
|---|---|
| admin | admin |

**Change your password immediately** after first login via **Users → Change My Password**.

---

## Configuration

All configuration lives in `/etc/jen/jen.config`. Copy `jen.config.example` as a starting point.

```ini
[kea]
# Kea Control Agent REST API
api_url  = http://YOUR-KEA-SERVER:8000
api_user = kea-api
api_pass = your-password

[kea_db]
# Kea MySQL database
host     = YOUR-KEA-SERVER
user     = kea
password = your-password
database = kea

[jen_db]
# Jen MySQL database (separate from Kea)
host     = YOUR-DB-SERVER
user     = jen
password = your-password
database = jen

[server]
http_port  = 5050
https_port = 8443

[kea_ssh]
# SSH access to Kea server for subnet editing (optional)
host     = YOUR-KEA-SERVER
user     = your-ssh-user
key_path = /etc/jen/ssh/jen_rsa
kea_conf = /etc/kea/kea-dhcp4.conf

[subnets]
# Format: subnet_id = Friendly Name, CIDR
1  = Production, 192.168.1.0/24
30 = IoT, 192.168.30.0/24

[ddns]
# Technitium DNS integration (optional)
log_path    = /var/log/kea/kea-ddns-technitium.log
api_url     = https://your-technitium-server/api
api_token   = your-token
forward_zone = your.domain.com
```

---

## Upgrading

Run the installer — it detects the existing version and handles the upgrade automatically:

```bash
tar xzf jen-v1.0.0.tar.gz
cd jen
sudo ./install.sh
```

Select bare metal, then choose to keep your existing config. Your config file, SSL certificates, SSH keys, and user accounts are always preserved.

---

## Updating from Git

After cloning the repo, future updates are:

```bash
cd ~/jen-kea
git pull
sudo cp jen.py /opt/jen/jen.py
sudo cp -r templates/* /opt/jen/templates/
sudo systemctl restart jen
```

Or just run `sudo ./install.sh` from the repo directory for a full guided upgrade.

---

## SSH Setup for Subnet Editing

1. Go to **Settings → SSH Key Management → Generate SSH Key**
2. Copy the public key shown on screen
3. On your Kea server, add it to the SSH user's authorized_keys:
```bash
echo "ssh-rsa AAAA... jen@your-jen-server" >> ~/.ssh/authorized_keys
```
4. Add a sudoers entry on your Kea server:
```bash
echo "youruser ALL=(ALL) NOPASSWD: /usr/sbin/kea-dhcp4, /usr/bin/systemctl restart isc-kea-dhcp4-server, /bin/cp, /usr/bin/tee, /usr/bin/python3, /usr/bin/tail" | sudo tee /etc/sudoers.d/jen-kea
sudo chmod 440 /etc/sudoers.d/jen-kea
```

---

## Telegram Alerts Setup

1. Message **@BotFather** on Telegram → `/newbot` → follow prompts → copy the token
2. Message **@userinfobot** on Telegram to get your chat ID
3. Go to **Settings → Telegram Alerts** in Jen
4. Enter token and chat ID, enable desired alert types, click **Save**
5. Click **Send Test Message** to verify

---

## Jen Database Setup

Jen requires its own MySQL database separate from the Kea database. Create it on your MySQL server:

```sql
CREATE DATABASE jen;
CREATE USER 'jen'@'localhost' IDENTIFIED BY 'your-password';
CREATE USER 'jen'@'your-jen-server-ip' IDENTIFIED BY 'your-password';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'localhost';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'your-jen-server-ip';
FLUSH PRIVILEGES;
```

Jen creates all required tables automatically on first start.

---

## Troubleshooting

**Service won't start:**
```bash
sudo journalctl -u jen -n 30 --no-pager
```

**Config file errors:** Check that all required sections are present and values are filled in. The installer will report missing config values clearly.

**Lost admin password:**
```bash
mysql -u jen -p -h your-db-server jen -e "UPDATE users SET password=SHA2('newpassword',256) WHERE username='admin';"
```

**Subnet editing fails:** Verify SSH is configured in Settings, the public key is in the Kea server's authorized_keys, and the sudoers entry allows python3, tee, cp, and tail.

---

## Background

Jen was built by Matthew Thibodeau, an IT engineer with over two decades of experience. After deploying ISC Kea DHCP in his home lab, he found that ISC Stork fell short of what he needed for day-to-day management — so he built Jen to fill that gap.

---

## License

MIT — do whatever you want with it.
