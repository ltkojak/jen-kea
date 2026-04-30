# Jen Administrator Guide

This guide covers installation, configuration, and administration of Jen.

---

## First-Time Setup Checklist

Before starting Jen for the first time, work through this checklist:

**On your Kea server:**
- [ ] Kea DHCP 3.0+ installed and running
- [ ] Kea Control Agent running on port 8000 (or your chosen port)
- [ ] Kea MySQL backend configured
- [ ] Remote MySQL access enabled (`bind-address = 0.0.0.0` in MariaDB config)
- [ ] MySQL user created for Jen's remote access to the `kea` database
- [ ] Separate `jen` MySQL database created with a dedicated user

**On your Jen server:**
- [ ] Ubuntu 22.04 or 24.04
- [ ] Network access to Kea server (API port and MySQL port)
- [ ] Tarball downloaded

**Run the installer:**
```bash
tar xzf jen-v3.2.9.tar.gz
cd jen
sudo ./install.sh
```

**After installation:**
- [ ] Log in with `admin / admin`
- [ ] Change the default admin password immediately
- [ ] Upload SSL certificate in Settings → SSL Certificate
- [ ] Configure Telegram alerts if desired
- [ ] Generate SSH key in Settings → Infrastructure → SSH Key Management
- [ ] Add the public key to your Kea server's authorized_keys

---

## Prerequisites — Kea MySQL Setup

Jen needs remote read/write access to the Kea MySQL database. Run this on your MySQL server:

```sql
CREATE USER 'kea'@'YOUR-JEN-SERVER-IP' IDENTIFIED BY 'your-password';
GRANT SELECT, INSERT, UPDATE, DELETE ON kea.* TO 'kea'@'YOUR-JEN-SERVER-IP';
FLUSH PRIVILEGES;
```

Then allow remote connections by editing `/etc/mysql/mariadb.conf.d/50-server.cnf`:

```
bind-address = 0.0.0.0
```

Restart MariaDB:
```bash
sudo systemctl restart mariadb
```

---

## Prerequisites — Jen MySQL Database

Jen requires its own database for users, audit log, settings, device inventory, API keys, and reservation notes.

```sql
CREATE DATABASE jen;
CREATE USER 'jen'@'localhost' IDENTIFIED BY 'your-password';
CREATE USER 'jen'@'YOUR-JEN-SERVER-IP' IDENTIFIED BY 'your-password';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'localhost';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'YOUR-JEN-SERVER-IP';
FLUSH PRIVILEGES;
```

Jen creates all required tables automatically on first start and runs schema migrations automatically on upgrade.

---

## Kea Reconnect Settings

By default, Kea shuts itself down if it loses the MySQL connection. Add reconnect settings to prevent this. In `/etc/kea/kea-dhcp4.conf`, add to both `lease-database` and `hosts-databases`:

```json
"on-fail": "serve-retry-continue",
"reconnect-wait-time": 3000,
"max-reconnect-tries": 10
```

---

## Configuration File Reference

All Jen configuration lives in `/etc/jen/jen.config`. The file is owned by `root:www-data` with permissions `640`.

### [kea] section

| Key | Description | Example |
|---|---|---|
| `api_url` | Kea Control Agent URL | `http://YOUR-KEA-SERVER:8000` |
| `api_user` | API authentication username | `kea-api` |
| `api_pass` | API authentication password | `your-password` |

### [kea_db] section

| Key | Description | Example |
|---|---|---|
| `host` | MySQL server hostname or IP | `YOUR-KEA-SERVER` |
| `user` | MySQL username for Kea database | `kea` |
| `password` | MySQL password | `your-password` |
| `database` | Kea database name | `kea` |

### [jen_db] section

| Key | Description | Example |
|---|---|---|
| `host` | MySQL server hostname or IP | `localhost` |
| `user` | MySQL username for Jen database | `jen` |
| `password` | MySQL password | `your-password` |
| `database` | Jen database name | `jen` |

### [server] section

| Key | Description | Default |
|---|---|---|
| `http_port` | HTTP port (redirects to HTTPS when cert installed) | `5050` |
| `https_port` | HTTPS port | `8443` |

### [kea_ssh] section

| Key | Description | Example |
|---|---|---|
| `host` | Kea server SSH hostname or IP | `YOUR-KEA-SERVER` |
| `user` | SSH username on Kea server | `youruser` |
| `key_path` | Path to Jen's SSH private key | `/etc/jen/ssh/jen_rsa` |
| `kea_conf` | Path to kea-dhcp4.conf on Kea server | `/etc/kea/kea-dhcp4.conf` |

Leave `host` blank to disable subnet editing.

### [subnets] section

Maps Kea subnet IDs to friendly names. Format: `id = Name, CIDR`

```ini
[subnets]
1  = Production, 192.168.1.0/24
30 = IoT, 192.168.30.0/24
70 = VLAN70, 192.168.70.0/24
```

The ID must match the `id` field in your `kea-dhcp4.conf` subnet definition.

### [ddns] section

| Key | Description | Example |
|---|---|---|
| `log_path` | Path to DDNS update log on Kea server | `/var/log/kea/kea-ddns.log` |
| `api_url` | Technitium API base URL | `https://dns.example.com/api` |
| `api_token` | Technitium API token | `your-token` |
| `forward_zone` | DNS forward zone | `example.com` |

---

## User Management

### Roles

| Role | Access |
|---|---|
| **Admin** | Full access — view and modify everything, manage users, access Settings |
| **Viewer** | Read-only access to Dashboard, Leases, Reservations, Subnets, DDNS |

### Adding Users

Go to **Settings → Users → Add User**. Enter a username, password (minimum 8 characters), and select a role.

### Session Timeout

Go to **Settings → System** to set the global default timeout in minutes. Individual users can have their own timeout override set from the Users page.

---

## Multi-Factor Authentication (MFA)

Jen supports TOTP-based MFA (Google Authenticator, Authy, 1Password, etc.).

### MFA Policy

Go to **Settings → System → MFA Policy** to set the policy:

| Policy | Behaviour |
|---|---|
| Off | MFA disabled for all users |
| Optional | Users can enrol but are not required to |
| Required for Admins | Admin accounts must use MFA |
| Required for All | All accounts must use MFA |

### Enrolling MFA

Go to **Profile → Security → Enable MFA**. Scan the QR code with your authenticator app. Save your backup codes — they are shown only once.

### Trusted Devices

After successful MFA login, you can choose to trust the device for 30 days. Trusted devices skip MFA on subsequent logins. Manage trusted devices under **Profile → Security → Trusted Devices**.

---

## REST API

Jen provides a read-only REST API at `/api/v1/` for integration with Home Assistant, Zabbix, and custom scripts.

### Authentication

All endpoints (except `/api/v1/health`) require an API key in the request header:

```
Authorization: Bearer jen_your_key_here
```

### Managing API Keys

Go to **Settings → API Keys** to generate, view, and revoke keys. A key is shown only once at creation — copy it immediately.

### Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/health` | Kea status and Jen version — no auth |
| GET | `/api/v1/subnets` | Subnet utilization with pool sizes |
| GET | `/api/v1/leases` | Active leases — params: subnet, mac, hostname, limit |
| GET | `/api/v1/leases/{mac}` | Single device lease with active boolean |
| GET | `/api/v1/devices` | Device inventory — params: mac, name, subnet, limit |
| GET | `/api/v1/devices/{mac}` | Single device with online status and current lease |
| GET | `/api/v1/reservations` | Reservations — params: subnet, limit |

Full documentation with examples is available at **Settings → API Docs** in the Jen interface.

### Home Assistant Quick Start

```yaml
# Presence detection — is this device home?
rest:
  - resource: "https://your-jen-url/api/v1/devices/aa:bb:cc:dd:ee:ff"
    headers:
      Authorization: "Bearer jen_your_key_here"
    binary_sensor:
      - name: "Phone Home"
        value_template: "{{ value_json.online }}"
        device_class: presence
```

---

## Device Fingerprinting

Jen automatically identifies devices by manufacturer and type using OUI (MAC address prefix) lookup. This runs in the background every 30 seconds — no configuration required.

### How It Works

The first 3 bytes of every MAC address are assigned to a manufacturer by the IEEE. Jen maintains a database of 800+ OUI prefixes mapped to manufacturers and device types. Identified devices show a brand logo badge next to their hostname on the Device Inventory, Leases, Reservations, and Dashboard pages.

For devices with randomized MAC addresses (iOS 14+ private MACs), Jen falls back to hostname pattern matching.

### Manual Override

To override the auto-detected type for a device, click the edit (✏) button on the Device Inventory page and select a device type from the dropdown. Manual overrides show a 🔒 indicator and are preserved through background tracking updates.

### Custom Brand Icons

Go to **Settings → Icons** to:
- View the 24 bundled brand logos
- Upload a custom SVG to override any bundled icon or add a new manufacturer
- Remove custom icons to revert to bundled versions

Custom icons are stored in `/opt/jen/static/icons/custom/` and survive upgrades.

---

## HTTPS Configuration

### Uploading a Certificate

1. Obtain an SSL certificate for your Jen server hostname (ZeroSSL, Let's Encrypt, or internal CA)
2. Go to **Settings → SSL Certificate**
3. Upload `certificate.crt`, `private.key`, and `ca_bundle.crt`
4. Click **Enable HTTPS** — Jen restarts automatically

After restart, HTTP on port 5050 redirects to HTTPS on port 8443.

### Renewing a Certificate

1. Go to **Settings → SSL Certificate → Replace Certificate**
2. Upload the three new files
3. Jen restarts automatically

---

## Rate Limiting

Configure in **Settings → System → Login Rate Limiting**.

| Setting | Description | Default |
|---|---|---|
| Max failed attempts | Attempts before lockout. 0 = disabled | 10 |
| Lockout duration | Minutes locked out. 0 = permanent until cleared | 15 |
| Mode | Lock by: IP address, username, or both | Both |

---

## Telegram Alerts

Configure in **Settings → Alerts**.

### Setting Up a Bot

1. Message **@BotFather** in Telegram
2. Send `/newbot` and follow the prompts — copy the token
3. Message **@userinfobot** to get your chat ID

### Alert Types

| Alert | Triggered when |
|---|---|
| Kea down/up | Kea stops responding or recovers |
| New device lease | A new dynamic lease is issued |
| Utilization threshold | A subnet exceeds the configured pool percentage |

---

## SSH Setup for Subnet Editing

### Generate the Key

1. Go to **Settings → Infrastructure → SSH Key Management**
2. Click **Generate SSH Key**
3. Copy the public key displayed

### Authorize on Kea Server

```bash
echo "ssh-rsa AAAA... jen@your-jen-server" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Add Sudoers Entry on Kea Server

```bash
echo "youruser ALL=(ALL) NOPASSWD: /usr/sbin/kea-dhcp4, /usr/bin/systemctl restart isc-kea-dhcp4-server, /bin/cp, /usr/bin/tee, /usr/bin/python3, /usr/bin/tail" | sudo tee /etc/sudoers.d/jen-kea
sudo chmod 440 /etc/sudoers.d/jen-kea
```

---

## Upgrading Jen

```bash
tar xzf jen-vX.X.X.tar.gz
cd jen
sudo ./install.sh
```

Select **Keep existing config** when prompted. The installer backs up the current application, installs the new files, restarts the service, and rolls back automatically if the service fails to start.

Your config file, SSL certificates, SSH keys, custom icons, and user accounts are never modified during an upgrade.

---

## Service Management

```bash
# Status
sudo systemctl status jen

# Start / stop / restart
sudo systemctl start jen
sudo systemctl stop jen
sudo systemctl restart jen

# Live logs
sudo journalctl -u jen -f

# Last 50 log lines
sudo journalctl -u jen -n 50 --no-pager
```

---

## Prometheus Metrics

Jen exposes a Prometheus-compatible metrics endpoint at `/metrics` (no authentication required):

```bash
curl -k https://your-jen-server:8443/metrics
```

Available metrics:
- `jen_subnet_active_leases` — active lease count per subnet (with subnet name and CIDR labels)
- `jen_kea_up` — 1 if Kea is reachable, 0 if not

---

## File Locations Reference

| Path | Purpose |
|---|---|
| `/opt/jen/jen.py` | Main application |
| `/opt/jen/templates/` | HTML templates |
| `/opt/jen/static/icons/brands/` | Bundled brand SVG icons |
| `/opt/jen/static/icons/custom/` | User-uploaded custom brand icons |
| `/opt/jen/static/` | Static assets (favicon, nav logo) |
| `/etc/jen/jen.config` | Configuration — credentials and settings |
| `/etc/jen/secret_key` | Flask session secret key (auto-generated) |
| `/etc/jen/ssl/` | SSL certificates |
| `/etc/jen/ssh/` | SSH keys for subnet editing |
| `/etc/jen/backups/` | Automatic backups created during upgrades |
| `/etc/systemd/system/jen.service` | Systemd service definition |
| `/etc/sudoers.d/jen` | Allows Jen to restart itself after cert upload |

---

## Kea HA Configuration

### Enabling HA Mode

Go to **Settings → Infrastructure → High Availability** and set:

- **Primary Server Name** — friendly name shown in the UI and alerts
- **HA Mode** — must match the `ha-mode` configured in `kea-dhcp4.conf` on your Kea servers

| Mode | Description |
|---|---|
| Standalone | No HA — single server deployment |
| Hot Standby | Primary handles all traffic; standby takes over on failure |
| Load Balancing | Both servers share the lease load |
| Passive Backup | Primary active; backup receives updates but doesn't serve |

Or edit `jen.config` directly:

```ini
[kea]
name    = Kea Primary
role    = primary
ha_mode = hot-standby
```

### Adding a Standby Server

Go to **Settings → Infrastructure → Additional Servers** and add your standby node, or add it to `jen.config`:

```ini
[kea_server_2]
name     = Kea Standby
role     = standby
api_url  = http://YOUR-STANDBY-SERVER:8000
api_user = kea-api
api_pass = your-kea-api-password
ssh_host = YOUR-STANDBY-SERVER
ssh_user = your-ssh-user
kea_conf = /etc/kea/kea-dhcp4.conf
```

### How Active Node Routing Works

When HA is configured, Jen automatically routes `config-get` and subnet editing commands to the active node. Jen queries `ha-heartbeat` on each server and selects the primary in `hot-standby`, `load-balancing`, or `partner-down` state. Falls back to the first reachable server if no active node is identified.

### HA Failover Alerts

Add an alert channel and enable the **HA failover / state change** alert type. You will receive a notification any time a server's HA state changes — including failovers, recovery, and sync events.

---

## DDNS Provider Configuration

The DDNS page shows Kea DNS update log activity and supports hostname lookup. The DNS provider is configurable — Jen is not tied to Technitium.

### Setting the DNS Provider

Go to **Settings → Infrastructure → DDNS Configuration** and choose:

| Provider | Description |
|---|---|
| Technitium DNS | Uses Technitium REST API for hostname lookup |
| Generic | Uses `dig`/`host` over SSH to the Kea server |
| None | Log viewer only — no hostname lookup |

Or set it in `jen.config`:

```ini
[ddns]
log_path     = /var/log/kea/kea-ddns.log
dns_provider = technitium   # technitium, generic, or none
api_url      = https://your-technitium-server/api
api_token    = your-token
forward_zone = your.domain.com
```

---

## Alert Channels — ntfy and Discord

### ntfy Setup

1. Go to **Settings → Alerts → Add Channel**
2. Choose **ntfy** as the channel type
3. Enter your ntfy server URL (use `https://ntfy.sh` for the public server, or your self-hosted URL)
4. Enter the topic name (e.g. `jen-alerts`)
5. Optionally set an access token (for protected topics) and priority

No app configuration needed — ntfy delivers to any subscribed device automatically.

### Discord Setup

1. In your Discord server, go to **Server Settings → Integrations → Webhooks → New Webhook**
2. Choose the channel and copy the webhook URL
3. Go to **Settings → Alerts → Add Channel** in Jen
4. Choose **Discord** and paste the webhook URL
