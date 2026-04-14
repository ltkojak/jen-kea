# Jen Administrator Guide

This guide covers installation, configuration, and administration of Jen.

---

## First-Time Setup Checklist

Before starting Jen for the first time, work through this checklist:

**On your Kea server (your Kea server):**
- [ ] Kea DHCP 3.0+ installed and running
- [ ] Kea Control Agent running on port 8000 (or your chosen port)
- [ ] Kea MySQL backend configured
- [ ] Remote MySQL access enabled (`bind-address = 0.0.0.0` in MariaDB config)
- [ ] MySQL user created for Jen's remote access to the `kea` database
- [ ] Separate `jen` MySQL database created with a dedicated user

**On your Jen server (your Jen server):**
- [ ] Ubuntu 22.04 or 24.04
- [ ] Network access to Kea server (API port and MySQL port)
- [ ] Tarball downloaded

**Run the installer:**
```bash
tar xzf jen-v1.0.0.tar.gz
cd jen
sudo ./install.sh
```

**After installation:**
- [ ] Log in with `admin / admin`
- [ ] Change the default admin password immediately
- [ ] Upload SSL certificate in Settings → SSL Certificate
- [ ] Configure Telegram alerts if desired
- [ ] Generate SSH key in Settings → SSH Key Management
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

Jen requires its own database for users, audit log, settings, and reservation notes.

```sql
CREATE DATABASE jen;
CREATE USER 'jen'@'localhost' IDENTIFIED BY 'your-password';
CREATE USER 'jen'@'YOUR-JEN-SERVER-IP' IDENTIFIED BY 'your-password';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'localhost';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'YOUR-JEN-SERVER-IP';
FLUSH PRIVILEGES;
```

Jen creates all required tables automatically on first start.

---

## Kea Reconnect Settings

By default, Kea shuts itself down if it loses the MySQL connection. Add reconnect settings to prevent this. In `/etc/kea/kea-dhcp4.conf`, add to both `lease-database` and `hosts-databases`:

```json
"on-fail": "serve-retry-continue",
"reconnect-wait-time": 3000,
"max-reconnect-tries": 10
```

This keeps Kea serving leases from memory even if MySQL is temporarily unavailable.

---

## Configuration File Reference

All Jen configuration lives in `/etc/jen/jen.config`. The file is owned by `root:www-data` with permissions `640` so the application can read it but it is not world-readable.

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
| `host` | MySQL server hostname or IP | `YOUR-KEA-SERVER` |
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
| `log_path` | Path to DDNS update log | `/var/log/kea/kea-ddns-technitium.log` |
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

Go to **Users → Add User**. Enter a username (letters, numbers, underscores, hyphens, dots), password (minimum 8 characters), and select a role.

### Deleting Users

Click **Delete** next to any user. You cannot delete your own account.

### Changing Passwords

Any user can change their own password via **Users → Change My Password**. Admins cannot change other users' passwords — users must do this themselves.

### Session Timeout

Go to **Settings → Session Timeout** to set the global default timeout in minutes. Individual users can have their own timeout override set from the Users page. Set to a high value for convenience, lower for security.

---

## HTTPS Configuration

### Uploading a Certificate

1. Obtain an SSL certificate for your Jen server hostname (ZeroSSL, Let's Encrypt, or internal CA)
2. Go to **Settings → SSL Certificate**
3. Upload `certificate.crt`, `private.key`, and `ca_bundle.crt` (CA bundle required for ZeroSSL)
4. Click **Enable HTTPS** — Jen restarts automatically

After restart, HTTP on port 5050 redirects to HTTPS on port 8443.

### Renewing a Certificate (ZeroSSL 90-day)

1. Issue a new certificate from ZeroSSL
2. Go to **Settings → SSL Certificate → Replace Certificate**
3. Upload the three new files
4. Jen restarts automatically — no command line needed

### Removing HTTPS

Go to **Settings → SSL Certificate → Remove Certificate**. Jen restarts in HTTP-only mode.

---

## Rate Limiting

Configure in **Settings → Login Rate Limiting**.

| Setting | Description | Default |
|---|---|---|
| Max failed attempts | Attempts before lockout. 0 = disabled | 10 |
| Lockout duration | Minutes to lock out. 0 = permanent until admin clears | 15 |
| Mode | What to lock: IP address, username, or both | Both |

When a user is locked out they see how many minutes remain. When fewer than 3 attempts remain before lockout, Jen warns the user.

To unlock all accounts immediately: **Settings → Login Rate Limiting → Clear All Lockouts**.

The failed attempt counter uses a rolling window equal to the lockout duration — old attempts outside this window do not count toward the threshold.

---

## Telegram Alerts

Configure in **Settings → Telegram Alerts**.

### Setting Up a Bot

1. Open Telegram and message **@BotFather**
2. Send `/newbot` and follow the prompts
3. Copy the token BotFather gives you
4. Message **@userinfobot** to get your personal chat ID

### Alert Types

| Alert | Triggered when |
|---|---|
| Kea goes down/up | Kea stops responding or recovers |
| New device lease | A new dynamic lease is issued (sends IP, MAC, hostname, subnet) |
| Utilization threshold | A subnet's dynamic lease count exceeds the configured % of the pool |

### Testing

Click **Send Test Message** after saving settings to verify the bot can reach you.

---

## SSH Setup for Subnet Editing

### Generate the Key

1. Go to **Settings → SSH Key Management**
2. Click **Generate SSH Key**
3. Copy the public key displayed

### Authorize on Kea Server

On your Kea server, add the public key:

```bash
echo "ssh-rsa AAAA... jen@your-jen-server" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Add Sudoers Entry on Kea Server

```bash
echo "youruser ALL=(ALL) NOPASSWD: /usr/sbin/kea-dhcp4, /usr/bin/systemctl restart isc-kea-dhcp4-server, /bin/cp, /usr/bin/tee, /usr/bin/python3, /usr/bin/tail" | sudo tee /etc/sudoers.d/jen-kea
sudo chmod 440 /etc/sudoers.d/jen-kea
```

### Verify

Test the connection from your Jen server:
```bash
sudo -u www-data ssh -i /etc/jen/ssh/jen_rsa -o StrictHostKeyChecking=no youruser@YOUR-KEA-SERVER "echo OK"
```

---

## Upgrading Jen

Run the installer from the new tarball:

```bash
tar xzf jen-vX.X.X.tar.gz
cd jen
sudo ./install.sh
```

Select bare metal, then **Keep existing config**. The installer:
1. Backs up the current `jen.py` to `/etc/jen/backups/`
2. Installs the new files
3. Restarts the service
4. Verifies it started correctly
5. Rolls back automatically if the service fails to start

Your config file, SSL certificates, SSH keys, favicon, and user accounts are never modified during an upgrade.

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

## File Locations Reference

| Path | Purpose |
|---|---|
| `/opt/jen/jen.py` | Main application |
| `/opt/jen/templates/` | HTML templates |
| `/opt/jen/static/favicon.ico` | Custom favicon (if uploaded) |
| `/etc/jen/jen.config` | Configuration — credentials and settings |
| `/etc/jen/jen.db` | Legacy SQLite (v1.x only — not used in v2+) |
| `/etc/jen/ssl/` | SSL certificates |
| `/etc/jen/ssh/` | SSH keys for subnet editing |
| `/etc/jen/backups/` | Automatic backups from upgrades |
| `/etc/systemd/system/jen.service` | Systemd service definition |
| `/etc/sudoers.d/jen` | Allows Jen to restart itself after cert upload |
