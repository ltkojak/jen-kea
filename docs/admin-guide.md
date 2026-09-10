# Jen Administrator Guide

This guide covers installation, configuration, and administration of Jen.

---

## First-Time Setup Checklist

Before starting Jen for the first time, work through this checklist:

**On your Kea server:**
- [ ] Kea DHCP installed and running
- [ ] A reachable command API — either the Control Agent on port 8000 (Kea 3.0/3.1), **or** an `http` `control-sockets` entry on each daemon (Kea 2.7.2+; **required for 3.2+**, which removed the Control Agent — see "Direct control sockets")
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
tar xzf jen-vX.Y.Z.tar.gz   # substitute the release you downloaded
cd jen
sudo ./install.sh
```

**After installation:**
- [ ] Log in with `admin / admin`
- [ ] Change the default admin password immediately
- [ ] Upload SSL certificate in Settings → Access & Security → SSL Certificate
- [ ] Configure Telegram alerts if desired
- [ ] Generate SSH key in Settings → Kea → SSH
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
| `connection_mode` | `ca` (default) or `direct` — see "Direct control sockets" below | `ca` |
| `api_url` | In `ca` mode: the Control Agent URL. In `direct` mode: kea-dhcp4's own HTTP/HTTPS control socket — **must include an explicit port** (a daemon socket is never on 80/443). | `https://10.10.10.20:8004` |
| `api_user` | API authentication username | `kea-api` |
| `api_pass` | API authentication password | `your-password` |
| `api_ca` | Optional. Path on the Jen host to a CA bundle — pins TLS verification for an `https://` `api_url`. | `/etc/jen/ssl/kea-ca.pem` |
| `api_tls_verify` | Optional, default `true`. Set `false` to skip TLS verification for an `https://` `api_url` (only sensible with a self-signed cert and no `api_ca`). | `true` |
| `api_client_cert` | Optional. Client-certificate PEM on the Jen host. Kea's per-daemon `https` socket defaults `cert-required` to `true` (mutual TLS), so without this an `https://` endpoint refuses the handshake. Set with `api_client_key` (both or neither). **Validated on save** — the pair must load and match. | `/etc/jen/ssl/jen-kea-client.pem` |
| `api_client_key` | Optional. The private key for `api_client_cert`. Must be readable by `www-data` (`root:www-data` `640` under `/etc/jen/ssl/`) — Jen checks that at save time, as the service user. | `/etc/jen/ssl/jen-kea-client.key` |

All of these are optional and backward-compatible — an existing
`jen.config` with none of them behaves exactly as it did before v5.10.0.

### Direct control sockets (Kea 2.7.2+ / required for 3.2+)

ISC **deprecated the Control Agent (`kea-ctrl-agent`) in Kea 3.0** and
**removed it entirely in Kea 3.2**. Since Kea 2.7.2 each daemon
(`kea-dhcp4`, `kea-dhcp6`, `kea-dhcp-ddns`) exposes its own HTTP/HTTPS
command API through a `control-sockets` list. Set `connection_mode =
direct` and point `api_url` at each daemon's socket — dhcp4 under `[kea]`,
dhcp6 under `[kea6]` for the primary and `api6_url` per additional server
(there is **no** fallback from v6 to the v4 URL in direct mode; a
kea-dhcp4 daemon cannot answer DHCPv6 commands). ISC's example uses port
**8004** for dhcp4; Jen's docs use **8006** for dhcp6.

Always **keep the existing `unix` entry** in `control-sockets` alongside
the new one (`kea-shell` and some hooks use it), and **firewall the
HTTP(S) port to the Jen host** regardless of which option below you pick.

#### Recommended — HTTPS on a management address, mutual TLS

Bind the control API to a management IP (not `0.0.0.0`), use HTTPS, and
require a client certificate. In `kea-dhcp4.conf`:

```json
"control-sockets": [
  { "socket-type": "unix", "socket-name": "/var/run/kea/kea4-ctrl-socket" },
  {
    "socket-type": "https",
    "socket-address": "10.10.10.20",
    "socket-port": 8004,
    "trust-anchor": "/etc/kea/tls/ca.crt",
    "cert-file": "/etc/kea/tls/server.crt",
    "key-file": "/etc/kea/tls/server.key",
    "cert-required": true,
    "authentication": {
      "type": "basic",
      "realm": "kea",
      "clients": [ { "user": "kea-api", "password": "your-password" } ]
    }
  }
]
```

Jen side:

```ini
[kea]
connection_mode = direct
api_url  = https://10.10.10.20:8004
api_user = kea-api
api_pass = your-password
api_ca          = /etc/jen/ssl/kea-ca.pem
api_client_cert = /etc/jen/ssl/jen-kea-client.pem
api_client_key  = /etc/jen/ssl/jen-kea-client.key
```

#### Without a client certificate

If you can't deploy a client cert to the Jen host, set `"cert-required":
false` on the Kea socket — otherwise Kea demands a client certificate
Jen can't present and the TLS handshake fails. Jen side: `api_ca` only
(no `api_client_cert` / `api_client_key`). The connection is still
encrypted and still firewalled to the Jen host; it just isn't mutual.

#### Plain HTTP

> ⚠️ Basic-auth credentials are sent **in the clear** over an `http`
> socket (ISC's own guidance). Bind to a management IP, **never
> `0.0.0.0`**, and firewall the port to the Jen host.

```json
"control-sockets": [
  { "socket-type": "unix", "socket-name": "/var/run/kea/kea4-ctrl-socket" },
  {
    "socket-type": "http",
    "socket-address": "10.10.10.20",
    "socket-port": 8004,
    "authentication": {
      "type": "basic", "realm": "kea",
      "clients": [ { "user": "kea-api", "password": "your-password" } ]
    }
  }
]
```

#### Making the certificates

A minimal private CA — one CA, a server cert per Kea host (SAN = the
management IP), one client cert for Jen:

```bash
# CA
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=jen-kea-ca"

# Kea server cert (repeat per host; set the SAN to that host's mgmt IP)
openssl req -newkey rsa:4096 -nodes -keyout server.key -out server.csr \
  -subj "/CN=kea01" -addext "subjectAltName=IP:10.10.10.20"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days 825 -out server.crt -copy_extensions copy

# Jen client cert
openssl req -newkey rsa:4096 -nodes -keyout jen-kea-client.key \
  -out jen.csr -subj "/CN=jen"
openssl x509 -req -in jen.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days 825 -out jen-kea-client.pem
```

On each **Kea host**: `ca.crt`, `server.crt`, `server.key` in
`/etc/kea/tls/` (`root:_kea` `640`). On the **Jen host**: `ca.crt` (as
`api_ca`), `jen-kea-client.pem`, `jen-kea-client.key` in `/etc/jen/ssl/`
(`root:www-data` `640`).

#### Notes

- **Never point `api_url` at an HA peer port.** In Kea 3.2 the HA hook's
  `restrict-commands` defaults to `true`, so the HA listener only accepts
  HA commands — Jen must talk to each daemon's *own* control socket.
- The **Probe** button on Settings → Kea reports the running Kea version
  and whether `ca` or `direct` answered, with a recommendation. Pick the
  server and `dhcp4`/`dhcp6` to test with **that** server's own URL and
  credentials, or paste a specific URL into the box next to it to test a
  candidate direct socket.
- For a **brand-new** Kea with no config yet, "Author a starting
  kea-dhcpX.conf" (Settings → Kea, superadmin) writes the `control-sockets`
  list for you when `connection_mode = direct`: it respects the endpoint
  scheme (http vs https), asks for the TLS paths, sets `cert-required`
  from whether Jen has a client certificate, and generates per server from
  each server's own API settings — including a **bind address chosen per
  server**, defaulting to the address Jen dials for that one. Every
  direct-mode API URL must include an explicit port.

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
| **SuperAdmin** | Full access to everything, all subnets, always — the only role that can manage users or use Database (export/import/backup/migrate) |
| **Admin** | Full management on assigned subnets — Settings (except the Databases tools and user management). Can be restricted to specific subnets (**Settings → Access & Security → Users → subnet access**); unrestricted by default |
| **Viewer** | Read-only access to Dashboard, Leases, Reservations, Subnets, DDNS, scoped to assigned subnets the same way as Admin |

### Adding Users

Go to **Settings → Access & Security → Users → Add User**. Enter a username, password (minimum 8 characters), and select a role.

### Session Timeout

Go to **Settings → Access & Security → Session Timeout** to set the global default timeout in minutes. Individual users can have their own timeout override set from the Users page.

---

## Multi-Factor Authentication (MFA)

Jen supports TOTP-based MFA (Google Authenticator, Authy, 1Password, etc.).

### MFA Policy

Go to **Settings → Access & Security → MFA policy** to set the policy:

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

### MFA Lockout

To prevent brute-forcing a TOTP code or backup code, the MFA verification step locks out after 10 failed attempts for 15 minutes. This is fixed and separate from the login rate limiting below — it isn't affected by that setting and is never permanent, so a locked-out user just needs to wait 15 minutes rather than contact an admin.

---

## REST API

Jen provides a read-only REST API at `/api/v1/` for integration with Home Assistant, Zabbix, and custom scripts.

### Authentication

All endpoints (except `/api/v1/health`) require an API key in the request header:

```
Authorization: Bearer jen_your_key_here
```

### Managing API Keys

Go to **Settings → Access & Security → API Keys** to generate, view, and revoke keys. A key is shown only once at creation — copy it immediately.

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

Full documentation with examples is available at **Settings → Access & Security → API Docs** in the Jen interface.

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

Go to **Settings → Appearance → Brand Icons** to:
- View the 24 bundled brand logos
- Upload a custom SVG to override any bundled icon or add a new manufacturer
- Remove custom icons to revert to bundled versions

Custom icons are stored in `/opt/jen/static/icons/custom/` and survive upgrades.

---

## HTTPS Configuration

### Uploading a Certificate

1. Obtain an SSL certificate for your Jen server hostname (ZeroSSL, Let's Encrypt, or internal CA)
2. Go to **Settings → Access & Security → SSL Certificate**
3. Upload `certificate.crt`, `private.key`, and `ca_bundle.crt`
4. Click **Enable HTTPS** — Jen restarts automatically

After restart, HTTP on port 5050 redirects to HTTPS on port 8443.

### Renewing a Certificate

1. Go to **Settings → Access & Security → SSL Certificate → Replace Certificate**
2. Upload the three new files
3. Jen restarts automatically

---

## Rate Limiting

Configure in **Settings → Access & Security → Login Rate Limiting**.

| Setting | Description | Default |
|---|---|---|
| Max failed attempts | Attempts before lockout. 0 = disabled | 10 |
| Lockout duration | Minutes locked out. 0 = permanent until cleared | 15 |
| Mode | Lock by: IP address, username, or both | Both |

---

## Telegram Alerts

Configure in **Settings → Alerts & Integrations**.

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

1. Go to **Settings → Kea → SSH**
2. Click **Generate SSH Key**
3. Copy the public key displayed

### Authorize on Kea Server

```bash
echo "ssh-rsa AAAA... jen@your-jen-server" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Kea host helper (v5.11.0+)

Every Kea-side action Jen performs — reading a config, testing a
candidate with `kea-dhcpX -t`, replacing the live file, restarting a
daemon, reading a log, installing a Kea package — goes through
`jen-kea-helper`, a small root-owned script at
`/usr/local/sbin/jen-kea-helper`. Jen calls it over SSH as
`sudo -n /usr/local/sbin/jen-kea-helper <op>` with a JSON request on
stdin; it never runs anything it is handed.

That means **one** sudoers line, and it is not root-equivalent the way
the old one was — the helper's own op allowlist and path walls are the
control:

```bash
sudo tee /etc/sudoers.d/jen-kea-helper >/dev/null <<'EOF'
# Jen (DHCP console) — SSH user "youruser". The helper's op allowlist is the control; see docs/ARCHITECTURE.md §3.3
youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper
EOF
sudo chmod 440 /etc/sudoers.d/jen-kea-helper
sudo visudo -c -f /etc/sudoers.d/jen-kea-helper
```

**Installing the helper.** From Jen: **Settings → Kea → SSH**, then
**Install helper** next to the server (this uses the legacy path once —
see below — so the old grant must still be present for the button to
work). By hand, copy `jen-kea-helper` from your Jen host to the Kea
host and:

```bash
sudo install -o root -g root -m 0755 ./jen-kea-helper /usr/local/sbin/jen-kea-helper
```

then add the sudoers line above. **Settings → Kea → SSH** shows
`helper v1` for each host once it is reachable.

Updating the helper is rare — only when its `HELPER_VERSION` changes,
which the release notes will call out. It is always a manual copy (the
helper has no self-update op, on purpose).

### Legacy grant (pre-5.11.0 — `python3` is root)

A Kea host that does not have the helper yet falls back to the old path:
Jen pipes a generated Python script over SSH into `sudo python3`. That
needs the grant below — and **`NOPASSWD: /usr/bin/python3` is root**,
full stop; the other lines only document what Jen runs, they don't
narrow anything. Jen shows an admin banner for every host still on this
path.

Keep this **only until every Kea host shows `helper v1`** in Settings →
Kea → SSH, then remove `/etc/sudoers.d/jen-kea`.

```bash
sudo tee /etc/sudoers.d/jen-kea >/dev/null <<'EOF'
# Jen (DHCP console) — LEGACY fallback. SSH user "youruser". python3 = root; see docs/ARCHITECTURE.md §3.3
youruser ALL=(root) NOPASSWD: /usr/bin/python3
youruser ALL=(root) NOPASSWD: /usr/bin/systemctl restart kea-dhcp4-server, /usr/bin/systemctl restart isc-kea-dhcp4-server
youruser ALL=(root) NOPASSWD: /usr/bin/systemctl * kea-dhcp6-server, /usr/bin/systemctl * isc-kea-dhcp6-server
youruser ALL=(root) NOPASSWD: /usr/bin/tail -200 /var/log/kea/*
youruser ALL=(root) NOPASSWD: SETENV: /usr/bin/apt-get update -qq, /usr/bin/apt-get install -y kea-dhcp4-server, /usr/bin/apt-get install -y kea-dhcp6-server
EOF
sudo chmod 440 /etc/sudoers.d/jen-kea
sudo visudo -c -f /etc/sudoers.d/jen-kea
```

`SETENV` on the `apt-get` line is needed because Jen runs it as
`sudo DEBIAN_FRONTEND=noninteractive apt-get install …`.

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

Jen exposes a Prometheus-compatible metrics endpoint at `/metrics`.

**As of v5.3.3, this endpoint is closed by default** — a security
review correctly pointed out that defaulting to fully open access,
even though the data exposed is deliberately limited to aggregate
counts (never individual MACs, IPs, or hostnames), is backwards from
a secure-by-default posture. You need to explicitly enable it, and
the easiest way is directly from the UI:

**From Settings → Alerts & Integrations → Prometheus Metrics** — enter a
token (or click Generate for a random one) and save, or check "Allow
open access" if you're already restricting `/metrics` at the network
or reverse-proxy level. Takes effect immediately, no restart needed.

If you'd rather edit `jen.config` directly, the same two options are
available under `[server]`:

**Option 1 — token-protected (recommended):**
```ini
[server]
metrics_token = some-long-random-string
```
```bash
curl -k -H "Authorization: Bearer some-long-random-string" https://your-jen-server:8443/metrics
```

**Option 2 — open access (if you're already restricting `/metrics` at
the network or reverse-proxy level and want the old behavior back):**
```ini
[server]
metrics_open = true
```
```bash
curl -k https://your-jen-server:8443/metrics
```

If neither is set, `/metrics` returns 401. **If you were already
scraping `/metrics` without a token before upgrading to v5.3.3, your
scrapes will start failing until you set one of the two options
above.**

Available metrics:
- `jen_subnet_active_leases` — active lease count per subnet (with subnet name and CIDR labels)
- `jen_kea_up` — 1 if Kea is reachable, 0 if not

---

## Health Center

**Network → Health** (`/health-center`) runs a fixed list of read-only
checks and shows `ok` / `warn` / `fail` / `skip` for each, with a one-line
detail and a link to the page that fixes it. It is **read-only** — no
changes are made and **no SSH is used at render time**, so it's safe to
leave open on a phone and safe to poll (it auto-refreshes every 60
seconds). Viewers can see it; a subnet-restricted user sees only their
own subnets in the capacity checks. `/health-center/data` returns the
same run as JSON for scripting (`?partial=1` returns the HTML fragment).

| Check | What it looks at | Where to fix it |
|---|---|---|
| **Kea servers reachable** | `version-get` per configured server | Settings → Kea; the server itself |
| **Kea version supported** | direct mode needs Kea ≥ 2.7.2; `ca` mode warns on Kea ≥ 3.0 (Control Agent deprecated) and fails on ≥ 3.2 (removed) | Settings → Kea → connection mode |
| **HA state healthy** | each server's HA state — `hot-standby`/`load-balancing` is ok, `partner-down`/`waiting`/`syncing` warn, `terminated` fails | Servers page; the Kea HA config |
| **Kea hooks loaded** | `libdhcp_host_cmds.so` (reservations), `libdhcp_lease_cmds.so` (leases), and `libdhcp_ha.so` when HA is configured | add the hook to `kea-dhcp4.conf` and reload |
| **Kea clock in sync** | the `Date` header Kea returns vs Jen's clock — warns > 30 s, fails > 5 min (HA and lease timers assume synced clocks) | NTP on the Kea host and the Jen host |
| **Subnet map matches Kea** | `check_config_drift()` — Jen's `[subnets]` list vs Kea's live config | Settings → Kea → `[subnets]` |
| **Every Kea subnet is named** | every subnet id in Kea's config has a name in Jen's `[subnets]`, and vice-versa | Settings → Kea → `[subnets]` |
| **Pool utilisation** | the latest lease snapshot per subnet — warns at the alert threshold, fails at 95 % | Subnets page; widen the pool |
| **Lease snapshots current** | the newest snapshot is no older than 2× the snapshot interval | Settings → System; check the background worker is running |
| **kea-dhcp-ddns reachable** | when dhcp4 `dhcp-ddns.enable-updates` is on: `version-get` on the `d2` service (`ca` mode only) | DDNS page; the D2 service |
| **kea-dhcp-ddns error counters** | D2's `ncr-error` + `update-error` statistics | DDNS page; the DNS server / TSIG keys |
| **TLS certificate expiry** | days until Jen's HTTPS certificate expires — warns at 30 days, fails at 7 | Settings → Access & Security → upload a renewed certificate |
| **Jen database** / **Kea database** | a `SELECT 1` round trip and its latency | the database host / credentials |
| **Database schema current** | the applied migration version matches the latest | restart Jen (migrations run at startup) |
| **Kea host helper installed** | each SSH-configured Kea host has recorded a `jen-kea-helper` version | Settings → Kea → SSH → Install helper |
| **Background workers running** | the scheduler + alert loop started with this process | only reported under gunicorn, not the werkzeug fallback |
| **Jen up to date** | always `skip` here — run the check from **Settings → System → Updates** (it contacts GitHub) | — |

The **TLS certificate expiring** alert (Settings → Alerts & Integrations)
fires once when the certificate crosses 30, 7, and 1 days remaining, and
resets when you install a renewed one.

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

Go to **Settings → Kea → Servers & High Availability** and set:

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

Go to **Settings → Kea → Servers & High Availability → Additional servers** and add your standby node, or add it to `jen.config`:

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
# Optional per-server DHCPv6 endpoint for direct mode — only needed when
# this server's kea-dhcp6 has its own socket. api6_user / api6_pass fall
# back to api_user / api_pass (v5.10.2):
# api6_url  = http://YOUR-STANDBY-SERVER:8006
# api6_user = kea-api
# api6_pass = your-kea-api-password
```

**A standby's DHCPv6 endpoint is its own.** Jen uses that server's
`api6_url` if set, otherwise — in `ca` mode — that server's own `api_url`
and credentials. The `[kea6]` section is the **primary's** override and is
never used for another server (v5.10.3; before that a standby with no
`api6_url` sent its DHCPv6 commands to the primary).

The **Additional Servers** editor manages `name`, `role`, `api_url`,
`api_user`, `api_pass`, `api6_url`, `api6_user`, `api6_pass`, `ssh_host`,
`ssh_user`, and `kea_conf`. Any other key you've hand-added to a
`[kea_server_N]` section (for example `ssh_key`) is preserved when you
save from the UI. Preservation follows the **server**, not its position in
the list: reordering or removing rows keeps every server's password and
hand-added keys with that server, and the remaining sections are
renumbered contiguously (v5.10.3).

### How Active Node Routing Works

When HA is configured, Jen automatically routes `config-get` and subnet editing commands to the active node. Jen queries `ha-heartbeat` on each server and selects the primary in `hot-standby`, `load-balancing`, or `partner-down` state. Falls back to the first reachable server if no active node is identified.

### HA Failover Alerts

Add an alert channel and enable the **HA failover / state change** alert type. You will receive a notification any time a server's HA state changes — including failovers, recovery, and sync events.

---

## DDNS Provider Configuration

The DDNS page shows Kea DNS update log activity and supports hostname lookup. The DNS provider is configurable — Jen is not tied to Technitium.

### Setting the DNS Provider

Go to **Settings → Alerts & Integrations → DDNS & DNS Provider** and choose:

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

1. Go to **Settings → Alerts & Integrations → Add Channel**
2. Choose **ntfy** as the channel type
3. Enter your ntfy server URL (use `https://ntfy.sh` for the public server, or your self-hosted URL)
4. Enter the topic name (e.g. `jen-alerts`)
5. Optionally set an access token (for protected topics) and priority

No app configuration needed — ntfy delivers to any subscribed device automatically.

### Discord Setup

1. In your Discord server, go to **Server Settings → Integrations → Webhooks → New Webhook**
2. Choose the channel and copy the webhook URL
3. Go to **Settings → Alerts & Integrations → Add Channel** in Jen
4. Choose **Discord** and paste the webhook URL
