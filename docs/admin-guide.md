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
- [ ] Log in as `admin` with the password you set during `install.sh`. If
  you were not prompted (a scripted or Docker install without
  `JEN_INITIAL_ADMIN_PASSWORD`), the installer prints a generated one and
  writes it to `/var/lib/jen/initial-admin-password` —
  `sudo cat /var/lib/jen/initial-admin-password`.
- [ ] Jen forces a password change on that first login; the file is
  deleted once you complete it
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
  direct-mode API URL must include an explicit port. The **Interfaces**
  field is shared across every target by default, but an HA pair whose
  nodes use different NIC names (`ens18` on one, `eth0` on the other,
  say) can override it per server (v5.19.1) — a second field appears
  under each server's bind-address picker once more than one SSH server
  is configured; leave it blank to keep using the shared list for that
  server.

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
| `trusted_proxies` | Comma list of reverse-proxy IPs / CIDRs to trust (v5.17.0) — see below | *(unset)* |
| `metrics_token` | Bearer token required to scrape `/metrics` | *(unset)* |

### Behind a reverse proxy (v5.17.0)

If Jen sits behind nginx / Caddy / Traefik, set `trusted_proxies` to the
proxy's address (an IP or CIDR, comma-separated for several):

```ini
[server]
trusted_proxies = 127.0.0.1, 10.0.0.0/8
```

When a request arrives from one of those addresses, Jen reads the real
client IP from `X-Forwarded-For` and the scheme from `X-Forwarded-Proto`.
Without this, rate limiting, the audit log and MFA trusted-device records
would all see the proxy's IP, and every client would look like the same
one. Requests from any *other* address ignore those headers entirely.

**The proxy must terminate HTTPS.** With `trusted_proxies` set Jen marks
its session cookie `Secure` and sends HSTS, on the assumption the browser
reached the proxy over TLS. Jen itself can then serve plain HTTP on the
loopback / private network between it and the proxy (no cert needed in
`[server]`).

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

### Sessions and step-up (v5.17.0)

- **Sign out** is a button, not a link — a `GET /logout` shows a confirm
  page, only the `POST` ends the session. The session is fully cleared on
  every login and every logout.
- **Confirm-your-password prompts.** Changing your own MFA — enrolling
  another authenticator, regenerating backup codes, adding or removing a
  trusted device, or a superadmin resetting someone's MFA — requires that
  you authenticated (password, plus a code if you have MFA) within the
  last **10 minutes**. Otherwise Jen shows a short "confirm your identity"
  screen first. A failed confirmation counts toward the same lockout as a
  failed login.

---

## Multi-Factor Authentication (MFA)

Jen supports TOTP-based MFA (Google Authenticator, Authy, 1Password, etc.).

### MFA Policy

Go to **Settings → Access & Security → MFA policy** to set the policy:

| Policy | Behavior |
|---|---|
| Off | MFA disabled for all users |
| Optional | Users can enroll but are not required to |
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

Custom icons are stored in `/var/lib/jen/icons/` (v5.13.0; `/opt/jen/static/icons/custom/` before that) and survive upgrades — that directory, like the rest of `/var/lib/jen`, is never touched by an upgrade.

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

## Shared networks (v5.15.0)

Kea lets several subnets share one **shared network** — they share the
whole address-pool space (a client can get an address from any member
subnet) and client classification applies per network. Jen sees, groups
and edits subnets that live inside `Dhcp4.shared-networks` the same way
as top-level ones.

Before 5.15.0 a nested subnet was invisible: it didn't appear on the
Subnets page, its pool wasn't counted, editing it silently did nothing,
and config-drift reported it as *missing from Kea*.

On the **Subnets** page (admin, SSH configured):

- Cards are grouped under a **Shared network: `<name>` · `<interface>`**
  heading; nested cards carry a small **shared** chip.
- The dropdown on each card **moves** the subnet between the top level and
  any shared network — one Kea push and restart.
- **New shared network** (bottom of the page) creates an empty one; add
  subnets to it from the Add Subnet form, or move existing ones in.
- **Delete network** removes an *empty* shared network (move its subnets
  out first). Creating and deleting a network needs access to all subnets.

Renaming a network isn't supported (Kea has none either) — delete the
empty network and create it under the new name.

**What happens when one of several Kea servers refuses a change
(v5.28.0).** Adding, deleting, or editing a subnet pushes to every
SSH-configured Kea server. Every server is validated (`kea-dhcp4 -t`)
before any of them is actually written; if one refuses (a stale
concurrency check, a config-test failure), nothing is written to
*any* server, and if a later server fails after an earlier one already
committed, that earlier write is reverted back to what it was —
never "server A has the new subnet, server B doesn't." A restart
failure after a successful write is reported per-server instead
("restart Kea manually") since the config on disk is already valid at
that point.

---

## DHCP Options (v5.18.0)

**Subnets → Options** on a subnet card (or the "Options: N here · M
inherited" line) opens a catalog-driven editor for `option-data` at four
levels — **global**, **shared network**, **subnet**, and **pool** — plus
an "Effective options" view that shows, for a given subnet or pool,
which value actually wins and where the ones it beat came from.

**Precedence.** For a lease, the most specific level wins:

```
pool  >  subnet  >  shared network  >  global
```

An option set at a more specific level *overrides* the same option set
higher up — it doesn't merge with it. The Effective options panel lists
every overridden value (struck through) alongside the one that's live.

**Why routers and DNS servers aren't here at the subnet level.** Codes 3
(`routers`) and 6 (`domain-name-servers`) at the **subnet** level are
owned by the **Edit Subnet** form, which already has dedicated Router
and DNS Servers fields — editing them from two places would be a good
way to silently overwrite one with the other. The Options page shows
them as **managed by Edit form** at that level with a link over, and
refuses a write there (server-side, not just hidden in the UI). The
*same* codes at global, shared-network, or pool level are ordinary
options — Jen doesn't special-case them there.

**Catalog and custom codes.** The "Add option" form offers Kea's common
DHCPv4 options by name (subnet-mask, routers, DNS, NTP, TFTP, classless
static routes, and more) with per-type validation before anything is
pushed to Kea. Anything else is a **Custom code** (1–254): give it a
number and, optionally, a name, and enter the value as raw hex — Jen
writes it with `csv-format: false` since it has no type information for
an option it doesn't recognize.

**Classless static routes** (code 121) use Kea's csv syntax — one or
more `network/prefix - router` pairs, comma-separated:

```
192.168.10.0/24 - 10.0.0.1, 0.0.0.0/0 - 10.0.0.1
```

**Not covered by this page:** per-client-class options (see **Client
Classes** below), reservation-level options beyond the existing DNS
field, `option-def` (custom option *definitions* — listed read-only at
the bottom of the page), IPv6 options, and vendor-space options (e.g.
`vendor-4491`) — those still require hand-editing `kea-dhcp4.conf`.

---

## Client Classes (v5.19.0)

**Subnets → Client Classes** manages Kea's `Dhcp4.client-classes` — the
list Kea evaluates, in order, against every incoming packet. A class can
**gate** eligibility for a subnet, pool, or shared network (a *guard*:
only clients matching the class are considered for it) or just attach
extra options to whichever clients match it without gating anything
(*additional*).

**Guided rules vs. a raw expression.** Most classes reduce to a small
set of shapes — match a vendor class string, a MAC address or OUI, a
relay circuit/remote ID, a hostname, or membership in another class.
The guided builder covers those: pick a field, an operator, and a
value, combine several rules with **all**/**any**, and optionally
negate the whole thing. Anything the builder can't express — a
`substring()` at an arbitrary offset, nested boolean logic, a
comparison against `pkt4.len`, and so on — goes in the **Advanced** tab
as Kea's own classification-expression syntax. Opening a class whose
expression doesn't match what its saved guided rules would produce
(because someone hand-edited it, in the Kea config directly or on an
older Jen version) opens in Advanced mode with a notice, rather than
silently overwriting the hand edit if you happen to hit Save.

Kea string literals are single-quoted with **no escape sequence** — a
value containing `'` can't be expressed as a guided rule or a literal
in Advanced mode.

**Preview.** As you edit, Jen shows the expression it will write and
runs it past Kea's own config test (`kea-dhcp4 -t`) with the candidate
class inserted into a copy of the live config — nothing is written to
disk for this. A rejection here is Kea's own error message, so it
catches a malformed expression before Save ever pushes anything.

**Only in additional list.** Kea 2.7.4 renamed several attachment keys
(`client-class` → `client-classes`, `require-client-classes` →
`evaluate-additional-classes`, `only-if-required` →
`only-in-additional-list`). Jen reads both spellings everywhere; when
*writing*, it keeps whatever spelling your config already uses, and
only picks based on the connected Kea's version when the config uses
neither yet. You'll never see a config that mixes both for the same
purpose because of something Jen wrote. Ticking the box without also
attaching the class as **Additional** somewhere means Kea will never
evaluate it — Jen warns about that both right after Save and on the
edit page itself (v5.19.1) until you fix one side or the other.

**Applies to.** Once a class exists, its edit page lists every subnet,
pool, and shared network with a **Guard** / **Additional** checkbox
each — check one to attach, uncheck to detach. A brand-new class has no
key to attach yet, so this list (and its option-data) only appears
after the first save.

**Deleting a class** that's still attached anywhere, or still named in
another class's `member(...)` expression, is refused with the list of
what's still using it — detach or edit those first.

**Built-in classes** (`ALL`, `KNOWN`, `UNKNOWN`, `DROP`, the
`VENDOR_CLASS_*`/`HA_*`/`AFTER_*`/`SPAWN_*` families, and `BOOTP`) show
up grayed-out if Kea's config authors option-data against them, but
Jen never creates, edits, or deletes them.

**Not covered by this page:** IPv6 classes, custom `option-def`s for
vendor spaces, per-class lease limits, and pool selection driven by class
beyond guard/additional attachment — those still require hand-editing
`kea-dhcp4.conf`. There's also no way to test a class against a
simulated packet — the config-test preview above is the closest Jen
gets; anything more needs a real DHCP exchange against a test client.
(Importing an existing Windows DHCP policy set as classes is covered
separately — see [Migrating from Windows DHCP](#migrating-from-windows-dhcp-v5240).)

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

then add the sudoers line above. **Settings → Kea → SSH** shows the
installed version for each host once it is reachable — green when it's
current, amber ("upgrade available") when it isn't.

**Upgrading the helper.** Rare — only when the release notes call out a
new `HELPER_VERSION`. Press **Update helper** in Settings → Kea → SSH
(the same button, relabelled once a version is already recorded) — it
re-copies the current file over the old one, then confirms the upgrade
actually took by asking the freshly-copied helper its own version
rather than trusting what the install script printed. If the copy
somehow didn't take (a shadowing binary earlier on `$PATH`, a stale
cache), the flash says so as "the copy did not take" instead of
claiming success. This still runs over the legacy `sudo python3` path —
the old grant needs to be present for one run, same as a fresh install;
if it's already been removed, the flash gives you the manual
`install -m 0755` command instead. There is no self-update op, on
purpose. v5.16.0 shipped **helper v2** (optimistic concurrency — see
below); a host still on v1 shows the amber hint and keeps working
behind the best-effort guard until it's upgraded. **Health Center**
(v5.19.1) also warns per host once a v1 helper is more than a passing
state — see "Kea host helper installed" there.

**v5.20.0 — the legacy grant is now checked, not just used.** Every
time Jen checks or installs the helper it also checks whether
`/etc/sudoers.d/jen-kea` (below) is still present, and records that
alongside the version. Settings → Kea → SSH shows a **"legacy grant
still present"** chip next to a host's helper status once it does, and
Health Center's "Kea host helper installed" check warns for the same
reason — even on a host that's fully upgraded to the current helper
version, since leaving the old grant in place after you no longer need
it is itself the residual risk. Remove
`/etc/sudoers.d/jen-kea` once every host you administer that way shows
`helper v2` (or later) to clear both.

### Kea config history (v5.16.0+)

Every Kea config Jen writes to a host is saved in Jen's database as a
revision — who, when, why, and the full config — and so is any change
Jen notices was made **outside** Jen on the next read (a hand edit to
`kea-dhcp4.conf`, say). Open it from **Servers → Config history** on
each server card. A revision page shows a unified diff against the one
before it, a **Download (masked)** link, and — for superadmins — a
**Restore this revision** button that re-validates the old config with
`kea-dhcpX -t`, re-applies it, and restarts Kea.

How many revisions are kept per server and service is **Settings →
System → Kea Config History** (default 50; older ones are pruned).
Because the page shows the whole config for a server — including subnets
a subnet-restricted admin can't otherwise see — the history pages need
access to **all** subnets, not just admin.

**Bodies are encrypted at rest (v5.20.0).** Every stored revision is
encrypted with the same Fernet key already used for MFA secrets and
alert-channel credentials (`jen/services/crypto.py`) — a database
dump alone doesn't hand over your Kea configs. This is transparent
everywhere in the UI; a pre-5.20.0 install re-encrypts its existing
history automatically on the first startup after upgrading.

**History is masked by default (v5.20.0).** The diff and the
**Download (masked)** link both redact any `password`, `secret`, or
`basic-auth-password` key (and anything ending `-password`,
`_password`, or `-secret`) to `********` — HA peer credentials, DB
passwords, DDNS TSIG keys. A change to a masked value's text doesn't
show up in the diff, by design. A superadmin sees a **Download
unmasked** link as well, which re-asks for your password if it's been
more than 10 minutes (the same step-up prompt as other sensitive
actions) and is recorded in the audit log every time it's used.

**The first "baseline" revision (v5.20.0).** The very first config
Jen ever sees on a given server/service — and the first one it sees
again right after that host's helper crosses from v1 to v2 — is
recorded with a **baseline** badge instead of `external` or `restore`.
This is expected, not a hand edit Jen noticed: it's just Jen recording
"here's what I found" before anything it does is comparable to
anything else.

**Optimistic concurrency.** With helper v2, the edit-subnet / add /
delete / shared-network forms send the config's SHA as it was when the
form was opened; if the file on the host changed underneath (another
admin, a hand edit), the write is refused atomically and you get *"The
Kea config on <host> changed since you opened this form — your edit was
NOT applied. Reload and try again."* This SHA is per server (v5.19.1) —
each server in an HA pair carries its own, since two servers' configs
are never byte-identical (each has its own `this-server-name`, at
least). On a host still running **helper v1 or the legacy path** there
is no atomic guard: Jen does a best-effort re-read-and-compare instead,
warns *"No atomic guard on <host>"* once per request, and does **not**
capture out-of-band changes as revisions (no SHA to compare). Upgrade
the helper to close that gap.

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

Select **Keep existing config** when prompted. The installer builds the new release under `/opt/jen/releases/<X.Y.Z>/`, points `/opt/jen/current` at it with one atomic symlink flip, restarts the service, and flips back to the previous release if it fails to start.

Your config file and SSL certificates and SSH keys (in `/etc/jen`), and your uploads, database backups and installed plugins (in `/var/lib/jen`), are never modified during an upgrade. Each release's application tree and its own virtualenv are root-owned and read-only to the service account.

**v5.27.0 changes how a new plugin install lands.** Installing or reinstalling a plugin from Settings → Plugins no longer writes its files directly — Jen asks a dedicated root-privileged service to fetch, verify, and place them, and the result lands read-only under `/opt/jen/plugins-installed/`, the same way a Jen release itself is root-owned. A plugin installed before v5.27.0 still works from its old, Jen-writable location (`/var/lib/jen/plugins/`); the Plugins page marks it "writable — reinstall to harden" with a one-click Reinstall button that moves it to the new location. Nothing about enabling, disabling, or a plugin's own database tables changes.

**v5.28.0 makes the page wait for the root side to actually finish.** A root-owned install/remove used to record success (and, for an install, offer Enable) the moment the request was queued — a request that then failed root-side still looked done everywhere except a result file nobody read. The page now only shows an install as recorded, and only offers Enable, once the root service's own result file confirms it; a failure flashes the real reason (e.g. a version requirement the running Jen doesn't meet) instead of silently doing nothing.

**v5.14.0 introduces the versioned layout.** The first upgrade to 5.14.0 must be run with `sudo ./install.sh` — the in-app update button cannot make the jump (the box has no `current` symlink yet, so the new unit can't start, and the in-app attempt rolls back cleanly to your current version). Every in-app update from 5.14.0 onward is the atomic-symlink path. The 5.14.0 install also removes the now-unused flat `/opt/jen/{jen,run.py,templates,static,plugins,venv}` once the versioned layout is live.

### Rolling back by hand

The previous release directory is left on disk. To go back to it:

```bash
ls /opt/jen/releases
sudo ln -sfn releases/<X.Y.Z> /opt/jen/current
sudo systemctl restart jen
```

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
| **Pool utilization** | the latest lease snapshot per subnet — warns at the alert threshold, fails at 95 % | Subnets page; widen the pool |
| **Lease snapshots current** | the newest snapshot is no older than 2× the snapshot interval | Settings → System; check the background worker is running |
| **kea-dhcp-ddns reachable** | when dhcp4 `dhcp-ddns.enable-updates` is on: `version-get` on the `d2` service (`ca` mode only) | DDNS page; the D2 service |
| **kea-dhcp-ddns error counters** | D2's `ncr-error` + `update-error` statistics | DDNS page; the DNS server / TSIG keys |
| **TLS certificate expiry** | days until Jen's HTTPS certificate expires — warns at 30 days, fails at 7 | Settings → Access & Security → upload a renewed certificate |
| **Jen database** / **Kea database** | a `SELECT 1` round trip and its latency | the database host / credentials |
| **Database schema current** | the applied migration version matches the latest | restart Jen (migrations run at startup) |
| **Kea host helper installed** | each SSH-configured Kea host has recorded a `jen-kea-helper` version, and (v5.20.0) whether the legacy `python3` grant is still present | Settings → Kea → SSH → Install helper; remove `/etc/sudoers.d/jen-kea` |
| **Background workers running** | the scheduler + alert loop started with this process | only reported under gunicorn, not the werkzeug fallback |
| **Jen up to date** | always `skip` here — run the check from **Settings → System → Updates** (it contacts GitHub) | — |

The **TLS certificate expiring** alert (Settings → Alerts & Integrations)
fires once when the certificate crosses 30, 7, and 1 days remaining, and
resets when you install a renewed one.

---

## File Locations Reference

| Path | Purpose |
|---|---|
| `/opt/jen/releases/<X.Y.Z>/app/` | One release's application tree (root-owned, read-only to the service account) — v5.14.0 |
| `/opt/jen/releases/<X.Y.Z>/venv/` | That release's virtualenv |
| `/opt/jen/current` | Symlink to the live release; a rollback flips it |
| `/var/lib/jen/icons/` | User-uploaded custom brand icons (v5.13.0) |
| `/var/lib/jen/branding/` | Uploaded favicon and nav logo (v5.13.0) |
| `/var/lib/jen/backups/` | Database backups (v5.13.0) |
| `/opt/jen/plugins-installed/` | Registry-installed plugins, root-owned and read-only to Jen (v5.27.0 — see above) |
| `/var/lib/jen/plugins/`, `/var/lib/jen/plugins-enabled/` | Legacy (pre-5.27.0) registry-installed plugins, and enable markers (v5.13.0) |
| `/var/lib/jen/plugin-requests/` | Install/remove request markers and results for the flow above (v5.27.0) |
| `/var/lib/jen/keys/` | `.secret_key` / `.mfa_key` fallbacks when `/etc/jen` copies are absent (v5.13.0) |
| `/etc/jen/jen.config` | Configuration — credentials and settings |
| `/etc/jen/secret_key`, `/etc/jen/mfa_key` | Flask session secret + MFA encryption key (auto-generated) |
| `/etc/jen/ssl/` | SSL certificates |
| `/etc/jen/ssh/` | SSH keys for subnet editing |
| `/etc/jen/backups/` | `jen.config` snapshots created during upgrades |
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
save from the UI. Preservation follows the **server**, not its position
in the list: reordering or removing rows keeps every server's password
and hand-added keys with that server. **The number in `[kea_server_N]`
is that server's permanent identity** (v5.20.0) — config history,
recorded helper status, and every `/servers/<id>` URL are keyed by it —
so saving no longer renumbers the remaining sections; removing a server
leaves a gap, and that's normal. Don't renumber `[kea_server_N]`
sections by hand.

### How Active Node Routing Works

When HA is configured, Jen automatically routes `config-get` and subnet editing commands to the active node. Jen queries `ha-heartbeat` on each server and selects the primary in `hot-standby`, `load-balancing`, or `partner-down` state. Falls back to the first reachable server if no active node is identified.

### Operating HA from Jen (v5.21.0)

**Servers** shows an **HA Status** panel on each server card that has the
`libdhcp_ha.so` hook loaded: local role/state, the partner's last-known
state and how long ago it was in touch, unacked-clients-left (a red
"partner-down imminent" badge once it drops to 2 or fewer — the partner
is close to being declared down), a collapsed config summary (mode,
timers, peers), and a **Compare Leases** table below the server grid
showing each subnet's assigned-address count side by side, with a
mismatched row highlighted — a small, momentary difference is normal
under load-balancing, a persistent one is worth investigating.

The action buttons send Kea's own HA commands, each confirmed before it
runs and recorded in the audit log:

- **Heartbeat** (admin) — re-checks this server's HA state right now,
  the same read-only `ha-heartbeat` call the page already uses elsewhere,
  offered here as an on-demand refresh.
- **Sync** (superadmin) — `ha-sync`: pulls the partner's lease database
  onto this server. Jen determines the partner's name from this
  server's own config — never from the form — so use it when you know
  this server's leases have fallen behind and you want it caught up
  from the partner, not the other way around. Can take a while on a
  large lease database.
- **Set Scopes** (superadmin) — `ha-scopes`: forces which server serves
  which scope, overriding the HA state machine's own decision. Use this
  only when you specifically need one server to stop or start serving a
  scope outside of normal failover — Kea does not persist this across a
  restart.
- **Continue** (superadmin) — `ha-continue`: tells this server to leave
  a `waiting` or `terminated` state and resume normal HA operation. Use
  it once you've confirmed the condition that caused the stall (a config
  mismatch, a manual `ha-reset` on the partner, etc.) is resolved.
- **Start/Cancel Maintenance** (superadmin) — `ha-maintenance-start` /
  `ha-maintenance-cancel`: tells the partner to take over from this
  server for planned work (an OS update, a hardware swap), then cancels
  that handover when you're done. Prefer this over stopping the Kea
  service directly — it's a clean, HA-aware handover instead of the
  partner discovering a dead peer.
- **Reset** (superadmin) — `ha-reset`: re-runs the HA state machine from
  scratch. This is the last resort Kea's own HA documentation describes
  for a state that isn't otherwise recovering — don't reach for it
  first.

**Kea ≥ 3.2 in `ca` mode:** these HA commands go through the Control
Agent, which Kea 3.2 removes (see "Kea Version Supported" in Health
Center). On such a host, switch to `direct` mode first (Settings → Kea)
— the existing deprecation banner already covers this, and the HA panel
simply won't work until you do. In `direct` mode, Kea's
`restrict-commands` hook parameter (default `true` since Kea 3.2)
refuses an HA command that doesn't arrive on the HA hook's own control
socket; Jen's direct mode already targets that socket, so no extra
configuration is needed there.

### HA Failover Alerts

Add an alert channel and enable the **HA failover / state change** alert type. You will receive a notification any time a server's HA state changes — including failovers, recovery, and sync events.

---

## DDNS

The **DDNS** page (Network → DDNS) has four tabs: **Status**, **Naming**, **D2 Configuration**, and **Verify**. It covers two independent mechanisms for keeping DNS in sync with DHCP leases, and Jen treats neither as more "correct" than the other:

- **Provider mode** — Jen itself pushes hostname records to an external DNS server's REST API (Technitium, Pi-hole, AdGuard Home) or over SSH (`dig`/`host` against BIND/Unbound). This existed before v5.23.0 and is unchanged.
- **D2 mode** — Kea's own DNS-update daemon, `kea-dhcp-ddns` ("D2"), sends dynamic DNS updates (RFC 2136) directly from `kea-dhcp4` as leases are issued/renewed/released. Jen v5.23.0 added the ability to read D2's status, configure its forward/reverse zones and TSIG keys, and verify what actually landed in DNS.

`[ddns] mode` picks which one the Status tab and Health Center report on: `provider` (default when a real provider is configured), `d2` (default when no provider is set but dhcp4's own DDNS is enabled), or `both`. This is display-only — running both mechanisms against the same records at once is an operator choice Jen doesn't second-guess, but it isn't a use case D2's own conflict-resolution options were designed to reconcile.

### Provider mode

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
dns_provider = technitium   # technitium, pihole, adguard, ssh, or none
api_url      = https://your-technitium-server/api
api_token    = your-token
forward_zone = your.domain.com
```

The **Status** tab's Hostname Lookup card queries whichever provider is configured, unchanged from earlier releases.

### D2 mode

D2 needs three things before Jen can manage it: a reachable control socket, at least one forward or reverse zone, and (usually) a TSIG key so BIND/Unbound/Technitium accept the updates as authenticated rather than rejecting them outright.

**1. Point Jen at D2's control socket.** In `ca` connection mode (the default) the Control Agent already proxies D2 alongside dhcp4/dhcp6 — nothing to configure. In `direct` mode, set **Settings → Kea → D2 Control Socket** (or `[d2] api_url` in `jen.config`) to D2's own HTTP control socket, conventionally port 53001:

```ini
[d2]
api_url  = http://YOUR-KEA-SERVER:53001
api_user = kea-api
api_pass = your-kea-api-password
```

`api_user`/`api_pass` fall back to `[kea]`'s if unset. Additional servers set their own `api_d2_url`/`api_d2_user`/`api_d2_pass` under their own `[kea_server_N]` section.

**2. Enable it on the dhcp4 side.** The **Naming** tab writes `Dhcp4.dhcp-ddns` (the master "send updates to D2" switch, D2's IP/port, and the NCR wire protocol) plus the naming knobs that control what hostname gets sent and how — qualifying suffix, generated-name prefix, conflict-resolution mode, and so on. Saving pushes to every SSH-configured Kea server and restarts dhcp4 on each.

**3. Configure D2's own zones and keys.** The **D2 Configuration** tab reads and writes `kea-dhcp-ddns.conf` directly (via the same helper + optimistic-concurrency guard as every other config edit in Jen — see "Kea Config History" below). Example: a BIND-hosted `lan.example.com` forward zone and its matching `/24` reverse zone, secured with a TSIG key.

On the BIND server, generate a key and allow D2 to update the zone:

```
tsig-keygen -a hmac-sha256 d2-key
```

```
key "d2-key" {
    algorithm hmac-sha256;
    secret "<the base64 secret tsig-keygen printed>";
};

zone "lan.example.com" {
    type primary;
    file "/etc/bind/db.lan.example.com";
    allow-update { key "d2-key"; };
};

zone "0.0.10.in-addr.arpa" {
    type primary;
    file "/etc/bind/db.10.0.0";
    allow-update { key "d2-key"; };
};
```

(A Technitium DNS server's UI equivalent: Zones → Add Zone → Primary, then Zone Options → Dynamic Updates → add the same TSIG key under Settings → DNS → TSIG.)

In Jen's D2 Configuration tab:

1. **TSIG Keys** → Add: name `d2-key`, algorithm `hmac-sha256` (must match what `tsig-keygen` used), paste the same base64 secret. The secret is write-only — Jen never re-displays it after saving, the same way an API key or database password never is.
2. **Forward Domains** → Add: zone `lan.example.com.` (note the trailing dot — Kea's own convention, and Jen requires it), key `d2-key`, DNS servers `10.0.0.1:53` (one `ip[:port]` per line — port defaults to 53 if omitted; an IPv6 server needs brackets around the address, `[2001:db8::53]:53`, since a bare IPv6 address can itself end in a colon plus digits — Jen never guesses which trailing digits are a port).
3. **Reverse Domains** → Add: zone `0.0.10.in-addr.arpa.`. Jen suggests this name next to the field for any subnet whose CIDR is a classful `/8`, `/16`, or `/24` — a classless `/25`–`/30` subnet needs its own RFC 2317 delegated zone name, which Jen can't safely guess and doesn't attempt to.

Each Add/Remove pushes to every SSH-configured server, guarded by that server's own current config hash (a stale read elsewhere can't silently overwrite a change made in between), tests the result with `kea-dhcp-ddns -t` before writing, and restarts D2 — exactly the same lifecycle as every other Kea config edit in Jen.

**4. Verify it actually worked.** The **Verify** tab runs `socket.getaddrinfo()`/`socket.gethostbyaddr()` from the Jen host's own system resolver — not from Kea, not from D2 directly — so a green check here means an ordinary client would see the same thing. Type a hostname and/or IP (or use one from an active lease) and Jen shows the forward and reverse results side by side with a ✓/✗ for whether they match what you typed.

### Troubleshooting D2

See `docs/troubleshooting.md` for a table mapping D2's `statistic-get-all` counters (`ncr-error`, `update-error`, etc.) to likely causes — TSIG key mismatches and an unreachable DNS server are the two most common.

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

---

## Migrating from Windows DHCP (v5.24.0)

**Subnets → Import from Windows DHCP** (superadmin only) reads a Windows
Server DHCP export and builds the equivalent Kea config for you to review
before anything is applied.

On the Windows DHCP server:

```powershell
Export-DhcpServer -ComputerName <server> -Leases:$False -File C:\dhcp-export.xml
```

Copy `dhcp-export.xml` to a machine you can reach Jen from and upload it.
Nothing is written to Kea during upload or review — Jen only parses the
file and shows you what it found.

**What maps:**

- Each scope → a `subnet4` with pools carved from its address range minus
  its exclusion ranges, and its lease duration.
- Scope options (routers, DNS, domain name, NTP, NetBIOS, boot server,
  domain search, and the classless static route options, 121 and the
  Microsoft-specific 249) → Kea `option-data`. An option Jen doesn't
  recognize is skipped with a warning rather than guessed at.
- Reservations → added to Kea's host database via `reservation-add` once
  you apply. Only `Dhcp`-type reservations with a real MAC address import;
  `Both`/`Bootp`-type reservations and anything with a non-MAC client ID
  are skipped and listed in the warnings.
- A superscope with two or more scopes actually selected for import
  becomes a Kea shared network; a superscope with only one scope selected
  stays a plain top-level subnet — Kea has no equivalent of a
  single-member superscope.
- Windows policies (the DHCP policy engine used for vendor/user class or
  MAC-based option overrides) become Kea client classes. A policy scoped
  to an IP range within the scope becomes a guard on just the pool
  carved out for that range; a policy with no IP range guards the whole
  subnet instead. A policy combining `Equals` and `NotEquals` conditions,
  or negating more than one condition, can't be expressed as a single
  Kea expression and is skipped with a warning — recreate it by hand
  under **Client Classes** afterward if you need it.

**What doesn't map** (skipped, with a warning, or simply not read):
IPv6 scopes, DHCP failover/HA relationships (set those up separately —
see [Kea HA Configuration](#kea-ha-configuration)), server-level policies
(only scope-level policies are read), MAC filter allow/deny lists, and
lease state — this is a config migration, not a lease migration.

**Review, then preview, then apply.** The review step lists every scope
with an include checkbox (active scopes are checked by default, inactive
ones aren't) and lets you change the subnet ID or name Jen suggests
before anything is computed. Preview runs `kea-dhcp4 -t` against the
merged config and shows a real diff against what's live right now — apply
is refused if Kea rejects the config. Applying pushes the config, restarts
Kea, adds the queued reservations one at a time (a failure on one
reservation doesn't stop the others — failures are listed at the end),
and registers the new subnets with Jen.

**This only ever touches the primary Kea server's config.** If you run
an HA pair, sync the change to the standby the way you already do for any
other config change — the wizard doesn't know about your HA relationship
and won't push to a partner on its own.

**Validated against a real `Export-DhcpServer` file** (two scopes, 57
reservations, per-reservation options). Exclusions, superscopes,
policies and options 121/249 are still only exercised by a
hand-authored fixture — read the preview diff before you apply.

---

## Single sign-on (OIDC) (v5.25.0)

**Settings → Access & Security → Single Sign-On** (superadmin only) lets
users log in through an external OpenID Connect provider — Authentik,
Keycloak, Entra ID, Okta, or anything else that speaks OIDC — with a
role mapped from a claim. Local accounts keep working exactly as before;
this is an additional login path, not a replacement.

### Setting it up

1. Register Jen as an OIDC client (a "confidential client" / "web
   application") at your IdP, with the redirect URI
   `https://your-jen-host/login/oidc/callback`.
2. On Settings → Access & Security, tick **Enable single sign-on** and
   fill in:
   - **Issuer URL** — your IdP's issuer, e.g.
     `https://authentik.example.com/application/o/jen/`. Jen reads
     `<issuer>/.well-known/openid-configuration` for everything else.
     Must be `https://` (an `http://127.0.0.1`/`localhost` issuer is
     allowed only for local testing).
   - **Client ID** / **Client Secret** — from the IdP's client
     registration. The secret is write-only, same as every other
     password field in Jen: it's never shown again, and leaving it
     blank on a later save keeps the existing value.
   - **Role Mapping** — `role=claim-value[,claim-value...];...`, e.g.
     `superadmin=jen-superadmin;admin=jen-admin;viewer=jen-viewer`. The
     right side names group(s)/claim value(s) at the IdP, not a Jen
     concept — create groups (or an equivalent claim) there with those
     exact names, or change the mapping to match names you already
     have. A user who belongs to more than one mapped group gets the
     highest-privilege one.
   - **Default Role** — used when a user's groups match nothing above.
     Set to **None** to deny login outright for anyone with no mapped
     group, rather than quietly handing out Viewer to every employee at
     the organization.
3. Save. The **Sign in with SSO** button appears on the login page
   immediately — no restart needed.

### Provider examples

**Authentik** — create a group per role (`jen-superadmin`, `jen-admin`,
`jen-viewer`), assign users to them, and add a `groups` scope mapping to
the application so the ID token/userinfo carries a `groups` claim listing
group names. Role Mapping: `superadmin=jen-superadmin;admin=jen-admin;viewer=jen-viewer`.

**Keycloak** — use Keycloak's realm or client roles, and add a "Group
Membership" or "User Realm Role" protocol mapper to the client so the
token exposes a `groups` (or `roles`) claim. If you map realm roles
instead of groups, set **Role Claim** to `roles` and point the mapping
at your role names instead.

**Entra ID (Azure AD)** — by default Entra sends `groups` as GUIDs
(object IDs), not display names, unless you configure the app
registration's optional claims to emit group names — Role Mapping
accepts either, it's just matching strings, but a GUID-based mapping is
harder for a human to audit later. Configuring "Emit groups as role
claims" or adding the `groups` optional claim with the `sAMAccountName`
or `NetbiosDomainAndSAMAccountName` group type gets you readable names.

### The linking rules

A repeat login is matched **only** on the IdP's `sub` claim — never on
username or email, both of which can be reassigned or reused at most
IdPs over time. First login for a new `sub`: if **Automatically create
an account** is on, Jen creates one (username sanitized from the
`preferred_username` claim, falling back to `email` then `sub` if that
doesn't pass Jen's username rules) with a random, immediately-discarded
password and the mapped role. If a *local* account already has that
username, the login is refused with "an account named X already exists
— ask an admin to rename it or link it" — Jen never auto-suffixes or
guesses; ambiguity here is worse than a refusal. The sanctioned way to
convert an existing local account is the **Link to SSO** action on the
Users page (edit a user → enter their external ID / `sub` claim by
hand, confirmed out of band) — from that point on it behaves exactly
like an auto-created account.

On every subsequent login, an OIDC user's role is recomputed from
their current groups and overwritten if it changed — Jen doesn't trust
a role assigned to them locally to still be correct. Subnet access
stays Jen-managed either way; nothing about SSO touches it.

### What's different for an SSO-managed account

- **No local password.** The Users page hides the password-reset
  fields and disables the role selector (with a note explaining why)
  for a linked account — its role comes from the IdP, and its password
  was never meant to be used. A local `/login` attempt for that
  username is refused with the same generic "invalid username or
  password" message a wrong password gets, so the login form can't be
  used to figure out which accounts are SSO-managed.
- **No Jen MFA.** The IdP owns multi-factor authentication for its own
  users; Jen's MFA enrollment page shows "managed by your identity
  provider" instead of offering to enroll a factor Jen would never
  actually check.
- **Confirming your identity for sensitive actions (v5.28.0).** A
  handful of routes (MFA management, a masked config-history download)
  require a "recent" login and bounce you to a confirmation step
  otherwise. For a local account that's a password (and TOTP/backup
  code, if enrolled) re-entry; an SSO-managed account has no usable
  local password to enter, so it's sent through a fresh sign-on round
  trip with your IdP instead (`prompt=login`, so the IdP can't just
  silently re-assert an existing session) — confirming the SAME
  identity is still behind the keyboard without ever re-running role
  mapping or creating a new session.
- **Deleting** an SSO-managed account works the same as any other.

### The local login form

**Keep the local username/password form on the login page** stays on
by default — SSO is additive. Unchecking it hides the password form
entirely, but `/login?local=1` always works regardless, as a
break-glass path if the IdP is ever unreachable.

### Behind a reverse proxy

If Jen sits behind a proxy that changes the externally-visible URL (a
different hostname, or terminating TLS in front of a plain-HTTP Jen),
set `[server] trusted_proxies` (see "Configuration File Reference →
Behind a reverse proxy" above) so Jen computes the right scheme/host
for its own redirect URI. If that still doesn't match what your IdP
expects, set **Redirect URI** explicitly to override it.

### Logout

Signing out of Jen only ends the Jen session — it does not sign you out
of the identity provider (no RP-initiated logout). If your IdP session
is still active, visiting `/login/oidc` again will sign you straight
back in.

### Not covered

SAML and LDAP providers, SCIM provisioning, RP-initiated logout, API
keys via OIDC, and mapping IdP groups to per-subnet access restrictions
(the role mapping only ever produces superadmin/admin/viewer) are all
out of scope for this release.
