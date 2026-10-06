# Jen Administrator Guide

This guide covers installation, configuration, and administration of Jen.

---

## Runbooks

Quick links into the procedures below, roughly in the order you're likely to need them. The in-app [Getting Started](#first-time-setup-checklist) checklist covers the same ground for a fresh install.

- **Install Jen** — [First-Time Setup Checklist](#first-time-setup-checklist)
- **First login** — [First-Time Setup Checklist](#first-time-setup-checklist) (forced password change, SSL certificate, SSH key)
- **Add the HA partner** — [Kea HA Configuration](#kea-ha-configuration), [Operating HA from Jen](#operating-ha-from-jen-v5210)
- **Set up direct control sockets** — [Direct control sockets](#direct-control-sockets-kea-272--required-for-32)
- **Rotate the Kea CA** — [Direct control sockets](#direct-control-sockets-kea-272--required-for-32) ("Let Jen do it" — the Rotate Kea CA button)
- **Take a node down for patching** — [Planned maintenance, step by step](#planned-maintenance-step-by-step-v5380)
- **Upgrade Kea to 3.2** — [Upgrading Kea](#upgrading-kea-the-32-readiness-group-v5380)
- **Migrate from Windows DHCP** — [Migrating from Windows DHCP](#migrating-from-windows-dhcp-v5240)
- **Migrate from ISC DHCP** — [Migrating from ISC DHCP (dhcpd.conf)](#migrating-from-isc-dhcp-dhcpdconf-v5370)
- **Recover Jen on a new machine** — [Recover Jen on a new machine](#recover-jen-on-a-new-machine); `sudo ./install.sh --restore` from a Settings → Databases → Recovery bundle (stops Jen, snapshots what it replaces, health-checks, and rolls back on failure)
- **Undo a restore** — `sudo ./install.sh --rollback <snapshot dir>`, see [Recover Jen on a new machine](#recover-jen-on-a-new-machine)
- **Restore from a backup on the same machine** — Settings → Databases → Backups (export/import individual tables without moving to a new box)
- **Get help** — Settings → System → "Report an issue" opens a GitHub issue with your version filled in; grab a support bundle first from the button next to it
- **Relocate app/config/data at install time** — [On-Disk Paths](#on-disk-paths-v5670); moving an *existing* install's data directory afterward is `docs/runbooks.md` §5

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
- [ ] A fresh install with Kea not yet connected lands you on **`/setup`**
  next (v5.67.0) — a six-step guided first hour: connect Kea, see what it
  found, install the Kea host helper, capture a baseline, make a recovery
  point, investigate your first client. Any step can be skipped and
  picked up later from Getting Started.
- [ ] Upload SSL certificate in Settings → Access & Security → SSL Certificate
- [ ] Configure Telegram alerts if desired

---

## On-Disk Paths (v5.67.0)

By default:

| What | Default path | Env override (systemd sets this for a relocated install) |
|------|---------------|------------------------------------------------------------|
| App tree (`app_dir`) | `/opt/jen` | `JEN_ROOT` (`<app_dir>/current/app`) |
| Config, secrets, TLS, SSH keys (`config_dir`) | `/etc/jen` | `JEN_CONFIG_DIR` |
| User-writable data — uploads, DB backups, plugins (`data_dir`) | `/var/lib/jen` | `JEN_CONTENT_DIR` |

Any or all three can be chosen at **fresh install time** with
`install.sh --app-dir`/`--config-dir`/`--data-dir` — see
`docs/installation.md` Method 1c for the flags and
`docs/ARCHITECTURE.md` §3.1/§6.1 for why the choice is recorded in a
separate, root-owned `/etc/jen-layout.conf` rather than in `jen.config`
itself. Every later `--upgrade`/`--repair`/`--configure` run reads that
file back automatically; you never repeat the flags, and passing one
again with a different value is refused.

**Moving an existing install's data directory** (the common case — a
disk running low, moving onto NFS/NAS) is a short, deliberate procedure
with Jen stopped, not a flag: `docs/runbooks.md` §5.

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

All Jen configuration lives in `/etc/jen/jen.config`. The file is owned by `www-data:www-data` with permissions `600`.

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
| `dhcp4_log_path` | Optional (v5.48.0). Where kea-dhcp4 writes its log on the Kea server, read by the client trace page through the helper's `tail-log` op — must be an absolute `*.log` path under `/var/log`. | `/var/log/kea/kea-dhcp4.log` |

All of these are optional and backward-compatible — an existing
`jen.config` with none of them behaves exactly as it did before v5.10.0.

### Direct control sockets (Kea 2.7.2+ / required for 3.2+)

ISC **deprecated the Control Agent (`kea-ctrl-agent`) in Kea 3.0** and
**removed it entirely in Kea 3.2**. Since Kea 2.7.2 each daemon
(`kea-dhcp4`, `kea-dhcp6`, `kea-dhcp-ddns`) exposes its own HTTP/HTTPS
command API through a `control-sockets` list, and `connection_mode =
direct` makes Jen talk to those sockets instead — dhcp4 under `[kea]`,
dhcp6 under `[kea6]` for the primary and `api6_url` per additional
server, D2 under `[d2]` / `api_d2_url` (there is **no** fallback from
v6 or D2 to the v4 URL in direct mode; a kea-dhcp4 daemon cannot answer
DHCPv6 commands). ISC's example uses port **8004** for dhcp4; Jen's
docs use **8006** for dhcp6 and **53001** for D2.

Two ways to get there. The first is the one to use.

#### Let Jen do it — Settings → Kea → "Set up direct socket" (v5.29.0)

Each daemon on each server has a **Set up direct socket** button: in
the Control Plane card (kea-dhcp4 on server 1), the Kea6 card
(kea-dhcp6), the D2 card (kea-dhcp-ddns), and under each additional
server's row (its kea-dhcp4, and kea-dhcp6 when IPv6 is on). Fill in
the form — it needs almost nothing:

| Field | Default | Notes |
|---|---|---|
| Scheme | `https` when the host's helper is v4+, else `http` | https = mutual TLS with Jen's own CA, below. http = basic-auth in the clear; management network only. |
| Bind address | the server's SSH host, when it's an IP | The IP the daemon listens on. Never `0.0.0.0`. Firewall the port to the Jen host. |
| Port | 8004 / 8006 / 53001 | Never the Control Agent's `:8000`. |
| API username / password | the pair Jen already uses for that server | Editable; blank keeps the defaults. |

Jen then, on that one server: adds the entry to `control-sockets` in
the daemon's config (the existing `unix` entry stays), validates the
file with `kea-dhcpX -t`, writes it, restarts the daemon, **probes the
new socket** — a `version-get`, then a `config-get` that must answer
*as that daemon* (a Control Agent left listening on the same host
answers `version-get` identically, which is exactly the trap this
avoids) — and only then writes its own settings: the daemon's URL and
credentials, `connection_mode = direct` for kea-dhcp4, and for https
the CA and client certificate paths. If anything before the probe
fails, the change set is reverted; if the probe fails, the socket stays
in the Kea config (it's valid and harmless) and **nothing in Jen
changes** — the message says exactly what didn't answer, and running
the form again just re-probes. It needs an SSH host for the server and
the Kea host helper (any version for http, **v4** for https), and Kea
2.7.2 or newer.

**https, and the Jen-managed Kea CA.** Choosing https makes Jen its
own certificate authority for the Kea link: a private CA at
`/etc/jen/ssl/kea-ca.crt` / `kea-ca.key` (EC P-256, 10 years, created
the first time it's needed), a server certificate per daemon (5 years;
SAN = the bind address and the SSH host) pushed to
`/etc/kea/tls/<service>/{ca.crt,server.crt,server.key}` on the Kea
host by the helper's `install-tls` op (owned `root:<daemon group>`,
key mode `0640`), and one client certificate for Jen at
`/etc/jen/ssl/jen-kea-client.pem` / `.key`. The socket is written with
`cert-required: true` — the daemon accepts *only* Jen's certificate,
which is the actual security here, not just an encrypted password. One
CA serves every server; Health Center watches every certificate's
expiry (warn at 90 days, fail at 14); **Rotate Kea CA** on the Control
Plane card re-issues everything and re-pushes every server, all or
nothing (it asks for your password again, and a push that fails part-
way rolls the already-pushed servers back to the current CA). If you
already run your own CA, Jen won't overwrite it — the `api_ca` field
above stays yours and https is a by-hand setup (next section).

**Several servers / HA.** Run the form per server. The connection
mode is global, so after the first kea-dhcp4 switches Jen to direct
mode the Dashboard cards of servers still on the Control Agent show
the "answered as the Control Agent" error until you set theirs up
too — Jen names them when it switches. Never point a socket at an HA
peer port (see the notes below). **Switch back** (per daemon, shown in
direct mode) removes the http/https entry, restarts the daemon,
restores the remembered Control Agent URL for kea-dhcp4 and returns
Jen to `ca` mode only once no server is still answering on its own
socket.

**Why not Let's Encrypt?** The Kea link needs *client* certificates
(ACME issues server certificates only), and homelab management
addresses are RFC 1918 IPs with no public name. A CA Jen owns issues
both halves and can rotate them wholesale. See
`docs/ARCHITECTURE.md` §3.12 for the tradeoff of the CA key living on
the Jen host.

#### By hand

Always **keep the existing `unix` entry** in `control-sockets` alongside
the new one (`kea-shell` and some hooks use it), and **firewall the
HTTP(S) port to the Jen host** regardless of which option below you pick.

**Don't just point `direct` mode at the Control Agent's port (`:8000`).**
Switching `connection_mode` to `direct` without actually adding an
`http`/`https` entry to each daemon's own `control-sockets` list means
`api_url` is still reaching the Control Agent (if it's still running) —
and in direct mode Jen sends no `service` field, so the Control Agent
answers for *itself*, not for `kea-dhcp4`. `version-get` looks
identical either way (Kea reports the same version string), but
`config-get` comes back as the Control Agent's own config — no
`Dhcp4` key at all — so every page that reads live subnet data
(Dashboard, Subnets, drift detection, Health) goes quietly blank with
no error. **v5.28.1** made this loud instead of silent: a `config-get`
that answers as the wrong daemon in direct mode now returns a real
error naming which daemon actually answered, shown as a banner on the
Dashboard and Subnets pages; Settings → Kea → Probe identifies the
same mismatch before you even switch modes. If you hit this, add a
real `http`/`https` `control-sockets` entry as shown below — or let
"Set up direct socket" do it — not just a different port number.

**Recommended — HTTPS on a management address, mutual TLS.** Bind the
control API to a management IP (not `0.0.0.0`), use HTTPS, and require
a client certificate. In `kea-dhcp4.conf`:

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

**Without a client certificate.** If you can't deploy a client cert to
the Jen host, set `"cert-required": false` on the Kea socket —
otherwise Kea demands a client certificate Jen can't present and the
TLS handshake fails. Jen side: `api_ca` only (no `api_client_cert` /
`api_client_key`). The connection is still encrypted and still
firewalled to the Jen host; it just isn't mutual.

**Plain HTTP.**

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

**Making the certificates yourself.** A minimal private CA — one CA, a
server cert per Kea host (SAN = the management IP), one client cert for
Jen:

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
  candidate direct socket. When it finds the Control Agent answering
  where a daemon socket should be, its recommendation names the file
  and key involved and points at "Set up direct socket".
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
- **Writing the authored config is all-or-nothing (v5.68.0-beta.15).** It
  used to write server by server, so one server could end up with the new
  file and another with none (or with its old one), and "overwrite" replaced
  whatever happened to be on the host at that moment. It now goes through the
  same change set as every other multi-server edit: every server's config is
  built and checked (`kea-dhcpX -t`) before anything is written; each write is
  guarded with the file **Preview & Validate showed you** (a server with no file
  is guarded as "must not exist", so a file that appeared meanwhile is never
  overwritten); if a later server fails, the earlier ones are put back - a file
  Jen created is removed again, one it replaced is restored from what it read -
  and Jen's own `[subnets]` is written only when every server succeeded. A server
  whose file changed after the preview refuses with *changed since you
  previewed it*, so run Preview again. **Overwrite** means "replace the file I
  previewed"; an existing file is not replaced without the tick, and not at all
  unless it was previewed. A rollback that cannot finish (a server that is
  unreachable at that moment) is a banner on the Servers page, like any other
  change set. Removing a file Jen created needs the host's helper on build 13 or
  later (press **Update helper**); on an older one the banner tells you to delete
  the file by hand.

### [kea_db] section

| Key | Description | Example |
|---|---|---|
| `host` | MySQL server hostname or IP | `YOUR-KEA-SERVER` |
| `user` | MySQL username for Kea database | `kea` |
| `password` | MySQL password | `your-password` |
| `database` | Kea database name | `kea` |
| `port` | MySQL port (v5.67.0-beta.8); blank or absent means 3306 | `3306` |
| `ssl_ca` | Path to a CA bundle on the Jen host. When set, Jen connects to Kea's database over TLS, verified against it; empty means a plain connection. The setup wizard's Connect step has a field for it (v5.67.0-beta.15) | `/etc/jen/ssl/kea-db-ca.pem` |

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

### [updates] section (v5.32.0)

| Key | Description | Default |
|---|---|---|
| `channel` | Release channel this install follows: `stable` or `beta` — see "Release channels" under Upgrading Jen. Set from Settings → System → Updates; anything else is read as `stable`. | `stable` |

### [alerts] section (v5.68.0-beta.5)

| Key | Description | Default |
|---|---|---|
| `client_problem_threshold` | Optional. How many times within an hour one client must have the same kind of DHCP trouble (a NAK, a decline, a failed DNS update, …) before the **Client had DHCP trouble** alert fires — once per client and kind per 24 hours, whatever the count afterwards. A whole number of 1 or more; anything else is logged and read as the default. | `3` |

Everything else about alerts is configured in Settings → Alerts & Integrations; this is the one alert setting that lives in `jen.config`, because the sweep that fires it runs in the background with no page to configure it from.

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

**What a subnet-scoped account sees of IPv6.** The subnet list of an account is a list of IPv4 subnets, so an IPv6 subnet is judged through the IPv4 subnet it is paired with (the third field of its `[subnets6]` line). A paired IPv6 subnet is visible to the accounts that can see its IPv4 subnet; an IPv6 subnet with no pairing is visible only to accounts with no subnet restriction. This holds for the IPv6 views of Leases, Devices and Reservations, the add and delete reservation forms, the Subnets page and its edit pages, the Dashboard's IPv6 numbers, global search and the Investigation page. Asking for an IPv6 subnet the account cannot see, by hand-typing its id, returns "not found", the same as an id that does not exist. If a scoped account is missing IPv6 data you expect it to have, check that the subnet has a pairing.

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

Jen supports two kinds of second factor, and a user may enroll either or both: TOTP authenticator apps (Google Authenticator, Authy, 1Password, etc.) and, from v5.31.0, passkeys (WebAuthn / FIDO2 — Windows Hello, Touch ID / iCloud Keychain, Android, 1Password, Bitwarden, Keeper, YubiKey and similar hardware keys). Both sit *behind* the password: passkeys are a second factor here, not a passwordless login.

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

### Passkeys (v5.31.0)

On the same **Profile → Security** page, **Add a Passkey** starts the browser's own passkey prompt; give it a name (which laptop, which key) so the list stays readable. A passkey can be a user's first factor (the forced-enrollment flow accepts one just like an authenticator app, and issues backup codes the same way) or an addition beside TOTP. At login the verification page opens on a **Passkey** tab when one is enrolled, with Authenticator and Backup Code still available; "remember this device" works the same for all three. Step-up confirmations (`/auth/reauth`) accept a passkey in place of a code.

What an administrator needs to know:

- **Passkeys are bound to the address users type.** The WebAuthn relying-party id is the hostname of the page (`jen.lan`, `10.0.0.5`, …), without the port. Renaming the host or moving Jen to a new address invalidates every enrolled passkey — users enroll again. Behind a reverse proxy, set `[server] trusted_proxies` so Jen sees the external scheme, and forward the original `Host` header.
- **Browsers only create passkeys on a secure page** — https, or `http://localhost`. Over plain http on a LAN address the Add-a-Passkey card explains this and offers nothing; set up HTTPS (or terminate TLS at a trusted proxy) first.
- **What Jen stores** is the credential's public key, its id, a signature counter, and the name — nothing secret, so nothing to encrypt (unlike TOTP secrets, ARCHITECTURE §3.6). An assertion whose counter did not advance is rejected as a cloned authenticator.
- **Removing** the last factor is refused while MFA is required for that account, exactly as for TOTP. A superadmin's **Reset MFA** on the Users page clears passkeys along with everything else.
- The lockout below applies to passkey attempts too.

### Trusted Devices

After successful MFA login, you can choose to trust the device for 30 days. Trusted devices skip MFA on subsequent logins. Manage trusted devices under **Profile → Security → Trusted Devices**.

### MFA Lockout

To prevent brute-forcing a TOTP code or backup code, the MFA verification step locks out after 10 failed attempts for 15 minutes. This is fixed and separate from the login rate limiting below — it isn't affected by that setting and is never permanent, so a locked-out user just needs to wait 15 minutes rather than contact an admin.

---

## REST API

Jen provides a read-only REST API at `/api/v1/` for integration with Home Assistant, Zabbix, and custom scripts.

### Authentication

All endpoints (except `/api/v1/health` and `/api/v1/openapi.json`) require an API key in the request header:

```
Authorization: Bearer jen_your_key_here
```

### Managing API Keys

Go to **Settings → Access & Security → API Keys** to generate, view, and revoke keys. A key is shown only once at creation — copy it immediately.

### Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/health` | Jen's liveness — no auth, no Kea call, and the body is `jen_version` alone (v5.65.12; it carried Kea's cached state and the subnet count from 5.65.6, narrowed to a per-server list in 5.65.8, moved to `/api/v1/health/kea` in 5.65.10, and dropped entirely here since every real consumer reads `jen_version` only) |
| GET | `/api/v1/openapi.json` | This same API as an OpenAPI 3.0 document — no auth, by design: generated from one static description with no database access, so the only values in it specific to this install are the version (already public on `/api/v1/health`) and this server's own URL, reflected back (v5.66.0-beta.4; see `docs/ARCHITECTURE.md` §3.15 for the full unauthenticated-surface list) |
| GET | `/api/v1/health/kea` | A live probe of the server Jen is serving from (in an HA pair, the active one) — needs an API key; one Kea call, so it can take as long as the Kea API timeout when it is unreachable (v5.65.6); returns `kea_up`, `kea_version`, `kea_checked_at`, `server`, `servers` (every server's last known state, cached, since 5.65.10) and `subnets` (since 5.65.12) |
| GET | `/api/v1/subnets` | Subnet utilization with pool sizes; since v5.36.0 also `peak_30d`, `trend_per_day`, `days_to_90pct` and `forecast` (rising / flat / falling / insufficient) |
| GET | `/api/v1/servers` | Kea servers, HA state, and `packet_health` — `{status, window_minutes, rates}`, null until two snapshots exist (v5.41.0) |
| GET | `/api/v1/events` | Raw event stream rows — params: mac, ip, kind, since (ISO 8601), limit (v5.42.0) |
| GET | `/api/v1/timeline/{mac}` | One client's merged timeline — events, matching audit/alert entries, current lease/reservation/device (v5.42.0) |
| GET | `/api/v1/health/checks` | The Health Center run as JSON, scoped to the key's subnet access (v5.43.0) |
| GET | `/api/v1/health/readiness` | Just the Kea 3.2 readiness group + its `{ready, actions, checked}` summary (v5.43.0) |
| GET | `/api/v1/leases` | Active leases — params: subnet, mac, hostname, limit |
| GET | `/api/v1/leases/{mac}` | Single device lease with active boolean |
| GET | `/api/v1/devices` | Device inventory — params: mac, name, subnet, limit |
| GET | `/api/v1/devices/{mac}` | Single device with online status and current lease |
| GET | `/api/v1/reservations` | Reservations — params: subnet, limit |
| POST | `/api/v1/reservations` | Create a reservation — JSON `{subnet_id, ip, mac, hostname?, dns?, notes?}` → 201 (v5.34.0, write key) |
| DELETE | `/api/v1/reservations/{host_id}` | Delete a reservation by Kea host id (v5.34.0, write key) |
| PATCH | `/api/v1/devices/{mac}` | Set a device's `name`, `owner`, `notes` (any subset; `null` clears) (v5.34.0, write key) |
| POST | `/api/v1/subnets/{id}/notes` | Set the subnet's note — JSON `{text}` (empty clears) (v5.34.0, write key) |

Full documentation with examples is available at **Settings → Access & Security → API Docs** in the Jen interface, and as an OpenAPI 3.0 document at `/api/v1/openapi.json`.

### Writing through the API (v5.34.0)

Write access is **per key and off by default**: tick *Allow writes* when creating the key. A read-only key gets `403` on every write endpoint; every key created before v5.34.0 is read-only. Writes honour the key's subnet scope exactly as reads do, are audited with the key's name as the actor (`[api-key:Home Assistant] …`), and are limited to 60 per minute per key. Reservations go through Kea's `host_cmds` hook like the Reservations page — never a config-file change — so a Kea refusal (duplicate address, unknown subnet) comes back as `502` with Kea's own message. Nothing that edits a Kea configuration file (subnets, pools, options, classes) is exposed through the API; those need the preview-and-apply flow in the UI.

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

## Theming (v5.55.0)

Every color in Jen's UI is a CSS token (`jen/services/theme.py`), not a hard-coded hex value — a theme is just a set of values for those tokens.

### Choosing a theme

Any logged-in user — any role — can pick their own look from the palette icon in the nav bar (desktop) or the **Theme** button in the phone's More sheet. The choice is per-browser (stored in `localStorage`), so it doesn't affect anyone else and doesn't need a page reload to take effect.

Seven presets ship with Jen:

- **Dark** — the install default since day one. Byte-identical to what every prior version rendered; upgrading never changes anyone's look.
- **Light**
- **High contrast** — every text/background pairing is at least 7:1 (WCAG AAA)
- **Phosphor** — amber-on-green terminal look, monospace UI on desktop only (a phone keeps the regular font — a mono table would overflow it)
- **Slate** — a cooler dark theme, blue-grey surfaces with a blue accent
- **Ember** — a warm dark theme, near-black with an orange accent
- **Retro** — an early-90s desktop: a teal background behind grey panels, a navy accent and beveled borders

A user who hasn't picked one gets the install's default theme, below.

### Install default

Go to **Settings → Appearance → Theme** (superadmin only) to set which theme a viewer gets before they've picked one for themselves. Changing it doesn't affect anyone who has already made their own choice.

### Custom palette

A superadmin can also define the install's own palette: 11 colors (background, three surface shades, border, text, muted text, and the primary/success/warning/danger accents), a corner radius, and whether to use the monospace UI on desktop. The form shows a live preview and flags any pairing under WCAG AA (4.5:1 for body text, 3:1 for muted text and the primary accent) as you edit — these are warnings, not a block, in case the install has its own reason. "Start from…" copies a built-in preset's values into the form as a starting point.

Every color is validated as a plain hex value (`#1a1a2a` or `#fff`) on save — nothing else is accepted, so a saved palette can never inject anything beyond a color into the page. Once saved, "Custom" appears as a choice both in the install-default dropdown above and in every user's own picker.

Removing the custom palette falls the install default back to Dark if it had been set to Custom; anyone who had personally picked Custom falls back to Dark too, the next time they load a page.

---

## Bundled plugins

Seven plugins ship inside Jen (every directory under `plugins/`; `shipped_plugin_ids()` in
`jen/services/plugins.py` is the list). None is on until you enable it under **Settings → Plugins**, and a change
there needs a Jen restart. Each keeps its own tables in Jen's database (created by its own migrations when it
first loads), sends nothing anywhere until you configure a target, and follows the same subnet rules as the core
pages: a restricted user sees only what belongs to their subnets. All of them are IPv4 only, and none needs
anything beyond what is listed below. Adding, removing and acting on things is an admin action in every one;
viewers are read-only. What a plugin needs from the Jen host is checked by the plugin, not assumed: if the
program is missing the page says so.

**Network Discovery** — finds devices on a subnet that Kea does not know about. *Needs* `nmap` on the Jen host
(Settings → Plugins offers an Install button on a systemd host). *Stores* scan results (the last three per
subnet), the hosts you marked known, and its schedule in its own `nd_*` tables. *Sends* probes to the addresses of
the subnet you scan and, when an unknown host appears, a "Rogue Device" alert to the channels you opted in. The
known list has no subnet, so marking or forgetting a host is for an administrator who can see every subnet (5.65.9).

**IPAM Lite** — the whole address space of a subnet, Kea-managed or not: what is leased, reserved, static or
planned, with labels and owners. *Needs* nothing from the host. *Stores* the static and planned entries, the
unmanaged subnets you add, and an assignment history in its own `ipam_*` tables. *Sends* nothing outside Jen, except
a conflict alert when a static entry's address is taken by a DHCP client. The subnet page folds every run of four or
more empty addresses into one row, on subnets of any size (`?all=1` shows them all).

**Host Watchdog** — probes chosen hosts and alerts when one stops answering, and again when it returns. *Needs*
`ping` on the Jen host for ICMP targets (Ubuntu's `/usr/bin/ping` carries the capability, package `iputils-ping`);
a TCP target needs nothing. *Stores* the targets, their state and a short check history in its own `wd_*` tables.
*Sends* one ICMP echo or TCP connection per due target, at most every five minutes, and the up/down alerts. A target
belongs to the subnet its address is in (an address in no subnet belongs to accounts that can see every subnet), and
the history, pause and delete actions check that stored subnet, never a value in the URL. A new target's first
successful check is recorded without an alert.

**Local DNS Sync** — pushes DHCP names into Pi-hole v6 or AdGuard Home so `nas.lan` resolves without Kea DDNS.
*Needs* a Pi-hole v6 or AdGuard Home install whose API the Jen host can reach. *Stores* each target, an encrypted
credential (never shown again) and a ledger of the records Jen created, in its own `ds_*` tables. *Sends* record
changes to the DNS server, over TLS that is verified unless you switch that off per target. A target starts paused:
Preview shows exactly what would change, and it must be run before the target can be enabled. Jen only ever touches
records it created itself; an address change removes the old record before adding the new one. A target is judged as
a whole: Preview, Enable and Pause need access to every subnet it covers, and adding or removing one needs an account
that can see every subnet, while the record list and the Unbound export show only the records in the viewer's own
subnets.

**Switch Port Locator** — which switch port a MAC is on. *Needs* `snmpbulkwalk` (package `snmp`) on the Jen host
(an Install button on a systemd host) and managed switches that answer SNMPv2c. *Stores* the switches (with their
SNMP community string, which is kept as entered, so use a read-only community), the port list and the MAC sightings
in its own `sp_*` tables. *Sends* SNMP walks to the switches you add, every ten minutes, and a "moved" alert
(off until a channel opts in) when a known MAC changes port. The community string is a command-line argument of the
walk, so it is visible in the process list on the Jen host for those few seconds; net-snmp has no alternative for
SNMPv2c. A port with more than eight MACs is treated as an uplink and shown as "Auto (uplink, 37 MACs)". A switch
belongs to the subnet its management address is in: a subnet-scoped account sees and changes only switches
addressed inside its own subnets, and a switch addressed by hostname is for accounts that can see every subnet.

**Wake & Actions** — Wake-on-LAN from a lease, reservation or device row, and a favourites list. *Needs* nothing
from the host beyond being able to send UDP broadcast on the target's subnet. *Stores* the favourites (and an
optional SecureOn password) in its own `wol_hosts` table. *Sends* one standard magic packet per wake, to the subnet's
directed broadcast address and the limited broadcast address, at most one per MAC every five seconds; every wake
is audited. The subnet of a wake or a new favourite is the one the MAC is in (its active lease, then its
reservation), never a value in the request, and a MAC Jen has never seen is for accounts that can see every subnet.

**Presence** — publishes tracked devices' online or offline state. *Needs* the Jen host's IPv4 neighbour table
(`ip -4 neigh`, read every five minutes alongside lease events). *Stores* the devices you track, their current
state, and your sinks (an MQTT password or HTTP bearer token is stored encrypted and never shown again) in its own
`pr_*` tables. *Sends* every state change to each sink you configured: a Home Assistant webhook, MQTT, or any HTTP
endpoint; nothing is published for a device you did not choose to track. Because every state change goes to every
enabled sink, adding, pausing, testing and removing a sink is superadmin-only; other admins see the list
read-only. A device that is not on a segment the Jen host has an interface on cannot appear in its neighbour table,
so its state follows lease events only, and the page says "lease-based" beside it.

*Presence* is also the push alternative to the polling example in the Home Assistant quick start above, which asks
the REST API whether a device is online.

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
| Client had DHCP trouble (v5.68.0-beta.5) | One client has the same kind of DHCP trouble (a NAK, a decline, a failed DNS update) at least three times within an hour — once per client and kind per day |

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

**User class (option 77) has two forms (v5.68.0-beta.10).** A client sends option 77 either as the bare string (`dhclient`'s `send user-class`, most Linux clients) or length-prefixed as RFC 3004 describes (Windows: one length byte, then the string), and Kea compares the bytes, so a rule written for one form does not match clients that send the second. The guided builder therefore offers two fields: **User class (option 77) - plain text** writes `option[77].hex == 'text'` (or `substring(option[77].hex,0,N) == 'text'` for *starts with*, exactly what it always wrote), and **User class (option 77) - length-prefixed** writes `option[77].hex == 0x<length byte><text>` (for *starts with*, `substring(option[77].hex,1,N) == 'text'`, which skips the length byte and so looks at the first user class only). Checked against real Kea 3.0.3, 3.2.0 and 3.3.1, which agreed on every case: each rule matches only the clients that send its form. A client that sends both forms, or several user classes in one option, needs an Advanced expression. Explain on the Investigation page shows which form a client actually sent, from Kea's packet dump.

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

**Explaining a client (v5.35.0).** Network → Explain reconstructs the decision for one client — subnet, reservation, classes, guards, pools, options — from the config Jen holds. It evaluates class `test` expressions itself, but only the grammar the guided rule builder writes (`<accessor> == 'string'`, `<accessor> == 0xhex`, `substring(<accessor>,0,n) == 'string'`, `member('class')`, `and` / `or` / `not`, over option 60/77/12/61, `pkt4.mac`, relay circuit/remote id). A class written as a raw expression outside that grammar is reported as *not evaluable* and shown verbatim; an input the operator didn't supply makes a class *undecided* and the page names the input. The answer assumes those classes did not match. Built-in `KNOWN` / `UNKNOWN` follow the reservation step; `only-in-additional-list` classes are evaluated only where something in the selected subnet, its pools, its shared network or the matched reservation lists them. Subnet selection is the operator's (or the lease's) subnet — Kea's real choice depends on the receiving interface, which Jen cannot see; a supplied giaddr is checked against the subnet's relay addresses and range.

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

Step-by-step procedures for rotating the signing key, recovering from a
release that shipped a broken helper build, and installing the helper
by hand (including with no route to the internet) are all in
**[docs/runbooks.md](runbooks.md)**.

That means **one** sudoers line, and it is not root-equivalent the way
the old one was — the helper's own op allowlist and path walls are the
control:

One line — a multi-line heredoc pastes badly into some terminals and web
consoles:

```bash
printf '%s\n' '# Jen (DHCP console) — SSH user "youruser". The helper op allowlist is the control; see docs/ARCHITECTURE.md §3.3' 'youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper' | sudo tee /etc/sudoers.d/jen-kea-helper >/dev/null && sudo chmod 440 /etc/sudoers.d/jen-kea-helper && sudo visudo -c -f /etc/sudoers.d/jen-kea-helper
```

**Installing the helper.** From Jen: **Settings → Kea → SSH**, then
**Install helper** next to the server (this uses the legacy path once —
see below — so the old grant must still be present for the button to
work). By hand, on the Kea host — this is the exact command Jen itself
shows in every flash that offers a by-hand fallback (v5.66.0-beta.2,
Q104): it downloads BOTH the helper and its release signature, verifies
the signature locally with `ssh-keygen -Y verify` against the same key
embedded in Jen itself, runs the downloaded candidate's own `version` op
and checks it reports exactly the version/build this release ships
(v5.66.0-beta.7, Q109 — the same self-check the automatic signed-update
path already runs before installing anything), and only installs it once
both pass — nothing is ever installed unverified or unchecked (`vX.Y.Z`
is your installed Jen version, shown on the About page; `7`/`9` are this
release's `HELPER_VERSION`/`HELPER_BUILD`):

```bash
d="$(mktemp -d)" && cd "$d" && curl -fsSLO https://github.com/ltkojak/jen-kea/releases/download/vX.Y.Z/jen-kea-helper && curl -fsSLO https://github.com/ltkojak/jen-kea/releases/download/vX.Y.Z/jen-kea-helper.sig && printf '%s\n' 'release@jen ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXk5NbQwUy85pHCzLfOwPisL0JGLCOrHuRjRZSf25vD' > allowed_signers && ssh-keygen -Y verify -f allowed_signers -I release@jen -n jen-kea-helper -s jen-kea-helper.sig < jen-kea-helper && /usr/bin/python3 -I jen-kea-helper version </dev/null | /usr/bin/python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get("ok") is True and d.get("helper_version")==7 and d.get("helper_build")==13 else 1)' && sudo install -o root -g root -m 0755 jen-kea-helper /usr/local/sbin/jen-kea-helper
```

then add the sudoers line above. **Settings → Kea → SSH** shows the
installed version for each host once it is reachable — green when it's
current, amber ("upgrade available") when it isn't. A bad signature (a
corrupted download, a stripped mirror, tampering in transit) makes
`ssh-keygen` exit non-zero, a candidate that doesn't self-report what it
just verified as makes the self-check exit non-zero, and the `&&` chain
means nothing gets installed either way — never "install anyway".

**Offline / air-gapped Kea host.** If the Kea host has no route to
GitHub, fetch `jen-kea-helper` and `jen-kea-helper.sig` on any machine
that does — they are the same two release assets the one-liner above
downloads — copy both onto the Kea host by whatever transport you
trust (`scp`, a USB drive), then run the same verify-then-install steps
locally, in the directory holding both files:

```bash
printf '%s\n' 'release@jen ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXk5NbQwUy85pHCzLfOwPisL0JGLCOrHuRjRZSf25vD' > allowed_signers && ssh-keygen -Y verify -f allowed_signers -I release@jen -n jen-kea-helper -s jen-kea-helper.sig < jen-kea-helper && /usr/bin/python3 -I jen-kea-helper version </dev/null | /usr/bin/python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get("ok") is True and d.get("helper_version")==7 and d.get("helper_build")==13 else 1)' && sudo install -o root -g root -m 0755 jen-kea-helper /usr/local/sbin/jen-kea-helper
```

Never skip the verify step just because you trust the transport — it's
what catches a corrupted or partial copy before it's installed as root.
A tarball install already has both files sitting side by side in the
extracted `jen/` directory, so this is the same two files, not a
separate download.

**Upgrading the helper.** Press **Update helper** in Settings → Kea → SSH
(the same button, relabelled once a version is already recorded). What
happens next depends on the host's current version — see "v5.66.0 ships
helper v6 — signed updates, no grant" below for a host already at v6:
below that, this still runs over the legacy `sudo python3` path — the
old grant needs to be present for one run, same as a fresh install; if
it's already been removed, the flash gives you the same verified
by-hand one-liner above instead. Either way Jen never trusts the
install script's own printed version: it re-checks the freshly-updated
host and reports what it actually says, so a copy that silently didn't
take (a shadowing binary earlier on `$PATH`, a stale cache) reads as
"the copy did not take" instead of a false success. v5.16.0 shipped
**helper v2** (optimistic concurrency — see below); a host still on v1
shows the amber hint and keeps working behind the best-effort guard
until it's upgraded. **Health Center** (v5.19.1) also warns per host
once a v1 helper is more than a passing state — see "Kea host helper
installed" there.

**v5.66.0 ships helper v6 — signed updates, no grant.** From v6 on, an
"Update helper" click needs no legacy grant at all: Jen sends the new
helper file together with its release signature, and the helper's own
`update` op — never Jen — decides whether to install it, by checking
two things itself: a valid `ssh-keygen -Y verify` signature from the
Jen *project's* release key (the same permanent trust root the
self-updater already uses — never Jen's own SSH identity, and never
transferable from the release-tarball's own signature, since the two
use distinct namespaces) under the `jen-kea-helper` namespace, and a
`HELPER_VERSION` strictly higher than the one already running (equal
counts as not-newer; a downgrade is never installed, even signed). A
fully-compromised Jen can therefore install a genuine, newer Jen
release's helper and nothing else. A host still on v5 or older takes
one more hop through the legacy path to reach v6 — needing the old
grant present for that one last run — and never needs it again once
it's there. A host that shows **"signed updates"** next to its version
in the table above has already made that hop.

If a signed update is refused, the flash says exactly why: *the host
refused the signature* points at a problem with the release itself, not
this host — Jen already retried once with a freshly fetched signature
before reporting it (v5.66.0-beta.2, Q104), so this is never worth
working around by hand; the same signature would fail there too.
Reinstall Jen from the release tarball and retry, or wait for a newer
release. *No signature available* (reworded in the same Q — it used to
say "offline?") means neither Jen's own local copy nor a fresh fetch
produced a signature that verifies against this exact helper — that
points at the Jen install itself, so the fix is the same: reinstall
Jen from the release tarball. *No ssh-keygen* means the Kea host is
missing `openssh-client` (or its distro equivalent) — install it there
and retry; `ssh-keygen -Y sign`/`-Y verify` need OpenSSH 8.0+, already
true of every distro this guide targets (Ubuntu 22.04 ships 8.9, 24.04
ships 9.6), so this is never a new dependency, just a missing package.
None of these three offer the by-hand line above as a way around them
— it would fail the exact same verification, on purpose.

**Key rotation.** `/etc/jen-kea-helper/allowed_signers` on the Kea host
itself is the one place a helper update's trust root can be extended
without a new Jen release: a root-owned file (mode without group or
world write, at most 8 KiB), one line per key in the same "allowed
signers" format as the embedded key —
`release@jen <key-type> <base64-key>`. It's additive, never a
replacement: the helper always also trusts its own embedded key. This
exists for a genuine key rotation (list the new key here across every
Kea host for one release before switching which key `release.yml`
signs with — the same rotation shape as the self-updater's own trust
root) and as a test hook for the automated suite; an operator does not
normally need this file at all.

**v5.66.0-beta.2 ships helper v7 — nothing changes for you.** A
third-party review of the v6 design asked for the update machinery to
be hardened, not redesigned: every binary the helper runs
(`systemctl`, `apt-get`, `kea-dhcpX`, `ssh-keygen`) is now resolved
through a root-owned allowlist rather than trusting the caller's
`$PATH`, and a signed candidate is run once in a throwaway check
before it replaces the live helper and once more right after — a
failure at either point rolls back automatically, restoring the
previous helper rather than leaving a broken one in place. A
helper-only fix like this one doesn't change the protocol, so it ships
under a new `HELPER_BUILD` number rather than bumping `HELPER_VERSION`
— Settings → Kea → SSH shows it as **"v7 (build 7)"** once a host has
it, and still offers **Update helper** the same way it did for v6. (v5.68.0-beta.7: the button
appears for a build-only update too — a host on v7 whose build is below the one this Jen ships reads
"v7 (build 7, build 10 available)" and has the button beside it; until then the button compared
versions alone, so builds 8, 9 and 10 showed the text and no button.)
None of this needs anything from you.

**This release ships helper build 8 — the update op never installs with
no way back.** Another review found the one case the v7 rollback above
didn't cover: on the rare host with no helper file at all yet at the
installed path, a postflight failure on that very first signed update
had nothing to restore. `update` now refuses up front, before writing
anything, when there's nothing installed to update — the flash reads
*"no helper to update"* and the fix is the same by-hand install command
given for a v5-or-older host's one last hop. If a signed update fails
its postflight check AND the automatic rollback also fails (very rare —
disk full, or permissions changed on the Kea host mid-update), the flash
reads *"failed to update AND failed to roll back"* and names both the
installed path and its `.prev` backup — that one case genuinely needs
you on the host by hand; see `docs/runbooks.md`. Settings → Kea → SSH
shows this build as **"v7 (build 8)"**.

**Helper build 10 (v5.68.0-beta.6) — a Kea installed from ISC's packages can have its config validated again. Press Update helper.**
ISC's own deb packages install the daemon binary, `/usr/sbin/kea-dhcp4`, owned by the Kea service account (`_kea:_kea`, mode `0750`) — not
`root:root`. From helper build 7 (v5.66.0-beta.2) through build 9 the helper required `root:root` of every binary it runs, **including that
one**, so on such a host every operation that checks a config before writing it (`test-config` and `apply-config`: every subnet, option, class,
DDNS and logging change) answered "kea-dhcp4 is not installed on this server" for a Kea that was installed, and nothing reached Kea through the
helper. Releases 5.66.0 and 5.67.0 carry that. A host on the legacy `sudo python3` path (no helper) was never affected. Build 10 runs
`kea-dhcpX -t` **as the account the daemon runs as** — the unit's `User=`, else the binary's own owner — which is what the daemon itself does on
every start. Trust follows who executes the file: a binary the helper runs as root must still be `root:root` with no group or other write bit (nothing
else the helper runs changed); the Kea daemon binary is trusted only when it is a regular file owned by exactly that account, a system account (a
uid below 1000, never root), with no group or other write bit. Anything else is still refused, now with the reason on the Servers page ("is owned by
alice, not a system account and not the daemon's user"). The helper (root) never executes a binary an unprivileged account can replace. The file the
test reads is written mode `0644` explicitly and the helper's clean environment gains `HOME=/`. **Press Update helper on every Kea host after
upgrading Jen** — Settings → Kea → SSH shows the host as "v7 (build 9, build 10 available)", and Health Center warns "helper build < 10 on an
ISC-packaged Kea cannot validate configs" for a host whose Kea version string says so. No sudoers change: it is still the one `/usr/local/sbin/jen-kea-helper` line.

**Helper build 11 (v5.68.0-beta.13) — the config check runs with the daemon's real credentials and leaves nothing readable behind. Press Update
helper again.** Two things build 10 got only partly right about the copy of your Kea config that the helper writes beside the real file to run
`kea-dhcpX -t` on. (1) That copy is the whole config, **database credentials included**, and it was written mode `0644`; whether another local account on
the Kea host could read it depended on `/etc/kea`'s own mode on the package in use. It is now created `0600` and owned by the account that runs the check
(the daemon's own account, or root when the binary is `root:root`), whatever the umask, and is still removed on every exit path. (2) The check ran as the
daemon account's primary group with no supplementary groups, so a unit with `Group=` or `SupplementaryGroups=` (TLS material readable through a group)
started fine under systemd and failed Jen's check. The helper now reads `User`, `Group` and `SupplementaryGroups` from the unit in one `systemctl show` and
runs the check with exactly that identity; a group the unit names that the host does not have is refused with the reason on the Servers page
(*"kea-dhcp4 is present but the helper will not run it: its unit names the group 'x', which does not exist on this host"*) instead of being guessed. The
kea-compat job records `/etc/kea`'s owner and mode on each ISC image so the window build 11 closed is on record. No sudoers change.

**Helper build 12 (v5.68.0-beta.14) — the config check runs as the account the unit names, whoever owns the binary. Press Update helper again.** Build 11
looked at the unit's account only after it had decided the Kea binary was not `root:root`, so a binary owned by root (a hand install, or a package that does
not give it to the service account) under a unit that says `User=_kea` was checked **as root**: the check could pass as root on a file or a key the real
daemon, running as `_kea`, cannot read, and Jen would push a config that then failed to start. The order is now fixed: (1) the unit's identity is
resolved first (`User=` by name **or by numeric uid**, `Group=`, `SupplementaryGroups=`); (2) the binary is verified second — `root:root` with no
group/other write bit, or owned by exactly the unit's account — and a root-owned binary the unit's account cannot execute is refused; (3) the check runs as
the unit's account whenever the unit names one, and as root only when it names none (or names root). A `User=` or `Group=` this host has no account for is
refused with the reason (*"its unit runs as User=x, which is not an account on this host"*) and the check is never run as root instead. The supplementary
groups are what systemd itself gives the daemon: the account's own `/etc/group` memberships plus the unit's `SupplementaryGroups=`, so TLS material readable
because the account is in `ssl-cert` is readable to the check as it is to the daemon. No sudoers change. The by-hand install line shown in the flash and in
this guide embeds the new build.

**Helper build 13 (v5.68.0-beta.15) — every file the helper writes is private from its first byte, the lock is taken for every op, and Jen can undo
an authored config. Press Update helper again.** (1) `apply-config` wrote the candidate config — **database passwords included** — to a fixed-name
temp file created with the default permissions (0644) and only then copied the destination's mode onto it; `install-tls` wrote `server.key` the same
way and `chmod`ed it 0640 after the private key was already on disk; and the `.jen_backup` copy was made the same way. Every one of those files is now
created by one routine: a unique name in the destination's own directory, created exclusively with mode 0600, written and synced, given its final
owner, group and mode on the open file, and only then renamed into place. A replacement of a 0600 config is never readable by another account at any
instant; a new config is still `0644` (so Kea's account can read it) and the TLS key is still `0640 root:<Kea's group>`, but only once they are
complete. (2) The copy of your config that the helper writes beside the real file to check it (`kea-dhcpX -t`) is now **owned by root, group = the
Kea account's group, mode 0640**: readable by the account that runs the check, not writable by it, so that account cannot change the config between
its being written and its being checked. (3) The `.jen_lock` lock is taken for **every** config check, apply and TLS install of a file (it was
taken only when a sha was supplied), so two helper runs on one config never share a temp file or race each other. (4) A Kea binary owned by its
service account is accepted only if that account has **execute** permission on it - the check used to ask "may anyone execute it?", which is true for
a file with only the other-execute bit set and then failed to start as that account. (5) One new op, `remove-config`: it deletes a config file only
if it still is exactly the file Jen wrote (a sha is required), under the same lock - it is how Jen undoes an Author Kea Config on a server that had no
file before when a later server fails. No sudoers change: it is still the one `/usr/local/sbin/jen-kea-helper` line. A host on an older helper keeps
working, but a failed authoring there leaves the new file and the Servers banner says to delete it by hand.

**v5.20.0 — the legacy grant is now checked, not just used.** Every
time Jen checks or installs the helper it also checks whether
`/etc/sudoers.d/jen-kea` (below) is still present, and records that
alongside the version. Settings → Kea → SSH shows a **"legacy grant
still present"** chip next to a host's helper status once it does, and
Health Center's "Kea host helper installed" check warns for the same
reason — even on a host that's fully upgraded to the current helper
version, since leaving the old grant in place after you no longer need
it is itself the residual risk. **v5.49.0 puts a button on it:** with
the chip showing and the helper installed, **Remove legacy grant** (next
to the host's Check button, superadmin, recent sign-in required) makes
the grant delete itself. It refuses unless the helper's own sudoers
file exists, holds the helper line for the SSH user and passes
`visudo -c` — so a host is never left with no root path — and it
re-checks the host afterwards so the chip and the Health row clear.
Jen has no button that adds the grant back: it would be Jen handing
itself root. Settings → Kea → SSH also carries a collapsed box, **Grant
or revoke the legacy root path by hand**, with both command blocks
filled in with each server's SSH user.

**v5.49.0 ships helper v5 — no new op.** `tail-log` (the op Trace and the DDNS log tab use) now reads the log through a bounded `collections.deque`, so memory is limited to the lines requested (at most 1000) however large the file is. Every host reporting v4 or older therefore shows the neutral *"v5 available"* next to its version with the **Update helper** button; nothing stops working without it.

**v5.29.0 ships helper v4 — one new op, `install-tls`.** It exists for
the https option of Settings → Kea → "Set up direct socket": Jen's own
private CA (see "Direct control sockets") issues a server certificate
for the daemon, and this op writes it — exactly three files, `ca.crt`,
`server.crt` and `server.key`, under `/etc/kea/tls/<service>/` and
nowhere else (the payload never carries a path). The key is written
`root:<daemon group>` mode `0640` so the daemon can read it and nothing
else can; the helper refuses to write through a symlink and refuses
anything that isn't PEM-shaped. Only the https setup needs v4 — the
http option, and everything else Jen does, works with any helper
version, so Settings → Kea → SSH does **not** show the amber "upgrade
available" for a v3 host — it shows a neutral *"v4 available (needed
for https sockets)"* next to the version, with the **Update helper**
button (v5.29.1; in v5.29.0 the button was missing for hosts already
at v2/v3), and the https option itself says "needs jen-kea-helper v4"
until you press it. There is no legacy-path equivalent
for this op, on purpose: certificate keys never travel in a generated
root script.

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

### Investigation logging — the one logger entry Jen touches (v5.68.0-beta.3)

Jen can put a Kea server's `kea-dhcp4` logger at DEBUG, debuglevel 55, for 5, 15 or 60 minutes (Trace and Servers, admins with access to every subnet) and puts it back itself. It touches **one thing**: the `Dhcp4.loggers` entry named `kea-dhcp4`. It sets `severity` and `debuglevel` and adds a `user-context` marker:

```json
"user-context": { "jen-investigation": { "until": "2026-10-04T12:15:00+00:00",
                  "restore": { "severity": "INFO", "debuglevel": "absent" } } }
```

`restore` is exactly what was there before (`"absent"` removes the key again; `{"created": true}` means Jen created the entry and removes it). **If a hand edit or a partial write leaves the marker without a readable `restore` object** (missing, not an object, no `severity` or no `debuglevel`, a `created` that is not `true`), Jen does **not** guess and changes nothing: the logger and the marker stay exactly as they are, the Health row **DEBUG logging left on** goes red with *the restore marker on &lt;server&gt; is unreadable — restore by hand* and the by-hand steps, *Turn it off now* says the same, and the sweep keeps reading the marker every minute, so once you have set `severity`/`debuglevel` back (or repaired `restore`) it finishes the job itself. (Before this release an unreadable marker was treated as proof that the keys had never existed, and its removal deleted the logger's severity and debuglevel with it.) The entry's `output-options`, every other logger and every other `user-context` key are left alone. The marker lives in the config on purpose: it survives a Jen restart, a restored database or a second Jen, and a person reading the file can see what is on and how to undo it. By hand, setting `severity`/`debuglevel` back to `restore` and deleting the `jen-investigation` key is the whole undo.

**What Jen records, and when it lets go (v5.68.0-beta.9).** Jen keeps an index of what it knows is on, and each entry says two things separately: whether the config file is back and whether the running Kea has taken it. An entry is dropped only when both are true. If a reload was refused and the restart failed, the file is already clean but Kea is still at DEBUG: the entry stays, the Health row says so, and the sweep tries the reload or restart again every minute until Kea takes it, even if the original time was longer. When you turn logging on and Kea does not take it, Jen puts the file straight back. **A server cannot be removed from Settings (or have its SSH host or API URL blanked) while it has an entry** until you turn the logging off from Servers. If a server is removed from Jen some different way (a hand edit of `jen.config`) while logging was on, Jen cannot reach it: the Servers page and the Health row show *Investigation logging may still be on on &lt;name&gt; (removed from Jen)*, with the host and the config path, and the by-hand edit above is the restore. Press **I restored it by hand** on the Servers page afterwards so that Jen stops reporting it. A marker Jen finds in a server's config that its own index did not list, and a refused removal, each write an audit row.

It is applied like every Kea edit (`kea-dhcp4 -t` first, the sha guard, revert on failure, a config revision with source `jen`) and the daemon is told with `config-reload` instead of a restart; a Kea that lacks `config-reload` or refuses it is restarted and the flash says so. One server at a time per Jen; there is no API route for it and `install.sh --unattended` never touches it. A more specific logger entry of your own (`kea-dhcp4.packets`, say) with its own `severity` keeps overriding the root one for that component, so a log that still lacks the packet dump after turning it on is usually that.

### The Problems inbox (v5.68.0-beta.5)

**Network → Problems** (`/problems`, every signed-in user, scoped by subnet) is fed by one core scheduler job, `jen_client_problems_sweep`, every five minutes, beside the investigation-logging sweep. For each SSH-configured Kea server it reads the last 1000 lines of the DHCPv4 log (`[kea] dhcp4_log_path`) through the helper's existing `tail-log` op — no new helper op, no sudo line — and writes one row per kind and client to the `client_problems` table (migration 30) for the messages `DHCP4_PACKET_NAK_0001`–`0004` (and the DHCPNAK Kea sends, visible at INFO), `DHCP4_DECLINE_LEASE` and its two failure forms, `DHCP4_PACKET_DROP_0007`/`0008`, `DHCP4_SUBNET_SELECTION_FAILED` and `DHCP4_DDNS_REQUEST_SEND_FAILED`. The packet-drop and subnet-selection messages and the NAK reasons beyond the first are DEBUG-level, so they appear only while a server logs at DEBUG; the DNS-update failure is an ERROR and is there at any level. Two more kinds need no log: a declined lease (a `lease4` row in state 1 that has not expired) and a reservation held by a different client, both read in one query from the lease database and resolved the moment the state is gone.

A per-server watermark (a `client_problems_wm:<server id>` row in `settings`) is the newest log time already counted, so the same line read by two sweeps is one event; log rotation between sweeps loses nothing already counted, and a server that writes more than 1000 lines between two sweeps loses the oldest. A server that cannot be read — no helper, SSH down — records nothing and is named in the job's log line; the Health Center's server rows already say why. A row whose kind has not recurred for 24 hours is marked resolved and leaves the page; rows not seen for 30 days are deleted by the daily audit cleanup (whatever the audit retention setting, including keep-forever). A row's subnet is where the event itself says (v5.68.0-beta.9): the subnet its address is in, else the subnet Kea selected for that very transaction (a DEBUG line, so only while investigation logging is on). It is never where the client is now: a NAK that names no address belongs to no subnet Jen can prove, so it is shown only to users who may see every subnet, and a client that was refused in one subnet and has since moved to a different subnet does not appear in that subnet's users' inbox. The times on a row are the events' own. Kea writes its log in the host's local time, so Jen converts each time to UTC with an offset it measures from the lease database (it matches the newest allocation lines of the tail to the lease rows' expiry, to the nearest quarter hour) and remembers per server; a server that has shown it nothing yet is read as UTC, and hovering **Last seen** on the page names the offset used for each server. The first time Jen reads a server's log it records what it finds, with those real times, and never alerts: a backlog is not news.

The alert type `client_problems` ("Client had DHCP trouble") is opt-in per channel like every alert type. It fires when one client has the same kind of trouble at least `[alerts] client_problem_threshold` times (3) within an hour of the newest log line, at most once per client and kind per 24 hours, with the subnet id attached so a channel scoped to subnets filters it. The window is the last hour from now, not from the newest line. An alert about a client Jen could not place in a subnet has no subnet id, and a channel that has a subnet scope does not receive it (a channel with no scope hears everything). A row counts as alerted only when a channel actually took the alert: a delivery that failed is recorded as attempted and tried again after half an hour while the client's trouble is still inside the window, and the sweep's log line counts attempted, delivered and failed. The two database kinds never alert: they are states, not events.

### Legacy grant (pre-5.11.0 — `python3` is root)

A Kea host that does not have the helper yet falls back to the old path:
Jen pipes a generated Python script over SSH into `sudo python3`. That
needs the grant below — and **`NOPASSWD: /usr/bin/python3` is root**,
full stop; the other lines only document what Jen runs, they don't
narrow anything. Jen shows an admin banner for every host still on this
path. (v5.68.0-beta.6: a host on this path was never affected by the
ISC-package ownership problem described under Helper build 10 above — the
generated script has no ownership check on the Kea binary — while the same
host moved onto helper build 7–9 was; press Update helper to reach build 10. Build 11 (v5.68.0-beta.13) changes only how the helper validates a
config on a host that has it — the validation copy is `0600`, owned by the account that runs the check, and runs with the unit's `Group=` and
`SupplementaryGroups=` — and the generated script of this path is unchanged. Build 12 (v5.68.0-beta.14) only changes which account the
helper validates as when the unit names one; the generated script of this path still runs no `-t` check of its own and is unchanged again. Build 13 (v5.68.0-beta.15) changes only how the helper writes and locks files on a host that has it, and
adds `remove-config`: the legacy path has no such op, so a failed Author Kea Config there leaves the file it created and says to delete it by hand.)

The grant is needed for **one run** to install the helper, and — below
helper v6 — for **one more run** to reach v6 (Update helper copies the
file through it). The life cycle is: add the grant → Install or Update
helper → remove the grant (the **Remove legacy grant** button in
Settings → Kea → SSH, or `sudo rm -f /etc/sudoers.d/jen-kea`). Leaving
it in place between those runs is the residual risk. **From v6 on,
updates are verified by signature (see "Kea host helper" above) and
never need this grant again** — a host that shows "signed updates" next
to its helper version has already made the last hop that needed it.
Three things never use this path at all, whatever the host has: D2
(kea-dhcp-ddns) operations (v5.23.0), the https "Set up direct socket"
material push (v5.29.0's `install-tls`), Trace (v5.49.0's client trace
reads up to 1000 log lines through the helper), and — from v6 — every
helper update itself; D2/https/Trace need the helper at v3, v4 and any
version respectively.

One line — a multi-line heredoc pastes badly into some terminals and web
consoles:

```bash
printf '%s\n' '# Jen (DHCP console) — LEGACY fallback. SSH user "youruser". python3 = root; see docs/ARCHITECTURE.md §3.3' 'youruser ALL=(root) NOPASSWD: /usr/bin/python3' 'youruser ALL=(root) NOPASSWD: /usr/bin/systemctl restart kea-dhcp4-server, /usr/bin/systemctl restart isc-kea-dhcp4-server' 'youruser ALL=(root) NOPASSWD: /usr/bin/systemctl * kea-dhcp6-server, /usr/bin/systemctl * isc-kea-dhcp6-server' 'youruser ALL=(root) NOPASSWD: /usr/bin/tail -200 /var/log/kea/*' 'youruser ALL=(root) NOPASSWD: SETENV: /usr/bin/apt-get update -qq, /usr/bin/apt-get install -y kea-dhcp4-server, /usr/bin/apt-get install -y kea-dhcp6-server' | sudo tee /etc/sudoers.d/jen-kea >/dev/null && sudo chmod 440 /etc/sudoers.d/jen-kea && sudo visudo -c -f /etc/sudoers.d/jen-kea
```

`SETENV` on the `apt-get` line is needed because Jen runs it as
`sudo DEBIAN_FRONTEND=noninteractive apt-get install …`.

**"No legacy python3 grant" even though the line above is definitely
there (v5.65.13).** A one-shot `sudo -n /usr/bin/python3 …` probe can't
tell "the line is missing" apart from sudo refusing a CORRECT line for
an unrelated reason — the fix is to surface what sudo actually said,
not just yes/no:

- **A later rule wins.** `/etc/sudoers.d` is read in lexical filename
  order, and for any given command the LAST matching rule decides — a
  file sorting after `jen-kea` (a per-user file named after the login,
  cloud-init's `90-cloud-init-users`, anything from `k`–`z`) that grants
  the SSH user `ALL` WITH a password makes `sudo -n /usr/bin/python3`
  need one too, even though `jen-kea`'s own line is untouched. Sudo
  says *"a password is required"*.
- **`Defaults requiretty` / `use_pty`** on a hardened box — Jen's SSH
  session runs without a terminal, and sudo without a PTY under that
  setting says *"sorry, you must have a tty to run sudo"*. Since the
  helper (once installed) is granted `NOPASSWD` too and answers fine
  over the very same connection, a host where the helper works but this
  probe doesn't is a symptom of a rule affecting `python3` specifically,
  not requiretty.
- **The grant was pasted on the wrong box.** If Jen and the Kea daemon
  aren't the same host, the SSH card's own **user@host** — the exact
  target Jen probes — tells you which one to paste on.

Settings → Kea → SSH's **Test legacy grant** button (next to Check)
probes the grant without attempting an install and shows sudo's own
first line of output, plus (when it fails) the `python3` rule(s) from a
full `sudo -n -l` and any later rule that grants `ALL` without
`NOPASSWD` — the pair that tells "a later rule overrides it" apart from
"the line is genuinely missing". Diagnose by hand the same way, reading
the rules in the order they print (last match wins):

```bash
sudo -n -l
```

Never `sudo -n -l /usr/bin/python3` (or any other `-l <command>` form)
to answer this question — sudo's `listpw` default is `any`, so it asks
for no password, and prints the command as runnable, as long as ANY of
the user's rules carries `NOPASSWD` (the helper's own rule always
does), whether or not THIS command specifically would actually need
one.

---

## Upgrading Jen

```bash
tar xzf jen-vX.X.X.tar.gz
cd jen
sudo ./install.sh
```

Select **Keep existing config** when prompted. The installer builds the new release under `/opt/jen/releases/<X.Y.Z>/`, points `/opt/jen/current` at it with one atomic symlink flip, restarts the service, and flips back to the previous release if it fails to start.

Coming from a stable install more than one release old? **[docs/upgrading.md](upgrading.md)** covers every operator-visible change since v5.56.3, one section per change, so you know what to expect before you upgrade rather than after. Restoring a recovery bundle onto a fresh box, rotating the helper signing key, or recovering from a bad helper build are step-by-step procedures in **[docs/runbooks.md](runbooks.md)**.

Your config file and SSL certificates and SSH keys (in `/etc/jen`), and your uploads, database backups and installed plugins (in `/var/lib/jen`), are never modified during an upgrade. Each release's application tree and its own virtualenv are root-owned and read-only to the service account.

### Release channels (v5.32.0)

Jen publishes two kinds of release. A **stable** release is a plain version (`5.33.0`). A **beta** is the same code published first as a pre-release (`5.33.0-beta.1`, then `-beta.2` if something needed fixing), so it can be run for real before it becomes stable. From 5.32.0 on, every feature release goes out as a beta first; the stable release is the last beta with only the version number changed.

Each install follows one channel, chosen under **Settings → System → Updates** (superadmin, with a password confirmation) and stored as `[updates] channel` in `jen.config`:

| Channel | What "Check for Updates" and the in-app updater offer |
|---|---|
| `stable` (default) | The newest stable release. Betas are never offered. |
| `beta` | The newest release of either kind — a box on `5.33.0-beta.1` is offered `-beta.2`, then `5.33.0` when it's promoted. |

Things to know before choosing beta:

- A beta may carry bugs a stable release never sees. That's what it's for. Report them with the exact version from the About page.
- It's the same signed tarball, the same checksum and signature verification, the same staged install and automatic rollback. Beta means less soak time, not less safety.
- **Switching back to stable never downgrades.** The box keeps the beta it's running until the next stable release is newer than it; then it's offered that. Nothing is removed.
- Every beta has its own changelog entry, and a plugin that requires Jen `5.33.0` loads on `5.33.0-beta.1` — the beta *is* that version, early.

The in-app updater on a box that predates 5.32.0 only ever asks GitHub for the latest stable release, which is why 5.32.0 itself shipped straight to stable.

**v5.27.0 changes how a new plugin install lands.** Installing or reinstalling a plugin from Settings → Plugins no longer writes its files directly — Jen asks a dedicated root-privileged service to fetch, verify, and place them, and the result lands read-only under `/opt/jen/plugins-installed/`, the same way a Jen release itself is root-owned. A plugin installed before v5.27.0 still works from its old, Jen-writable location (`/var/lib/jen/plugins/`); the Plugins page marks it "writable — reinstall to harden" with a one-click Reinstall button that moves it to the new location. Nothing about enabling, disabling, or a plugin's own database tables changes.

**v5.28.2 makes plugin migrations portable across MySQL and MariaDB.** A plugin's `db_migrations` are plain SQL, and until now the only way to write a re-runnable `ALTER TABLE` was MariaDB's `IF [NOT] EXISTS` — which MySQL 8 doesn't have, so a plugin using it (IPAM did, for every schema change since its v1.3.0) simply failed to migrate on MySQL and never enabled. Jen now records a migration whose only error is "duplicate column", "duplicate key name" or "can't DROP — doesn't exist" as already applied and moves on; a genuinely wrong statement still fails. Plugin authors: write plain `ALTER`s and use the explicit `{"version": N, "description": "…", "sql": "…"}` migration form. IPAM v1.4.4 requires this release for exactly that reason — on an older Jen the Plugins page refuses it with the usual "requires Jen …" message until you upgrade.

**v5.28.1 gates activation on a plugin's own database migrations.** If a plugin declares `db_migrations` in its manifest and one fails to apply, the plugin is no longer enabled anyway — the Plugins page shows a red "migration failed — not enabled" chip with the underlying error, and Jen keeps running with the plugin's previous state (if any) untouched. Fix whatever the error names (usually a schema conflict from a manual DB change, or a genuinely broken migration in a newer plugin release) and reinstall or restart Jen to retry. The one exception: a version that has already migrated cleanly once before is still loaded even if a later attempt logs an error — that's an old, deliberate carve-out (v4.4.19) for a manifest-format quirk on an otherwise-working install, not a reason to make its existing functionality disappear.

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

## Kea data: exports, backups and migration (v5.67.0-beta.11)

**Settings → Databases** offers three Kea groups, and they are not the same thing:

| Group | Tables | What it is for |
|---|---|---|
| **Kea host reservations (IPv4 and IPv6)** | `hosts`, `dhcp4_options`, `dhcp6_options`, `ipv6_reservations` | Every permanent host reservation with its per-host options. This is what the **scheduled backup**, **Back Up Now**, and the Recovery step of the setup wizard save, and the default for a Kea migration. |
| **Kea host reservations — IPv4 only** | `hosts`, `dhcp4_options` | The IPv4 half, kept for exports made before the group above existed. |
| **Active leases** | `lease4` | A point-in-time snapshot, on request only. Leases are transient — they expire and renew on their own — so they are never part of a backup. |

A backup is *reservations*, not "Kea's database": it carries no leases and none of Kea's configuration (that lives in `kea-dhcp4.conf`, which Jen keeps a revision history of under Servers → Config history). A table that does not exist on your Kea is left out of the file rather than written empty.

The Kea export is streamed to disk one row at a time, like the Jen export, so a large `lease4` never has to fit in memory.

**Export format 3.** A binary column — a reservation's identifier, a lease's hardware address, an option's value — is written as `{"$bin": "<hex>"}`, a tagged object that cannot be confused with text that merely looks like hex, and the file's `_meta.binary_columns` lists which columns were binary. On import Jen decodes by the **target's own column types**: a tagged value always becomes bytes; a bare string bound for a binary column in an older file (formats 1 and 2 wrote hex text) is decoded as hex; a value that is not valid hex **refuses that table**, naming the column and row, and imports nothing into it — the other tables in the file are still imported. A database-to-database **migration** copies the bytes as bytes and never goes through the file format at all. Restores run in foreign-key order: `hosts` before the option and IPv6 rows that point at it, whatever order the file lists them.

**Importing Kea data (v5.67.0-beta.13): host by host, never by id.** A `host_id` in a file is never an identity — it is only a number the exporting database happened to assign. Each reservation in the file is matched to one already in the target by what Kea's own unique keys mean by "the same reservation": its identifier, identifier type, and DHCPv4 and DHCPv6 subnet. A reservation that is not there is inserted **without** its `host_id` (the target assigns one), and the options and IPv6 reservations that came with it are attached to *that* host; their own ids (`option_id`, `reservation_id`) are never carried either. The duplicate setting then means exactly this:

- **Skip** (the safe default): a reservation that already exists is left as it is, and the file's options and IPv6 reservations for it are skipped with it. Only a duplicate key is ever "skipped" — a foreign-key failure, a wrong type or a value too long **aborts the import and rolls the whole thing back**, naming the table and row; nothing is committed half-restored under a green line.
- **Overwrite**: the matched reservation is **updated in place** (its `host_id` stays the same — nothing is deleted and re-inserted), and for each child table the file *contains* (`dhcp4_options`, `dhcp6_options`, `ipv6_reservations`) that reservation's rows are replaced by the file's. A child table the file does not contain is never touched: importing an IPv4-only file over a dual-stack reservation keeps its IPv6 reservations and DHCPv6 options.
- Options in a file that belong to no reservation in it — older backups also carried global, subnet and class options — are not written anywhere; the result line counts them. (A reservation backup carries **host-scoped options only** since 5.67.0-beta.13: Kea's `dhcp_option_scope` numbers a host's options 3, and the export asks for exactly those.) A backup made before Kea 3.2 lacks columns a newer schema requires (`client_classes` on both options tables); the import fills them with their empty value rather than failing.

**Migrating a Kea database (v5.67.0-beta.13): into an initialised Kea database, data only.** Jen never creates or changes Kea's tables. The target must already be a Kea database that `kea-admin db-init mysql` has initialised — it has Kea's `schema_version` row, with the **same major version** as the source's, and every table of the group being migrated. Anything else is refused before a row is written, naming what is wrong. The rows are copied in one transaction with plain inserts (a primary-key or unique-key collision is an error, not a silently skipped row), counted from what the database reports, and verified per table. If anything fails the transaction is rolled back and nothing that was on the target is touched. Before this release a failed migration dropped whatever tables it believed it had created — including a freshly initialised target's own. **The migration copies the group's rows exactly as the backup does (v5.67.0-beta.17):** the hosts, their IPv6 reservations and a reservation's own, host-scoped options — never the options of Kea's config backend (global, subnet, shared-network, pool and class options), which are not part of a reservation move and would be written into the target by their source ids or fail on its empty subnet tables. The result says how many host-scoped option rows were copied and, when the source had any, how many config-backend option rows it left behind.

**A CA bundle for the target (v5.67.0-beta.15).** The migration page has an optional **CA bundle** field, used by the connection test and by both migrations: a path to a file on the Jen host, and the connection to the target is then TLS verified against it. Without it the connection is plain, which fails against a target that requires TLS and sends the password in clear to one that merely allows it. A path that is not a file on the Jen host is refused before anything connects.

**Migrating Jen's own database** creates tables, so every table being migrated must be **absent** from the target (use an empty database). A table that already exists refuses the migration, and nothing is replaced or merged; nothing ticked on the page is refused rather than meaning "everything". A failure drops only the tables that migration created.

> **If you restored or migrated Kea reservations through Jen before 5.67.0-beta.11** every identifier on those rows was stored as the text of its own hex (a MAC stored as the twelve characters `341343e60e2a`), and those clients never matched their reservation again. The Health Center's **Kea reservations have plausible identifiers** check finds them, and **Settings → Databases → Import → Check reservation identifiers** shows exactly which rows, with before and after, and repairs the ones you tick. See [Troubleshooting](troubleshooting.md#reservations-restored-by-an-older-jen-never-match-their-client).

## The installer: Jen's own database and its log (v5.67.0-beta.18)

**Jen's database is the one thing the installer cannot defer.** Jen runs its schema migrations against `[jen_db]` before it serves a single page, so with no reachable database the service dies on start and systemd restarts it every five seconds — there is no login page and no `/setup` to finish in. The installer therefore offers no "continue without it" for Jen's database: interactively the menu is `r` retry, `e` edit and try again, `i` install MariaDB on this machine and create the database (only when the host is `localhost`, `127.0.0.1` or `::1`), and `q` quit; unattended (`--unattended` or an answers file) an unreachable Jen database is **fatal**, with the SQL to create it and the reason. (Kea's API and database are different: Jen runs without them and `/setup` connects them, so their prompts keep a `c` continue.) If the service still fails to start, the installer prints the journal and names `[jen_db]` in `jen.config` as the likeliest cause.

**The install log.** `/var/log/jen-install.log` (root:root, mode 0600, appended per run under a dated header) receives the stdout and stderr of every `apt-get`, `pip`, `python -m venv`, `systemctl` and `mysql` call the installer makes — `apt` runs with `DEBIAN_FRONTEND=noninteractive` and `NEEDRESTART_MODE=l`, so it neither prompts nor prints its epilogue — and a failing step prints the last 20 lines and the path. Commands whose arguments or input carry the database password record only what the step is, never the argument or the statement. If the file cannot be opened the installer says so and carries on without a log.

**MariaDB here, on request.** With `JEN_DB_INSTALL_LOCAL=yes` (answers file or environment) — or `y` at the interactive prompt, or `i` in the menu — a local, unreachable Jen database makes the installer `apt-get install -y mariadb-server`, `systemctl enable --now mariadb`, wait up to 30 seconds for a root connection over the unix socket, create the database and user, and test them. It is never done for a remote host, never without that opt-in, and `uninstall.sh` leaves MariaDB and Jen's database in it alone at every level.

## Jen data: importing, restoring and what a plugin leaves behind (v5.67.0-beta.14)

**Settings → Databases → Import** accepts a Jen export (gzip-compressed, or plain JSON) and asks, for a Jen export, how to apply it. The two modes make different promises, and the page says which:

- **Replace** (the default) clears each ticked table and inserts **exactly the rows in the file**. A row the database refuses — a missing value in a required column, a duplicate key, a value too long — fails the import; the count shown for a table is what the database reports it inserted, and it must equal the file's. Before the first change Jen saves a snapshot of the whole Jen database (an ordinary export, in a private `pre-import-<time>` folder under the backups directory); if **anything** fails — a core table, a plugin's migration, a plugin's rows — the snapshot is put back: every table, the plugin migration records, and any plugin table the failed import created. A failed replace leaves the database as it was, and the page says so. Two honest limits: Jen keeps running while it imports, so anything written to the replaced tables between the snapshot and a failure is lost along with the import; and if the snapshot itself cannot be taken (disk full, directory not writable) nothing is imported. If putting it back also fails, the folder is **kept**, named in the message, and its `jen_db.json.gz` is an ordinary export — import it with Replace once the cause is fixed.
- **Merge** inserts only rows whose key is not already in the table and keeps what is there. It takes **no snapshot**: the core tables are committed together, then each plugin's tables one plugin at a time, and a failure stops at the table named — what was already committed stays. The result line for each table is what really happened (`N added`, or `N added, M skipped` when rows were left out), never the number of rows in the file.

**A scoped replace of a parent table needs its dependents.** A restore runs with the database's foreign keys switched off, so deleting a table's rows never cascades. Replacing only `users` would leave multi-factor methods, backup codes, trusted devices, passkeys, saved searches, dashboard layouts and API keys pointing at accounts that no longer exist. If the file carries those tables and you did not tick them, the import is refused before anything changes, naming them; tick them too, or restore the whole file.

**The file is checked first.** An upload that is not a Jen export — the top level is not an object, a table is not a list of rows, a row is not an object, a number is text, `format` is newer than this Jen understands — is refused with `not a Jen export: <reason>`, never an error page. gzip is recognised by its first two bytes, so a damaged gzip says so; a plain-JSON file goes through the same size cap and memory check as a compressed one.

**Restoring onto a new machine** (`sudo ./install.sh --restore`, see below) is strict about the core tables as well as the plugins: a table that is missing, a file whose rows have no column this schema knows, a count the database does not confirm, or a skipped row stops the restore and rolls everything back. `--lenient-plugins` relaxes only the plugin half.

**What happens to a plugin's data when you uninstall it.** Uninstalling removes the plugin's files and nothing else: its tables and rows stay in the database, **and in every backup** — the scheduled and manual backups, the recovery bundle, the pre-restore and pre-import snapshots and a Jen database migration. Jen records which tables each plugin owns (`plugin_tables`, written whenever the plugin's migrations run) so the answer no longer depends on the plugin's code being on disk. Reinstalling reconnects them: the plugin finds its tables where it left them. Restoring a backup onto a **new** machine without the plugin installed cannot recreate its tables (a table is only ever created by the plugin's own code, never from a file), so that plugin's data is named in the restore output and stays inside the backup; install the plugin and restore again to bring it back. A plugin uninstalled **before** 5.67.0-beta.14 was not recorded: its data is still in the database but not in a backup until you reinstall and uninstall it once more.

**Backup schedule (v5.67.0-beta.15).** An enabled schedule must back up at least one thing: tick the Jen database, the Kea reservations, or both, or leave the schedule disabled. A schedule with neither ticked used to be accepted, to record a "run" every night with nothing in it, and to count as protection on the Getting started checklist; the page now refuses it and the checklist counts a schedule only when it is enabled and has a target. A schedule saved that way by an older Jen shows "Nothing was backed up — no target is selected" as its last status until you tick something.

## Recovery Bundle (v5.44.0)

### Recover Jen on a new machine

**Export**, on the box you're moving away from: **Settings → Databases → Recovery**, superadmin, step-up (recent password confirmation) required. Choose a passphrase (12 characters minimum, entered twice) and download `jen-recovery-<hostname>-<timestamp>.tar.enc`. This is **not the same as a regular backup** — it is NOT redacted. It contains, in the clear once decrypted:

- `jen.config` — every credential Jen holds: the Jen and Kea database passwords, Kea Control Agent credentials, and (if configured) the OIDC client secret.
- The MFA encryption key (`/etc/jen/mfa_key`) — without it, every stored TOTP secret and passkey is permanently unusable, and encrypted `kea_config_revisions`/`alert_channels` rows can't be decrypted either.
- `/etc/jen/ssl/` and `/etc/jen/ssh/` wholesale — Jen's own HTTPS certificate and key, the private Kea CA (v5.29.0) if you use direct HTTPS control sockets, and the SSH keypair Jen uses to reach your Kea hosts.
- A fresh export of every Jen database table (users, reservations notes, alert config, MFA, API keys, audit log — everything `Settings → Databases → Export` can select, plus a few tables that export never exposed individually) **and every table any currently installed plugin owns** (v5.66.0-beta.5 — a DNS Sync target's synced records, IPAM's static entries, Watchdog's targets and check history, and so on for every bundled plugin; before this release only the plugin's own enabled/disabled row came back, never its data). Check **"Without audit history"** on the form to leave `audit_log` out (the biggest table on a long-running install); export it separately from `Settings → Databases → Export` afterward if you need it.
- Uploaded content (custom icons, the nav logo) — not the plugin code trees themselves (those come back from the plugin registry on restore) and not the scheduled-backup archives (redundant with the fresh export just taken).
- The latest Kea config Jen has a record of pushing or noticing, per server and service — a reference copy, never pushed anywhere automatically.

Since 5.65.0 the bundle is written and read as a stream (format `JENREC2`), so building or restoring one no longer needs memory in proportion to its size, and the size limit is 2 GB rather than 200 MB. A bundle made by an earlier Jen (`JENREC1`) still restores exactly as before. A bundle that was cut short or edited is refused with the same message as a wrong passphrase, and nothing on the box is touched.

The database export inside the bundle is itself written straight to disk one row at a time now too (v5.66.0-beta.4) — building the bundle never needs much memory, however large `audit_log` has grown. **Restoring still does** (see the step-by-step below), which is exactly why the manifest records the export's size and `jen.tools.restore` checks it against the machine's free memory before touching anything.

The bundle is only as secret as the passphrase. Anyone with both the file and the passphrase can read all of the above. Store the file somewhere only you control, and never send the passphrase alongside it (a different channel, or memorize it).

**Restore**, on the new machine, after a normal `sudo ./install.sh` has already set up Jen (venv, systemd unit, sudoers) with its own fresh secrets:

```bash
sudo ./install.sh --restore /path/to/jen-recovery-*.tar.enc
```

You'll be prompted for the passphrase (never pass it as a command-line argument — anything on argv is visible to every other process on the box via `ps`). The installer refuses to proceed if the bundle's Jen major version doesn't match the installed one, if the Kea server the bundle's own `jen.config` points at is reachable right now and running a different Kea *major* version than the manifest recorded at export time (unreachable skips this check with a loud warning, since you may be restoring before Kea itself is back up), or if this machine does not currently report enough free memory or disk space to restore the bundle — measured, not guessed (`docs/runbooks.md`'s "Before you start: size" step), and checked BEFORE anything is stopped or touched; the check weighs whichever is bigger, the incoming bundle's own database export or the one already on this machine (v5.66.0-beta.6 — the pre-restore snapshot and a rollback both have to hold the existing database's export too), and the refusal names both the figure needed and what's actually available. Once those pass, the restore runs as a sequence, all through `python3 -m jen.tools.restore` (the module `install.sh --restore` calls):

1. **Stop** — if `jen` is a running systemd service it is stopped, so nothing is writing to the config, content or database while they are replaced.
2. **Snapshot** — everything about to be overwritten is saved to `<content dir>/backups/pre-restore-<UTC timestamp>/` (mode 0700): a tar of `/etc/jen`, a tar of the content directory (without `backups/` and `tmp/`), and a fresh export of the Jen database. If the snapshot cannot be taken, nothing is changed.
3. **Apply** — `/etc/jen/*`, the content directory and the database are replaced from the bundle. Files the bundle carries overwrite; files already on disk that it does not carry are **left in place, never deleted**, and named in the output ("left in place (not in the bundle) under …"). A plugin the bundle recorded whose code is not on this machine produces a warning — its data is **not** restored by this run (a table is only ever created by the plugin's own code), but it is still inside the bundle: keep the bundle, reinstall the plugin from Settings → Plugins, then run the restore again.
4. **Start and health-check** — Jen is started again (only if it was running before, or you passed `--start`) and `/api/v1/health` is polled for up to 60 seconds on the restored `[server] http_port`.
5. **Roll back on failure** — if anything raises during the apply, or Jen does not come up healthy, the snapshot is put back (config, content, database), Jen is started again, and the command exits non-zero naming the snapshot directory.

**A plugin that lost its data fails the restore (v5.67.0-beta.11).** For a plugin whose code is on this machine, a failed migration replay, a failed row import or a failed invariant check used to print a warning, start Jen, pass the health wait and exit 0 over missing data. It is now an error that names the plugin and the table and takes the same rollback as any failed apply: Jen is as it was before the restore, byte for byte. `--lenient-plugins` is the explicit escape — the failures are printed, and recorded with the snapshot in `restore-report.txt`. A plugin whose code is **not** on this machine stays a warning: its data is still in the bundle for a later restore. The Settings → Databases import page shows the same failures as errors, not as a line among the successes.

Flags: `--no-stop` skips the stop/start (use it in Docker, or where Jen is not a systemd unit — stop it yourself first), `--start` starts Jen afterwards even if it was not running, `--force` allows a bundle from a newer Jen, `--lenient-plugins` accepts a plugin's data failing to restore (below). Snapshots are small and are kept. To undo a restore that finished but turned out wrong: `sudo ./install.sh --rollback /path/to/pre-restore-<timestamp>` (add `--no-stop` if Jen is not a systemd unit).

Afterward:

1. Confirm Jen is up and you can log in (the restore already started it and checked `/api/v1/health` if it was running; if it was stopped, start it: `sudo systemctl start jen`).
2. Log in and go to **Settings → Kea → SSH** — run **Update helper** on each server. A helper-version mismatch right after a restore is expected, not a bug (this box's `jen-kea-helper` copy came from wherever `install.sh` last ran, not from the old box).
3. Check **Settings → Plugins** — every plugin you had installed came back enabled with its data intact (v5.66.0-beta.5: its own tables, not just its enabled/disabled row), but the plugin *code* was not re-copied; reinstall from the registry for anything the page flags as missing. A plugin whose code isn't on this machine at all is skipped and named in the restore's own output — its data stays in the bundle, untouched, and comes back the next time you restore *after* reinstalling it.
4. **A bundle made before v5.66.0-beta.5 never contained any plugin's data to begin with** — only Jen's own core tables. Restoring one leaves every plugin exactly as this fresh install already has it (enabled with an empty schema, or not installed at all); there is nothing to recover for it. Take a fresh recovery bundle once you're on v5.66.0-beta.5 or later so the next restore actually covers plugin data too.
5. Confirm HTTPS and the SSH connection to each Kea host still work — the restored certs/keys should just work if the new box's hostname and network position match the old one, but verify rather than assume.
6. If the bundle was made with **"Without audit history"** checked, `audit_log` is empty — the restore's own printed checklist says so; restore one exported separately if you need it.

Never touches a Kea host directly — every Kea-side operation you take after a restore (the helper update, anything else) goes through the exact same UI you'd use any other day.

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
- `jen_subnet_days_to_90pct` (v5.43.0) — the pool exhaustion forecast's days-to-90% per subnet; `-1` when the trend is flat, falling, or there isn't yet enough history
- `jen_server_pkt4_<name>_total` (v5.43.0) — DHCPv4 packet counters per server, one metric family per counter name (`jen_server_pkt4_received_total`, `jen_server_pkt4_ack_sent_total`, …), from the latest packet health snapshot (v5.41.0/Q42) — absent entirely until a server has taken one

### Grafana dashboard (v5.43.0)

A ready-made dashboard ships at `contrib/grafana/jen-kea.json` in the
release tarball, and Settings → System → **Download Grafana dashboard**
(admin) serves the same file at
`GET /settings/system/grafana-dashboard.json`. Import it into Grafana
(Dashboards → Import → Upload JSON file, or paste the URL) and point
its `DS_PROMETHEUS` datasource variable at whatever Prometheus instance
scrapes `/metrics`. Panels: Kea reachability per server, pool
utilization (stat + time series), active leases, the pool exhaustion
forecast, and packet health rates — the last two skip a subnet/server
gracefully rather than erroring when there isn't yet enough history or
a first packet health snapshot.

---

## Health Center

**Support bundle (v5.33.0).** When you need to ask for help, Settings → System → Support bundle → **Download** gives you one zip to attach: the Health Center results below, plus versions and channel, HA state, subnet drift, each server's latest Kea config, plugin state, schema versions, recent audit and alert rows, and a scrubbed tail of the Jen log. Every password, key, token and secret is masked before it is written (a test in the suite seeds each secret location with a sentinel and asserts none survive), key *paths* appear but key *files* are never opened, and the zip is built in memory when you click — nothing is stored on the server. Superadmin, with a password confirmation, because the bundle describes the whole topology.

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
| **DEBUG logging left on** (v5.68.0-beta.3) | Fails when a server's investigation logging should have ended and Jen's sweep has not been able to put the log level back (two minutes' grace). Reads Jen's own index, never SSH at render time. | Turn it off from Trace or Servers; see Troubleshooting → "DEBUG logging left on" |
| **Subnet map matches Kea** | `check_config_drift()` — Jen's `[subnets]` list vs Kea's live config | Settings → Kea → `[subnets]` |
| **Every Kea subnet is named** | every subnet id in Kea's config has a name in Jen's `[subnets]`, and vice-versa | Settings → Kea → `[subnets]` |
| **Configuration Doctor** (v5.40.0) | `jen/services/config_doctor.py`'s sixteen semantic checks on the live config — see "Configuration Doctor" below | Network → Doctor |
| **Packet health** (v5.41.0) | `pkt4-*`/`v4-allocation-fail*` counters from the last hour of `statistic-get-all` snapshots — worst verdict across servers; warns when drops + parse failures exceed 1 % of received or any allocation failure occurred, fails when drops exceed 10 % or NAKs exceed 10 % of all replies (ACK + NAK) once there are at least 10 NAKs in the window; on Kea 3.2 the extra drop reasons Kea reports (queue full, RFC violation, service disabled, …) are listed in the detail; `skip` until a server has two snapshots | Servers page — see "Packet Health" in the user guide |
| **Server capabilities** (v5.64.0) | What each Kea server can do right now, as Jen derives it — Control Agent vs direct control sockets, the Kea host helper (and whether it is new enough for https sockets and Trace), packet statistics and the 3.2 drop-reason counters, HA / lease / reservation commands, DDNS, Kea 3.2 readiness — listed as *on* and *off* per server. Informational: it never warns or fails on its own (an unreachable server is `kea_reachable`'s to report, a missing helper the helper row's). Hook- and DDNS-derived items are read from the active server's config only; another server shows them off. A refresh also drops the cached capabilities other pages hold | Servers page; `/api/v1/health/checks` (id `capabilities`) |
| **Pool utilization** | the latest lease snapshot per subnet — warns at the alert threshold, fails at 95 % | Subnets page; widen the pool |
| **Pool exhaustion forecast** (v5.36.0) | a least-squares line through the last 30 days of daily peak active leases per subnet — warns when it reaches 90 % of the pool within 30 days, fails within 7; `skip` until a subnet has 7 days of snapshots. A pool resize restarts the fit. | Reports page; widen the pool or shorten lease lifetimes |
| **Lease snapshots current** | the newest snapshot is no older than 2× the snapshot interval | Settings → System; check the background worker is running |
| **kea-dhcp-ddns reachable** | when dhcp4 `dhcp-ddns.enable-updates` is on: `version-get` on the `d2` service (`ca` mode only) | DDNS page; the D2 service |
| **kea-dhcp-ddns error counters** | D2's `ncr-error` + `update-error` statistics | DDNS page; the DNS server / TSIG keys |
| **TLS certificate expiry** | days until Jen's HTTPS certificate expires — warns at 30 days, fails at 7 | Settings → Access & Security → upload a renewed certificate |
| **Jen database** / **Kea database** | a `SELECT 1` round trip and its latency | the database host / credentials |
| **Database schema current** | the applied migration version matches the latest | restart Jen (migrations run at startup) |
| **Kea reservations have plausible identifiers** (v5.67.0-beta.11) | `hosts` rows whose identifier (hw-address, DUID or client-id) is the ASCII text of its own hex — the mark an older restore or migration left; `skip` for a subnet-restricted account (the count is fleet-wide) | Settings → Databases → Import → Check reservation identifiers |
| **Kea host helper installed** | each SSH-configured Kea host has recorded a `jen-kea-helper` version, and (v5.20.0) whether the legacy `python3` grant is still present | Settings → Kea → SSH → Install helper; **Remove legacy grant** (or remove `/etc/sudoers.d/jen-kea` by hand) |
| **Background workers running** | the scheduler + alert loop started with this process | only reported under gunicorn, not the werkzeug fallback |
| **Jen up to date** | always `skip` here — run the check from **Settings → System → Updates** (it contacts GitHub) | — |
| **Control transport ready for 3.2** (readiness, v5.38.0) | `ca` mode fails once any server is on Kea 3.0+ and warns below that; `direct` mode warns for any server/daemon without its own control-socket URL | Settings → Kea → Set up direct socket |
| **Kea host helper current for 3.2** (readiness) | each SSH host's recorded `jen-kea-helper` version against the one Jen ships (v4 carries the direct-socket and TLS ops) | Settings → Kea → SSH → Update helper |
| **No removed config keys** (readiness) | the live config for keys Kea removed or renamed: `require-client-classes`, `only-if-required`, the singular `client-class`, `reservation-mode`, and the DDNS parameters that moved out of `dhcp-ddns` (`qualifying-suffix`, `override-*`, `replace-client-name`, `generated-prefix`, `hostname-char-*`) — each with its path and replacement | Client Classes (Jen rewrites the class keys on save); by hand for the rest |
| **HA peers on the same Kea** (readiness) | both reachable peers' Kea minor version | upgrade one node at a time (planned maintenance) but finish both |
| **kea-dhcp-ddns on its own socket** (readiness) | when DDNS updates are on: D2 answers `version-get` on its own http socket rather than via the Control Agent | Settings → Kea → D2 Control Socket |

The **TLS certificate expiring** alert (Settings → Alerts & Integrations)
fires once when the certificate crosses 30, 7, and 1 days remaining, and
resets when you install a renewed one.

### Upgrading Kea (the 3.2 readiness group, v5.38.0)

Kea 3.2 removes the Control Agent. The **Kea 3.2 readiness** group at
the bottom of the Health Center is the plan for that upgrade: five
checks that only report, never change anything, and `skip` wherever
this install has nothing to look at (a single Docker box with no
helper, no HA and no DDNS skips most of them). Settings → Kea shows
the same result as one line on the Servers card: *Ready for Kea 3.2*
or *N action(s) before upgrading*. Work through the actions in this
order: put every server and daemon on its own control socket
(Settings → Kea → Set up direct socket, which needs Kea 2.7.2+ and the
current helper), fix any removed config key the check names, make
sure D2 has its own socket if you use DDNS, then upgrade the HA pair
one node at a time with the planned-maintenance flow and finish both
nodes before calling it done — Kea's HA hook expects matching
versions. The existing **Kea version supported** check keeps
reporting what is running today; readiness reports what has to
happen before tomorrow.

The **Pool exhaustion forecast** alert (v5.36.0) fires when a subnet's
trend reaches 90 % of its pool within 30 days, at most once per subnet
every 7 days (the settings key `pool_forecast_alerted_<subnet id>` holds
the date it last fired). It is a complement to the utilization alert, not
a replacement: utilization says where you are, the forecast says where
you are heading.

The **Packet health** alert (v5.41.0) fires once per server when its
packet-processing verdict flips to warn or fail, and again — a separate
"recovered" notice — once it returns to a clean state, the same
detected-once/resolved-once pattern as HA failover and config drift. It
is computed in the same snapshot pass as `lease_history`, so it fires on
the same cadence as the snapshot interval, not every alert-loop tick.

## Configuration Doctor

**Network → Doctor** (`/tools/doctor`, v5.40.0) looks for things in the
live Kea config that are valid syntax and valid types — so `kea-dhcp4
-t` (Settings → Kea → Test config) has nothing to say about them — but
are contradictory, unreachable, or simply pointless. It is **not** a
syntax or type checker: run Test config for that. Admin/superadmin
only, unrestricted by subnet access, since the whole config's shape is
what the page shows. Each finding is `fail` (Kea will refuse to load
the config, or the affected part can never actually work),
`warn` (loads fine, but is very likely a mistake), or `info`
(harmless, flagged so you know it's there) and always says why, not
just what.

Findings of the same kind (v5.50.0) are grouped: 68 reservations that
sit inside a dynamic pool show as **one** row with a count and a
"Show all" list, sharing the explanation once, instead of 68 near
identical cards. The Health Center row reads "N note(s) of K kind(s)",
and the JSON API keeps returning the flat findings.

| Check | What it means |
|---|---|
| Pools overlap | Two pool ranges intersect — Kea refuses to load a config with overlapping pools |
| Pool outside its subnet | A pool's range extends past its subnet's prefix — Kea refuses to load this too |
| Reservation address outside its subnet | A reservation's address doesn't fall inside the subnet prefix Jen filed it under |
| Reservation address is inside a dynamic pool | Info normally (Kea excludes it automatically); `warn` when `reservations-out-of-pool` is on for that subnet, since Kea then refuses the reservation |
| Same identifier / address reserved twice in one subnet | Two host-database rows collide on (subnet, MAC or client-id) or (subnet, address) — only one is actually in effect |
| Class is never attached anywhere | A defined client class that no subnet, pool, shared network, or other class's `member()` ever references |
| `member()` references an undefined class | A class's test names another class that doesn't exist — that clause never evaluates true |
| Class test can never be true | An `and`-chain that pins the same field to two different literal values at once — only proven for the flat-AND grammar the Explain page's parser understands |
| Pool guard contradicts its subnet's guard | A pool requires class C while its subnet requires a class whose test is the exact negation of C's — the pool can never be reached |
| Subnet has nothing to hand out | No pools and no reservations — every request in it gets no offer |
| Lease timers out of order / very short / very long | `renew-timer` / `rebind-timer` / `valid-lifetime` should strictly increase; under a minute is usually a units typo; over 30 days is just flagged for awareness |
| Global option is never actually used | Every subnet overrides a globally-set option, so the global value never wins for any client |
| Shared network members disagree on lease time / gateway | Subnets in the same shared network usually should behave alike |
| HA peers disagree on configuration | The two servers' `high-availability` blocks differ in mode, timers, or peer roles beyond `this-server-name` — checked only when HA is configured, and only when both peers answer |
| Config key removed or renamed in a newer Kea | The same removed-key scan the Health Center's readiness group runs, folded in here as findings with a fix link |

Findings link straight to where you'd fix them: a subnet or pool
finding to the Subnets page, a class finding to Client Classes (which
also offers "Explain a client against this class" — the Explain page
re-evaluates every class for whatever client attributes you give it),
a reservation finding to Reservations filtered by the address in
question. **Re-run** just reloads the page — every check reads the
config fresh each time, nothing is cached.

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
- **Take over for partner / Cancel Handover** (superadmin) —
  `ha-maintenance-start` / `ha-maintenance-cancel`. **Read the
  direction carefully — it is the opposite of what v5.21.0–v5.32.0
  said.** Kea's `ha-maintenance-start` is sent to the server that will
  *keep serving*: that server tells its partner to enter
  `in-maintenance` and takes over every scope itself
  (`partner-in-maintenance`). So to take node B down for an OS update,
  click **Take over for B** on node **A**. Wait for B's state to show
  `in-maintenance`, then shut B down; A moves to `partner-down`, and
  when B comes back Kea re-synchronises and both return to normal on
  their own — no further clicks. **Cancel Handover** returns both
  servers to their previous states and only works while A is still
  `partner-in-maintenance` (before B is actually down). Prefer this over
  stopping the Kea service directly — it's a clean, HA-aware handover
  instead of the partner discovering a dead peer.
- **Reset** (superadmin) — `ha-reset`: re-runs the HA state machine from
  scratch. This is the last resort Kea's own HA documentation describes
  for a state that isn't otherwise recovering — don't reach for it
  first.

#### Planned maintenance, step by step (v5.38.0)

**Servers → Planned maintenance** (superadmin, with a password
confirmation) wraps the two maintenance commands above in a guided
page so the direction can't be got wrong. No new Kea command is used.

1. **Pick the server to take down** (A). Jen reads both servers' HA
   configs and finds A's partner B — the Jen server whose
   `this-server-name` is the one other peer A's config lists. If B is
   not a server under Settings → Kea, the page stops: Jen only knows one
   side of the pair; add the partner first.
2. **Preflight.** The relevant Health checks run and are shown: both
   servers reachable, HA state healthy, clocks in sync, subnet map not
   drifted, lease snapshots current. A `fail` blocks the handover; a
   `warn` is shown and lets you decide.
3. **Start handover.** Jen sends `ha-maintenance-start` to **B** — the
   server that keeps serving — and polls both every 5 seconds until B
   reports `partner-in-maintenance` and A reports `in-maintenance`. If
   that hasn't happened after 60 seconds the page says which side did
   not move and offers Cancel while B is still `partner-in-maintenance`.
4. **Do your work.** A is out of service; B answers everything. Stop
   Kea on A, patch, reboot. **Cancel** (`ha-maintenance-cancel` to B)
   is offered only while B is still `partner-in-maintenance`; once A is
   actually down, B moves to `partner-down` and cancel no longer applies
   — the page says so. Nothing advances on its own here.
5. **Bring A back.** Click Back once A is up. Jen polls until A answers
   and both report `hot-standby` / `load-balancing` again; Kea
   negotiates and syncs leases by itself (with a shared lease database
   — `send-lease-updates` / `sync-leases` false — there is nothing to
   sync, and the page says that instead).
6. **Repeat for B** with one click, if both nodes need the same work
   (an OS or Kea upgrade — see "Upgrading Kea" under Health Center).

The flow's state lives in your session, not the database; every
transition is recorded in the audit log as `ha_maintenance_<step>`
against both server names. `GET /servers/ha/<id>/status.json` (admin)
returns a server's normalised HA status for scripting.

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

The **DDNS** page (Network → DDNS) has five tabs: **Status**, **Naming**, **D2 Configuration**, **Verify**, and **Reconcile**. It covers two independent mechanisms for keeping DNS in sync with DHCP leases, and Jen treats neither as more "correct" than the other:

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

### Reconcile (v5.47.0)

Verify checks one name at a time; **Reconcile** (Network → DDNS → Reconcile) runs the same forward/reverse check over the whole fleet at once — every reservation, then every active lease with a hostname, up to the limit you set (max 1000; each one is a live lookup, and the whole run is bounded — at most 8 lookups run at once and the whole run is capped at 10 seconds; a lookup that has not answered by then is abandoned and shown as `lookup-failed`, so one hung resolver can't hold the page). Runs are single-flight: a second click while one is running gets "a reconciliation is already running" instead of starting more work — you wait, Jen does not. Nothing is written anywhere, to Jen's database or to Kea — this is a read-only report, subnet-restricted the same way every other subnet-scoped page in Jen is.

Each row gets one verdict:

| Verdict | Meaning |
|---|---|
| `ok` | Forward and reverse both resolve to what's expected. |
| `missing-forward` | The resolver definitively said the name doesn't exist (NXDOMAIN / no data). |
| `lookup-failed` | The resolver could not answer — a timeout, SERVFAIL or an unreachable server (v5.49.0-beta.2). This says nothing about whether the record exists; fix the resolver, then run Reconcile again. |
| `wrong-forward` | The name resolves, but not to the IP Jen expects. |
| `missing-ptr` | The resolver definitively said the IP has no PTR record. |
| `wrong-ptr` | The PTR record points to a different name than expected. |
| `stale-ptr` | The PTR record points to a name that belongs to a lease that has since expired elsewhere — DNS wasn't cleaned up when that name's lease ended. |
| `multiple-a` | More than one A record exists for the name. Several A records are a legitimate design, so this is informational — review it, don't assume it's wrong. (Named `duplicate-a` before v5.49.0-beta.2.) |

Filter to one verdict with the badges above the table, or **Export CSV** for the current filter. A mismatched row has **Fix in Kea** (jumps to Reservations, searched by that row's IP) and **re-verify** (jumps to the Verify tab, pre-filled) links; an `ok` row has neither, there's nothing to do.

The Health Center's **DNS/DHCP names match** check (group DDNS) reads the summary from the last time someone ran this page — it never resolves anything itself, so it stays instant like every other Health check. It shows `skip` until DDNS is on and at least one Reconcile run has happened.

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

**If Kea applies the config but doesn't restart cleanly,** the page
gives you a button to add the queued reservations once you've fixed
whatever kept the service from restarting — you have **30 minutes**
from that moment to do it, checked against the primary's live config
each time so reservations are never added against a config that
changed again in the meantime. **Re-importing the export is not a way
to recover a missed window:** the importer skips any scope whose CIDR
already exists in Kea before it ever reaches that scope's
reservations, so a second import adds none of them back. Add the
missed reservations by hand (Subnets → the subnet → Reservations) if
you miss the window.

**Validated against a real `Export-DhcpServer` file** (two scopes, 57
reservations, per-reservation options). Exclusions, superscopes,
policies and options 121/249 are still only exercised by a
hand-authored fixture — read the preview diff before you apply.

---

## Migrating from ISC DHCP (dhcpd.conf) (v5.37.0)

**Subnets → Import from ISC DHCP** (superadmin only) reads an ISC
`dhcpd.conf` and runs it through the same review → preview → apply
wizard as the Windows importer above. Copy `/etc/dhcp/dhcpd.conf` off
the old server and upload it; if it uses `include`, paste the included
files into it first — includes are not followed. You can add
`/var/lib/dhcp/dhcpd.leases` too: it is read only so the review page
can say how many active leases sit in the ranges you are importing.

**What maps:**

- Global `option` statements → Kea global `option-data` (on by default
  on the review page, because a dhcpd.conf's global options are
  inherited by every subnet exactly as Kea's are). `default-lease-time`
  → `valid-lifetime`, inherited down from global and `shared-network`
  the way dhcpd inherits it; dhcpd's own default (12 hours) applies when
  none is set.
- `subnet A netmask M { … }` → a `subnet4`. Every `range` becomes a pool
  (adjacent ranges are merged); `range dynamic-bootp` is treated as a
  plain range. A subnet with no range is imported without pools
  (reservations only). The comment on the line above a `subnet` is used
  as its name — `# Office LAN` — so name your subnets there.
- `shared-network N { … }` → a Kea shared network of the same name.
- `host H { hardware ethernet …; fixed-address …; }` → a reservation
  (`option host-name` names it, else the host declaration name). Hosts
  declared outside a subnet are placed by their address; options set
  directly on a host, or in an enclosing `group { }`, travel with the
  reservation.
- `class "C" { match if …; }` → a client class, for the forms Jen's
  class builder can express: `option vendor-class-identifier = "X"`,
  `substring(option vendor-class-identifier, 0, n) = "X"` (a prefix),
  the same on `user-class` and `host-name`, `hardware = 1:MAC`,
  `substring(hardware, 1, 6)` (MAC) and `substring(hardware, 1, 3)`
  (OUI), `option dhcp-client-identifier`, `option agent.circuit-id` /
  `agent.remote-id`, joined by `and` or `or` (one kind per class) and
  optionally wrapped in `not (…)`. Options and `filename` inside the
  class become its option-data.
- A pool's `allow members of "C"` guards that pool with C. `deny members
  of "C"` guards it with a generated `not_C` class (`not member('C')`);
  several `allow` lines become an `A_or_B` class. Both need the referenced
  classes to exist, so they are created even when you untick the class
  checkbox.
- `next-server` and `filename` on a subnet → Kea's own `next-server` /
  `boot-file-name` subnet fields.
- `option rfc3442-classless-static-routes` (and the `ms-` spelling) in
  dhcpd's decimal-byte form → option 121, decoded.

**What doesn't map** — every one is a warning with its source line
number on the review page, never a silent drop: option definitions
(`option foo code N = …`) and option spaces, `include`, `failover peer`
(set up Kea HA instead — see [Kea HA Configuration](#kea-ha-configuration)),
`if` / `elsif` / `else` blocks, `subclass` and `match` without `if`,
`spawn with`, regex (`~=`) matches, OMAPI, DDNS statements (`key`,
`zone`, `ddns-*` — configure dynamic DNS on the DDNS page), pool-level
options and lease times (Kea pools carry neither), `deny
unknown-clients` (guard the pool with Kea's built-in `KNOWN` class
afterwards), `max-lease-time` (Kea's `valid-lifetime` is fixed; set
`max-valid-lifetime` by hand if clients may ask for longer), hosts
identified by `dhcp-client-identifier` rather than a MAC, hosts whose
`fixed-address` is a hostname or in no declared subnet, `deny booting`
hosts, and per-host `filename`/`next-server`. Server tuning knobs with
no Kea equivalent (`log-facility`, `ping-check`, …) are collapsed into
one summary line. `dhcpd6.conf` is not imported (IPv4 only).

**Leases are never imported** — this is a config migration. Kea starts
with an empty lease database; clients keep the address dhcpd gave them
until their lease's renewal time, then ask Kea, which hands out a fresh
lease from the same pool (a reservation keeps its fixed address). The
only visible effect is that a client may change address once, at
renewal, if its old one is taken first. If you need to keep addresses
stable through the cutover, shorten `default-lease-time` on dhcpd a day
before switching so every client renews quickly afterwards.

Review, preview and apply behave exactly as for the Windows importer
above, including the primary-server-only rule and the 30-minute
reservation retry window after a failed restart.

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
a role assigned to them locally to still be correct. Subnet access is
similarly recomputed on every login when **Subnet Mapping** (below) is
configured; when it isn't, subnet access stays whatever it was set to
locally (by default, unrestricted).

### Subnet Mapping (v5.46.0)

By default, SSO logins are subnet-unrestricted — the same as before
this setting existed. To scope IdP groups to specific subnets, fill in
**Subnet Mapping** on the same Single Sign-On card:
`group:subnet-id[,subnet-id...]|*;...`, for example
`network-iot-admins:30,31;network-all:*`. The left side is a group/claim
value from the same claim **Role Claim** already reads; the right side
is either a comma-separated list of subnet IDs (see each subnet's
numeric ID on the Subnets page) or a bare `*` for every subnet. A field
below it previews what the current text would resolve to against your
actual subnets as you type — no round trip, and nothing is saved until
you click Save.

This is applied on every login, after role mapping: a user whose groups
match one or more mapped entries gets the union of those subnets (or
unrestricted access outright if any matching group is `*`). A user
whose groups match **nothing** in the mapping gets **no subnet access
at all** by default — set **When no group matches the Subnet Mapping**
to **Leave unrestricted** if you'd rather that case fall back to full
access instead of a deliberately locked-out account. Subnet Mapping
never affects a local account, only SSO logins, and leaving the field
blank (the default) disables the whole feature — no existing SSO
deployment's access narrows the moment this box is upgraded to a
version that has this field.

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

SAML and LDAP providers, SCIM provisioning, RP-initiated logout, and
API keys via OIDC are all out of scope for this release.


## Icons (v5.50.0)

The interface draws its icons from one inline SVG sprite of
[Lucide](https://lucide.dev) icons (ISC licence, `static/icons/LICENSE`).
They take their colour from the surrounding text, so they follow the
light and dark themes, and they need no extra request and no change to
the Content-Security-Policy.

- In a template call `{{ icon("pencil") }}`; add a class with
  `{{ icon("pencil", "ico-muted") }}` and a spoken label for an icon with no
  text beside it with `{{ icon("pencil", label="Edit") }}`. A name that is not
  in the sprite renders nothing, and `tests/test_icons.py` fails on any
  such name before it ships. `icon` is a Jinja global
  (`jen/services/icons.py`), so it also works inside HTMX partials.
- Inside a `{% block scripts %}` region write the inline form instead:
  `<svg class="ico" aria-hidden="true"><use href="#i-pencil"></use></svg>`.
- **To add an icon:** save the Lucide SVG as `static/icons/src/<name>.svg`,
  run `py tools/build_icon_sprite.py` to regenerate `templates/_icon_sprite.html`,
  and commit both. A test refuses a sprite that differs from its sources.
- `tools/replace_emoji_icons.py` with `tools/icon_map.json` is the one-off
  emoji-to-icon converter used for the initial swap.
- **No emoji in the UI.** `tests/test_icons.py` scans `templates/`,
  `jen/routes/` and `static/js/` for pictographic characters. The allowlist
  holds only content that is not chrome: device-type badges on the Devices
  page and the alert channels' test messages.
- Default alert messages open with one of four glyphs, each with one meaning
  (shown as a legend on Settings → Alerts): critical, warning, recovered,
  information. Templates an operator customised are never rewritten.
