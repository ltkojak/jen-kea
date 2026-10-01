# Jen Installation Guide

---

## Requirements

### Bare Metal / Systemd

- Ubuntu 22.04 or 24.04
- Python 3.10 or newer
- Network access to your Kea server (ports 8000 for API, 3306 for MySQL)
- MySQL/MariaDB server accessible for the Jen database

### Docker

- Any Linux host with Docker and Docker Compose plugin installed
- Network access to your Kea server

---

## Pre-Installation: Kea Server Setup

Before installing Jen, prepare your Kea server.

### Enable Remote MySQL Access

Edit `/etc/mysql/mariadb.conf.d/50-server.cnf` on your Kea server:

```
bind-address = 0.0.0.0
```

Restart MariaDB:
```bash
sudo systemctl restart mariadb
```

### Create MySQL User for Jen (Kea Database Access)

```sql
CREATE USER 'kea'@'YOUR-JEN-SERVER-IP' IDENTIFIED BY 'your-password';
GRANT SELECT, INSERT, UPDATE, DELETE ON kea.* TO 'kea'@'YOUR-JEN-SERVER-IP';
FLUSH PRIVILEGES;
```

### Create the Jen Database

```sql
CREATE DATABASE jen;
CREATE USER 'jen'@'YOUR-JEN-SERVER-IP' IDENTIFIED BY 'your-password';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'YOUR-JEN-SERVER-IP';
FLUSH PRIVILEGES;
```

---

## Installation Methods

### Method 1 — Guided Installer (recommended)

```bash
tar xzf jen-vX.Y.Z.tar.gz   # substitute the release you downloaded
cd jen
sudo ./install.sh
```

The installer will:
1. Run pre-flight checks (OS, Python, disk space on the real targets, dependencies)
2. Ask: bare metal or Docker
3. Ask only for Jen's own database, the HTTP/HTTPS ports, and an admin
   password — testing Jen's database as you go and offering to create it
   itself when MariaDB is local and root can already connect
4. Install files, set permissions, enable service
5. Start Jen and verify it responds

From v5.67.0, Kea's API, database, subnets, SSH access, and DDNS are no
longer asked here at all — log in once installed and a six-step guided
**`/setup`** wizard connects Kea live, in the browser, with the same
testing and retry the old terminal prompts used to do (see "First Login"
in the README). An `--answers` file (below) can still supply any of those
keys directly, skipping the matching `/setup` step entirely.

### Method 1b — Scripted / unattended install

For a repeatable install (a base image, a provisioning script, this
project's own CI) skip the wizard entirely with an answers file:

```bash
cat > answers.env << 'EOF'
JEN_KEA_API_URL=http://kea.example.lan:8000
JEN_KEA_API_USER=kea-api
JEN_KEA_API_PASS=...
JEN_KEA_DB_HOST=kea.example.lan
JEN_KEA_DB_USER=kea
JEN_KEA_DB_PASS=...
JEN_DB_HOST=127.0.0.1
JEN_DB_USER=jen
JEN_DB_PASS=...
JEN_INITIAL_ADMIN_PASSWORD=...
JEN_SUBNETS=1=Production,10.10.10.0/24;30=IoT,10.10.30.0/24
EOF
chmod 600 answers.env
sudo ./install.sh --answers answers.env --unattended
```

Same `JEN_*` names `.env.example` and the Docker path already use — see
that file for the full list, including the optional SSH and DDNS
settings. The file is parsed as plain `KEY=value` lines, never sourced
as a shell script, and refused unless it's a regular file not writable
by group or other. Anything the file leaves out still prompts if a
terminal is attached; without one, a missing required value is a fatal
error naming it. `JEN_*` values also work as plain environment
variables with no file at all, taking the same priority order (file,
then environment, then a prompt or a default).

### Method 1c — Relocating app/config/data (v5.67.0)

By default Jen lives at the paths it always has: the app tree under
`/opt/jen`, config and secrets under `/etc/jen`, user-writable data
under `/var/lib/jen`. Any or all three can be relocated at **fresh
install time only**:

```bash
sudo ./install.sh \
    --app-dir /srv/jen/app \
    --config-dir /srv/jen/etc \
    --data-dir /srv/jen/data
```

The common case is `--data-dir` alone — pointing uploads, database
backups and registry-installed plugins at a separate volume (a second
disk, a mounted NFS/NAS share, a ZFS dataset with its own snapshot
policy) without moving the application itself. Each flag stands alone;
any left unset keeps its default. The same three values are also
`JEN_APP_DIR` / `JEN_CONFIG_DIR` / `JEN_DATA_DIR` in `--answers` or the
plain environment, following the same resolution order as every other
setting in Method 1b.

The chosen layout is recorded root-owned in `/etc/jen-layout.conf` (see
`docs/ARCHITECTURE.md` §3.1 and §6.1 for why that file lives outside
`/etc/jen` itself) and every later `--upgrade` / `--repair` /
`--configure` run reads it back automatically — you never repeat these
flags. Passing one of them again with a *different* value than what's
already recorded is refused outright: relocating an **existing** install
is a runbook (`docs/runbooks.md` §5), not a flag, since a partial move
would leave root-owned state in two places at once.

#### A dedicated directory, nothing shared (v5.67.0-beta.5)

Each of `--app-dir`/`--config-dir`/`--data-dir` must name a directory
that belongs to Jen alone, never a shared system location another
package writes to:

- **Not a shared FHS root**, exact match: `/etc`, `/var`, `/var/lib`,
  `/var/log`, `/var/cache`, `/usr`, `/usr/local`, `/usr/lib`,
  `/usr/share`, `/opt`, `/srv`, `/mnt`, `/media`, `/boot`, `/bin`,
  `/sbin`, `/lib`, `/lib64`, `/root`, `/snap` are all refused outright
  — a *child* of one (`/opt/jen`, the default) is fine. Also still
  refused: `/tmp`, `/run`, `/proc`, `/sys`, `/dev`, `/home`.
- **A conservative path grammar**: letters, digits, `.`, `_`, `-` per
  path segment, 200 characters max. This isn't pickiness — install.sh
  renders `jen.service` with `sed -e s#@@APP_DIR@@#$INSTALL_DIR#g` (a
  `#` or `&` in the path would rewrite the sed expression), `%` is a
  systemd specifier, and a space would split `ExecStart` into multiple
  arguments.
- **A fresh target must be absent, an empty directory, or already
  carry Jen's own marker.** A directory with real, unrelated content
  is never silently reused.

If any of this refuses a candidate you believe should work, the
message says exactly which rule and why — there's no way to override
it short of choosing a different path.

#### Every existing ancestor must be root-owned and not writable by anyone else

Once a candidate's own grammar/shared-root checks pass, `install.sh`
(and, on every later privileged run, the root self-updater) walks every
*existing* ancestor directory of each of the three paths and refuses if
any of them is not owned by root, or is writable by group or other.
This is not a warning — it's a hard stop, because a writable parent
lets a local user rename the root-owned child aside and plant a symlink
in its place for the next privileged run to follow.

The one-line fix, named in the refusal itself:

```bash
sudo chmod go-w <the ancestor directory it names>
```

Ubuntu's own `/opt` ships `755` (not writable by group or other), so a
default, unrelocated install never hits this. It's most likely to come
up relocating under a directory something else created with a
permissive umask — fix the one directory named and re-run.

### Method 2 — Docker (external MySQL)

```bash
cd jen
cp jen.config.example jen.config
nano jen.config    # fill in all values
docker compose up -d
```

### Method 3 — Docker (bundled MySQL)

```bash
cd jen
cp jen.config.example jen.config
# Edit jen.config — set [jen_db] host = jen-mysql
nano jen.config
cp .env.example .env
nano .env          # set MySQL passwords
docker compose -f docker-compose.mysql.yml up -d
```

### Method 4 — Manual bare metal

For a distro `install.sh` doesn't recognize, an air-gapped host, or
config management — the full step-by-step (packages, the `/opt/jen/venv`,
every path and owner, service + sudoers + updater) is in
[`manual-install.md`](manual-install.md).

---

## First Login

Open `http://YOUR-SERVER-IP:5050` in your browser. Username is `admin`;
the password is whichever one you set in the wizard (or gave as
`JEN_INITIAL_ADMIN_PASSWORD`). If you left it blank, Jen generated one
itself — it's printed once during install and saved to
`/var/lib/jen/initial-admin-password` (readable by root only), and
you'll be asked to change it on first login.

---

## Post-Installation Steps

1. **Change the admin password** — Users → Change My Password
2. **Upload an SSL certificate** — Settings → SSL Certificate (enables HTTPS on port 8443)
3. **Generate SSH key** — Settings → SSH Key Management (required for subnet editing)
4. **Configure Telegram** — Settings → Telegram Alerts (optional)
5. **Add additional users** — Users → Add User (optional)

---

## Upgrading

Run the installer from the new tarball:

```bash
tar xzf jen-vX.X.X.tar.gz
cd jen
sudo ./install.sh
```

Select bare metal, then **Keep existing config**. Your configuration, certificates, SSH keys, and user accounts are preserved.

---

## Uninstalling

```bash
sudo ./uninstall.sh
```

This removes the application files and service. Configuration files and data are preserved by default — you'll be asked separately if you want a full wipe.
