# Jen Installation Guide

---

## Requirements

### Bare Metal / Systemd

- Ubuntu 22.04 or 24.04
- Python 3.10 or newer
- Network access to your Kea server (ports 8000 for API, 3306 for MySQL)
- A MySQL/MariaDB database for Jen's own data. If this machine has no database server, the installer can
  install MariaDB here and create the database for you — when you ask it to (below); you do not have to install
  one first

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
   password — testing Jen's database as you go. Jen cannot start without
   its own database, so there is no "continue without it": if it does not
   answer you can **retry**, **edit** the values, **install MariaDB on this
   machine** and create the database (offered only when the host is this
   machine), or **quit**; and when MariaDB is already local and root can
   connect, the installer offers to create the database itself
4. Install files, set permissions, enable service
5. Start Jen and verify it responds

Everything the installer runs — `apt-get`, `pip`, the virtualenv, `systemctl`,
`mysql` — writes its output to **`/var/log/jen-install.log`** (root-only,
appended per run) instead of scrolling past the progress line; if a step fails
the installer prints the last 20 lines and the path, and the summary names the
log. The log never contains the database password.

**A database server on a fresh machine (v5.67.0-beta.18).** Answer `y` to
"Install MariaDB on this machine and create the database now?" (or choose `i`
from the failure menu) and the installer runs `apt-get install mariadb-server`,
enables and starts the service, waits for it to answer, creates Jen's database
and user, and tests the connection. It is only ever offered for `localhost`,
`127.0.0.1` or `::1`, never installs anything unless you say so (the prompt
defaults to no), starts an already-installed server instead of reinstalling it,
and `uninstall.sh` never removes it — at any level, MariaDB and Jen's database in it are
yours from then on. Debian and Ubuntu only, like the installer.

From v5.67.0, Kea's API, database, subnets, SSH access, and DDNS are no
longer asked here at all — log in once installed and a six-step guided
**`/setup`** wizard connects Kea live, in the browser, with the same
testing and retry the old terminal prompts used to do (see "First Login"
in the README). An `--answers` file (below) can still supply any of those
keys directly. There is no per-step skipping: the wizard is a one-time
redirect that fires only while Jen has no Kea API URL and no named subnet,
so an answers file that supplies both means you are never sent to
`/setup` — it stays reachable from Getting started.

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
settings. **An unattended install whose Jen database does not answer stops** (it
prints the SQL to create it and the reason, and exits non-zero) rather than
installing a service that would restart every five seconds; to let the
installer install MariaDB on this machine and create the database, add
`JEN_DB_INSTALL_LOCAL=yes` (honoured only for a local `JEN_DB_HOST`). The file is parsed as plain `KEY=value` lines, never sourced
as a shell script, and refused unless it's a regular file not writable
by group or other. A value may have spaces around the `=`, may be
wrapped in one matching pair of quotes (stripped), and the line may
start with `export` — none of that becomes part of the value
(5.67.0-beta.9). Anything the file leaves out still prompts if a
terminal is attached; without one, a missing required value is a fatal
error naming it (the Jen database password is the one value with no
default; an empty `JEN_DB_PASS=` on its own line counts as given). `JEN_*`
values also work as plain environment variables with no file at all, taking
the same priority order (file, then environment, then a prompt or a
default).

If a `jen.config` already exists — a reinstall onto the config an
app-only `uninstall.sh` kept — the installer **keeps it**, and an answers
file does not rewrite it: it only feeds a *new* config. Run
`sudo ./install.sh --configure` to rewrite one on purpose (5.67.0-beta.9).

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
setting in Method 1b — the answers file is read *before* the layout is
resolved, so these three keys count there exactly as the flags do
(5.67.0-beta.8 and earlier ignored them in an answers file and installed
to the defaults).

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
  is never silently reused. An empty directory you created beforehand is
  fine — whether this is an install or an upgrade is decided by the
  layout checker from the recorded layout file, a marker, or Jen's own
  content, never by whether the directory merely exists
  (5.67.0-beta.9). A config or data directory a previous install left
  behind is recognised by its content (`jen.config`; `icons`, `branding`,
  `backups` or `keys`) and stamped once the new install completes.
- **Not under `/root`** — nothing under it can work, because the service
  runs with `ProtectHome=yes`.

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
cp .env.example .env
nano .env          # JEN_DB_HOST/USER/PASS for Jen's own database, JEN_INITIAL_ADMIN_PASSWORD
docker compose up -d
```

`docker-compose.yml` reads `.env` (it is required — `env_file: .env`) and
`run.py` turns the `JEN_*` values into `/etc/jen/jen.config` on the first
start; the Kea side is connected afterwards in the `/setup` wizard, the same
as a bare-metal install. `jen.config` is **not** mounted by default — to
bring a hand-written one instead, uncomment the `./jen.config` mount in the
compose file. `sudo ./install.sh --docker` writes `.env` for you.

### Method 3 — Docker (bundled MySQL)

```bash
cd jen
cp .env.example .env
nano .env          # MYSQL_ROOT_PASSWORD, JEN_MYSQL_PASSWORD, JEN_INITIAL_ADMIN_PASSWORD
docker compose -f docker-compose.mysql.yml up -d
```

The compose file wires Jen's database to the `jen-mysql` container itself
(`JEN_DB_HOST`, `JEN_DB_USER`, `JEN_DB_NAME` and `JEN_DB_PASS` come from its
`environment:` block), so `.env` carries only `JEN_MYSQL_PASSWORD`, which both
containers share, and `MYSQL_ROOT_PASSWORD`. Both containers carry
`restart: unless-stopped`, which is also what makes **Save & Restart** in
Settings work in Docker — Jen stops its own process and Docker starts it again.

### Method 4 — Manual bare metal

For a distro `install.sh` doesn't recognize, an air-gapped host, or
config management — the full step-by-step (packages, a per-release
virtualenv, every path and owner, service + sudoers + updater) is in
[`manual-install.md`](manual-install.md). Its commands are run, in order, by
this project's own CI on every push.

---

## First Login

Open `http://YOUR-SERVER-IP:5050` in your browser. Username is `admin`;
the password is whichever one you set in the wizard (or gave as
`JEN_INITIAL_ADMIN_PASSWORD`). If you left it blank, Jen generated one
itself — it's saved to `/var/lib/jen/initial-admin-password` (readable by
root only; `sudo cat` it — the path follows `--data-dir` if you relocated),
and you'll be asked to change it on first login.

---

## Post-Installation Steps

1. **Change the admin password** — your profile → Change Password
2. **Upload an SSL certificate** — Settings → Security → SSL Certificate (enables HTTPS on port 8443)
3. **Generate SSH key** — Settings → Kea → SSH Key Management (required for subnet editing)
4. **Add a Telegram channel** — Settings → Alerts (optional)
5. **Add additional users** — Users → Add User (optional)

---

## Upgrading

Run the installer from the new tarball:

```bash
tar xzf jen-vX.X.X.tar.gz
cd jen
sudo ./install.sh
```

Choose **Keep existing config** when asked (or run `sudo ./install.sh --upgrade` to skip every
question). Your configuration, certificates, SSH keys, and user accounts are preserved. Once a box is
running a release with the in-app updater, Settings → System → Updates does the same thing without the
tarball — see [`upgrading.md`](upgrading.md).

---

## Uninstalling

```bash
sudo ./uninstall.sh
```

This removes the application files and service. Configuration files and data are preserved by default — you'll be asked separately if you want a full wipe. A reinstall onto what level 1 kept (`sudo ./install.sh`) finds your config and keeps it.

The three levels: **1** removes the app and the service (keeps config, certificates, SSH keys, uploads and backups), **2** also removes `jen.config` (a dated copy is kept beside it), and **3** removes everything — the config and data directories, the layout record, and the root self-updater with its two oneshot units (`jen-update.service`, `jen-plugin-install.service`), which levels 1 and 2 leave in place. `uninstall.sh` asks the checker copy that ships beside it; run it from the extracted release tarball. An installed updater from an older release is only used when the script has no copy beside it *and* the installed one answers `--check-layout --help` (5.67.0-beta.9).
