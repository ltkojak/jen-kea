# Manual bare-metal install

`sudo ./install.sh` is the supported path and does everything below
interactively. This page is for the cases it doesn't cover — a distro
it doesn't recognize, an air-gapped or config-managed host, or just
wanting to know exactly what lands where.

Targets Ubuntu 22.04 / 24.04 + Python 3.10+ + Kea 3.0+ with a
MySQL/MariaDB backend. Adjust package names for other distros.

## 1. System packages

```bash
sudo apt install -y python3 python3-venv python3-pip \
    mariadb-client-core openssh-client openssl curl
```

`python3-venv` is required — Jen runs from its own virtualenv, not
system site-packages.

## 2. Layout (v5.14.0 — versioned release directories)

| Path | Owner | Purpose |
|---|---|---|
| `/opt/jen/releases/<X.Y.Z>/app/` | `root:root`, `a+rX` | one release's full tree (`jen/`, `run.py`, `templates/`, `static/`, `plugins/`, the shipped external files, `docs/`) — read-only to the service account |
| `/opt/jen/releases/<X.Y.Z>/venv/` | `root:root` | that release's virtualenv, built for its own `requirements.txt` |
| `/opt/jen/current` | symlink | relative symlink → `releases/<live>`; the unit runs `current/venv/bin/python current/app/run.py` |
| `/var/lib/jen/` | `www-data:www-data`, `0750` | user content: `icons/`, `branding/`, `backups/`, `plugins/`, `plugins-enabled/`, `keys/` — **never touched by upgrades** (v5.13.0) |
| `/etc/jen/` | `www-data:www-data` | `jen.config`, `ssl/`, `ssh/`, `backups/` — **never touched by upgrades** |
| `/etc/jen/jen.config` | `root:www-data`, `0640` | config + secrets |
| `/etc/systemd/system/jen.service` | root | the unit |
| `/etc/sudoers.d/jen` | root, `0440` | the two `systemctl` grants www-data needs (restart, self-update trigger) |
| `/usr/local/sbin/jen-update-root.py` | `root:root`, `0700` | in-app self-updater (runs as root, outside every dir www-data can write) |
| `/etc/systemd/system/jen-update.service` | root | oneshot that invokes the updater |

```bash
tar xzf jen-vX.Y.Z.tar.gz && cd jen
VER=$(grep -oP 'JEN_VERSION\s*=\s*"\K[0-9.]+' jen/__init__.py)
REL="/opt/jen/releases/$VER"

sudo mkdir -p "$REL/app" /etc/jen/ssl /etc/jen/ssh /etc/jen/backups \
    /var/lib/jen/{icons,branding,backups,plugins,plugins-enabled,keys}
sudo cp -r . "$REL/app/"
sudo rm -rf "$REL/app/.git" "$REL/app/tests"
```

## 3. Virtualenv (per release)

```bash
sudo python3 -m venv "$REL/venv"
sudo "$REL/venv/bin/pip" install --upgrade pip
sudo "$REL/venv/bin/pip" install -r "$REL/app/requirements.txt"
sudo "$REL/venv/bin/python" -m compileall -q "$REL/venv/lib" "$REL/app/jen" "$REL/app/plugins"
# leave the whole release dir root-owned
sudo chown -R root:root "$REL" && sudo chmod -R a+rX "$REL"
```

`jen.service` runs the release's venv interpreter directly. `run.py`
still carries a re-exec shim as a safety net (it prefers
`current/venv`, then the flat `/opt/jen/venv`), so a Docker image or a
still-flat box also works.

## 4. Config

```bash
sudo cp jen.config.example /etc/jen/jen.config
sudo nano /etc/jen/jen.config      # Kea API, kea_db, jen_db, ssh, subnets, ports
sudo chown root:www-data /etc/jen/jen.config && sudo chmod 640 /etc/jen/jen.config
```

Create the Jen database (Jen runs its own migrations on first start):

```sql
CREATE DATABASE jen;
CREATE USER 'jen'@'%' IDENTIFIED BY 'a-strong-password';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'%';
FLUSH PRIVILEGES;
```

The Kea database and Control Agent are configured on the Kea side — see
the main install guide.

## 5. Service, sudoers, updater

```bash
# The shipped external files live inside the release now.
sudo cp "$REL/app/jen.service"        /etc/systemd/system/jen.service
sudo cp "$REL/app/jen-sudoers"        /etc/sudoers.d/jen
sudo chmod 440                        /etc/sudoers.d/jen
sudo visudo -cf /etc/sudoers.d/jen    # sanity-check before it takes effect
sudo cp "$REL/app/jen-update-root.py" /usr/local/sbin/jen-update-root.py
sudo chown root:root                  /usr/local/sbin/jen-update-root.py
sudo chmod 700                        /usr/local/sbin/jen-update-root.py
sudo cp "$REL/app/jen-update.service" /etc/systemd/system/jen-update.service

# Activate this release (relative symlink, replaced atomically).
sudo ln -sfn "releases/$VER" /opt/jen/current.tmp
sudo mv -T /opt/jen/current.tmp /opt/jen/current

sudo chown -R root:root /opt/jen && sudo chmod -R a+rX /opt/jen
sudo chown -R www-data:www-data /etc/jen /var/lib/jen
sudo chmod 750 /var/lib/jen
```

### On each Kea host (v5.11.0+)

```bash
# copy /opt/jen/current/app/jen-kea-helper from the Jen host first, then:
sudo install -o root -g root -m 0755 ./jen-kea-helper /usr/local/sbin/jen-kea-helper
echo 'youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper' | sudo tee /etc/sudoers.d/jen-kea-helper
sudo chmod 440 /etc/sudoers.d/jen-kea-helper
sudo visudo -c -f /etc/sudoers.d/jen-kea-helper
```

Or click **Install helper** in Settings → Kea → SSH (needs the legacy
`/etc/sudoers.d/jen` grant present once). See the Admin Guide → Kea host
helper for the legacy fallback grant.

## 6. Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now jen
sudo systemctl status jen
journalctl -u jen -f
```

## 7. First login

`http://YOUR-SERVER:5050`, user `admin`. If you didn't pre-seed a
password (`JEN_INITIAL_ADMIN_PASSWORD` in the environment at first DB
seed), Jen generates one at first boot, prints it to the log, and writes
it to `/var/lib/jen/initial-admin-password` (mode 0600) —
`sudo cat /var/lib/jen/initial-admin-password`. Jen forces a change on
first login and deletes the file once you complete it.

## Upgrading manually

Repeat steps 2, 3, and 5 with the new tarball — a **new**
`releases/<X.Y.Z>/` directory — then activate it with the `ln -sfn` /
`mv -T` pair from step 5 and `sudo systemctl daemon-reload && sudo
systemctl restart jen`. The old release directory stays on disk as a
hand-rollback target (`sudo ln -sfn releases/<old> /opt/jen/current &&
sudo systemctl restart jen`). Or use the in-app update button, which
runs the staged, rollback-capable updater at
`/usr/local/sbin/jen-update-root.py`: it builds the whole release under
a staging directory (its own venv included) and the install is one
atomic symlink flip, so a rollback is a true point-in-time revert. See
`docs/ARCHITECTURE.md` §6.

The **first** upgrade to 5.14.0 has to be done with `sudo ./install.sh`
(or the manual steps above), not the in-app button — the box has no
`current` symlink yet, so the new unit can't start and the in-app
attempt rolls back cleanly to the previous version.

## Rolling back by hand

```bash
ls /opt/jen/releases                 # what's on disk
sudo ln -sfn releases/<X.Y.Z> /opt/jen/current
sudo systemctl restart jen
```
