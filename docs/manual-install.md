# Manual bare-metal install

`sudo ./install.sh` is the supported path and does everything below
interactively, or scripted end to end with `--answers <file>` (see
[`installation.md`](installation.md)'s "Scripted / unattended install"
— the same `JEN_*` names `.env.example` uses for Docker). This page is
for the cases neither covers — a distro `install.sh` doesn't recognize,
an air-gapped host, or just wanting to know exactly what lands where.

Targets Ubuntu 22.04 / 24.04 + Python 3.10+ + Kea 3.0+ with a
MySQL/MariaDB backend. Adjust package names for other distros.

> **These commands are tested.** CI's `manual-install` job extracts every
> block on this page marked as runnable (`tools/doc_commands.py`) and runs
> them, in order, on a clean Ubuntu runner — then checks that Jen came up at
> this release's version. The blocks that cannot run there (editing the
> config, the SQL, the Kea-host steps, the ones that follow a log) are the
> ones that are not marked, and a short stand-in does what the text says to do
> by hand. A command on this page that stops working fails that job.

<!-- ci:hook enter-tree -->

## 1. System packages

<!-- ci:run -->
```bash
sudo apt install -y python3 python3-venv python3-pip openssh-client openssl curl
command -v mysql >/dev/null || sudo apt install -y mariadb-client-core
```

`python3-venv` is required — Jen runs from its own virtualenv, not
system site-packages. `mariadb-client-core` supplies the `mysql` client;
the second line installs it only when one is not already there (it
conflicts with Oracle's `mysql-client-core`).

## 2. Layout (v5.14.0 — versioned release directories)

| Path | Owner | Purpose |
|---|---|---|
| `/opt/jen/releases/<version>/app/` | `root:root`, `a+rX` | one release's full tree (`jen/`, `run.py`, `templates/`, `static/`, `plugins/`, the shipped external files, `docs/`) — read-only to the service account |
| `/opt/jen/releases/<version>/venv/` | `root:root` | that release's virtualenv, built for its own `requirements.txt` |
| `/opt/jen/current` | symlink | relative symlink → `releases/<live>`; the unit runs `current/venv/bin/python current/app/run.py` |
| `/var/lib/jen/` | `www-data:www-data`, `0750` | user content: `icons/`, `branding/`, `backups/`, `plugins/`, `plugins-enabled/`, `keys/` — **never touched by upgrades** (v5.13.0) |
| `/etc/jen/` | `www-data:www-data` | `jen.config`, `ssl/`, `ssh/`, `backups/` — **never touched by upgrades** |
| `/etc/jen/jen.config` | `www-data:www-data`, `0600` | config + secrets |
| `/etc/systemd/system/jen.service` | root | the unit, **rendered** from `jen.service.template` (step 5) |
| `/etc/sudoers.d/jen` | root, `0440` | the three `systemctl` grants `www-data` needs (restart, self-update trigger, plugin-install trigger) |
| `/usr/local/sbin/jen-update-root.py` | `root:root`, `0700` | in-app self-updater (runs as root, outside every dir `www-data` can write) |
| `/etc/systemd/system/jen-update.service`, `jen-plugin-install.service` | root | the two oneshot units that invoke the updater |

The version is read from the tree itself, **whole** — a beta is
`5.67.0-beta.10`, not `5.67.0`. The in-app updater treats
`releases/<version>` as the live release's name and removes the ones it no
longer needs, so a directory named for a truncated version would be removed
out from under the running service.

```bash
tar xzf jen-vX.Y.Z.tar.gz && cd jen      # substitute the release you downloaded
```

<!-- ci:run -->
```bash
VER=$(grep -oP 'JEN_VERSION\s*=\s*"\K[^"]+' jen/__init__.py)
REL="/opt/jen/releases/$VER"

sudo mkdir -p "$REL/app" /etc/jen/ssl /etc/jen/ssh /etc/jen/backups \
    /var/lib/jen/{icons,branding,backups,plugins,plugins-enabled,keys}
sudo cp -r . "$REL/app/"
sudo rm -rf "$REL/app/.git" "$REL/app/tests"
```

Keep `VER` and `REL` set in this shell for the steps below — they are the
only variables this page uses.

## 3. Virtualenv (per release)

<!-- ci:run -->
```bash
sudo python3 -m venv "$REL/venv"
sudo "$REL/venv/bin/pip" install --upgrade pip
sudo "$REL/venv/bin/pip" install -r "$REL/app/requirements.txt"
sudo "$REL/venv/bin/python" -m compileall -q "$REL/venv/lib" "$REL/app/jen" "$REL/app/plugins"
# leave the whole release dir root-owned
sudo chown -R root:root "$REL" && sudo chmod -R a+rX,go-w "$REL"
```

`jen.service` runs the release's venv interpreter directly. `run.py`
still carries a re-exec shim as a safety net (it prefers
`current/venv`, then the flat `/opt/jen/venv`), so a Docker image or a
still-flat box also works.

## 4. Config

<!-- ci:run -->
```bash
sudo cp "$REL/app/jen.config.example" /etc/jen/jen.config
```

Edit it — Kea API, `kea_db`, `jen_db`, SSH, subnets, ports. Every section has
to be *present* (Jen refuses to start without `[kea]`), but only the `[jen_db]`
values have to be real: leave the Kea values blank and the `/setup` wizard
fills them in once Jen is running.

<!-- ci:hook edit-config -->
```bash
sudo nano /etc/jen/jen.config
```

<!-- ci:run -->
```bash
sudo chown www-data:www-data /etc/jen/jen.config && sudo chmod 600 /etc/jen/jen.config
```

Create the Jen database (Jen runs its own migrations on first start):

<!-- ci:hook create-db -->
```sql
CREATE DATABASE jen;
CREATE USER 'jen'@'%' IDENTIFIED BY 'a-strong-password';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'%';
FLUSH PRIVILEGES;
```

The Kea database and Control Agent are configured on the Kea side — see
the main install guide.

## 5. Service, sudoers, updater

The unit is **rendered**, not copied: `jen.service.template` carries
`@@APP_DIR@@`, `@@CONFIG_DIR@@` and `@@DATA_DIR@@` placeholders, and
`jen-update-root.py --render-unit` is the one renderer — the same function
the in-app updater runs on every update, so a hand-installed unit and a
managed one come out identical. With no flags it uses this box's layout
(`/etc/jen-layout.conf` if present, otherwise `/opt/jen`, `/etc/jen` and
`/var/lib/jen`); `--app-dir`, `--config-dir` and `--data-dir` override. It
refuses a path outside the layout grammar and an unresolved placeholder.

<!-- ci:run -->
```bash
# The updater first — it is also what renders the unit.
sudo cp "$REL/app/jen-update-root.py" /usr/local/sbin/jen-update-root.py
sudo chown root:root                  /usr/local/sbin/jen-update-root.py
sudo chmod 700                        /usr/local/sbin/jen-update-root.py
sudo /usr/bin/python3 /usr/local/sbin/jen-update-root.py --render-unit \
    "$REL/app/jen.service.template" /etc/systemd/system/jen.service

sudo cp "$REL/app/jen-sudoers"        /etc/sudoers.d/jen
sudo chmod 440                        /etc/sudoers.d/jen
sudo visudo -cf /etc/sudoers.d/jen    # sanity-check before it takes effect
sudo cp "$REL/app/jen-update.service"         /etc/systemd/system/jen-update.service
sudo cp "$REL/app/jen-plugin-install.service" /etc/systemd/system/jen-plugin-install.service

# Activate this release (relative symlink, replaced atomically).
sudo ln -sfn "releases/$VER" /opt/jen/current.tmp
sudo mv -T /opt/jen/current.tmp /opt/jen/current

sudo chown -R root:root /opt/jen && sudo chmod -R a+rX,go-w /opt/jen
sudo chown -R www-data:www-data /etc/jen /var/lib/jen
sudo chmod 750 /var/lib/jen
```

The rendered unit already carries `Environment=JEN_SERVICE_MANAGER=systemd`,
the explicit signal Jen's own deployment check looks for first; there is
nothing to append to it.

Check the result the way the installer's own pre-flight does — it prints the
three directories it accepted:

<!-- ci:run -->
```bash
sudo /usr/bin/python3 /usr/local/sbin/jen-update-root.py --check-layout --for auto
```

### On each Kea host (v5.11.0+)

```bash
# copy /opt/jen/current/app/jen-kea-helper AND jen-kea-helper.sig from the Jen host first
# (v5.66.0-beta.2 ships both, side by side, in every tarball install) — then, in the
# directory holding both files, verify before installing (never skip this, even when you
# trust the copy: it's what catches a corrupted or partial transfer before it runs as root).
# This also self-tests the candidate (v5.66.0-beta.7, Q109) — 7/9 below are this release's own
# HELPER_VERSION/HELPER_BUILD, not placeholders:
printf '%s\n' 'release@jen ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXk5NbQwUy85pHCzLfOwPisL0JGLCOrHuRjRZSf25vD' > allowed_signers && ssh-keygen -Y verify -f allowed_signers -I release@jen -n jen-kea-helper -s jen-kea-helper.sig < jen-kea-helper && /usr/bin/python3 -I jen-kea-helper version </dev/null | /usr/bin/python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get("ok") is True and d.get("helper_version")==7 and d.get("helper_build")==12 else 1)' && sudo install -o root -g root -m 0755 jen-kea-helper /usr/local/sbin/jen-kea-helper
echo 'youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper' | sudo tee /etc/sudoers.d/jen-kea-helper
sudo chmod 440 /etc/sudoers.d/jen-kea-helper
sudo visudo -c -f /etc/sudoers.d/jen-kea-helper
```

Or click **Install helper** in Settings → Kea → SSH (needs the legacy
`/etc/sudoers.d/jen-kea` grant present once). See the Admin Guide → Kea
host helper for the legacy fallback grant.

## 6. Start

<!-- ci:run -->
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now jen
sudo systemctl status jen --no-pager
```

Follow the log with:

```bash
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
`releases/<version>/` directory — then activate it with the `ln -sfn` /
`mv -T` pair from step 5 and `sudo systemctl daemon-reload && sudo
systemctl restart jen`. Render the unit again with `--render-unit` from the
new release's template, and copy `jen-update-root.py` from it first: that
script, not the unit, is what the in-app updater trusts. The old release
directory stays on disk as a hand-rollback target. Or use the in-app update
button, which runs the staged, rollback-capable updater at
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
sudo ln -sfn releases/<version> /opt/jen/current
sudo systemctl restart jen
```
