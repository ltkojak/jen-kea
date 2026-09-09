# Manual bare-metal install

`sudo ./install.sh` is the supported path and does everything below
interactively. This page is for the cases it doesn't cover — a distro
it doesn't recognise, an air-gapped or config-managed host, or just
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

## 2. Layout

| Path | Owner | Purpose |
|---|---|---|
| `/opt/jen/` | `www-data:www-data` | application code (`jen/`, `run.py`, `templates/`, `static/`, `requirements.txt`, `CHANGELOG.md`) |
| `/opt/jen/venv/` | `root:root` | Python dependencies (service reads/executes, never writes) |
| `/etc/jen/` | `www-data:www-data` | `jen.config`, `ssl/`, `ssh/`, `backups/` — **never touched by upgrades** |
| `/etc/jen/jen.config` | `root:www-data`, `0640` | config + secrets |
| `/etc/systemd/system/jen.service` | root | the unit |
| `/etc/sudoers.d/jen` | root, `0440` | the two `systemctl` grants www-data needs (restart, self-update trigger) |
| `/usr/local/sbin/jen-update-root.py` | `root:root`, `0700` | in-app self-updater (runs as root, outside every dir www-data can write) |
| `/etc/systemd/system/jen-update.service` | root | oneshot that invokes the updater |

```bash
tar xzf jen-vX.Y.Z.tar.gz && cd jen

sudo mkdir -p /opt/jen /etc/jen/ssl /etc/jen/ssh /etc/jen/backups \
    /opt/jen/static/icons/custom
sudo cp -r run.py jen templates static requirements.txt CHANGELOG.md /opt/jen/
```

## 3. Virtualenv

```bash
sudo python3 -m venv /opt/jen/venv
sudo /opt/jen/venv/bin/pip install --upgrade pip
sudo /opt/jen/venv/bin/pip install -r /opt/jen/requirements.txt
sudo /opt/jen/venv/bin/python -m compileall -q /opt/jen/venv/lib
# leave it root-owned
```

`run.py` re-execs into `/opt/jen/venv/bin/python` on start, so
`jen.service` calls the system `python3` and the venv is picked up
automatically. If the venv is ever broken (an OS Python upgrade), the
service falls back to the system interpreter — rebuild with the three
commands above.

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
sudo cp jen.service                 /etc/systemd/system/jen.service
sudo cp jen-sudoers                 /etc/sudoers.d/jen
sudo chmod 440                      /etc/sudoers.d/jen
sudo visudo -cf /etc/sudoers.d/jen  # sanity-check before it takes effect
sudo cp jen-update-root.py          /usr/local/sbin/jen-update-root.py
sudo chown root:root                /usr/local/sbin/jen-update-root.py
sudo chmod 700                      /usr/local/sbin/jen-update-root.py
sudo cp jen-update.service          /etc/systemd/system/jen-update.service

sudo chown -R www-data:www-data /opt/jen/jen /opt/jen/run.py /opt/jen/templates /opt/jen/static
sudo chown -R www-data:www-data /etc/jen
```

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
seed), it's `admin` / `admin` and Jen forces a change on first login.

## Upgrading manually

Repeat steps 2, 3, and 5 with the new tarball (config in `/etc/jen` is
untouched), then `sudo systemctl restart jen`. Or use the in-app update
button, which runs the staged, rollback-capable updater at
`/usr/local/sbin/jen-update-root.py` (it stages and validates the new
release before touching `/opt/jen` and restores a snapshot on any
failure — with the one caveat that the venv is shared, so a rollback
keeps the newer dependencies; see `docs/ARCHITECTURE.md` §6).
