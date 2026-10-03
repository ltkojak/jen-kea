# Jen Docker Guide

---

## Overview

Jen supports two Docker deployment modes. **Both are configured through
`.env`** (`JEN_*` environment variables); `run.py` turns those into
`/etc/jen/jen.config` inside the container on first start.

| Mode | Jen's own DB | Kea DB |
|---|---|---|
| **External** (`docker-compose.yml`) | a MySQL/MariaDB server you already run | a server you already run |
| **Bundled** (`docker-compose.mysql.yml`) | a MariaDB container Docker manages | a server you already run |

The Kea database **always** connects to your external Kea server — Docker
never manages that. The whole **Kea** section is optional: leave it blank
and connect Kea afterward, live in the browser, from the `/setup` wizard
that greets a fresh superadmin's first login.

---

## Prerequisites

- Docker: `curl -fsSL https://get.docker.com | sudo sh`
- Docker Compose **v2.24 or newer**: `sudo apt install docker-compose-plugin`
  (earlier versions don't consistently handle quoted/interpolated `.env`
  values, so a password with a special character could reach the
  container mangled)
- Network reachability from the Docker host to the Kea Control Agent API
  and the Kea database
- For External mode: a database + user created for Jen's own data

---

## Guided install (recommended)

```bash
cd jen
sudo ./install.sh --docker
```

Pick External or Bundled; the installer runs the config wizard, writes
`.env` (with a generated MariaDB password for Bundled mode and the admin
password you choose), builds the image, and starts the stack.

---

## By hand

### Mode 1 — External database

```bash
cd jen
cp .env.example .env
```

Fill in:

- the **Kea** section (`JEN_KEA_API_*`, `JEN_KEA_DB_*`) — **optional**:
  leave every `JEN_KEA_*` line blank to connect Kea afterward, live in
  the browser, from the `/setup` wizard a fresh superadmin lands on
- **`JEN_DB_HOST` / `JEN_DB_USER` / `JEN_DB_PASS` / `JEN_DB_NAME`** — your
  server (this one is not optional — Jen can't boot without its own
  database)
- **`JEN_DATABASE_MODE`** — `external` here
- **`JEN_INITIAL_ADMIN_PASSWORD`** — the first-login `admin` password.
  Leave it blank and Jen generates one at first boot: find it with
  `docker compose logs jen | grep 'initial password'` (Jen still forces a
  change on first login).

> If a password or token contains `$`, a backtick, `#`, a space or a
> quote, **single-quote the value** — `JEN_DB_PASS='p$ss w0rd'` — so
> Compose reads it literally. The guided installer does this for you.
> (Needs Compose ≥ 2.24 — see Prerequisites.)

```bash
docker compose up -d
```

### Mode 2 — Bundled database

```bash
cd jen
cp .env.example .env
```

Fill in the **Kea** section (optional — same as Mode 1, leave every
`JEN_KEA_*` line blank to connect Kea afterward from `/setup`), plus:

- **`MYSQL_ROOT_PASSWORD`** and **`JEN_MYSQL_PASSWORD`** (any strong
  values; compose refuses to start if either is blank)
- **`JEN_INITIAL_ADMIN_PASSWORD`**
- **leave the `JEN_DB_*` lines blank** — `docker-compose.mysql.yml` wires
  the `jen` container to the `jen-mysql` container itself (`JEN_DB_HOST=jen-mysql`,
  `JEN_DB_PASS=${JEN_MYSQL_PASSWORD}`).

```bash
docker compose -f docker-compose.mysql.yml up -d
```

Jen waits for the MariaDB container to be healthy before starting.

### Verify

```bash
docker ps
docker logs jen
```

---

## Escape hatch: mount your own `jen.config`

If you'd rather not use env vars, uncomment the mount in the compose file
and provide a file (`jen.config.example` is the template):

```yaml
volumes:
  - ./jen.config:/etc/jen/jen.config:ro
```

`run.py` skips env-var generation when a valid `jen.config` is present.

---

## Persistent data

| Volume | Contents |
|---|---|
| `jen-config` | `/etc/jen` — SSL certs, SSH keys, secret key, `jen.config` snapshots |
| `jen-content` | `/var/lib/jen` — uploaded icons, favicon and nav logo, database backups, registry-installed plugins (v5.13.0) |
| `jen-icons` | `/opt/jen/static/icons/custom` — the pre-5.13 brand-icon location; on start the app copies anything left in it into `jen-content`, and the volume can be dropped once that has happened (below) |
| `jen-mysql-data` | MariaDB data (Bundled mode only) |

**Upgrading to 5.13.0:** user content moved out of the application tree
(`/opt/jen` is now root-owned and read-only to the service account) into
`/var/lib/jen`, backed by the new `jen-content` volume. On the first
start after the upgrade Jen copies anything still in the old `jen-icons`
volume into `jen-content` automatically. Once that start has succeeded
you can drop the `jen-icons` line from your compose file and
`docker volume rm jen-icons`. If a box had installed the `ipam` or
`network-discovery` plugin from the registry, both the bundled copy and
the migrated copy now exist — the `/var/lib/jen` copy wins.

**v5.27.0 root-owned plugin installs don't apply here.** On a real
systemd host, installing a registry plugin now asks a separate
root-privileged service to fetch and verify it into a directory the
Jen process can't write to — closing off a plugin install as a
persistence path for a compromised web process. A container has no
systemd unit to trigger that with, so Jen keeps installing plugins the
same way it always has in Docker: in-process, into `jen-content`. The
Plugins page never shows the "reinstall to harden" prompt here, since
there's nothing to harden into.

**Plugin programs are in the image (v5.65.10).** Network Discovery needs `nmap`, Host Watchdog `ping` and
Switch Port Locator `snmpbulkwalk`; the image installs `nmap`, `iputils-ping` and `snmp`, the three packages
the plugin installer allow-lists on a real host. The Plugins page's `apt install` hint does not apply inside a
container; rebuild the image instead. **Updates and restarts are the container's job:** the Update and Restart
buttons are hidden here, because they drive the `jen` systemd service that a container does not have.

**Podman is a container too (v5.67.0-beta.15).** Jen recognises a container by `/.dockerenv` (Docker) or `/run/.containerenv` (Podman), so under Podman it behaves exactly as above — and "Save & Restart", a port change and a certificate change really restart it: Jen stops its own process and the container's restart policy brings it back. Give the container one (`podman run --restart=unless-stopped …`, or a systemd unit or Quadlet that restarts it); without a restart policy the container stays stopped after the change.

`/etc/jen/jen.config` lives in the `jen-config` volume. To change
configuration, edit `.env` and re-run `docker compose ... up -d` — on the
next start `run.py` only regenerates the config if it's missing or has no
`api_url`, so **to force a rewrite, delete the file first**:
`docker compose exec jen rm /etc/jen/jen.config && docker compose restart jen`.

---

## Ports

Defaults: 5050 (HTTP), 8443 (HTTPS). Override in `.env`:

```ini
HTTP_PORT=5050        # host side
HTTPS_PORT=8443
JEN_HTTP_PORT=5050    # container side (rarely changed)
JEN_HTTPS_PORT=8443
```

---

## Common commands

```bash
docker compose logs -f jen
docker compose restart jen
docker compose down
docker compose down -v          # WARNING: deletes all data
docker compose build && docker compose up -d
```

(Add `-f docker-compose.mysql.yml` for the Bundled stack.)

---

## HTTPS

Upload your certificate through **Settings → Access & Security** — it's stored in the
`jen-config` volume at `/etc/jen/ssl/`. gunicorn picks it up on the next
restart. No Docker-specific configuration.

---

## SSH keys for subnet editing

Generated through **Settings → Kea → SSH**, stored in the
`jen-config` volume at `/etc/jen/ssh/`. Add the public key to the Kea
server's `authorized_keys`, same as a bare-metal install.

## Kea host helper updates (v5.66.0+)

A Docker image is built from source, so it never has a local
`jen-kea-helper.sig` the way a box updated through `jen-update-root.py`
does (that file is written only as part of the self-update pipeline).
A **signed** "Update helper" click still works — it fetches the
signature from this release's own GitHub asset instead, the same
fallback a hand-installed tarball or a dev checkout uses — it just
needs the Jen container to reach `github.com` when you press the
button. See the Admin Guide's "Kea host helper" for what each refusal
reason means.

---

## Updating

```bash
cd jen
docker compose build          # rebuild the image from the new source
docker compose up -d
```

Volume data is preserved. (There is no published image registry yet, so
`build` is the update step.)
