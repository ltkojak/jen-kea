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
never manages that.

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

- the **Kea** section (`JEN_KEA_API_*`, `JEN_KEA_DB_*`)
- **`JEN_DB_HOST` / `JEN_DB_USER` / `JEN_DB_PASS` / `JEN_DB_NAME`** — your
  server
- **`JEN_DATABASE_MODE`** — `external` here
- **`JEN_INITIAL_ADMIN_PASSWORD`** — the first-login `admin` password
  (leave blank for legacy `admin`/`admin` + forced change)

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

Fill in the **Kea** section, plus:

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
| `jen-config` | `/etc/jen` — SSL certs, SSH keys, secret key, backups |
| `jen-icons` | `/opt/jen/static/icons/custom` — uploaded brand icons |
| `jen-mysql-data` | MariaDB data (Bundled mode only) |

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

Upload your certificate through **Settings → System** — it's stored in the
`jen-config` volume at `/etc/jen/ssl/`. gunicorn picks it up on the next
restart. No Docker-specific configuration.

---

## SSH keys for subnet editing

Generated through **Settings → Infrastructure**, stored in the
`jen-config` volume at `/etc/jen/ssh/`. Add the public key to the Kea
server's `authorized_keys`, same as a bare-metal install.

---

## Updating

```bash
cd jen
docker compose build          # rebuild the image from the new source
docker compose up -d
```

Volume data is preserved. (There is no published image registry yet, so
`build` is the update step.)
