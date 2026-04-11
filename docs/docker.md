# Jen Docker Guide

---

## Overview

Jen supports two Docker deployment modes:

| Mode | Jen DB | Kea DB |
|---|---|---|
| **External MySQL** (`docker-compose.yml`) | Your existing MySQL server | Your existing MySQL server |
| **Bundled MySQL** (`docker-compose.mysql.yml`) | MariaDB container managed by Docker | Your existing MySQL server |

The Kea database **always** connects to your external Kea server — Docker does not manage that.

---

## Prerequisites

- Docker installed: `curl -fsSL https://get.docker.com | sudo sh`
- Docker Compose plugin: `sudo apt install docker-compose-plugin`
- Kea server MySQL accessible from your Docker host
- Jen database created on your MySQL server (or use bundled MySQL mode)

---

## Mode 1 — External MySQL

Use this when you already have a MySQL server running and want Jen to connect to it for its own database (same server as Kea DB is fine, just a different database).

### Setup

```bash
cd jen
cp jen.config.example jen.config
nano jen.config
```

Fill in all sections. The `[jen_db]` section should point to your external MySQL server.

```bash
docker compose up -d
```

### Verify

```bash
docker ps
docker logs jen
```

---

## Mode 2 — Bundled MySQL

Use this when you don't have an external MySQL server available for the Jen database, or you want Jen's data fully self-contained in Docker.

### Setup

```bash
cd jen
cp jen.config.example jen.config
nano jen.config
```

In `jen.config`, set the `[jen_db]` host to `jen-mysql`:

```ini
[jen_db]
host     = jen-mysql
user     = jen
password = your-jen-db-password
database = jen
```

Set the MySQL passwords:

```bash
cp .env.example .env
nano .env
```

```ini
MYSQL_ROOT_PASSWORD=your-root-password
JEN_MYSQL_PASSWORD=your-jen-db-password
```

The `JEN_MYSQL_PASSWORD` here must match the password in `jen.config [jen_db]`.

Start:

```bash
docker compose -f docker-compose.mysql.yml up -d
```

Jen waits for the MariaDB container to be healthy before starting.

---

## Persistent Data

Both compose files use Docker volumes for persistent storage:

| Volume | Contents |
|---|---|
| `jen-config` | `/etc/jen` — SSL certs, SSH keys, backups |
| `jen-mysql-data` | MariaDB data (bundled MySQL mode only) |

Your `jen.config` is mounted read-only from the current directory into the container. Edit it on the host and restart the container to apply changes.

---

## Port Configuration

By default Jen listens on 5050 (HTTP) and 8443 (HTTPS). Override in `.env`:

```ini
HTTP_PORT=5050
HTTPS_PORT=8443
```

---

## Common Docker Commands

```bash
# View logs
docker compose logs -f jen

# Restart Jen
docker compose restart jen

# Stop everything
docker compose down

# Stop and remove volumes (WARNING: deletes all data)
docker compose down -v

# Rebuild after code changes
docker compose build
docker compose up -d
```

---

## HTTPS in Docker

Upload your SSL certificate through the Jen Settings UI — it's stored in the `jen-config` volume at `/etc/jen/ssl/`. No special Docker configuration needed.

---

## SSH Keys for Subnet Editing

SSH keys are stored in the `jen-config` volume at `/etc/jen/ssh/`. Generate them through the Jen Settings UI. The public key needs to be added to your Kea server's `authorized_keys` as with a bare metal install.

---

## Updating

```bash
cd jen
docker compose pull   # if using a registry
docker compose build  # if building locally
docker compose up -d
```

Your data in volumes is preserved across updates.
