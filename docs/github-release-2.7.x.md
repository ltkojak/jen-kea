# Jen v2.7.5 — Professional Installer

This release is a complete overhaul of the install and uninstall experience, plus several bug fixes discovered during testing against the 2.6.x modularized codebase.

**No features were changed. No configuration was changed. All URLs and APIs are identical.**

---

## Highlights

### BBS/ANSI Terminal Installer

`install.sh` has been rewritten from scratch with a retro terminal aesthetic — teal block banner, spinner animations, coloured status indicators, and a bordered summary box at the end.

### Flag System

| Flag | Behaviour |
|---|---|
| *(none)* | Auto-detect: wizard on fresh install, upgrade prompt on existing |
| `--upgrade` | Non-interactive upgrade, keep existing config |
| `--configure` | Re-run config wizard only, then restart |
| `--repair` | Reinstall files and restart, keep config untouched |
| `--unattended` | Fully silent — no prompts (for CI/CD) |
| `--docker` | Docker installation path |

### Fresh Install Wizard

Walks through complete configuration with live connection tests:

- **Kea API** — URL, credentials, live `version-get` test shown inline
- **Kea database** — host, credentials, live connection test
- **Jen database** — host, credentials, live connection test with `CREATE DATABASE` SQL shown on failure
- **Admin password** — set during install; no more default `admin/admin`
- **Subnet map** — add as many subnets as needed interactively
- **SSH access** — optional, enables subnet editing from the UI
- **DDNS** — Technitium, Pi-hole, AdGuard, SSH/Bind9
- **Ports** — HTTP and HTTPS

### Upgrade Mode

Detects the installed version from `jen/__init__.py` and shows the version transition clearly. Prompts before proceeding. `--upgrade` or `--unattended` skips the prompt.

### Post-Install Summary

Displays a bordered summary box after install showing the access URL, login credentials, config file path, log command, and next steps.

### Uninstaller Overhaul

`uninstall.sh` rewritten with matching red-themed ANSI aesthetic.

- Shows all installed components and current service status before asking anything
- Three-level removal:
  - **App only** *(default)* — removes `/opt/jen` and the systemd service; preserves config, SSL certs, SSH keys, and backups so reinstall is painless
  - **App + config** — also removes `jen.config`
  - **Full wipe** — removes everything; requires typing `DELETE` to confirm
- Detects installed version and current running state

---

## New Feature — Server Ports in UI (2.7.5)

Settings → Infrastructure now has a **Server Ports** card. No more manual `jen.config` editing to change ports.

- **HTTP only:** HTTP port editable, HTTPS field disabled with a link to configure SSL
- **HTTPS enabled:** both ports editable; HTTP port labelled "redirect only"
- Saving triggers an automatic Jen restart (port binding requires a restart)
- Validates 1024–65535 range and HTTP ≠ HTTPS

---

## Bug Fixes

### 2.7.4
- Login 500: `name 'User' is not defined` in `auth.py` — missing import from `jen.models.user`
- Login error: `Data too long for column 'password'` — werkzeug 3.x changed default hash method from `pbkdf2:sha256` (103 chars) to `scrypt` (162 chars), exceeding `VARCHAR(256)`. Column widened to `VARCHAR(512)` with an automatic startup migration for existing installs

### 2.7.3
- Upgrade version arrow `→` too thin to read — replaced with `==>` in bold cyan

### 2.7.2
- Installed version showed as `unknown` — `run.py` imports `JEN_VERSION` rather than defining it; installer now reads `jen/__init__.py` as the canonical version source
- Bash syntax error from blank line inserted inside a `case` statement — fixed all three "keep config" code paths

### 2.7.1
- Box borders misaligned — ANSI escape codes inflate raw string length, causing hand-padded spaces to land wrong. Replaced with `_box_line()` helper that strips ANSI, measures visible character width using Python (handles UTF-8 `•` and `—`), and pads to exactly 54 inner chars
- `prompt_yn` now loops on invalid input — only Y/y/yes, N/n/no, or Enter accepted
- Config mode choice now loops on invalid input — only 1, 2, 3, or Enter accepted

---

## Upgrading

```bash
cd ~
tar xzf jen-v2.7.5.tar.gz
cd jen
sudo ./install.sh
```

The installer auto-detects your existing installation and will prompt before upgrading. Your config, database, SSL certificates, and SSH keys are untouched.

---

## What's Next — 3.0

- SQLAlchemy models replacing raw PyMySQL
- Alembic migrations
- HTMX for partial page updates
- pytest suite for critical paths
- A codebase a second developer can meaningfully contribute to
