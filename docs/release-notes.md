# Jen Release Notes

---

## Version 2.7.0 — April 2026

### Professional Installer Overhaul

Complete rewrite of `install.sh` and `uninstall.sh` with a BBS/ANSI terminal aesthetic.

**install.sh flags:** `--upgrade`, `--configure`, `--repair`, `--unattended`, `--docker`

Fresh install wizard covers: Kea API (with live connection test), Kea DB, Jen DB, admin password, subnets, SSH, DDNS (Technitium/Pi-hole/AdGuard/SSH), ports. Upgrade mode shows version transition and prompts before proceeding. Post-install summary in a bordered ANSI box.

**uninstall.sh:** Three-level removal — app only / app + config / full wipe. Full wipe requires typing `DELETE`. SSL certs, SSH keys, and backups preserved by default.

---

## Version 2.6.2 — April 2026

### Code Modularization — Phase 2 (Complete)

All 104 routes migrated from the `jen.py` monolith into 14 Flask Blueprint modules. The service entry point changes from `jen.py` to `run.py`.

**No changes to any feature, URL, API, or configuration.**

**Entry point change:** The systemd service now runs `python3 /opt/jen/run.py`. This is handled automatically by the installer — no manual changes needed.

**14 route blueprints created:**

| Blueprint | Routes |
|---|---|
| `api.py` | REST API v1 endpoints, API key management |
| `auth.py` | Login, logout |
| `dashboard.py` | Dashboard, stats, Prometheus metrics |
| `ddns.py` | DDNS status page |
| `devices.py` | Device inventory |
| `leases.py` | Leases, IP map |
| `mfa_routes.py` | MFA enrollment, verification, trusted devices |
| `reports.py` | Reports |
| `reservations.py` | Reservations, bulk operations |
| `search.py` | Global search, saved searches |
| `servers.py` | Kea server management |
| `settings.py` | All Settings pages |
| `subnets.py` | Subnet view and editing |
| `users.py` | User management, profile |

With this release, the `jen/` package is complete. `jen.py` is retained for reference but is no longer executed. All future development happens in the modular package.

---

## Version 2.6.1 — April 2026

### Fixed
- `install.sh` was not copying the `jen/` package directory or `run.py` to `/opt/jen/` — the modularization introduced in 2.6.0 would have been silently absent on all installs and upgrades
- Backup and rollback updated to include the `jen/` package
- Post-install verification now confirms all 9 package modules import correctly

---

## Version 2.6.0 — April 2026

### Code Modularization — Phase 1

This release introduces the `jen/` Python package alongside the existing `jen.py` monolith. All behaviour is identical — this is a structural refactor that sets up the foundation for route blueprint migration in 2.7.x and the full 3.0 rewrite.

**No changes to any feature, UI, API, or configuration.**

**New package layout:**

| Module | Contents |
|---|---|
| `jen/extensions.py` | Shared state: cfg, KEA_SERVERS, SUBNET_MAP, all globals |
| `jen/config.py` | Config loading, writing, subnet map parsing |
| `jen/models/db.py` | Database connections, schema init, migrations |
| `jen/models/user.py` | User model, password hashing, audit logging |
| `jen/services/kea.py` | Kea API, HA detection, active server routing |
| `jen/services/alerts.py` | Alert channels, templates, background monitor |
| `jen/services/fingerprint.py` | OUI database, device classification, icons |
| `jen/services/mfa.py` | TOTP, backup codes, trusted devices |
| `jen/services/auth.py` | Input validators, rate limiting |
| `run.py` | New entry point |

**For operators:** Nothing changes. Install and upgrade work exactly as before. The service still runs `python3 /opt/jen/jen.py`.

---

## Version 2.5.10 — April 2026

### Documentation
- `docs/user-guide.md` — added Mobile Access, ntfy/Discord alert channels, and Kea Servers/HA sections
- `docs/faq.md` — added Mobile, High Availability, and DDNS Providers FAQ sections
- `docs/troubleshooting.md` — added HA troubleshooting, Mobile troubleshooting, and Alert Channels sections

### Added
- Servers page shows a warning when multiple servers are configured but HA mode is not set, with a direct link to configure it

### Improved
- `install.sh` template validation upgraded from file count to full Jinja parse check — broken templates now cause installer to fail and roll back rather than silently installing a broken version

---

## Version 2.5.4 — April 2026

### Mobile Experience Overhaul

**Root cause of double-tap fixed.** iOS Safari adds a 300ms delay before firing click events unless the element explicitly opts out. The fix is `touch-action: manipulation` — now applied globally to every interactive element in the app. Single tap works everywhere.

**Three distinct layouts.** Jen now detects and adapts to three screen contexts:

- **Desktop (>1024px)** — unchanged full layout
- **iPad (769–1024px)** — full table layout with low-priority columns hidden (MAC addresses, timestamps), saving space without losing important data
- **iPhone (≤768px)** — hamburger nav, tables reflow into per-row cards, all buttons minimum 44px tap target

**Hamburger nav on iPhone.** The previous horizontally-scrolling nav bar of tiny links is replaced with a ☰ button that opens a full-width drawer showing all navigation destinations with large, easy-to-tap rows. Closes automatically on navigation or outside tap. Desktop nav is completely unchanged.

**Table card reflow.** On iPhone, the Leases, Reservations, and Devices tables reflow into individual cards. Each row becomes a card showing field labels (IP, Hostname, Subnet, Type, Actions) — no more horizontal scrolling to find the action buttons.

**iOS form zoom prevented.** All form inputs use 16px font size on mobile, which prevents iOS from auto-zooming the viewport when an input is focused.

**Safe area support.** `viewport-fit=cover` added for proper content insets on iPhone notch and Dynamic Island devices.

---

## Version 2.5.3 — April 2026

### Default Favicon
Jen now ships with a default favicon — a teal circle with a white "J", available in 16×16 through 256×256 resolution. Fresh installs no longer show a blank browser tab icon.

The favicon can still be replaced via **Settings → Appearance → Upload Favicon**. The default is tracked in the repository; user-uploaded replacements are gitignored as before.

---

## Version 2.5.2 — April 2026

### Security Fix — Password Hashing
Passwords were previously stored as plain SHA-256 hashes — no salt, fast to brute-force. They are now stored using werkzeug's `pbkdf2:sha256` with a random salt and 260,000 iterations.

**Migration is automatic and seamless.** Existing users do not need to change their passwords. On each successful login, Jen detects a legacy hash and silently upgrades it to the new format. No manual database changes are required.

### Bug Fixes
- Default DDNS log path hardcoded as `kea-ddns-technitium.log` — changed to `kea-ddns.log`
- Bare `except:` clauses in alert channel config parsing replaced with specific exception types

---

## Version 2.5.1 — April 2026

### Additional DNS Providers
The DDNS hostname lookup now supports four DNS providers:

- **Technitium DNS** — existing integration unchanged
- **Pi-hole** — supports both v5 (api.php) and v6 (new REST API with session authentication)
- **AdGuard Home** — REST API with Basic Auth, queries rewrite rules for hostname lookup
- **DNS via SSH** — runs `dig` over the existing Kea SSH connection; works with Bind9, Unbound, or any DNS server accessible from the Kea host. No additional configuration required.

Provider-specific fields show and hide dynamically when you change the DNS Provider dropdown in Settings → Infrastructure → DDNS Configuration.

### Bug Fixes
- Fixed hardcoded server name `theelders` in DDNS SSH timeout error message
- Fixed hardcoded username `matthew` as SSH fallback in subnet editing
- Added 10-second TTL cache to active server detection to avoid unnecessary `ha-heartbeat` calls on every page load

---

## Version 2.5.0 — April 2026

### ntfy and Discord Alert Channels
Two new alert channel types are now supported alongside the existing Telegram, Email, Slack, and Webhook channels.

**ntfy** — works with both the public ntfy.sh server and self-hosted ntfy instances. Configurable topic, access token for protected topics, and message priority (min/low/default/high/urgent).

**Discord** — standard Discord webhook integration. Messages are formatted with bold text preserved and delivered to the configured channel with "Jen DHCP" as the sender username.

Both channels support all existing alert types including the new HA failover alert.

### Kea HA Support
Jen now has full awareness of Kea High Availability deployments.

**Active node routing** — when multiple servers are configured, Jen automatically routes `config-get` and subnet editing commands to the active primary node. Active node detection uses `ha-heartbeat` to identify the server in `hot-standby`, `load-balancing`, or `partner-down` state with primary role. Falls back to the first reachable server.

**HA state monitoring** — the background alert loop now tracks HA state for all configured servers. Any state change (including failovers, recovery, and sync events) fires an `ha_failover` alert to all configured channels.

**Servers page improvements** — the Servers page now shows an ⚡ ACTIVE indicator on the current active node, a top banner displaying the configured HA mode, and improved HA state badge colors.

**HA configuration UI** — new High Availability card in Settings → Infrastructure with HA mode dropdown (standalone / hot-standby / load-balancing / passive-backup) and primary server name field. Also configurable via `jen.config` `[kea]` section with `ha_mode` and `name` keys.

### DDNS — Provider-Agnostic
The DDNS page is no longer tied to Technitium DNS.

The DNS provider is now configurable in Settings → Infrastructure → DDNS Configuration with three options:
- **Technitium** — existing Technitium REST API integration (unchanged for existing users)
- **Generic** — hostname lookup via `dig`/`host` over SSH to the Kea server
- **None** — log viewer only, no hostname lookup

Also configurable via `jen.config [ddns]` with the `dns_provider` key.

---

## Version 2.4.10 — April 2026

### Documentation Updates
- `docs/user-guide.md` — added Device Inventory, device fingerprinting badges, API Keys, MFA enrollment, and Settings → Icons sections (all missing since 2.x)
- `docs/faq.md` — added FAQ sections for device fingerprinting, randomized MACs (iOS private MACs), REST API, and MFA
- Version references updated throughout

---

## Version 2.4.9 — April 2026

### Docker Fixes
- Fixed Dockerfile missing pip packages required for MFA: `pyotp`, `qrcode[pil]`, `authlib`, `cryptography`
- Fixed Dockerfile not copying `static/icons/brands/` — brand SVG logos were missing in Docker deployments
- Added `jen-icons` volume to both compose files so user-uploaded custom icons survive container updates
- Bumped image tag to `jen-dhcp:2.4.9` in both compose files

---

## Version 2.4.8 — April 2026

### Bug Fixes
- Fixed device edit modal not opening for devices with names or owners — inline onclick broken by double quotes inside HTML attributes; switched to data-* attributes with event delegation
- Fixed device fingerprint badges not showing on Leases, Reservations, and Dashboard — MAC case mismatch (Kea uppercase vs devices table lowercase)
- Fixed Apple TV not getting Apple TV icon
- Fixed missing Lenovo OUI `c0:a5:e8`, Roku OUI `50:06:f5`, Amazon Echo Show OUIs
- Fixed device edit failing for icon names longer than 10 characters — column widened to VARCHAR(50)

---

## Version 2.4.x — April 2026

### Device Fingerprinting
Automatic device identification by manufacturer and type using OUI (MAC address prefix) lookup. Runs in the background every 30 seconds. OUI database covers 800+ prefixes: Apple, Samsung, Amazon, Google, Raspberry Pi, Roku, Ring, Sonos, Ecobee, Ubiquiti, Cisco, Netgear, Synology, QNAP, Meross, TP-Link/Kasa, Espressif (ESP8266/ESP32/ESPHome/Tasmota), Philips Hue, Lutron, Dell, HP, Lenovo, Intel, LG, Nintendo, PlayStation, Xbox, printers, virtual machines, and more.

Hostname-based fallback for randomized MACs (iOS 14+ private MAC addresses).

### Brand SVG Logos
24 bundled Simple Icons SVG logos display in Device Inventory, Leases, Reservations, and Dashboard. Manufacturer badges appear next to hostnames on every page.

### Manual Device Type Override
Edit any device to manually set its type. Manual overrides show a lock indicator. The background tracking loop respects overrides and will not overwrite them.

### Visual Icon Picker
Device edit modal includes a visual grid of brand logo previews for icon selection.

### Custom Icon Management
Settings → Icons: upload custom SVGs to override bundled icons or add new manufacturers. Stored in `/opt/jen/static/icons/custom/` and survive upgrades.

### Device Type & Subnet Filters
Type filter bar and subnet filter dropdown added to the Device Inventory page.

### API Enrichment
`GET /api/v1/leases` now returns `manufacturer` and `device_type` per lease.

---

## Version 2.3.x — April 2026

### REST API
Read-only REST API at `/api/v1/` for integration with Home Assistant, Zabbix, and custom scripts.

| Endpoint | Description |
|---|---|
| `GET /api/v1/health` | Kea status and Jen version — no auth required |
| `GET /api/v1/subnets` | Subnet utilization with pool sizes and percentages |
| `GET /api/v1/leases` | Active leases, filterable by subnet/MAC/hostname |
| `GET /api/v1/leases/{mac}` | Single device lease with `active` boolean |
| `GET /api/v1/devices` | Device inventory, filterable by MAC/name/subnet |
| `GET /api/v1/devices/{mac}` | Single device with `online` status and current lease |
| `GET /api/v1/reservations` | Reservations, filterable by subnet |

Authentication: `Authorization: Bearer jen_your_key_here`

### API Key Management
Settings → API Keys: generate named read-only keys, revoke or delete. Key shown once at creation.

### Live API Documentation
Settings → API Docs: all endpoints documented with parameters, examples, and ready-to-paste Home Assistant YAML and Zabbix HTTP agent config.

### Bug Fixes
- Fixed column sorting only applying to current page — now server-side ORDER BY before pagination
- Fixed CSV Import, lease release, MFA device revoke, MFA policy save — routes were missing
- Fixed Add Reservation form subnet pre-selection from Leases pin button
- Standardized table row height and font size across all pages

---

## Version 2.2.x — April 2026

### Stability & Bug Fixes
- Fixed MFA full flow — enroll, verify, trusted devices, backup codes
- Fixed Flask secret key regenerating on every restart
- Fixed dashboard time filter — Kea stores `expire` as TIMESTAMP not Unix integer
- Fixed subnets page showing empty lease duration and no address pools
- Fixed DDNS log reading via SSH from Kea server
- Fixed Server Status dashboard widget showing real data
- Server-side sorting on Leases, Reservations, and Devices
- Replaced dropdown nav with flat links and contextual section tab bars
- Renamed Admin to Settings; Users and Audit Log moved into Settings tabs

---

## Version 1.5.1 — April 2026

Switched to GPL v3 license.

---

## Version 1.0.0 — April 2026

Initial public release. Dashboard, Lease Management, Reservations, Subnet Editing, Telegram Alerts, HTTPS, rate limiting, audit log, Prometheus metrics, Docker support.
