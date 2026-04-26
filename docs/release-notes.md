# Jen Release Notes

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
