# Changelog

## [2.6.7] - 2026-04-29

### Fixed — Offline audit pass (2.6.x close-out)
Full static analysis of all 14 blueprints before declaring 2.6.x complete. Found and fixed 8 issues:

- `mfa_routes.py`: `load_user()` called bare — the login_manager user loader isn't directly importable from blueprints. Added a local `_load_user()` helper that queries the DB directly, identical logic to the registered loader.
- `dashboard.py`, `devices.py`, `leases.py`, `reservations.py`: `DEVICE_TYPE_DISPLAY` used but never imported from `jen.services.fingerprint`. Added explicit import alongside the `__fp` alias in each file.

**2.6.x is now complete.** All 14 blueprints pass a full targeted audit: zero bare `cfg`, zero unnamespaced `url_for`, zero missing service constant imports, zero missing wrapper functions, all 14 blueprints and 33 templates syntax-valid.

## [2.6.6] - 2026-04-29

### Fixed
- Settings → Alerts 500 error: `DEFAULT_TEMPLATES` and `ALERT_TYPE_LABELS` used in `settings.py` but never imported from `jen.services.alerts` — added explicit import
- Alert background thread error: `__get_global_setting` called in `alerts.py` but the lazy wrapper function was never defined — added missing wrapper

## [2.6.5] - 2026-04-29

### Fixed — Full blueprint audit pass
Complete audit of all 13 route blueprints identified 154 issues in two categories:

**Bare `cfg` references (46):** `cfg` was used directly in `ddns.py`, `servers.py`, `settings.py`, and `dashboard.py` instead of `extensions.cfg`. These caused 500 errors on Servers, DDNS, Settings → Alerts, and Settings → Infrastructure pages.

**Unnamespaced `url_for` calls (108):** All `url_for('endpoint')` calls used pre-blueprint bare names. Flask blueprints require `url_for('blueprint.endpoint')`. Fixed across all 13 blueprints — `auth`, `dashboard`, `devices`, `leases`, `mfa_routes`, `reports`, `reservations`, `search`, `servers`, `settings`, `subnets`, `users`.

Note: `subnets.py` contains a local variable also named `cfg` (the Kea config-get result dict) — those `.get()` calls are correct as-is and were not changed.

## [2.6.4] - 2026-04-29

### Fixed
- Navigation sub-tabs completely missing after blueprint migration — all `request.endpoint` checks in `base.html` used bare endpoint names (e.g. `'leases'`) but Flask blueprints namespace endpoints as `blueprint.function` (e.g. `'leases.leases'`). Updated all 20+ endpoint checks throughout the template.

## [2.6.3] - 2026-04-29

### Fixed
- `get_manufacturer_icon_url` and `DEVICE_TYPE_DISPLAY` not resolved in dashboard, leases, reservations, and devices blueprints — the automated transformation script missed these because they appear as keyword argument values rather than standalone calls
- `get_global_setting` not resolved in `alerts.py` background thread — the lazy wrapper was defined but the calls still used the bare name

## [2.6.2] - 2026-04-28

### Changed — Code Modularization (Phase 2 — Complete)
All 104 routes migrated from `jen.py` into 14 Flask Blueprint modules under `jen/routes/`. The `jen.service` systemd unit now runs `run.py` instead of `jen.py`. `jen.py` is retained as a compatibility reference but is no longer the entry point.

**14 route blueprints:**
- `jen/routes/api.py` — REST API v1 + API key management
- `jen/routes/auth.py` — login, logout
- `jen/routes/dashboard.py` — dashboard, stats, metrics, Prometheus
- `jen/routes/ddns.py` — DDNS status page
- `jen/routes/devices.py` — device inventory
- `jen/routes/leases.py` — leases, IP map
- `jen/routes/mfa_routes.py` — MFA enrollment and verification
- `jen/routes/reports.py` — reports
- `jen/routes/reservations.py` — reservations including bulk operations
- `jen/routes/search.py` — global search and saved searches
- `jen/routes/servers.py` — Kea server management
- `jen/routes/settings.py` — all Settings pages
- `jen/routes/subnets.py` — subnet view and editing
- `jen/routes/users.py` — user management and profile

**Entry point change:**
`ExecStart=/usr/bin/python3 /opt/jen/run.py` (was `jen.py`)

**No behaviour changes.** All routes, URLs, and features are identical.

## [2.6.1] - 2026-04-28

### Fixed
- `install.sh` was not copying the new `jen/` package directory or `run.py` to `/opt/jen/` — the modularization would have been silently missing on all installs
- Backup now also snapshots the `jen/` package before upgrading so rollback can restore it
- Rollback now also restores the `jen/` package alongside `jen.py`

### Added
- Post-install verification now imports all 9 `jen/` package modules and reports success or any import issues

## [2.6.0] - 2026-04-28

### Changed — Code Modularization (Phase 1)
`jen.py` remains the functional monolith and is fully intact. A parallel `jen/` package has been introduced alongside it with all business logic extracted into proper modules. No behaviour changes — this is a structural refactor only.

**New package structure:**
- `jen/__init__.py` — application factory (`create_app()`)
- `jen/extensions.py` — shared state hub (cfg, KEA_SERVERS, SUBNET_MAP, all globals)
- `jen/config.py` — config loading, writing, subnet map parsing
- `jen/models/db.py` — database connections and schema init/migrations
- `jen/models/user.py` — User model, password hashing, audit logging, global settings
- `jen/services/kea.py` — Kea API communication, HA detection, active server routing
- `jen/services/alerts.py` — alert channels, templates, check_alerts background loop
- `jen/services/fingerprint.py` — OUI database, device classification, manufacturer icons
- `jen/services/mfa.py` — TOTP, backup codes, trusted devices
- `jen/services/auth.py` — input validators, login rate limiting
- `jen/routes/` — blueprint directory (empty in 2.6.x, populated in 2.7.x)
- `run.py` — new entry point (loads monolith via compatibility shim for 2.6.x)

**Why this approach:**
The `extensions.py` singleton pattern means all modules share the same global state without circular imports. Any module that writes `extensions.KEA_SERVERS = new_value` has that change visible to every other module immediately, because Python module objects are singletons.

**What's next (2.7.x):**
Routes will be migrated from `jen.py` into Blueprint modules one section at a time. Once complete, `jen.py` becomes `run.py` calling `create_app()` and the monolith is retired.

## [2.5.10] - 2026-04-28

### Added
- Servers page warning when multiple servers configured but `ha_mode` not set — shows alert with direct link to Settings → Infrastructure → High Availability

### Improved
- `install.sh` template validation: replaced file count check with full Jinja parse validation — broken templates now cause installer rollback rather than silent bad install

### Updated
- `docs/user-guide.md` — Mobile Access, ntfy/Discord channels, and Kea Servers/HA sections added
- `docs/faq.md` — Mobile, High Availability, and DDNS Providers FAQ sections added
- `docs/troubleshooting.md` — HA troubleshooting, Mobile troubleshooting, and Alert Channels sections added

## [2.5.9] - 2026-04-28

### Fixed
- `settings_alerts.html` had a stray `{% else %}🔗{% endif %}` fragment left over from before ntfy/discord channel types were added — caused a Jinja template parse error on the Alert Settings page. All 33 templates now validated clean.

## [2.5.8] - 2026-04-28

### Fixed
- Servers page crashed with "Encountered unknown tag 'endif'" — the HA state reference card and a duplicate `{% block scripts %}` / `{% endblock %}` were appended outside the content block during the 2.5.x rewrite, causing Jinja to fail parsing the template. Removed the duplicate block and restored correct template structure.

## [2.5.7] - 2026-04-28

### Fixed
- Sub-tab links (Management, Network, Settings section tabs) had iOS 300ms tap delay. Applied global `touchstart` instant navigation to every `<a href>` on every page — covers sub-tabs, pagination, sort headers, action links, and anything else that navigates. Replaces the per-group whack-a-mole approach with one fix that covers everything.

## [2.5.6] - 2026-04-28

### Fixed
- Mobile hamburger drawer showed 9 expanded individual page links instead of matching the desktop nav's 5 grouped items (Dashboard, Management, Network, Settings, About). Drawer now mirrors the desktop exactly — tapping Management lands on Leases and the Management sub-tabs (Leases, Reservations, Devices) appear below, same as desktop. Active state detection matches desktop grouping.

## [2.5.5] - 2026-04-28

### Fixed
- Hamburger drawer links had a noticeable delay before navigating on iOS — `touch-action: manipulation` CSS fixes `click` events but not `href` navigation. Fixed by adding `touchstart` listeners on drawer links that call `e.preventDefault()` and navigate immediately via `window.location.href`, bypassing the 300ms delay entirely.

## [2.5.4] - 2026-04-28

### Fixed
- iOS/mobile double-tap required on all interactive elements — root cause was missing `touch-action: manipulation`. Applied globally to all buttons, links, inputs, selects, labels, table cells, and anything with `onclick`. Single tap now fires immediately on all interactive elements across the entire app.
- Nav on iPhone was a horizontally-scrolling bar of tiny links — replaced with hamburger (☰) menu that opens a full-width drawer with large tap targets (52px minimum). Desktop nav unchanged.

### Added
- Three distinct responsive breakpoints: desktop (>1024px full layout), iPad (769–1024px, hides low-priority columns), iPhone (≤768px, hamburger nav + table card reflow)
- `mobile-cards` CSS class: on iPhone, data tables reflow into individual cards per row showing field labels, eliminating horizontal scrolling on Leases, Reservations, and Devices pages
- `hide-mobile` and `hide-tablet` column classes: MAC addresses, timestamps, and other secondary data hidden on small screens but available via card label on mobile
- `viewport-fit=cover` for iPhone notch/Dynamic Island safe area support
- All form inputs use `font-size: 16px` on mobile to prevent iOS auto-zoom on focus
- Minimum 44px tap targets on all buttons and pagination controls (Apple HIG guideline)
- Scrollbar-hidden section tabs for clean tab overflow on mobile

## [2.5.3] - 2026-04-27

### Added
- Default favicon.ico shipped with Jen — teal circle with white "J", transparent background, available in 16×16 through 256×256. Eliminates blank browser tab icon on fresh installs.

### Fixed
- Removed `static/favicon.ico` from `.gitignore` and `.dockerignore` so the default favicon is tracked and included in Docker builds. User-uploaded replacements via Settings still work as before.

## [2.5.2] - 2026-04-27

### Security
- Replaced SHA-256 password hashing with werkzeug `pbkdf2:sha256` (salted, iterated). Existing users are automatically migrated to the new hash on their next successful login — no manual database changes required.

### Fixed
- Bare `except:` clauses in alert channel JSON parsing replaced with `except (json.JSONDecodeError, ValueError)`
- Default DDNS log path was still `kea-ddns-technitium.log` — changed to `kea-ddns.log`

### Updated
- `docs/release-notes.md` — 2.5.2 entry added

## [2.5.1] - 2026-04-27

### Added
- Pi-hole DNS provider for DDNS hostname lookup — supports both v5 (api.php) and v6 (REST API with session auth)
- AdGuard Home DNS provider for DDNS hostname lookup — Basic Auth REST API
- SSH/Bind9/Unbound DNS provider — runs `dig` over existing SSH connection, no extra config needed
- Active server TTL cache (10s) in `get_active_kea_server()` to avoid hammering `ha-heartbeat` on every page load

### Fixed
- Hardcoded `theelders` in DDNS SSH timeout error message — now uses configured `KEA_SSH_HOST`
- Hardcoded `matthew` as default SSH username in subnet edit — now uses configured `KEA_SSH_USER`
- `generic` DNS provider renamed to `ssh` for clarity (both values still accepted)
- DDNS settings UI now shows correct field sections per provider with dynamic show/hide
- DNS provider fields properly initialised on page load (not just on dropdown change)

### Updated
- `jen.config.example` — documented all four DNS providers with example config blocks
- `docs/admin-guide.md` — DDNS provider section updated with Pi-hole, AdGuard, SSH options

## [2.5.0] - 2026-04-26

### Added
- ntfy alert channel — supports ntfy.sh and self-hosted ntfy, configurable topic/token/priority
- Discord alert channel — Discord webhook integration with bold text formatting
- `ha_failover` alert type — fires when any Kea server's HA state changes
- `get_active_kea_server()` — automatically routes config-get and subnet editing to the active HA node
- HA state monitoring in `check_alerts()` — tracks HA state per server, alerts on state changes
- HA Configuration card in Settings → Infrastructure — ha_mode dropdown and server name field
- `/settings/infrastructure/save-ha` route to save HA settings
- Servers page HA enhancements — ⚡ ACTIVE indicator, HA mode banner, improved state badge colors
- DDNS `dns_provider` config option — `technitium`, `generic` (dig/host over SSH), or `none`
- Generic DNS lookup via SSH for non-Technitium setups
- `jen.config.example` — documented `ha_mode`, `role`, `name` in `[kea]`; `dns_provider` in `[ddns]`; example `[kea_server_2]` block

### Changed
- All `kea_command("config-get")` calls now use `get_active_kea_server()` — correct behaviour in HA setups
- DDNS page subtitle no longer hardcodes "Technitium DNS"
- Settings → Infrastructure DDNS section — replaced Technitium-specific form with provider-agnostic form

### Updated
- `docs/admin-guide.md` — HA configuration, DDNS provider config, ntfy/Discord setup
- `docs/release-notes.md` — 2.5.0 entry

## [2.4.10] - 2026-04-26

### Updated
- `docs/user-guide.md` — added Device Inventory, device fingerprinting, API Keys, MFA, and Settings → Icons sections (all missing since 2.x)
- `docs/faq.md` — added FAQ sections for device fingerprinting, randomized MACs, REST API, and MFA
- `docs/wiki-home.md` — version reference updated to 2.4.10
- `jen.config.example` — version comment updated to 2.4.10
- `Dockerfile`, `docker-compose.yml`, `docker-compose.mysql.yml` — version bumped to 2.4.10

## [2.4.9] - 2026-04-26

### Fixed
- Fix Dockerfile missing pip packages for MFA: `pyotp`, `qrcode[pil]`, `authlib`, `cryptography`
- Fix Dockerfile not copying `static/icons/brands/` — brand SVGs missing in Docker deployments
- Fix custom icons not persisting across container updates — added `jen-icons` volume in both compose files
- Bump Docker image tag to `jen-dhcp:2.4.9`

### Updated
- `docs/release-notes.md` — complete 2.x release history added
- `docs/admin-guide.md` — updated for MFA, REST API, device fingerprinting, custom icons, Prometheus metrics
- `docs/docker.md` — added `jen-icons` volume to persistent data table
- `docs/installation.md`, `docs/wiki-home.md` — version references updated

## [2.4.8] - 2026-04-25

### Fixed
- Fix device edit modal not opening for devices with names/owners: use data-* attributes instead of inline onclick

## [2.4.7] - 2026-04-25

### Fixed
- Fix device edit modal not opening: attempt to HTML-escape quotes in onclick (superseded by 2.4.8)

## [2.4.6] - 2026-04-25

### Fixed
- Add try/catch debug to edit modal to surface JS errors

## [2.4.5] - 2026-04-25

### Fixed
- Fix device edit silently failing for devices with longer icon names (e.g. `raspberrypi`, `philipshue`): `device_icon_override` column was VARCHAR(10) which truncated/errored on names longer than 10 chars. Widened to VARCHAR(50). Auto-migration fixes existing installs.
- Replace plain icon name dropdown with visual icon picker in edit modal — shows actual brand logo previews in a grid so you can see what you're selecting.

## [2.4.4] - 2026-04-25

### Fixed
- Fix device badges not showing on Leases, Reservations, and Dashboard: MACs from Kea are uppercase (`78:C4:FA`) but devices table stores lowercase (`78:c4:fa`) — lookup was silently failing. `get_device_info_map` now normalizes all MACs to lowercase, and the badge macro does the same.
- Fix Apple TV showing Apple logo instead of Apple TV logo: `classify_device` now returns manufacturer "Apple TV" for appletv hostnames, and `MANUFACTURER_ICON_MAP` maps "Apple TV" → `appletv.svg` (custom icon).
- Fix `pw08tf8v` (Lenovo) not being identified: added missing Lenovo OUI `c0:a5:e8`.

### Added
- Icon override in device edit modal — choose any bundled or custom icon to use for a specific device, independent of device type. Useful for Apple TV, HomePod, or any device where the auto-detected icon isn't specific enough.
- Subnet filter dropdown on Device Inventory page — filter devices by subnet alongside search and stale filter.

## [2.4.3] - 2026-04-25

### Added
- Manual device type override in the Device Inventory edit modal — choose from a dropdown (Apple, Android, IoT, TV, Gaming, etc.) to override auto-detection for any device. Overridden devices show a 🔒 indicator and a dashed badge border. Setting back to "Auto-detect" clears the override.
- Auto-detection loop now respects manual overrides — if a device has a manual type set, the background tracker will not overwrite it on subsequent lease updates.
- Device fingerprint badges now appear on Leases, Reservations, and Dashboard recently issued leases pages — small manufacturer logo/icon badge next to the hostname on every row.
- API `/api/v1/leases` endpoint now returns `manufacturer` and `device_type` fields per lease.
- Shared `_device_badge.html` Jinja macro keeps badge rendering consistent across all pages.

## [2.4.2] - 2026-04-25

### Fixed
- Fix iPhones/iPads not being identified: iOS 14+ uses randomized (private) MAC addresses by default — the OUI lookup always returns Unknown for these. Added hostname-based fallback detection so devices with `iphone`/`ipad` in the hostname are identified as Apple regardless of MAC. Same fallback now catches Echo/Alexa, Chromecast, Roku, Ring, Sonos, and gaming consoles by hostname when OUI is unknown.
- Add missing Roku OUI `50:06:f5` and Amazon Echo Show OUIs `50:d4:5c`, `b0:8b:a8` plus several other missing Amazon prefixes.

## [2.4.1] - 2026-04-25

### Added
- Brand SVG logos in Device Inventory — 24 bundled Simple Icons SVGs replace emoji for identified manufacturers (Apple, Samsung, Cisco, Dell, HP, Lenovo, Intel, LG, Google, Raspberry Pi, Roku, Ring, Sonos, Ubiquiti, Netgear, Synology, QNAP, Philips Hue, TP-Link, PlayStation, Epson, Espressif, VMware, QEMU)
- Custom icon management at Settings → Icons — upload your own SVG to override any bundled icon or add new manufacturers. Custom icons take priority over bundled ones and survive upgrades (stored in `/opt/jen/static/icons/custom/`)
- Icon display uses white-tinted SVG logos with colored badge backgrounds matching device type

## [2.4.0] - 2026-04-24

### Added
- Device fingerprinting via OUI (MAC address manufacturer lookup) — automatically identifies device manufacturer and type for every device in the inventory
- OUI database covering 800+ prefixes across Apple, Samsung, Amazon, Google, Raspberry Pi, Espressif (ESP8266/ESP32/Tasmota/ESPHome), Meross, TP-Link/Kasa, Roku, Ring, Ecobee, Sonos, Nest, Ubiquiti, Cisco, Netgear, Synology, QNAP, Lutron, Philips Hue, Nintendo, PlayStation, Xbox, Intel, Dell, HP, Lenovo, LG, Canon/Epson/Brother printers, VMware/QEMU/Hyper-V virtual machines, and more
- Hostname-based sub-classification for Apple devices: distinguishes iPhone/iPad (📱) from MacBook/iMac (💻) from Apple TV (📺)
- Device type badge in inventory table — shows manufacturer name and emoji icon (📱 💻 🔌 📺 🎮 🖨️ 🗄️ 🌐 🥧 etc.)
- Device type filter bar above inventory — click any type to filter the full inventory
- Auto-migration: adds `manufacturer`, `device_type`, `device_icon` columns to existing `devices` table on first run

## [2.3.8] - 2026-04-24

### Fixed
- Fix lease release button (✕ on Leases page) — `/leases/release` route was missing entirely; added with proper audit logging
- Fix MFA trusted device revoke buttons — template used `/mfa/revoke-device/<id>` and `/mfa/revoke-all-devices` but routes were named differently; added alias routes and the missing revoke-all route
- Fix MFA policy Save button in Settings → System — `/settings/system/save-mfa-mode` route was missing; added
- Fix CSV Import on Reservations page — `/reservations/import` route was missing entirely; added with full dry-run support, duplicate detection, and per-row error reporting

## [2.3.7] - 2026-04-24

### Fixed
- Fix Add Reservation form not pre-selecting the correct subnet when arriving from the Leases pin button: the `selected` attribute comparison used `s.id` but the template iterates as `sid` — option was never matched so the form always defaulted to the first subnet (Production)

## [2.3.6] - 2026-04-24

### Fixed
- Fix 404 when clicking the pin (📌) button on the Leases page: button was POSTing to `/leases/make-reservation` which never existed. Changed to a GET link to `/reservations/add` with IP, MAC, hostname, and subnet pre-filled as query params. The Add Reservation form now pre-populates all fields when arriving from a lease row.

## [2.3.5] - 2026-04-23

### Fixed
- Fix API keys and all REST API v1 routes returning 404: routes were appended after the `if __name__ == "__main__"` block which starts `serve_forever()` — the server was already running and blocking before the route decorators at the bottom of the file ever executed. Moved all API routes before the main block so they register correctly at startup.

## [2.3.4] - 2026-04-23

### Fixed
- Fix Reservations rows taller than Leases: root cause was emoji buttons (🗑️ ✏️) rendering taller than their line-height and stretching table rows. Replaced with plain text equivalents (✕ ✏) in Reservations, Devices, and Saved Searches action columns to match the plain-text buttons already used in Leases.

## [2.3.3] - 2026-04-23

### Fixed
- Fix Reservations rows taller than Leases rows: hostname column text was wrapping to two lines when the column was narrow (7-column table). Added `white-space:nowrap` to hostname cells on Leases, Reservations, and Devices. Also removed remaining `font-size:11px` inline overrides from Devices date cells.

## [2.3.2] - 2026-04-23

### Fixed
- Fix table row inconsistency between Leases and Reservations pages — inline `font-size:12px` overrides on individual `<td>` cells were fighting the global 13px rule. Removed inline font-size from data cells; added `td.mono { font-size: 12px }` CSS rule so monospace cells (IPs, MACs, timestamps) are consistently slightly smaller across all pages without per-cell overrides.

## [2.3.1] - 2026-04-23

### Fixed
- Fix `/api/docs` returning JSON 404 — path starts with `/api/` so the API 404 handler intercepted it before the login redirect could fire. Moved to `/settings/api-docs` so it's treated as a settings page.

## [2.3.0] - 2026-04-23

### Added
- REST API v1 — read-only API at `/api/v1/` with the following endpoints:
  - `GET /api/v1/health` — Kea status and Jen version (no auth required)
  - `GET /api/v1/subnets` — subnet utilization stats with pool sizes and utilization percentages
  - `GET /api/v1/leases` — active leases, filterable by subnet/MAC/hostname
  - `GET /api/v1/leases/{mac}` — single device lease lookup with `active` boolean
  - `GET /api/v1/devices` — device inventory, filterable by MAC/name/subnet
  - `GET /api/v1/devices/{mac}` — single device with `online` status and current lease
  - `GET /api/v1/reservations` — all reservations, filterable by subnet
- API key management in Settings → API Keys — generate, revoke, and delete keys; key shown once at creation
- Live API documentation at `/api/docs` — all endpoints documented with parameters, example requests/responses, and ready-to-paste Home Assistant YAML and Zabbix HTTP agent config
- `api_keys` table added to Jen database automatically on first run after upgrade

### Fixed
- Standardized table row height and font size (13px) across all pages — Leases, Reservations, Devices, Users, Audit Log were all slightly different

## [2.2.38] - 2026-04-21

### Fixed
- Fix dashboard Server Status widget showing useless placeholder text — now fetches real server status (online/offline, HA state, version) and displays it inline, with a "View Details" link to the Servers page
- Fix sorting only applying to current page on Leases, Reservations, and Devices — client-side JS sorting only sorts the visible page. All three pages now use server-side ORDER BY with `?sort=column&dir=asc|desc` URL parameters, so sorting is applied before pagination across the full dataset. Column headers are now clickable sort links with ↑/↓ indicators. Sort state is preserved through pagination.

## [2.2.37] - 2026-04-17

### Fixed
- Fix DDNS log reading: my restoration in v2.2.34 incorrectly used paramiko (which was never installed or needed). The original implementation always used `subprocess` to call the system `ssh` binary directly — no extra dependencies required. Reverted to subprocess-based SSH. Removed all paramiko references introduced in v2.2.35/2.2.36.

## [2.2.36] - 2026-04-17

### Fixed
- Fix DDNS page showing "X Error" with no detail: `log_message` was never displayed in the template, making SSH errors invisible. Added Detail row to Log Info card and logger.error calls so errors appear both on screen and in journalctl.

## [2.2.35] - 2026-04-17

### Fixed
- Fix DDNS page crashing with "cannot access local variable 'paramiko'": `paramiko` was imported inside the try block but referenced in the except clause — if the import itself failed, the variable was undefined. Moved `paramiko` to top-level imports with a `HAS_PARAMIKO` guard.
- Fix Subnets page showing empty lease duration, 0.0h timers, and no address pools: route was only fetching active/reserved counts from the DB but never fetching lease times, renew/rebind timers, or pool ranges from the Kea API config-get. All subnet config data now fetched from Kea and passed to template.

## [2.2.34] - 2026-04-17

### Fixed
- Fix DDNS log showing "File not found": log lives on the Kea server (theelders), not on bigben where Jen runs. Route was restored with a plain local `open()` call instead of the original SSH-based log reading via paramiko. Restored SSH log fetch.

### Changed
- Remove hamburger/mobile panel nav entirely — now that the desktop nav is flat links with no dropdowns, the same nav works on all screen sizes. On small screens the nav scrolls horizontally. Simpler, more consistent, eliminates the messy mobile-only code path.

## [2.2.33] - 2026-04-17

### Fixed
- Fix nav logo version number alignment: when a logo image is set, version number now centers beneath the logo instead of left-justifying awkwardly beside it

## [2.2.32] - 2026-04-17

### Fixed
- Fix branding nav color section: had a nested `<form>` inside a `<form>` for the Reset button (invalid HTML — browsers silently ignore inner forms). Split into two separate forms. Reset button now always visible, disabled/greyed out when no custom color is set rather than hidden.

## [2.2.31] - 2026-04-17

### Fixed
- Fix About page error: `lease_counts` was referenced in the template but never passed by the route

### Changed
- Rework Custom Branding in Settings: replace pointless app-name text field with nav logo image upload (PNG/SVG/JPG/WebP, max 200KB) — logo replaces "Jen" text in nav bar when set. Nav bar color picker kept. Added missing save routes (`/settings/upload-nav-logo`, `/settings/remove-nav-logo`, `/settings/save-nav-color`) which previously didn't exist, making the old branding form completely non-functional.

## [2.2.30] - 2026-04-17

### Changed
- Replace dropdown nav menus with flat nav links + contextual section tab bars — eliminates iPad/touch double-tap issues entirely. Management, Network, and Settings are now direct links; when you're inside a section, a sticky tab bar appears below the nav showing all pages in that section. Profile avatar dropdown preserved as-is.
- Rename "Admin" nav item to "Settings"; moved Users and Audit Log into Settings section tabs alongside System, Alerts, Infrastructure
- Moved Reports from Network to Management section tabs
- About is now a direct top-level nav link (no submenu needed)
- Mobile hamburger menu updated to match new structure with Settings section replacing Admin

## [2.2.29] - 2026-04-17

### Fixed
- Fix dashboard recent leases time filter definitively: `expire` in Kea's lease4 table is a `TIMESTAMP` column (not a Unix integer), so all `UNIX_TIMESTAMP()` arithmetic was producing NULL comparisons and showing every active lease regardless of window. Also discovered `valid_lifetime` is stored per-lease in the lease4 row — no need to look it up from Kea config. Query now uses correct `expire - INTERVAL valid_lifetime SECOND > NOW() - INTERVAL N SECOND` timestamp arithmetic.

## [2.2.28] - 2026-04-17

### Fixed
- Fix time selector immediately snapping back to "Last 30 min": `hours` was passed to template as `str(float)` so `1.0 != "1"`, `4.0 != "4"` etc. — no option ever matched so browser defaulted to first item and form auto-submitted. Now strips trailing `.0` so values match option strings exactly.
- Add logging of dashboard lease lifetime values and query errors to help diagnose the recent leases time filter issue

## [2.2.27] - 2026-04-16

### Fixed
- Fix dashboard recent leases still showing all leases: previous fix hardcoded `86400s` lease lifetime which didn't match actual Kea config. Now reads `valid-lifetime` from Kea API config-get (with per-subnet overrides) and uses the real lease duration to calculate `issued_at = expire - valid_lifetime`. Time window filtering and "Obtained" timestamps are now accurate.

## [2.2.26] - 2026-04-16

### Fixed
- Fix dashboard "Recently Issued Leases" showing all active leases regardless of time window — query had no time filter and used `expire DESC` (future expiry) instead of filtering by when the lease was issued. Now filters by `expire - 86400 > NOW() - window` to approximate issue time
- Fix dashboard time selector resetting to "Last 30 min" on every page load — route never read the `hours` query parameter and never passed it back to the template; both fixed
- Fix trusted device "Remember this device" not persisting across logout — cookie was written as `jen_trusted` but read back as `jen_trusted_device`; name mismatch meant the cookie was never found on subsequent logins, always prompting for MFA again

## [2.2.25] - 2026-04-16

### Fixed
- Fix enrolled TOTP methods not showing on MFA settings page: DB schema uses column `name` but queries referenced non-existent column `device_name` — SELECT was failing silently (caught by bare `except`) returning empty list, and INSERT would also fail on new enrollments. Both corrected to use `name`.

## [2.2.24] - 2026-04-16

### Fixed
- Fix dashboard layout broken by malformed HTML from route restoration: closing `</div>` for stat cards was misplaced mid-template with a stray HTML comment, causing all subnet cards to render incorrectly
- Fix dashboard JS placed inside `{% block title %}` instead of `{% block scripts %}`, meaning `saveDashPrefs()` and related functions were injected into the page `<title>` tag rather than as executable JavaScript — Save Layout button silently did nothing
- Fix widget ID mismatch: HTML used `dash-subnet-stats` (hyphens) but JS referenced `dash-subnet_stats` (underscores); standardised to underscores throughout

## [2.2.23] - 2026-04-16

### Fixed
- Fix `mfa_verify` route rendering nonexistent `mfa_verify.html` — the template was always named `mfa_challenge.html`; route now renders the correct template and passes `has_totp` context variable it requires
- Fix field name collision in `mfa_challenge.html` — the "remember for" select was also named `remember_device` instead of `remember_days`, causing the days value to be lost on submit

## [2.2.22] - 2026-04-16

### Fixed
- Fix MFA verify route using `current_user` (who isn't logged in yet at verify time) — now correctly reads `mfa_pending_user_id` from session, calls `login_user()` only after successful code verification, and clears pending session keys on success
- Fix `mfa_enroll` template variable mismatches introduced during route restoration: `new_secret` → `secret`, action `setup_totp` → `enroll`, field `name` → `device_name` — enrollment form was silently broken and could not actually enroll a new authenticator

## [2.2.21] - 2026-04-16

### Fixed
- Fix login completely broken: `app.secret_key` was set to `os.urandom(24).hex()` on every startup, generating a new random key each time. This caused sessions to be invalidated on every restart and made login impossible with multiple gunicorn workers (each worker got a different key). Secret key is now generated once and persisted to `/etc/jen/secret_key`, then loaded on startup so sessions are stable across restarts and workers

## [2.2.20] - 2026-04-16

### Fixed
- Fix login form blanking username/password fields on failed login attempts — template now repopulates the username field and all failed login render paths pass `prefill_username` back to the template

## [2.2.19] - 2026-04-16

### Fixed
- Fix MFA redirect on login: `url_for("mfa_challenge")` corrected to `url_for("mfa_verify")`, resolving the "Could not build url for endpoint 'mfa_challenge'" error on the login page

## [1.0.0] - 2026-04-10

Initial public release.

### Features
- Dashboard with live subnet utilization, recently issued leases, Kea health indicator, auto-refresh
- Lease browser — filter by subnet, time window, search by IP/MAC/hostname
- Manual lease release and stale lease cleanup
- Lease history (expired leases)
- Visual IP address map per subnet
- Reservations — add, edit, delete with duplicate detection
- Per-reservation notes field
- Per-reservation DNS override
- Bulk CSV import and export for reservations
- Subnet editing via SSH — pool ranges, lease times, scope options
- Auto-backup and rollback on subnet edit failure
- Audit log — all changes tracked with user, timestamp, source IP
- DDNS status page with Technitium log viewer and hostname lookup
- Telegram alerts — Kea down/up, new device lease, utilization threshold
- Login rate limiting — configurable attempts, lockout duration, mode
- HTTPS via SSL certificate upload in UI
- SSH key generation for subnet editing in Settings
- Session timeout — global and per-user
- Dark/light mode toggle
- Sortable columns and pagination
- Prometheus metrics endpoint
- Guided installer with bare metal and Docker support
- Uninstaller
- Docker support (external MySQL and bundled MySQL modes)
- Full documentation
