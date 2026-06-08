# Jen v3.6.0 — Release Notes
**Released:** 2026-06-08
**Series:** 3.6.x — Plugin Framework

---

## Overview

3.6.0 introduces the Jen plugin framework — a mechanism for installing optional add-ins without modifying Jen core. Plugins can add new routes, nav items, templates, and database tables. This release ships the framework itself plus two stub plugins (Network Discovery and IPAM Lite) as proof of concept. Full plugin implementations follow in their own versioned releases.

This is a foundational release. No existing functionality changes. The only new user-visible feature is **Settings → Plugins**.

---

## What's New

### 🧩 Plugin Framework

**How it works:**

Plugins live in `/opt/jen/plugins/<plugin-id>/`. Each plugin contains:
- `manifest.json` — metadata, version, Jen version requirement, nav entries, DB migrations
- `plugin.py` — optional Flask blueprint registration via a `register(app)` function
- `templates/` — optional Jinja templates the plugin can render

On startup, Jen scans `/opt/jen/plugins/`, loads all enabled plugins, registers their blueprints, and appends their template folders to the Jinja search path. Disabled plugins are skipped entirely. The plugin loading happens after all core blueprints are registered so plugins can safely reference core utilities.

**Settings → Plugins page:**

A new tab in Settings shows:
- All installed plugins with their version, status (enabled/disabled), and Jen version compatibility
- The plugin registry — fetched live from `registry.json` on GitHub — showing available plugins with descriptions, tags, and an Install button
- Enable/disable and Uninstall actions per plugin

**Plugin nav injection:**

Plugins can declare nav items in their `manifest.json`. Items with `"section": "network"` appear as tabs in the Network section alongside Subnets, Servers, and DDNS. The Network nav link's active state also activates when a plugin page is open. Additional sections (management, settings) can be supported in future releases.

**Registry:**

The plugin registry is a JSON file hosted at:
```
https://raw.githubusercontent.com/ltkojak/jen-kea/main/plugins/registry.json
```
Jen fetches it when the Plugins page is opened. If the registry is unreachable (no internet, GitHub down) a warning is shown but installed plugins continue to work normally. Community contributors can submit plugins by opening a PR to add an entry to `registry.json`.

**Install flow:**

1. Open Settings → Plugins
2. Browse the registry, click Install
3. Jen downloads the plugin zip, validates the manifest, runs DB migrations, enables the plugin
4. Restart Jen — the plugin is now active

**Versioning:**

- Jen core continues semver (`3.6.x`)
- Plugins version independently (`network-discovery v1.0.0`, `ipam v1.0.0`)
- Each plugin declares `requires_jen` — plugins requiring a newer Jen version show a warning instead of an Install button

### 📦 Bundled Plugin Stubs

Two plugins ship in the `plugins/` directory of the repo as v0.1.0 stubs:

**Network Discovery** (`plugins/network-discovery/`)
- Registers the `network_discovery` blueprint at `/network/discovery`
- Injects a "🔍 Discovery" tab into the Network nav section
- DB migrations create `nd_scan_jobs` and `nd_scan_results` tables
- v0.1.0 is a placeholder page; full scan implementation comes in v1.0.0

**IPAM Lite** (`plugins/ipam/`)
- Registers the `ipam` blueprint at `/network/ipam`
- Injects a "📋 IPAM" tab into the Network nav section
- DB migrations create `ipam_static_entries` and `ipam_assignment_history` tables
- v0.1.0 is a placeholder page; full address space view comes in v1.0.0

---

## Technical Details

**New files:**
- `jen/services/plugins.py` — plugin loader, registry fetcher, enable/disable, install/uninstall
- `jen/routes/plugins.py` — Settings → Plugins page routes
- `templates/plugins.html` — Plugins management page
- `plugins/registry.json` — plugin registry manifest
- `plugins/network-discovery/` — Network Discovery plugin stub
- `plugins/ipam/` — IPAM Lite plugin stub

**Modified files:**
- `jen/__init__.py` — `load_plugins(app)` called after blueprints; plugin nav context processor added
- `jen/extensions.py` — `PLUGIN_DIR` and `PLUGIN_REGISTRY_URL` constants added
- `jen/models/db.py` — `plugins` table added to `init_jen_db()`
- `templates/base.html` — Plugins tab in Settings section-tabs; plugin nav injection in Network tabs
- `install.sh` — `/opt/jen/plugins/` directory created on install

**Plugin security:**
- Plugin IDs are validated as `[a-z0-9-]` before any file operations
- Downloaded zips are extracted to a temp location and validated before replacing any existing install
- Manifest `id` field must match the requested plugin ID — mismatches are rejected
- Jen version requirement is checked before completing install

---

## Upgrading

```bash
cd ~
tar xzf jen-v3.6.0.tar.gz
cd jen
sudo ./install.sh
```

The `plugins` DB table is created automatically on startup. The `/opt/jen/plugins/` directory is created by the installer.

---

## What's Next

- **Network Discovery v1.0.0** — nmap/arp-scan integration, rogue device detection, scheduled scans, results table
- **IPAM Lite v1.0.0** — full address space view (available/dynamic/reserved/static), ownership tracking, assignment history, replaces Netbox for static IP management

---

*Jen is a self-hosted DHCP infrastructure management UI for ISC Kea.*
*GPL v3 — Copyright 2026 Matthew Thibodeau*
