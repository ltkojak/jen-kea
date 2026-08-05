# Jen v2.6.7 — Code Modularization

This release completes the full modularization of Jen's codebase. The `jen.py` monolith (6,272 lines) has been split into a proper Python package. **No features were changed. No configuration was changed. All URLs and APIs are identical.**

---

## What Changed

### jen.py → jen/ package

The application is now structured as a proper Python package:

```
jen/
  __init__.py          # App factory — create_app()
  extensions.py        # Shared state hub (cfg, KEA_SERVERS, SUBNET_MAP, globals)
  config.py            # Config loading, writing, subnet map parsing
  models/
    db.py              # Database connections, schema init, migrations
    user.py            # User model, password hashing, audit logging
  services/
    kea.py             # Kea API communication, HA detection, active server routing
    alerts.py          # Alert channels, templates, background monitor
    fingerprint.py     # OUI database, device classification, manufacturer icons
    mfa.py             # TOTP, backup codes, trusted devices
    auth.py            # Input validators, login rate limiting
  routes/
    api.py             # REST API v1 + API key management
    auth.py            # Login, logout
    dashboard.py       # Dashboard, stats, Prometheus metrics
    ddns.py            # DDNS status page
    devices.py         # Device inventory
    leases.py          # Leases, IP map
    mfa_routes.py      # MFA enrollment and verification
    reports.py         # Reports
    reservations.py    # Reservations, bulk operations
    search.py          # Global search, saved searches
    servers.py         # Kea server management
    settings.py        # All Settings pages
    subnets.py         # Subnet view and editing
    users.py           # User management, profile
run.py                 # New entry point
```

### Entry point change

The systemd service now runs `run.py` instead of `jen.py`:

```
ExecStart=/usr/bin/python3 /opt/jen/run.py
```

This is handled automatically by the installer — no manual changes needed.

### jen.py retained

`jen.py` is kept at `/opt/jen/jen.py` for reference but is no longer executed.

---

## Upgrading

```bash
cd ~
tar xzf jen-v2.6.7.tar.gz
cd jen
sudo ./install.sh
```

The installer will:
- Copy the `jen/` package to `/opt/jen/jen/`
- Copy `run.py` to `/opt/jen/run.py`
- Update the systemd service to use `run.py`
- Verify all 27 package modules install correctly
- Validate all 33 templates

Your config, database, and existing data are untouched.

---

## Release History

### 2.6.7 — Offline audit close-out
- `mfa_routes.py`: `load_user()` called bare — added local `_load_user()` helper
- `dashboard.py`, `devices.py`, `leases.py`, `reservations.py`: `DEVICE_TYPE_DISPLAY` used without import — added explicit import in each file
- Full targeted audit passes clean: zero bare `cfg`, zero unnamespaced `url_for`, zero missing imports, zero missing wrappers, all 14 blueprints and 33 templates valid

### 2.6.6
- Settings → Alerts 500: `DEFAULT_TEMPLATES` and `ALERT_TYPE_LABELS` not imported from `jen.services.alerts`
- Alert background thread error: `__get_global_setting` wrapper missing from `alerts.py`

### 2.6.5
- Full audit of all 14 blueprints — 154 issues found and fixed
- 46 bare `cfg` references replaced with `extensions.cfg` across `ddns.py`, `servers.py`, `settings.py`, `dashboard.py`
- 108 unnamespaced `url_for('endpoint')` calls updated to `url_for('blueprint.endpoint')` across all blueprints

### 2.6.4
- Navigation sub-tabs missing — all `request.endpoint` checks in `base.html` used pre-blueprint bare names. Updated all 20+ checks to blueprint-namespaced format (e.g. `'leases'` → `'leases.leases'`)

### 2.6.3
- `get_manufacturer_icon_url` and `DEVICE_TYPE_DISPLAY` unresolved in dashboard, leases, reservations, devices blueprints
- `get_global_setting` bare calls in `alerts.py` background thread

### 2.6.2 — Route blueprints complete
- All 104 routes migrated from `jen.py` into 14 Flask Blueprint modules
- `jen.service` updated to use `run.py`

### 2.6.1
- `install.sh` was not copying the `jen/` package or `run.py` to `/opt/jen/`
- Backup and rollback updated to include `jen/` package directory
- Post-install verification checks all 9 core package modules import correctly

### 2.6.0 — Package structure introduced
- `jen/` package created alongside `jen.py`
- All services and models extracted: `kea.py`, `alerts.py`, `fingerprint.py`, `mfa.py`, `auth.py`, `db.py`, `user.py`
- `extensions.py` shared state hub introduced — solves circular import problem for globals
- `config.py` extracted with `load_config()`, `init_extensions_from_config()`, `load_kea_servers()`
- `run.py` entry point created

---

## What's Next — 2.7.x

Professional installer overhaul:
- Interactive setup wizard for fresh installs
- Branded header, coloured progress output
- `--upgrade`, `--configure`, `--repair` flag system
- Better error messages with actionable guidance
- Post-install summary with URLs and next steps
