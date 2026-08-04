# Jen v3.5.7 — Release Notes
**Released:** 2026-05-19
**Series:** 3.5.x — Multi-Tenancy, Access Control, User Management & Notifications

---

## Overview

The 3.5.x series is the largest release in Jen's history. It delivers a complete three-tier role system with subnet-level access control, a rebuilt user management page, multiple new notification channels, and two new dashboard widgets — all across eight patch releases over a single day of rapid iteration and auditing.

No breaking changes to the API. No config file changes required. Drop-in upgrade from any 3.4.x release — existing admin accounts are promoted to SuperAdmin automatically on first startup.

---

## What's New — 3.5.0

### ⭐ Three-Tier Role System

Jen now has three distinct roles:

| Role | Who it's for | What they can do |
|------|-------------|-----------------|
| ⭐ **SuperAdmin** | Network administrators | Full access to everything, all subnets, always. Manages users and role assignments. Cannot be subnet-restricted. |
| 🔧 **Admin** | Delegated subnet managers | Full create/edit/delete capability on their assigned subnets. Can access Settings, Database, and Audit Log. Cannot manage other users. |
| 👁️ **Viewer** | Read-only observers | See-only access to their assigned subnets. Cannot access Settings, Database, or Audit Log. |

### 🔒 Subnet-Level Access Control

Every user (except SuperAdmin) can be restricted to a specific list of subnets. A restricted user only sees data for their assigned subnets — everywhere in the application:

- **Leases** — only leases on assigned subnets
- **Reservations** — only reservations on assigned subnets
- **Devices** — only devices last seen on assigned subnets
- **Dashboard** — only subnet cards for assigned subnets; recent lease activity filtered
- **Network / Subnets** — only assigned subnets listed
- **Reports** — history data filtered to assigned subnets
- **Search** — results filtered to assigned subnets
- **IP Map** — only assigned subnets in the dropdown
- **Add/Edit Reservation** — subnet dropdown only shows assigned subnets
- **Edit Subnet** — access check before the form loads; dropdown filtered
- **`/api/stats` and `/api/top-devices`** — only returns data for accessible subnets

Setting `subnet_access = NULL` (the default) means all subnets — unrestricted. SuperAdmins are always unrestricted regardless of what is stored.

### 🏗️ Shared Access Control Module

`jen/services/access.py` replaces the duplicated `_admin_required` decorator that previously lived in every route file. It provides:

- `superadmin_required` — for user management routes
- `admin_required` — for settings, database, subnet editing
- `add_subnet_restriction()` — appends `WHERE subnet_id IN (...)` to any query based on the current user's access list

### 🗃️ Database Migration

Two `ALTER TABLE` statements run automatically on startup:

```sql
ALTER TABLE users MODIFY COLUMN role ENUM('superadmin','admin','viewer') NOT NULL DEFAULT 'viewer';
ALTER TABLE users ADD COLUMN subnet_access JSON DEFAULT NULL;
```

All existing `admin` users are promoted to `superadmin`. Existing `viewer` users get `subnet_access = NULL` — no change to what they can see. Zero manual steps required.

---

## What's New — 3.5.5

### 👤 Users Page — Complete Redesign

The user management page was rebuilt from a cluttered inline-form table to a clean read-only table with a proper edit modal.

**Clean table.** Each row shows Username, Role badge, Subnet access summary, MFA status, and Session timeout as read-only values.

**✏️ Edit modal.** One button per row opens a modal pre-populated with that user's current settings. Everything is in one place:

- **Role** — selector (disabled when editing your own account to prevent self-demotion)
- **Subnet access** — multi-select; hidden automatically when SuperAdmin role is chosen
- **Session timeout** — per-user override of the global default
- **Password reset** — set a new password for any user; leave blank to keep current
- **MFA reset** — wipe a user's entire MFA enrollment (methods, backup codes, trusted devices) so they re-enroll on next login; button disabled if no MFA enrolled
- **Delete** — with confirmation; hidden when editing your own account

**＋ Add User button** in the page header opens a creation modal with all fields: username, password, role, subnet access, and session timeout.

**"Change my password" removed** — it belongs on the profile page, which is where it lives.

**Built-in protections:**
- Cannot delete your own account
- Cannot demote your own account from SuperAdmin
- Cannot delete or demote the last SuperAdmin account

**New routes:**
- `POST /users/edit/<id>` — unified edit (role + subnets + timeout + optional password)
- `POST /users/reset-mfa/<id>` — wipe MFA enrollment (SuperAdmin only)

---

## What's New — 3.5.7

### 🔔 Notification Channels — Pushover + Multi-Channel

**Pushover added.** Pushover (one-time $5 per platform) is now a supported channel. Configure your User Key and Application API Token in the channel settings. The first line of each alert becomes the push notification title; the rest is the body.

**Multiple simultaneous channels now work.** The Add Channel modal was disabling the channel type selector whenever any channel already existed — making it impossible to add a second channel through the UI. The backend has always supported multiple channels (it fires all enabled channels for every alert). The UI restriction is now removed. Run any combination simultaneously: ntfy.sh on your phone, Telegram in a group chat, Pushover as a backup, a generic webhook to your logging system.

**Supported channels:**
| Channel | Type | Notes |
|---------|------|-------|
| 📱 Telegram | Bot API | Chat ID + bot token |
| 💬 Slack | Incoming webhook | One webhook URL |
| 🔔 ntfy | HTTP push | Self-hosted or ntfy.sh cloud, optional access token |
| 📲 Pushover | Mobile push | User Key + API token, $5 one-time |
| 🎮 Discord | Incoming webhook | Server webhook URL |
| 🔗 Generic Webhook | HTTP POST | JSON or text payload, custom headers |
| 📧 Email | SMTP | starttls, app passwords supported |

Each channel has a 🧪 Test button, per-channel enable/disable toggle, and configurable alert type list.

### 📊 New Dashboard Widgets

Two new optional widgets — both **off by default**. Enable via the ✨ Customize button on the dashboard.

**📈 Lease Sparklines per Subnet (30 days)**

One SVG sparkline card per subnet showing the hourly active lease count trend over the last 30 days. Each card displays:
- Subnet name and CIDR
- A rendered sparkline of the active lease count over time
- Current active count
- Trend delta vs 30 days ago (e.g. `+3` or `-2`)

Uses the existing `/api/lease-history?days=30` endpoint — no new database queries. Data comes from the lease history snapshots the background thread takes every 30 minutes. Will show a "no history yet" message until at least a day of snapshots has been collected.

**📱 Top Active Devices (30 days)**

A table of the 10 most recently active devices on your accessible subnets in the last 30 days. Each row shows:
- Device name or hostname (with MAC address as fallback)
- Last known IP address
- Subnet
- Last seen timestamp
- Manufacturer

Reserved devices are marked with a 📌 badge. The widget fully respects subnet access control — users restricted to specific subnets only see devices from those subnets.

Powered by new `GET /api/top-devices` endpoint.

---

## Patches — 3.5.1 through 3.5.6

### 3.5.1 — Migration Reliability Fix

The `admin → superadmin` promotion `UPDATE` was gated inside the ENUM expansion guard, so it only ran once. On some installs the ENUM change succeeded but the session cache still held the old role, causing "SuperAdmin access required" when navigating to the Users page.

Fixed by running the promotion `UPDATE` unconditionally on every startup — it's a no-op if there is nothing to promote.

If you deployed 3.5.0 and are seeing the error, run:
```sql
UPDATE users SET role='superadmin' WHERE role='admin';
```
Then log out and back in to clear the session cache.

---

### 3.5.2 — Access Control Audit (Six Gaps Fixed)

A full audit of all 3.5.0 changes found six places where the new role system was not applied consistently.

**Backend gaps:**
- `api.py` — Four API key management routes used inline `role != "admin"` checks, blocking SuperAdmins from managing API keys.
- `mfa.py` — With MFA set to "required for admins," SuperAdmin accounts were not prompted for MFA at login.

**Template gaps:**
- `servers.html` — SSH restart and sync buttons were hidden from SuperAdmins.
- `user_profile.html` — SuperAdmin accounts received the Viewer (grey) role badge.

**Subnet dropdown leakage:** Six routes were passing the unfiltered `SUBNET_MAP` to templates with subnet selection dropdowns. A restricted user would see all subnets in the `<select>` even though the data was correctly filtered. Fixed for `add_reservation`, `edit_reservation`, `edit_subnet`, `ipmap`, `reports`, and `search`.

---

### 3.5.3 — Scheduled Backups Were Silently Failing

Every scheduled backup run was failing with `BadGzipFile` since the feature was introduced in 3.4.0. The `run_scheduled_backup()` function called `gzip.decompress()` on bytes that were never compressed — `export_jen()` and `export_kea()` return plain JSON bytes; only `_write_backup()` applies gzip compression when writing to disk. The manual "Back Up Now" button worked correctly because it used the right pattern. Fixed by removing the spurious `gzip.decompress()` call.

Secondary fix: the guard preventing duplicate same-day backups now handles both Python `datetime` objects and string-formatted dates returned from the DB.

---

### 3.5.4 — Full End-to-End Audit (Two Fixes)

Complete audit of 34 Python files, 41 templates, 7 version strings, security posture, permission matrix, subnet filter coverage, HTMX partials, blueprint registration, DB schema, session cache, and installer.

- Stale `admin_required` decorator removed from `__init__.py` — dead code with the old `role != "admin"` check, left over before `access.py` was created.
- Test suite updated — `conftest.py`, `test_auth.py`, `test_users.py`, and `test_reservations.py` were all creating test users with `role='admin'`. Updated to `'superadmin'`.

---

### 3.5.5 — See "What's New — 3.5.5" above

---

### 3.5.6 — Password Column Width Migration Fix

Setting a user's password via the new edit modal failed with `(1406, "Data too long for column 'password' at row 1")` on some installations. The migration that widens the `password` column only matched `varchar(256)` exactly. Installations with any other column size never got widened. The migration now parses the actual numeric width from `SHOW COLUMNS` and widens to `VARCHAR(512)` whenever the current width is less than 512.

---

## Version History (3.5.x)

| Version | Date | Description |
|---------|------|-------------|
| 3.5.0 | 2026-05-19 | Three-tier roles, subnet-level access control, shared access module |
| 3.5.1 | 2026-05-19 | Fix admin→superadmin migration not running reliably on existing installs |
| 3.5.2 | 2026-05-19 | Audit: fix SuperAdmin gaps in API keys, MFA, server buttons, profile badge, subnet dropdowns |
| 3.5.3 | 2026-05-19 | Fix scheduled backups silently failing with BadGzipFile since 3.4.0 |
| 3.5.4 | 2026-05-19 | Full audit: remove stale decorator, fix test suite role references |
| 3.5.5 | 2026-05-19 | Users page redesign: clean table, edit modal, password reset, MFA reset |
| 3.5.6 | 2026-05-19 | Fix password column migration matching any width < 512, not just varchar(256) |
| 3.5.7 | 2026-05-19 | Pushover alerts, multi-channel support, sparklines widget, top devices widget |

---

## Upgrading

No config file changes. No manual DB steps.

```bash
cd ~
tar xzf jen-v3.5.7.tar.gz
cd jen
sudo ./install.sh
```

The installer runs all DB migrations automatically on startup. Your existing admin account will be promoted to SuperAdmin. Log out and back in after the first startup to pick up the new role from a fresh session.

---

## Permission Matrix

| Feature | ⭐ SuperAdmin | 🔧 Admin | 👁️ Viewer |
|---------|-------------|---------|---------|
| Leases / Reservations / Devices | All subnets | Assigned subnets | Assigned subnets (read-only) |
| Dashboard | All subnets | Assigned subnets | Assigned subnets (read-only) |
| Network / Subnets | ✅ All | ✅ Assigned | 👁️ Assigned |
| Edit Subnet | ✅ | ✅ Assigned | ❌ |
| Reports | ✅ All | ✅ Assigned | 👁️ Assigned |
| Settings | ✅ | ✅ | ❌ |
| Database | ✅ | ✅ | ❌ |
| Audit Log | ✅ | ✅ | ❌ |
| User Management | ✅ | ❌ | ❌ |
| Assign roles / subnets | ✅ | ❌ | ❌ |

---

*Jen is a self-hosted DHCP infrastructure management UI for ISC Kea.*
*GPL v3 — Copyright 2026 Matthew Thibodeau*
