# Jen v3.5.6 — Release Notes
**Released:** 2026-05-19
**Series:** 3.5.x — Multi-Tenancy, Access Control & User Management

---

## Overview

The 3.5.x series delivers the most significant architectural change in Jen's history: a full three-tier role system with subnet-level access control, a completely redesigned user management page, and a cascade of audit-driven fixes that hardened the implementation after the initial release. Every data-bearing page in the application is now filtered by what the logged-in user is permitted to see.

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
- **Edit Subnet** — access check before the form loads; subnet dropdown filtered
- **`/api/stats` endpoint** — only returns stats for assigned subnets

Setting `subnet_access = NULL` (the default) means "all subnets" — unrestricted. SuperAdmins are always unrestricted regardless of what's stored.

### 🏗️ Shared Access Control Module

A new `jen/services/access.py` replaces the duplicated `_admin_required` decorator that previously lived in every single route file. It provides:

- `superadmin_required` — decorator for user management routes
- `admin_required` — decorator for settings, database, subnet editing
- `add_subnet_restriction()` — appends a `WHERE subnet_id IN (...)` clause to any query based on the current user's access list

### 🗃️ Database Migration

Two `ALTER TABLE` statements run automatically on startup:

```sql
ALTER TABLE users MODIFY COLUMN role ENUM('superadmin','admin','viewer') NOT NULL DEFAULT 'viewer';
ALTER TABLE users ADD COLUMN subnet_access JSON DEFAULT NULL;
```

All existing `admin` users are promoted to `superadmin`. Existing `viewer` users get `subnet_access = NULL` (all subnets — no change in what they can see). Zero manual steps required.

---

## What's New — 3.5.5

### 👤 Users Page — Complete Redesign

The user management page was rebuilt from a cluttered inline-form table into a clean read-only table with a proper edit modal.

**Clean table view.** Each row shows Username, Role badge (⭐/🔧/👁️), Subnet access summary, MFA status, and Session timeout as read-only values. No inline forms cluttering the table cells.

**✏️ Edit modal per user.** A single Edit button per row opens a modal pre-populated with that user's current settings. Everything is in one place:

- **Role** — selector (disabled when editing your own account)
- **Subnet access** — multi-select; hidden automatically when SuperAdmin is chosen
- **Session timeout** — override the global default per user
- **Password reset** — set a new password for any user; leave blank to keep the current one
- **MFA reset** — wipe a user's MFA enrollment (methods, backup codes, trusted devices) so they re-enroll on next login; button disabled if no MFA enrolled
- **Delete** — with confirmation; hidden when editing your own account

**＋ Add User button** in the page header opens a creation modal with all fields: username, password, role, subnet access, and session timeout.

**"Change my password" removed** from this page — it's on the profile page, which is the right place.

**New routes:**
- `POST /users/edit/<id>` — unified edit (role + subnets + timeout + optional password reset)
- `POST /users/reset-mfa/<id>` — wipe MFA enrollment for a user (SuperAdmin only)

**Protections:**
- Cannot delete your own account
- Cannot demote your own account from SuperAdmin
- Cannot delete or demote the last SuperAdmin account

---

## Patches — 3.5.1 through 3.5.6

### 3.5.1 — Migration Reliability Fix

The `admin → superadmin` promotion `UPDATE` was gated inside the ENUM expansion guard, so it only ran once. On some installs the ENUM change succeeded but the session cache still held the old role, causing "SuperAdmin access required" when navigating to the Users page.

Fixed by running `UPDATE users SET role='superadmin' WHERE role='admin'` unconditionally on every startup — it's a no-op if there's nothing to promote.

If you deployed 3.5.0 and are seeing the error, run:
```sql
UPDATE users SET role='superadmin' WHERE role='admin';
```
Then log out and back in to clear the session cache.

---

### 3.5.2 — Access Control Audit (Six Gaps Fixed)

A full audit of all 3.5.0 changes found six places where the new role system wasn't applied consistently.

**Backend gaps:**

- **`api.py`** — Four API key management routes used inline `role != "admin"` checks. SuperAdmins were blocked from creating or managing API keys. Fixed to `role not in ("superadmin", "admin")`.
- **`mfa.py`** — With MFA set to "required for admins," SuperAdmin accounts were not prompted for MFA at login. Fixed to include `superadmin` in the check.

**Template gaps:**

- **`servers.html`** — SSH restart/sync buttons were hidden from SuperAdmins (two places).
- **`user_profile.html`** — SuperAdmin accounts got the Viewer (grey) role badge instead of the Admin (blue) one.

**Subnet dropdown leakage (most important):**

Six routes were passing the full unfiltered `SUBNET_MAP` to templates with subnet selection dropdowns. A restricted user would see all subnets in the `<select>` even though the data was correctly filtered. All now pass `current_user.filter_subnet_map()`:

- `add_reservation`, `edit_reservation`, `edit_subnet`, `ipmap`, `reports`, `search`

---

### 3.5.3 — Scheduled Backups Were Silently Failing

Every scheduled backup run was failing with a `BadGzipFile` exception that was silently swallowed. The only visible sign was `"Jen: FAILED — not a gzip file"` in the `last_status` column of the backup schedule table.

`run_scheduled_backup()` was calling `gzip.decompress(content)` on bytes returned by `export_jen()` and `export_kea()` — which return plain JSON bytes, not gzip-compressed data. The manual "Back Up Now" button worked fine because it used the correct pattern. Fixed by removing the spurious `gzip.decompress()` call.

Secondary fix: the guard preventing duplicate same-day backups now handles both Python `datetime` objects and string-formatted date values from the DB.

---

### 3.5.4 — Full End-to-End Audit (Two Fixes)

Complete audit of 34 Python files, 41 templates, 7 version strings, security posture, permission matrix, subnet filter coverage, HTMX partials, blueprint registration, DB schema, session cache, and installer.

Two real issues found and fixed:

- **Stale `admin_required` in `__init__.py`** — a dead decorator with the old `role != "admin"` check, left over before `access.py` existed. Not imported anywhere so no runtime risk, but removed for clarity.
- **Test suite using old `'admin'` role** — `conftest.py`, `test_auth.py`, `test_users.py`, and `test_reservations.py` were all setting up test users with `role='admin'`. Since that role no longer exists as the top-level admin, tests would fail if run. Updated to `'superadmin'` throughout.

---

### 3.5.5 — See "What's New — 3.5.5" above

---

### 3.5.6 — Password Column Width Migration Fix

Setting a user's password via the new edit modal failed with `(1406, "Data too long for column 'password' at row 1")` on some installations.

The migration that widens the `password` column only matched `varchar(256)` exactly. Installations with any other initial column size (e.g. `varchar(128)`, `varchar(255)`) never got widened. The migration now parses the actual numeric width from `SHOW COLUMNS` and widens to `VARCHAR(512)` whenever the current width is less than 512 — regardless of what the original size was.

---

## Version History (3.5.x)

| Version | Date | Description |
|---------|------|-------------|
| 3.5.0 | 2026-05-19 | Three-tier roles, subnet-level access control, shared access module |
| 3.5.1 | 2026-05-19 | Fix admin→superadmin migration not running reliably on existing installs |
| 3.5.2 | 2026-05-19 | Audit: fix SuperAdmin gaps in API keys, MFA, server buttons, profile badge, subnet dropdowns |
| 3.5.3 | 2026-05-19 | Fix scheduled backups silently failing with BadGzipFile |
| 3.5.4 | 2026-05-19 | Full audit: remove stale decorator, fix test suite role references |
| 3.5.5 | 2026-05-19 | Users page redesign: clean table, edit modal, password reset, MFA reset |
| 3.5.6 | 2026-05-19 | Fix password column migration matching any width < 512, not just varchar(256) |

---

## Upgrading

No config file changes. No manual DB steps.

```bash
cd ~
tar xzf jen-v3.5.6.tar.gz
cd jen
sudo ./install.sh
```

The installer runs all DB migrations automatically on startup. Your existing admin account will be promoted to SuperAdmin. Log out and back in after the first startup to pick up the new role from a fresh session.

---

## Permission Matrix Reference

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

## Coming Next

- **3.5.x** — Notification channels: ntfy.sh, Pushover, Slack (multiple simultaneous channels with per-channel enable/disable and test buttons)
- **3.5.x** — Dashboard widgets: top devices by activity, lease history sparklines per subnet (30-day, optional, off by default)

---

*Jen is a self-hosted DHCP infrastructure management UI for ISC Kea.*
*GPL v3 — Copyright 2026 Matthew Thibodeau*
