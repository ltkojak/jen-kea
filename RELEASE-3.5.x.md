# Jen v3.5.3 — Release Notes
**Released:** 2026-05-19
**Series:** 3.5.x — Multi-Tenancy & Access Control

---

## Overview

The 3.5.x series delivers the biggest architectural change in Jen's history: a full three-tier role system with subnet-level access control. Every data-bearing page in the application is now filtered by what the logged-in user is permitted to see. The 3.5.1 through 3.5.3 patches address migration issues, access control gaps found during audit, and a silent failure in the scheduled backup system.

No breaking changes to the API. No config file changes required. Drop-in upgrade from any 3.4.x release — existing admin accounts are promoted to SuperAdmin automatically.

---

## What's New — 3.5.0

### ⭐ Three-Tier Role System

Jen now has three distinct roles instead of two:

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

### 👤 Updated User Management Page

The Users page is now SuperAdmin-only. It was redesigned around the new role model:

- **Role** — inline dropdown per user, changes apply immediately on selection
- **Subnet Access** — multi-select per user; choose specific subnets or "All Subnets"
- **SuperAdmin users** show "All (unrestricted)" for subnet access — the field is not editable for them
- **Protections built in:**
  - Cannot delete the last SuperAdmin account
  - Cannot demote the last SuperAdmin to a lower role
  - Cannot demote your own account from SuperAdmin
- **Role reference card** on the page explains the permission matrix at a glance
- **Add User form** hides the subnet selector when SuperAdmin is chosen (SuperAdmins can't be restricted)

New routes added (SuperAdmin only):
- `POST /users/set-role/<id>`
- `POST /users/set-subnets/<id>`

### 🏗️ Shared Access Control Module

A new `jen/services/access.py` replaces the duplicated `_admin_required` decorator that previously lived in every single route file. It provides:

- `superadmin_required` — decorator for user management routes
- `admin_required` — decorator for settings, database, subnet editing
- `add_subnet_restriction()` — helper that appends a `WHERE subnet_id IN (...)` clause to any query based on the current user's access list

### 🗃️ Database Migration

Two `ALTER TABLE` statements run automatically on startup:

```sql
ALTER TABLE users MODIFY COLUMN role ENUM('superadmin','admin','viewer') NOT NULL DEFAULT 'viewer';
ALTER TABLE users ADD COLUMN subnet_access JSON DEFAULT NULL;
```

All existing `admin` users are promoted to `superadmin`. Existing `viewer` users get `subnet_access = NULL` (all subnets — no change in what they can see). Zero manual steps required.

---

## Patches — 3.5.1 through 3.5.3

### 3.5.1 — Migration Reliability Fix

The `admin → superadmin` promotion `UPDATE` was gated inside the ENUM expansion guard, so it only ran once. If the ENUM change succeeded but the session cache still held the old role, existing users would land on the dashboard and see "SuperAdmin access required" when navigating to Users.

Fixed by running `UPDATE users SET role='superadmin' WHERE role='admin'` unconditionally on every startup — it's a no-op if there's nothing to promote, and it costs one cheap query. The ENUM `ALTER TABLE` remains guarded since that is not idempotent.

If you deployed 3.5.0 and are seeing the SuperAdmin error, either upgrade to 3.5.1+ or run:
```sql
UPDATE users SET role='superadmin' WHERE role='admin';
```
Then log out and back in to clear the session cache.

---

### 3.5.2 — Access Control Audit (Six Gaps Fixed)

A full audit of all 3.5.0 changes found six places where the new role system wasn't applied consistently:

**Backend:**

- **`api.py` — API key management blocked SuperAdmins.** Four routes (`/settings/api-keys`, create, revoke, delete) used inline `role != "admin"` checks rather than the shared decorator. SuperAdmins couldn't create or manage API keys. Fixed to `role not in ("superadmin", "admin")`.

- **`mfa.py` — MFA `required_admins` mode excluded SuperAdmins.** With MFA set to "required for admins," SuperAdmin accounts were not prompted for MFA at login. Fixed to include `superadmin` in the check.

**Templates:**

- **`servers.html` — SSH action buttons hidden from SuperAdmins.** The restart and sync buttons were gated on `role == 'admin'` in two places. SuperAdmins couldn't use them.

- **`user_profile.html` — Wrong role badge for SuperAdmin.** The profile page showed the `badge-admin` style only for `admin` role, so SuperAdmin accounts got the `badge-viewer` (grey) styling instead.

**Subnet dropdown leakage (most important):**

Six routes were passing the full unfiltered `SUBNET_MAP` to templates that render subnet selection dropdowns. A restricted user would see all subnets in the `<select>` even though the data behind them was correctly filtered. All now pass `current_user.filter_subnet_map()`:

- `add_reservation`
- `edit_reservation`
- `edit_subnet` GET (also now checks `can_access_subnet()` before the form loads)
- `ipmap`
- `reports` (also filters the data iteration loop)
- `search`

---

### 3.5.3 — Scheduled Backups Were Silently Failing

Every scheduled backup run was failing with a `BadGzipFile` exception that was swallowed silently. The only visible sign was `"Jen: FAILED — not a gzip file"` / `"Kea: FAILED — not a gzip file"` in the `last_status` column of the backup schedule table — easy to miss.

**Root cause:** `run_scheduled_backup()` called `gzip.decompress(content)` on the bytes returned by `export_jen()` and `export_kea()`. Those functions return plain JSON bytes — they are not gzip-compressed. Gzip compression only happens inside `_write_backup()` when the file is written to disk. The manual "Back Up Now" button used the correct pattern (`json.loads(content.decode("utf-8"))`) and worked fine — this bug was isolated to the scheduled code path.

**Fix:** Removed the spurious `gzip.decompress()` call. Scheduled backups now match the manual backup pattern exactly.

**Secondary fix:** The guard that prevents a backup running twice in one day (`last_run.date() == now.date()`) used `hasattr(last_run, "date")` which only works when pymysql returns a Python `datetime` object. Made it handle string-formatted dates too, so it can't be bypassed by an unexpected return type.

---

## Version History (3.5.x)

| Version | Date | Description |
|---------|------|-------------|
| 3.5.0 | 2026-05-19 | Three-tier roles, subnet-level access control, new Users page |
| 3.5.1 | 2026-05-19 | Fix admin→superadmin migration not running reliably on existing installs |
| 3.5.2 | 2026-05-19 | Audit: fix SuperAdmin gaps in API keys, MFA, server buttons, profile badge, subnet dropdowns |
| 3.5.3 | 2026-05-19 | Fix scheduled backups silently failing with BadGzipFile since 3.4.0 |

---

## Upgrading

No config file changes. No manual DB steps.

```bash
cd ~
tar xzf jen-v3.5.3.tar.gz
cd jen
sudo ./install.sh
```

The installer will run the DB migrations automatically on startup. Your existing admin account will be promoted to SuperAdmin. Log out and back in after the first startup to pick up the new role from a fresh session.

---

## Known Issues / Coming Next

- **3.5.1 (Notification channels):** ntfy.sh, Pushover, Slack. Multiple simultaneous channels with per-channel enable/disable and test buttons.
- **3.5.2 (Dashboard widgets):** Top devices by activity, lease history sparklines per subnet (30-day view). Both optional, off by default.
- The mobile drawer open animation was removed in 3.3.10 (iOS `translateY` reliability). A `max-height` CSS transition replacement is planned as part of 3.5.1 polish.

---

*Jen is a self-hosted DHCP infrastructure management UI for ISC Kea.*
*GPL v3 — Copyright 2026 Matthew Thibodeau*
