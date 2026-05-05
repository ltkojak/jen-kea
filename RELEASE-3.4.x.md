# Jen v3.4.4 — Release Notes
**Released:** 2026-05-05
**Series:** 3.4.x — Database Management & UI Polish

---

## Overview

The 3.4.x series delivered two major themes: a full **Database Management** feature set (3.4.0), and a round of **live filtering, pagination, and lease action button fixes** across the Management section (3.4.1–3.4.4). No database migrations, no breaking config changes, no API changes. Drop-in upgrade from any 3.3.x release.

---

## What's New — 3.4.0

### 🗄️ Database Management

A new top-level **Database** menu item — visible to admins only, hidden entirely from viewer accounts. Every screen clearly labels which database it is operating on: **Jen** (🟢 green — users, devices, settings, audit log, API keys) or **Kea** (🟡 yellow — reservations, DHCP options, active leases). The host and database name are shown on every panel so there is never any ambiguity.

**Export**

Download a compressed `.json.gz` export from either database. Jen exports let you choose individual tables (users, devices, settings, alerts, audit log, API keys, MFA data, saved searches, and more). Kea offers two clearly labelled export types:

- **Reservations** — `hosts` + `dhcp4_options` tables. These are your permanent MAC-to-IP assignments. This is the one you want for backups and migrations.
- **Active Leases** — `lease4` table. Dynamic, transient leases. Rarely needed, and clearly marked as such.

Every export file contains a metadata header with the Jen version, schema version, export timestamp, and table list — the file is self-describing.

**Import / Restore**

Upload an export file and Jen reads the metadata header first, showing you exactly what is in the file (tables and row counts) before touching any live data. Jen and Kea exports are automatically identified from the header — you cannot accidentally import a Kea file into Jen or vice versa. Schema version mismatches are detected and warned before proceeding. The import runs in a full transaction and rolls back completely on any failure. Jen imports support per-table selection and replace vs. merge mode. Kea imports support skip vs. overwrite duplicate handling.

**Scheduled Backups**

Configure automatic daily or weekly backups with a configurable retention count (keep last N files). Backups are saved to `/opt/jen/backups/` with `chmod 600` permissions — only readable by the Jen service user. APScheduler runs in-process so no cron entry is needed. The Backups tab lists all stored files with their database label (🟢/🟡), size, export date, table list, and per-file Download and Delete buttons. A "Back Up Now" button lets you run an on-demand backup at any time.

**Migration Wizard**

A three-step wizard for copying a database to a new server. Step 1: choose Jen or Kea, and optionally select which tables to migrate. Step 2: enter the target server credentials and run a live connection test — the wizard shows the MySQL version and existing table count before you proceed. Step 3: confirm and run. Migration progress streams to the browser in real-time. On any failure, the target database is fully rolled back and all created tables are dropped, leaving it completely clean. Row counts are verified on both sides before the transaction is committed.

**Pre-upgrade Backup Prompt**

The installer now asks "Create a database backup before upgrading? [Y/n]" before applying any upgrade. If confirmed, both Jen and Kea databases are exported to `/opt/jen/backups/` with the version stamp in the filename before any files are touched.

**New dependencies:** `apscheduler<4` (in-process scheduler), `paramiko` (SSH for subnet editing, added in 3.3.14).

**New DB table:** `backup_schedule` — a singleton row storing schedule config, last run time, and last run status.

---

## What Changed — 3.4.1 through 3.4.4

### 3.4.1 — Pagination & HTMX Overhaul (Leases, Reservations, Devices)

**Filters lost on page change.** The original pagination links did not carry all active filter parameters. Navigating to page 2 would silently drop the subnet filter, search term, sort order, or any combination of them. All three pages now include the complete filter state in every pagination link.

**Default changed to show all rows.** The previous hardcoded `LIMIT 50` is gone. By default all matching rows are returned. A "Show all / 50 / 100 / 250 per page" dropdown in each filter bar lets you opt into pagination when working with very large datasets. The chosen value is preserved through sorting, filtering, and pagination.

**HTMX live filtering added to Devices.** Leases and Reservations already had HTMX live filtering (results update as you type, no page reload). Devices was the only holdout — it used a plain GET form with `onchange=submit()`, causing a full page reload on every filter change. Replaced with the same HTMX pattern. A `_device_rows.html` partial was created so the initial page load and HTMX swaps share a single row template, matching the approach used on Leases (since v3.3.16) and Reservations.

**Type-filter badge links now preserve all active filters** — subnet, stale toggle, per_page, sort, and direction are all included.

---

### 3.4.2 — Devices HTMX Actually Fixed

The HTMX filter on Devices was not working despite the 3.4.1 changes. Two bugs:

HTMX collects input values by serializing the nearest `<form>` ancestor — but the filter bar in 3.4.1 was a `<div>` with HTMX attributes and no `<form>` wrapper. Every HTMX request fired with zero query parameters, returning all devices every time regardless of what was typed. Fixed by wrapping the inputs in `<form method="GET" style="display:contents;">` with the HTMX attributes on the form element, matching the pattern already working on Leases and Reservations.

Additionally the `type` filter parameter (set by the device-type badge bar) was missing from the form entirely, so combining a type badge selection with a search would silently drop the type. Added as a hidden input field.

---

### 3.4.3 — Leases: Smarter Action Buttons

Every active lease previously showed a 📌 "Create reservation" button and a ✕ "Release lease" button regardless of whether the device already had a reservation. Both were wrong for reserved devices:

- Creating a duplicate reservation would error in Kea or silently conflict.
- Releasing a lease for a reserved device is pointless — Kea immediately re-issues the same lease to the same MAC.

The leases route now cross-references the Kea `hosts` table using a single batch query against all MACs on the page (`WHERE HEX(dhcp_identifier) IN (...)`), with no per-row queries.

**New behaviour:**

| Device status | Buttons shown |
|---|---|
| Has a reservation | 📋 grey button → links to `/reservations?search=<MAC>` |
| No reservation | 📌 Create reservation + ✕ Release lease (unchanged) |

---

### 3.4.4 — Leases: Cursor-Closed Crash Fix

The reservation lookup added in 3.4.3 caused "Could not load leases: Cursor closed" on every page load immediately after deployment. The main lease query ran inside a `with db.cursor() as cur:` block. When that block exited the cursor was closed. The reservation lookup then called `cur.execute()` on the already-closed cursor outside the block. Fixed by opening a fresh `with db.cursor() as res_cur:` block for the reservation query.

---

## Version History (3.4.x)

| Version | Date | Description |
|---------|------|-------------|
| 3.4.0 | 2026-05-04 | Database Management — export, import, scheduled backups, migration wizard |
| 3.4.1 | 2026-05-04 | Pagination filters preserved; default show-all; HTMX on Devices |
| 3.4.2 | 2026-05-05 | Fix Devices HTMX: missing form wrapper and type filter param |
| 3.4.3 | 2026-05-05 | Leases: hide create/release for reserved devices; show view-reservation link |
| 3.4.4 | 2026-05-05 | Fix leases cursor-closed crash introduced in 3.4.3 |

---

## Upgrading

No database migrations. No config file changes. No API changes.

```bash
cd ~
tar xzf jen-v3.4.4.tar.gz
cd jen
sudo ./install.sh
```

The installer will detect `apscheduler` as a new dependency and install it automatically. Upgrade from any 3.3.x or earlier 3.4.x release is fully supported.

---

## Known Issues / Coming Next

- The database export format uses JSON rather than SQL. This is intentional for portability, but means exports are not directly consumable by `mysql` CLI. A future version may add a SQL export option.
- The Migration Wizard streams progress in real-time but does not yet support resuming a failed migration from where it left off — it always rolls back and starts clean.

---

*Jen is a self-hosted DHCP infrastructure management UI for ISC Kea.*
*GPL v3 — Copyright 2026 Matthew Thibodeau*
