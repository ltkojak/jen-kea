# Jen v3.2.9 — Dashboard, Alerts & Stability

This release series builds on the 3.0/3.1 foundation with a fully redesigned dashboard, a working alert system, consistent UTC timestamps throughout, and a significant number of bug fixes uncovered by the test suite and real-world use.

---

## What's New in 3.2.x

### Dashboard — Six New Widgets (3.2.0)

The dashboard went from a static snapshot to a genuinely useful monitoring tool.

**Utilization History Charts**
Each subnet now has a sparkline showing dynamic lease utilization over time, drawn with the Canvas API (no external charting library required). Color shifts from blue → yellow → red as utilization approaches threshold. Time range selector: 24h, 3d, 7d, 30d. Uses the `lease_history` table which has been collecting snapshots every 30 minutes since initial setup — the data was already there, just never displayed.

**Totals Summary**
New widget below the subnet cards showing aggregate counts across all subnets: total active leases, dynamic, reserved, overall pool utilization with a live progress bar, and subnet count. Updates with every api/stats poll.

**Alert Summary Widget**
Previously showed "No recent alerts" hardcoded. Now fetches from `/api/alert-summary` and displays the last 10 alerts with timestamp, type icon, delivery status, and error detail on hover. If all recent alerts failed to deliver, a warning banner links directly to alert configuration.

**Recent Leases — HTMX Time Window**
The time window dropdown (30min → 24h) on the Recent Leases widget now updates the table live via HTMX without reloading the page.

**Subnet Card Links**
Clicking a subnet stat card navigates to `/leases?subnet=ID`, filtered to that subnet. Previously clicking did nothing.

**Last Updated Timestamp**
"Updated HH:MM:SS UTC" displayed next to the refresh dot so you always know how fresh the data is.

**Customize Panel**
All six widgets are individually toggleable. Checkboxes now correctly reflect your saved preferences when the panel opens. Default layout includes History Charts, Totals, Subnet Statistics, and Recent Leases.

---

### Alert System Improvements (3.2.3 / 3.2.4 / 3.2.7)

**Test alert button fixed** — The Test button on each alert channel was throwing `NameError: name '_send_telegram_channel' is not defined`. Six send functions were being called as bare names instead of through the module reference — a holdover from the 2.6.x modularization. Fixed for all channel types: Telegram, email, Slack, webhook, ntfy, Discord.

**`import requests` missing** — `alerts.py` and `settings.py` both used `requests.post()` without importing `requests`. Another 2.6.x modularization artifact. Fixed.

**Restart alert flood fixed** — On every Jen restart, `known_macs` started empty, causing "new device" alerts to fire for every device currently on the network. `known_macs` is now seeded from the `devices` table at startup so only genuinely new devices trigger alerts.

**True new-device detection** — "New device" alerts now only fire for MACs that have never appeared in the `devices` table at all, not just devices unseen since last restart.

**Alert log with error detail** — Settings → Alerts now shows the last 20 alerts with full error messages, so you can see exactly why a delivery failed instead of just seeing "failed".

---

### Consistent UTC Timestamps (3.2.8)

All timestamps across the UI now display in UTC consistently. Previously some areas showed server local time and others showed UTC — actively confusing in an IT context.

- New Jinja filters `|utcfmt`, `|utcdate`, `|utctime` applied across all 12 affected templates
- Dashboard "Last Updated" shows `HH:MM:SS UTC` using `getUTCHours()` instead of `toLocaleTimeString()`
- `alerts.py` daily summary was using `datetime.now()` without timezone — fixed to UTC
- Alert log timestamps in both the dashboard widget and Settings → Alerts show UTC suffix

---

### Bug Fixes Found by Test Suite

**`MAC_RE` and `HOST_RE` undefined** (`auth.py`) — Every reservation add and edit that validated a MAC address was raising `NameError`. MAC and hostname validation was silently not working since 2.6.x.

**`SUBNET_NAMES` undefined** (`search.py`) — Global search was 500-ing on every request since 2.6.x.

**`api/stats` missing `servers` key on error** — When the Kea DB query failed, the JSON response omitted the `servers` key, breaking dashboard server status updates.

**`DATE_FORMAT` PyMySQL escaping** — The lease history query used `%Y` and `%H` in SQL `DATE_FORMAT()` calls inside PyMySQL `execute()`. PyMySQL processes `%` as Python format characters, consuming `%Y` before the SQL reached MySQL. Fixed with `%%Y`, `%%H`.

**Canvas colors** — Sparkline charts were drawing invisible lines because Canvas API doesn't understand CSS variables like `var(--primary)`. Added `resolveCssColor()` to resolve CSS variables to actual hex values before drawing. Fill area uses proper `rgba()` syntax.

---

### Installer Fix (3.2.9)

The installer's template validation step was calling `exit 1` after the "Config file present" line, killing the install before the completion banner appeared. The validator used a bare Jinja environment that didn't know about Jen's custom filters (`|utcfmt` etc), causing every template to fail validation. Fixed by registering no-op versions of custom filters in the validation environment.

---

## Upgrading

```bash
cd ~
tar xzf jen-v3.2.9.tar.gz
cd jen
sudo ./install.sh
```

Run the test suite after upgrading:
```bash
cd ~/jen
~/.local/bin/pytest tests/ -v
```

All 69 tests should pass.

---

## Full 3.x Changelog

| Version | Summary |
|---|---|
| 3.0.0 | Connection pooling, 69-test suite |
| 3.0.2 | MAC_RE, SUBNET_NAMES bugs fixed by tests |
| 3.0.3 | Pool logging fix |
| 3.1.0 | HTMX: inline delete and live filter on reservations and leases |
| 3.2.0 | Dashboard: sparklines, totals, alert summary, HTMX recent leases, subnet links, last updated |
| 3.2.1–3.2.6 | Sparkline fixes: canvas layout, PyMySQL DATE_FORMAT escaping, CSS variable color resolution |
| 3.2.3–3.2.4 | Alert test button fixed, missing imports fixed |
| 3.2.7 | Alert restart flood fix, true new-device detection, alert log with errors |
| 3.2.8 | Consistent UTC timestamps throughout |
| 3.2.9 | Installer template validation fix |
