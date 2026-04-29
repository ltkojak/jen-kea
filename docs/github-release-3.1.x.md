# Jen v3.1.0 — HTMX

This release completes the 3.0 roadmap. Jen now uses HTMX for partial page updates on the most-used pages — no full reloads, no scroll position resets, no waiting.

---

## What's New

### HTMX — Partial Page Updates

HTMX 1.9.12 is now included. It's served locally from `/static/js/htmx.min.js` — downloaded automatically during install if internet is available, and works fully offline after that. No CDN dependency. No JavaScript frameworks. No build step.

**Reservations**

- **Delete a reservation** — the row disappears instantly. The rest of the page doesn't move. No full reload, no scroll reset, no flash message round trip.
- **Filter by subnet or search** — the table updates live as you type (400ms debounce) or the moment you change the subnet dropdown. No submit button required.
- Both features degrade gracefully to standard form POST/GET if JavaScript is unavailable.

**Leases**

- **Filter by subnet, time window, or search** — table updates live without reloading the page. Changing a busy subnet from "All" to "IoT" is instant.

**Devices**

- Already had JavaScript modal editing — behaviour unchanged, no HTMX needed there.

---

## What Came Before — The Full 3.x Story

### 3.0.0 — Connection Pooling + Test Suite

**Connection pooling** (`dbutils.pooled_db.PooledDB`) replaced raw `pymysql.connect()` calls. Previously every DB operation opened a fresh TCP connection — ~1 second on a remote database server. Now Jen maintains 2 persistent connections to each database, opened at startup and reused indefinitely. Every request costs ~0ms for connection overhead instead of ~1s.

**69-test pytest suite** covering all critical paths — auth, dashboard, leases, reservations, users, settings. Tests run against a separate `jen_test` database, mock the Kea API, and reset state between each test. Run with `pytest tests/ -v`.

### 3.0.2 — Bugs Found by Tests

The test suite immediately found two production bugs that had been present since the 2.6.x modularization:

- `MAC_RE` and `HOST_RE` undefined in `jen/services/auth.py` — every reservation add and edit that validated a MAC address was raising `NameError`. MAC validation was silently not working.
- `SUBNET_NAMES` undefined in `jen/routes/search.py` — global search was 500-ing on every request.

Both fixed. This is exactly what the test suite is for.

---

## Upgrading

```bash
cd ~
tar xzf jen-v3.1.0.tar.gz
cd jen
sudo ./install.sh
```

The installer downloads HTMX during install. After that Jen works fully offline.

**Run the test suite after upgrading:**
```bash
~/.local/bin/pytest tests/ -v
```

All 69 tests should pass. If any fail, the output tells you exactly what's wrong before it affects production.

---

## What's Next

The foundation is solid. Future work:

- **HTMX on more pages** — devices inline edit, settings saves without reload
- **More test coverage** — DDNS, alerts, MFA flows
- **Reports improvements** — historical lease data visualisation
