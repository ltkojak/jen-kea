# Plugin registry

`registry.json` is the list Settings → Plugins fetches (from
`raw.githubusercontent.com/ltkojak/jen-kea/main/plugins/registry.json`)
to show available plugins and drive install/update. It is the **source
of truth** for every field an entry has — `install_plugin()` and
`fetch_registry()` (`jen/services/plugins.py`) trust it as-is; neither
live-fetches anything from the plugin's own repository to correct it.

## Releasing a new plugin version

Each plugin (`jen-plugin-ipam`, `jen-plugin-network-discovery`) lives in
its own repository and ships a `plugin.zip` at its root. A release is
**one commit here** that does all of the following together — an entry
with any one of these stale is worse than not updating at all:

1. In the plugin's own repo: bump `manifest.json`'s `version`, add the
   matching top entry to its `CHANGELOG.md`, run
   `python3 tools/verify.py --build` (rebuilds `plugin.zip`
   deterministically from the tree and runs the same checks its CI
   runs), commit, push, wait for its CI to go green, then tag `vX.Y.Z`
   and push the tag. The zip is built with fixed timestamps from an
   LF-normalised tree, so the `sha256` it prints is the one the
   published tag will have. (v1.4.1 of ipam shipped as a version bump
   only because its zip was never rebuilt — the CI now refuses a zip
   that isn't byte-for-byte a rebuild of the tree.)
2. Confirm the `sha256` of the zip actually published at the tag:
   ```bash
   curl -fsSL https://github.com/ltkojak/jen-plugin-<id>/raw/vX.Y.Z/plugin.zip | sha256sum
   ```
3. Update this repo's `plugins/registry.json` for that plugin:
   - `download_url` → `https://github.com/ltkojak/jen-plugin-<id>/raw/vX.Y.Z`
     (the **tag**, never `main` — `main` moves, a tag doesn't, so the
     checksum below stays valid forever once committed)
   - `sha256` → the value from step 2, lowercase hex
   - `version`, `description`, `requires_jen`, `db_migrations`, `nav`,
     `changelog_url` → equal to that same tag's `manifest.json`
4. Resync the bundled copy under `plugins/<id>/` from the same tag —
   `manifest.json`, `plugin.py`, `templates/`, `CHANGELOG.md`,
   `README.md` (never `plugin.zip` or a `.enabled` file). The bundled
   copy is what a fresh install sees before it ever fetches this
   registry, and what CI's real-manifest migration tests run against
   both MariaDB and MySQL 8.

There is no live sync between this file and the plugin repos (v5.21.1 —
there used to be, for `version`/`description`/`db_migrations`; it was
removed because it read `main`, which could report a version and
migration list that didn't match what `install_plugin()` actually
downloads and checksums from a pinned tag). What there is instead
(v5.28.2) is a test: `tests/test_plugin_registry.py::TestBundledCopiesMatchRegistry`
fails CI if a registry entry's version or manifest fields differ from
the bundled copy's, so steps 3 and 4 can't land separately.

## What a plugin can ask Jen for (v5.30.0)

Three hooks exist beyond `register(app)`. Each is optional; a plugin
that uses one should set `requires_jen` to `5.30.0` or later.

`requires_jen` is compared on the numeric version only (v5.32.0): a Jen
running a pre-release of a version — `5.33.0-beta.1` — satisfies a plugin
that requires `5.33.0`, because the beta *is* that version, early. A
plugin cannot require a beta specifically; `requires_jen` is always a
plain `X.Y.Z`.

### OS packages — `"os_packages": ["nmap"]`

Debian/Ubuntu package names whose binary of the same name the plugin
shells out to. Jen never runs `apt` from the web process: Settings →
Plugins shows *"needs on the Jen host: nmap"* with an **Install**
button on a systemd host (the root-run `jen-plugin-install.service`
installs it — the same request/execute split as plugin installs, and
only packages in the root script's built-in allowlist, currently
`nmap`, are ever installed; ask for the list to be widened in a Jen
release before declaring anything else) or the `apt install` command
elsewhere. Put the same list in the plugin's registry entry — the root
side reads the registry, not the marker. In code, check for the binary
at call time (`shutil.which("nmap")`), never at import.

### Periodic jobs — `register_periodic(plugin_id, name, fn, every_minutes)`

`from jen.plugin_api import register_periodic`, called from
`register(app)`. `create_app()` must not start background work, so a
plugin never starts its own thread: it registers a callable and Jen's
one periodic loop (started only by the real entrypoint, never in the
test suite) runs it every `every_minutes` (the first run is one interval
after startup). The floor is `PERIODIC_MIN_MINUTES` (5, in
`jen/services/background.py`): a shorter interval makes `register_periodic`
raise `ValueError` at register time, which fails your `register(app)`: Jen logs "Failed to load plugin"
and the plugin does not load (none of its
routes exist). Do not catch that error to carry on with a
shorter loop; register at five or more. Each run is wrapped — an exception is
logged and recorded on the job, never propagated — and a run still in
progress when the next tick comes is skipped, not stacked.
`periodic_jobs()` lists what's registered.

### Subnet context — `subnet_context(subnet_id)`

`from jen.plugin_api import subnet_context, classify_address, in_pool`.
One dict with everything Jen already knows about a subnet: gateway(s)
and DNS from the effective DHCP options (global → shared-network →
subnet precedence), the pools, network and broadcast, the Kea servers'
own addresses and the Jen host's, and the subnet's notes — plus
`classify_address(ctx, ip)` (`gateway` / `dns` / `network` /
`broadcast` / `kea-server` / `jen-host` / `None`) and `in_pool(ctx,
ip)`. The Kea config behind it is one cached `config-get` (30 s), so
calling it per page render adds nothing. Use it before calling an
address "unknown" or "available".

## The plugin API surface — `jen.plugin_api` (v5.34.0)

A plugin imports from **`jen.plugin_api` and nowhere else inside `jen`**.
It is a thin, versioned re-export of what plugins have needed so far;
nothing new lives behind it, and importing it does no work:

| Area | Names |
|---|---|
| Database | `jen_db()`, `kea_db()`, `kea6_db()` (context managers, preferred); `get_jen_db()`, `get_kea_db()` (raw connections — close what you open) |
| Audit & settings | `audit(action, entity, details)`, `get_global_setting(key, default)`, `set_global_setting(key, value)` |
| Access control | `assert_subnet_access(subnet_id)`, `get_accessible_subnet_map()`, `is_admin_or_above()`, `is_superadmin()`, decorators `admin_required`, `superadmin_required`, `viewer_or_above`; `can_access_subnet(subnet_id, *, allow_unattributed=False)` and `api_key_can_access_subnet(key, subnet_id, *, allow_unattributed=False)` (v5.65.2) |
| Diagnostic surface (v5.65.2) | decorator `diagnostic_surface(subject="client")` — mark a route that looks up one client (see below) |
| Client | `client_subnet_for_mac(mac)` → the subnet a client is in now, by Jen's ONE precedence (current lease, then reservation, then the device's last known subnet), or `None` — treat `None` as unrestricted-only via `can_access_subnet` (v5.65.6) |
| Subnets | `subnet_map()` (all IPv4 subnets), `subnet_context(subnet_id)`, `classify_address(ctx, ip)`, `in_pool(ctx, ip)`, `dhcp4_config()` |
| Alerts | `send_alert(alert_type, subnet_id=…, subject=…, body=…)` |
| Background | `register_periodic(plugin_id, name, fn, every_minutes)`, `unregister_periodic`, `periodic_jobs()` |
| Events (v5.42.0; `emit` added v5.57.0) | `subscribe(kind_or_"*", fn)`, `unsubscribe(fn)`, `emit(kind, **fields)`, `event_kinds` (the pinned kind vocabulary) |
| CSV | `safe_cell(value)`, `safe_row(values)` |
| Devices | `classify_device(mac, hostname)` → (manufacturer, type, icon) |
| Plugins | `installed_plugins()`, `is_systemd_host()` |
| Jen | `jen_version()`, `PLUGIN_API_VERSION` |
| Alert types (v5.57.0) | `register_alert_type(plugin_id, type_id, *, label, icon, default_template)` |
| Row actions (v5.57.0) | `register_row_action(plugin_id, surface, *, label, icon, href, method="GET", roles=(…), confirm=None, when=None)` |
| Search (v5.57.0) | `register_search_provider(plugin_id, *, title, fn)` |
| Plugin API routes (v5.57.0) | `api_key_required(write=False)`, `filter_subnet_ids(key_row, subnet_ids)` |
| Secrets (v5.57.0) | `encrypt_secret(plaintext)`, `decrypt_secret(stored)` |

```python
from jen.plugin_api import assert_subnet_access, audit, jen_db, subnet_context
```

### Events — `subscribe(kind_or_"*", fn)` / `unsubscribe(fn)` (v5.42.0)

Jen's event stream (`jen.services.events`, the record behind the
Timeline page and `GET /api/v1/events`) calls every subscriber after
each `emit()` — a plugin can react to `lease.new`, `reservation.added`,
`config.applied`, and the rest of the pinned kind vocabulary (`from
jen.plugin_api import event_kinds`) without polling. There is no
`emit()` in the plugin surface — plugins observe the stream, they don't
write to it; `discovery.unknown` is reserved for network-discovery's own
future use.

```python
from jen.plugin_api import subscribe, unsubscribe


def _on_new_lease(event):
    # event: {id, kind, mac, ip, subnet_id, hostname, server, actor, detail}
    ...


subscribe("lease.new", _on_new_lease)  # or subscribe("*", fn) for every kind
```

`fn` is called right after the row is written — keep it fast, and never
let it raise: an exception is logged and swallowed. Since v5.49.0-beta.2
subscribers run on **one shared worker thread**, not on the thread that
called `emit()` (whenever Jen's background workers are running — under the
gunicorn launcher, always): a slow subscriber delays the next subscriber,
never Jen. The hand-off queue holds 1000 events; past that, deliveries are
dropped and logged (the `events` row is still written, so the Timeline stays
complete). Outside the background workers (tests, CLI tools) `fn` is still
called inline. There's no `unsubscribe_all` — a plugin that
`register(app)`s a subscriber and can be disabled at runtime is
responsible for calling `unsubscribe(fn)` itself if it needs to stop
listening.

**Versioning.** `PLUGIN_API_VERSION` is `3` (v5.57.0 — the additions
below pushed it from `2`, which events itself pushed from `1`). Adding a
name is a MINOR Jen release and does not move it; removing a name or
changing a signature moves it and is a MAJOR for Jen. A manifest may
declare the version it was written against:

```json
"plugin_api": 3
```

Jen refuses to load a plugin whose `plugin_api` is newer than what it
offers — the Plugins page shows *needs plugin API vN* instead of the
plugin failing with an ImportError at boot. A plugin that uses the
surface should set `requires_jen` to `5.34.0` or later.

`tests/test_plugin_api.py` checks that the bundled copies import only
the surface (a short transitional list of internals is tolerated until
the plugins' own releases move over), and that every name they use is
offered by it.

### Emitting events — `emit(kind, **fields)` (v5.57.0)

The other side of `subscribe()`: a plugin can now write to the stream
Jen itself writes to (`jen.services.events`, the record behind Timeline
and `GET /api/v1/events`), not just observe it. `kind` must be
`plugin.<plugin_id>.<name>` (lowercase, `<plugin_id>` matching your own
manifest id) — anything else is refused and logged, `emit()` itself
never raises, matching its contract for every other failure mode.
Fields are the same as a core event: `mac`, `ip`, `subnet_id`,
`hostname`, `server`, `actor`, `detail`. Timeline and the dashboard's
Recent Events widget both render a plugin kind with a puzzle icon and
your plugin's display name instead of the raw kind string.

```python
from jen.plugin_api import emit

emit("plugin.watchdog.host_down", mac=mac, ip=ip, subnet_id=subnet_id, detail="3 missed pings")
```

### Registering an alert type — `register_alert_type(...)` (v5.57.0)

Adds your own entry to Settings → Alerts, selectable per channel and
editable per-install exactly like a core alert type (`kea_down`,
`new_lease`, …) — no separate code path. `type_id` must start with
`<plugin_id>_`, so two plugins can never collide. Call it from
`register(app)`, once per type, every time the plugin loads (it's a
cheap dict merge, not a database write):

```python
from jen.plugin_api import register_alert_type

register_alert_type(
    "watchdog",
    "watchdog_host_down",
    label="Host stopped responding",
    icon="triangle-alert",
    default_template="⚠️ <b>{subject}</b> stopped responding to ping.",
)
```

Send it the same way as any core type:

```python
from jen.plugin_api import send_alert

send_alert("watchdog_host_down", subnet_id=subnet_id, subject=hostname)
```

A custom template an admin saved for your type survives a plugin
upgrade (templates live in the settings-table-backed `alert_templates`
table by type id); if the plugin is later removed, the type simply
stops appearing on the settings page on the next registration pass —
its past `alert_log` rows are untouched.

### Adding a row action — `register_row_action(...)` (v5.57.0)

Adds a menu item to the Leases, Reservations or Devices row-action menu
(the "⋮" button on each row) — rendered fresh on every row, after the
built-in items, with the caller's own session (Jen's subnet rules and
the `roles` you pass are both enforced at render; enforce them again in
your own route, since a hidden menu item is not access control).
`href` is a format string; `{mac}`, `{ip}`, `{subnet_id}` and
`{hostname}` are filled in and URL-encoded per row.

```python
from jen.plugin_api import register_row_action

register_row_action(
    "watchdog",
    "lease",
    label="Ping now",
    icon="activity",
    href="/plugin/watchdog/ping?mac={mac}",
    roles=("admin", "superadmin"),
    confirm="Ping {mac} right now?",
)
```

`method="POST"` renders a form (with `csrf_token`) instead of a plain
link; `when(row)` is called per row if you only want the action to show
sometimes (a raising `when()` just hides it for that row).

### Adding a search result — `register_search_provider(...)` (v5.57.0)

Adds a card of results to `/search`, after Jen's own sections. `fn`
gets the query text and the CALLER's own subnet scope — return rows
outside it if you like, Jen drops them anyway (the same defence-in-depth
rule as every other subnet-scoped surface), so there's no harm in a
simple query that doesn't pre-filter. At most 20 rows are shown; a
provider that raises shows "unavailable" instead of breaking the page.

```python
from jen.plugin_api import register_search_provider


def _search(query, accessible_subnet_ids, all_subnets):
    hosts = find_matching_hosts(query)  # your own lookup
    return [
        {"title": h.name, "subtitle": h.ip, "href": f"/plugin/watchdog/host/{h.id}", "subnet_id": h.subnet_id}
        for h in hosts
    ]


register_search_provider("watchdog", title="Host Watchdog", fn=_search)
```

### Subnet checks — `can_access_subnet` / `api_key_can_access_subnet` (v5.65.2)

A route that acts on a row must check the row's OWN subnet, and a row with no
subnet must not be a way round the restriction. Core's rule
(docs/ARCHITECTURE.md §2) is: derive the subject's subnet server-side from where
the object actually is (never from a `subnet_id` the caller typed), check it before
acting, and treat "no attributable subnet" as **unrestricted callers only**. Both
helpers implement exactly that: `None` returns `False` for a subnet-restricted user
or key, `True` for an unrestricted one, and `allow_unattributed=True` is the
explicit, commented opt-out. Do not write `if sid is not None and sid not in
allowed: deny` — it makes `None` mean allow.

```python
from jen.plugin_api import api_key_can_access_subnet, can_access_subnet

if not can_access_subnet(row["subnet_id"]):  # a session user
    abort(403)
if not api_key_can_access_subnet(g.api_key, sid):  # an API key
    return jsonify({"error": "Not found."}), 404
```

### Client-facing routes — `diagnostic_surface` (v5.65.2)

A route that resolves ONE client (by MAC, IP or hostname) or reads the lease,
reservation, device, event or alert tables for a caller-chosen client is part of
Jen's diagnostic surface. Decorate it (innermost, directly above `def`) with
`@diagnostic_surface(subject="client")`. Jen collects the tagged routes after
plugins load and its authorization-matrix test requires every one to have a row
proving a subnet-restricted caller sees no other subnet's client through it; a
plugin route that reads those tables without the decorator fails Jen's own CI for
the bundled plugins.

### A plugin's own API routes — `api_key_required(...)` (v5.57.0)

For a plugin route mounted under `/api/v1/plugins/<plugin_id>/…`, using
the same Bearer API keys Jen's own REST v1 uses (Settings → Access &
Security → API Keys). Sets `flask.g.api_key` on success — `filter_subnet_ids`
narrows a list of subnet ids to what the key can access, the same
convention every other subnet-scoped surface follows. A request under
`/api/v1/` with a Bearer header is already CSRF-exempt.

```python
from flask import g, jsonify

from jen.plugin_api import api_key_required, filter_subnet_ids


@app.route("/api/v1/plugins/watchdog/hosts")
@api_key_required()
def watchdog_hosts():
    ids = filter_subnet_ids(g.api_key, all_watched_subnet_ids())
    return jsonify(hosts_in(ids))


@app.route("/api/v1/plugins/watchdog/silence/<int:host_id>", methods=["POST"])
@api_key_required(write=True)
def watchdog_silence(host_id): ...
```

Document your own plugin's endpoints in its README — Jen's
`/api/v1/openapi.json` deliberately doesn't list them (see its own
`description` field).

### Error text — log it, show a generic message (v5.65.7)

A failed database or filesystem call must not put its own exception text into a page or an API response: it names tables, columns, users and hosts. Log it (`logger.error(f"...: {e}")`) and show a generic sentence ("Could not save the target; the details are in Jen's log."; `{"error": "internal error; the details are in the Jen log"}` for an API). Jen's test suite (`tests/test_no_raw_exception_leaks.py`) scans every bundled plugin's `plugin.py` for `flash(f"...{e}")`, `flash(str(e))` and `jsonify(... str(e))` and fails on one. The only exceptions are messages written for the user, and the diagnostic of an integration the admin configured (a DNS server, a webhook, an SNMP switch): those go in that test's allow-list with the reason.

### Secrets — `encrypt_secret(plaintext)` / `decrypt_secret(stored)` (v5.57.0)

The same encryption Jen uses for MFA secrets and alert-channel tokens
(`jen/services/crypto.py`), for a plugin holding its own credential (an
API token, a device password). Store the returned `v1:…`-prefixed
string as a JSON string literal if the column is `JSON` (MariaDB
enforces `json_valid()` on every value in one) or a plain `VARCHAR`.

```python
from jen.plugin_api import decrypt_secret, encrypt_secret

token_to_store = encrypt_secret(raw_token)  # save this
raw_token = decrypt_secret(token_to_store)  # read it back
```

### Sprite icon names in `nav[].icon` (v5.57.0)

A manifest's `nav[].icon` can name a Lucide sprite icon directly —
`"icon": "activity"` — instead of an emoji; Jen's nav renderer already
resolves a recognized sprite name to the real icon and falls back to
plain text for anything else, so a legacy emoji manifest keeps working
unchanged.

## Writing migrations

`db_migrations` entries are `{"version": N, "description": "…", "sql":
"…"}` — explicit, strictly increasing, never reused or reordered (the
old positional flat-string form still loads, but a re-ordered edit
silently renumbers history). Write plain, portable DDL: Jen runs
against both MariaDB and MySQL 8, and MySQL has no `ADD COLUMN IF NOT
EXISTS` / `DROP INDEX IF EXISTS`. You don't need them: since v5.28.2
the runner records a migration whose only error is "duplicate column",
"duplicate key name" or "can't DROP — doesn't exist" as already
applied, so a plain `ALTER` is safe on a re-run and on a fresh database
that never had what it drops. A plugin that relies on that must set
`requires_jen` to `5.28.2` or later.

## Why a checksum is required

`install_plugin()` refuses outright if a registry entry has no
`sha256`, the same fail-closed rule the self-updater applies to its own
release tarball. Registry.json is fetched over HTTPS from this repo's
own `main` branch — a mutable ref, but it's the same trust root as the
app itself (see `docs/ARCHITECTURE.md` §3). The checksum's job isn't
protecting against that; it's making sure the specific tagged
`plugin.zip` a user's Jen instance downloads is byte-for-byte the one
that was actually reviewed and hashed here, not a rebuild, a
mid-transfer corruption, or a compromised plugin repository.
