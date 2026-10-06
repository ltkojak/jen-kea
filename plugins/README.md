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
| IPv6 access (v5.68.0-beta.8) | `can_access_subnet6(subnet6_id)` — may the session user see something in this v6 subnet? A paired v6 subnet follows its v4 subnet; an unpaired one is for unrestricted users only. Every bundled plugin is IPv4-only today, so nothing calls it yet; a plugin that ever looks at a v6 subnet must ask this, never compare the v6 id with the user's v4 list |
| Alert types (v5.57.0) | `register_alert_type(plugin_id, type_id, *, label, icon, default_template)` |
| Row actions (v5.57.0) | `register_row_action(plugin_id, surface, *, label, icon, href, method="GET", roles=(…), confirm=None, when=None)` |
| Search (v5.57.0) | `register_search_provider(plugin_id, *, title, fn)` |
| Investigation (v5.68.0-beta.4) | `register_investigation_provider(plugin_id, *, title, fn)` — `fn(subject, accessible_subnet_ids, all_subnets) -> card | None` |
| Plugin API routes (v5.57.0) | `api_key_required(write=False)`, `filter_subnet_ids(key_row, subnet_ids)` |
| Secrets (v5.57.0) | `encrypt_secret(plaintext)`, `decrypt_secret(stored)` |
| Helpers (v5.65.10) | `json_object_body()`, `str_field(body, name, max_len)`, `normalize_mac(raw)`, `like_pattern(text)`, `in_placeholders(values)`, `subnet_for_ip(ip)`, `search_scope(ids, all_subnets, column)`, `require_write()`, `subnet_or_404(subnet_id)`; `assert_subnet_access(subnet_id, *, notify=True)` — see "Helpers every plugin used to copy" below |

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

`register_investigation_provider` (v5.68.0-beta.4) is additive: `PLUGIN_API_VERSION` stays 3, and a plugin that uses it sets
`requires_jen` to `5.68.0` (a 5.68.0 beta satisfies it).

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
gets the query text and the CALLER's own subnet scope. Jen re-filters
every returned row against that scope (the same defence-in-depth rule as
every other subnet-scoped surface), but it does so AFTER your query has
run, so **your own `LIMIT` must come after your own subnet filter**: a
provider that limits to 20 rows and lets Jen filter them can spend all 20
on matches in subnets the caller cannot see and hand a restricted caller
nothing. Put the scope in the query with `search_scope()` (below) and match
the text with `like_pattern()`. At most 20 rows are shown; a provider that
raises, or has not answered within 1 s, shows "unavailable" instead of breaking the page (see *Provider budget*, below).

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

### Telling the Investigation page what you know about a client — `register_investigation_provider(...)` (v5.68.0-beta.4)

The Investigation page (`/client`) lays out what the core knows about one client. A plugin that knows a fact the core cannot — the
switch port a MAC sits on, whether a host answers a ping, which DNS records carry its name — adds ONE card under **What else Jen
knows** on the Overview, after the core facts. `fn` is handed the client Jen has already resolved, never a typed identifier:

```python
from jen.plugin_api import register_investigation_provider


def _investigate(subject, accessible_subnet_ids, all_subnets):
    row = find_port(subject.mac)  # your own lookup, scoped like a search provider's
    if not row:
        return None  # nothing to say: no card, no heading
    return {
        "summary": f"On {row.switch} port {row.port}",
        "status": "ok",  # "ok" | "warn" | "none"; warn also puts the summary in the page's one-line answer
        "href": f"/plugin/switchport/mac/{subject.mac}",  # your own page for this client
        "rows": [{"label": "Switch", "value": row.switch, "href": f"/plugin/switchport/switch/{row.switch_id}"}],
    }


register_investigation_provider("switchport", title="Switch Port Locator", fn=_investigate)
```

* `subject` is a read-only copy of the caller's authorized view of the client (`mac`, `ip`, `hostname`, `duid`, `subnet_ids`,
  `leases4`, `reservations`, `leases6`, `reservations6`, `device`). Editing it changes nothing anyone else sees. A provider never
  resolves the client itself.
* **Scope is yours and Jen's.** Jen only asks about a client the caller may see, and hands you the caller's own
  `accessible_subnet_ids` and `all_subnets` — put them in your own query (`search_scope()`, `can_access_subnet()`) exactly as a
  search provider does, and answer `None` rather than a row from a subnet outside them. A client the caller cannot place in a
  subnet is the page's ordinary "No client matched" answer and no provider is called at all. **Judge what you stored by the
  subnet it was stored in** (*Stored data*, below): never by where the client is now.
* The card is `{"summary": one sentence, "rows": [{"label", "value", "href"?}], "href", "status"}`. Jen validates and trims it:
  text is length-capped, at most 20 rows, an unknown `status` reads as `ok`, and any `href` that is not a single-slash path inside
  Jen is dropped. A card with neither summary nor rows is the same as `None`.
* Providers are shown in registration order and run with a hard 1.0 s budget (*Provider budget*, below). One that raises — or
  answers something that is not a card — shows "unavailable" and is logged; one that is too slow shows "unavailable (over 1 s)". It
  never breaks the page.
* Same cache rule as a search provider: do your own `LIMIT` after your own scope filter. Registered once, in `register(app)`.

### Stored data — judge it by its own subnet (v5.68.0-beta.11)

A plugin that keeps a row about a client (a favourite, a tracked device, a port a MAC was seen on, a scan result) holds a **stored
object**, and a stored object belongs to the subnet it was stored in — the subnet of the row, or of the thing the row is about (a
switch's subnet is the one its management address is in). That is the subnet a caller must be allowed to see to be shown it.
**Where the client is now never widens that.** A favourite saved in subnet B is not shown to a caller scoped to A because the
client's lease has since moved to A; the client's current subnet is a fact you may print beside the row ("now in ..."), and only
when the caller may see that subnet too, because naming a subnet is access to it. A row with no subnet is for an unrestricted caller
only, and so is a switch addressed by a hostname or by an address in no Kea subnet.

**The rule holds on every surface, not only the card** (v5.68.0-beta.12): the list page, a view by id, add or relabel over an existing row,
delete, a move, the search provider, the JSON API and the row action all judge a stored object on its own subnet. If one function answers
"may this caller see the row?", every surface calls it; a page that judges by the client's current subnet while the card judges by the stored
one is two plugins in one. A search row's `subnet_id` is the subnet of the object whose information the row prints (the switch's, the
favourite's), never the client's. A plugin that keeps a subnet column and lets an event rewrite it to follow the client has no stored subnet
at all: say what the column means (Presence's `pr_tracked.subnet_id` is the **owner** subnet, set when the device is tracked and changed only
by an explicit move by a caller who can see both subnets, audited) and derive the current location at read time.

**A live act is the other kind of thing, and it is kept apart.** A wake packet, a probe, a poll or a publish acts on a device, so it is
judged on where the device is now, because that is where the act lands. It never borrows what a stored object holds for it: if the caller may
not see the favourite, the favourite contributes nothing to the act - not its SecureOn password, not its stored subnet as a fallback - and
the act goes ahead without it (a NIC that wants the password simply ignores the packet), with no word that a hidden object exists. Wake &
Actions' `wake_inputs(favourite, current_subnet, can)` is the model: the same function serves the page, the row action and the API, with the
session's or the key's own predicate. A test proves it by recording what reaches the packet builder. Wake & Actions 1.1.2, Switch Port Locator
1.1.2 and Presence 1.2.0 are the reference, after 1.1.1 started them on the card: the pure `in_scope(subnet_id, accessible, all)` on the
stored subnet, a harness test for the client that moved from B to A, and a position-by-position filter for rows (switch positions)
whose subnet is derived rather than a column — filter *before* keeping the few you show, so hidden rows cannot push a visible one out.

### Provider budget — what Jen enforces on a provider (v5.68.0-beta.11)

Search and investigation providers are run by `jen/services/provider_budget.py`, not in the request thread. The page waits at most
`BUDGET_SECONDS` (1.0) for the providers as a group — they run concurrently, on a small shared pool, so several slow ones cost one
second, not one each. A provider that has not answered by then is shown as "unavailable (over 1 s)" and the page goes on; Python cannot
stop a thread that is running, so the call is logged once, counted, and its answer dropped when it arrives. At most 8 provider calls
are outstanding at once, and a slot is only returned when the call really ends: when they are all taken, a new call is not started and
the provider reads "unavailable (busy)". The practical rules for a provider: answer from your own tables with no network call in the
request path, give every query and socket its own timeout well under a second, and expect to run in a worker thread — the caller's
request (`current_user`, `request`, `url_for`) is there, a copy of it, but `flask.g` set earlier in the request is not.

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

`write=True` also applies Jen's per-key write limit: at most 60 write requests a minute per key, shared
with Jen's own write endpoints (a call over the budget is a 429), and a malformed write counts (the budget
is on calls). Read the request body with `json_object_body()` (below), so a JSON array is a 400 and not a
500.

Document your own plugin's endpoints in its README — Jen's
`/api/v1/openapi.json` deliberately doesn't list them (see its own
`description` field).

### Helpers every plugin used to copy (v5.65.10)

Seven plugins each carried their own copy of these, and the copies had drifted (two conventions for "not a
MAC", a `LIKE` that took a typed `%` literally in two plugins and as a wildcard in two others). They are one
import now, additive (`PLUGIN_API_VERSION` stays 3; a plugin using them sets `requires_jen` to `5.65.10`):

| Helper | What it does | The copied code it replaces |
|---|---|---|
| `json_object_body()` | `(dict, None)` for the request's JSON body, or `(None, (response, 400))` when it is an array, a string, a number or not JSON; no body is `{}` | `request.get_json(silent=True) or {}` followed by `.get`, which 500s on an array |
| `str_field(body, name, max_len=None)` | the field as a stripped, cut string; `""` when missing, null or not a string | `str(body.get("mac", ""))` and a bare `re.sub` on whatever arrived |
| `normalize_mac(raw)` | `aa:bb:cc:dd:ee:ff`, or `None` for anything that is not a MAC (blank and non-strings included) | `_normalize_mac` in six plugins, half returning `""` and half `None` |
| `like_pattern(text)` | `%text%` with `%`, `_` and backslash literal | IPAM's `_like_pattern`, Discovery's inline copy; Watchdog and Switch Port had none |
| `in_placeholders(values)` | `%s,%s,%s` for a dynamic `IN (...)`; an empty list gives `NULL` | `_in_placeholders` in three plugins |
| `subnet_for_ip(ip)` | the Kea subnet id whose CIDR holds the address, or `None` | `derive_subnet_id` / `_derive_subnet_id` in Watchdog, DNS Sync, Switch Port and Wake |
| `search_scope(ids, all_subnets, column)` | `(sql, params)` limiting a search provider's own query to the caller's subnets, or `None` when they may see nothing | a `LIMIT` before the filter, in four providers |
| `require_write(message=..., redirect_endpoint=...)` | route decorator, under `@login_required`: admins only, checked before the route reads the request; a JSON or `/api/` request gets a 403 body, a page a flash and a redirect | `_is_admin` + `_require_write` in seven plugins |
| `subnet_or_404(subnet_id)` | `(subnet, None)` or `(None, (json 404, 404))` for a JSON or poll route: no flash, one answer for "not there" and "not yours" | IPAM's history route and Discovery's status poll left a flash for the next page |
| `assert_subnet_access(subnet_id, notify=True)` | as before; `notify=False` queues no flash | the same |

```python
from jen.plugin_api import like_pattern, search_scope


def _search(query, accessible_subnet_ids, all_subnets):
    scope = search_scope(accessible_subnet_ids, all_subnets, "e.subnet_id")
    if scope is None:  # the caller may see no subnet at all
        return []
    clause, params = scope
    with jen_db() as db, db.cursor() as cur:
        cur.execute(
            f"SELECT ... FROM my_entries e WHERE e.label LIKE %s AND {clause} ORDER BY e.updated_at DESC LIMIT 20",  # nosec B608 - `clause` is `%s` placeholders only
            (like_pattern(query), *params),
        )
        return [...]
```

**A per-MAC row's stored `subnet_id` is a cache, not the truth.** A plugin that keeps a row per client (a
tracked device, a favourite, a switch-port sighting) stores the subnet it was in when the row was written,
and a client moves. To decide who may act on the row, judge `client_subnet_for_mac(mac)` first (Jen's one
precedence: current lease, then reservation, then the device's last known subnet) and use the stored value
only when that returns `None`. Presence judges it this way; a plugin that judged the stored value alone left
a client that had moved actionable by whoever could see its old subnet, and the rest are being moved onto the rule.

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

## Table ownership — what ends up in a backup or recovery bundle (v5.66.0-beta.5)

Jen derives which tables your plugin owns straight from your own
`db_migrations` DDL — it parses (never executes) every `CREATE TABLE`,
`DROP TABLE`, and `RENAME TABLE`/`ALTER TABLE … RENAME TO` across your
migrations and works out the set of tables that exist after all of them
have run. That derived set is what every export, scheduled backup, and
recovery bundle includes for your plugin — nothing to register, nothing
to keep in sync by hand as you add migrations.

This fails the plugin's own migration run (and its install) if the
derivation collides with a core Jen table name or another plugin's own
table — a naming accident here is exactly the kind of bug you want caught
at install time, not discovered the day someone restores a backup and
two plugins' rows landed in the same table.

If your ownership genuinely can't be expressed as "whatever my own DDL
creates" (a table your migrations only ever `ALTER`, never `CREATE`,
because your plugin adopted a table another release created under a
different name, say), list it explicitly instead:

```json
{
  "id": "your-plugin",
  "db_migrations": [...],
  "backup_tables": ["your_custom_table", "your_other_table"]
}
```

`backup_tables`, when present, replaces the derivation entirely for your
plugin — it isn't merged with it — and is checked against the same
collision rules. Only reach for it when the derivation genuinely can't
express your ownership; for the overwhelming majority of plugins (every
bundled one included) the derivation alone is correct and this key
should stay absent.

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
