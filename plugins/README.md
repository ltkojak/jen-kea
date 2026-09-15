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

`from jen.services.background import register_periodic`, called from
`register(app)`. `create_app()` must not start background work, so a
plugin never starts its own thread: it registers a callable and Jen's
one periodic loop (started only by the real entrypoint, never in the
test suite) runs it every `every_minutes` (minimum 5; the first run is
one interval after startup). Each run is wrapped — an exception is
logged and recorded on the job, never propagated — and a run still in
progress when the next tick comes is skipped, not stacked.
`periodic_jobs()` lists what's registered.

### Subnet context — `subnet_context(subnet_id)`

`from jen.services.subnet_context import subnet_context, classify_address, in_pool`.
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
| Access control | `assert_subnet_access(subnet_id)`, `get_accessible_subnet_map()`, `is_admin_or_above()`, `is_superadmin()`, decorators `admin_required`, `superadmin_required`, `viewer_or_above` |
| Subnets | `subnet_map()` (all IPv4 subnets), `subnet_context(subnet_id)`, `classify_address(ctx, ip)`, `in_pool(ctx, ip)`, `dhcp4_config()` |
| Alerts | `send_alert(alert_type, subnet_id=…, subject=…, body=…)` |
| Background | `register_periodic(plugin_id, name, fn, every_minutes)`, `unregister_periodic`, `periodic_jobs()` |
| Events (v5.42.0) | `subscribe(kind_or_"*", fn)`, `unsubscribe(fn)`, `event_kinds` (the pinned kind vocabulary) |
| CSV | `safe_cell(value)`, `safe_row(values)` |
| Devices | `classify_device(mac, hostname)` → (manufacturer, type, icon) |
| Plugins | `installed_plugins()`, `is_systemd_host()` |
| Jen | `jen_version()`, `PLUGIN_API_VERSION` |

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

`fn` is called synchronously, right after the row is written — keep it
fast, and never let it raise: an exception is logged and swallowed, but
a slow subscriber still blocks whatever thread called `emit()` (usually
the alert loop's tick). There's no `unsubscribe_all` — a plugin that
`register(app)`s a subscriber and can be disabled at runtime is
responsible for calling `unsubscribe(fn)` itself if it needs to stop
listening.

**Versioning.** `PLUGIN_API_VERSION` is `2` (events pushed it from `1`
— see below). Adding a name is a MINOR Jen release and does not move
it; removing a name or changing a signature moves it and is a MAJOR for
Jen. A manifest may declare the version it was written against:

```json
"plugin_api": 2
```

Jen refuses to load a plugin whose `plugin_api` is newer than what it
offers — the Plugins page shows *needs plugin API vN* instead of the
plugin failing with an ImportError at boot. A plugin that uses the
surface should set `requires_jen` to `5.34.0` or later.

`tests/test_plugin_api.py` checks that the bundled copies import only
the surface (a short transitional list of internals is tolerated until
the plugins' own releases move over), and that every name they use is
offered by it.

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
