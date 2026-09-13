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
