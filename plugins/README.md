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

1. In the plugin's own repo, tag the release commit `vX.Y.Z` (matching
   `manifest.json`'s own `version`) and make sure `plugin.zip` on that
   tag is actually rebuilt from the release's source — a tag whose
   `plugin.zip` doesn't match its own `manifest.json` silently ships
   old code under a new version number.
2. Compute the real `sha256` of that tag's `plugin.zip`:
   ```bash
   curl -fsSL https://github.com/ltkojak/jen-plugin-<id>/raw/vX.Y.Z/plugin.zip | sha256sum
   ```
3. Update this repo's `plugins/registry.json` for that plugin:
   - `download_url` → `https://github.com/ltkojak/jen-plugin-<id>/raw/vX.Y.Z`
     (the **tag**, never `main` — `main` moves, a tag doesn't, so the
     checksum below stays valid forever once committed)
   - `sha256` → the value from step 2, lowercase hex
   - `version`, `description`, `db_migrations` → copied from that same
     tag's `manifest.json`, by hand

There is no live sync between this file and the plugin repos (v5.21.1 —
there used to be, for `version`/`description`/`db_migrations`; it was
removed because it read `main`, which could report a version and
migration list that didn't match what `install_plugin()` actually
downloads and checksums from a pinned tag). If you forget step 3's
manifest fields, they simply go stale until the next release — nothing
will warn you.

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
