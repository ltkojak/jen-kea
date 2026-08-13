"""
jen/services/plugins.py
───────────────────────
Plugin framework for Jen.

A plugin is a directory under /opt/jen/plugins/<plugin-id>/ containing:
  manifest.json   — metadata, version, Jen requirement, nav entries
  plugin.py       — optional: defines register(app) to add Flask blueprints

manifest.json schema
────────────────────
{
  "id":           "network-discovery",       # unique slug, no spaces
  "name":         "Network Discovery",       # display name
  "version":      "1.0.0",                   # semver
  "description":  "Scan subnets for...",
  "author":       "Matthew Thibodeau",
  "requires_jen": "3.6.0",                   # minimum Jen version
  "nav": [                                   # optional nav items to inject
    {
      "section":  "network",                 # which nav section: management|network|database|settings
      "label":    "Discovery",
      "icon":     "🔍",
      "endpoint": "network_discovery.index"  # Flask endpoint name from the plugin blueprint
    }
  ],
  "db_migrations": [                         # optional, v4.4.18+ format
    {
      "version": 1,                          # int, strictly increasing, never reused
      "description": "nd_scan_results table",
      "sql": "CREATE TABLE IF NOT EXISTS nd_scan_results (...)"
    }
  ]
}

Plugin DB tables should be prefixed with the plugin id to avoid collisions.

Plugin migrations (v4.4.18+)
─────────────────────────────
Each entry in db_migrations is tracked individually in
plugin_schema_migrations (plugin_id, version) — applied once, recorded,
and never re-run, the same discipline jen/models/migrations.py has used
for core Jen's own schema since migration 1. Checked on every Jen
startup (load_plugins()) as well as at install/update time, so a
manually-copied plugin or a manifest that gains a new migration in a
later release both catch up automatically. A failing migration stops
that plugin's remaining migrations and is surfaced back to the
install/update caller — it no longer just logs an error and reports
success anyway. As with core migrations, every migration's SQL must
still be idempotent (CREATE TABLE IF NOT EXISTS, guarded ALTERs) since
MySQL/MariaDB DDL auto-commits and can't be rolled back — the tracking
table only prevents re-running an already-applied migration, it doesn't
make a non-idempotent statement safe to write in the first place.
"""

import importlib.util
import json
import logging
import os
import re
import sys
from typing import Optional

import requests

from jen import extensions

logger = logging.getLogger(__name__)

# In-memory registry of loaded plugin metadata
_loaded_plugins: dict[str, dict] = {}

# Every function below that turns a plugin_id into a filesystem path must
# validate it against this first — a plugin_id is attacker-influenced input
# (it arrives as a URL path segment) and several of these functions end in
# os.remove()/shutil.rmtree() against os.path.join(PLUGIN_DIR, plugin_id).
# install_plugin()/update_plugin() already had this check at the route
# layer; enable/disable/uninstall didn't (v4.4.4).
_PLUGIN_ID_RE = re.compile(r'^[a-z0-9\-]{1,64}$')


def valid_plugin_id(plugin_id: str) -> bool:
    return bool(plugin_id) and bool(_PLUGIN_ID_RE.match(plugin_id))


# ── Versioning helper ─────────────────────────────────────────────────────────

def _parse_version(v: str) -> tuple:
    """Parse 'X.Y.Z' into (X, Y, Z) tuple for comparison."""
    try:
        return tuple(int(x) for x in str(v).strip().split(".")[:3])
    except Exception:
        return (0, 0, 0)


def jen_version_meets(required: str) -> bool:
    """Return True if the running Jen version satisfies required minimum."""
    from jen import JEN_VERSION
    return _parse_version(JEN_VERSION) >= _parse_version(required)


# ── Plugin discovery & loading ────────────────────────────────────────────────

def discover_plugins() -> list[dict]:
    """
    Scan PLUGIN_DIR for installed plugins.
    Returns list of manifest dicts with added 'path' and 'enabled' keys.
    """
    plugins = []
    if not os.path.isdir(extensions.PLUGIN_DIR):
        return plugins
    for name in sorted(os.listdir(extensions.PLUGIN_DIR)):
        path = os.path.join(extensions.PLUGIN_DIR, name)
        manifest_path = os.path.join(path, "manifest.json")
        if not os.path.isdir(path) or not os.path.isfile(manifest_path):
            continue
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            manifest["path"] = path
            manifest["enabled"] = _is_enabled(manifest["id"])
            manifest["version_ok"] = jen_version_meets(
                manifest.get("requires_jen", "0.0.0")
            )
            plugins.append(manifest)
        except Exception as e:
            logger.warning(f"Could not load plugin manifest from {path}: {e}")
    return plugins


def load_plugins(app) -> None:
    """
    Load all enabled installed plugins into the Flask app.
    Called from create_app() after core blueprints are registered.

    v4.4.18: also runs any pending DB migrations for each plugin on
    every startup, not just at install/update time — mirrors
    jen.models.migrations.run_migrations() being called from
    init_jen_db() on every boot, for the same reason: a plugin that
    was manually copied into place (bypassing the install/update UI
    entirely) still needs its schema caught up, and a plugin whose
    manifest gained a new migration in a later release should apply it
    the next time Jen restarts, not only if someone happens to click
    "Update" again.
    """
    for plugin in discover_plugins():
        if not plugin.get("enabled"):
            continue
        if not plugin.get("version_ok", True):
            logger.warning(
                f"Plugin '{plugin['id']}' requires Jen {plugin.get('requires_jen')} "
                f"— skipping (version mismatch)"
            )
            continue
        mig_ok, mig_msg, mig_count = run_plugin_migrations(plugin)
        if not mig_ok:
            # v4.4.19: log loudly, but load the plugin anyway. A migration
            # problem — a manifest-format mismatch, a genuinely broken new
            # migration — used to also skip the plugin's blueprint and nav
            # entry entirely, which is a much worse outcome than the
            # migration issue itself: it makes an already-working plugin's
            # existing functionality vanish from the UI over a schema
            # change for a DIFFERENT, possibly-unrelated table. Found this
            # the hard way — a real installed plugin on the old manifest
            # format disappeared from the nav after updating Jen, even
            # though its tables and data were completely fine.
            logger.error(
                f"Plugin '{plugin['id']}' has a migration problem (loading "
                f"anyway — existing functionality may still work): {mig_msg}"
            )
        _load_plugin(app, plugin)


def _load_plugin(app, manifest: dict) -> bool:
    """
    Load a single plugin: run its plugin.py register(app) if present.
    Returns True on success.
    """
    plugin_id = manifest["id"]
    path      = manifest["path"]
    plugin_py = os.path.join(path, "plugin.py")

    try:
        if os.path.isfile(plugin_py):
            spec   = importlib.util.spec_from_file_location(
                f"jen_plugin_{plugin_id}", plugin_py
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[f"jen_plugin_{plugin_id}"] = module
            spec.loader.exec_module(module)
            if hasattr(module, "register"):
                module.register(app)
                logger.info(f"Plugin '{plugin_id}' registered successfully")
            else:
                logger.warning(f"Plugin '{plugin_id}' has plugin.py but no register() function")

        # Template folder is registered by the blueprint's template_folder param
        # No need to manually append to searchpath

        _loaded_plugins[plugin_id] = manifest
        return True

    except Exception as e:
        logger.error(f"Failed to load plugin '{plugin_id}': {e}")
        return False


# ── Enable / disable ──────────────────────────────────────────────────────────

def _enabled_file(plugin_id: str) -> str:
    return os.path.join(extensions.PLUGIN_DIR, plugin_id, ".enabled")


def _is_enabled(plugin_id: str) -> bool:
    return os.path.isfile(_enabled_file(plugin_id))


def enable_plugin(plugin_id: str) -> None:
    if not valid_plugin_id(plugin_id):
        logger.warning(f"enable_plugin: rejected invalid plugin_id {plugin_id!r}")
        return
    path = os.path.join(extensions.PLUGIN_DIR, plugin_id)
    if os.path.isdir(path):
        open(_enabled_file(plugin_id), "w").close()


def disable_plugin(plugin_id: str) -> None:
    if not valid_plugin_id(plugin_id):
        logger.warning(f"disable_plugin: rejected invalid plugin_id {plugin_id!r}")
        return
    ef = _enabled_file(plugin_id)
    if os.path.isfile(ef):
        os.remove(ef)


# ── Install / uninstall ───────────────────────────────────────────────────────

def _safe_extract(zf, dest_dir: str) -> None:
    """Extract a ZipFile to dest_dir, refusing any member whose resolved
    path would land outside dest_dir (a.k.a. "Zip Slip") — an entry named
    e.g. "../../../etc/cron.d/evil" or an absolute path would otherwise
    let a malicious plugin archive write files anywhere www-data can
    reach, not just into the plugin's own directory."""
    dest_dir_real = os.path.realpath(dest_dir)
    os.makedirs(dest_dir_real, exist_ok=True)
    for member in zf.infolist():
        member_path = os.path.realpath(os.path.join(dest_dir_real, member.filename))
        if member_path != dest_dir_real and \
                not member_path.startswith(dest_dir_real + os.sep):
            raise ValueError(f"Unsafe path in plugin archive: {member.filename!r}")
    zf.extractall(dest_dir_real)


def install_plugin(plugin_id: str, registry_entry: dict) -> tuple[bool, str]:
    """
    Download and install a plugin from its registry entry.
    Returns (success, message).
    """
    import zipfile, io, shutil

    if not valid_plugin_id(plugin_id):
        return False, "Invalid plugin ID."

    download_url = registry_entry.get("download_url", "").rstrip("/")
    if not download_url:
        return False, "No download URL in registry entry."
    if not download_url.startswith("https://"):
        return False, "Refusing to install from a non-HTTPS download URL."

    # Expect a zip archive at download_url/plugin.zip
    zip_url = f"{download_url}/plugin.zip"
    dest    = os.path.join(extensions.PLUGIN_DIR, plugin_id)

    try:
        resp = requests.get(zip_url, timeout=30)
        if resp.status_code != 200:
            return False, f"Download failed: HTTP {resp.status_code}"

        os.makedirs(extensions.PLUGIN_DIR, exist_ok=True)

        # Extract to a temp location then move
        tmp_dest = dest + "_tmp"
        if os.path.isdir(tmp_dest):
            shutil.rmtree(tmp_dest)
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            _safe_extract(zf, tmp_dest)

        # Validate manifest exists in extracted content
        mf = os.path.join(tmp_dest, "manifest.json")
        if not os.path.isfile(mf):
            shutil.rmtree(tmp_dest)
            return False, "Plugin archive missing manifest.json."

        # Validate manifest content
        with open(mf) as f:
            manifest = json.load(f)
        if manifest.get("id") != plugin_id:
            shutil.rmtree(tmp_dest)
            return False, f"Plugin ID mismatch: expected '{plugin_id}', got '{manifest.get('id')}'."

        # Check Jen version requirement
        required = manifest.get("requires_jen", "0.0.0")
        if not jen_version_meets(required):
            shutil.rmtree(tmp_dest)
            from jen import JEN_VERSION
            return False, f"Plugin requires Jen {required} (running {JEN_VERSION})."

        # Replace existing install if present
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        os.rename(tmp_dest, dest)

        # Run DB migrations — surface a real failure to the caller
        # (previously this just logged an error and pretended the
        # install succeeded regardless).
        mig_ok, mig_msg, mig_count = run_plugin_migrations(manifest)
        if not mig_ok:
            return False, f"Plugin files installed, but a DB migration failed: {mig_msg}"

        # Enable by default on fresh install
        enable_plugin(plugin_id)

        logger.info(f"Plugin '{plugin_id}' v{manifest.get('version')} installed"
                   + (f" ({mig_count} migration(s) applied)" if mig_count else ""))
        return True, f"Plugin '{manifest['name']}' v{manifest.get('version')} installed. Restart Jen to activate."

    except Exception as e:
        return False, f"Install failed: {e}"


def uninstall_plugin(plugin_id: str) -> tuple[bool, str]:
    """Remove plugin directory. Does not remove DB tables (data preservation)."""
    import shutil
    if not valid_plugin_id(plugin_id):
        return False, "Invalid plugin ID."
    path = os.path.join(extensions.PLUGIN_DIR, plugin_id)
    if not os.path.isdir(path):
        return False, "Plugin not found."
    try:
        shutil.rmtree(path)
        # Remove from loaded cache
        _loaded_plugins.pop(plugin_id, None)
        logger.info(f"Plugin '{plugin_id}' uninstalled")
        return True, f"Plugin '{plugin_id}' uninstalled. Restart Jen to fully remove."
    except Exception as e:
        return False, f"Uninstall failed: {e}"


def _plugin_applied_versions(plugin_id: str) -> set:
    """Return the set of already-applied migration versions for a plugin
    (empty if the tracking table doesn't exist yet — the very first
    core migration run creates it, but this stays defensive in case
    plugin loading is ever reachable before that)."""
    from jen.models.db import jen_db
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("SHOW TABLES LIKE 'plugin_schema_migrations'")
            if not cur.fetchone():
                return set()
            cur.execute(
                "SELECT version FROM plugin_schema_migrations WHERE plugin_id=%s",
                (plugin_id,)
            )
            return {r["version"] for r in cur.fetchall()}


def run_plugin_migrations(manifest: dict) -> tuple[bool, str, int]:
    """
    Apply any pending DB migrations from a plugin's manifest, in version
    order, each recorded in plugin_schema_migrations as it's applied —
    v4.4.18, replacing the old _run_plugin_migrations() which re-ran
    every migration in the manifest on every single install/update with
    no tracking of what had already been applied. Every migration
    currently shipped happens to be CREATE TABLE IF NOT EXISTS, so that
    was harmless in practice — but it meant plugin authors were on their
    own to hand-write idempotent SQL forever, and any single failing
    statement silently aborted every migration after it with nothing
    but a log line, no error surfaced anywhere a user would see it.

    manifest["db_migrations"] is a list of
    {"version": int, "description": str, "sql": str} objects — the
    version field is what actually gets tracked; unlike core Jen's own
    MIGRATIONS list (Python functions), plugin migrations stay plain SQL
    strings from JSON, since that's a much lower bar for a plugin author
    to write than a Python migration function.

    Returns (success, message, applied_count). Stops at the first
    failing migration — later ones in the same manifest are not
    attempted, mirroring core Jen's "a half-migrated schema must never
    serve requests silently" rule.
    """
    plugin_id = manifest["id"]
    raw_migrations = manifest.get("db_migrations", [])
    if not raw_migrations:
        return True, "", 0

    # v4.4.19: normalize the pre-4.4.18 flat-string format instead of
    # hard-rejecting it. Found the hard way — a real installed plugin
    # (from its own separate repo, not the copy bundled in jen-kea)
    # was still on the old format, and rejecting it here meant
    # load_plugins() skipped the plugin entirely: not just its
    # migrations, its whole blueprint and nav entry vanished, even
    # though the plugin's actual data and functionality were fine. A
    # manifest format change on Jen's side should never make an
    # already-working plugin disappear from the UI. Each plain string
    # is treated as an implicit migration numbered by its 1-based
    # position in the list — exactly the order the old unversioned
    # runner already executed them in, just now actually tracked.
    # Mixed manifests (some old-format strings, some new-format dicts)
    # are accepted too, since a plugin author might migrate one entry
    # at a time rather than all at once.
    normalized = []
    for i, m in enumerate(raw_migrations):
        if isinstance(m, str):
            normalized.append({"version": i + 1, "description": "", "sql": m})
        elif isinstance(m, dict) and "version" in m and "sql" in m:
            normalized.append(m)
        else:
            return False, (
                f"Plugin '{plugin_id}' manifest db_migrations entries must be "
                f'either a raw SQL string or a {{"version": int, "sql": str}} '
                f"object — got {m!r}"
            ), 0
    raw_migrations = normalized

    migrations = sorted(raw_migrations, key=lambda m: m["version"])
    versions = [m["version"] for m in migrations]
    if len(versions) != len(set(versions)):
        return False, f"Plugin '{plugin_id}' manifest has duplicate migration version numbers.", 0
    if any(not isinstance(v, int) for v in versions):
        return False, f"Plugin '{plugin_id}' manifest migration versions must be integers.", 0

    from jen.models.db import jen_db
    with jen_db() as db:
        with db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS plugin_schema_migrations (
                    plugin_id VARCHAR(100) NOT NULL,
                    version INT NOT NULL,
                    description VARCHAR(255) NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (plugin_id, version)
                )
            """)

    applied = _plugin_applied_versions(plugin_id)
    count = 0
    for m in migrations:
        version = m["version"]
        if version in applied:
            continue
        description = m.get("description", "")
        try:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute(m["sql"])
                    cur.execute(
                        "INSERT INTO plugin_schema_migrations "
                        "(plugin_id, version, description) VALUES (%s, %s, %s)",
                        (plugin_id, version, description)
                    )
            count += 1
            logger.info(f"Plugin '{plugin_id}' migration {version} applied: {description}")
        except Exception as e:
            msg = f"Plugin '{plugin_id}' migration {version} failed: {e}"
            logger.error(msg)
            return False, msg, count

    return True, "", count


# ── Registry ──────────────────────────────────────────────────────────────────

def fetch_registry(timeout: int = 10) -> tuple[list, Optional[str]]:
    """
    Fetch the plugin registry from GitHub.
    Returns (entries, error_message). error_message is None on success.
    """
    try:
        resp = requests.get(extensions.PLUGIN_REGISTRY_URL, timeout=timeout)
        if resp.status_code != 200:
            return [], f"Registry fetch failed: HTTP {resp.status_code}"
        entries = resp.json()
        if not isinstance(entries, list):
            return [], "Registry format invalid (expected a JSON array)."
        return entries, None
    except requests.Timeout:
        return [], "Registry fetch timed out."
    except Exception as e:
        return [], f"Registry fetch error: {e}"


def get_loaded_plugins() -> dict:
    """Return dict of currently loaded plugin manifests keyed by plugin_id."""
    return dict(_loaded_plugins)


def get_nav_items() -> list[dict]:
    """
    Return nav injection items from all loaded plugins.
    Each item: { section, label, icon, endpoint }
    """
    items = []
    for manifest in _loaded_plugins.values():
        for nav in manifest.get("nav", []):
            items.append(nav)
    return items
