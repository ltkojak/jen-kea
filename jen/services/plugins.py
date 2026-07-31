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
  "db_migrations": [                         # optional SQL to run on install
    "CREATE TABLE IF NOT EXISTS nd_scan_results (...)"
  ]
}

Plugin DB tables should be prefixed with the plugin id to avoid collisions.
"""

import importlib.util
import json
import logging
import os
import sys
from typing import Optional

import requests

from jen import extensions

logger = logging.getLogger(__name__)

# In-memory registry of loaded plugin metadata
_loaded_plugins: dict[str, dict] = {}


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
    path = os.path.join(extensions.PLUGIN_DIR, plugin_id)
    if os.path.isdir(path):
        open(_enabled_file(plugin_id), "w").close()


def disable_plugin(plugin_id: str) -> None:
    ef = _enabled_file(plugin_id)
    if os.path.isfile(ef):
        os.remove(ef)


# ── Install / uninstall ───────────────────────────────────────────────────────

def install_plugin(plugin_id: str, registry_entry: dict) -> tuple[bool, str]:
    """
    Download and install a plugin from its registry entry.
    Returns (success, message).
    """
    import zipfile, io, shutil

    download_url = registry_entry.get("download_url", "").rstrip("/")
    if not download_url:
        return False, "No download URL in registry entry."

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
            zf.extractall(tmp_dest)

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

        # Run DB migrations
        _run_plugin_migrations(manifest)

        # Enable by default on fresh install
        enable_plugin(plugin_id)

        logger.info(f"Plugin '{plugin_id}' v{manifest.get('version')} installed")
        return True, f"Plugin '{manifest['name']}' v{manifest.get('version')} installed. Restart Jen to activate."

    except Exception as e:
        return False, f"Install failed: {e}"


def uninstall_plugin(plugin_id: str) -> tuple[bool, str]:
    """Remove plugin directory. Does not remove DB tables (data preservation)."""
    import shutil
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


def _run_plugin_migrations(manifest: dict) -> None:
    """Run any DB migration SQL defined in the plugin manifest."""
    migrations = manifest.get("db_migrations", [])
    if not migrations:
        return
    try:
        from jen.models.db import jen_db
        with jen_db() as db:
            with db.cursor() as cur:
                for sql in migrations:
                    cur.execute(sql)
            db.commit()
        logger.info(f"Plugin '{manifest['id']}' DB migrations applied")
    except Exception as e:
        logger.error(f"Plugin '{manifest['id']}' DB migration failed: {e}")


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
