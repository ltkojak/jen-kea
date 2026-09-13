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

import contextlib
import importlib.util
import json
import logging
import os
import re
import subprocess
import sys

import requests

from jen import extensions

logger = logging.getLogger(__name__)

# In-memory registry of loaded plugin metadata
_loaded_plugins: dict[str, dict] = {}

# The plugin ids Jen ships in its own tree (extensions.PLUGIN_DIR_BUNDLED).
# Registry-installed plugins go to extensions.PLUGIN_DIR (CONTENT_DIR); a
# same-id copy there wins. Uninstalling a shipped plugin only disables it.
SHIPPED_PLUGIN_IDS = frozenset({"ipam", "network-discovery"})

# Every function below that turns a plugin_id into a filesystem path must
# validate it against this first — a plugin_id is attacker-influenced input
# (it arrives as a URL path segment) and several of these functions end in
# os.remove()/shutil.rmtree() against os.path.join(PLUGIN_DIR, plugin_id).
# install_plugin()/update_plugin() already had this check at the route
# layer; enable/disable/uninstall didn't (v4.4.4).
#
# v5.28.0 (Q24, A5) — unified with jen-update-root.py's own
# _PLUGIN_ID_RE, which requires the first character to be alnum
# (rejecting a leading '-', which this pattern used to accept on its
# own); www-data and the root-run request processor now agree on
# exactly which ids can ever exist. tests/test_plugin_registry.py
# asserts the two `.pattern` strings stay identical.
_PLUGIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


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
    Scan the shipped plugin tree (extensions.PLUGIN_DIR_BUNDLED), then the
    root-owned registry-installed tree (extensions.PLUGIN_DIR_ROOT, v5.27.0
    Q23), then the legacy writable one (extensions.PLUGIN_DIR, under
    CONTENT_DIR). A plugin present in more than one is taken from
    whichever base was scanned LAST — so a writable copy still shadows a
    root-owned one if both happen to exist (the request processor
    removes the writable copy once a root install lands; see
    jen-update-root.py::_install_one_plugin), and either shadows bundled.

    Returns manifest dicts with added 'path' / 'enabled' / 'version_ok' /
    'bundled' / 'root_owned' keys.
    """
    by_id: dict[str, dict] = {}
    bases = (
        (extensions.PLUGIN_DIR_BUNDLED, True, False),
        (extensions.PLUGIN_DIR_ROOT, False, True),
        (extensions.PLUGIN_DIR, False, False),
    )
    for base, bundled, root_owned in bases:
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            # v5.28.0 (Q24, A4) — a crash-safe swap in
            # jen-update-root.py::_install_one_plugin can leave a
            # `<id>.old-<ts>` directory sitting next to `<id>` between
            # the swap and the next --plugins run's sweep. Its
            # manifest.json still claims `id: <id>`, and it sorts AFTER
            # the real `<id>` directory — without this, "later wins"
            # would let a leftover shadow the live copy.
            if not valid_plugin_id(name):
                continue
            path = os.path.join(base, name)
            manifest_path = os.path.join(path, "manifest.json")
            if not os.path.isdir(path) or not os.path.isfile(manifest_path):
                continue
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
                manifest["path"] = path
                manifest["bundled"] = bundled
                manifest["root_owned"] = root_owned
                manifest["enabled"] = _is_enabled(manifest["id"])
                manifest["version_ok"] = jen_version_meets(manifest.get("requires_jen", "0.0.0"))
                by_id[manifest["id"]] = manifest  # later base in `bases` wins
            except Exception as e:
                logger.warning(f"Could not load plugin manifest from {path}: {e}")
    return [by_id[k] for k in sorted(by_id)]


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
                f"Plugin '{plugin['id']}' requires Jen {plugin.get('requires_jen')} — skipping (version mismatch)"
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
    path = manifest["path"]
    plugin_py = os.path.join(path, "plugin.py")

    try:
        if os.path.isfile(plugin_py):
            spec = importlib.util.spec_from_file_location(f"jen_plugin_{plugin_id}", plugin_py)
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
    # v5.13.0 — the marker lives in CONTENT_DIR/plugins-enabled/<id>, not
    # inside the plugin dir (which for a shipped plugin is read-only).
    return os.path.join(extensions.CONTENT_PLUGINS_ENABLED_DIR, plugin_id)


def _plugin_dir(plugin_id: str) -> str | None:
    """The on-disk directory for a plugin — the writable copy if there is
    one, else the root-owned copy, else the shipped copy, else None.

    v5.28.0 (Q24, A7) — PLUGIN_DIR_ROOT was missing here entirely, which
    made enable_plugin()/disable_plugin() silent no-ops for a
    root-owned plugin (installed via v5.27.0's root path): the enable
    marker was never written because this always returned None for it.
    Order matches discover_plugins()'s own precedence."""
    for base in (extensions.PLUGIN_DIR, extensions.PLUGIN_DIR_ROOT, extensions.PLUGIN_DIR_BUNDLED):
        path = os.path.join(base, plugin_id)
        if os.path.isdir(path):
            return path
    return None


def _is_enabled(plugin_id: str) -> bool:
    return os.path.isfile(_enabled_file(plugin_id))


def enable_plugin(plugin_id: str) -> None:
    if not valid_plugin_id(plugin_id):
        logger.warning(f"enable_plugin: rejected invalid plugin_id {plugin_id!r}")
        return
    if _plugin_dir(plugin_id):
        os.makedirs(extensions.CONTENT_PLUGINS_ENABLED_DIR, exist_ok=True)
        with open(_enabled_file(plugin_id), "w"):
            pass


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
        if member_path != dest_dir_real and not member_path.startswith(dest_dir_real + os.sep):
            raise ValueError(f"Unsafe path in plugin archive: {member.filename!r}")
    zf.extractall(dest_dir_real)


# ── Root-owned installs (v5.27.0, Q23) ──────────────────────────────────────
# install_plugin()/uninstall_plugin() below become REQUESTERS on a real
# systemd host: they write an empty marker and trigger
# jen-plugin-install.service, which runs jen-update-root.py --plugins as
# root and re-derives everything from the registry itself — the same
# request/execute split the self-updater already uses, for the same
# reason (a compromised www-data must never be able to extract arbitrary
# code into a directory Jen imports from). Docker and dev checkouts have
# no systemd unit to trigger and keep the pre-5.27.0 in-process path.


def is_systemd_host() -> bool:
    """Same detection jen/__init__.py's venv-migration check already
    uses. On a systemd host, install/uninstall become root-privileged
    requests; everywhere else — Docker, a dev/CI checkout — they still
    run in-process, unchanged."""
    return not os.path.exists("/.dockerenv") and "JEN_ROOT" not in os.environ


def _request_marker_path(plugin_id: str, action: str) -> str:
    return os.path.join(extensions.CONTENT_PLUGIN_REQUESTS_DIR, f"{plugin_id}.{action}")


def _write_plugin_request(plugin_id: str, action: str) -> None:
    """action in {"install", "remove"}. An empty marker file — the
    root-run request processor re-derives everything else from the
    registry itself; nothing here is trusted beyond the plugin_id
    (already validated by the caller) and which of the two actions was
    requested."""
    os.makedirs(extensions.CONTENT_PLUGIN_REQUESTS_DIR, exist_ok=True)
    with open(_request_marker_path(plugin_id, action), "w"):
        pass


def request_is_pending(plugin_id: str, action: str) -> bool:
    """True while `<plugin_id>.<action>` marker still exists — i.e. the
    root side hasn't picked it up (or finished it) yet. v5.28.0 (Q24,
    A9) — the route layer uses this, not response message text, to
    decide whether an install/uninstall was deferred to the root
    process or handled in-process."""
    return os.path.isfile(_request_marker_path(plugin_id, action))


def _start_plugin_install_unit() -> bool:
    """Fixed, zero-parameter command — the exact string jen-sudoers
    authorizes. --no-block matters here for the same reason it matters
    for jen-update.service: this call must not block waiting on a unit
    whose own work has nothing to do with restarting THIS process, and
    blocking here would tie up a request-handling thread/worker for no
    reason.

    v5.28.0 (Q24, A8) — returns whether the trigger actually succeeded.
    It used to be called for its side effect only, so a sudoers
    misconfiguration or a missing unit file left the caller reporting
    "Install requested" for a request that would never be picked up."""
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "/usr/bin/systemctl", "start", "--no-block", "jen-plugin-install.service"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except Exception as e:
        logger.error(f"Failed to trigger jen-plugin-install.service: {e}")
        return False
    if result.returncode != 0:
        logger.error(
            f"jen-plugin-install.service failed to start (exit {result.returncode}): "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
        return False
    return True


def _parse_systemctl_show(text: str) -> dict:
    """`systemctl show -p A -p B` prints `Key=Value` lines. Pure.
    Duplicated from jen/routes/settings/updates.py's identical helper
    rather than imported — a route module importing from another route
    module the wrong direction would be worse than six lines twice."""
    props = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    return props


def plugin_install_unit_status() -> dict:
    """Read-only `systemctl show` query — no sudo needed (rule 8 only
    applies to a command that CHANGES something), same as
    settings/updates.py::update_status()'s identical query against
    jen-update.service."""
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "show", "jen-plugin-install.service", "-p", "ActiveState", "-p", "SubState"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        props = _parse_systemctl_show(result.stdout)
    except Exception as e:
        logger.error(f"plugin_install_unit_status: could not query jen-plugin-install.service: {e}")
        props = {}
    return {"active_state": props.get("ActiveState", "unknown"), "sub_state": props.get("SubState", "")}


_RESULT_RE = re.compile(r"^(?P<id>[a-z0-9][a-z0-9-]{0,63})\.(?P<action>install|remove)\.result$")


def record_plugin_row(info: dict) -> None:
    """Upsert this plugin into Jen's own `plugins` bookkeeping table —
    write-only bookkeeping the app never reads back from (moved here
    from jen/routes/plugins.py, v5.28.0 Q24 A9, so both the in-process
    path and consume_plugin_results() below share one implementation).
    `info` needs id/name/version/description/author/requires_jen — a
    registry entry and a plugin manifest dict both have all of them."""
    from jen.models import db as _db

    try:
        with _db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO plugins (id, name, version, description, author, requires_jen, enabled)
                VALUES (%s, %s, %s, %s, %s, %s, 1)
                ON DUPLICATE KEY UPDATE
                    name=VALUES(name), version=VALUES(version),
                    description=VALUES(description), enabled=1
            """,
                (
                    info.get("id"),
                    info.get("name"),
                    info.get("version"),
                    info.get("description"),
                    info.get("author"),
                    info.get("requires_jen"),
                ),
            )
            db.commit()
    except Exception as e:
        logger.error(f"Failed to record plugin in DB: {e}")


def remove_plugin_row(plugin_id: str) -> None:
    from jen.models import db as _db

    try:
        with _db.jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM plugins WHERE id=%s", (plugin_id,))
            db.commit()
    except Exception as e:
        logger.error(f"Failed to remove plugin record from DB: {e}")


def _apply_plugin_result(plugin_id: str, action: str, ok: bool, raw_detail: str) -> str:
    """Apply one confirmed root-side outcome to Jen's own state (DB row,
    enable marker, restart_pending, audit log) and return the detail
    string a caller should display for it. Only ever called once per
    result, by consume_plugin_results() right after it deletes the
    `.result` file — never re-derives anything from a marker, since by
    this point the marker is long gone."""
    from jen.models.user import audit, set_global_setting

    if not ok:
        audit("PLUGIN_INSTALL_FAILED" if action == "install" else "PLUGIN_UNINSTALL_FAILED", plugin_id, raw_detail)
        return raw_detail

    if action == "install":
        manifest = next((p for p in discover_plugins() if p["id"] == plugin_id), None)
        if manifest:
            record_plugin_row(manifest)
        enable_plugin(plugin_id)
        set_global_setting("restart_pending", "true")
        version = manifest.get("version", "?") if manifest else "?"
        detail = f"installed v{version}" if manifest else "install completed"
        audit("PLUGIN_INSTALL", plugin_id, f"root-owned install completed v{version}")
        return detail

    remove_plugin_row(plugin_id)
    if os.path.isdir(os.path.join(extensions.PLUGIN_DIR_BUNDLED, plugin_id)):
        detail = f"the built-in copy of '{plugin_id}' is active again"
    else:
        disable_plugin(plugin_id)
        detail = "removed"
    set_global_setting("restart_pending", "true")
    audit("PLUGIN_UNINSTALL", plugin_id, detail)
    return detail


def consume_plugin_results() -> list[dict]:
    """Read and apply every root-run `<id>.<action>.result` the request
    processor has written since the last call — the QUEUED -> CONFIRMED
    half of the split v5.27.0 started (v5.28.0, Q24, A9). Each result
    is deleted as it's read, so this is safe to call repeatedly and
    from more than one place: plugins_page() calls it on every render
    (so a result that lands after the browser tab was closed still
    gets applied the next time anyone opens the page, not only via the
    poller) and the install-status route calls it too. Never raises.

    Returns a list of {"id", "action", "ok", "detail"} — one entry per
    result consumed this call (usually 0 or 1).

    A stale `<id>.result` (the pre-5.28.0 filename, with no action —
    left over from a box that installed a plugin under 5.27.0) is
    deleted on sight without being applied: there is no way to know
    which action it belonged to, and no code writes that filename
    anymore."""
    results = []
    d = extensions.CONTENT_PLUGIN_REQUESTS_DIR
    if not os.path.isdir(d):
        return results
    for name in sorted(os.listdir(d)):
        if not name.endswith(".result"):
            continue
        path = os.path.join(d, name)
        m = _RESULT_RE.match(name)
        if not m:
            with contextlib.suppress(OSError):
                os.remove(path)
            continue
        plugin_id, action = m.group("id"), m.group("action")
        try:
            with open(path) as f:
                raw_detail = f.read().strip()
        except OSError:
            continue
        with contextlib.suppress(OSError):
            os.remove(path)
        ok = raw_detail == "ok"
        detail = _apply_plugin_result(plugin_id, action, ok, raw_detail)
        results.append({"id": plugin_id, "action": action, "ok": ok, "detail": detail})
    return results


def install_plugin(plugin_id: str, registry_entry: dict) -> tuple[bool, str]:
    """
    Download and install a plugin from its registry entry.
    Returns (success, message).

    v5.3.3 — checksum verification added, mirroring the same principle
    already applied to the self-updater in v5.2.6: HTTPS-only, manifest
    ID matching, and zip-slip-safe extraction were all already present
    here, but nothing verified the downloaded zip's integrity against
    anything published alongside it. A compromised registry.json (or a
    compromised plugin repository) could otherwise serve arbitrary code
    that gets executed as www-data, plus whatever db_migrations the
    manifest declares.

    v5.21.1 — fail-closed on a MISSING checksum too, now matching the
    self-updater exactly. `install_plugin` used to log a warning and
    install anyway when a registry entry had no `sha256`, because
    neither plugin that existed at the time (network-discovery, ipam)
    had one yet, and computing one from what this function just
    downloaded would have been circular — no real security. Every
    registry entry now pins `download_url` to a release tag (not
    `main`) and carries the real `sha256` of that tag's `plugin.zip`,
    computed out-of-band from a verified download — see plugins/README.md
    for the release process. With that in place, a missing checksum is
    no longer a legitimate transition state; it means the registry
    entry is malformed or was tampered with, and install refuses
    outright, the same as a mismatch.

    v5.27.0 (Q23) — on a real systemd host, this no longer does any of
    the above itself. It writes an empty request marker and triggers
    jen-plugin-install.service, which re-derives everything from
    registry.json fresh as root and lands the plugin at
    extensions.PLUGIN_DIR_ROOT instead of the www-data-writable
    extensions.PLUGIN_DIR — closing the one remaining persistence
    foothold for a compromised web process (swap plugin.py, Jen runs it
    on the next restart). `registry_entry` is intentionally NOT passed
    through beyond the id: the root process fetches its own copy of the
    registry, so nothing this route read moments earlier is trusted
    into the privileged path. Docker and dev checkouts (no systemd unit
    to trigger) keep the pre-5.27.0 in-process path below, unchanged.
    """
    import hashlib
    import io
    import shutil
    import zipfile

    if not valid_plugin_id(plugin_id):
        return False, "Invalid plugin ID."

    if is_systemd_host():
        _write_plugin_request(plugin_id, "install")
        if not _start_plugin_install_unit():
            with contextlib.suppress(OSError):
                os.remove(_request_marker_path(plugin_id, "install"))
            return False, (
                "Could not start the plugin install service — run `sudo ./install.sh` to repair "
                "jen-sudoers and jen-plugin-install.service, then try again."
            )
        return True, "Install requested — Jen will pick the plugin up within a few seconds."

    download_url = registry_entry.get("download_url", "").rstrip("/")
    if not download_url:
        return False, "No download URL in registry entry."
    if not download_url.startswith("https://"):
        return False, "Refusing to install from a non-HTTPS download URL."

    # Expect a zip archive at download_url/plugin.zip
    zip_url = f"{download_url}/plugin.zip"
    dest = os.path.join(extensions.PLUGIN_DIR, plugin_id)

    try:
        resp = requests.get(zip_url, timeout=30)
        if resp.status_code != 200:
            return False, f"Download failed: HTTP {resp.status_code}"

        expected_sha256 = registry_entry.get("sha256", "").strip().lower()
        if not expected_sha256:
            return False, "Registry entry has no checksum — refusing to install."
        actual_sha256 = hashlib.sha256(resp.content).hexdigest()
        if actual_sha256 != expected_sha256:
            logger.error(
                f"Plugin '{plugin_id}' checksum mismatch: expected {expected_sha256}, "
                f"got {actual_sha256} — refusing to install."
            )
            return False, "Plugin package failed checksum verification. Refusing to install."

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

        logger.info(
            f"Plugin '{plugin_id}' v{manifest.get('version')} installed"
            + (f" ({mig_count} migration(s) applied)" if mig_count else "")
        )
        return True, f"Plugin '{manifest['name']}' v{manifest.get('version')} installed. Restart Jen to activate."

    except Exception as e:
        return False, f"Install failed: {e}"


def uninstall_plugin(plugin_id: str) -> tuple[bool, str]:
    """Remove a registry-installed plugin's directory. A shipped plugin
    (ipam / network-discovery) can't be removed — the tree is read-only
    — so uninstalling one just disables it. DB tables are left alone
    either way (data preservation).

    v5.27.0 (Q23) — a ROOT-owned copy (extensions.PLUGIN_DIR_ROOT) can
    only be removed the same way it was installed: a request, handled
    by jen-plugin-install.service as root. A legacy writable copy
    (extensions.PLUGIN_DIR, under CONTENT_DIR) is still removed
    in-process exactly as before — www-data already owns that directory
    outright, so there's no privilege boundary to cross for it.
    """
    import shutil

    if not valid_plugin_id(plugin_id):
        return False, "Invalid plugin ID."

    root_path = os.path.join(extensions.PLUGIN_DIR_ROOT, plugin_id)
    if os.path.isdir(root_path) and is_systemd_host():
        _write_plugin_request(plugin_id, "remove")
        if not _start_plugin_install_unit():
            with contextlib.suppress(OSError):
                os.remove(_request_marker_path(plugin_id, "remove"))
            return False, (
                "Could not start the plugin install service — run `sudo ./install.sh` to repair "
                "jen-sudoers and jen-plugin-install.service, then try again."
            )
        return True, "Removal requested — Jen will pick this up within a few seconds."

    path = os.path.join(extensions.PLUGIN_DIR, plugin_id)
    if not os.path.isdir(path):
        bundled = os.path.join(extensions.PLUGIN_DIR_BUNDLED, plugin_id)
        if os.path.isdir(bundled):
            disable_plugin(plugin_id)
            _loaded_plugins.pop(plugin_id, None)
            return True, f"'{plugin_id}' is a built-in plugin and can't be removed — it has been disabled instead."
        return False, "Plugin not found."
    try:
        shutil.rmtree(path)
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

    with jen_db() as db, db.cursor() as cur:
        cur.execute("SHOW TABLES LIKE 'plugin_schema_migrations'")
        if not cur.fetchone():
            return set()
        cur.execute("SELECT version FROM plugin_schema_migrations WHERE plugin_id=%s", (plugin_id,))
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
            return (
                False,
                (
                    f"Plugin '{plugin_id}' manifest db_migrations entries must be "
                    f'either a raw SQL string or a {{"version": int, "sql": str}} '
                    f"object — got {m!r}"
                ),
                0,
            )
    raw_migrations = normalized

    migrations = sorted(raw_migrations, key=lambda m: m["version"])
    versions = [m["version"] for m in migrations]
    if len(versions) != len(set(versions)):
        return False, f"Plugin '{plugin_id}' manifest has duplicate migration version numbers.", 0
    if any(not isinstance(v, int) for v in versions):
        return False, f"Plugin '{plugin_id}' manifest migration versions must be integers.", 0

    from jen.models.db import jen_db

    with jen_db() as db, db.cursor() as cur:
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
            with jen_db() as db, db.cursor() as cur:
                cur.execute(m["sql"])
                cur.execute(
                    "INSERT INTO plugin_schema_migrations (plugin_id, version, description) VALUES (%s, %s, %s)",
                    (plugin_id, version, description),
                )
            count += 1
            logger.info(f"Plugin '{plugin_id}' migration {version} applied: {description}")
        except Exception as e:
            msg = f"Plugin '{plugin_id}' migration {version} failed: {e}"
            logger.error(msg)
            return False, msg, count

    return True, "", count


# ── Registry ──────────────────────────────────────────────────────────────────


def fetch_registry(timeout: int = 10) -> tuple[list, str | None]:
    """
    Fetch the plugin registry from GitHub. registry.json is the source
    of truth for every field, including version/description/
    db_migrations.

    v5.3.x — this used to overlay each plugin's version/description/
    db_migrations by live-fetching manifest.json from its own repo's
    `main` branch, to avoid a second, easy-to-forget manual commit
    syncing those fields on every plugin release. v5.21.1 (Q17) removes
    that: every entry's download_url is now pinned to a release TAG
    (not `main`) with a real sha256 of that tag's plugin.zip, so a live
    fetch of `main`'s manifest.json would report a version and
    migration list that may not even match what install_plugin()
    downloads and checksums. registry.json itself is the one thing that
    has to be updated by hand now, in the same commit that pins the tag
    and computes the checksum — see plugins/README.md.
    """
    try:
        resp = requests.get(extensions.PLUGIN_REGISTRY_URL, timeout=timeout)
        if resp.status_code != 200:
            return [], f"Registry fetch failed: HTTP {resp.status_code}"
        entries = resp.json()
        if not isinstance(entries, list):
            return [], "Registry format invalid (expected a JSON array)."
    except requests.Timeout:
        return [], "Registry fetch timed out."
    except Exception as e:
        logger.error(f"Registry fetch error: {e}")
        return [], "Registry fetch failed. Check server logs for details."

    return entries, None


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
