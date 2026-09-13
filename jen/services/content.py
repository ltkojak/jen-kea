"""
jen/services/content.py
───────────────────────
v5.13.0 — user-writable content moved out of the application tree.

`/opt/jen` is reinstalled from the release tarball on every upgrade and is
now root-owned / read-only to the service user. Everything Jen writes at
runtime — uploaded brand icons, the nav logo, a custom favicon, DB
backups, registry-installed plugins, plugin enable markers, and the
secret-key / MFA-key fallbacks — lives under `extensions.CONTENT_DIR`
(`/var/lib/jen` in production, `$JEN_ROOT/var` in a checkout).

`ensure_content_dirs()` creates the subtree at startup; `migrate_legacy_content()`
does a best-effort COPY from the old `/opt/jen/...` locations for a box the
installer/updater migration missed (notably Docker's old `jen-icons`
named volume). Both are called once from `create_app()` and never crash
the factory.
"""

import hashlib
import logging
import os
import shutil

from jen import extensions

logger = logging.getLogger(__name__)

_CONTENT_SUBDIRS = (
    "CONTENT_ICONS_DIR",
    "CONTENT_BRANDING_DIR",
    "CONTENT_BACKUP_DIR",
    "CONTENT_PLUGIN_DIR",
    "CONTENT_PLUGINS_ENABLED_DIR",
    "CONTENT_PLUGIN_REQUESTS_DIR",
    "CONTENT_KEYS_DIR",
)


# Set by ensure_content_dirs(): True once CONTENT_DIR exists and Jen can
# write into it. base.html shows an admin banner when this is False (the
# box went 5.12→5.13 in-app so the root migration never ran, or perms are
# wrong — `sudo ./install.sh` fixes it). v5.15.0.
_CONTENT_DIR_WRITABLE = True


def ensure_content_dirs() -> None:
    """Create CONTENT_DIR and its subtree. `send_from_directory` needs the
    directory to exist even when empty. Logs and moves on if it can't —
    never crashes the factory (a broken deployment shows 404s, not a
    dead app), but records the failure so an admin gets a banner."""
    global _CONTENT_DIR_WRITABLE
    ok = True
    for attr in _CONTENT_SUBDIRS:
        path = getattr(extensions, attr)
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            logger.warning(f"content: could not create {path}: {e}")
            ok = False
    if ok:
        # makedirs on an existing dir doesn't prove writability — probe it.
        probe = os.path.join(extensions.CONTENT_DIR, ".jen-write-test")
        try:
            with open(probe, "w") as f:
                f.write("")
            os.remove(probe)
        except OSError as e:
            logger.warning(f"content: {extensions.CONTENT_DIR} is not writable: {e}")
            ok = False
    _CONTENT_DIR_WRITABLE = ok


def content_dir_incomplete() -> bool:
    """True when CONTENT_DIR is missing or unwritable — an admin needs to
    run `sudo ./install.sh`. Never flagged for a dev checkout / Docker
    (those set JEN_CONTENT_DIR or a writable $JEN_ROOT/var)."""
    if os.environ.get("JEN_ROOT") or os.environ.get("JEN_CONTENT_DIR") or os.path.exists("/.dockerenv"):
        return False
    return not _CONTENT_DIR_WRITABLE


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _copy_tree_if_new_empty(src: str, dst: str, label: str) -> None:
    """Copy every entry of src into dst, skipping any that already exist in
    dst. Never moves — the old tree may be owned by root or a named volume."""
    if not os.path.isdir(src):
        return
    copied = 0
    for name in os.listdir(src):
        s = os.path.join(src, name)
        d = os.path.join(dst, name)
        if os.path.exists(d):
            continue
        try:
            os.makedirs(dst, exist_ok=True)
            if os.path.isdir(s):
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)
            copied += 1
        except OSError as e:
            logger.warning(f"content migrate ({label}): {name}: {e}")
    if copied:
        logger.info(f"content migrate ({label}): copied {copied} item(s) from {src}")


def migrate_legacy_content() -> None:
    """Best-effort COPY of pre-5.13 content from /opt/jen into CONTENT_DIR.
    Idempotent (skips anything already present at the destination) and
    never moves. Covers a box the root-side migration missed and Docker's
    old `jen-icons` volume."""
    root = extensions.JEN_ROOT
    old_icons = os.path.join(root, "static", "icons", "custom")
    old_backups = os.path.join(root, "backups")
    old_plugins = os.path.join(root, "plugins")

    _copy_tree_if_new_empty(old_icons, extensions.CONTENT_ICONS_DIR, "icons")
    _copy_tree_if_new_empty(old_backups, extensions.CONTENT_BACKUP_DIR, "backups")

    # nav logo: the legacy static/ location -> branding/nav_logo.<ext>
    for ext in ("png", "svg", "jpg", "jpeg", "webp"):
        s = os.path.join(root, "static", f"nav_logo.{ext}")
        d = os.path.join(extensions.CONTENT_BRANDING_DIR, f"nav_logo.{ext}")
        if os.path.isfile(s) and not os.path.exists(d):
            try:
                os.makedirs(extensions.CONTENT_BRANDING_DIR, exist_ok=True)
                shutil.copy2(s, d)
                logger.info(f"content migrate (branding): nav_logo.{ext}")
            except OSError as e:
                logger.warning(f"content migrate (branding): nav_logo.{ext}: {e}")

    # favicon: only if the box's static/favicon.ico differs from the shipped
    # default (i.e. the operator uploaded one on a pre-5.13 box).
    old_favicon = os.path.join(root, "static", "favicon.ico")
    if os.path.isfile(old_favicon) and not os.path.exists(extensions.FAVICON_PATH):
        try:
            if _sha256(old_favicon) != extensions.SHIPPED_FAVICON_SHA256:
                os.makedirs(extensions.CONTENT_BRANDING_DIR, exist_ok=True)
                shutil.copy2(old_favicon, extensions.FAVICON_PATH)
                logger.info("content migrate (branding): custom favicon.ico")
        except OSError as e:
            logger.warning(f"content migrate (branding): favicon: {e}")

    # plugins: a registry-installed plugin whose id is NOT one Jen ships
    # (ipam, network-discovery) → copy the dir; the .enabled marker (bundled
    # ones too) → recreate under plugins-enabled/<id>.
    from jen.services.plugins import SHIPPED_PLUGIN_IDS

    if os.path.isdir(old_plugins):
        for pid in os.listdir(old_plugins):
            src = os.path.join(old_plugins, pid)
            if not os.path.isdir(src):
                continue
            dst = os.path.join(extensions.CONTENT_PLUGIN_DIR, pid)
            if pid not in SHIPPED_PLUGIN_IDS and not os.path.exists(dst):
                try:
                    os.makedirs(extensions.CONTENT_PLUGIN_DIR, exist_ok=True)
                    shutil.copytree(src, dst)
                    logger.info(f"content migrate (plugins): {pid}")
                except OSError as e:
                    logger.warning(f"content migrate (plugins): {pid}: {e}")
            marker = os.path.join(src, ".enabled")
            new_marker = os.path.join(extensions.CONTENT_PLUGINS_ENABLED_DIR, pid)
            if os.path.isfile(marker) and not os.path.exists(new_marker):
                try:
                    os.makedirs(extensions.CONTENT_PLUGINS_ENABLED_DIR, exist_ok=True)
                    with open(new_marker, "w"):
                        pass
                    logger.info(f"content migrate (plugins-enabled): {pid}")
                except OSError as e:
                    logger.warning(f"content migrate (plugins-enabled): {pid}: {e}")

    # secret-key / MFA-key fallbacks: $JEN_ROOT/.secret_key, $JEN_ROOT/.mfa_key
    for fn in (".secret_key", ".mfa_key"):
        s = os.path.join(root, fn)
        d = os.path.join(extensions.CONTENT_KEYS_DIR, fn)
        if os.path.isfile(s) and not os.path.exists(d):
            try:
                os.makedirs(extensions.CONTENT_KEYS_DIR, exist_ok=True)
                shutil.copy2(s, d)
                logger.info(f"content migrate (keys): {fn}")
            except OSError as e:
                logger.warning(f"content migrate (keys): {fn}: {e}")
