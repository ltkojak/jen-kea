"""
jen/tools/restore.py
──────────────────────
v5.44.0 (Q45) — `python3 -m jen.tools.restore <bundle.tar.enc>`

Run inside the Jen venv, as root, by `sudo ./install.sh --restore` —
the part of the recovery flow that must work with the app not running.
Prompts for the passphrase on the TTY (`getpass` — never a CLI argument
or environment variable; both are visible to any other process on the
box via `/proc` or `ps`), decrypts, checks version compatibility,
writes `/etc/jen` and the content directory, imports the database, and
prints a checklist of what a human still has to do.

Assumes a normal `sudo ./install.sh` has already run on this machine —
this restores STATE onto a working Jen install; it does not set one up
(the venv, the systemd unit, sudoers are untouched). Never touches Kea
hosts — restoring a bundled `kea-configs/*.json` is a reference file
only, not pushed anywhere.
"""

from __future__ import annotations

import argparse
import configparser
import contextlib
import getpass
import gzip
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


class RestoreRefused(RuntimeError):
    """A safety check failed — nothing has been written yet."""


def _existing_owner(path) -> tuple[int, int] | None:
    """`(uid, gid)` of `path` if it already exists, else `None` — a
    restored file matches whatever ownership is already there (set by
    the normal install this restore is layering onto) rather than this
    module guessing a service-user name."""
    try:
        st = os.stat(path)
        return st.st_uid, st.st_gid
    except OSError:
        return None


def _write_file(dest: Path, content: bytes, mode: int, owner: tuple[int, int] | None) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    dest.chmod(mode)
    if owner is not None and hasattr(os, "chown"):
        try:
            os.chown(dest, *owner)
        except OSError as e:
            print(f"warning: could not set ownership on {dest}: {e}", file=sys.stderr)


def extract_bundle(blob: bytes, passphrase: str, dest_dir: Path) -> None:
    """Decrypt and extract every member of the bundle under `dest_dir`.
    Raises `recovery.BadPassphrase` on a wrong passphrase or a
    tampered/corrupt bundle — the caller decides what that means."""
    from jen.services.recovery import open_bundle

    tf = open_bundle(blob, passphrase)
    try:
        safe_extract(tf, Path(dest_dir))
    finally:
        tf.close()


def safe_extract(tf, dest_dir: Path) -> None:
    """Extract every member of `tf` under `dest_dir`, refusing anything that
    is not a plain file or directory with a relative, in-tree name.

    v5.49.0-beta.2 — this runs as root, so it must not depend on which
    patch release of Python is installed: the old `extractall(filter="data")`
    with a bare-`extractall()` fallback on TypeError extracted symlinks,
    hardlinks and `..` paths unrestricted on any interpreter without the
    backported `filter=`. Every member is validated BEFORE anything is
    written, so a refused bundle leaves `dest_dir` untouched; file modes are
    masked to 0o644/0o755 (the restore steps set the real modes afterwards).
    Raises `RestoreRefused` naming the offending member."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    plan = []
    for m in tf.getmembers():
        pure = PurePosixPath(m.name)
        if not (m.isfile() or m.isdir()):
            raise RestoreRefused(f"bundle member {m.name!r} is not a plain file or directory — refusing the bundle")
        if pure.is_absolute() or ".." in pure.parts or not m.name or m.name.startswith(("/", "\\")):
            raise RestoreRefused(f"bundle member {m.name!r} has an unsafe path — refusing the bundle")
        target = (root / Path(*pure.parts)).resolve()
        if target != root and root not in target.parents:
            raise RestoreRefused(f"bundle member {m.name!r} would land outside the restore directory")
        plan.append((m, target))
    for m, target in plan:
        if m.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(m)
        with open(target, "wb") as out:
            out.write(src.read())
        target.chmod(0o755 if m.mode & 0o111 else 0o644)


def load_manifest(bundle_dir: Path) -> dict:
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.is_file():
        raise RestoreRefused("bundle has no manifest.json — not a Jen recovery bundle")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def check_jen_major(manifest: dict) -> None:
    from jen import JEN_VERSION
    from jen.version import parse_version

    bundle_major = parse_version(manifest.get("jen_version", ""))[0]
    here_major = parse_version(JEN_VERSION)[0]
    if bundle_major != here_major:
        raise RestoreRefused(
            f"this bundle was made by Jen {manifest.get('jen_version')} (major {bundle_major}); "
            f"this install is Jen {JEN_VERSION} (major {here_major}). Restoring across a MAJOR "
            f"version is not supported — install a matching Jen major version first, then restore."
        )


def check_bundle_version(manifest: dict, force: bool = False) -> None:
    """Refuse a bundle from a NEWER Jen, or one whose schema is ahead of this
    install's migrations, unless `force`. An older bundle into a newer Jen is
    the supported direction: migrations run forward at the next boot."""
    from jen import JEN_VERSION
    from jen.models.migrations import MIGRATIONS
    from jen.version import numeric

    if force:
        return
    if numeric(manifest.get("jen_version", "")) > numeric(JEN_VERSION):
        raise RestoreRefused(
            f"this bundle was made by Jen {manifest.get('jen_version')}, newer than this install "
            f"(Jen {JEN_VERSION}). Upgrade Jen first, or pass --force if you know the state is compatible."
        )
    here_schema = MIGRATIONS[-1][0] if MIGRATIONS else 0
    bundle_schema = manifest.get("schema_version", 0)
    if isinstance(bundle_schema, int) and bundle_schema > here_schema:
        raise RestoreRefused(
            f"this bundle's database schema (v{bundle_schema}) is ahead of this install's (v{here_schema}). "
            "Upgrade Jen first, or pass --force to restore anyway."
        )


def check_kea_major(manifest: dict, bundle_dir: Path) -> list[str]:
    """Probes each server named in the bundle's own jen.config (NOT the
    real one — that hasn't been written yet) with the bundle's own
    connection settings, and compares against the version the manifest
    recorded at export time. Returns warning lines (never raises for an
    unreachable server — that's a documented skip, not a refusal); DOES
    raise RestoreRefused for a reachable server whose MAJOR now differs
    from what the manifest recorded, since the bundled reservations/
    config may no longer apply."""
    from jen import config as jen_config
    from jen import extensions
    from jen.services import kea as kea_svc
    from jen.version import parse_version

    warnings: list[str] = []
    bundled_config = bundle_dir / "jen.config"
    if not bundled_config.is_file():
        warnings.append("bundle has no jen.config — skipping the Kea version check entirely")
        return warnings

    original_config_file = extensions.CONFIG_FILE
    try:
        extensions.CONFIG_FILE = str(bundled_config)
        jen_config.app_config.reload()
        recorded = manifest.get("kea_versions", {})
        for srv in extensions.KEA_SERVERS:
            name = srv.get("name", "?")
            try:
                r = kea_svc.kea_command("version-get", server=srv, timeout=5)
            except Exception as e:
                warnings.append(f"{name}: unreachable ({e}) — Kea version check skipped for this server")
                continue
            if r.get("result") != 0:
                warnings.append(f"{name}: unreachable — Kea version check skipped for this server")
                continue
            live_text = r.get("arguments", {}).get("extended", r.get("text", ""))
            live_version = live_text.splitlines()[0] if live_text else ""
            recorded_version = recorded.get(name, "")
            if not recorded_version:
                warnings.append(f"{name}: manifest recorded no version at export time — skipping the comparison")
                continue
            live_major = parse_version(live_version)[0]
            recorded_major = parse_version(recorded_version)[0]
            if live_major and recorded_major and live_major != recorded_major:
                raise RestoreRefused(
                    f"{name} is now running Kea major {live_major} ({live_version!r}) but the bundle "
                    f"was made against Kea major {recorded_major} ({recorded_version!r}) — the bundled "
                    f"reservations/config may not apply. Resolve the Kea version mismatch first."
                )
    finally:
        # Restore the VALUES, not just the path string — apply() derived
        # every extensions.* global from the bundle's config above, and
        # leaving that in place would be wrong for anything that runs
        # after this (including restore_jen_db() a few lines down, and
        # the test suite's own environment for a caller that runs this
        # mid-test). Best-effort: if the ORIGINAL config can't be
        # reloaded either (e.g. it never existed), that's a pre-existing
        # problem this function didn't cause — don't let it mask
        # whatever this function actually found.
        extensions.CONFIG_FILE = original_config_file
        try:
            jen_config.app_config.reload()
        except Exception as e:
            print(f"warning: could not reload {original_config_file} after the Kea version check: {e}", file=sys.stderr)
    return warnings


def restore_etc_jen(bundle_dir: Path, etc_jen: Path) -> list[str]:
    lines = []
    owner = _existing_owner(etc_jen) or _existing_owner(etc_jen.parent)

    config_src = bundle_dir / "jen.config"
    if config_src.is_file():
        _write_file(etc_jen / "jen.config", config_src.read_bytes(), 0o600, owner)
        lines.append("wrote jen.config")

    for key_name in ("mfa_key", "secret_key"):
        key_src = bundle_dir / key_name
        if key_src.is_file():
            _write_file(etc_jen / key_name, key_src.read_bytes(), 0o600, owner)
            lines.append(f"wrote {key_name}")

    for sub in ("ssl", "ssh"):
        src_root = bundle_dir / sub
        if not src_root.is_dir():
            continue
        count = 0
        for path in src_root.rglob("*"):
            if path.is_file():
                rel = path.relative_to(src_root)
                _write_file(etc_jen / sub / rel, path.read_bytes(), 0o600, owner)
                count += 1
        if count:
            lines.append(f"wrote {count} file(s) under {sub}/")
    return lines


def _bundle_owned(bundle_dir: Path) -> tuple[set[str], set[str]]:
    """(paths under /etc/jen, paths under the content dir) that this bundle
    writes — everything else already on disk is left alone."""
    etc: set[str] = set()
    for name in ("jen.config", "mfa_key", "secret_key"):
        if (bundle_dir / name).is_file():
            etc.add(name)
    for sub in ("ssl", "ssh"):
        root = bundle_dir / sub
        if root.is_dir():
            etc |= {f"{sub}/{p.relative_to(root).as_posix()}" for p in root.rglob("*") if p.is_file()}
    croot = bundle_dir / "content"
    content = {p.relative_to(croot).as_posix() for p in croot.rglob("*") if p.is_file()} if croot.is_dir() else set()
    return etc, content


def unknown_files(root: Path, owned: set[str], exclude: tuple[str, ...] = ()) -> list[str]:
    """Files under `root` that the bundle does not carry. The rule: bundle
    files overwrite, unknown files are LEFT IN PLACE (never deleted) and named
    in the output so the operator can decide."""
    if not Path(root).is_dir():
        return []
    return sorted(rel for rel, path in _walk_files(Path(root), exclude) if path.is_file() and rel not in owned)


def check_plugins(manifest: dict, plugin_dirs) -> list[str]:
    """Warnings (never refusals) for plugins the manifest recorded whose code
    is not present on this machine — their database rows are restored anyway."""
    out = []
    for p in manifest.get("plugins") or []:
        pid = p.get("id") if isinstance(p, dict) else None
        if pid and not any((Path(d) / pid).is_dir() for d in plugin_dirs):
            out.append(
                f"plugin {pid!r} is in the bundle but its code is not on this machine — "
                "reinstall it from Settings → Plugins (its database row is kept)"
            )
    return out


def restore_content(bundle_dir: Path, content_dir: Path) -> int:
    src_root = bundle_dir / "content"
    if not src_root.is_dir():
        return 0
    owner = _existing_owner(content_dir)
    count = 0
    for path in src_root.rglob("*"):
        if path.is_file():
            rel = path.relative_to(src_root)
            # A bundle from before v5.49.0-beta.2 carried the fallback key
            # files (content/keys/) as ordinary content; never write one
            # back world-readable.
            mode = 0o600 if rel.parts and rel.parts[0] == "keys" else 0o644
            _write_file(content_dir / rel, path.read_bytes(), mode, owner)
            count += 1
    return count


def restore_jen_db(bundle_dir: Path, config_file: Path) -> list[str]:
    """Import jen_db.json.gz through the DB import already used by
    Settings → Databases → Import — the same code path, just driven
    from a standalone script instead of a web request. Points
    extensions.CONFIG_FILE at the config just restored to `config_file`
    and reloads, so the DB credentials used are the ones that were
    just written — not whatever the pre-restore install had, and not
    whatever this process happened to have loaded earlier."""
    from jen import config as jen_config
    from jen import extensions
    from jen.services import dbexport

    extensions.CONFIG_FILE = str(config_file)
    jen_config.app_config.reload()

    db_file = bundle_dir / "jen_db.json.gz"
    if not db_file.is_file():
        return ["no jen_db.json.gz in bundle — database not restored"]
    return dbexport.import_jen(db_file.read_bytes())


# ── lifecycle: quiesce → snapshot → apply → start → health-check → roll back ──
#
# v5.49.0-beta.4 (Q55) — `install.sh --restore` used to rewrite jen.config,
# keys, content and the database underneath a RUNNING gunicorn + background
# workers, and gave no way back from a restore that broke Jen. The tool now
# stops the service (when it is a systemd unit that is running), takes a
# snapshot of everything it is about to overwrite, applies the bundle,
# starts Jen again, polls it, and rolls the snapshot back on any failure.

SERVICE = "jen"
_SNAPSHOT_EXCLUDE = ("backups", "tmp")  # top-level content dirs left out of snapshots
HEALTH_TIMEOUT_S = 60


def _have_systemctl() -> bool:
    return shutil.which("systemctl") is not None


def _systemctl(*args: str) -> int:
    """List-args, never a shell string. Returns the exit status."""
    return subprocess.run(["systemctl", *args], capture_output=True, text=True).returncode


def _service_active() -> bool:
    return _systemctl("is-active", "--quiet", SERVICE) == 0


def _service_port(config_file: Path) -> int:
    cp = configparser.ConfigParser()
    try:
        cp.read(config_file, encoding="utf-8")
        return cp.getint("server", "http_port", fallback=5050)
    except (configparser.Error, ValueError):
        return 5050


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # a 30x is an answer, not something to follow blindly
        return None


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost")


def _probe_health(url: str) -> tuple[bool, str | None]:
    """One GET of a health URL. Returns (healthy, redirect_location). Healthy
    means HTTP 200 with a JSON object carrying `jen_version` — a 404 from some
    other service on the port, a login page, or a proxy error page is not Jen."""
    import json as _json
    import ssl

    handlers: list = [_NoRedirect]
    if url.startswith("https://"):
        ctx = ssl.create_default_context()
        # Loopback only, and only ever Jen's own self-signed certificate.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(url, timeout=5) as resp:
            if resp.status != 200:
                return False, None
            body = _json.loads(resp.read(65536).decode("utf-8", "replace"))
            return (isinstance(body, dict) and bool(body.get("jen_version"))), None
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            return False, e.headers.get("Location")
        return False, None
    except Exception:
        return False, None


def _wait_healthy(port: int, timeout: float = HEALTH_TIMEOUT_S, interval: float = 2.0) -> bool:
    """Poll /api/v1/health (unauthenticated) until Jen answers 200 with a JSON
    body containing `jen_version`. With HTTPS on, the plain port only
    redirects: a redirect is followed ONLY to https://127.0.0.1:<port>/… or
    https://localhost:<port>/… (Jen's own jen/httpredirect.py), fetched
    without certificate verification (self-signed, loopback), and must itself
    answer 200 + JSON. 401, 404, a non-JSON 200 and a redirect anywhere else
    are unhealthy."""
    from urllib.parse import urlsplit

    deadline = time.monotonic() + timeout
    while True:
        ok, location = _probe_health(f"http://127.0.0.1:{port}/api/v1/health")
        if not ok and location:
            parts = urlsplit(location)
            if parts.scheme == "https" and parts.hostname in _LOOPBACK_HOSTS and parts.port:
                ok, _again = _probe_health(f"https://{parts.hostname}:{parts.port}{parts.path or '/'}")
        if ok:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def _point_config_at(cfg: Path) -> None:
    from jen import config as jen_config
    from jen import extensions

    extensions.CONFIG_FILE = str(cfg)
    jen_config.app_config.reload()


def _export_db() -> bytes:
    from jen.services import dbexport

    content, _fname = dbexport.export_jen()
    return gzip.compress(content)


def _import_db(gz: bytes) -> list[str]:
    from jen.services import dbexport

    return dbexport.import_jen(gz)


def _walk_files(root: Path, exclude: tuple[str, ...]):
    """(relative posix name, path) for every regular file/dir under `root`,
    pruning top-level directories named in `exclude`. Symlinks are skipped."""
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        if rel_dir == Path("."):
            dirnames[:] = [d for d in dirnames if d not in exclude]
        for name in sorted(dirnames) + sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            yield (rel_dir / name).as_posix(), path


def _tar_tree(root: Path, out: Path, exclude: tuple[str, ...] = ()) -> None:
    with tarfile.open(out, "w") as tf:
        if root.is_dir():
            for rel, path in _walk_files(root, exclude):
                tf.add(path, arcname=rel, recursive=False)
    os.chmod(out, 0o600)


def take_snapshot(etc_jen: Path, content_dir: Path) -> Path:
    """`<content>/backups/pre-restore-<UTC ts>/`: a tar of /etc/jen, a tar of
    the content dir minus backups/tmp, and a fresh jen_db.json.gz — all 0600
    in a 0700 directory. Raises on any failure (the caller refuses the
    restore rather than proceed without a way back)."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = Path(content_dir) / "backups" / f"pre-restore-{ts}"
    snap, n = base, 1
    while True:  # two restores in the same second must not collide
        try:
            snap.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            n += 1
            snap = base.with_name(f"{base.name}-{n}")
    os.chmod(snap, 0o700)
    _tar_tree(Path(etc_jen), snap / "etc-jen.tar")
    _tar_tree(Path(content_dir), snap / "content.tar", _SNAPSHOT_EXCLUDE)
    db = snap / "jen_db.json.gz"
    db.write_bytes(_export_db())
    os.chmod(db, 0o600)
    return snap


def _restore_tree(tar_path: Path, root: Path, exclude: tuple[str, ...] = ()) -> None:
    """Make `root` match the snapshot tar again: extract every member with its
    recorded mode/owner, and delete regular files the restore ADDED (present
    on disk, absent from the tar). Members are validated like safe_extract's."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    real = root.resolve()
    with tarfile.open(tar_path) as tf:
        members = tf.getmembers()
        for m in members:
            pure = PurePosixPath(m.name)
            if not (m.isfile() or m.isdir()) or pure.is_absolute() or ".." in pure.parts:
                raise RestoreRefused(f"snapshot member {m.name!r} is not a plain in-tree file or directory")
            target = (real / Path(*pure.parts)).resolve()
            if target != real and real not in target.parents:
                raise RestoreRefused(f"snapshot member {m.name!r} would land outside {root}")
        wanted = {m.name for m in members if m.isfile()}
        for rel, path in list(_walk_files(root, exclude)):
            if path.is_file() and rel not in wanted:
                path.unlink()
        for m in members:
            target = root / Path(*PurePosixPath(m.name).parts)
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tf.extractfile(m).read())
            target.chmod(m.mode & 0o777)
            if hasattr(os, "chown"):
                with contextlib.suppress(OSError):
                    os.chown(target, m.uid, m.gid)


def rollback_snapshot(snap: Path, etc_jen: Path, content_dir: Path) -> None:
    """Put /etc/jen, the content dir and the database back the way the
    snapshot found them."""
    snap = Path(snap)
    _restore_tree(snap / "etc-jen.tar", Path(etc_jen))
    _restore_tree(snap / "content.tar", Path(content_dir), _SNAPSHOT_EXCLUDE)
    cfg = Path(etc_jen) / "jen.config"
    if cfg.is_file():
        _point_config_at(cfg)  # the DB credentials are the ORIGINAL ones again
    _import_db((snap / "jen_db.json.gz").read_bytes())


def _fail_with_rollback(snap: Path, etc_jen: Path, content_dir: Path, reason: str, manage: bool, restart: bool) -> int:
    print(f"error: {reason}", file=sys.stderr)
    print(f"rolling back from {snap} …", file=sys.stderr)
    if manage:
        _systemctl("stop", SERVICE)
    try:
        rollback_snapshot(snap, etc_jen, content_dir)
    except Exception as e:
        print(f"ROLLBACK FAILED: {e}", file=sys.stderr)
        print(
            f"The snapshot is intact at {snap}. Redo it by hand: sudo ./install.sh --rollback {snap}", file=sys.stderr
        )
        return 2
    if manage and restart:
        _systemctl("start", SERVICE)
    print(f"rolled back — Jen is as it was before the restore. Snapshot kept at {snap}", file=sys.stderr)
    return 1


def run(
    bundle_path: str,
    passphrase: str,
    etc_jen: str = "/etc/jen",
    content_dir: str | None = None,
    force: bool = False,
    no_stop: bool = False,
    start: bool = False,
) -> int:
    import tempfile

    from jen import extensions
    from jen.services.recovery import BadPassphrase

    content_dir = content_dir or extensions.CONTENT_DIR

    blob = Path(bundle_path).read_bytes()
    with tempfile.TemporaryDirectory(prefix="jen-restore-") as tmp:
        bundle_dir = Path(tmp)
        try:
            extract_bundle(blob, passphrase, bundle_dir)
        except BadPassphrase as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

        try:
            manifest = load_manifest(bundle_dir)
            check_jen_major(manifest)
            check_bundle_version(manifest, force=force)
            kea_warnings = check_kea_major(manifest, bundle_dir)
        except RestoreRefused as e:
            print(f"refused: {e}", file=sys.stderr)
            return 1

        for w in kea_warnings:
            print(f"warning: {w}", file=sys.stderr)
        for w in check_plugins(manifest, [Path(content_dir) / "plugins", Path(extensions.JEN_ROOT) / "plugins"]):
            print(f"warning: {w}", file=sys.stderr)
        etc_owned, content_owned = _bundle_owned(bundle_dir)

        # ── quiesce ──────────────────────────────────────────────────────
        manage = not no_stop
        if no_stop:
            print(
                "--no-stop: not stopping or starting Jen — make sure it is stopped, and start it yourself afterwards."
            )
        elif not _have_systemctl():
            manage = False
            print("systemctl not found — treating this as --no-stop (stop and start Jen yourself).")
        was_running = False
        if manage:
            was_running = _service_active()
            if was_running:
                print("stopping jen …")
                if _systemctl("stop", SERVICE) != 0:
                    print("refused: could not stop the jen service — nothing was changed.", file=sys.stderr)
                    return 1
            else:
                print("jen is not running — leaving it stopped unless --start is given.")

        # ── snapshot ─────────────────────────────────────────────────────
        try:
            snap = take_snapshot(Path(etc_jen), Path(content_dir))
        except Exception as e:
            print(f"refused: could not snapshot the current state ({e}) — nothing was changed.", file=sys.stderr)
            if manage and was_running:
                _systemctl("start", SERVICE)
            return 1
        print(f"snapshot of the current state: {snap}")

        # ── apply ────────────────────────────────────────────────────────
        restart = was_running or start
        try:
            for line in restore_etc_jen(bundle_dir, Path(etc_jen)):
                print(line)
            content_count = restore_content(bundle_dir, Path(content_dir))
            print(f"restored {content_count} content file(s)")
            for line in restore_jen_db(bundle_dir, Path(etc_jen) / "jen.config"):
                print(line)
        except Exception as e:
            return _fail_with_rollback(
                snap, Path(etc_jen), Path(content_dir), f"apply failed: {e}", manage, was_running
            )

        for label, root, owned, excl in (
            ("/etc/jen", Path(etc_jen), etc_owned, ()),
            ("the content directory", Path(content_dir), content_owned, _SNAPSHOT_EXCLUDE),
        ):
            extra = unknown_files(root, owned, excl)
            if extra:
                shown = ", ".join(extra[:20]) + (f" … (+{len(extra) - 20} more)" if len(extra) > 20 else "")
                print(f"left in place (not in the bundle) under {label}: {shown}")

        # ── start + health-check ─────────────────────────────────────────
        if manage and restart:
            print("starting jen …")
            port = _service_port(Path(etc_jen) / "jen.config")
            if _systemctl("start", SERVICE) != 0 or not _wait_healthy(port):
                return _fail_with_rollback(
                    snap,
                    Path(etc_jen),
                    Path(content_dir),
                    f"Jen did not come up healthy on port {port} after the restore",
                    manage,
                    was_running,
                )
            print("jen is up and answering.")

    print()
    print(f"Recovery bundle restored. A snapshot of what it replaced is at {snap}")
    print(f"(undo with: sudo ./install.sh --rollback {snap})")
    print("Next:")
    if not (manage and restart):
        print("  1. Start Jen: sudo systemctl start jen")
    else:
        print("  1. Confirm Jen is up and you can log in.")
    print("  2. Log in and go to Settings → Kea → SSH — run 'Update helper' on each server")
    print("     (a helper version mismatch after a restore is expected, not a bug).")
    print("  3. Check Settings → Plugins — any plugin the manifest recorded is back in the")
    print("     database, but its code was NOT re-copied here; reinstall from the registry")
    print("     for anything the page flags as missing.")
    print("  4. Confirm HTTPS and SSH to your Kea hosts both still work as expected.")
    return 0


def run_rollback(
    snapshot_dir: str, etc_jen: str = "/etc/jen", content_dir: str | None = None, no_stop: bool = False
) -> int:
    """`--rollback <dir>`: redo the rollback by hand from a named snapshot."""
    from jen import extensions

    snap = Path(snapshot_dir)
    for name in ("etc-jen.tar", "content.tar", "jen_db.json.gz"):
        if not (snap / name).is_file():
            print(f"error: {snap} is not a pre-restore snapshot (missing {name})", file=sys.stderr)
            return 1
    content_dir = content_dir or extensions.CONTENT_DIR
    manage = not no_stop and _have_systemctl()
    was_running = manage and _service_active()
    if manage and was_running:
        print("stopping jen …")
        if _systemctl("stop", SERVICE) != 0:
            print("refused: could not stop the jen service — nothing was changed.", file=sys.stderr)
            return 1
    try:
        rollback_snapshot(snap, Path(etc_jen), Path(content_dir))
    except Exception as e:
        print(f"ROLLBACK FAILED: {e}", file=sys.stderr)
        if manage and was_running:
            _systemctl("start", SERVICE)
        return 2
    print(f"rolled back from {snap}")
    if manage and was_running:
        _systemctl("start", SERVICE)
        print("started jen.")
    elif not manage:
        print("Start Jen yourself: sudo systemctl start jen")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m jen.tools.restore",
        description="Restore Jen from an encrypted recovery bundle (Settings → Databases → Recovery).",
    )
    parser.add_argument("bundle", nargs="?", default=None, help="Path to the jen-recovery-*.tar.enc bundle")
    parser.add_argument(
        "--no-stop",
        action="store_true",
        help="Do not stop/start the jen service (Docker, or a Jen that is not a systemd unit)",
    )
    parser.add_argument(
        "--start", action="store_true", help="Start Jen after the restore even if it was not running before"
    )
    parser.add_argument(
        "--rollback",
        metavar="SNAPSHOT_DIR",
        default=None,
        help="Undo a restore from its pre-restore snapshot directory",
    )
    parser.add_argument("--etc-jen", default="/etc/jen", help="Where to write config/keys (default: /etc/jen)")
    parser.add_argument("--content-dir", default=None, help="Where to restore content (default: Jen's own)")
    parser.add_argument("--force", action="store_true", help="Restore a bundle from a newer Jen / newer schema anyway")
    args = parser.parse_args(argv)

    if args.rollback:
        return run_rollback(args.rollback, etc_jen=args.etc_jen, content_dir=args.content_dir, no_stop=args.no_stop)
    if not args.bundle:
        parser.error("a bundle path is required (or --rollback SNAPSHOT_DIR)")

    if not os.path.isfile(args.bundle):
        print(f"error: {args.bundle} not found", file=sys.stderr)
        return 1

    passphrase = getpass.getpass("Recovery bundle passphrase: ")
    if not passphrase:
        print("error: passphrase must not be empty", file=sys.stderr)
        return 1

    return run(
        args.bundle,
        passphrase,
        etc_jen=args.etc_jen,
        content_dir=args.content_dir,
        force=args.force,
        no_stop=args.no_stop,
        start=args.start,
    )


if __name__ == "__main__":
    sys.exit(main())
