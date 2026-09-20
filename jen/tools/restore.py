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
import getpass
import json
import os
import sys
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


def run(
    bundle_path: str,
    passphrase: str,
    etc_jen: str = "/etc/jen",
    content_dir: str | None = None,
    force: bool = False,
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

        etc_lines = restore_etc_jen(bundle_dir, Path(etc_jen))
        for line in etc_lines:
            print(line)

        content_count = restore_content(bundle_dir, Path(content_dir))
        print(f"restored {content_count} content file(s)")

        db_results = restore_jen_db(bundle_dir, Path(etc_jen) / "jen.config")
        for line in db_results:
            print(line)

    print()
    print("Recovery bundle restored. Next:")
    print("  1. Restart Jen: sudo systemctl restart jen")
    print("  2. Log in and go to Settings → Kea → SSH — run 'Update helper' on each server")
    print("     (a helper version mismatch after a restore is expected, not a bug).")
    print("  3. Check Settings → Plugins — any plugin the manifest recorded is back in the")
    print("     database, but its code was NOT re-copied here; reinstall from the registry")
    print("     for anything the page flags as missing.")
    print("  4. Confirm HTTPS and SSH to your Kea hosts both still work as expected.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m jen.tools.restore",
        description="Restore Jen from an encrypted recovery bundle (Settings → Databases → Recovery).",
    )
    parser.add_argument("bundle", help="Path to the jen-recovery-*.tar.enc bundle")
    parser.add_argument("--etc-jen", default="/etc/jen", help="Where to write config/keys (default: /etc/jen)")
    parser.add_argument("--content-dir", default=None, help="Where to restore content (default: Jen's own)")
    parser.add_argument("--force", action="store_true", help="Restore a bundle from a newer Jen / newer schema anyway")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.bundle):
        print(f"error: {args.bundle} not found", file=sys.stderr)
        return 1

    passphrase = getpass.getpass("Recovery bundle passphrase: ")
    if not passphrase:
        print("error: passphrase must not be empty", file=sys.stderr)
        return 1

    return run(args.bundle, passphrase, etc_jen=args.etc_jen, content_dir=args.content_dir, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
