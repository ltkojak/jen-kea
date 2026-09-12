#!/usr/bin/env python3
"""
/usr/local/sbin/jen-update-root.py
──────────────────────────────────
v5.2.6 — security fix. This script exists to close a real privilege
escalation path: the previous design had www-data (the Jen web
process) write a helper script to /tmp/jen_update_install.sh and then
`sudo` execute it as root. Since /tmp is world-writable and www-data
is the exact account permitted to write that exact path, the entire
checksum/signature verification built into the old self_update() Flask
route was irrelevant to an attacker who had already gained ANY code
execution as www-data through a completely unrelated bug — they never
needed to go through the update route at all. They could write that
file themselves and sudo it directly: instant root.

The fix moves the entire download → verify → extract → install
pipeline into this script, which:
  - lives outside every directory www-data can write to (NOT under
    /opt/jen at all, where install.sh's own `chown -R www-data:www-data`
    would otherwise silently re-expose it)
  - is owned root:root, mode 0700 — www-data cannot read or modify it
  - takes NO arguments and reads NO input from www-data at all — it
    always re-derives "the current latest release" from GitHub itself,
    the same way the old code did, but that re-derivation now happens
    in the trusted context instead of the untrusted one
  - is only reachable via `sudo systemctl start jen-update.service`,
    which takes no parameters, mirroring the existing safe
    `sudo systemctl restart jen` sudoers pattern already used elsewhere

The practical result: even a fully-compromised www-data account can
now only ever trigger "install whatever GitHub currently publishes as
the latest jen-kea release" — nothing else. It cannot inject arbitrary
file content or arbitrary commands into the root execution context,
because nothing it controls ever reaches this script as input.

Also fixes a separate issue found in the same review: the old code
proceeded with an UNVERIFIED update if a checksum file was missing, had
no matching entry, or failed to parse — logging a warning and
continuing anyway. This script fails closed: no valid checksum match,
no update, full stop.

v5.3.3 — a third-party review of this whole redesign correctly pointed
out a maintainability gap it introduced: this script installed the
application it updates, but never a new copy of itself, or of
jen-update.service. A fix shipped inside jen-update-root.py would
therefore never reach an already-running instance via the in-app
update button — only a manual `sudo ./install.sh --upgrade` would ever
pick it up, quietly recreating the exact "self-update can't fix
itself" trap this redesign exists to close for the application. See
install_self_update_files() below for the fix and the safety reasoning
for replacing this script's own installed copy while it's the one
currently running.

v5.5.0 — the flow started running pip, non-fatally, because run.py went
from werkzeug to gunicorn and a file-only update would land run.py
expecting a package that wasn't there.

v5.8.0 — the flow is now transactional and venv-based:
  1. download + checksum-verify, extract to a staging dir
  2. ensure /opt/jen/venv exists (create it if this install predates it)
  3. pip install the *staged* requirements.txt into the venv — a failure
     here aborts before any file in /opt/jen is touched
  4. compile + import the staged jen/ package under the updated venv —
     a failure aborts, still nothing changed
  5. snapshot everything a rollback needs — the replace-wholesale parts
     of /opt/jen AND the out-of-tree files an update can replace
     (jen.service, /etc/sudoers.d/jen, this script, jen-update.service)
  6. swap the files in, restart, health-check (unit active + HTTP answers)
  7. on ANY failure from step 6 — an exception during the swap, or an
     unhealthy service — restore the whole snapshot (daemon-reload
     included) and restart the previous version

v5.8.1 — step 7 now also catches an exception *during* the file swap
(5.8.0 only rolled back on the health check), and the snapshot covers
the external unit/sudoers/updater files so a bad jen.service can't
survive a rollback.

v5.8.2 — from a real stuck box. Step 2 now demands a venv with a working
pip (a half-built venv from a failed `python3 -m venv` used to be handed
straight to pip), apt-installs python3-venv and retries if the OS package
is missing, and logs the actual pip output on every failed attempt. Step
6 also byte-compiles the *installed* tree and confirms the running
process reports the new version via /api/v1/health — either failing
rolls back. The post-restart health-check window is 90s (was 45),
overridable with `[server] update_health_timeout`.

v5.8.3 — the 5.8.2 health/version probes hit the plain-HTTP port and let
urllib follow redirects, so on an SSL install they chased
jen/httpredirect.py's 301 into a TLS handshake against a cert that
doesn't name 127.0.0.1, failed, and rolled back a *healthy* HTTPS
upgrade. Both probes now talk to the app's real port (HTTPS directly when
certs are present), don't follow redirects (a 301/302/401 is itself
proof-of-life), and don't verify TLS on the loopback call. Also:
`apt-get update` + one more retry if the python3-venv install fails on a
box with stale indices.

v5.14.0 — versioned release directories + an atomic symlink switch.
Each release is built whole under `/opt/jen/releases/<X.Y.Z>/`:
`app/` is the extracted tarball, `venv/` is a virtualenv built for
exactly that `app/requirements.txt`. `/opt/jen/current` is a relative
symlink to the live release; the update is `os.replace()` of that link,
which is atomic, and the rollback is flipping it back — the previous
release directory is never touched, so it is its own rollback. The
per-release venv finally closes the "a rollback keeps the newer deps"
gap: the old release's venv is exactly the deps it shipped with.

The updater that installs 5.14.0 is the OLD (flat) one, so 5.14.0 lands
flat and boots through the `JEN_ROOT` fallback + run.py's shim. The
first run of THIS updater on such a box has no `current` symlink yet
("migration run"): it builds `releases/<ver>/`, snapshots the flat tree
for rollback, creates `current`, and on success removes the flat
leftovers. `sudo ./install.sh --upgrade` does the same immediately.
Docker stays flat (no venv, the container is the isolation) and reaches
the app through the same `JEN_ROOT` fallback.
"""

import configparser
import contextlib
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

GITHUB_REPO = "ltkojak/jen-kea"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_ASSET_PREFIX = f"https://github.com/{GITHUB_REPO}/releases/download/"

# v5.26.0 — the permanent trust root for signed releases (Q22). release.yml
# signs SHA256SUMS with the private half of this key (`ssh-keygen -Y sign`,
# held only in the repo's RELEASE_SIGNING_KEY Actions secret) and publishes
# SHA256SUMS.sig; verify_release_signature() below checks it with this
# public half via `ssh-keygen -Y verify`. Rotation: add the new key
# alongside this one (as a second line — an "allowed signers" file may list
# more than one) for one release before switching the secret, then drop
# the old one a release after that.
RELEASE_SIGNERS = "release@jen ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXk5NbQwUy85pHCzLfOwPisL0JGLCOrHuRjRZSf25vD"
RELEASE_SIGNATURE_IDENTITY = "release@jen"
RELEASE_SIGNATURE_NAMESPACE = "jen-release"
INSTALL_DIR = "/opt/jen"
VENV_DIR = "/opt/jen/venv"  # legacy flat venv path (pre-5.14 / Docker); removed by the migration run
RELEASES_DIR = "/opt/jen/releases"  # v5.14.0 — releases/<X.Y.Z>/{app,venv}
CURRENT_LINK = "/opt/jen/current"  # v5.14.0 — relative symlink → releases/<live>
SYSTEM_PYTHON = "/usr/bin/python3"
SELF_INSTALL_PATH = "/usr/local/sbin/jen-update-root.py"
UPDATE_SERVICE_PATH = "/etc/systemd/system/jen-update.service"
CONFIG_FILE = "/etc/jen/jen.config"
# Hardcoded in jen/extensions.py — not configurable. Their presence is
# exactly what jen.config.ssl_configured() keys on, so the updater can
# read the same signal without importing the jen package.
SSL_CERT = "/etc/jen/ssl/certificate.crt"
SSL_KEY = "/etc/jen/ssl/private.key"

# v5.13.0 — user-writable content lives here, outside /opt/jen. Hardcoded
# in jen/extensions.py the same way the SSL paths above are; the updater
# migrates pre-5.13 content into it and chowns it to www-data.
CONTENT_DIR = "/var/lib/jen"

# v5.14.0 — the flat parts of /opt/jen. In the versioned layout the
# previous release directory IS the rollback (it's never touched), so
# these matter for exactly ONE case: the migration run on a still-flat
# box, where snapshot_install()/restore_snapshot() copy them aside and
# put them back if the switch to the versioned layout fails. On success
# the migration run deletes them (they'd shadow nothing but confuse).
_ROLLBACK_ITEMS = (
    "jen",
    "run.py",
    "templates",
    "static",
    "plugins",
    "requirements.txt",
    "CHANGELOG.md",
    "jen-kea-helper",
)
_FLAT_LEFTOVERS = (*_ROLLBACK_ITEMS, "venv")

# Files an update also replaces that live OUTSIDE /opt/jen. A bad
# jen.service / sudoers / updater would make the app fail AND make a
# jen-only rollback useless (the bad unit is still installed), so these
# get snapshotted too. {live path: name under snapshot_dir/_ext/}
_EXTERNAL_ITEMS = {
    "/etc/systemd/system/jen.service": "jen.service",
    "/etc/sudoers.d/jen": "sudoers-jen",
    SELF_INSTALL_PATH: "jen-update-root.py",
    UPDATE_SERVICE_PATH: "jen-update.service",
}


def log(msg):
    # Captured by journald via the systemd unit — `journalctl -u
    # jen-update.service` is the way to diagnose a failed update,
    # since this no longer runs inside a Flask request at all.
    print(f"[jen-update] {msg}", flush=True)


def fetch_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        if resp.status != 200:
            raise RuntimeError(f"GitHub API returned HTTP {resp.status}")
        return json.loads(resp.read().decode())


def fetch_text(url, timeout=15):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()


def fetch_bytes_with_sha256(url, timeout=120):
    req = urllib.request.Request(url)
    sha256 = hashlib.sha256()
    chunks = []
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Download failed: HTTP {resp.status}")
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            chunks.append(chunk)
            sha256.update(chunk)
    return b"".join(chunks), sha256.hexdigest()


def install_external_files(app_dir):
    """
    v5.14.0 — install the files a release ships that live OUTSIDE the
    release directory: the systemd unit (`jen.service`, + `daemon-reload`)
    and the sudoers grant (`jen-sudoers`, validated with `visudo -c`
    first, never installed on a failure). The application tree itself is
    no longer copied anywhere — it IS `app_dir` (`releases/<ver>/app/`),
    reached through the `current` symlink. `jen-update-root.py` and
    `jen-update.service` are handled by install_self_update_files() with
    its atomic replace-while-running dance. `app_dir` is
    `releases/<ver>/app` and is already `root:root` (chowned on the
    staging dir before the rename).

    Kept as its own function so it's testable against a hand-built
    directory without mocking the network or tar extraction.
    """
    service_src = os.path.join(app_dir, "jen.service")
    if os.path.isfile(service_src):
        shutil.copy2(service_src, "/etc/systemd/system/jen.service")
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)

    sudoers_src = os.path.join(app_dir, "jen-sudoers")
    if os.path.isfile(sudoers_src):
        check = subprocess.run(["/usr/sbin/visudo", "-c", "-f", sudoers_src], capture_output=True, text=True)
        if check.returncode != 0:
            log(f"ERROR: new jen-sudoers failed validation, not installing it: {check.stderr}")
        else:
            shutil.copy2(sudoers_src, "/etc/sudoers.d/jen")
            os.chmod("/etc/sudoers.d/jen", 0o440)


_SHIPPED_PLUGIN_IDS = ("ipam", "network-discovery")


def migrate_user_content(install_dir=INSTALL_DIR, content_dir=CONTENT_DIR, extracted=None):
    """v5.13.0 — MOVE pre-5.13 user content from the /opt/jen tree into
    CONTENT_DIR, once, before the file install replaces those locations.
    Idempotent (skips anything already at the destination), never
    clobbers, and ends by making CONTENT_DIR www-data:www-data 0750.

    Pure enough to test against tmp dirs: pass `extracted` so the favicon
    comparison uses the fresh tarball's shipped default."""
    icons = os.path.join(content_dir, "icons")
    branding = os.path.join(content_dir, "branding")
    backups = os.path.join(content_dir, "backups")
    plug = os.path.join(content_dir, "plugins")
    plug_en = os.path.join(content_dir, "plugins-enabled")
    keys = os.path.join(content_dir, "keys")
    for d in (icons, branding, backups, plug, plug_en, keys):
        os.makedirs(d, exist_ok=True)

    def _mv(src, dst):
        if os.path.exists(src) and not os.path.exists(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)

    old_static = os.path.join(install_dir, "static")
    old_custom = os.path.join(old_static, "icons", "custom")
    if os.path.isdir(old_custom):
        for name in os.listdir(old_custom):
            _mv(os.path.join(old_custom, name), os.path.join(icons, name))
    for ext in ("png", "svg", "jpg", "jpeg", "webp"):
        _mv(os.path.join(old_static, f"nav_logo.{ext}"), os.path.join(branding, f"nav_logo.{ext}"))

    old_favicon = os.path.join(old_static, "favicon.ico")
    shipped_favicon = os.path.join(extracted, "static", "favicon.ico") if extracted else None
    if os.path.isfile(old_favicon) and not os.path.exists(os.path.join(branding, "favicon.ico")):
        differs = True
        if shipped_favicon and os.path.isfile(shipped_favicon):
            differs = _file_sha256(old_favicon) != _file_sha256(shipped_favicon)
        if differs:
            shutil.move(old_favicon, os.path.join(branding, "favicon.ico"))

    old_backups = os.path.join(install_dir, "backups")
    if os.path.isdir(old_backups):
        for name in os.listdir(old_backups):
            _mv(os.path.join(old_backups, name), os.path.join(backups, name))

    old_plugins = os.path.join(install_dir, "plugins")
    if os.path.isdir(old_plugins):
        for pid in os.listdir(old_plugins):
            src = os.path.join(old_plugins, pid)
            if not os.path.isdir(src):
                continue
            if pid not in _SHIPPED_PLUGIN_IDS:
                _mv(src, os.path.join(plug, pid))
                src = os.path.join(plug, pid)  # the .enabled marker moved with the dir
            marker = os.path.join(src, ".enabled")
            new_marker = os.path.join(plug_en, pid)
            if os.path.isfile(marker) and not os.path.exists(new_marker):
                shutil.move(marker, new_marker)

    for fn in (".secret_key", ".mfa_key"):
        _mv(os.path.join(install_dir, fn), os.path.join(keys, fn))

    subprocess.run(["/bin/chown", "-R", "www-data:www-data", content_dir], check=False)
    subprocess.run(["/bin/chmod", "750", content_dir], check=False)


def _file_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def install_self_update_files(extracted, self_install_path=SELF_INSTALL_PATH, update_service_path=UPDATE_SERVICE_PATH):
    """
    v5.3.3 fix — a real gap found by a third-party review of the v5.2.6
    redesign: the file install (the release directory, plus
    install_external_files() for jen.service / jen-sudoers) never
    installed a new copy of THIS script or of jen-update.service itself.
    A fix shipped inside jen-update-root.py would never reach
    an already-running instance via the in-app update button — only a
    manual `sudo ./install.sh --upgrade` would pick it up, silently
    reintroducing the exact "self-update can't fix itself" maintenance
    trap this whole redesign was meant to close for the application it
    updates.

    Safe to do while this exact script is the one currently running:
    the interpreter already read this script's full source into memory
    before execution began, so replacing the file on disk has no
    effect on the process executing right now — only the *next*
    invocation (the next time jen-update.service starts) sees the new
    content. Confirmed this reasoning is standard, correct POSIX
    behavior, not just assumed.

    Writes to a temp file in the SAME directory as the real
    destination, then uses os.replace() (atomic on POSIX, and
    guaranteed atomic specifically because source and destination
    share a filesystem) rather than overwriting in place — so a
    concurrent invocation can never observe a partially-written file.
    Ownership and mode are set on the temp file BEFORE the rename, so
    there is no window where the installed path exists with the wrong
    permissions either. Both this script and the systemd unit that
    invokes it must remain root-owned and unwritable by www-data at
    every point in time, not just at the end of this function.
    """
    new_script_src = os.path.join(extracted, "jen-update-root.py")
    if os.path.isfile(new_script_src):
        dest_dir = os.path.dirname(self_install_path)
        fd, tmp_path = tempfile.mkstemp(dir=dest_dir, prefix=".jen-update-root-", suffix=".tmp")
        try:
            with open(new_script_src, "rb") as src_f:
                content = src_f.read()
            os.write(fd, content)
        finally:
            os.close(fd)
        os.chown(tmp_path, 0, 0)
        os.chmod(tmp_path, 0o700)
        os.replace(tmp_path, self_install_path)
        log(f"Updated {self_install_path} from this release.")

    new_service_src = os.path.join(extracted, "jen-update.service")
    if os.path.isfile(new_service_src):
        dest_dir = os.path.dirname(update_service_path)
        fd, tmp_path = tempfile.mkstemp(dir=dest_dir, prefix=".jen-update-service-", suffix=".tmp")
        try:
            with open(new_service_src, "rb") as src_f:
                content = src_f.read()
            os.write(fd, content)
        finally:
            os.close(fd)
        os.chown(tmp_path, 0, 0)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, update_service_path)
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)
        log(f"Updated {update_service_path} and reloaded systemd.")


def _venv_usable(python_bin):
    """True if `python_bin` exists, runs, AND has a working pip. A venv
    left half-built by a failed `python3 -m venv` (interpreter present,
    ensurepip never ran) passes a bare `-c ''` but has no pip — v5.8.1
    handed exactly that back and then failed with 'No module named pip'."""
    try:
        if subprocess.run([python_bin, "-c", ""], capture_output=True, timeout=15).returncode != 0:
            return False
        return subprocess.run([python_bin, "-m", "pip", "--version"], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _try_build_venv(venv_dir):
    """`python3 -m venv <dir>` + bootstrap pip. Returns True if the result
    is usable. Wipes any half-built leftover first."""
    venv_py = os.path.join(venv_dir, "bin", "python")
    if os.path.exists(venv_dir):
        shutil.rmtree(venv_dir, ignore_errors=True)
    r = subprocess.run([SYSTEM_PYTHON, "-m", "venv", venv_dir], capture_output=True, text=True)
    if r.returncode != 0:
        log(f"  `python3 -m venv` failed: {(r.stderr or r.stdout).strip()}")
        return False
    subprocess.run([venv_py, "-m", "ensurepip", "--upgrade"], capture_output=True)
    subprocess.run([venv_py, "-m", "pip", "install", "-q", "--upgrade", "pip"], capture_output=True)
    return _venv_usable(venv_py)


def _build_venv_with_apt_recovery(venv_dir):
    """`python3 -m venv <dir>`, apt-installing `python3-venv` / `python3-full`
    and retrying (once more after `apt-get update`) if the OS package is
    missing. This script runs as root, so it can. Returns True if the
    result is a usable venv."""
    if _try_build_venv(venv_dir):
        return True

    # Most common cause on Debian/Ubuntu: python3-venv isn't installed
    # (an install that has only ever used the in-app update button).
    log("Installing python3-venv / python3-full and retrying…")
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    pkgs = ["python3-venv", "python3-full"]

    def _apt_install():
        return subprocess.run(
            ["/usr/bin/apt-get", "install", "-y", "-qq", *pkgs], capture_output=True, text=True, env=env
        )

    apt = _apt_install()
    if apt.returncode != 0:
        # A box old enough to be in this state often has stale package
        # indices — the install fails with "Unable to locate package" or a
        # 404 on an old pool URL. `apt-get update` once, then one last try.
        log(f"  apt-get install failed ({(apt.stderr or apt.stdout).strip()}); refreshing indices and retrying…")
        subprocess.run(["/usr/bin/apt-get", "update", "-qq"], capture_output=True, text=True, env=env)
        apt = _apt_install()
        if apt.returncode != 0:
            log(f"  apt-get install still failed: {(apt.stderr or apt.stdout).strip()}")
    return apt.returncode == 0 and _try_build_venv(venv_dir)


def _build_release_venv(venv_dir):
    """
    Build the per-release virtualenv at `venv_dir` (a brand-new path
    under a staging directory — no "is the existing one usable" shortcut,
    it can't exist yet). This is what makes the update transactional: the
    live release's venv is never touched, so a pip failure here or a
    rollback later leaves the running install's dependencies exactly as
    they were. Returns the venv's python, or None if a venv genuinely
    can't be produced (which aborts the update).
    """
    if _build_venv_with_apt_recovery(venv_dir):
        return os.path.join(venv_dir, "bin", "python")
    log(f"ERROR: could not build a virtualenv at {venv_dir}.")
    return None


def install_python_dependencies(requirements_path, python_bin):
    """
    Install the release's pinned dependencies with `python_bin -m pip`.
    Returns True on success (or when there's nothing to do); False on a
    pip failure.

    v5.8.0 — a failure here ABORTS the update. It runs against the
    *staged* requirements.txt before any file in /opt/jen is touched, so
    a release that genuinely needs a new library (or a transient PyPI
    problem) leaves the running install exactly as it was, rather than
    the pre-5.8.0 behavior of logging a warning and restarting into a
    half-updated app.
    """
    if not os.path.isfile(requirements_path):
        log(f"WARNING: {requirements_path} not found — skipping dependency install.")
        return True
    log(f"Installing Python dependencies with {python_bin} …")
    cmd = [python_bin, "-m", "pip", "install", "--upgrade", "-r", requirements_path]
    # v5.14.0 the caller always passes a per-release venv python, so the
    # SYSTEM_PYTHON branch below is a belt-and-braces fallback only. A
    # plain string compare is right here (NOT realpath — a venv's
    # bin/python realpaths to the system interpreter, see run.py's guard).
    attempts = []
    if python_bin == SYSTEM_PYTHON:
        # No venv — system pip needs the PEP 668 override (pip >= 23).
        r1 = subprocess.run(cmd + ["--break-system-packages"], capture_output=True, text=True)
        attempts.append(("--break-system-packages", r1))
        result = r1
        if r1.returncode != 0:
            r2 = subprocess.run(cmd, capture_output=True, text=True)  # older pip
            attempts.append(("plain", r2))
            result = r2
    else:
        result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        log("Dependencies installed.")
        return True
    log("ERROR: pip install failed — aborting update, /opt/jen untouched.")
    for label, r in attempts or [("", result)]:
        tail = (r.stderr or r.stdout or "").strip()
        log(f"  [{label or 'pip'}]: {tail}" if tail else f"  [{label or 'pip'}]: (no output, exit {r.returncode})")
    return False


def validate_staged_release(staged_root, python_bin):
    """
    Confirm the extracted release is loadable with the (now updated)
    dependencies before it replaces the running install: every module in
    the staged jen/ package compiles, and the app factory + migration
    registry import cleanly. Returns True if the staged code is sound.
    """
    staged_pkg = os.path.join(staged_root, "jen")
    compiled = subprocess.run([python_bin, "-m", "compileall", "-q", staged_pkg], capture_output=True, text=True)
    if compiled.returncode != 0:
        log(f"ERROR: staged jen/ failed to compile — aborting:\n{compiled.stdout}\n{compiled.stderr}")
        return False
    # Import the staged tree by putting it on PYTHONPATH (not by reading
    # anything from this script's own argv — see the "no caller input"
    # property tested in tests/test_jen_update_root.py).
    env = {**os.environ, "PYTHONPATH": staged_root}
    imported = subprocess.run(
        [python_bin, "-c", "import jen; from jen import create_app; from jen.models import migrations"],
        capture_output=True,
        text=True,
        env=env,
    )
    if imported.returncode != 0:
        log(f"ERROR: staged code did not import cleanly — aborting:\n{imported.stderr.strip()}")
        return False
    log("Staged release validated (compiles + imports).")
    return True


def _copy_any(src, dst):
    """Replace dst (file or dir) with a copy of src.

    symlinks=True: copy a symlink AS a symlink, never follow it. A
    snapshot must reproduce the tree as it is, and following links is
    how v5.8.2/5.8.3 died on a real box — a stray dangling
    `/opt/jen/templates/templates -> (gone)` left behind by some ancient
    install made copytree raise ENOENT at the snapshot step, before the
    swap, on every single update attempt."""
    if os.path.isdir(src):
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        elif os.path.exists(dst) or os.path.islink(dst):
            os.unlink(dst)
        shutil.copytree(src, dst, symlinks=True)
    else:
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)


def snapshot_install(snapshot_dir, install_dir=INSTALL_DIR):
    """Copy aside everything a failed update would need to put back — the
    replace-wholesale parts of /opt/jen, plus the unit/sudoers/updater
    files that live outside it."""
    ext_dir = os.path.join(snapshot_dir, "_ext")
    os.makedirs(ext_dir, exist_ok=True)
    for item in _ROLLBACK_ITEMS:
        src = os.path.join(install_dir, item)
        if os.path.exists(src):
            _copy_any(src, os.path.join(snapshot_dir, item))
    for live_path, name in _EXTERNAL_ITEMS.items():
        if os.path.exists(live_path):
            shutil.copy2(live_path, os.path.join(ext_dir, name))


def restore_snapshot(snapshot_dir, install_dir=INSTALL_DIR, current_link=None):
    """Put a snapshot_install() snapshot back — the flat /opt/jen tree,
    then the external files, then daemon-reload + chown + restart jen.
    v5.14.0 — this is the MIGRATION-run rollback: a half-created `current`
    symlink is removed so the box stays on the flat layout it started
    from. (The steady-state versioned rollback is just an os.replace() of
    the `current` link back to the previous release — main() does that
    inline; the previous release dir was never touched.)"""
    if current_link is None:
        current_link = CURRENT_LINK
    if os.path.islink(current_link) or os.path.lexists(current_link):
        with contextlib.suppress(OSError):
            os.unlink(current_link)
    for item in _ROLLBACK_ITEMS:
        src = os.path.join(snapshot_dir, item)
        if os.path.exists(src):
            _copy_any(src, os.path.join(install_dir, item))
    ext_dir = os.path.join(snapshot_dir, "_ext")
    reload_needed = False
    for live_path, name in _EXTERNAL_ITEMS.items():
        saved = os.path.join(ext_dir, name)
        if os.path.isfile(saved):
            shutil.copy2(saved, live_path)
            if live_path.endswith(".service"):
                reload_needed = True
    if reload_needed:
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=False)
    # v5.13.0 — the application tree is root-owned; CONTENT_DIR (untouched
    # by a rollback) stays www-data.
    subprocess.run(
        ["/bin/chown", "-R", "root:root", *[os.path.join(install_dir, i) for i in _ROLLBACK_ITEMS]],
        check=False,
    )
    subprocess.run(["/usr/bin/systemctl", "restart", "jen"], check=False)


def _remove_flat_leftovers(install_dir=INSTALL_DIR):
    """v5.14.0 — after a successful migration run, delete the flat
    application tree from /opt/jen. Everything now lives under
    releases/<ver>/ and is reached through `current`; the flat copies
    would shadow nothing (JEN_ROOT resolves to current/app) but they are
    confusing and waste disk. /opt/jen itself, /opt/jen/releases,
    /opt/jen/current and any .rollback-* snapshot are left alone."""
    for item in _FLAT_LEFTOVERS:
        path = os.path.join(install_dir, item)
        if os.path.islink(path) or os.path.isfile(path):
            with contextlib.suppress(OSError):
                os.unlink(path)
                log(f"Removed flat leftover {path}")
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            log(f"Removed flat leftover {path}/")


def _server_cfg(key, fallback):
    try:
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(CONFIG_FILE)
        return cfg.getint("server", key, fallback=fallback)
    except Exception:
        return fallback


def _installed_version():
    """JEN_VERSION out of the on-disk jen/__init__.py — the versioned
    layout's `current/app/jen/__init__.py` first (v5.14.0), the flat
    `/opt/jen/jen/__init__.py` second (pre-5.14, Docker, and the one
    transitional boot)."""
    for base in (os.path.join(CURRENT_LINK, "app"), INSTALL_DIR):
        try:
            with open(os.path.join(base, "jen", "__init__.py")) as f:
                for line in f:
                    if line.startswith("JEN_VERSION"):
                        return line.split("=", 1)[1].strip().strip("\"'")
        except OSError:
            continue
    return "?"


def _ssl_enabled():
    """Same signal jen.config.ssl_configured() uses — cert + key present."""
    return os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY)


def _local_base_url():
    """
    scheme://127.0.0.1:port the running app actually answers on. When SSL
    is on we talk to the HTTPS port directly rather than the plain-HTTP
    port — that port serves only jen/httpredirect.py's 301 to
    `https://<host>:<https_port>/`, and chasing that redirect means a TLS
    handshake against a cert that names a hostname (or is self-signed),
    not 127.0.0.1, which fails and made a healthy HTTPS upgrade look dead.
    """
    if _ssl_enabled():
        return f"https://127.0.0.1:{_server_cfg('https_port', 8443)}"
    return f"http://127.0.0.1:{_server_cfg('http_port', 5050)}"


def _local_opener():
    """
    An opener for probing the local instance that (1) does NOT follow
    redirects — a 301/302 is itself proof the app is serving — and (2)
    does NOT verify TLS: this is a loopback call and Jen's cert
    legitimately won't validate against 127.0.0.1 anyway.
    """

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))


def _running_version():
    """
    Version reported by the *running* process, via the public
    /api/v1/health endpoint. This is the real proof the restart picked up
    the new code — the on-disk string is near-tautological right after we
    wrote it. Returns None if the endpoint can't be read as JSON; the
    caller then falls back to the on-disk string.
    """
    try:
        resp = _local_opener().open(f"{_local_base_url()}/api/v1/health", timeout=5)
        payload = json.loads(resp.read().decode("utf-8", "replace"))
        if isinstance(payload, dict):
            return payload.get("jen_version") or None
    except (urllib.error.URLError, OSError, ValueError):
        pass
    return None


def service_healthy(timeout=None):
    """
    After the restart, wait up to `timeout`s for jen to be back: the unit
    active AND the app answering on its real port (HTTPS when SSL is
    configured, HTTP otherwise) with anything below 500 — a 200, or a
    301/302/401 all mean it's serving. Default is 90s (a slow homelab box
    + migrations + background-worker init + gunicorn spawn), override with
    `[server] update_health_timeout`.
    """
    if timeout is None:
        timeout = _server_cfg("update_health_timeout", 90)
    opener = _local_opener()
    url = f"{_local_base_url()}/"
    log(f"Waiting up to {timeout}s for jen at {url} …")
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(3)
        if subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "jen"]).returncode != 0:
            continue
        if _probe_once(opener, url):
            return True
    return False


def _probe_once(opener, url):
    """One HTTP probe: anything below 500 (200, a 301/302 to login, a 401)
    means the app is serving. Used by service_healthy() and, since v5.9.0,
    as the pre-swap baseline."""
    try:
        resp = opener.open(url, timeout=5)
        return resp.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except (urllib.error.URLError, OSError):
        return False


def verify_release_checksum(tarball_name, actual_hash, checksum_text):
    """
    Pure function: given the checksum file's text content, confirm it
    contains a matching, correct entry for this exact tarball. Returns
    True only on an exact match. Deliberately has no "proceed anyway"
    path of any kind — the caller is expected to abort on anything
    other than True, matching the fail-closed behavior that's the
    whole point of this rewrite (the old code logged a warning and
    proceeded unverified in three separate cases; this function gives
    none of them anywhere to hide).
    """
    expected_hash = None
    for line in checksum_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == tarball_name:
            expected_hash = parts[0].lower()
            break
    return expected_hash is not None and expected_hash == actual_hash


def verify_release_signature(sums_text, sig_bytes, signers_text):
    """
    v5.26.0 (Q22) — confirm `sums_text` (the SHA256SUMS content) carries
    a valid `ssh-keygen -Y sign` signature from an identity/key listed in
    `signers_text` (an "allowed signers" file body — RELEASE_SIGNERS at
    module scope in production; a throwaway test key in tests). Wraps a
    subprocess call to `ssh-keygen -Y verify`, since Python's stdlib has
    no ed25519-SSH-signature verifier and this avoids a new dependency
    entirely (openssh-client ships on every target OS already).

    Both the signers file and the signature itself need to be real files
    on disk for `-f`/`-s` — verify writes them to a throwaway temp
    directory and removes it unconditionally afterward, regardless of
    the result. Returns False (never raises) on anything short of a
    genuine, matching, correctly-namespaced signature: a non-zero
    `ssh-keygen` exit, a missing binary, a timeout — matching
    verify_release_checksum's fail-closed shape, so the caller's "if not
    verify_...(): abort" pattern stays identical for both checks.
    """
    try:
        with tempfile.TemporaryDirectory() as tmp:
            signers_path = os.path.join(tmp, "allowed_signers")
            sig_path = os.path.join(tmp, "release.sig")
            with open(signers_path, "w") as f:
                f.write(signers_text)
            with open(sig_path, "wb") as f:
                f.write(sig_bytes)
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    signers_path,
                    "-I",
                    RELEASE_SIGNATURE_IDENTITY,
                    "-n",
                    RELEASE_SIGNATURE_NAMESPACE,
                    "-s",
                    sig_path,
                ],
                input=sums_text.encode(),
                capture_output=True,
                timeout=10,
            )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


KEEP_MARKER = ".keep"  # written into a snapshot the CRITICAL path wants preserved


def _prune_old_releases(releases_dir=RELEASES_DIR, current_link=CURRENT_LINK, install_dir=INSTALL_DIR):
    """
    v5.14.0 — keep the disk from filling with old release dirs. Keeps:
      - the release `current` points at,
      - the single newest OTHER release directory (a hand-rollback
        target, and the CRITICAL path's fallback),
      - any release dir carrying a `.keep` marker.
    Removes the rest, plus:
      - `*.staging-*` dirs older than a day (a crashed earlier attempt),
      - any `.failed`-marked release dir,
      - legacy `.rollback-<ts>` snapshot dirs left under /opt/jen by the
        pre-5.14 updater (except a `.keep`-marked one — that may be the
        only intact copy of a previous release if a rollback died
        halfway, and "click Update again" must never delete it).
    """
    removed = 0
    now = time.time()

    def _mtime(p):
        try:
            return os.path.getmtime(p)
        except OSError:
            return 0.0

    current_target = None
    if os.path.islink(current_link):
        current_target = os.path.basename(os.readlink(current_link).rstrip("/"))

    try:
        names = os.listdir(releases_dir)
    except OSError:
        names = []
    release_dirs = []
    for name in names:
        path = os.path.join(releases_dir, name)
        if ".staging-" in name:
            if now - _mtime(path) > 86400:
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
            continue
        if os.path.isdir(path) and not os.path.islink(path):
            release_dirs.append(name)

    release_dirs.sort(key=lambda n: _mtime(os.path.join(releases_dir, n)), reverse=True)
    kept_one_other = False
    for name in release_dirs:
        path = os.path.join(releases_dir, name)
        if name == current_target:
            continue
        if os.path.exists(os.path.join(path, KEEP_MARKER)):
            log(f"Keeping release {name} — marked for recovery.")
            continue
        if not os.path.exists(os.path.join(path, ".failed")) and not kept_one_other:
            kept_one_other = True
            continue
        shutil.rmtree(path, ignore_errors=True)
        removed += 1

    # Legacy .rollback-<ts> snapshots from the pre-5.14 updater.
    try:
        snaps = sorted(n for n in os.listdir(install_dir) if n.startswith(".rollback-"))
    except OSError:
        snaps = []
    for name in snaps[:-1]:  # newest stays (mirrors the pre-5.14 behavior)
        path = os.path.join(install_dir, name)
        if os.path.exists(os.path.join(path, KEEP_MARKER)):
            log(f"Keeping {name} — marked for recovery by an earlier failed rollback.")
            continue
        shutil.rmtree(path, ignore_errors=True)
        removed += 1

    if removed:
        log(f"Pruned {removed} old release / staging / snapshot dir(s).")
    return removed


def _confirm_running_version(version, attempts=5, delay=3):
    """
    v5.9.1 — the running process must report the version we installed;
    the on-disk JEN_VERSION only proves the copy succeeded, so it is no
    longer accepted as "confirmed". /api/v1/health is retried a few times
    (the app may still be warming up right after service_healthy() saw
    the port answer) and a definite mismatch fails immediately.
    """
    last = None
    for i in range(attempts):
        running = _running_version()
        if running == version:
            return running
        if running is not None:
            raise RuntimeError(
                f"post-restart version mismatch — expected v{version}, the running process reports v{running}"
            )
        last = i
        if i < attempts - 1:
            time.sleep(delay)
    raise RuntimeError(
        f"could not read the running version from {_local_base_url()}/api/v1/health after {last + 1} tries — "
        f"refusing to call the update confirmed (the on-disk file says v{_installed_version()}, but that only "
        "proves the files were copied)"
    )


def _switch_current(target_release, current_link=None):
    """Atomically point `current` at `releases/<target_release>`. The
    symlink target is RELATIVE so /opt/jen can be bind-mounted; the swap
    is os.replace() of the link itself (atomic on POSIX), never
    os.remove()+os.symlink() which has a window where `current` is gone."""
    if current_link is None:
        current_link = CURRENT_LINK
    tmp_link = current_link + ".tmp"
    if os.path.lexists(tmp_link):
        os.unlink(tmp_link)
    os.symlink(os.path.join("releases", target_release), tmp_link)
    os.replace(tmp_link, current_link)


def _extract_release(tarball_path, dest_app):
    """Extract the WHOLE tarball into `dest_app`, stripping the leading
    `jen/` path component. Same tar-slip protection as before: filter by
    TYPE (files/dirs only — a member named safely under `jen/` can still
    be a sym/hardlink pointing outside) and reject `..` / absolute names.
    Extraction IS the install now — there is no second copy step."""
    os.makedirs(dest_app, exist_ok=True)
    with tarfile.open(tarball_path, "r:gz") as tf:
        members = []
        for m in tf.getmembers():
            if not m.name.startswith("jen/") or ".." in m.name or os.path.isabs(m.name):
                continue
            if not (m.isfile() or m.isdir()):
                continue
            m.name = m.name[len("jen/") :]
            if not m.name:
                continue
            members.append(m)
        tf.extractall(dest_app, members=members)


def _rollback_release(snapshot_dir, prev, migration_run, version, release_dir):
    """Undo a failed switch. Migration run → restore the flat tree and
    drop the half-made `current`. Steady state → flip `current` back to
    the previous release (its dir was never touched) and restore the
    external unit/sudoers/updater files from the snapshot. Then restart
    and health-check; an unhealthy result is the CRITICAL path."""
    if os.path.isdir(release_dir):
        with contextlib.suppress(OSError):
            open(os.path.join(release_dir, ".failed"), "w").close()

    if migration_run:
        restore_snapshot(snapshot_dir)
    else:
        try:
            _switch_current(prev)
        except OSError as e:
            log(f"  WARNING: could not flip `current` back to {prev}: {e}")
        ext_dir = os.path.join(snapshot_dir, "_ext")
        reload_needed = False
        for live_path, name in _EXTERNAL_ITEMS.items():
            saved = os.path.join(ext_dir, name)
            if os.path.isfile(saved):
                shutil.copy2(saved, live_path)
                if live_path.endswith(".service"):
                    reload_needed = True
        if reload_needed:
            subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=False)
        subprocess.run(["/usr/bin/systemctl", "restart", "jen"], check=False)

    if service_healthy():
        log(f"Rolled back to the previous install. The v{version} update was NOT applied.")
        shutil.rmtree(snapshot_dir, ignore_errors=True)
        return

    # Rollback restart itself unhealthy — keep every recovery artefact.
    with contextlib.suppress(OSError), open(os.path.join(snapshot_dir, KEEP_MARKER), "w") as f:
        f.write(f"rollback restart unhealthy after v{version} attempt; probe {_local_base_url()}/\n")
    if not migration_run and prev:
        prev_dir = os.path.join(RELEASES_DIR, prev)
        if os.path.isdir(prev_dir):
            with contextlib.suppress(OSError):
                open(os.path.join(prev_dir, KEEP_MARKER), "w").close()
    log(
        "CRITICAL: rollback restart also unhealthy. Recovery snapshot kept at "
        f"{snapshot_dir}; check `journalctl -u jen`. If `systemctl is-active jen` says active, "
        f"the PROBE is what's failing (it used {_local_base_url()}/), not the app — the previous "
        "version is restored and running; fix the probe's view of the ports/SSL and retry."
    )


def main():
    _prune_old_releases()
    log("Checking GitHub for the latest release…")
    data = fetch_json(GITHUB_RELEASES_API)
    version = data.get("tag_name", "").lstrip("v")
    if not version:
        log("ERROR: could not determine latest version from GitHub API response.")
        return 1

    # The UI only offers the update button when GitHub is ahead, but this
    # unit re-derives "latest" on its own — a race, or a second click,
    # would otherwise re-download and re-install the version already on
    # disk (and restart jen for nothing).
    installed = _installed_version()
    if installed == version:
        log(f"Already running v{version} — nothing to do.")
        return 0

    assets = data.get("assets", [])
    asset_url = ""
    for asset in assets:
        if asset["name"].endswith(".tar.gz") and "jen-v" in asset["name"]:
            asset_url = asset["browser_download_url"]
            break

    if not asset_url or not asset_url.startswith(GITHUB_ASSET_PREFIX):
        log("ERROR: no valid release asset found.")
        return 1

    checksum_asset_url = ""
    for asset in assets:
        if asset["name"].lower() in ("sha256sums", "sha256sums.txt", "checksums.txt"):
            checksum_asset_url = asset["browser_download_url"]
            break

    # ── Fail closed on checksum verification. The old code logged a
    # warning and proceeded unverified in three separate cases (no
    # checksum asset published, checksum asset present but no matching
    # entry, or an exception during verification). This script treats
    # all three as a hard stop.
    if not checksum_asset_url:
        log(f"ERROR: no checksum asset published for v{version} — refusing to install unverified.")
        return 1

    # Same scheme/host validation as asset_url above — this URL also
    # comes from GitHub's own API response, but nothing stops that
    # response from ever containing something other than a genuine
    # github.com download link, so it gets the same explicit check
    # rather than being trusted just because it came from the "assets"
    # list. Caught by bandit (B310: audit url open for permitted
    # schemes) during review — asset_url already had this check,
    # checksum_asset_url had been missed.
    if not checksum_asset_url.startswith(GITHUB_ASSET_PREFIX):
        log("ERROR: checksum asset URL is not a genuine GitHub release download link.")
        return 1

    # v5.26.0 — the checksum file itself must be signed, checked BEFORE
    # the (large) tarball download even starts. Anyone who can forge a
    # release — a compromised PAT, a hijacked Actions run — can publish
    # any SHA256SUMS/tarball pair they like, but can't produce a
    # signature RELEASE_SIGNERS accepts without the private half of a
    # key that has never left GitHub Actions secrets. Fail closed: no
    # signature asset published is refused exactly like no checksum
    # asset published above, never a warn-and-proceed.
    sig_asset_url = ""
    for asset in assets:
        if asset["name"].lower() in ("sha256sums.sig", "sha256sums.txt.sig", "checksums.txt.sig"):
            sig_asset_url = asset["browser_download_url"]
            break

    if not sig_asset_url:
        log(f"ERROR: no release signature published for v{version} — refusing to install unverified.")
        return 1

    if not sig_asset_url.startswith(GITHUB_ASSET_PREFIX):
        log("ERROR: signature asset URL is not a genuine GitHub release download link.")
        return 1

    try:
        checksum_text = fetch_text(checksum_asset_url)
    except Exception as e:
        log(f"ERROR: could not fetch checksum file — refusing to install unverified: {e}")
        return 1

    try:
        sig_bytes = fetch_text(sig_asset_url).encode()
    except Exception as e:
        log(f"ERROR: could not fetch release signature — refusing to install unverified: {e}")
        return 1

    if not verify_release_signature(checksum_text, sig_bytes, RELEASE_SIGNERS):
        log("ERROR: release signature verification failed — refusing to install unverified.")
        return 1

    log("Release signature verified.")

    log("Downloading release…")
    tarball_bytes, actual_hash = fetch_bytes_with_sha256(asset_url)

    tarball_name = asset_url.rsplit("/", 1)[-1]
    if not verify_release_checksum(tarball_name, actual_hash, checksum_text):
        log(f"ERROR: checksum verification failed for {tarball_name} — refusing to install unverified.")
        return 1

    log("Checksum verified.")

    log("Checking the on-disk layout…")
    prev = None
    if os.path.islink(CURRENT_LINK):
        prev = os.path.basename(os.readlink(CURRENT_LINK).rstrip("/"))
    migration_run = prev is None
    if migration_run:
        log("No `current` symlink — this is the migration run from the flat layout.")

    staging = os.path.join(RELEASES_DIR, f"{version}.staging-{int(time.time())}")
    staging_app = os.path.join(staging, "app")
    staging_venv = os.path.join(staging, "venv")
    release_dir = os.path.join(RELEASES_DIR, version)

    tmp_tarball = tempfile.NamedTemporaryFile(suffix=".tar.gz", prefix="jen_update_", delete=False)  # noqa: SIM115
    try:
        tmp_tarball.write(tarball_bytes)
        tmp_tarball.close()

        # ── Build the new release entirely under a staging dir. Nothing
        # the running install depends on — not its files, not its venv —
        # is touched until the switch. That is what makes this atomic.
        _extract_release(tmp_tarball.name, staging_app)
        if not os.path.isdir(os.path.join(staging_app, "jen")):
            log("ERROR: update package format invalid — expected a jen/ package inside the tarball.")
            return 1

        python_bin = _build_release_venv(staging_venv)
        if not python_bin:
            log("ERROR: could not build the release's virtualenv — aborting, /opt/jen untouched.")
            return 1

        if not install_python_dependencies(os.path.join(staging_app, "requirements.txt"), python_bin):
            return 1

        # The whole staging tree is root-owned (www-data reads/executes,
        # never writes — a writable app tree or venv is a persistence
        # foothold), then byte-compiled with the interpreter that will run
        # it so the first post-restart request isn't paying compile cost
        # and a syntax error surfaces here, before the switch.
        subprocess.run(["/bin/chown", "-R", "root:root", staging], check=False)
        _compile_targets = [staging_venv]
        _compile_targets += [
            os.path.join(staging_app, d) for d in ("jen", "plugins") if os.path.isdir(os.path.join(staging_app, d))
        ]
        subprocess.run([python_bin, "-m", "compileall", "-q", *_compile_targets], capture_output=True)

        if not validate_staged_release(staging_app, python_bin):
            return 1

        # v5.9.0 — baseline the health probe against the app running NOW.
        # If the probe can't see a known-good Jen it can't be trusted to
        # judge the new one either (the 5.8.2 updater on an SSL box
        # installed a healthy 5.8.4 and rolled it back on that false
        # negative).
        probe_url = f"{_local_base_url()}/"
        if not _probe_once(_local_opener(), probe_url):
            log(
                f"ERROR: the health probe cannot reach the currently-running Jen at {probe_url} "
                "— it would wrongly roll back a good update. Aborting before the switch. "
                "Check `systemctl status jen`, the [server] ports in /etc/jen/jen.config, and whether "
                "/etc/jen/ssl/certificate.crt + private.key match how Jen is actually serving."
            )
            return 1

        # Snapshot the out-of-tree files an update replaces (jen.service,
        # sudoers, this script, jen-update.service). On the migration run
        # also snapshot the flat /opt/jen tree — that run's rollback is
        # "put the flat layout back", the previous release dir doesn't
        # exist yet. In steady state the _ROLLBACK_ITEMS paths don't exist
        # under /opt/jen at all, so only _ext/ gets populated.
        snapshot_dir = os.path.join(INSTALL_DIR, f".rollback-{int(time.time())}")
        log(f"Snapshotting current install → {snapshot_dir}")
        try:
            snapshot_install(snapshot_dir)
        except (OSError, shutil.Error) as e:
            log(f"ERROR: could not snapshot the current install — aborting, /opt/jen untouched: {e}")
            shutil.rmtree(snapshot_dir, ignore_errors=True)
            return 1

        # ── From here, ANY failure flips back and restarts the previous
        # version.
        try:
            log("Installing files…")
            if migration_run:
                migrate_user_content(INSTALL_DIR, CONTENT_DIR, staging_app)

            if os.path.isdir(release_dir):
                shutil.rmtree(release_dir)  # a prior failed attempt at this exact version
            os.rename(staging, release_dir)
            staging = None  # renamed — the finally block must not delete it

            install_external_files(os.path.join(release_dir, "app"))
            install_self_update_files(os.path.join(release_dir, "app"))

            _switch_current(version)
            subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=False)
            log(f"Update to v{version} installed. Restarting jen…")
            subprocess.run(["/usr/bin/systemctl", "restart", "jen"], check=False)
            if not service_healthy():
                raise RuntimeError("jen did not come back healthy after the update")
            running = _confirm_running_version(version)
            log(f"Confirmed: the running process reports v{running}.")
        except Exception as e:
            log(f"ERROR: {e} — rolling back.")
            _rollback_release(snapshot_dir, prev, migration_run, version, release_dir)
            return 1

        if migration_run:
            _remove_flat_leftovers()
        log("jen is back up and serving.")
        shutil.rmtree(snapshot_dir, ignore_errors=True)
        _prune_old_releases()
        log("Done.")
        return 0

    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp_tarball.name)
        if staging and os.path.isdir(staging):
            shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
