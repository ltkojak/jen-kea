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

The shared venv still means a rollback keeps the (forward-compatible,
floor-pinned) newer deps — a true atomic switch waits for the versioned
release directories tracked for a future major (see docs/ARCHITECTURE.md
§6).
"""

import configparser
import hashlib
import json
import os
import shutil
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
INSTALL_DIR = "/opt/jen"
VENV_DIR = "/opt/jen/venv"
SYSTEM_PYTHON = "/usr/bin/python3"
SELF_INSTALL_PATH = "/usr/local/sbin/jen-update-root.py"
UPDATE_SERVICE_PATH = "/etc/systemd/system/jen-update.service"
CONFIG_FILE = "/etc/jen/jen.config"

# The parts of /opt/jen that install_extracted_files() replaces wholesale
# (rmtree + recopy) rather than merging — so a failed update has to be
# able to put exactly these back. static/ is an additive copy (never
# rmtree'd) and holds user icon uploads, so it's deliberately not here:
# a rolled-back app just leaves the new static files sitting unused.
_ROLLBACK_ITEMS = ("jen", "run.py", "templates", "requirements.txt", "CHANGELOG.md")

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


def install_extracted_files(extracted, install_dir=INSTALL_DIR):
    """
    Perform the actual file installation from an already-extracted,
    already-verified release directory into install_dir. Pulled out as
    its own function (rather than left inline in main()) specifically
    so it's independently testable against a hand-built fake extracted
    directory, without needing to mock network calls or tarfile
    extraction at all — matching this project's general preference for
    small, directly-testable functions over one large script body.

    Scope: jen/ package, run.py, CHANGELOG.md, requirements.txt,
    templates/, static/ (additive, preserving an existing favicon.ico —
    see v5.1.8), jen.service (+ `systemctl daemon-reload`), and
    jen-sudoers (validated with `visudo -c` first, never installed on a
    validation failure). main() has already pip-installed requirements
    into the venv and snapshotted everything a rollback needs before
    calling this.
    """
    # Core application package
    jen_src = os.path.join(extracted, "jen")
    if os.path.isdir(jen_src):
        target = os.path.join(install_dir, "jen")
        if os.path.isdir(target):
            shutil.rmtree(target)
        shutil.copytree(jen_src, target)

    # Entry point
    run_py_src = os.path.join(extracted, "run.py")
    if os.path.isfile(run_py_src):
        shutil.copy2(run_py_src, os.path.join(install_dir, "run.py"))

    # CHANGELOG.md (v5.2.5 fix, carried forward here)
    changelog_src = os.path.join(extracted, "CHANGELOG.md")
    if os.path.isfile(changelog_src):
        shutil.copy2(changelog_src, os.path.join(install_dir, "CHANGELOG.md"))

    # requirements.txt — keep the pinned dependency list current beside
    # the installed app. main() has already pip-installed it into the
    # venv (from the staged copy) before reaching this point.
    requirements_src = os.path.join(extracted, "requirements.txt")
    if os.path.isfile(requirements_src):
        shutil.copy2(requirements_src, os.path.join(install_dir, "requirements.txt"))

    # Templates
    templates_src = os.path.join(extracted, "templates")
    if os.path.isdir(templates_src):
        target = os.path.join(install_dir, "templates")
        if os.path.isdir(target):
            shutil.rmtree(target)
        shutil.copytree(templates_src, target)

    # static/ — additive copy, preserving favicon.ico (may be a real
    # user upload, not just the shipped default — see v5.1.8).
    static_src = os.path.join(extracted, "static")
    if os.path.isdir(static_src):
        static_dest = os.path.join(install_dir, "static")
        os.makedirs(static_dest, exist_ok=True)
        existing_favicon = os.path.join(static_dest, "favicon.ico")
        preserved_favicon = None
        if os.path.isfile(existing_favicon):
            preserved_favicon = tempfile.NamedTemporaryFile(delete=False)
            preserved_favicon.close()
            shutil.copy2(existing_favicon, preserved_favicon.name)
        for root, _dirs, files in os.walk(static_src):
            rel = os.path.relpath(root, static_src)
            dest_root = static_dest if rel == "." else os.path.join(static_dest, rel)
            os.makedirs(dest_root, exist_ok=True)
            for fname in files:
                shutil.copy2(os.path.join(root, fname), os.path.join(dest_root, fname))
        if preserved_favicon:
            shutil.copy2(preserved_favicon.name, existing_favicon)
            os.unlink(preserved_favicon.name)

    # systemd service file
    service_src = os.path.join(extracted, "jen.service")
    if os.path.isfile(service_src):
        shutil.copy2(service_src, "/etc/systemd/system/jen.service")
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)

    # sudoers entry — validate before installing to avoid locking out
    # all sudo access with a malformed file.
    sudoers_src = os.path.join(extracted, "jen-sudoers")
    if os.path.isfile(sudoers_src):
        check = subprocess.run(["/usr/sbin/visudo", "-c", "-f", sudoers_src], capture_output=True, text=True)
        if check.returncode != 0:
            log(f"ERROR: new jen-sudoers failed validation, not installing it: {check.stderr}")
        else:
            shutil.copy2(sudoers_src, "/etc/sudoers.d/jen")
            os.chmod("/etc/sudoers.d/jen", 0o440)

    # Ownership — everything the web process needs to read/write goes
    # to www-data. This script and its own directory are never touched
    # by this chown, since they're not under install_dir at all.
    subprocess.run(
        [
            "/bin/chown",
            "-R",
            "www-data:www-data",
            os.path.join(install_dir, "jen"),
            os.path.join(install_dir, "run.py"),
            os.path.join(install_dir, "templates"),
            os.path.join(install_dir, "static"),
        ],
        check=False,
    )


def install_self_update_files(extracted, self_install_path=SELF_INSTALL_PATH, update_service_path=UPDATE_SERVICE_PATH):
    """
    v5.3.3 fix — a real gap found by a third-party review of the v5.2.6
    redesign: install_extracted_files() above installs the application
    (jen/, run.py, templates/, static/, jen.service, jen-sudoers), but
    never installed a new copy of THIS script or of jen-update.service
    itself. A fix shipped inside jen-update-root.py would never reach
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


def _python_works(python_bin):
    """True if `python_bin` exists and can execute a trivial program —
    catches a venv whose interpreter symlink is dangling after an OS
    python upgrade."""
    try:
        return subprocess.run([python_bin, "-c", ""], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def ensure_venv(venv_dir=VENV_DIR):
    """
    v5.8.0 — Jen runs its dependencies out of /opt/jen/venv. Return the
    path to that venv's python, creating the venv first if this is an
    install that predates it (or repairing one an OS python bump left
    broken). Returns None if a venv genuinely can't be built, so the
    caller can fall back to the system interpreter + --break-system-packages
    exactly as pre-5.8.0 updates did.
    """
    venv_py = os.path.join(venv_dir, "bin", "python")
    if _python_works(venv_py):
        return venv_py
    log("No usable venv at /opt/jen/venv — creating it.")
    try:
        if os.path.exists(venv_dir):
            shutil.rmtree(venv_dir)
        subprocess.run([SYSTEM_PYTHON, "-m", "venv", venv_dir], check=True, capture_output=True, text=True)
        if _python_works(venv_py):
            subprocess.run([venv_py, "-m", "pip", "install", "-q", "--upgrade", "pip"], capture_output=True)
            return venv_py
    except (OSError, subprocess.SubprocessError) as e:
        log(f"WARNING: could not create /opt/jen/venv ({e}) — falling back to system python.")
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
    the pre-5.8.0 behaviour of logging a warning and restarting into a
    half-updated app.
    """
    if not os.path.isfile(requirements_path):
        log(f"WARNING: {requirements_path} not found — skipping dependency install.")
        return True
    log(f"Installing Python dependencies with {python_bin} …")
    cmd = [python_bin, "-m", "pip", "install", "--upgrade", "-r", requirements_path]
    # ensure_venv() returns the literal venv path or None → SYSTEM_PYTHON;
    # a plain string compare is right here (NOT realpath — a venv's
    # bin/python realpaths to the system interpreter, see run.py's guard).
    if python_bin == SYSTEM_PYTHON:
        # No venv — system pip needs the PEP 668 override (pip >= 23).
        result = subprocess.run(cmd + ["--break-system-packages"], capture_output=True, text=True)
        if result.returncode != 0:
            result = subprocess.run(cmd, capture_output=True, text=True)  # older pip
    else:
        result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        log("Dependencies installed.")
        return True
    log(f"ERROR: pip install failed — aborting update, /opt/jen untouched:\n{result.stderr.strip()}")
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
    """Replace dst (file or dir) with a copy of src."""
    if os.path.isdir(src):
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        elif os.path.exists(dst):
            os.unlink(dst)
        shutil.copytree(src, dst)
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


def restore_snapshot(snapshot_dir, install_dir=INSTALL_DIR):
    """Put a snapshot_install() snapshot back — /opt/jen tree, then the
    external files, then daemon-reload + chown + restart jen."""
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
    subprocess.run(
        ["/bin/chown", "-R", "www-data:www-data", *[os.path.join(install_dir, i) for i in _ROLLBACK_ITEMS]],
        check=False,
    )
    subprocess.run(["/usr/bin/systemctl", "restart", "jen"], check=False)


def _http_port():
    try:
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(CONFIG_FILE)
        return cfg.getint("server", "http_port", fallback=5050)
    except Exception:
        return 5050


def service_healthy(timeout=45):
    """
    After the restart, wait up to `timeout`s for jen to be back: the unit
    active AND the HTTP port answering with anything below 500 (a 200, or
    a 301/302 to login when SSL is on — both mean the app is serving).
    """
    port = _http_port()
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(3)
        if subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "jen"]).returncode != 0:
            continue
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
                if resp.status < 500:
                    return True
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return True
        except (urllib.error.URLError, OSError):
            pass
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


def main():
    log("Checking GitHub for the latest release…")
    data = fetch_json(GITHUB_RELEASES_API)
    version = data.get("tag_name", "").lstrip("v")
    if not version:
        log("ERROR: could not determine latest version from GitHub API response.")
        return 1

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

    log("Downloading release…")
    tarball_bytes, actual_hash = fetch_bytes_with_sha256(asset_url)

    tarball_name = asset_url.rsplit("/", 1)[-1]
    try:
        checksum_text = fetch_text(checksum_asset_url)
    except Exception as e:
        log(f"ERROR: could not fetch checksum file — refusing to install unverified: {e}")
        return 1

    if not verify_release_checksum(tarball_name, actual_hash, checksum_text):
        log(f"ERROR: checksum verification failed for {tarball_name} — refusing to install unverified.")
        return 1

    log("Checksum verified.")

    # ── Extract to a temp dir. Same tar-slip protection as the
    # previous implementation: filter by TYPE, not just name — a
    # member named safely under "jen/" can still be a symlink/hardlink
    # whose target points outside tmp_dir. Only allow plain files and
    # directories.
    tmp_dir = tempfile.mkdtemp(prefix="jen_update_extract_")
    tmp_tarball = tempfile.NamedTemporaryFile(suffix=".tar.gz", prefix="jen_update_", delete=False)
    try:
        tmp_tarball.write(tarball_bytes)
        tmp_tarball.close()

        with tarfile.open(tmp_tarball.name, "r:gz") as tf:
            members = [
                m
                for m in tf.getmembers()
                if m.name.startswith("jen/")
                and ".." not in m.name
                and not os.path.isabs(m.name)
                and (m.isfile() or m.isdir())
            ]
            tf.extractall(tmp_dir, members=members)

        extracted = os.path.join(tmp_dir, "jen")
        if not os.path.isdir(extracted):
            log("ERROR: update package format invalid — expected jen/ directory in tarball.")
            return 1

        # ── Transactional install (v5.8.0) ──────────────────────────────
        # Everything up to install_extracted_files() is against staging
        # and the venv only; /opt/jen's own files are not touched until
        # the release has been proven to install its deps and import.
        python_bin = ensure_venv() or SYSTEM_PYTHON
        if python_bin == SYSTEM_PYTHON and not os.path.exists("/.dockerenv"):
            log(
                "WARNING: running WITHOUT /opt/jen/venv — installing to system python. "
                "Jen is not isolated. Run `sudo ./install.sh --repair` after this update "
                "to finish the venv migration (the app shows a banner about this too)."
            )

        if not install_python_dependencies(os.path.join(extracted, "requirements.txt"), python_bin):
            return 1
        # The venv stays root:root (this script runs as root; www-data only
        # reads/executes it — a writable venv is a persistence foothold).
        if python_bin != SYSTEM_PYTHON:
            subprocess.run(["/bin/chown", "-R", "root:root", VENV_DIR], check=False)
            subprocess.run([python_bin, "-m", "compileall", "-q", os.path.join(VENV_DIR, "lib")], capture_output=True)

        if not validate_staged_release(extracted, python_bin):
            return 1

        snapshot_dir = os.path.join(INSTALL_DIR, f".rollback-{int(time.time())}")
        log(f"Snapshotting current install → {snapshot_dir}")
        snapshot_install(snapshot_dir)

        # From here on ANY failure — an exception during the file swap, or
        # a service that doesn't come back healthy — restores the snapshot
        # and restarts the previous version. (v5.8.0 only rolled back on
        # the health check; a raise mid-swap left /opt/jen half-updated.)
        try:
            log("Installing files…")
            install_extracted_files(extracted, INSTALL_DIR)
            install_self_update_files(extracted)
            log(f"Update to v{version} installed. Restarting jen…")
            subprocess.run(["/usr/bin/systemctl", "restart", "jen"], check=False)
            if not service_healthy():
                raise RuntimeError("jen did not come back healthy after the update")
        except Exception as e:
            log(f"ERROR: {e} — rolling back.")
            restore_snapshot(snapshot_dir)
            if service_healthy():
                log(f"Rolled back to the previous install. The v{version} update was NOT applied.")
                shutil.rmtree(snapshot_dir, ignore_errors=True)
            else:
                log(
                    "CRITICAL: rollback restart also unhealthy. Snapshot kept at "
                    f"{snapshot_dir}; check `journalctl -u jen`."
                )
            return 1

        log("jen is back up and serving.")
        shutil.rmtree(snapshot_dir, ignore_errors=True)
        log("Done.")
        return 0

    finally:
        try:
            os.unlink(tmp_tarball.name)
        except OSError:
            pass
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
