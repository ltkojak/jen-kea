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
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

GITHUB_REPO = "ltkojak/jen-kea"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_ASSET_PREFIX = f"https://github.com/{GITHUB_REPO}/releases/download/"
INSTALL_DIR = "/opt/jen"
SELF_INSTALL_PATH = "/usr/local/sbin/jen-update-root.py"
UPDATE_SERVICE_PATH = "/etc/systemd/system/jen-update.service"


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

    Mirrors the exact same file scope and safety behaviors as the
    previous self_update() Flask route's copy_cmds list: jen/ package,
    run.py, CHANGELOG.md, templates/, static/ (additive, preserving an
    existing favicon.ico rather than overwriting it — see v5.1.8),
    jen.service, and jen-sudoers (validated with visudo -c before
    installing, never installed if validation fails).
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
        check = subprocess.run(["/usr/sbin/visudo", "-c", "-f", sudoers_src],
                               capture_output=True, text=True)
        if check.returncode != 0:
            log(f"ERROR: new jen-sudoers failed validation, not installing it: {check.stderr}")
        else:
            shutil.copy2(sudoers_src, "/etc/sudoers.d/jen")
            os.chmod("/etc/sudoers.d/jen", 0o440)

    # Ownership — everything the web process needs to read/write goes
    # to www-data. This script and its own directory are never touched
    # by this chown, since they're not under install_dir at all.
    subprocess.run(
        ["/bin/chown", "-R", "www-data:www-data",
         os.path.join(install_dir, "jen"), os.path.join(install_dir, "run.py"),
         os.path.join(install_dir, "templates"), os.path.join(install_dir, "static")],
        check=False,
    )


def install_self_update_files(extracted, self_install_path=SELF_INSTALL_PATH,
                               update_service_path=UPDATE_SERVICE_PATH):
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
            members = [m for m in tf.getmembers()
                       if m.name.startswith("jen/")
                       and ".." not in m.name
                       and not os.path.isabs(m.name)
                       and (m.isfile() or m.isdir())]
            tf.extractall(tmp_dir, members=members)

        extracted = os.path.join(tmp_dir, "jen")
        if not os.path.isdir(extracted):
            log("ERROR: update package format invalid — expected jen/ directory in tarball.")
            return 1

        log("Installing files…")
        install_extracted_files(extracted, INSTALL_DIR)
        install_self_update_files(extracted)

        log(f"Update to v{version} installed. Restarting jen…")
        subprocess.run(["/usr/bin/systemctl", "restart", "jen"], check=False)
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

