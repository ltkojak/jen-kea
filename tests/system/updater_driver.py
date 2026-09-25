"""
tests/system/updater_driver.py
───────────────────────────────
Q84 scenario 6 — drives the REAL jen-update-root.py `main()` inside the
`updater` container (root, its own /opt/jen; the checkout is mounted at
/repo). Runs there, not in the pytest process:

    python3 /repo/tests/system/updater_driver.py layout
    python3 /repo/tests/system/updater_driver.py update [--hang-after-extract]
    python3 /repo/tests/system/updater_driver.py prune

`layout` lays out a versioned-release tree serving 5.0.0. `update` runs main()
against a fabricated GitHub release for 5.0.1: the release listing, the asset
download and the systemd calls are stood in for (there is no GitHub and no
systemd here); everything that decides whether the update is safe is the real
code — checksum verification, the ssh-keygen signature check (against a
throwaway key swapped in for RELEASE_SIGNERS), extraction, byte-compile, staged
validation, the snapshot, the rename, the atomic `current` switch, pruning.
`--hang-after-extract` parks the process right after `_extract_release` (the
harness SIGKILLs it there: after extract, before the switch).
"""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time

SENTINEL = "/tmp/sys-updater.sentinel"
KEY = "/tmp/sys-updater-key"
OLD, NEW = "5.0.0", "5.0.1"

spec = importlib.util.spec_from_file_location("jur", "/repo/jen-update-root.py")
jur = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jur)


def emit(obj):
    print("@@ " + json.dumps(obj, default=str), flush=True)


def _write_release(root, version):
    """A minimal but REAL package: validate_staged_release imports it."""
    pkg = os.path.join(root, "jen")
    os.makedirs(os.path.join(pkg, "models"), exist_ok=True)
    with open(os.path.join(pkg, "__init__.py"), "w") as f:
        f.write(f'JEN_VERSION = "{version}"\n\ndef create_app():\n    return None\n')
    open(os.path.join(pkg, "models", "__init__.py"), "w").close()
    with open(os.path.join(pkg, "models", "migrations.py"), "w") as f:
        f.write("MIGRATIONS = []\n")
    with open(os.path.join(root, "requirements.txt"), "w") as f:
        f.write("# none\n")


def layout():
    for item in os.listdir("/opt/jen"):
        p = os.path.join("/opt/jen", item)
        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
    app = f"/opt/jen/releases/{OLD}/app"
    os.makedirs(app)
    os.makedirs(f"/opt/jen/releases/{OLD}/venv")
    _write_release(app, OLD)
    os.symlink(os.path.join("releases", OLD), "/opt/jen/current")
    for f in (SENTINEL,):
        if os.path.exists(f):
            os.unlink(f)
    emit({"layout": "ok", "current": os.readlink("/opt/jen/current")})


def _fabricate_release():
    """(releases-listing, {url: bytes}) for a signed 5.0.1 tarball."""
    src = "/tmp/sys-rel-src"
    shutil.rmtree(src, ignore_errors=True)
    _write_release(src, NEW)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for dirpath, _dirs, files in os.walk(src):
            for name in files:
                full = os.path.join(dirpath, name)
                tf.add(full, arcname="jen/" + os.path.relpath(full, src))
    tarball = buf.getvalue()
    tar_name = f"jen-v{NEW}.tar.gz"
    sums = f"{hashlib.sha256(tarball).hexdigest()}  {tar_name}\n"

    if not os.path.exists(KEY):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", KEY], check=True)
    with open("/tmp/SHA256SUMS", "w") as f:
        f.write(sums)
    if os.path.exists("/tmp/SHA256SUMS.sig"):
        os.unlink("/tmp/SHA256SUMS.sig")
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-q", "-f", KEY, "-n", jur.RELEASE_SIGNATURE_NAMESPACE, "/tmp/SHA256SUMS"],
        check=True,
    )
    with open("/tmp/SHA256SUMS.sig", "rb") as f:
        sig = f.read()
    with open(KEY + ".pub") as f:
        kind, blob = f.read().split()[:2]
    jur.RELEASE_SIGNERS = f"{jur.RELEASE_SIGNATURE_IDENTITY} {kind} {blob}"

    base = f"{jur.GITHUB_ASSET_PREFIX}v{NEW}/"
    urls = {base + tar_name: tarball, base + "SHA256SUMS": sums.encode(), base + "SHA256SUMS.sig": sig}
    listing = [
        {
            "tag_name": f"v{NEW}",
            "draft": False,
            "prerelease": False,
            "assets": [
                {"name": n, "browser_download_url": base + n} for n in (tar_name, "SHA256SUMS", "SHA256SUMS.sig")
            ],
        }
    ]
    return listing, urls


def update(hang_after_extract):
    listing, urls = _fabricate_release()
    jur.fetch_json = lambda url: listing
    jur.fetch_text = lambda url, timeout=15: urls[url].decode()
    jur.fetch_bytes_with_sha256 = lambda url, timeout=120: (urls[url], hashlib.sha256(urls[url]).hexdigest())

    # no GitHub-served venv build, no systemd, no real web app to probe
    def build_venv(venv_dir):
        os.makedirs(venv_dir, exist_ok=True)
        if hang_after_extract:
            with open(SENTINEL, "w") as f:
                f.write(str(os.getpid()))
            while True:
                time.sleep(1)
        return sys.executable

    jur._build_release_venv = build_venv
    jur.install_python_dependencies = lambda req, py: True
    jur._probe_once = lambda opener, url: True
    jur.service_healthy = lambda timeout=None: True
    jur._confirm_running_version = lambda version, attempts=5, delay=3: version
    jur.install_external_files = lambda app_dir: None
    jur.install_self_update_files = lambda app_dir: None

    real_run = subprocess.run

    def run(argv, *a, **k):
        if isinstance(argv, (list, tuple)) and argv and argv[0] == "/usr/bin/systemctl":
            return subprocess.CompletedProcess(argv, 0, "", "")
        return real_run(argv, *a, **k)

    subprocess.run = run
    rc = jur.main()
    emit({"rc": rc, "current": os.readlink("/opt/jen/current")})


def prune():
    removed = jur._prune_old_releases()
    emit({"removed": removed, "releases": sorted(os.listdir("/opt/jen/releases"))})


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "layout":
        layout()
    elif mode == "update":
        update("--hang-after-extract" in sys.argv)
    elif mode == "prune":
        prune()
    else:
        raise SystemExit(f"unknown mode {mode!r}")
