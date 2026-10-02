#!/usr/bin/env python3
"""
tools/ci_updater_hop.py
────────────────────────
v5.67.0-beta.10 (Q122) — drives a release's OWN root self-updater through a
real hop, in CI, on a real box. Nothing started `jen-update.service` for
old-release -> new-release before this: the unit tests pin the updater's
functions one at a time, and the install job upgrades through install.sh, so
the path every stable operator actually takes — the stable release's own
`jen-update-root.py`, run as root, switching `current` to a release it has
never heard of and restarting the service — had never been exercised by
anything. (The old workflow grepped a journal for it that was always empty.)

`hop` loads the given updater with importlib and calls its REAL `main()`:
channel selection, release picking, asset validation, extraction, venv build,
dependency install, validation, health baseline, snapshot, the file installs,
the `current` flip, the restart, the health wait and the running-version
confirmation all run for real. Only the four network-facing seams are stood in
for, and they are named here so nothing about them is a surprise:

  fetch_json                  -> a one-release list describing the tarball
  fetch_text                  -> the matching SHA256SUMS text / a placeholder signature
  verify_release_signature    -> True   (STAND-IN: the signature step; the real
                                 verification is covered by tests/test_jen_update_root.py
                                 and release.yml, and needs the release key)
  fetch_bytes_with_sha256     -> the tarball's bytes and their real sha256

`bump` writes a copy of a tarball with `jen/__init__.py`'s JEN_VERSION changed,
so a second hop has a "next release" to move to.

Run as root, on the box. Pure stdlib.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import re
import sys
import tarfile

# What `hop` replaces on the loaded module, and why each one is a stand-in.
STAND_INS = ("fetch_json", "fetch_text", "verify_release_signature", "fetch_bytes_with_sha256")
# What must exist on the module for the hop to mean anything — a missing one
# fails loudly instead of silently skipping a stage.
REQUIRED = (*STAND_INS, "main", "GITHUB_ASSET_PREFIX", "install_external_files", "install_self_update_files")


def build_release_list(prefix: str, version: str, tarball_name: str, prerelease: bool) -> list[dict]:
    """The GitHub releases-API shape the updater's own main() reads."""
    base = f"{prefix}v{version}/"
    return [
        {
            "tag_name": f"v{version}",
            "prerelease": prerelease,
            "draft": False,
            "assets": [
                {"name": tarball_name, "browser_download_url": base + tarball_name},
                {"name": "SHA256SUMS", "browser_download_url": base + "SHA256SUMS"},
                {"name": "SHA256SUMS.sig", "browser_download_url": base + "SHA256SUMS.sig"},
            ],
        }
    ]


def install_stand_ins(module, tarball_bytes: bytes, version: str, prerelease: bool) -> str:
    """Replace the network seams on `module`. Returns the tarball's sha256."""
    sha = hashlib.sha256(tarball_bytes).hexdigest()
    name = f"jen-v{version}.tar.gz"
    releases = build_release_list(module.GITHUB_ASSET_PREFIX, version, name, prerelease)

    module.fetch_json = lambda url, *a, **k: releases
    module.fetch_text = lambda url, *a, **k: (
        f"{sha}  {name}\n" if url.endswith("SHA256SUMS") else "stand-in-signature\n"
    )
    module.verify_release_signature = lambda *a, **k: True
    module.fetch_bytes_with_sha256 = lambda url, *a, **k: (tarball_bytes, sha)
    return sha


def load_updater(path: str):
    spec = importlib.util.spec_from_file_location("jen_updater_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    missing = [n for n in REQUIRED if not hasattr(module, n)]
    if missing:
        raise SystemExit(f"{path} has no {missing} — the hop harness would be driving something else")
    return module


def bump_tarball(src: bytes, version: str) -> bytes:
    """`src` (a gzip tarball from `git archive --prefix=jen/`) with jen/__init__.py's JEN_VERSION set to `version`."""
    out = io.BytesIO()
    changed = 0
    with tarfile.open(fileobj=io.BytesIO(src), mode="r:gz") as tin, tarfile.open(fileobj=out, mode="w:gz") as tout:
        for member in tin.getmembers():
            data = tin.extractfile(member).read() if member.isfile() else None
            if member.name == "jen/jen/__init__.py":
                text = data.decode("utf-8")
                text, n = re.subn(r'^(JEN_VERSION\s*=\s*)"[^"]+"', rf'\g<1>"{version}"', text, count=1, flags=re.M)
                changed += n
                data = text.encode("utf-8")
                member.size = len(data)
            tout.addfile(member, io.BytesIO(data) if data is not None else None)
    if not changed:
        raise SystemExit("jen/jen/__init__.py has no JEN_VERSION line to bump")
    return out.getvalue()


def _cmd_hop(args) -> int:
    module = load_updater(args.updater)
    with open(args.tarball, "rb") as f:
        tarball = f.read()
    sha = install_stand_ins(module, tarball, args.version, args.prerelease)
    print(
        f"[hop] {args.updater} -> v{args.version}  (tarball sha256 {sha[:12]}…; signature step stood in for)",
        flush=True,
    )
    sys.argv = [args.updater]
    rc = module.main()
    print(f"[hop] updater main() returned {rc}", flush=True)
    return int(rc or 0)


def _cmd_bump(args) -> int:
    with open(args.src, "rb") as f:
        src = f.read()
    with open(args.out, "wb") as f:
        f.write(bump_tarball(src, args.version))
    print(f"[bump] {args.out}: JEN_VERSION = {args.version}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    hop = sub.add_parser("hop", help="run an updater's real main() against a local tarball")
    hop.add_argument("--updater", required=True, help="path to the jen-update-root.py to drive")
    hop.add_argument("--tarball", required=True, help="the release tarball to hop onto")
    hop.add_argument("--version", required=True, help="that tarball's version, as its tag would say it")
    hop.add_argument(
        "--prerelease", action="store_true", help="publish it as a prerelease (the box needs channel = beta)"
    )
    hop.set_defaults(fn=_cmd_hop)
    bump = sub.add_parser("bump", help="copy a tarball with a different JEN_VERSION")
    bump.add_argument("--src", required=True)
    bump.add_argument("--out", required=True)
    bump.add_argument("--version", required=True)
    bump.set_defaults(fn=_cmd_bump)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
