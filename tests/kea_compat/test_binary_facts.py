"""
tests/kea_compat/test_binary_facts.py
───────────────────────────────────────
v5.68.0-beta.6 (Q141) — who owns ISC's `kea-dhcp4`, and who does the daemon run as, on each ISC image the compatibility job boots.

jen-kea-helper (build 7 to 9) required `root:root` of every binary it runs, the Kea daemon's included, and a comment in the system suite's Kea node
asserted that "a real apt install puts the binary under root:root". Nobody checked that against ISC's packages — the ones Jen targets — and on
the maintainer's Kea 3.0.4 deb the file is `_kea:_kea` 0750, so every config push through the helper failed ("kea-dhcp4 is not installed").
Build 10 runs `kea-dhcpX -t` as the daemon's own account and trusts a regular file owned by exactly that SYSTEM account (a uid below 1000, never root)
with no group or other write bit. This records what each image really has — owner, group, uid, mode, the account the running daemon's process
belongs to, the image's own USER — into $KEA_COMPAT_BINARY_OUT, and asserts the two things the helper's rule depends on, so the suite goes red the
day ISC changes either: the binary is NOT root-owned, and it satisfies the helper's rule. Run against the compat job's own running daemon
container (default name `kea`).
"""

import json
import os
import subprocess

import pytest

pytestmark = pytest.mark.kea_compat

CONTAINER = os.environ.get("KEA_COMPAT_CONTAINER", "kea")
OUT = os.environ.get("KEA_COMPAT_BINARY_OUT", "")
BINARY = "/usr/sbin/kea-dhcp4"


def _docker(*args, check=True):
    p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=60)
    if check and p.returncode != 0:
        raise AssertionError(f"docker {' '.join(args)} -> {p.returncode}: {p.stderr.strip()}")
    return p.stdout.strip()


def _exec(*cmd, check=True):
    return _docker("exec", CONTAINER, *cmd, check=check)


def parse_stat(text: str) -> dict:
    """`stat -c '%U|%G|%u|%g|%a|%F'` -> owner facts. Pure."""
    owner, group, uid, gid, mode, kind = text.strip().split("|", 5)
    return {
        "owner": owner,
        "group": group,
        "uid": int(uid),
        "gid": int(gid),
        "mode": mode.zfill(4),
        "regular": kind.strip().lower() == "regular file",
    }


def helper_would_run_it(facts: dict) -> bool:
    """The condition jen-kea-helper's `_daemon_bin_ok` applies to a binary the helper runs as the daemon's account: a regular file, owned by a SYSTEM
    account (a uid below 1000, never root), with no group or other write bit. Pure - the same test as the helper's, on recorded facts."""
    return bool(facts["regular"]) and 0 < facts["uid"] < 1000 and not (int(facts["mode"], 8) & 0o022)


class TestParse:
    def test_the_real_shape(self):
        facts = parse_stat("_kea|_kea|105|106|750|regular file")
        assert facts == {"owner": "_kea", "group": "_kea", "uid": 105, "gid": 106, "mode": "0750", "regular": True}
        assert helper_would_run_it(facts)

    @pytest.mark.parametrize(
        "text",
        [
            "root|root|0|0|755|regular file",  # root-owned: the helper runs it as root, not as an account
            "alice|alice|1001|1001|750|regular file",  # not a system account
            "_kea|_kea|105|106|770|regular file",  # group-writable
            "_kea|_kea|105|106|757|regular file",  # world-writable
            "_kea|_kea|105|106|750|symbolic link",  # not a regular file
        ],
    )
    def test_the_shapes_the_helper_refuses(self, text):
        assert not helper_would_run_it(parse_stat(text))


def _daemon_run_as() -> dict:
    """The account the RUNNING daemon's process belongs to (from /proc, which every image has), and its name."""
    script = (
        'for p in /proc/[0-9]*; do if [ "$(cat $p/comm 2>/dev/null)" = kea-dhcp4 ]; then '
        "awk '/^Uid:/ {print $2}' $p/status; break; fi; done"
    )
    uid = _exec("sh", "-c", script, check=False).strip()
    if not uid.isdigit():
        return {"uid": None, "name": None}
    name = _exec("awk", "-F:", f"$3=={uid} {{print $1}}", "/etc/passwd", check=False).strip()
    return {"uid": int(uid), "name": name or None}


def test_binary_facts():
    facts = parse_stat(_exec("stat", "-c", "%U|%G|%u|%g|%a|%F", BINARY))
    image_user = _docker("inspect", "--format", "{{.Config.User}}", CONTAINER, check=False)
    entrypoint = _docker("inspect", "--format", "{{json .Config.Entrypoint}}", CONTAINER, check=False)
    record = {
        "binary": BINARY,
        **facts,
        "daemon_runs_as": _daemon_run_as(),
        "image_user": image_user or "(none: the image's default user, root)",
        "entrypoint": entrypoint,
        "helper_would_run_it": helper_would_run_it(facts),
    }
    print(json.dumps(record, indent=2))
    if OUT:
        with open(OUT, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
    assert facts["regular"], f"{BINARY} is not a regular file on this image: {record}"
    assert facts["uid"] != 0, (
        f"ISC's image now ships {BINARY} owned by root - the helper's two-tier rule (and the system suite's Kea node, which no longer chowns it) "
        f"were written against a binary owned by the daemon's service account: {record}"
    )
    assert helper_would_run_it(facts), (
        f"jen-kea-helper would refuse ISC's {BINARY} on this image (it must be owned by a system account, uid below 1000, with no group/other "
        f"write bit): {record}"
    )
