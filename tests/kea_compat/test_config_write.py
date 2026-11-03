"""tests/kea_compat/test_config_write.py - Q211: Jen's own mutation over the daemon's API, on real Kea.

Each row is one sentence of ISC's ARM (kea.readthedocs.io/en/kea-3.0.5/arm/ctrl-channel.html) made a fact per version. ORDERED: the file is a sequence
(pytest runs it top to bottom), and the last row restores the original file so the log-level step that follows starts from it. Facts go to
$KEA_COMPAT_WRITE_OUT, written after every fact (a row that fails leaves its answer behind); the row outcomes are added by conftest.py.

The job's earlier steps mount /etc/kea READ-ONLY. This module is the one that does not: its module fixture records what the daemon sees of the mounted
file and directory, recreates the container ONCE with the directory read-write (test_log_levels._restart's recipe), and puts the original file back
at the end. The first `config-write` is sent exactly as it ships; only if it fails for permission is the mounted file chowned to the account the
daemon runs as - and the row records which it was, because that is the operator step Jen 7's helper op will make (Q212, BB4).

A row that fails on a version is NOT fixed here: the assertion stays and the facts keep the daemon's answer.
"""

import copy
import hashlib
import json
import os
import shutil
import tempfile
import time
from datetime import datetime, timedelta, timezone

import pytest

from jen.services import config_revisions
from jen.services import kea as __kea
from jen.services import kea_config_edit as __ed
from jen.services import kea_config_view as __view
from tests.kea_compat import kea_config
from tests.kea_compat import test_binary_facts as __binary
from tests.kea_compat import test_log_levels as __levels
from tests.kea_compat import test_real_kea as __real

pytestmark = pytest.mark.kea_write

OUT = os.environ.get("KEA_COMPAT_WRITE_OUT", "")
CONF_DIR = os.environ.get("KEA_COMPAT_CONF_DIR", "")
CONF_PATH = os.path.join(CONF_DIR, "kea-dhcp4.conf") if CONF_DIR else ""
DAEMON_DIR = "/etc/kea"
DAEMON_CONF = "/etc/kea/kea-dhcp4.conf"
OUTSIDE = "/tmp/jen-x.conf"  # nosec B108 - a path INSIDE the throwaway daemon container, written (or refused) by Kea
SIBLING = "/etc/kea/jen-candidate.conf"
NEW_SUBNET = {
    "id": 2,
    "subnet": "10.98.0.0/24",
    "pools": [{"pool": "10.98.0.100 - 10.98.0.200"}],
    "relay": {"ip-addresses": ["10.98.0.1"]},
}
TRANSPORT_TEXT = ("Cannot connect to Kea API", "timed out", "Kea API call failed")

ORIGINAL = None  # (cfg, hash) as read by test_01, used by test_90
_STATE = {}  # what the module fixture saved: the file's bytes and the directory's mode


class _Facts(dict):
    """A dict that writes itself to $KEA_COMPAT_WRITE_OUT on every assignment, keeping the `rows` conftest.py adds."""

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.flush()

    def flush(self):
        if not OUT:
            return
        try:
            with open(OUT) as fh:
                rows = json.load(fh).get("rows", {})
        except (OSError, ValueError):
            rows = {}
        with open(OUT, "w") as fh:
            json.dump({**self, "rows": rows}, fh, indent=2, default=str)


@pytest.fixture(scope="module")
def facts():
    return _Facts()


@pytest.fixture(scope="module", autouse=True)
def writable_daemon(facts):
    """BA1: record, recreate once with the directory read-write, and (after the last row) put the original file back."""
    with open(CONF_PATH, "rb") as fh:
        _STATE["bytes"] = fh.read()
    _STATE["dir_mode"] = os.stat(CONF_DIR).st_mode & 0o777
    facts["original_file_sha256"] = hashlib.sha256(_STATE["bytes"]).hexdigest()
    facts["mount"] = "read-write for this step (the suite before it and the log-level step after it mount it read-only)"
    __levels._restart("INFO", None, writable=True, write_config=False)
    facts["daemon_runs_as"] = __binary._daemon_run_as()
    facts["mounted_file_as_the_daemon_sees_it"] = __binary.mounted_path_facts(DAEMON_CONF)
    facts["mounted_dir_as_the_daemon_sees_it"] = __binary.mounted_path_facts(DAEMON_DIR)
    facts["runner_uid"] = os.getuid() if hasattr(os, "getuid") else None
    yield
    _put_the_original_file_back()


# ── helpers (the compat suite's own where it has one) ───────────────────────────────────────────────────────────────


def _first(reply, key):
    """(value, where) of `key` in a reply: under `arguments` (ISC's config-hash-get example) or at the top level."""
    args = reply.get("arguments")
    if isinstance(args, dict) and key in args:
        return args[key], f"arguments.{key}"
    if key in reply:
        return reply[key], key
    return None, None


def _brief(reply):
    args = reply.get("arguments")
    return {
        "result": reply.get("result"),
        "text": (reply.get("text") or "")[:300],
        "argument_keys": sorted(args) if isinstance(args, dict) else None,
    }


def _hash():  # config-hash-get -> arguments.hash
    return _first(__real._ok(__kea.kea_command("config-hash-get")), "hash")[0]


def _get_reply():
    return __real._ok(__kea.kea_command("config-get"))


def _get():  # config-get -> arguments (Dhcp4 inside)
    return _get_reply()["arguments"]


def _body(cfg):
    """What config-test / config-set take: the daemon's section only (config-get's `arguments` also carries the digest)."""
    return {"Dhcp4": cfg["Dhcp4"]}


def _file():
    """The daemon's configuration file, read as the daemon sees it (a file Kea wrote may not be readable to the runner). Kea writes JSON."""
    text = __binary._exec("cat", DAEMON_CONF)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise AssertionError(f"{DAEMON_CONF} is not JSON ({exc}): {text[:200]!r}") from exc


def _subnet_ids(cfg):
    return sorted(s.get("id") for s, _ in __view.iter_subnet4(cfg["Dhcp4"]))


def _transport_failure(reply):
    return any(t in (reply.get("text") or "") for t in TRANSPORT_TEXT)


def _restart_daemon():
    """A graceful restart, as `systemctl restart` is: stop (Kea removes its pid file), clear the run directory, start the SAME container."""
    __levels._sh("docker", "stop", "-t", "30", "kea")
    __levels._clear_run_dir()
    __levels._sh("docker", "start", "kea")
    __levels._wait_ready()


def _root(*cmd):
    return __levels._sh("docker", "exec", "-u", "root", "kea", *cmd, check=False)


def _exists(path):
    return _root("test", "-e", path).returncode == 0


def _put_the_original_file_back():
    """Replace (never open-for-write) the mounted file with the bytes the job started with, runner-owned and 0644, and the directory's mode with its own."""
    if not _STATE.get("bytes") or not CONF_PATH:
        return
    tmp = CONF_PATH + ".restore"
    with open(tmp, "wb") as fh:
        fh.write(_STATE["bytes"])
    os.chmod(tmp, 0o644)
    os.replace(tmp, CONF_PATH)
    os.chmod(CONF_DIR, _STATE["dir_mode"])


def _can_write(file_facts, uid):
    """Whether `uid` may write the file by its owner and other bits (the daemon's supplementary groups are not known here)."""
    if not file_facts or uid is None:
        return False
    mode = int(file_facts["mode"], 8)
    return (file_facts["uid"] == uid and bool(mode & 0o200)) or bool(mode & 0o002)


def _permission_shaped(reply):
    text = (reply.get("text") or "").lower()
    return any(
        w in text for w in ("permission", "denied", "not permitted", "unable to open", "cannot open", "unable to write")
    )


def _config_write_as_it_ships(facts):
    """The first `config-write`, sent as it is; if it fails for permission, the file is chowned to the daemon's account and it is sent again
    (and, only if that is not enough, the directory is opened too). Every step is recorded - this is the fact Q212's helper op is built on."""
    first = __kea.kea_command("config-write")
    facts["config_write_as_shipped"] = _brief(first)
    if first.get("result") == 0:
        facts["chown_needed"] = False
        facts["write_needed"] = "nothing: the mounted file as the image and the runner left it"
        return first
    uid = (facts.get("daemon_runs_as") or {}).get("uid")
    seen = __binary.mounted_path_facts(DAEMON_CONF)
    permission = _permission_shaped(first) or not _can_write(seen, uid)
    facts["config_write_failure_is_permission"] = permission
    facts["chown_needed"] = False
    if not permission or not uid:
        return first
    done = _root("chown", str(uid), DAEMON_CONF)
    facts["chown_needed"] = True
    facts["chown"] = {
        "to_uid": uid,
        "returncode": done.returncode,
        "stderr": done.stderr.strip()[:200],
        "file_after": __binary.mounted_path_facts(DAEMON_CONF),
    }
    second = __kea.kea_command("config-write")
    facts["config_write_after_chown"] = _brief(second)
    if second.get("result") == 0:
        facts["write_needed"] = "the file owned by the daemon's account"
        return second
    os.chmod(
        CONF_DIR, 0o777
    )  # beyond the entry's ladder: is it the DIRECTORY the daemon needs? (restored with the original file)
    _STATE["dir_open"] = True
    third = __kea.kea_command("config-write")
    facts["config_write_after_chown_and_an_open_directory"] = _brief(third)
    if third.get("result") == 0:
        facts["write_needed"] = "the file owned by the daemon's account AND a directory it may write"
    return third


# ── the rows ──────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_01_config_get_is_not_redacted(facts):
    """ARM: "the returned configuration is not redacted, i.e. it contains database passwords in plain text"; and since 2.4.0 a SHA-256 digest."""
    global ORIGINAL
    reply = _get_reply()
    cfg = reply["arguments"]
    want = kea_config.build()["Dhcp4"]["lease-database"]["password"]
    got = cfg["Dhcp4"]["lease-database"].get("password")
    from_reply, where = _first(reply, "hash")
    from_hash_get = _hash()
    ORIGINAL = (copy.deepcopy(cfg), from_hash_get)
    facts["config_get_lease_password_in_plain_text"] = got == want
    # config-get renders the hosts backend as the list `hosts-databases` on 3.x (the singular key is what the file was written with)
    hosts = cfg["Dhcp4"].get("hosts-database") or (cfg["Dhcp4"].get("hosts-databases") or [{}])[0]
    facts["config_get_hosts_database_key"] = "hosts-database" if "hosts-database" in cfg["Dhcp4"] else "hosts-databases"
    facts["config_get_hosts_password_in_plain_text"] = hosts.get("password") == want
    facts["hash_on_config_get"] = bool(from_reply)
    facts["hash_on_config_get_where"] = where
    facts["hash_on_config_hash_get"] = bool(from_hash_get)
    facts["hash_hex_length"] = len(from_hash_get or "")
    facts["config_get_hash_equals_config_hash_get"] = bool(from_reply) and from_reply == from_hash_get
    facts["config_get_top_level_keys"] = sorted(cfg)
    assert got == want, f"config-get redacted the lease database password: {got!r}"
    assert from_reply or from_hash_get, f"no digest on config-get or config-hash-get: {sorted(reply)} {sorted(cfg)}"


def test_02_a_jen_mutation_applies_live_and_the_hash_moves(facts):
    """ARM: config-set applies live (no restart) and returns a digest; the product's own add_subnet4 builds the configuration."""
    cfg = _get()
    h0 = _hash()
    after, code = __ed.add_subnet4(copy.deepcopy(cfg), copy.deepcopy(NEW_SUBNET))
    assert code == "ok"
    __real._ok(__kea.kea_command("config-test", arguments=_body(after)))
    started = time.monotonic()
    reply = __real._ok(__kea.kea_command("config-set", arguments=_body(after)))
    facts["config_set_reply"] = _brief(reply)
    from_reply, where = _first(reply, "hash")
    facts["hash_on_config_set"] = bool(from_reply)
    facts["hash_on_config_set_where"] = where
    h1 = _hash()
    facts["hash_after_set"] = h1
    facts["hash_moved_by_config_set"] = h1 != h0
    facts["config_set_hash_equals_config_hash_get"] = bool(from_reply) and from_reply == h1
    facts["config_set_and_hash_read_ms"] = round((time.monotonic() - started) * 1000)
    assert from_reply and from_reply != h0 and from_reply == h1, (h0, from_reply, h1, _brief(reply))
    assert 2 in _subnet_ids(_get())  # the daemon's own answer, never the reply's text
    __real.test_reservation_add_get_del_roundtrip()  # the database hook survived the reconfigure: host_cmds still answers and the row is stored
    facts["host_cmds_round_trip_after_set"] = True


def test_03_config_write_persists_and_a_restart_keeps_it(facts):
    """ARM: the config-set result "is kept in memory only" until config-write; and since 2.7.9 config-write is confined to the -c file's directory."""
    written = _config_write_as_it_ships(facts)
    assert written.get("result") == 0, (
        f"config-write: {_brief(written)} (as shipped: {facts.get('config_write_as_shipped')})"
    )
    on_disk = _file()
    facts["file_carries_the_new_subnet"] = 2 in _subnet_ids(on_disk)
    facts["file_password_in_plain_text"] = on_disk["Dhcp4"]["lease-database"].get("password") == "kea_pw"
    facts["file_top_level_keys"] = sorted(on_disk)
    facts["file_after_write"] = __binary.mounted_path_facts(DAEMON_CONF)
    assert facts["file_carries_the_new_subnet"] and facts["file_password_in_plain_text"], facts
    _restart_daemon()
    after = _get()
    facts["subnet_after_restart"] = 2 in _subnet_ids(after)
    facts["hash_after_restart"] = _hash()
    facts["hash_survives_restart"] = facts["hash_after_restart"] == facts["hash_after_set"]
    assert facts["subnet_after_restart"], "the restart lost the subnet config-write persisted"
    assert facts["hash_survives_restart"], (facts["hash_after_set"], facts["hash_after_restart"])


def test_04_a_bad_config_set_leaves_the_old_one_serving(facts):
    """ARM: on a failed config-set "the server retains its current configuration"."""
    cfg = _get()
    h0 = _hash()
    bad = copy.deepcopy(cfg)
    bad["Dhcp4"]["subnet4"][0]["pools"] = [{"pool": "192.0.2.1 - 192.0.2.9"}]  # outside its prefix: Kea refuses
    refused = __kea.kea_command("config-set", arguments=_body(bad))
    facts["bad_config_set_reply"] = _brief(refused)
    facts["hash_unchanged_after_bad_set"] = _hash() == h0
    facts["subnets_unchanged_after_bad_set"] = _subnet_ids(_get()) == _subnet_ids(cfg)
    assert refused.get("result") not in (0, None) and not _transport_failure(refused), refused
    assert facts["hash_unchanged_after_bad_set"] and facts["subnets_unchanged_after_bad_set"], facts
    __real.test_reservation_add_get_del_roundtrip()  # still served
    facts["served_after_bad_set"] = True


def test_05_config_write_outside_the_directory_is_refused(facts):
    """ARM: "As of Kea 2.7.9, the file may only be written to the same directory as the configuration file given at startup with -c"."""
    outside = __kea.kea_command("config-write", arguments={"filename": OUTSIDE})
    facts["config_write_outside_the_directory"] = _brief(outside)
    facts["outside_file_created"] = _exists(OUTSIDE)
    if facts["outside_file_created"]:
        _root("rm", "-f", OUTSIDE)
    # the design may stage a candidate beside the file: is a SIBLING name inside the directory allowed?
    sibling = __kea.kea_command("config-write", arguments={"filename": SIBLING})
    facts["sibling_write"] = _brief(sibling)
    facts["sibling_file_created"] = _exists(SIBLING)
    if sibling.get("result") != 0 and not _STATE.get("dir_open"):
        os.chmod(
            CONF_DIR, 0o777
        )  # a refusal says nothing about Kea's rule while the daemon cannot create files here: ask again with the directory writable
        again = __kea.kea_command("config-write", arguments={"filename": SIBLING})
        facts["sibling_write_directory_writable"] = _brief(again)
        facts["sibling_file_created_directory_writable"] = _exists(SIBLING)
        os.chmod(CONF_DIR, _STATE["dir_mode"])
    if _exists(SIBLING):
        _root("rm", "-f", SIBLING)
    assert outside.get("result") not in (0, None) and not _transport_failure(outside), outside
    assert not facts["outside_file_created"], f"config-write wrote {OUTSIDE}: {_brief(outside)}"


def test_06_the_hash_is_a_concurrency_guard(facts):
    """Kea has no compare-and-set: Jen compares config-hash-get with the digest it read, then sets. This records the window and what a stale set does."""
    h0 = _hash()
    facts["hash_stable_between_reads"] = _hash() == h0
    cfg = _get()
    other = copy.deepcopy(cfg)
    other["Dhcp4"]["valid-lifetime"] = cfg["Dhcp4"]["valid-lifetime"] + 1
    __real._ok(__kea.kea_command("config-set", arguments=_body(other)))  # a second client
    h1 = _hash()
    facts["hash_moved_by_a_second_clients_set"] = h1 != h0
    # a stale writer (it read before the second client's set) is not refused by the daemon: the compare is Jen's
    started = time.monotonic()
    stale = __kea.kea_command("config-set", arguments=_body(cfg))
    facts["a_stale_set_is_accepted_by_the_daemon"] = stale.get("result") == 0
    facts["stale_set_ms"] = round((time.monotonic() - started) * 1000)
    facts["hash_after_stale_set_equals_the_first_read"] = _hash() == h0
    assert facts["hash_stable_between_reads"], "two reads with no change between them gave two digests"
    assert facts["hash_moved_by_a_second_clients_set"], "a second client's config-set did not move the digest"


def test_07_the_investigation_marker_survives_the_round_trip(facts):
    """The marker (INV-001's record) is a user-context on the logger: it must come back from config-get, be written by config-write and keep DEBUG 55."""
    cfg = _get()
    until = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(timespec="seconds")
    marked, code = __ed.set_investigation_logging(copy.deepcopy(cfg), until)
    assert code == "ok"
    __real._ok(__kea.kea_command("config-set", arguments=_body(marked)))
    got = _get()
    logger = next((x for x in got["Dhcp4"].get("loggers", []) if x.get("name") == "kea-dhcp4"), {})
    facts["logger_after_set"] = {k: logger.get(k) for k in ("severity", "debuglevel")}
    facts["marker_in_config_get"] = __ed.investigation_marker(got) is not None
    facts["marker_in_config_get_equals_what_was_set"] = __ed.investigation_marker(got) == __ed.investigation_marker(
        marked
    )
    __real._ok(__kea.kea_command("config-write"))
    facts["marker_in_file_after_write"] = __ed.investigation_marker(_file()) is not None
    assert facts["marker_in_config_get"], "user-context did not survive config-get"
    assert facts["marker_in_file_after_write"], "user-context did not survive config-write"
    assert str(logger.get("severity")).upper() == "DEBUG" and logger.get("debuglevel") == 55, (
        logger
    )  # INV-002's oracle: the daemon runs at what the marker asked


RELOAD_NAME = "kea-reload"


def _second_daemon_digest(facts, live_dhcp4):
    """Q211 fixup 2: Jen's own rendering of the running configuration (canonical JSON, written through the container's shell) is what a daemon started from it
    would run. The first daemon is stopped (the control port is the config's own), a second one is started on a scratch directory holding that file, and its
    `config-hash-get` is read; the first daemon is started again afterward. Recorded, never asserted: the question is whether the digest a `config-set` returned
    is the digest of the same configuration after a start."""
    scratch = tempfile.mkdtemp(prefix="kea-reload-", dir=os.path.dirname(CONF_DIR))
    try:
        os.chmod(scratch, 0o755)
        for name in ("jen-api.user", "jen-api.pw"):
            shutil.copy(os.path.join(CONF_DIR, name), os.path.join(scratch, name))
            os.chmod(os.path.join(scratch, name), 0o644)
        text = config_revisions.canonical({"Dhcp4": live_dhcp4})
        # through the container's shell, as the entry says: the file is written by the image's own `sh`, not by the runner
        __levels._sh(
            "docker", "run", "--rm", "-i", "--entrypoint", "sh", "-v", f"{scratch}:/c", __levels.IMAGE,
            "-c", "cat > /c/kea-dhcp4.conf", input=text,
            check=True,
        )  # fmt: skip
        facts["reload_file_bytes"] = len(text.encode("utf-8"))
        __levels._sh("docker", "stop", "-t", "30", "kea")
        __levels._sh("docker", "rm", "-f", RELOAD_NAME, check=False)
        __levels._sh(
            "docker", "run", "-d", "--name", RELOAD_NAME, "--network", "host",
            "--tmpfs", "/var/run/kea:rw,mode=750",
            "-e", "MARIADB_TLS_DISABLE_PEER_VERIFICATION=1",
            "-v", f"{scratch}:/etc/kea", __levels.IMAGE,
        )  # fmt: skip
        for _ in range(40):
            if _probe_command("version-get", port=8004).get("result") == 0:
                break
            time.sleep(1)
        else:
            facts["reload_second_daemon_started"] = False
            facts["reload_second_daemon_log_tail"] = __levels._sh("docker", "logs", RELOAD_NAME, check=False).stderr[
                -1500:
            ]
            return None
        facts["reload_second_daemon_started"] = True
        reply = _probe_command("config-hash-get", port=8004)
        return _first(reply, "hash")[0]
    finally:
        __levels._sh("docker", "rm", "-f", RELOAD_NAME, check=False)
        shutil.rmtree(scratch, ignore_errors=True)
        __levels._clear_run_dir()
        __levels._sh("docker", "start", "kea")
        __levels._wait_ready()


def test_08_what_config_get_adds_and_accepts(facts):
    """Q212's two remaining markers, as facts (recorded, not asserted - except that the daemon answers after all of it): which keys `config-get` adds to what
    the file carried, whether the `hash` it returns beside `Dhcp4` is accepted when sent back, how long a `config-set` takes, and whether the digest a
    `config-set` returned equals the digest of a daemon STARTED from Jen's rendering of the same configuration."""
    assert ORIGINAL is not None, "test_01 did not record the original configuration"
    authored = json.loads(_STATE["bytes"])[
        "Dhcp4"
    ]  # the file as the job wrote it (a compat file Jen's own builder wrote)
    first = ORIGINAL[0]["Dhcp4"]  # what config-get said of it before any change
    facts["keys_added_top"] = sorted(set(first) - set(authored))
    facts["keys_dropped_top"] = sorted(set(authored) - set(first))
    facts["keys_added_subnet"] = sorted(set(first["subnet4"][0]) - set(authored["subnet4"][0]))
    facts["keys_added_pool"] = sorted(set(first["subnet4"][0]["pools"][0]) - set(authored["subnet4"][0]["pools"][0]))
    facts["valid_lifetime_authored_vs_running"] = [authored.get("valid-lifetime"), first.get("valid-lifetime")]
    live_reply = _get_reply()
    live = live_reply["arguments"]["Dhcp4"]
    facts["hash_beside_dhcp4"] = "hash" in live_reply["arguments"]
    hash_back = __kea.kea_command("config-set", arguments={"Dhcp4": live, "hash": "0" * 64})
    facts["config_set_accepts_hash_key"] = _brief(
        hash_back
    )  # recorded: Jen strips the key before a mutation either way
    facts["hash_after_a_set_that_carried_a_hash_key"] = _hash()
    started = time.monotonic()
    done = __real._ok(__kea.kea_command("config-set", arguments={"Dhcp4": live}))
    facts["config_set_seconds"] = round(time.monotonic() - started, 2)
    set_digest = _first(done, "hash")[0]
    facts["config_set_digest_is_config_hash_get"] = set_digest == _hash()
    try:
        second = _second_daemon_digest(facts, live)
        facts["second_daemon_digest"] = second
        facts["reload_digest_equals_set_digest"] = None if second is None else second == set_digest
    except (
        Exception
    ) as exc:  # recorded, not asserted: a second daemon that cannot start must not redden the rows the entry names
        facts["reload_error"] = f"{type(exc).__name__}: {exc}"[:400]
    assert _hash(), "the daemon does not answer after row 08"


DHCP6_NAME = "kea6-compat"
DHCP6_PORT = 8016


def _jens_modules(monkeypatch):
    """Q212: the product's own transport module against the real daemon. The compat job has no Jen database, so the revision store and the stored probe are the in-memory stand-ins the unit tests use, and
    the investigation questions (which read Jen's settings) answer "nothing owed"."""
    from jen.services import kea_api_config as api
    from tests import _kea_api_world as world

    store = world.install_store(monkeypatch)
    world.install_probes(monkeypatch)
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")
    monkeypatch.setattr("jen.services.investigation_logging.restore_window", lambda server, now=None: "")
    return api, store


def _compat_server():
    return {
        "id": 1,
        "name": "kea-compat",
        "api_url": os.environ.get("KEA_COMPAT_URL", ""),
        "api_user": os.environ.get("KEA_COMPAT_USER", ""),
        "api_pass": os.environ.get("KEA_COMPAT_PASS", ""),
    }


def test_09_jens_own_transport_round_trip(facts, monkeypatch):
    """Q212 (BB1): `kea_api_config.apply` against the REAL daemon with the product's own `add_subnet4`, then `revert`, then the pending record: Jen "dies" between `config-set` and `config-write` and the next
    read settles the change by content."""
    api, store = _jens_modules(monkeypatch)
    server = _compat_server()
    cfg, digest = api.read(server, "dhcp4", capture=False)
    assert cfg is not None and digest
    block = {
        "id": 3,
        "subnet": "10.97.0.0/24",
        "pools": [{"pool": "10.97.0.100 - 10.97.0.200"}],
        "relay": {"ip-addresses": ["10.97.0.1"]},
    }
    candidate, code = __ed.add_subnet4(copy.deepcopy(cfg), block)
    assert code == "ok"
    started = time.monotonic()
    result = api.apply(server, "dhcp4", candidate, digest, "compat: add subnet 3", before_cfg=cfg)
    facts["transport_apply"] = {
        "code": result.get("code"),
        "detail": (result.get("detail") or "")[:200],
        "seconds": round(time.monotonic() - started, 2),
    }
    assert result["ok"], result
    assert 3 in _subnet_ids(_get()) and 3 in _subnet_ids(_file())  # live AND persisted
    facts["transport_apply_digest_is_config_hash_get"] = result["sha256"] == _hash()
    rows = [(r["source"], r["hash_kind"]) for r in store.rows]
    facts["transport_revision_rows"] = rows
    # the way back is the same transport
    back = api.revert(server, "dhcp4", cfg, result["sha256"], "compat: rollback", before_cfg=candidate)
    facts["transport_revert"] = {"code": back.get("code"), "detail": (back.get("detail") or "")[:200]}
    assert back["ok"], back
    assert 3 not in _subnet_ids(_get()) and 3 not in _subnet_ids(_file())
    # Jen dies between config-set and config-write: a pending row exists, the daemon runs the change, the file does not carry it
    now_cfg, now_digest = api.read(server, "dhcp4", capture=False)
    store.record(1, "dhcp4", candidate, now_digest, "compat: interrupted", hash_kind="kea", source="pending")
    __real._ok(__kea.kea_command("config-set", arguments=_body(candidate)))
    assert 3 in _subnet_ids(_get()) and 3 not in _subnet_ids(_file())
    notes = []
    settled_cfg, settled_digest = api.read(server, "dhcp4", capture=False, notes=notes)
    facts["transport_pending_notes"] = notes
    facts["transport_pending_finished_the_write"] = 3 in _subnet_ids(_file())
    facts["transport_pending_row_after"] = [
        (r["source"], r["hash_kind"]) for r in store.rows if r["id"] == store.rows[-1]["id"]
    ]
    assert notes and "finished" in notes[0], notes
    assert 3 in _subnet_ids(_file()) and store.pending(1, "dhcp4") is None
    # put it back for the rows that follow
    done = api.revert(server, "dhcp4", cfg, settled_digest, "compat: rollback", before_cfg=settled_cfg)
    assert done["ok"], done


def _dhcp6_config():
    base = kea_config.build(http_port=DHCP6_PORT)["Dhcp4"]
    return {
        "Dhcp6": {
            "interfaces-config": {"interfaces": ["*"], "service-sockets-require-all": False},
            "control-sockets": copy.deepcopy(base["control-sockets"]),
            "lease-database": {"type": "memfile", "persist": False},
            "valid-lifetime": 4000,
            "subnet6": [
                {"id": 1, "subnet": "2001:db8:1::/64", "pools": [{"pool": "2001:db8:1::100 - 2001:db8:1::200"}]}
            ],
            "loggers": [{"name": "kea-dhcp6", "output-options": [{"output": "stdout"}], "severity": "INFO"}],
        }
    }


def test_10_the_same_over_dhcp6(facts, monkeypatch):
    """Q212 (BB1 f): the same sequence for the v6 daemon the ISC image carries. A daemon that cannot be started here is a recorded fact and a skip - dhcp6 then joins D2 on the file path in this beta."""
    api, store = _jens_modules(monkeypatch)
    probe_binary = __levels._sh(
        "docker", "run", "--rm", "--entrypoint", "sh", __levels.IMAGE, "-c", "command -v kea-dhcp6", check=False
    )
    facts["dhcp6_binary_in_image"] = probe_binary.returncode == 0
    if probe_binary.returncode != 0:
        # run 41703269176: ISC's kea-dhcp4 image has no kea-dhcp6 (`exec: "kea-dhcp6": executable file not found`), so this row cannot be built against a real daemon
        facts["dhcp6_started"] = False
        pytest.skip("ISC's dhcp4 image carries no kea-dhcp6: dhcp6 joins D2 on the file path in this beta")
    scratch = tempfile.mkdtemp(prefix="kea6-", dir=os.path.dirname(CONF_DIR))
    try:
        os.chmod(scratch, 0o755)
        conf = os.path.join(scratch, "kea-dhcp6.conf")
        with open(conf, "w") as fh:
            json.dump(_dhcp6_config(), fh, indent=2)
        os.chmod(conf, 0o644)
        for name in ("jen-api.user", "jen-api.pw"):
            shutil.copy(os.path.join(CONF_DIR, name), os.path.join(scratch, name))
            os.chmod(os.path.join(scratch, name), 0o644)
        __levels._sh("docker", "rm", "-f", DHCP6_NAME, check=False)
        started = __levels._sh(
            "docker", "run", "-d", "--name", DHCP6_NAME, "--network", "host", "--tmpfs", "/var/run/kea:rw,mode=750",
            "-v", f"{scratch}:/etc/kea", "--entrypoint", "kea-dhcp6", __levels.IMAGE, "-c", "/etc/kea/kea-dhcp6.conf",
            check=False,
        )  # fmt: skip
        facts["dhcp6_container_started"] = started.returncode == 0
        for _ in range(40):
            if _probe_command("version-get", port=DHCP6_PORT).get("result") == 0:
                break
            time.sleep(1)
        else:
            facts["dhcp6_started"] = False
            facts["dhcp6_log_tail"] = (
                __levels._sh("docker", "logs", DHCP6_NAME, check=False).stderr[-1500:] + started.stderr[-300:]
            )
            pytest.skip("kea-dhcp6 did not start in this image: dhcp6 joins D2 on the file path in this beta")
        facts["dhcp6_started"] = True
        server = {
            "id": 1,
            "name": "kea6-compat",
            "api_url": "http://127.0.0.1:9/",
            "api6_url": f"http://127.0.0.1:{DHCP6_PORT}/",
            "api6_user": os.environ.get("KEA_COMPAT_USER", ""),
            "api6_pass": os.environ.get("KEA_COMPAT_PASS", ""),
        }
        cfg, digest = api.read(server, "dhcp6", capture=False)
        assert cfg is not None and digest, "config-get over dhcp6 gave no configuration with a digest"
        candidate = copy.deepcopy(cfg)
        candidate["Dhcp6"]["valid-lifetime"] = 4100
        result = api.apply(server, "dhcp6", candidate, digest, "compat: dhcp6 lifetime", before_cfg=cfg)
        facts["dhcp6_apply"] = {"code": result.get("code"), "detail": (result.get("detail") or "")[:200]}
        assert result["ok"], result
        live = _first(__real._ok(__kea.kea_command("config-get", service="dhcp6", server=server)), "hash")[0]
        facts["dhcp6_apply_digest_is_the_daemons"] = result["sha256"] == live
        with open(conf) as fh:
            persisted = json.load(fh)
        facts["dhcp6_file_carries_the_change"] = persisted["Dhcp6"].get("valid-lifetime") == 4100
        assert facts["dhcp6_file_carries_the_change"], "config-write did not persist the dhcp6 change"
        back = api.revert(server, "dhcp6", cfg, result["sha256"], "compat: rollback", before_cfg=candidate)
        assert back["ok"], back
    finally:
        __levels._sh("docker", "rm", "-f", DHCP6_NAME, check=False)
        shutil.rmtree(scratch, ignore_errors=True)


def test_90_restore_puts_the_original_back(facts):
    """The configuration the job started with goes back into the daemon, into the file, and then the original file's own bytes replace it."""
    assert ORIGINAL is not None, "test_01 did not record the original configuration"
    cfg0, h0 = ORIGINAL
    __real._ok(__kea.kea_command("config-set", arguments=_body(cfg0)))
    __real._ok(__kea.kea_command("config-write"))
    now = _get()
    same = config_revisions.canonical(_body(now)) == config_revisions.canonical(_body(cfg0))
    facts["restored_configuration_equals_the_original"] = same
    facts["hash_after_restore_equals_the_original"] = _hash() == h0
    _put_the_original_file_back()
    with open(CONF_PATH, "rb") as fh:
        facts["original_file_restored_byte_for_byte"] = (
            hashlib.sha256(fh.read()).hexdigest() == facts["original_file_sha256"]
        )
    assert same, "the restored configuration differs from the original"
    assert facts["original_file_restored_byte_for_byte"]


# ── an extra the entry did not list: the same question for a daemon that is NOT root ─────────────────────────────────────

PROBE_NAME = "kea-nonroot"
PROBE_PORT = 8014
ACCOUNT = "100:101"  # the `kea` account ISC's image creates and owns the daemon binary with (binary-<version>.json)


def _probe_command(command, arguments=None, port=PROBE_PORT):
    import requests

    payload = {"command": command, **({"arguments": arguments} if arguments else {})}
    auth = (os.environ.get("KEA_COMPAT_USER", ""), os.environ.get("KEA_COMPAT_PASS", ""))
    try:
        data = requests.post(f"http://127.0.0.1:{port}/", json=payload, auth=auth, timeout=10).json()
    except (requests.RequestException, ValueError) as exc:
        return {"result": -1, "text": f"transport: {type(exc).__name__}"}
    return data[0] if isinstance(data, list) else data


def _scratch_stat(scratch, name="kea-dhcp4.conf"):
    done = __levels._sh(
        "docker", "run", "--rm", "--entrypoint", "stat", "-v", f"{scratch}:/c", __levels.IMAGE,
        "-c", "%u|%g|%a|%i|%s", f"/c/{name}",
        check=False,
    )  # fmt: skip
    parts = done.stdout.strip().split("|")
    if len(parts) != 5:
        return {"error": (done.stderr or done.stdout).strip()[:200]}
    return dict(zip(("uid", "gid", "mode", "inode", "size"), parts, strict=True))


def _grant_the_file(scratch):
    """The grant Q212's helper op would make: the daemon's group on the FILE and group-write - never the directory, never other-write."""
    steps = []
    for tool, arg in (("chgrp", "101"), ("chmod", "g+w")):
        done = __levels._sh(
            "docker", "run", "--rm", "--entrypoint", tool, "-v", f"{scratch}:/c", __levels.IMAGE,
            arg, "/c/kea-dhcp4.conf",
            check=False,
        )  # fmt: skip
        steps.append(done.returncode)
    return steps == [0, 0]


def _nonroot_daemon(facts, scratch):
    os.chmod(scratch, 0o755)
    conf = os.path.join(scratch, "kea-dhcp4.conf")
    with open(conf, "w") as fh:
        json.dump(kea_config.build(http_port=PROBE_PORT), fh, indent=2)
    os.chmod(conf, 0o644)
    for name in (
        "jen-api.user",
        "jen-api.pw",
    ):  # the control socket's basic-auth files, read from the daemon's /etc/kea
        shutil.copy(os.path.join(CONF_DIR, name), os.path.join(scratch, name))
        os.chmod(os.path.join(scratch, name), 0o644)
    facts["nonroot_account"] = ACCOUNT
    facts["nonroot_file_before"] = _scratch_stat(scratch)
    __levels._sh("docker", "rm", "-f", PROBE_NAME, check=False)
    __levels._sh(
        "docker", "run", "-d", "--name", PROBE_NAME, "--network", "host", "--user", ACCOUNT,
        "--tmpfs", "/var/run/kea:rw,uid=100,gid=101,mode=750",
        "-e", "MARIADB_TLS_DISABLE_PEER_VERIFICATION=1",
        "-v", f"{scratch}:/etc/kea", __levels.IMAGE,
    )  # fmt: skip
    for _ in range(40):
        if _probe_command("version-get").get("result") == 0:
            break
        time.sleep(1)
    else:
        facts["nonroot_started"] = False
        facts["nonroot_log_tail"] = __levels._sh("docker", "logs", PROBE_NAME, check=False).stderr[-1500:]
        return
    facts["nonroot_started"] = True
    facts["nonroot_runs_as_uid"] = __levels._sh("docker", "exec", PROBE_NAME, "id", "-u", check=False).stdout.strip()
    first = _probe_command("config-write")
    facts["nonroot_config_write_as_shipped"] = _brief(first)
    if first.get("result") != 0:
        facts["nonroot_grant_made"] = _grant_the_file(scratch)
        facts["nonroot_file_after_grant"] = _scratch_stat(scratch)
        second = _probe_command("config-write")
        facts["nonroot_config_write_after_grant"] = _brief(second)
        facts["nonroot_file_after_write"] = _scratch_stat(scratch)
        facts["nonroot_written_in_place"] = facts["nonroot_file_after_grant"].get("inode") == facts[
            "nonroot_file_after_write"
        ].get("inode")
        if second.get("result") != 0:
            os.chmod(scratch, 0o777)
            facts["nonroot_config_write_after_grant_and_an_open_directory"] = _brief(_probe_command("config-write"))
            os.chmod(scratch, 0o755)
    sibling = _probe_command("config-write", {"filename": SIBLING})
    facts["nonroot_sibling_write"] = _brief(sibling)


def test_91_an_unprivileged_daemon_needs_its_file_writable_and_nothing_more(facts):
    """EXTRA - not one of the entry's eight rows, RECORDED and NEVER ASSERTED. ISC's images run the daemon as root, so rows 03 and 05 cannot say what a package
    install (the daemon is an unprivileged account, the file belongs to root) needs. This boots a second daemon on a scratch directory as the image's own `kea`
    account, sends config-write as the file stands, then with the grant the helper op would make (the daemon's group + group-write on the FILE only), and
    records the daemon's answers, whether it wrote the file in place, and whether a sibling name is allowed. A probe that cannot start records why."""
    scratch = tempfile.mkdtemp(prefix="kea-nonroot-", dir=os.path.dirname(CONF_DIR))
    try:
        _nonroot_daemon(facts, scratch)
    except (
        Exception
    ) as exc:  # recorded, not asserted: an extra that cannot start must not redden the rows the entry names
        facts["nonroot_error"] = f"{type(exc).__name__}: {exc}"[:400]
    finally:
        __levels._sh("docker", "rm", "-f", PROBE_NAME, check=False)
        shutil.rmtree(scratch, ignore_errors=True)
