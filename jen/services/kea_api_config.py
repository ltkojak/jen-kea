"""
jen/services/kea_api_config.py
──────────────────────────────
Q212 (7.0.0-beta.1) - a Kea server's configuration changed over the daemon's OWN API: `config-get`, `config-hash-get`, `config-test`, `config-set`, `config-write`.
No SSH, no restart. This is the ONE module that sends `config-set`, `config-write` or `config-hash-get` (a source test pins it, `tests/test_kea_host.py`), it posts only through
`jen.services.kea.kea_command` (so `credentials.resolve` chooses every credential and nothing here can name a host), and it imports nothing that speaks SSH.

Every function answers the HostResult shape the file path already answers (`kea_host._from_helper_test`): `{"ok", "code", "detail", "via": "api", "sha256"?}` - so the
change set, the restore and the import dispatch on the transport and read nothing new. `code` is one of:

    ok | conflict | testerror | guard | set-failed | write-failed | unverified | unknown | noanswer | investigation-on | nokey | noservice

`needs_hands` (a bool, beside the code) is set when the daemon may be in a state Jen cannot name: the line a person reads says both digests.

What this module knows of Kea, from the rows of `tests/kea_compat/test_config_write.py` (docs/ARCHITECTURE.md 3.17):
  - `config-get` is not redacted (database passwords in plain text): a reply is NEVER logged, nor is a `config-set` payload; this module logs command names and digests only.
  - the digest is under `arguments.hash` on `config-get`, `config-set` and `config-hash-get`; Jen cannot compute it, so it is only ever compared with another digest the daemon gave.
  - Kea has NO compare-and-set (a stale `config-set` is accepted): `apply` compares first, and the daemon's own `config-get` afterward is the record.
  - a refused `config-set` leaves the old configuration serving - but ISC says the server can also stop; so a refusal is followed by a question, never assumed.
  - `config-write` (no filename) persists what runs, in place; a change a restart would lose did not stand.
"""

from __future__ import annotations

import copy
import json
import logging

from jen.services import config_revisions as _rev
from jen.services import kea as _kea
from jen.services import kea_host as _host

logger = logging.getLogger(__name__)

# dhcp4 only in 7.0.0-beta.1. ISC's own dhcp4 image has no kea-dhcp6 binary, so Q211's row 10 ("the same over dhcp6") could not be built against a real daemon (run 41703269176: `exec:
# "kea-dhcp6": executable file not found`); dhcp6 joins D2 on the file path in this beta, and `kea_changeset._transport` says so for every service this module does not serve.
SERVICE_KEY = {"dhcp4": "Dhcp4"}

# Kea cuts a control connection at 10 s (not configurable); one second more than that is the whole wait, and a test narrows it.
COMMAND_TIMEOUT = 15
# `config-write` writes what runs and is idempotent: it is re-sent when no answer came, never when Kea answered.
WRITE_ATTEMPTS = 3

PENDING = "pending"

TRANSPORTS = ("api", "file", "off")


def declared_transport(server: dict) -> str:
    """The server's `config_transport` setting, in ONE place (the change set, the file path's choke point and the capability badge all read it here): `api | file | off`. ABSENT (or blank) is exactly
    today's behavior - `file` when the server has an SSH host, `off` when it has none (an API-only server was never a write target and stays one until its operator switches it). A value that is not
    one of the three, spelled exactly, reads as `off`: `API`, `yes` and `ssh` are mistakes, and a mistake never grants a write path."""
    raw = server.get("config_transport")
    if raw is None or str(raw).strip() == "":
        return "file" if server.get("ssh_host") else "off"
    value = str(raw).strip()
    return value if value in TRANSPORTS else "off"


def _name(server: dict) -> str:
    return server.get("name") or server.get("ssh_host") or f"Server {server.get('id')}"


def _result(ok: bool, code: str, detail: str = "", sha256: str | None = None, **extra) -> dict:
    out = {"ok": ok, "code": code, "via": "api"}
    if detail:
        out["detail"] = detail
    if sha256:
        out["sha256"] = sha256
    out.update(extra)
    return out


def _cmd(server: dict, service: str, command: str, arguments: dict | None = None, timeout=None) -> dict:
    """The one sender: `kea_command` with this module's wait. Logs the command's name and its result code, never an argument or a reply."""
    reply = _kea.kea_command(command, service, arguments, server=server, timeout=timeout or COMMAND_TIMEOUT)
    logger.debug("kea_api_config: %s on %s -> result %s", command, _name(server), reply.get("result"))
    return reply


def _answered(reply: dict) -> bool:
    """Kea sent this reply (a refusal included); False for one Jen fabricated for a transport fault - read by the `transport` key, never by the sentence."""
    return "transport" not in reply


def _ok(reply: dict) -> bool:
    return _answered(reply) and reply.get("result") == 0


def _text(reply: dict) -> str:
    return str(reply.get("text") or "").strip()[:300]


def _digest(reply: dict) -> str | None:
    value = (reply.get("arguments") or {}).get("hash") if isinstance(reply.get("arguments"), dict) else None
    return value if isinstance(value, str) and value else None


def _section(cfg: dict | None, service: str) -> dict:
    return (cfg or {}).get(SERVICE_KEY.get(service, ""), {}) or {}


# Kea renders some singular keys of a file as lists in `config-get` (docs/ARCHITECTURE.md 3.17: `hosts-database` comes back as `hosts-databases`, `control-socket` as `control-sockets`). The table's SOURCE is a
# compat row (`tests/kea_compat/test_config_write.py::test_11_what_config_get_renames`, Q216 BF4): a row and this table that disagree are settled by the row, and the table is edited.
RENAMED_KEYS = {"hosts-database": "hosts-databases", "control-socket": "control-sockets"}

# The ONE kind of string Kea re-renders: a pool "a - b" is reported as "a-b" (compat run 41712142556). The spacing rule is for a string UNDER one of these keys and nowhere else; a path the compat row
# reports that is not a `pool` is a new entry here, named, never a wider rule (Q216 BF5).
SPACE_INSENSITIVE_KEYS = frozenset({"pool"})

# Keys of `interfaces-config` that `config-get` OMITS when they hold their default (compat row 11, Kea 3.0.5, 3.2.1 and 3.3.3: a file carrying `service-sockets-require-all: false` and
# `service-sockets-max-retries: 0` comes back without them). A file that carries one at its default is carried by a daemon that does not report it; any other value is a difference.
OMITTED_AT_DEFAULT = {"service-sockets-require-all": False, "service-sockets-max-retries": 0}


_MISSING = object()


def _walk(running: object, candidate: object, under: str | None = None, path: str = ""):
    """THE one walk (Q217 BG3 b): `None` when the configuration the daemon RUNS carries everything the candidate said, else `(path, candidate_leaf, running_leaf)` for the FIRST thing it does not -
    the path built as the walk descends (`Dhcp4.subnet4[2].pools[0].pool`; the caller prefixes the section). `config-get` returns the daemon's configuration with Kea's own defaults written out (45 keys
    at the top of `Dhcp4`, 13 per subnet and one per pool - docs/ARCHITECTURE.md 3.17, row 08), so a candidate Jen built is a SUBSET of what the daemon reports after it takes it: every key present with
    an equal value, lists the same length and elementwise the same. Equality would never hold for a subnet Jen just added. Used with a check of the BEFORE state FIRST, never alone: a candidate that only
    deletes is a subset of the configuration it came from. `under` is the key a value sits below: a candidate key Kea renames (`RENAMED_KEYS`) is carried by the list that took its place, and a string
    is compared without its spaces only under a `pool` key."""
    if isinstance(candidate, dict):
        if not isinstance(running, dict):
            return (path, candidate, running)
        for k, v in candidate.items():
            here = f"{path}.{k}" if path else k
            if k in running:
                found = _walk(running[k], v, k, here)
                if found is not None:
                    return found
                continue
            renamed = running.get(RENAMED_KEYS.get(k, ""))
            if isinstance(renamed, list) and len(renamed) == 1:
                found = _walk(
                    renamed[0], v, k, here
                )  # (the list Kea reports in the key's place: descend, so a difference is named at its own path, never as the whole object)
                if found is None:
                    continue
                return found
            if (
                under == "interfaces-config"
                and k in OMITTED_AT_DEFAULT
                and v == OMITTED_AT_DEFAULT[k]
                and type(v) is type(OMITTED_AT_DEFAULT[k])
            ):
                continue
            return (here, v, _MISSING)
        return None
    if isinstance(candidate, list):
        if not isinstance(running, list):
            return (path, candidate, running)
        if len(running) != len(candidate):
            return (path, candidate, running)
        for i, (r, c) in enumerate(zip(running, candidate, strict=True)):
            found = _walk(r, c, under, f"{path}[{i}]")
            if found is not None:
                return found
        return None
    if isinstance(running, str) and isinstance(candidate, str):
        if under in SPACE_INSENSITIVE_KEYS:
            same = running.replace(" ", "") == candidate.replace(" ", "")
        else:
            same = running == candidate
        return None if same else (path, candidate, running)
    return None if running == candidate else (path, candidate, running)


def _carries(running: object, candidate: object, under: str | None = None) -> bool:
    """Does the configuration the daemon RUNS carry everything the candidate said? `first_difference` answers the same question with the path; this is its negation, so they cannot disagree."""
    return _walk(running, candidate, under) is None


def first_difference(running: object, candidate: object, under: str | None = None, path: str = "") -> str:
    """The FIRST path of `candidate` that `running` does not carry (`""` when it is carried): the one walk, as a path."""
    found = _walk(running, candidate, under, path)
    return "" if found is None else (found[0] or "/")


def file_in_daemon(file_cfg: dict | None, live_cfg: dict | None, service: str) -> bool:
    """Is everything the FILE says carried by what the daemon runs? A file Jen authored (or an older Kea-written one) is a subset of the daemon's configuration with its defaults written out, and
    nothing in it would be lost by a `config-write`; a file with a subnet or a value the daemon does not run is a hand edit and is not. (fix row 7: equality never held for an authored file.)"""
    return _carries(_section(live_cfg, service), _section(file_cfg, service))


_SECRET_WORDS = ("password", "secret", "token")


def _secret_path(path: str) -> bool:
    """Is any segment of `path` a name a value must not be printed under? (`hosts-databases[0].password` is on a path Jen prints.)"""
    for segment in path.replace("[", ".").replace("]", "").split("."):
        low = segment.lower()
        if any(w in low for w in _SECRET_WORDS) or low == "key" or low.endswith(("-key", "_key")):
            return True
    return False


def _leaf(value: object) -> str:
    if value is _MISSING:
        return "nothing"
    if isinstance(value, dict):
        return f"an object with {len(value)} keys"  # (a container is never printed: it may hold a secret the path does not name)
    if isinstance(value, list):
        return f"a list of {len(value)}"
    text = json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= 60 else text[:59] + "…"


def difference_text(file_cfg: dict | None, live_cfg: dict | None, service: str) -> str:
    """Where the file and the daemon differ, in a sentence an operator can act on: `at <path>: the file says <a>, the daemon <b>` (each leaf cut to 60 characters, and the values replaced by an
    ellipsis when any segment of the path names a secret) - or `""` when the file is carried. The path is prefixed with the section (`Dhcp4.`)."""
    found = _walk(_section(live_cfg, service), _section(file_cfg, service), None, SERVICE_KEY.get(service, service))
    if found is None:
        return ""
    path, mine, theirs = found
    if _secret_path(path):
        return f"at {path}: the file and the daemon differ (the values are not shown)"
    return f"at {path}: the file says {_leaf(mine)}, the daemon {_leaf(theirs)}"


def same_modulo_defaults(a_cfg: dict | None, b_cfg: dict | None, service: str) -> bool:
    """Either configuration carries the other: the verification of Kea's own `config-write` (a rendering of what runs, defaults included or not)."""
    return _carries(_section(a_cfg, service), _section(b_cfg, service)) or _carries(
        _section(b_cfg, service), _section(a_cfg, service)
    )


def _canonical(cfg: dict | None, service: str) -> str:
    """The service's own section in the stored canonical form (key order and Kea's formatting do not matter; the `hash` beside it is never part of it)."""
    return _rev.canonical({SERVICE_KEY[service]: _section(cfg, service)})


def _body(cfg: dict, service: str) -> dict:
    """What `config-set` / `config-test` take: the service's section only."""
    key = SERVICE_KEY[service]
    return {key: cfg[key]}


def _split(reply: dict, service: str) -> tuple[dict | None, str | None]:
    """(cfg, digest) of a `config-get` reply that Kea answered with result 0 - the service's own key REQUIRED and the digest stripped out of the cfg - or (None, None)."""
    key = SERVICE_KEY[service]
    args = reply.get("arguments") if isinstance(reply.get("arguments"), dict) else {}
    if not _ok(reply) or key not in args:
        return None, None
    return {k: v for k, v in args.items() if k != "hash"}, _digest(reply)


def _get(server: dict, service: str, timeout=None) -> tuple[dict | None, str | None, str]:
    """`config-get`: (cfg, digest, "") or (None, None, <why>). A reply without a digest is a FAILED read - never `config-hash-get` as a substitute (the two are not the same instant)."""
    if service not in SERVICE_KEY:
        return None, None, f"{service} is not configured over the API"
    reply = _cmd(server, service, "config-get", timeout=timeout)
    if not _answered(reply):
        return None, None, _text(reply) or f"{_name(server)} did not answer"
    if reply.get("result") != 0:
        return None, None, _text(reply) or f"{_name(server)} refused config-get"
    cfg, digest = _split(reply, service)
    if cfg is None:
        return None, None, f"{_name(server)} answered config-get without a {SERVICE_KEY[service]} section (nokey)"
    if not digest:
        return None, None, f"{_name(server)} answered config-get without a digest"
    return cfg, digest, ""


def hash(server: dict, service: str = "dhcp4", timeout=None) -> str | None:
    """`config-hash-get`: the daemon's current digest, or None when it did not answer one."""
    if service not in SERVICE_KEY:
        return None
    reply = _cmd(server, service, "config-hash-get", timeout=timeout)
    return _digest(reply) if _ok(reply) else None


def _capture(server: dict, service: str, cfg: dict, digest: str) -> None:
    """The file path's own capture rule, for `kea` rows (Q212, BB1 e): no `kea` row yet -> a baseline; a digest unlike the latest `kea` row's -> `external` (a hand `config-set` on the daemon
    shows in Config history the way a hand edit of the file does). A `raw` row is never compared with a `kea` digest, and a PENDING row is not a baseline."""
    sid = server.get("id")
    if sid is None:
        return
    try:
        last = _rev.latest_of_kind(sid, service, "kea")
        if last is not None and last.get("source") == PENDING:
            return
        if last is None:
            _rev.record(
                sid,
                service,
                cfg,
                digest,
                "initial baseline - first config Jen read from the daemon",
                hash_kind="kea",
                source="baseline",
            )
        elif last.get("sha256") and last["sha256"] != digest:
            _rev.record(sid, service, cfg, digest, "changed outside Jen", hash_kind="kea", source="external")
    except Exception as e:  # a failed history write never fails the read it rode on
        logger.warning("kea_api_config: capture failed for server %s/%s: %s", sid, service, type(e).__name__)


def read(
    server: dict,
    service: str,
    *,
    errors: list | None = None,
    timeout: int | None = None,
    capture: bool = True,
    helper_only: bool = False,  # accepted so the dispatch in `kea_host.read_config` is kwarg-compatible; an API read has no helper
    notes: list | None = None,
) -> tuple[dict | None, str | None]:
    """`(cfg, digest)` from the daemon's own `config-get`, or `(None, None)` with a sentence appended to `errors`. The digest comes from the reply, beside the service's section, and is
    STRIPPED from `cfg` before anything reads it.

    A pending change of Jen's own (BB9 c: Jen died between `config-set` and the verify) is CLASSIFIED by content on this read and the line it earns goes to `notes`; a read never settles it (Q216,
    AA19: a read that reconciles is a write path - it sent `config-write` and changed the store from a GET, outside the change lock). Settlement is `settle_pending`, under the lock."""
    cfg, digest, why = _get(server, service, timeout)
    if cfg is None:
        if errors is not None:
            errors.append(why)
        return None, None
    try:
        _classify_pending(server, service, cfg, digest, notes)
    except _rev.RevisionStoreUnreadable:
        if notes is not None:
            notes.append(unreadable_sentence(server))
    if capture:
        _capture(server, service, cfg, digest)
    return cfg, digest


def write_file(server: dict, service: str = "dhcp4") -> dict:
    """`config-write` of what runs, no filename - the switch's and the probe's own call. `ok`, `write-failed` (Kea's own words) or `noanswer`."""
    if service not in SERVICE_KEY:
        return _result(False, "noservice", f"{service} is not configured over the API")
    reply = _cmd(server, service, "config-write")
    if _ok(reply):
        return _result(True, "ok")
    if not _answered(reply):
        return _result(False, "noanswer", _text(reply))
    return _result(False, "write-failed", _text(reply) or "config-write was refused")


def test(server: dict, service: str, cfg: dict) -> dict:
    """`config-test` of a candidate (advisory: Kea's own validation before anything is set). `ok`, `testerror` (Kea's words) or `noanswer`."""
    if service not in SERVICE_KEY:
        return _result(False, "noservice", f"{service} is not configured over the API")
    reply = _cmd(server, service, "config-test", _body(cfg, service))
    if _ok(reply):
        return _result(True, "ok")
    if not _answered(reply):
        return _result(False, "noanswer", _text(reply))
    return _result(False, "testerror", _text(reply) or "config-test refused the configuration")


# ── the API-only guard (step 2) ───────────────────────────────────────────────────────────────────────────────────────


GUARD_SENTENCE = (
    "a change to the control socket, a hook library or its parameters, or TLS material goes through the file path"
)


def _hooks(sec: dict) -> list:
    """The `hooks-libraries` list AS VALUES - each entry's `library` and its `parameters`, in order (Q216 AA4): an HA peer's address or a lease_cmds setting is a hook's `parameters`, and a restore
    of a revision from before such a change would otherwise be sent over the API with the paths and the order unchanged."""
    return list(sec.get("hooks-libraries") or [])


def _api_only_guard(service: str, running: dict | None, candidate: dict) -> str:
    """The candidate's `control-sockets`, `hooks-libraries` (each entry as a value: the library AND its parameters, in order) and every TLS path Jen's own certificate files appear at must equal the running configuration's: a change to
    the socket the command arrives on is never sent over that socket, and a hook library or a certificate is host material the file path checks (`tlsmissing`) and this path cannot. This is what
    makes the direct-socket callers, the restore and the import safe over the API without each writer knowing the rule."""
    from jen.services import kea_authoring as _auth
    from jen.services import kea_tls as _tls

    before, after = _section(running, service), _section(candidate, service)
    for key in ("control-sockets", "control-socket"):
        if (before.get(key) or None) != (after.get(key) or None):
            return GUARD_SENTENCE
    if _hooks(before) != _hooks(after):
        return GUARD_SENTENCE
    tls = _tls.remote_tls_paths(service)
    if sorted(_auth.referenced_tls_paths(running or {}, tls)) != sorted(_auth.referenced_tls_paths(candidate, tls)):
        return GUARD_SENTENCE
    return ""


# ── the pending record (step 3) and its reconciliation ────────────────────────────────────────────────────────────────────


PENDING_SETTLE_SECONDS = 120  # an apply finishes inside its commands' waits; a pending row younger than this belongs to one in flight and no reader may settle it (fix row 3)


def _row_age_seconds(row: dict) -> float:
    """Seconds since a revision row was written (UTC); 0-age cannot be told apart from "unknown", so an unreadable stamp counts as old."""
    from datetime import datetime, timezone

    stamp = row.get("created_at")
    try:
        when = stamp if isinstance(stamp, datetime) else datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return PENDING_SETTLE_SECONDS + 1
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds()


def unreadable_sentence(server: dict) -> str:
    return f"the record of an earlier change on {_name(server)} cannot be read; nothing is sent until it can"


def record_unreadable(server: dict, service: str = "dhcp4") -> str:
    """A refusal sentence when the record of pending changes cannot be READ, else "" (Q216, AA11): `None` from the store means nothing is pending, and a store that could not be asked is not that."""
    sid = server.get("id")
    if sid is None or service not in SERVICE_KEY:
        return ""
    try:
        _rev.pending(sid, service)
    except _rev.RevisionStoreUnreadable:
        return unreadable_sentence(server)
    return ""


def _classify_pending(server: dict, service: str, cfg: dict, digest: str, notes: list | None) -> None:
    """What a pending row would be settled as, said in a line - and nothing else: no command is sent, no row changes (a read is not a write path, Q216 AA19). Raises `RevisionStoreUnreadable`."""
    sid = server.get("id")
    if sid is None or service not in SERVICE_KEY or notes is None:
        return
    row = _rev.pending(sid, service)
    if row is None:
        return
    try:
        candidate = json.loads(row["config"])
    except (TypeError, ValueError):
        return
    at = str(row.get("created_at") or "an earlier time")
    if _row_age_seconds(row) < PENDING_SETTLE_SECONDS:
        notes.append(f"a change of {at} is in progress; it is not settled until it has had {PENDING_SETTLE_SECONDS} s")
    elif row.get("sha256") and digest == row["sha256"]:
        notes.append(
            f"a change of {at} never reached the daemon; its record is removed at the next change or when you settle it"
        )
    elif _carries(_section(cfg, service), _section(candidate, service)):
        notes.append(
            f"a change of {at} is live and its file write is not proved yet; the next change finishes it, or you can settle it from the server's card"
        )
    else:
        notes.append(
            f"a change of {at} is unresolved: the daemon runs {digest}, which is neither the state before it ({row.get('sha256') or 'unknown'}) nor the change; resolve it from Config history"
        )


def settle_pending(server: dict, service: str = "dhcp4") -> list[str]:
    """Settle a pending row by content NOW - the two places that may (Q216 AA19), both under `kea_changeset.change_lock`: this, called by the card's "settle" route, and `pending_block`, asked by the
    Plan of a change set and by `apply`. The lines say what happened."""
    notes: list[str] = []
    cfg, digest, why = _get(server, service)
    if cfg is None:
        return [f"{_name(server)} did not answer ({why}); nothing was settled"]
    try:
        _reconcile_pending(server, service, cfg, digest, notes)
    except _rev.RevisionStoreUnreadable:
        notes.append(unreadable_sentence(server))
    return notes or ["there is no pending change to settle"]


def _reconcile_pending(server: dict, service: str, cfg: dict, digest: str, notes: list | None) -> tuple[dict, str]:
    """If Jen died between `config-set` and the verify, the next change finds a `pending` row and settles it by CONTENT (Jen cannot compute Kea's digest, so a digest alone cannot say
    whose configuration runs): equal to the candidate -> that change is live, `config-write` is sent (idempotent) and verified, the row becomes `jen`; its digest equal to the row's BEFORE
    digest -> nothing landed, the row is deleted; neither -> the row stays and the line names both digests; no answer -> the row stays. Returns the (cfg, digest) the daemon runs NOW. A WRITER:
    never from a read - the caller holds the change lock. Raises `RevisionStoreUnreadable`."""
    sid = server.get("id")
    if sid is None or service not in SERVICE_KEY:
        return cfg, digest
    row = _rev.pending(sid, service)
    if row is None:
        return cfg, digest
    try:
        candidate = json.loads(row["config"])
    except (TypeError, ValueError):
        return cfg, digest
    at = str(row.get("created_at") or "an earlier time")
    if _row_age_seconds(row) < PENDING_SETTLE_SECONDS:
        if notes is not None:
            notes.append(
                f"a change of {at} is in progress; it is not settled until it has had {PENDING_SETTLE_SECONDS} s"
            )
        return cfg, digest
    if row.get("sha256") and digest == row["sha256"]:
        _rev.discard(row["id"])
        if notes is not None:
            notes.append(f"a change of {at} never reached the daemon; its record was removed")
        return cfg, digest
    if _carries(_section(cfg, service), _section(candidate, service)):
        # (second pass, row 5) the settlement's `config-write` is a write of this server's file: it asks what every other writer asks first - the investigation marker and the host's restore window
        from jen.services import investigation_logging as _inv

        waits = _host.guard_kea_write(server, cfg, service) or (
            _inv.restore_window(server) if service == "dhcp4" else ""
        )
        if waits:
            if notes is not None:
                notes.append(f"a change of {at} is live and its file write waits: {waits}")
            return cfg, digest
        wrote = write_file(server, service)
        again, digest2, _ = _get(server, service)
        if wrote.get("ok") and again is not None and digest2:
            _rev.finish(row["id"], source="jen", sha256=digest2, cfg=again)
            if notes is not None:
                notes.append(f"a change of {at} was finished now")
            return again, digest2
        if notes is not None:
            notes.append(
                f"a change of {at} is live but its file write is not proved ({wrote.get('detail') or 'no answer'}); the daemon runs {digest}"
            )
        return cfg, digest
    if notes is not None:
        notes.append(
            f"a change of {at} is unresolved: the daemon runs {digest}, which is neither the state before it ({row.get('sha256') or 'unknown'}) nor the change; resolve it from Config history"
        )
    return cfg, digest


def pending_block(server: dict, service: str) -> str:
    """A sentence when a pending change is on record and the daemon is in neither of its states (read, reconcile, and nothing settled it); else "". `apply` refuses on it (a restore, which is
    the operator's way out, passes `source="restore"` and is not stopped)."""
    sid = server.get("id")
    if sid is None:
        return ""
    try:
        if _rev.pending(sid, service) is None:
            return ""
        notes: list = []
        cfg, digest, why = _get(server, service)
        if cfg is None:
            return f"an earlier change on {_name(server)} is unresolved and the daemon did not answer ({why})"
        _reconcile_pending(server, service, cfg, digest, notes)
        if _rev.pending(sid, service) is None:
            return ""
    except _rev.RevisionStoreUnreadable:
        return unreadable_sentence(
            server
        )  # (Q216 AA11) a store that cannot be asked is a refusal, never "nothing is pending"
    return notes[-1] if notes else f"an earlier change on {_name(server)} is unresolved; resolve it from Config history"


# ── apply: the nine steps, in this order and no other ─────────────────────────────────────────────────────────────────────


def _unproved(code: str, detail: str, **extra) -> dict:
    return _result(False, code, detail, needs_hands=True, **extra)


def _undo(server: dict, service: str, before_cfg: dict | None, before_hash: str) -> bool:
    """Put the previous configuration back over the API and PROVE it: the daemon's own `config-get` afterward equals it (or carries the digest it had)."""
    if before_cfg is None:
        return False
    reply = _cmd(server, service, "config-set", _body(before_cfg, service))
    if not _ok(reply) and _answered(
        reply
    ):  # a refusal; a transport fault is ASKED about below, never assumed (the forward set's rule)
        return False
    got, digest, _why = _get(server, service)
    return got is not None and (digest == before_hash or _canonical(got, service) == _canonical(before_cfg, service))


def _after_a_set_failure(server: dict, service: str, expect_hash: str, reply: dict) -> dict:
    """`config-set` was refused by Kea: ISC's rule is that the old configuration keeps serving, and Jen asks the daemon rather than assume it."""
    now = hash(server, service)
    if now == expect_hash:
        return _result(False, "set-failed", _text(reply) or "config-set was refused")
    if now is None:
        return _unproved(
            "noanswer",
            f"{_name(server)} refused the change and then did not answer; the daemon may have stopped serving - a restart reloads its file, which this change never touched",
        )
    return _unproved(
        "unverified",
        f"{_name(server)} refused the change but now runs a configuration with digest {now}, not the {expect_hash} it had; "
        "the daemon may have stopped serving - a restart reloads its file, which this change never touched",
        before_hash=expect_hash,
        after_hash=now,
    )


def _after_a_set_without_an_answer(
    server: dict, service: str, cfg: dict, before_cfg: dict | None, expect_hash: str
) -> tuple[str | None, dict | None]:
    """`config-set` got no answer: only the daemon's own `config-get` can say whose configuration runs, compared CANONICALLY with the candidate. (h1, None) to continue; (None, result) to stop."""
    got, digest, why = _get(server, service)
    if got is None:
        return None, _unproved(
            "noanswer",
            f"{_name(server)} did not answer the change or the question that followed it ({why}); the daemon may or may not carry it",
        )
    if before_cfg is not None and _canonical(got, service) == _canonical(before_cfg, service):
        return None, _result(
            False, "set-failed", "config-set got no answer and the daemon still runs the previous configuration"
        )
    if _carries(_section(got, service), _section(cfg, service)):
        return digest, None
    return None, _unproved(
        "unverified",
        f"{_name(server)} did not answer config-set and now runs a configuration that is neither the change nor the one before it (digest {digest}, before {expect_hash})",
        before_hash=expect_hash,
        after_hash=digest,
    )


def _write_with_retries(server: dict, service: str) -> tuple[dict | None, bool, bool]:
    """`config-write`, re-sent when no answer came (it is idempotent: it writes what runs). (last reply, answered 0, an earlier attempt got NO answer - it may have written)."""
    reply, silent = None, False
    for _ in range(WRITE_ATTEMPTS):
        reply = _cmd(server, service, "config-write")
        if _ok(reply) or _answered(reply):
            break
        silent = True
    return reply, _ok(reply or {}), silent and _answered(reply or {})


def _has_ssh(server: dict) -> bool:
    return bool(server.get("ssh_host"))


def apply(
    server: dict,
    service: str,
    cfg: dict,
    expect_hash: str | None,
    summary: str,
    source: str = "jen",
    *,
    before_cfg: dict | None = None,
) -> dict:
    """Write `cfg` to the daemon over its own API: compare, set, write, verify - the HostResult of the file path's `apply_config`. `expect_hash` is the digest read with the configuration
    this change was built from (the Plan read); `before_cfg` is that configuration (the undo's target and the API-only guard's reference; read here when a caller has none).

    The sequence, in this order and no other:
      (1) `guard_kea_write` (INV-005: the investigation marker) - a refusal is `guard`, nothing sent.
      (2) the API-only guard - a socket, a hook library or a TLS path that differs from the running configuration's is `guard`.
      (3) the pending record is written (the candidate, with the BEFORE digest), so a reader can settle a half-applied change by content.
      (4) `config-hash-get` equals `expect_hash` or `conflict` (nothing sent); no `expect_hash` at all is `conflict` too - a compare that is not asked for is not a compare (Q216 BF3).
      (5) `config-set` -> h1. A refusal: ask the daemon; a missing answer: ask `config-get` and compare canonically.
      (6) `config-write` (re-sent on a missing answer); a refusal undoes the set (`write-failed`); no answer is never `ok`.
      (7) `config-get` carries h1, or `unverified` (NOT undone: a different digest may be someone else's change).
      (8) where SSH exists the helper reads the FILE and it must equal what `config-get` reports.
      (9) the revision recorded (the pending row, finished in place), `{"ok": True, "code": "ok", "sha256": h1}`.
    """
    if service not in SERVICE_KEY:
        return _result(False, "noservice", f"{service} is not configured over the API in this release")
    sid = server.get("id")

    refusal = _host.guard_kea_write(server, cfg, service)  # (1)
    if refusal:
        return _result(False, "guard", refusal)
    if source != "rollback":
        # (1a) BB9 d: never inside the window in which the HOST restores logging - a rollback undoes a change that stood, and is not a new write over the restore
        from jen.services import (
            investigation_logging as _inv,
        )  # lazy: that module imports the change set, which imports this one

        window = _inv.restore_window(server) if service == "dhcp4" else ""
        if window:
            return _result(False, "investigation-on", window)
    # (1b) no write without the probe's facts, the operator's consent and a daemon that is not known to refuse its file
    gated = probe_gate(server, source)
    if gated:
        return _result(False, "guard", gated)

    if before_cfg is None:
        before_cfg, before_digest, why = _get(server, service)
        if before_cfg is None:
            return _result(False, "noanswer", f"the running configuration of {_name(server)} could not be read ({why})")
        expect_hash = expect_hash or before_digest
    if (
        not expect_hash
    ):  # (Q216 BF3) the digest compare is the only compare the API has: a call that brings none sends nothing
        return _result(False, "conflict", "no digest to compare against - read the daemon first")
    guarded = _api_only_guard(service, before_cfg, cfg)  # (2)
    if guarded:
        return _result(False, "guard", guarded)

    if source != "restore":
        blocked = pending_block(server, service)
        if blocked:
            return _unproved("unverified", blocked)

    pending_id = None
    if sid is not None:  # (3)
        pending_id = _rev.record(sid, service, cfg, expect_hash or "", summary, hash_kind="kea", source=PENDING)

    def _drop_pending():
        if pending_id is not None:
            _rev.discard(pending_id)

    now = hash(server, service)  # (4)
    if now is None:
        _drop_pending()
        return _result(False, "noanswer", f"{_name(server)} did not answer the digest question; nothing was sent")
    if expect_hash and now != expect_hash:
        _drop_pending()
        return _result(
            False,
            "conflict",
            f"the daemon on {_name(server)} runs digest {now}, not the {expect_hash} this change was built from",
            before_hash=expect_hash,
            after_hash=now,
        )

    reply = _cmd(server, service, "config-set", _body(cfg, service))  # (5)
    if _ok(reply):
        h1 = _digest(reply) or hash(server, service)
        if not h1:
            return _unproved(
                "unverified", f"{_name(server)} accepted the change but returned no digest; it may be live"
            )
    elif _answered(reply):
        outcome = _after_a_set_failure(server, service, expect_hash or now, reply)
        if not outcome.get("needs_hands"):
            _drop_pending()
        return outcome
    else:
        h1, stop = _after_a_set_without_an_answer(server, service, cfg, before_cfg, expect_hash or now)
        if stop is not None:
            if not stop.get("needs_hands"):
                _drop_pending()
            return stop

    wrote, wrote_ok, maybe_written = _write_with_retries(server, service)  # (6)
    unwritten = ""
    if not wrote_ok:
        if wrote is not None and _answered(wrote):
            remember_refusal(
                server, _text(wrote)
            )  # BB9 a: a fleet does not undo the same change on every edit; cleared only by evidence
            proved_back = _undo(server, service, before_cfg, expect_hash or now)
            if proved_back and maybe_written:
                return _unproved(
                    "write-failed",
                    f"{_text(wrote) or 'config-write was refused'}; an earlier attempt got no answer and may have written the file, so it may carry a change the daemon no longer runs",
                    after_hash=h1,
                )
            if proved_back:
                _drop_pending()
                return _result(False, "write-failed", _text(wrote) or "config-write was refused")
            return _unproved(
                "write-failed",
                f"{_text(wrote) or 'config-write was refused'}; the change could not be proved undone - the daemon may run it without the file carrying it",
                after_hash=h1,
            )
        unwritten = "the file may not carry this change"

    got, digest, why = _get(server, service)  # (7)
    if got is None or digest != h1:
        return _unproved(
            "unverified",
            f"{_name(server)} did not confirm the change ({why or f'its digest is {digest}, not the {h1} the set returned'}); the daemon's own answer is the record and nothing was undone",
            before_hash=expect_hash or now,
            after_hash=digest,
        )

    raw_sha = None
    if _has_ssh(server):  # (8)
        file_cfg, raw_sha = _host.read_config_versioned(server, service, capture=False)
        if file_cfg is None or not same_modulo_defaults(file_cfg, got, service):
            return _unproved(
                "unverified",
                f"the file on {_name(server)} does not carry what the daemon runs"
                + (f" ({unwritten})" if unwritten else ""),
                before_hash=expect_hash or now,
                after_hash=h1,
            )
    elif unwritten:
        return _unproved("unverified", f"{_name(server)}: {unwritten}", after_hash=h1)

    if pending_id is not None:  # (9)
        _rev.finish(pending_id, source=source, sha256=h1, cfg=got)
        _rev.discard_pending(
            sid, service
        )  # (fix row 2) an unresolved row an earlier crash left is superseded by a change that stood
    if raw_sha and sid is not None and not str(raw_sha).startswith(_host._CANONICAL_SENTINEL_PREFIX):
        _rev.record(sid, service, got, raw_sha, summary or f"{source} {service}", hash_kind="raw", source=source)
    return _result(True, "ok", sha256=h1)


def revert(
    server: dict, service: str, cfg: dict, expect_hash: str | None, summary: str, *, before_cfg: dict | None = None
) -> dict:
    """`apply` with `source="rollback"`: put a configuration this module wrote back, guarded by the digest that write returned."""
    return apply(server, service, copy.deepcopy(cfg), expect_hash, summary, source="rollback", before_cfg=before_cfg)


def record_after_file_write(server: dict, service: str, summary: str, source: str = "jen") -> bool:
    """A change reached this server by the FILE path (its daemon was restarted on the new file): record what the daemon runs NOW as a `kea` row, from `config-get`, so the next API write
    does not read this one as somebody else's change. Best effort and never raises: a daemon that does not answer records nothing, and the next read captures it as it would any hand edit."""
    sid = server.get("id")
    if sid is None or service not in SERVICE_KEY:
        return False
    cfg, digest, _why = _get(server, service)
    if cfg is None:
        return False
    return (
        _rev.record(sid, service, cfg, digest, summary or f"{source} {service}", hash_kind="kea", source=source)
        is not None
    )


def api_daemon_differs(server: dict, service: str) -> str:
    """The choke point's question for a FILE-path write onto a server whose transport is `api` (Q212, BB2 e): does the file the writer is about to replace carry what the daemon runs? A sentence
    naming both digests when BOTH answered and differ - the next logging toggle would otherwise erase an `unverified` apply or a hand `config-set` - else "". A file or a daemon that cannot be read
    is not a difference (the write's own guards decide), so a host whose daemon is down can still be put back."""
    if declared_transport(server) != "api" or service not in SERVICE_KEY:
        return ""
    live, digest, _why = _get(server, service)
    if live is None:
        return ""
    sid = server.get("id")
    try:
        last = _rev.latest_of_kind(sid, service, "kea") if sid is not None else None
    except Exception as e:  # a history read never decides this question: containment below is the fallback
        logger.warning("kea_api_config: api_daemon_differs could not read the history of %s: %s", sid, type(e).__name__)
        last = None
    if last is not None and last.get("source") != PENDING and last.get("sha256") and last["sha256"] != digest:
        # (Q216 AA - the blind spot) a hand `config-set` of a key the FILE omits (one of the 45 defaults `config-get` writes out) is invisible to containment; the DIGEST of the last configuration Jen
        # recorded for this daemon is the check, and containment is the fallback for a server with no `kea` row yet (docs/ARCHITECTURE.md 3.17 says that is its limit)
        return (
            f"the daemon on {_name(server)} runs a configuration that is not the one Jen last recorded for it (the daemon {digest[:12]}, Jen's record {str(last['sha256'])[:12]}); "
            "restore or resolve it from Config history first"
        )
    file_cfg, raw = _host.read_config_versioned(server, service, capture=False)
    if file_cfg is None or file_in_daemon(file_cfg, live, service):
        return ""
    where = difference_text(file_cfg, live, service)
    return (
        f"the daemon on {_name(server)} runs a configuration its file does not carry ({where + '; ' if where else ''}the daemon {digest[:12]}, the file {str(raw or 'unknown')[:12]}); "
        "restore or resolve it from Config history first"
    )


# ── the stored probe: the facts are the gate (Q212, BB3 c/d) ──────────────────────────────────────────────────────────────


PROBE_KEY = "config_transport_probe:{}"
PROBE_MAX_AGE_DAYS = 7
PROBE_SENTENCE = "run the readiness check on the server's Write mode card first"


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stored_probe(server_id) -> dict | None:
    """The stored result of the last probe of this server (`settings` key `config_transport_probe:<id>`), or None. It is what `capabilities.derive` reads and what the card renders - a
    settings read, never a Kea call."""
    if server_id is None:
        return None
    from jen.models import user as _user

    try:
        raw = _user.get_global_setting(PROBE_KEY.format(server_id))
        data = json.loads(raw) if raw else None
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def store_probe(server_id, data: dict) -> bool:
    from jen.models import user as _user

    return bool(_user.set_global_setting(PROBE_KEY.format(server_id), json.dumps(data, sort_keys=True)))


def _age_days(iso: str | None) -> float | None:
    from datetime import datetime, timezone

    try:
        when = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds() / 86400


def _bound(server: dict) -> str:
    """Which endpoint a stored probe was read from: a hash of the API url and the SSH host (never stored in the clear). Server ids are reused (the next free number) and `api_url` can be re-pointed,
    so consent given to one Kea must not carry to another that inherits its number (fix row 6)."""
    import hashlib

    return hashlib.sha256(f"{server.get('api_url') or ''}|{server.get('ssh_host') or ''}".encode()).hexdigest()[:16]


CONSENTS = ("consent_rendering", "consent_unauthenticated", "discard_file_edit", "confirm_no_include")


def consent_gap(name: str, facts: dict | None, consents, *, has_ssh: bool, strict: bool = True) -> tuple[str, str]:
    """(sentence, needs): the FIRST thing that stands between these `facts` and an operator's named `consents` - "" when nothing does. THE one definition of whether the operator's consents cover the facts (Q216
    AA1): the switch's rules of BB8 moved here verbatim, asked by the switch, by `probe(consent=True)` and - for the facts a refresh brought - by the gate. `needs` is the consent field that would answer
    the sentence (or the helper grant, `allow_config_write`). With `strict=False` a fact that is ABSENT from a stored result (an older release wrote none; a test stores three keys) is not an unknown one."""
    facts = facts or {}
    consents = set(consents or ())

    def known(key):
        return strict or key in facts

    if not facts.get("config_api"):
        return (
            f"{name}: the daemon could not be read over its API ({facts.get('read_error') or 'no answer'}); nothing was changed",
            "",
        )
    if facts.get("test_ok") is False:
        return (
            f"{name}: the daemon did not accept its own configuration in a config-test ({facts.get('test_detail') or 'refused'}); nothing was changed",
            "",
        )
    if facts.get("include"):
        return (
            f"{name}: the file carries an include ({', '.join(facts['include'])}); the daemon reports the merged configuration and config-write renders one flat file, so Live API is not recommended here",
            "",
        )
    if has_ssh and (
        (known("agree") and facts.get("agree") is None)
        or (known("include") and facts.get("include") is None)
        or (known("write") and not isinstance(facts.get("write"), dict))
    ):
        return (
            f"{name}: SSH is configured but the host's facts could not be read (is the helper installed at build 19 or later, and does SSH answer?), so the file could not be compared with the daemon; nothing was changed",
            "",
        )
    if not has_ssh and "confirm_no_include" not in consents:
        return (
            f"{name} has no SSH host, so Jen cannot see its file: confirm that the file carries no include and no edit the daemon has not loaded, then switch again",
            "confirm_no_include",
        )
    if has_ssh and facts.get("agree") is False and "discard_file_edit" not in consents:
        return (
            f"{name}: the file on the host carries a configuration the daemon is not running - restart Kea first, or tick 'discard the file's edit' (the switch makes the file the daemon's configuration)",
            "discard_file_edit",
        )
    write = facts.get("write")
    if has_ssh and isinstance(write, dict) and write.get("may_write") is False:
        return (
            f"{name}: the daemon's account ({write.get('account') or 'unknown'}) may not write its file ({write.get('mode')}); press Allow the daemon to write its file, then switch again",
            "allow_config_write",
        )
    if "consent_rendering" not in consents:
        return (
            f"{name}: Kea writes its file in its own form - comments and key order are not kept (a 1,932-byte file became 4,769). This is the one moment they are lost: tick the confirmation to go on",
            "consent_rendering",
        )
    if facts.get("auth") == "none" and "consent_unauthenticated" not in consents:
        return (
            f"{name}: this endpoint has no authentication; anything that can reach it can change this daemon's configuration. Confirm that, then switch again",
            "consent_unauthenticated",
        )
    return "", ""


def consents_called_for(facts: dict | None, *, has_ssh: bool) -> list[str]:
    """The consents the FACTS call for, in the order `consent_gap` names them (Q217 BG2): the card's row 3 and the gate's table are one list (a test walks `consent_gap` one refusal at a time and
    compares). `consent_rendering` is asked of every switch."""
    facts = facts or {}
    out = []
    if not has_ssh:
        out.append("confirm_no_include")
    if has_ssh and facts.get("agree") is False:
        out.append("discard_file_edit")
    out.append("consent_rendering")
    if facts.get("auth") == "none":
        out.append("consent_unauthenticated")
    return out


def consent_allowed(name: str, facts: dict | None, consents, *, has_ssh: bool, strict: bool = True) -> str:
    """`consent_gap`'s sentence alone: "" when the named consents cover the facts."""
    return consent_gap(name, facts, consents, has_ssh=has_ssh, strict=strict)[0]


def probe_gate(server: dict, source: str = "jen") -> str:
    """NO API write without it: a sentence for a server whose stored result is absent, older than 7 days, has `config_api` false, carries no `consented_at` (the operator's named consent, from
    the card), carries a fact the consent given does not cover (a refresh found an include, or the endpoint lost its authentication - Q216 AA12), or remembers a refused write (BB9 a); "" otherwise. A
    server added through Settings with `api` written by the save route therefore cannot be written to until its operator has read the probe's facts once: the probe is a click, the facts are the gate."""
    stored = stored_probe(server.get("id"))
    if not stored:
        return PROBE_SENTENCE
    if stored.get("bound") and stored["bound"] != _bound(server):
        return f"{_name(server)} now points at a different Kea than the one that was checked - {PROBE_SENTENCE.replace('first', 'again')}"
    age = _age_days(stored.get("at"))
    if age is None or age > PROBE_MAX_AGE_DAYS:
        return f"the last check of {_name(server)} is older than {PROBE_MAX_AGE_DAYS} days - {PROBE_SENTENCE.replace('first', 'again')}"
    if not stored.get("config_api"):
        return f"the daemon on {_name(server)} could not be read over its API at the last check - {PROBE_SENTENCE.replace('first', 'again')}"
    if not stored.get("consented_at"):
        return f"changes over the API to {_name(server)} have not been allowed yet - read the facts and allow them from the server's card"
    # the consent on record covers the facts it was given for; a stored result from before the consents were recorded (7.0.0-beta.1) counts as having been given all of them
    given = stored.get("consents", CONSENTS)
    uncovered = consent_allowed(_name(server), stored, given, has_ssh=_has_ssh(server), strict=False)
    if uncovered:
        prefix = f"{_name(server)}: "
        return (
            uncovered[len(prefix) :] if uncovered.startswith(prefix) else uncovered
        )  # (the caller names the server: "❌ kea-d: ...")
    return (
        "" if source in ("rollback", "restore") else refusal_sentence(server)
    )  # a rollback puts back a change that DID stand on this server, and a restore is the way out the failure's own line names (Q216 AA14): a remembered refusal must not stop either


def refusal_sentence(server: dict) -> str:
    """BB9 a: after a `write-failed` the stored result carries `refused` (Kea's own text) and a change set refuses to PLAN against the server, so a fleet does not undo the same change on every edit."""
    stored = stored_probe(server.get("id"))
    if stored and stored.get("refused"):
        return f"the daemon on {_name(server)} may not write its file ({stored['refused']}); fix it, then run the readiness check on the server's Write mode card"
    return ""


def remember_refusal(server: dict, text: str) -> bool:
    """Record Kea's own refusal of `config-write` in the stored result. Cleared only by evidence (`probe` with the helper's `config-write-check` saying the account may write, or the operator's
    "I have fixed it" with its audit row) - never by a probe that proves nothing."""
    sid = server.get("id")
    if sid is None:
        return False
    stored = stored_probe(sid) or {"at": _now_iso()}
    stored["refused"] = (text or "config-write was refused")[:300]
    return store_probe(sid, stored)


def clear_refusal(server_id) -> bool:
    stored = stored_probe(server_id)
    if not stored or "refused" not in stored:
        return True
    stored.pop("refused", None)
    return store_probe(server_id, stored)


def _endpoint_facts(server: dict, service: str) -> dict:
    """How the endpoint is authenticated and whether it is reached over TLS - read from what `credentials.resolve` gave the server dict, never sent anywhere. Kea draws no line between a client that reads
    and one that writes (RBAC is subscriber-only), so the credential that reads is the credential that writes and NOTHING new is created on Kea."""
    endpoint = _kea._endpoint_for(server, service)
    if isinstance(endpoint, dict):
        return {"auth": "unknown", "tls": None}
    url, user, pwd = endpoint
    tls = str(url).lower().startswith("https://")
    if user or pwd:
        auth = "password"
    elif tls and _kea._tls_client_cert():
        auth = "client certificate"
    else:
        auth = "none"
    return {"auth": auth, "tls": tls}


PROBE_REFRESH_AFTER_HOURS = 24


def refresh_probe(server: dict, service: str = "dhcp4") -> bool:
    """Keep the FACTS fresh without asking the operator again (Q216 AA12): re-run the probe for a server whose operator has consented, leaving `consented_at` and `consents` exactly as they are while `bound`
    is unchanged. True when the stored facts were replaced. A daemon (or a host's helper) that does not answer keeps the previous facts and their age - reachability is runtime (BB2 b) - and a fact that
    now stands outside the consent given closes the gate with its own sentence (`probe_gate`)."""
    sid = server.get("id")
    stored = stored_probe(sid)
    if not stored or not stored.get("consented_at") or service not in SERVICE_KEY:
        return False
    if stored.get("bound") and stored["bound"] != _bound(server):
        return False  # a re-pointed server is for its operator to check again
    cfg, _digest, _why = _get(server, service)
    if cfg is None:
        return False
    fresh = probe(server, service, persist=False)
    if _has_ssh(server) and (
        fresh.get("include") is None or fresh.get("agree") is None or not isinstance(fresh.get("write"), dict)
    ):
        return False  # (second pass, row 4) the host did not answer this time - or its file could not be read: what was known stays known, never an unknown that closes the gate
    latest = (
        stored_probe(sid) or {}
    )  # (row 10) re-read just before the write: a consent or a refusal given while the facts were being read is the operator's, not ours to discard
    for key in ("consented_at", "consents", "refused"):
        if key in latest:
            fresh[key] = latest[key]
        else:
            fresh.pop(key, None)
    return store_probe(sid, fresh)


def refresh_if_stale(server: dict, service: str = "dhcp4") -> bool:
    """The change set's Plan: facts older than a day are refreshed before the gate is asked."""
    stored = stored_probe(server.get("id"))
    age = _age_days((stored or {}).get("at"))
    if not stored or age is None or age * 24 < PROBE_REFRESH_AFTER_HOURS:
        return False
    return refresh_probe(server, service)


def probe(server: dict, service: str = "dhcp4", *, consent: bool = False, consents=(), persist: bool = True) -> dict:
    """The facts an operator reads before the first change over the API, from a GUARDED `config-get` (never `config-hash-get`, which the Control Agent also answers), a `config-test` of the running
    configuration, how the endpoint is authenticated, and - where SSH exists - the helper's `config-write-check` and a compare of the file with the daemon. Stored (BB3 d) and returned.
    `consent` records the operator's named consent (`consented_at`, and the `consents` it was given with) ONLY when `consent_allowed` answers "" for the consents the caller carries - the switch's terms
    exactly (Q216 AA1). `persist=False` returns the facts without storing them (the refresh decides)."""
    sid = server.get("id")
    prev = stored_probe(sid) or {}
    out = {"at": _now_iso(), "service": service, "bound": _bound(server)}
    if prev.get("bound") and prev["bound"] != out["bound"]:
        prev = {}  # a different endpoint: nothing carries over (consent, a remembered refusal)
    cfg, _digest, why = _get(server, service)
    out["config_api"] = cfg is not None
    if cfg is None:
        out["read_error"] = why
    else:
        tested = test(server, service, cfg)
        out["test_ok"] = bool(tested["ok"])
        if not tested["ok"]:
            out["test_detail"] = tested.get("detail", "")
    out.update(_endpoint_facts(server, service))
    out["authored"] = False
    if sid is not None:
        try:
            out["authored"] = any(
                r.get("source") in ("jen", "authoring") for r in _rev.list_revisions(sid, service, limit=500)
            )
        except Exception as e:  # a history read never fails the probe
            logger.warning("kea_api_config: probe could not read the history of %s: %s", sid, type(e).__name__)
    refused = prev.get("refused")
    if _has_ssh(server):
        check = _host.config_write_check(server, service)
        out["write"] = (
            {
                "may_write": bool(check.get("may_write")),
                "owner_uid": check.get("owner_uid"),
                "owner_gid": check.get("owner_gid"),
                "mode": check.get("mode"),
                "account": (check.get("account") or {}).get("name") if check.get("account") else "root",
                "daemon_is_root": bool(check.get("daemon_is_root")),
            }
            if check.get("ok")
            else {"unavailable": check.get("detail") or check.get("code")}
        )
        out["include"] = list(check.get("includes") or []) if check.get("ok") else None
        if not check.get("ok"):
            # (Q217 BG3 a) SSH EXISTS here: the helper did not answer. The card names that cause (a helper below build 19, SSH down), never "without SSH"
            out["include_unavailable"] = str(check.get("detail") or check.get("code") or "the helper did not answer")[
                :300
            ]
        file_cfg, _raw = _host.read_config_versioned(server, service, capture=False)
        out["agree"] = None if file_cfg is None or cfg is None else file_in_daemon(file_cfg, cfg, service)
        if out["agree"] is False:
            out["agree_at"] = difference_text(file_cfg, cfg, service)
        if check.get("ok") and check.get("may_write"):
            refused = None  # evidence: the host says the daemon's account may write its file
    else:
        out["write"] = "unknown until the first change - Jen undoes a change whose write fails"
        out["include"] = None  # cannot be known without the host; the switch asks the operator to confirm there is none
        out["agree"] = None
    if refused:
        out["refused"] = refused
    if prev.get("consented_at"):
        out["consented_at"] = prev["consented_at"]
        if "consents" in prev:
            out["consents"] = prev["consents"]
    if consent:
        given = sorted(set(consents or ()) & set(CONSENTS))
        gap = consent_allowed(_name(server), out, given, has_ssh=_has_ssh(server))
        if not gap:
            out["consented_at"] = _now_iso()
            out["consents"] = given
        else:
            out["consent_refused"] = gap
    if persist:
        store_probe(sid, out)
    return out
