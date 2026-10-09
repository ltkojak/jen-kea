"""
jen/services/investigation_logging.py
──────────────────────────────────────
v5.68.0-beta.3 (Q138) — investigation logging on demand: the DEBUG loggers Trace and Explain need, on ONE Kea server, for a
bounded time, put back by Jen itself.

What Kea's log shows about a client depends on its level (tests/kea_compat/test_log_levels.py, Kea 3.0.3 / 3.2.0 / 3.3.1):
the client id at any level, the assigned classes at debuglevel 45, the whole packet at 55. Until now Jen told an operator that
and left them to edit Kea's config by hand on a production DHCP server and then remember to undo it. `turn_on` does it - the pure
mutation is jen.services.kea_config_edit.set_investigation_logging - through the one sanctioned write path,
`kea_changeset.apply_change` (one target, the sha guard, preflight with `kea-dhcp4 -t`, the revert on failure, an audit row and a
config revision), and `turn_off` / `sweep` put it back.

HOW THE DAEMON LEARNS OF IT. `config-reload` re-reads the file the daemon was started with through the control channel Jen already
uses, so a log-level change needs no restart (no dropped packets, nothing for HA to notice). Jen asks the daemon whether it has the
command (`list-commands`) and uses it with `restart=False`; if the daemon does not list it, or refuses it, the restart path is used
and the result says so. The kea-compat probe records what `config-reload` actually did on each supported Kea version.

THE RECORD. The marker that says what is on and what undoes it lives IN THE KEA CONFIG (a `user-context` on the logger entry), so it
survives a Jen restart, a restored database and a second Jen. The settings record kept here (`investigation_logging`) is only an
index of what THIS Jen knows is on, so the every-minute sweep can be cheap: it looks at that index, and only every
`FULL_SCAN_EVERY`-th run (ten minutes) reads every server's config to find and restore an expired marker nobody indexed - "whether or
not this Jen set it" - and to adopt a live one so the banners show it. One server at a time per Jen; there is no API for any of it.

v5.68.0-beta.9 (Q144): each index entry carries the FILE state, the DAEMON state and what is still owed (see "the state machine" below),
a server removed from Jen while an entry exists keeps it (the Health row says how to restore it by hand) and the settings routes refuse
to remove a server that has one, and every adoption or refused removal writes an audit row.

v5.68.0-beta.23 (Q158): the daemon is OBSERVED, never inferred. Six betas corrected this state machine at the level of acknowledgements (what a call
returned), and each left a case where the acknowledgement and the truth differ - the sharpest: a `config-reload` Kea APPLIED whose HTTP reply was
lost came back as a failure, the file was put back, the entry dropped, and the daemon stayed at DEBUG 55 with nothing left that knew. Kea answers
the question directly - `config-get` returns the RUNNING daemon's loggers, severity, debuglevel and user-context included - so `daemon_logger` reads
it, `observe` turns it into the entry's `daemon` field (debug / restored / other / unknown) after every reload and every restart, and ONE rule
follows: an entry is dropped when the file is restored AND the daemon was SEEN restored. Anything else keeps the entry, pending, and the Health row
says "unconfirmed". Every write of the index is checked too (`_save`/`_put`/`_drop` return whether it was stored).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from jen import extensions
from jen.services import kea as _kea
from jen.services import kea_changeset as _changeset
from jen.services import kea_config_edit as _edit
from jen.services import kea_host as _host

logger = logging.getLogger(__name__)

RECORD_KEY = "investigation_logging"
DURATIONS = (5, 15, 60)  # minutes; 60 is offered with a confirm that names the disk
FULL_SCAN_EVERY = 10  # sweep runs between reads of every server's config
OVERDUE_GRACE_S = 120  # how long past `until` before the Health row calls it left on
RELOAD_TRIES = (
    3  # fixup 4 (F1): reloads asked of a daemon seen at DEBUG with the file restored, before the ONE restart per entry
)
OBSERVE_AFTER_RESTART_S = 8  # a restarted daemon takes a few seconds to answer on its control socket: look for this long before saying "unknown"
_lock = threading.Lock()
_runs = {"n": 0}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sleep(seconds: float) -> None:  # a name the tests replace
    time.sleep(seconds)


def _iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).isoformat(timespec="seconds")


# ── the index of what this Jen knows is on ───────────────────────────────────


DAMAGED_KEY = (
    RECORD_KEY + ".damaged"
)  # the unreadable value, kept once before anything overwrites it (v5.68.0-beta.24, Q159)


_ENTRY_STR_FIELDS = ("ssh_host", "kea_conf", "by", "mode", "error", "seen", "observed_at", "server_id")
_ENTRY_BOOL_FIELDS = ("removed", "marker_invalid", "contradiction", "restarted", "deadline_malformed")


_LEGACY_ABSENT_KEYS = ("observed_at", "seen", "reload_tries", "restarted", "contradiction")
_legacy_logged: set = set()


def _is_legacy_entry(e) -> bool:
    """An entry written before beta.9 (no file / daemon) or beta.23 (no observations): it carries none of the keys those releases added. `_record`
    normalises it; anything else that lacks `file` or `daemon` is damaged (v5.68.0-beta.26, Q161, item 3)."""
    return isinstance(e, dict) and not any(k in e for k in _LEGACY_ABSENT_KEYS)


def _valid_entry(e) -> bool:
    """Is `e` an index entry this module could have written? (v5.68.0-beta.25, Q160, item 4.) `_record` used to validate the outer shape only, so
    `{"servers": {"2": {}}}` or `{"servers": {"2": null}}` read as healthy and `turn_on`'s `others = [e["name"] ...]` raised, as did every reader of
    `entry.get(...)` on a non-dict. Every field is either absent or of the type `_entry_for` / `observe` write."""
    if not isinstance(e, dict) or not isinstance(e.get("name"), str) or not isinstance(e.get("until"), str):
        return False
    # v5.68.0-beta.26 (Q161, item 3): the fields that DECIDE what Jen does are checked for meaning, not just type. `until` any string passed (and an
    # unreadable one reads as "due now", so the sweep would restore a live session), `restore` any dict passed (`{}` is not a way back), `file` and `daemon`
    # could be absent (and default to "debug"), and `reload_tries` any int (a negative one is more reloads than the bound allows).
    if _edit._parse_until(e["until"]) is None:
        return False
    if "restore" in e and _edit.restore_problem(e["restore"]):
        return False
    if ("file" not in e or "daemon" not in e) and not _is_legacy_entry(e):
        return False
    if e.get("file", "debug") not in ("debug", "restored"):
        return False
    if e.get("daemon", "debug") not in ("debug", "restored", "other", "unknown"):
        return False
    if e.get("pending") not in (None, "reload", "restart"):
        return False
    if any(k in e and not isinstance(e[k], str) for k in _ENTRY_STR_FIELDS):
        return False
    if any(k in e and not isinstance(e[k], bool) for k in _ENTRY_BOOL_FIELDS):
        return False
    if "reload_tries" in e and (
        isinstance(e["reload_tries"], bool)
        or not isinstance(e["reload_tries"], int)
        or not 0 <= e["reload_tries"] <= RELOAD_TRIES + 1
    ):
        return False
    if "restore" in e and not isinstance(e["restore"], dict):
        return False
    revision = e.get("history_revision")
    return revision is None or (isinstance(revision, int) and not isinstance(revision, bool))


def _record() -> dict:
    """The index: {"servers": {...}, "damaged": bool, "raw": the unreadable value or "", "bad": [server ids whose entry failed validation]}.

    v5.68.0-beta.24 (Q159, item 3): a stored value that is not a JSON object with a `servers` object - malformed JSON, a list, a string, an object
    without `servers` - used to read as an EMPTY index. The one-server rule then allowed a second session, the next write overwrote the damaged value,
    and the only thing that might rediscover a running DEBUG was the ten-minute scan. It is `damaged` now: turn-on refuses, Health fails naming the
    setting, `_save` keeps the old value in `investigation_logging.damaged` before it writes anything, and the full scan rebuilds the record."""
    from jen.models import user as _user

    raw = _user.get_global_setting(RECORD_KEY, "") or ""
    data = None
    if raw != "":
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
    damaged = raw != "" and not (isinstance(data, dict) and isinstance(data.get("servers"), dict))
    bad = []
    if raw != "" and not damaged:
        bad = [
            str(sid) for sid, e in data["servers"].items() if not _valid_entry(e)
        ]  # Q160 item 4: every entry, not just the outer shape
        damaged = bool(bad)
        if not damaged:
            for sid, e in data["servers"].items():
                if (
                    "file" not in e or "daemon" not in e
                ):  # the defined legacy shape (Q161): normalised, and said once per server
                    e.setdefault("file", "debug")
                    e.setdefault("daemon", "debug")
                    e.setdefault("pending", None)
                    if sid not in _legacy_logged:
                        _legacy_logged.add(sid)
                        logger.info(
                            "investigation_logging: the entry for server %s predates the file/daemon fields; read as file=debug daemon=debug",
                            sid,
                        )
    servers = data["servers"] if (raw != "" and not damaged) else {}
    return {"servers": servers, "damaged": damaged, "raw": raw if damaged else "", "bad": bad}


def _save(record: dict) -> bool:
    """Store the index. True when it was stored: `set_global_setting` answers False when the Jen database did not take the write (v5.68.0-beta.22), and
    a caller that says "recorded" or "dropped" must say it on the strength of that answer (v5.68.0-beta.23, Q158).

    A DAMAGED value (Q159) is copied to `investigation_logging.damaged` first, once (when that key is empty), and if the copy cannot be stored nothing
    is overwritten: a person may need the old value to see which server was meant."""
    from jen.models import user as _user

    keep = record.get("damaged") and record.get("raw") and not _user.get_global_setting(DAMAGED_KEY, "")
    if keep and _user.set_global_setting(DAMAGED_KEY, record["raw"]) is False:
        return False
    stored = (
        _user.set_global_setting(RECORD_KEY, json.dumps({"servers": record["servers"]}) if record["servers"] else "")
        is not False
    )
    if stored:
        record["damaged"], record["raw"] = False, ""  # what is stored now is a record this code wrote
    return stored


def _row(sid, entry: dict, now: datetime) -> dict:
    """One index entry as the banners, the Servers page and the Health row read it."""
    due = _edit._parse_until(entry.get("until"))
    remaining = int((due - now).total_seconds()) if due else -1
    file_state, daemon = entry.get("file", "debug"), entry.get("daemon", "debug")
    tries, restarted = int(entry.get("reload_tries") or 0), bool(entry.get("restarted"))
    # a restore that cleaned the file but left the daemon at DEBUG 55 is the failure this module exists to prevent
    stuck = file_state == "restored" and daemon != "restored"
    contradiction = bool(entry.get("contradiction"))
    exhausted = stuck and daemon == "debug" and tries >= RELOAD_TRIES and restarted
    return {
        "server_id": sid,
        "name": entry.get("name") or f"Server {sid}",
        "until": entry.get("until", ""),
        "remaining_s": max(0, remaining),
        "overdue": remaining < -OVERDUE_GRACE_S,
        "by": entry.get("by", ""),
        "mode": entry.get("mode", ""),
        "error": entry.get("error", ""),
        # v5.68.0-beta.13 (Q148): the marker lost its restore object, so Jen refused to guess - a person restores it
        "marker_invalid": bool(entry.get("marker_invalid")),
        "history_revision": entry.get("history_revision"),
        # v5.68.0-beta.9 (Q144): the state machine's three fields, and what a person needs for a server Jen can no longer reach
        "file": file_state,
        "daemon": daemon,
        "pending": entry.get("pending"),
        # v5.68.0-beta.23 (Q158): what the running daemon was last SEEN doing, and when / what it showed
        "observed_at": entry.get("observed_at", ""),
        "seen": entry.get("seen", ""),
        "removed": bool(entry.get("removed")),
        "ssh_host": entry.get("ssh_host", ""),
        "kea_conf": entry.get("kea_conf", ""),
        "stuck": stuck,
        # fixup 4: the bound on the daemon step, the API-vs-SSH contradiction, and whether a PERSON has to act
        "reload_tries": tries,
        "restarted": restarted,
        "contradiction": contradiction,
        # v5.68.0-beta.27 (Q162, item 2): the marker's deadline could not be read when the record was rebuilt, so the entry was made due NOW
        "deadline_malformed": bool(entry.get("deadline_malformed")),
        "exhausted": exhausted,
        "needs_hand": stuck and (daemon == "other" or contradiction or exhausted),
        # (F6) the FILE carries investigation DEBUG and the daemon was seen NOT running it: "on" would be a false report
        "not_loaded": file_state == "debug"
        and daemon == "restored"
        and not entry.get("marker_invalid")
        and not entry.get("removed"),
    }


def active(now: datetime | None = None) -> list[dict]:
    """What is on, for the banners and the Health row: [{server_id, name, until, remaining_s, overdue, error, ...}], soonest first."""
    now = now or _now()
    return sorted((_row(sid, entry, now) for sid, entry in _record()["servers"].items()), key=lambda e: e["until"])


def hand_text(e: dict) -> str:
    """What the Health row and the Servers page say about an entry whose config file is restored and whose daemon was not SEEN restored (an `active()`
    row). It depends on what was OBSERVED, never on what is assumed."""
    name = e["name"]
    if e.get("deadline_malformed"):
        note = " (its marker's deadline was unreadable, so it was treated as due)"
        return hand_text({**e, "deadline_malformed": False}).replace(name + ":", name + ":" + note, 1)
    if e.get("contradiction"):
        return (
            f"{name}: the Kea that Jen's API settings ([kea] api_url) answer for is not running the file Jen wrote on {e.get('ssh_host') or 'the Kea host'} "
            "over SSH (ssh_host) - api_url and ssh_host may not be the same Kea. The config file there is back as it was, but the Kea on that host was "
            f"asked to read the DEBUG file and may still be running DEBUG 55: {by_hand_daemon(e)}"
        )
    if e.get("exhausted"):
        return f"{name}: Jen reloaded {RELOAD_TRIES} times and restarted once; Kea is still at DEBUG 55 - restore it by hand: {by_hand_daemon(e)}"
    if e["daemon"] == "debug":
        return f"{name}: the config file is restored but Kea is still at DEBUG 55 - Jen keeps trying a reload or restart every minute (up to {RELOAD_TRIES} reloads and one restart)"
    if e["daemon"] == "other":
        return (
            f"{name}: the config file is restored, but Kea's running logger ({e.get('seen') or 'unreadable'}) is neither at investigation DEBUG nor at "
            f"what it was before - Jen has left it alone and looks again every minute. {by_hand_running(e)}"
        )
    return (
        f"{name}: the config file is restored but Kea's running log level is unconfirmed since {e.get('observed_at') or 'the restore'} "
        "(its API did not answer) - Jen looks again every minute and changes nothing it cannot see"
    )


# ── applying a change to ONE server ──────────────────────────────────────────
#
# THE STATE MACHINE (v5.68.0-beta.9, Q144). Turning investigation logging on or off is two steps that can each fail on their own:
# the FILE (the `loggers` entry and its marker, written through apply_change) and the DAEMON (which has to re-read the file:
# `config-reload`, else a restart). An index entry therefore records both, and a third field says what is still owed:
#
#   file    "debug" | "restored"            what Jen last wrote successfully into the config file
#   daemon  "debug" | "restored" | "unknown" what the running daemon is believed to be doing
#   pending "reload" | "restart" | None      the daemon step still owed to make the daemon match the file
#
# An entry is dropped ONLY when file and daemon are both "restored". Nothing is inferred from "the file has no marker": a restore
# whose daemon step failed leaves the file clean and the daemon at DEBUG 55, and the next minute's change set then finds no marker
# and reports "nothing" - which used to read as "done" and forgot the daemon. Now a "nothing" with a daemon step still owed runs
# that step. The enable side is the mirror: the entry is saved as soon as the file is written (writing it took responsibility for
# it), before the daemon is asked, so a restart between the two activates DEBUG with an entry already indexed.


def _reload_support(server: dict) -> str:
    """Does the daemon have `config-reload`? "yes", "no" (Kea answered and does not list it) or "unknown" (Kea's API did not answer).

    v5.68.0-beta.21 (Q156): this used to be a bool, and "unknown" read as "no": `list-commands` failing - a Control Agent that is down, a timeout -
    returns result 1 from `kea_command`, `config-reload` is not in the missing answer, and turning logging ON wrote the file AND restarted
    kea-dhcp4 over SSH. On Kea 3.0+ `config-reload` is always listed, so "not listed" can only mean "could not ask". A restart of a production
    daemon must not follow from an API that did not answer."""
    reply = _kea.kea_command("list-commands", server=server)
    if reply.get("result") != 0:
        return "unknown"
    return "yes" if "config-reload" in (reply.get("arguments") or []) else "no"


def _unreachable_note(server: dict) -> str:
    return f"Kea's API on {_name(server)} did not answer, so Jen could not ask whether it can re-read its config without a restart"


# ── observing the running daemon (v5.68.0-beta.23, Q158) ────────────────────────────────────────────────────────────────────────────


def daemon_logger(server: dict) -> dict | None:
    """What the RUNNING kea-dhcp4 says its logger is, read with `config-get` (tests/kea_compat/test_log_levels.py records it on Kea 3.0.3 / 3.2.0 / 3.3.1):
    {"present": bool, "severity", "debuglevel", "marker": the `jen-investigation` user-context or None}. None when Kea's API did not answer, or
    answered with something that is not a Dhcp4 configuration - the caller must treat that as "could not see", never as "restored"."""
    reply = _kea.kea_command("config-get", server=server)
    if reply.get("result") != 0:
        return None
    arguments = reply.get("arguments")
    section = arguments.get("Dhcp4") if isinstance(arguments, dict) else None
    if not isinstance(section, dict):
        return None
    loggers = section.get("loggers")
    if loggers is None:
        loggers = []
    if not isinstance(loggers, list):
        return None
    entry = next((x for x in loggers if isinstance(x, dict) and x.get("name") == _edit.INVESTIGATION_LOGGER), None)
    if entry is None:
        return {"present": False, "severity": None, "debuglevel": None, "marker": None}
    context = entry.get("user-context")
    marker = context.get(_edit.INVESTIGATION_KEY) if isinstance(context, dict) else None
    return {
        "present": True,
        "severity": entry.get("severity"),
        "debuglevel": entry.get("debuglevel"),
        "marker": marker if isinstance(marker, dict) else None,
    }


def _at_investigation_level(seen: dict) -> bool:
    return str(seen.get("severity") or "").upper() == _edit.INVESTIGATION_SEVERITY and seen.get("debuglevel") == (
        _edit.INVESTIGATION_DEBUGLEVEL
    )


def _is_original(seen: dict, restore) -> bool:
    """Is the running logger what the marker's restore object says it was before Jen touched it? `restore` is None for an entry written before
    beta.23 (it did not carry the object): then "restored" is "carries no marker and is not at the investigation level"."""
    if seen.get("marker") is not None:
        return False
    if isinstance(restore, dict) and restore.get("created") is True:
        return not seen["present"]
    if not seen["present"]:
        return not isinstance(restore, dict)  # a logger that existed and is gone is not what the object describes
    if not isinstance(restore, dict) or _edit.restore_problem(restore):
        return not _at_investigation_level(seen)
    severity, level = restore.get("severity", "absent"), restore.get("debuglevel", "absent")
    shown_severity = str(seen.get("severity") or "").upper()
    # a key the original did not have is Kea's own default (INFO / 0): all that can be said is that it is not the investigation value
    severity_ok = (
        shown_severity != _edit.INVESTIGATION_SEVERITY
        if severity == "absent"
        else shown_severity == str(severity).upper()
    )
    level_ok = (
        seen.get("debuglevel") != _edit.INVESTIGATION_DEBUGLEVEL
        if level == "absent"
        else seen.get("debuglevel") == level
    )
    return severity_ok and level_ok


def _describe(seen: dict) -> str:
    if not seen["present"]:
        return "no kea-dhcp4 logger"
    if (
        seen.get("marker") is not None
        and str(seen.get("severity") or "").upper() == _edit.INVESTIGATION_SEVERITY
        and not _at_investigation_level(seen)
    ):
        # v5.68.0-beta.24 (Q159, item 1): the marker is ours, the level is not the one it names - said, and classified "other" (never "debug")
        return f"DEBUG at debuglevel {seen.get('debuglevel')}, not 55"
    return f"{seen.get('severity') or 'default severity'} / debuglevel {seen.get('debuglevel') if seen.get('debuglevel') is not None else 'default'}"


def observe(server: dict, entry: dict, *, wait_s: float = 0.0) -> str:
    """Read the running daemon and set `entry["daemon"]` (and `observed_at`, `seen`) from what it SHOWS - never from what a call returned:
    "debug" (DEBUG with the jen-investigation marker), "restored" (what the marker's restore object says it was, or the logger absent when Jen
    created it), "other" (something else - said so), "unknown" (Kea's API did not answer: nothing is inferred). `wait_s` keeps looking that long
    for an answer, one try a second - a daemon that has just been restarted takes a moment to open its control socket."""
    deadline = time.monotonic() + max(0.0, wait_s)
    seen = daemon_logger(server)
    while seen is None and time.monotonic() < deadline:
        _sleep(1.0)
        seen = daemon_logger(server)
    return observe_from(entry, seen)


def observe_from(entry: dict, seen: dict | None) -> str:
    """`observe`'s classification applied to a logger that was ALREADY read (v5.68.0-beta.25, Q160): the damaged-index recovery reads the file and the daemon
    of every server into a candidate before it writes anything, and classifies with the same body `observe` uses."""
    entry["observed_at"] = _iso(_now())
    if seen is None:
        state, entry["seen"] = "unknown", ""
    else:
        entry["seen"] = _describe(seen)
        if seen["marker"] is not None and _at_investigation_level(seen):
            state = "debug"
        elif _is_original(seen, entry.get("restore")):
            state = "restored"
        else:
            state = "other"
    entry["daemon"] = state
    return state


def _seen_line(entry: dict) -> str:
    state = entry.get("daemon")
    if state == "debug":
        return "Kea is still running at DEBUG 55."
    if state == "other":
        return (
            f"Kea's running logger is {entry.get('seen') or 'neither at investigation DEBUG nor at its original setting'}: neither investigation DEBUG "
            "nor what it was before - Jen has left it and keeps checking."
        )
    return "Jen could not read Kea's running log level, so it does not know - it looks again every minute."


def _change(server: dict, mutate_fn, summary: str, unsupported: str, *, refuse_unknown: bool = False):
    """Step 1: write one mutation to ONE server through apply_change - with a restart folded in when the daemon has no
    `config-reload`. Returns (ChangeSetResult, use_reload, support); with `refuse_unknown` and Kea's API silent nothing is written and the
    result is None. (Turning logging OFF never refuses: DEBUG 55 must come off, so there the restart is the fallback.)"""
    support = _reload_support(server)
    if support == "unknown" and refuse_unknown:
        return None, False, support
    use_reload = support == "yes"
    result = _changeset.apply_change(
        "dhcp4",
        mutate_fn,
        summary,
        servers=[server],
        restart=not use_reload,
        code_messages={
            "unsupported": unsupported,
            "marker-invalid": "the investigation-logging marker is unreadable, so nothing was changed",
        },
    )
    return result, use_reload, support


def _daemon_step(
    server: dict, use_reload: bool, *, allow_restart: bool, verify=None, refused_note: str | None = None
) -> dict:
    """Step 2: make the daemon re-read its file - `config-reload` when the daemon has it, a restart otherwise or when the reload is
    refused. Returns {"ok", "mode": "reload"|"restart"|"", "lines": [...]}.

    `verify` (v5.68.0-beta.23, Q158) is asked before a refused reload becomes a restart: a reply that is not 0 is a refusal, a connection failure
    or a timeout - the last of which Kea may well have APPLIED - so a caller that can LOOK at the daemon says whether it is already where it should
    be (True), and then nothing is restarted."""
    if use_reload:
        reply = _kea.kea_command("config-reload", server=server)
        if reply.get("result") == 0:
            return {"ok": True, "mode": "reload", "lines": ["Kea re-read its config without a restart."]}
        refused = reply.get("text") or "refused"
        if verify is not None and verify():
            return {
                "ok": True,
                "mode": "reload",
                "lines": [
                    f"Kea's API did not confirm the reload ({refused}), but Kea was seen at the right level, so nothing was restarted."
                ],
            }
        if not allow_restart:
            # v5.68.0-beta.22 (Q157): turning logging ON never restarts Kea. A `config-reload` that does not return 0 is a refusal, a connection failure
            # or a timeout - `kea_command` gives all three the same shape - and at this point they cannot be told apart. beta.21 refused when
            # `list-commands` was silent and then restarted over SSH when the NEXT call to the same API failed; the caller puts the file back.
            return {
                "ok": False,
                "mode": "",
                "lines": [
                    refused_note
                    or (
                        f"Kea's API did not confirm the reload ({refused}), so the log level was put back; nothing was restarted - "
                        "check Settings → Kea → Probe."
                    )
                ],
            }
        restarted = _host.service_action(server, "dhcp4", "restart")
        if restarted.get("ok"):
            return {
                "ok": True,
                "mode": "restart",
                "lines": [f"config-reload was refused ({refused}), so Kea was restarted instead."],
            }
        return {
            "ok": False,
            "mode": "",
            "lines": [
                f"❌ The config was written but Kea did not take it: config-reload was refused ({refused}) and the restart failed "
                f"({restarted.get('detail', 'no detail')}). The daemon is still running on its previous settings."
            ],
        }
    restarted = _host.service_action(server, "dhcp4", "restart")
    if restarted.get("ok"):
        return {"ok": True, "mode": "restart", "lines": ["Kea was restarted."]}
    return {
        "ok": False,
        "mode": "",
        "lines": [
            f"❌ Kea did not restart ({restarted.get('detail', 'no detail')}). The daemon is still running as it was."
        ],
    }


def _audit(action: str, server_name: str, detail: str) -> None:
    try:
        from jen.models import user as _user

        _user.audit(action, server_name, detail)
    except Exception as e:  # an audit failure must not undo a log level
        logger.debug(f"investigation_logging: audit failed: {e}")


def _name(server: dict) -> str:
    return server.get("name") or server.get("ssh_host") or f"Server {server.get('id')}"


def _entry_for(server: dict, until: str, by: str = "") -> dict:
    """A fresh index entry. It carries what Jen would need to tell a person how to restore the server by hand if the server is
    ever removed from Jen: its name, its SSH host and its config path."""
    return {
        "name": _name(server),
        "until": until,
        "by": by,
        "mode": "",
        "ssh_host": server.get("ssh_host") or "",
        "kea_conf": server.get("kea_conf") or "",
        "file": "debug",
        "daemon": "unknown",
        "pending": None,
    }


def _put(record: dict, sid, entry: dict) -> bool:
    """Index `entry` for `sid`. True when it was STORED (v5.68.0-beta.23, Q158): turn_on does not ask the daemon on an unstored entry."""
    if record.get("damaged"):
        # v5.68.0-beta.25 (Q160): a damaged record is never written piecemeal - the one write that replaces it is the recovery's, after every server was examined
        logger.error("investigation_logging: refused to write an entry into a damaged record (a programming error)")
        return False
    record["servers"][str(sid)] = entry
    return _save(record)


def _drop(record: dict, sid) -> bool:
    """Forget `sid`'s entry. True when it is gone from the store; False when the write failed - then the entry is still stored, and the next sweep
    observes it again and drops it (the in-memory copy is put back so the rest of this call sees what is stored)."""
    gone = record["servers"].pop(str(sid), None)
    if gone is None:
        return True
    if record.get("damaged"):  # never overwrite a damaged value from here (Q160)
        record["servers"][str(sid)] = gone
        return False
    if _save(record):
        return True
    record["servers"][str(sid)] = gone
    return False


def _revert_file(server: dict, summary: str) -> tuple[bool, list[str]]:
    """Put the file back WITHOUT touching the daemon (it never took the change). (restored, lines)."""
    result = _changeset.apply_change(
        "dhcp4",
        lambda cfg: _edit.clear_investigation_logging(cfg),
        summary,
        servers=[server],
        restart=False,
        code_messages={},
    )
    return result.status in ("ok", "nothing"), [text for _kind, text in result.lines]


# ── turn on / off ────────────────────────────────────────────────────────────


def _undo_activation(server: dict, record: dict, why: str) -> dict:
    """Logging was switched on and Jen could not STORE that it had been: take it off again at once through the restore path (which keeps trying
    while the entry cannot be written). {"ok": False, "mode", "lines"}; the caller holds the lock."""
    outcome = _restore(server, record, None, "investigation logging on failed: log level put back")
    return {
        "ok": False,
        "mode": "",
        "lines": [f"❌ {why}, so logging was turned off again."] + outcome["lines"],
        "until": "",
    }


#: v5.68.0-beta.23 (Q158 fixup 4, F3): what a "restored" daemon right after a reload or restart that was ASKED OF A DEBUG FILE means. The daemon that read
#: the file cannot show the original level, so the daemon Kea's API answers for is not the daemon whose file Jen edits over SSH.
CONTRADICTION = (
    "the daemon Kea's API answers for is not running the file Jen wrote (api_url and ssh_host may not be the same Kea)"
)
UNSTORED = "Jen could not record this (its database did not take the write); the ten-minute scan reads Kea's running logger and finishes it."


def _did_not_take(server, record, sid, entry, lines, step_lines, *, contradiction=False) -> dict:
    """The daemon did not (visibly) take the DEBUG file: put it straight back, WITHOUT a restart - and then LOOK, because a reload whose reply was
    lost may have been applied. Seen restored: the entry is dropped ("not activated"). Seen at DEBUG: kept, the sweep finishes it. Seen at anything
    else: kept and LEFT ALONE. With `contradiction` (a reload or restart that was asked of a DEBUG file and answered "restored") the entry is kept
    whatever the second look says: it names the contradiction. Every write here is checked (F4)."""
    restored, revert_lines = _revert_file(server, "investigation logging on failed: log level put back")
    head = lines + revert_lines + step_lines
    if restored:
        entry.update(file="restored")
        state = observe(server, entry)
        if contradiction:
            entry.update(daemon="other", seen=CONTRADICTION, contradiction=True, pending=None)
            entry.pop("error", None)
            stored = _put(record, sid, entry)
            tail = [f"Logging was not activated: {CONTRADICTION}."] + ([] if stored else [UNSTORED])
            return {"ok": False, "mode": "", "lines": head + tail, "until": ""}
        if state == "restored":
            if _drop(record, sid):
                return {"ok": False, "mode": "", "lines": head + ["Logging was not activated."], "until": ""}
            _put(record, sid, entry)
            return {
                "ok": False,
                "mode": "",
                "lines": head
                + ["Logging was not activated; Jen could not clear its own record, and the next sweep does."],
                "until": "",
            }
        entry.update(pending=None if state == "other" else "reload")
        entry.pop("error", None)
        stored = _put(record, sid, entry)
        if state == "debug":
            tail = [
                "Kea applied the change although its API did not confirm it. The file is back and the sweep asks Kea to re-read it within a "
                "minute; the entry stays until Jen has seen Kea back at its original level."
            ]
        else:
            tail = [f"The file is back. {_seen_line(entry)} The entry stays until Jen has seen Kea restored."]
        if not stored:
            tail.append(UNSTORED)
        return {"ok": False, "mode": "", "lines": head + tail, "until": ""}
    note = "❌ The config file still carries the DEBUG marker and could not be put back; Jen keeps trying every minute."
    observe(server, entry)
    entry.update(pending="reload", error=note[:300])
    if contradiction:
        entry.update(daemon="other", seen=CONTRADICTION, contradiction=True)
    stored = _put(record, sid, entry)
    return {"ok": False, "mode": "", "lines": head + [note] + ([] if stored else [UNSTORED]), "until": ""}


def turn_on(server: dict, minutes: int, actor: str = "") -> dict:
    """Investigation logging on `server` for `minutes` (one of DURATIONS), through apply_change. Refused while ANOTHER server has
    it on (one at a time per Jen). Returns {"ok", "mode", "lines", "until"}.

    v5.68.0-beta.23 (Q158): the daemon is OBSERVED after the reload (and after a restart) rather than inferred from the reply. A reload whose reply
    was lost HAS been applied, so an unconfirmed reload reverts the file and then LOOKS: seen at its original level, the entry is dropped; seen at
    DEBUG, the entry is kept (file restored, daemon debug, reload owed) and the sweep finishes it; not seen, it is kept as unknown. A daemon seen
    at neither level after a restart or reload did not take it (the file is put back, no second restart), and a daemon seen at its ORIGINAL level
    right after a reload or restart that succeeded is a contradiction, not a refusal: it is not the daemon whose file Jen edited."""
    if minutes not in DURATIONS:
        return {"ok": False, "mode": "", "lines": [f"Choose {', '.join(map(str, DURATIONS))} minutes."], "until": ""}
    name = _name(server)
    sid = str(server.get("id"))
    with _lock:
        record = _record()
        if record.get("damaged"):
            return {
                "ok": False,
                "mode": "",
                "lines": ["Jen's record of investigation logging cannot be read; see Health → DEBUG logging left on"],
                "until": "",
            }
        others = [e["name"] for other, e in record["servers"].items() if other != sid]
        if others:
            return {
                "ok": False,
                "mode": "",
                "lines": [
                    f"Investigation logging is already on for {', '.join(others)}; turn that off first (one server at a time)."
                ],
                "until": "",
            }
        until = _iso(_now() + timedelta(minutes=minutes))
        captured: dict = {}

        def mutate(cfg):
            new_cfg, code = _edit.set_investigation_logging(cfg, until)
            marker = _edit.investigation_marker(new_cfg) if code == "ok" else None
            if marker is not None:  # what the logger WAS: the daemon is later judged "restored" against it
                captured["restore"] = marker.get("restore")
            return new_cfg, code

        result, use_reload, _support = _change(
            server,
            mutate,
            f"investigation logging on for {minutes} min",
            "this config has no Dhcp4 section to log from",
            refuse_unknown=True,
        )
        if result is None:
            # Kea's API did not answer: turning ON must never become a restart of a production daemon. Nothing was written.
            return {
                "ok": False,
                "mode": "",
                "lines": [
                    f"{_unreachable_note(server)}, and Jen will not turn logging on by restarting Kea. "
                    "Check Settings → Kea → Probe, then try again."
                ],
                "until": "",
            }
        lines = [text for _kind, text in result.lines]
        entry = _entry_for(server, until, actor)
        if captured.get("restore") is not None:
            entry["restore"] = captured["restore"]

        if result.status == "rollback_failed":
            # the change set could not put the file back after a failed restart: the file may carry the marker and the daemon is
            # in an unknown state - take responsibility for it rather than forgetting it
            entry.update(daemon="unknown", pending="restart", error=(lines[-1] if lines else "rollback failed")[:300])
            if not _put(record, sid, entry):
                lines.append(
                    "❌ Jen could not record this either: the next ten-minute scan finds the marker in the file."
                )
            return {"ok": False, "mode": "", "lines": lines, "until": ""}
        if result.status != "ok":
            return {"ok": False, "mode": "", "lines": lines, "until": ""}

        if not use_reload:  # the change set restarted the daemon: file and daemon moved together - and the daemon is looked at, not assumed
            entry["restarted"] = True
            state = observe(server, entry, wait_s=OBSERVE_AFTER_RESTART_S)
            if state in ("restored", "other"):
                # the restart SUCCEEDED, so a daemon at its original level is not a refusal (F3: it is not the daemon whose file was edited), and a
                # daemon at some third level did not take the file either (F2): put the file back, restart nothing again, look again
                shown = entry.get("seen") or "not at DEBUG"
                step_lines = [
                    "Kea was restarted, but its running logger is "
                    + (
                        f"{shown}, the level it had before"
                        if state == "restored"
                        else f"{shown}, neither DEBUG nor what it was before"
                    )
                    + " - the change did not take."
                ]
                return _did_not_take(server, record, sid, entry, lines, step_lines, contradiction=(state == "restored"))
            entry.update(pending=None if state == "debug" else "reload", mode="restart")
            if not _put(record, sid, entry):
                return _undo_activation(server, record, "Jen could not record that logging is on")
            _audit("INVESTIGATION_LOGGING_ON", name, f"DEBUG 55 until {until} (restart)")
            tail = [] if state == "debug" else [_seen_line(entry)]
            return {
                "ok": True,
                "mode": "restart",
                "lines": lines + ["Kea has no config-reload here, so it was restarted."] + tail,
                "until": until,
            }

        # The file now carries DEBUG 55: Jen is responsible for it from this moment, so the entry is saved BEFORE the daemon is asked - and when it
        # cannot be saved the daemon is NOT asked (a DEBUG daemon with no stored entry is exactly what this module exists to prevent).
        entry.update(daemon="unknown", pending="reload")
        if not _put(record, sid, entry):
            restored, revert_lines = _revert_file(server, "investigation logging on failed: Jen could not record it")
            note = ["Jen could not record this (its database did not take the write), so nothing was activated."]
            if not restored:
                note.append(
                    "❌ The config file still carries the DEBUG marker and could not be put back; the ten-minute scan finds the marker and "
                    "the sweep puts it back when it is due."
                )
            return {"ok": False, "mode": "", "lines": lines + revert_lines + note, "until": ""}
        step = _daemon_step(server, use_reload=True, allow_restart=False)
        if step["ok"]:
            state = observe(server, entry)
            if state == "debug":
                entry.update(pending=None, mode=step["mode"])
                entry.pop("error", None)
                if not _put(record, sid, entry):
                    return _undo_activation(server, record, "Jen could not record that logging is on")
                _audit("INVESTIGATION_LOGGING_ON", name, f"DEBUG 55 until {until} ({step['mode']})")
                return {"ok": True, "mode": step["mode"], "lines": lines + step["lines"], "until": until}
            if state == "unknown":
                # Kea said it reloaded; its API then did not answer a config-get. The reload was confirmed, the level was not READ BACK
                entry.update(pending=None, mode=step["mode"])
                if not _put(record, sid, entry):
                    logger.warning("investigation_logging: the unconfirmed-on entry for %s could not be stored", name)
                _audit(
                    "INVESTIGATION_LOGGING_ON",
                    name,
                    f"DEBUG 55 until {until} ({step['mode']}; the running level was not read back)",
                )
                return {
                    "ok": True,
                    "mode": step["mode"],
                    "lines": lines
                    + step["lines"]
                    + [
                        "Jen could not read Kea's running log level back to confirm it; the entry stays and the sweep looks again."
                    ],
                    "until": until,
                }
            # the reload SUCCEEDED and the daemon shows something else: at its original level that is a contradiction, at a third level it did not take
            shown = entry.get("seen") or "not at DEBUG"
            step = {
                "ok": False,
                "mode": "",
                "lines": [f"Kea said it reloaded, but its running logger is {shown} - the change did not take."],
            }
            return _did_not_take(server, record, sid, entry, lines, step["lines"], contradiction=(state == "restored"))
        # The daemon did not (visibly) take it: put the file straight back, WITHOUT a restart - and then look
        return _did_not_take(server, record, sid, entry, lines, step["lines"])


def _restore(server: dict, record: dict, now: datetime | None, summary: str) -> dict:
    """Put `server`'s logger back and make the daemon take it. `now=None` restores unconditionally (the button); a datetime
    restores only what is due (the sweep). The entry is dropped only when the file is restored AND the daemon was SEEN restored (v5.68.0-beta.23,
    Q158): every reload and restart is followed by a `config-get`, and a daemon Jen could not see, or saw at anything else, keeps the entry pending.

    Fixup 4 (F1): the daemon step is BOUNDED. A daemon seen at neither level ("other") after the file is restored is LEFT ALONE - no reload, no restart,
    Health fails with the by-hand text. A daemon seen at DEBUG gets `RELOAD_TRIES` reloads and then ONE restart per entry, and then nothing: the
    prose has always said "Jen keeps trying every minute" and the code did, for ever, restarting a production daemon a minute.
    Returns {"ok", "mode", "lines"}; caller holds the lock."""
    sid = str(server.get("id"))
    entry = record["servers"].get(sid)
    captured: dict = {}

    def mutate(cfg):
        marker = _edit.investigation_marker(cfg)
        if marker is not None and not _edit.restore_problem(marker.get("restore")):
            captured["restore"] = marker["restore"]
        return _edit.clear_investigation_logging(cfg, now=now)

    result, use_reload, support = _change(server, mutate, summary, "")
    lines = [text for _kind, text in result.lines]
    if result.status == "aborted" and result.last_code == "marker-invalid":
        # v5.68.0-beta.13 (Q148): the marker's restore object is missing or malformed. Nothing was written (the change set aborted before
        # any write), the entry is KEPT so the Health row and the Servers page keep saying so, and a person is told how to finish it.
        entry = entry or _entry_for(server, _iso(now or _now()))
        text = marker_invalid_text(server, entry)
        entry.update(marker_invalid=True, error=text[:900])
        _put(record, sid, entry)
        return {"ok": False, "mode": "", "lines": [f"❌ {text}"]}
    fresh = False
    if result.status == "ok":
        entry = entry or _entry_for(server, _iso(now or _now()))
        if captured.get("restore") is not None and entry.get("restore") is None:
            entry["restore"] = captured["restore"]
        if not use_reload:  # the change set restarted the daemon: both steps done - now look at it
            entry.update(file="restored", pending=None, restarted=True)
            entry.pop("error", None)
            state = observe(server, entry, wait_s=OBSERVE_AFTER_RESTART_S)
            why = (
                f"{_unreachable_note(server)}, so Kea was restarted to take the restore (DEBUG 55 has to come off)."
                if support == "unknown"
                else "Kea has no config-reload here, so it was restarted."
            )
            return _finish(server, record, entry, state, "restart", lines + [why])
        # the file is clean, the daemon not yet looked at: say so in the index before the daemon is asked
        entry.pop("error", None)
        entry.update(file="restored", pending="reload")
        _put(record, sid, entry)
        fresh = True
    elif result.status == "nothing":
        # no marker in the file: nothing to write. The daemon may still be at DEBUG - the very case a forgotten reload leaves - so LOOK before acting.
        if entry is None:
            return {"ok": True, "mode": "nothing", "lines": lines}
        entry.pop("error", None)
        entry.update(file="restored")
        if entry.get("contradiction"):
            # fixup 5 (F10): the daemon this entry's API answers for is NOT the one whose file was edited, so what it shows - the captured original level
            # - proves nothing about the box SSH restarted on the DEBUG file. No observation is believed here: only Forget (after a look) ends it
            return _left_alone(record, sid, entry, lines)
        before = entry.get("daemon")
        state = observe(server, entry)
        if state == "restored":
            return _finish(server, record, entry, state, "nothing", lines)
        if state == "other":
            # neither investigation DEBUG nor what it was: a hand edit, another tool, or the API answering for a different Kea. Jen has nothing to
            # put back and a reload or restart would not be the fix: it is left alone, said so, and a person decides (Forget, after a look)
            return _left_alone(record, sid, entry, lines)
        if state == "unknown" and before != "debug" and now is not None:
            # Kea's API did not answer and the daemon was NOT last seen at DEBUG: the sweep does not reload or restart on a guess (a restart every
            # minute of a daemon Jen cannot see is not a fix). One that was last SEEN at DEBUG, or a person pressing Turn off, goes on to the
            # documented fallback below - and the observation after it moves `daemon` off "debug", so that happens once.
            entry["pending"] = entry.get("pending") or "reload"
            _put(record, sid, entry)
            return {"ok": False, "mode": "", "lines": lines + [_seen_line(entry)]}
        entry["pending"] = entry.get("pending") or "reload"
        _put(record, sid, entry)
    else:
        if entry is not None:
            entry["error"] = (lines[-1] if lines else "restore failed")[:300]
            _put(record, sid, entry)
        return {"ok": False, "mode": "", "lines": lines}
    return _daemon_phase(server, record, entry, lines, fresh=fresh)


def _daemon_phase(server: dict, record: dict, entry: dict, lines: list[str], *, fresh: bool) -> dict:
    """The daemon step of a restore, bounded (F1): up to RELOAD_TRIES reloads, then ONE restart per entry, then nothing. `fresh` is the call that
    wrote the file back: a reload Kea refuses may fall back to the restart at once (the documented behaviour of Turn off and the expiry), once."""
    sid = str(server.get("id"))
    tries = int(entry.get("reload_tries") or 0)
    restarted = bool(entry.get("restarted"))
    reload_now = _reload_support(server)
    can_reload = entry.get("pending") != "restart" and reload_now == "yes"
    if can_reload and tries < RELOAD_TRIES:
        entry["reload_tries"] = tries + 1
        step = _daemon_step(
            server,
            use_reload=True,
            allow_restart=fresh and not restarted,
            verify=lambda: observe(server, entry) == "restored",
            refused_note=f"Kea's API did not confirm the reload (try {tries + 1} of {RELOAD_TRIES}); Jen looks at the daemon and tries again.",
        )
    elif not restarted:
        step = _daemon_step(server, use_reload=False, allow_restart=True)
        entry["restarted"] = (
            True  # one restart per entry, whether or not it worked: a failing unit is not restarted every minute either
        )
    else:
        entry["pending"] = None
        _put(record, sid, entry)
        return {"ok": False, "mode": "", "lines": lines + [hand_text(_row(sid, entry, _now()))]}
    if step["mode"] == "restart":
        entry["restarted"] = True
    state = observe(server, entry, wait_s=OBSERVE_AFTER_RESTART_S if step["mode"] == "restart" else 0.0)
    why = (
        [f"{_unreachable_note(server)}, so Kea was restarted to take the restore (DEBUG 55 has to come off)."]
        if reload_now == "unknown" and step["mode"] == "restart"
        else []
    )
    if step["ok"]:
        return _finish(server, record, entry, state, step["mode"], lines + step["lines"] + why)
    entry.update(
        pending="reload" if reload_now == "yes" else "restart",
        error=step["lines"][-1][:300],
    )
    _put(record, sid, entry)
    return {"ok": False, "mode": "", "lines": lines + step["lines"]}


def _left_alone(record: dict, sid: str, entry: dict, lines: list[str]) -> dict:
    """The daemon is seen at neither level after the file was restored: nothing is reloaded or restarted, the entry is kept (so Health says so and a
    person can Forget it after a look), and the lines say what to check."""
    entry["pending"] = None
    if not _put(record, sid, entry):
        logger.warning("investigation_logging: the left-alone entry %s could not be stored", sid)
    if entry.get("contradiction"):
        return {"ok": False, "mode": "", "lines": lines + [hand_text(_row(sid, entry, _now()))]}
    return {"ok": False, "mode": "", "lines": lines + [_seen_line(entry), by_hand_running(entry)]}


def _finish(server: dict, record: dict, entry: dict, state: str, mode: str, lines: list[str]) -> dict:
    """The daemon step is over and the daemon has been looked at. Seen restored: the entry is dropped (and if the record cannot be cleared the
    next sweep drops it - the restore itself is done). Anything else keeps the entry and says what was seen; a daemon seen at neither level is left
    alone (nothing is owed), at DEBUG or unseen the step is still owed."""
    sid = str(server.get("id"))
    if entry.get("contradiction"):
        return _left_alone(record, sid, entry, lines)  # never dropped on an observation (fixup 5, F10)
    if state == "restored":
        if not _drop(record, sid):
            entry["pending"] = None
            return {
                "ok": True,
                "mode": mode,
                "lines": lines
                + [
                    "Jen could not clear its own record of this (its database did not take the write); the next sweep does."
                ],
            }
        return {"ok": True, "mode": mode, "lines": lines}
    entry["pending"] = None if state == "other" else (entry.get("pending") or "reload")
    if not _put(record, sid, entry):
        logger.warning("investigation_logging: the entry for %s could not be stored after the daemon step", sid)
    extra = [by_hand_running(entry)] if state == "other" else []
    return {"ok": False, "mode": "", "lines": lines + [_seen_line(entry)] + extra}


def turn_off(server: dict, actor: str = "", reason: str = "investigation logging off") -> dict:
    """Put `server`'s logger back now. Returns {"ok", "mode", "lines"}; the index entry is dropped only when the file AND the daemon
    are restored, so a restore the daemon did not take is retried by the sweep."""
    name = _name(server)
    with _lock:
        record = _record()
        if record.get("damaged"):
            return {
                "ok": False,
                "mode": "",
                "lines": [
                    "Jen's record of investigation logging cannot be read; the scan rebuilds it from the servers within a minute (see Health → DEBUG logging left on)"
                ],
            }
        outcome = _restore(server, record, None, reason)
        if outcome["ok"]:
            _audit("INVESTIGATION_LOGGING_OFF", name, f"{reason} ({outcome['mode']}) by {actor or 'the sweep'}")
        return outcome


def blocking_removal(server_ids) -> list[dict]:
    """The index entries of the servers in `server_ids` (ints or strings) - investigation logging is on there, or a restore is
    still owed - for the settings routes that would stop Jen from reaching them. Removing such a server is refused until turn_off
    succeeds: Jen would otherwise lose the only way it has to put the log level back."""
    wanted = {str(i) for i in server_ids}
    record = _record()
    if record.get("damaged"):
        # v5.68.0-beta.26 (Q161, item 1): an unreadable record is not evidence that this server is NOT at investigation DEBUG. beta.24 made the record
        # `damaged` and this reader still read its empty server map as "nothing blocks the removal" - so a server running DEBUG 55 whose entry was in the
        # unreadable value could be removed, and with it the only way to put it back.
        return [{"server_id": sid, "name": f"Server {sid}", "damaged_record": True} for sid in sorted(wanted)]
    return [{"server_id": sid, **entry} for sid, entry in record["servers"].items() if sid in wanted]


def removal_refusal(server_ids, actor: str = "") -> str:
    """ "" when none of `server_ids` has an index entry, else the sentence a settings route flashes (and an audit row is written)."""
    blocked = blocking_removal(server_ids)
    if not blocked:
        return ""
    if any(b.get("damaged_record") for b in blocked):
        _audit(
            "INVESTIGATION_LOGGING_REMOVAL_REFUSED",
            ", ".join(b["name"] for b in blocked),
            "removal refused while Jen's record of investigation logging is unreadable"
            + (f" (by {actor})" if actor else ""),
        )
        return (
            "Jen's record of investigation logging cannot be read, so it cannot tell whether this server is at investigation DEBUG. Repair the record "
            "first (Health → DEBUG logging left on) — removing the server now could leave its Kea at DEBUG with no way for Jen to put it back."
        )
    names = ", ".join(b.get("name") or f"Server {b['server_id']}" for b in blocked)
    _audit(
        "INVESTIGATION_LOGGING_REMOVAL_REFUSED",
        names,
        f"removal of a Kea server refused while investigation logging is on or owed a restore{' (by ' + actor + ')' if actor else ''}",
    )
    return (
        f"Investigation logging is on for {names}, or its restore is not finished: turn it off from Servers first. Removing the "
        "server now would leave its Kea at DEBUG with no way for Jen to put it back."
    )


def _unconfirmed_for_an_hour(entry: dict) -> bool:
    """An entry whose daemon could not be seen, for over an hour past its deadline: nothing will ever be learned by waiting longer."""
    due = _edit._parse_until(entry.get("until"))
    return bool(
        entry.get("daemon") == "unknown"
        and entry.get("file") == "restored"
        and due
        and _now() - due > timedelta(hours=1)
    )


#: The four settings that say WHICH Kea Jen reaches for a server (v5.68.0-beta.27, Q162, item 1). Credentials (api_user, api_pass, the SSH key) and the
#: display name are NOT identity: they change nothing about which Kea is reached, and a wrong one is corrected by changing it back (Health shows the server
#: unreachable meanwhile).
IDENTITY_FIELDS = ("ssh_host", "ssh_user", "kea_conf", "api_url")
_DEFAULT_KEA_CONF = "/etc/kea/kea-dhcp4.conf"


def endpoint_change_refusal(server_id, proposed: dict, actor: str = "") -> str:
    """ "" when `proposed` leaves the server's identity alone, or the server has no outstanding investigation state; else the sentence a settings route flashes
    (and an audit row is written).

    v5.68.0-beta.27 (Q162, item 1): the removal guard (Q144) protects a server's PRESENCE. The same id with a new SSH host, SSH user, config path or API URL
    passes it - and then every later observation, reload and restore goes to a DIFFERENT Kea, while the one that was at DEBUG 55 is left there. A server with
    an entry (the log level on, or a restore not finished) or any server while the record is unreadable cannot have these four fields changed until
    `turn_off` has succeeded or the record is rebuilt. `proposed` may carry any subset of the four; a field it does not carry is not being changed, and a blank
    config path is the default one."""
    current = next((s for s in (extensions.KEA_SERVERS or []) if str(s.get("id")) == str(server_id)), None)
    if current is None:
        return ""

    def norm(key, value):
        value = (value or "").strip()
        return value or (_DEFAULT_KEA_CONF if key == "kea_conf" else "")

    changed = [k for k in IDENTITY_FIELDS if k in proposed and norm(k, proposed[k]) != norm(k, current.get(k))]
    if not changed:
        return ""
    name = _name(current)
    by = f" (by {actor})" if actor else ""
    record = _record()
    if record.get("damaged"):
        _audit(
            "INVESTIGATION_LOGGING_ENDPOINT_CHANGE_REFUSED",
            name,
            f"change of {', '.join(changed)} refused while Jen's record of investigation logging is unreadable{by}",
        )
        return (
            "Jen's record of investigation logging cannot be read, so it cannot tell whether this server is at investigation DEBUG; repair the record first "
            "(Health → DEBUG logging left on) — changing where Jen reaches this Kea could leave the old one at DEBUG with no way back."
        )
    entry = record["servers"].get(str(server_id))
    if entry is None or entry.get("removed"):
        return ""
    _audit(
        "INVESTIGATION_LOGGING_ENDPOINT_CHANGE_REFUSED",
        name,
        f"change of {', '.join(changed)} refused while investigation logging is on or owed a restore{by}",
    )
    return (
        f"Investigation logging is on for {name}, or its restore is not finished: turn it off from Servers first. Changing its {', '.join(changed)} now would "
        "point Jen at a different Kea while this one is still at DEBUG."
    )


def forget(server_id, actor: str = "") -> bool:
    """Drop the index entry of a server that was removed from Jen, whose marker was damaged, or whose daemon Jen sees at neither level (or has not been
    able to see for over an hour), after a person put it right by hand. Refuses (False) any other entry: a live server with a readable marker is put
    back with turn_off, never forgotten. Jen LOOKS before it lets go (fixup 4, F5): it refuses while the running Kea is seen at investigation DEBUG,
    reads the config file to check the marker is gone ("I fixed it" is checked, not believed), and writes the audit row only when the entry is
    really gone."""
    with _lock:
        record = _record()
        if record.get("damaged"):
            return False  # nothing in an unreadable record can be forgotten (Q161): it is rebuilt first
        entry = record["servers"].get(str(server_id))
        if not entry:
            return False
        removed = bool(entry.get("removed"))
        damaged = bool(entry.get("marker_invalid"))
        seen_other = entry.get("daemon") == "other" and entry.get("file") == "restored"
        if not (removed or damaged or seen_other or _unconfirmed_for_an_hour(entry)):
            return False
        if not removed:
            server = next((s for s in _ssh_servers() if str(s.get("id")) == str(server_id)), None)
            if server is None:
                return False
            probe = dict(entry)
            state = observe(server, probe)
            if state == "debug":
                return False  # Kea is running investigation DEBUG: put it back, do not forget it
            if seen_other and not damaged and state == "unknown":
                return False  # "left at something else" was an observation; forgetting needs a fresh one
            try:
                cfg, _sha = _host.read_config_versioned(server, "dhcp4")
            except Exception:
                return False
            if not cfg or _edit.investigation_marker(cfg) is not None or _edit.validate_investigation_marker(cfg):
                return False
        if not _drop(record, server_id):
            return False
    _audit(
        "INVESTIGATION_LOGGING_FORGOTTEN",
        entry.get("name") or str(server_id),
        f"restored by hand; entry dropped by {actor or 'an admin'}",
    )
    return True


def _revision_before_on(server_id) -> int | None:
    """The Config history revision a person starts from when the marker is damaged: the one recorded just BEFORE the oldest consecutive
    "investigation logging on" revision - the config as it was before Jen touched the logger. None when there is no such revision."""
    try:
        from jen.services import config_revisions as _rev

        rows = _rev.list_revisions(int(server_id), "dhcp4", limit=200)  # newest first
    except Exception:
        return None
    on = "investigation logging on for"
    i = next((n for n, r in enumerate(rows) if str(r.get("summary") or "").startswith(on)), None)
    if i is None:
        return None
    while i + 1 < len(rows) and str(rows[i + 1].get("summary") or "").startswith(on):
        i += 1
    return rows[i + 1]["id"] if i + 1 < len(rows) else None


def marker_invalid_text(server: dict, entry: dict) -> str:
    """The sentence for a marker Jen will not guess at: shown by turn_off, recorded on the entry for the sweep, and the Health row. It
    finds the Config history revision to start from and keeps it on the entry (the Servers page links it)."""
    entry.setdefault("server_id", str(server.get("id")))
    if not entry.get("history_revision"):
        entry["history_revision"] = _revision_before_on(server.get("id"))
    return (
        f"the investigation-logging marker on {_name(server)} is damaged, so Jen cannot tell what the logger was before and changed "
        f"nothing — {by_hand_damaged(entry)}"
    )


def by_hand_damaged(entry: dict) -> str:
    """What a person does when the marker's own record of the old values is damaged. The marker cannot be the source - it is the thing
    that is damaged - so the guidance goes to Servers -> Config history, to the config as it was before Jen turned the logging on."""
    where = entry.get("kea_conf") or "its kea-dhcp4.conf"
    host = entry.get("ssh_host") or "the Kea host"
    revision = entry.get("history_revision")
    server_id = entry.get("server_id")
    found = (
        f"revision {revision} (Servers → Config history → /servers/{server_id}/config-history/{revision})"
        if revision and server_id
        else "the revision recorded just before the one summarised “investigation logging on” (none is on record for this server — "
        "use a backup of the file instead)"
    )
    return (
        f"Jen no longer knows the logger's original settings. Open Servers → Config history and look at {found}: that is the config "
        f"as it was before the logging went on. Then on {host}, in {where}: in the `kea-dhcp4` entry of Dhcp4 → loggers set severity and "
        "debuglevel back to what that config has (remove a key it does not have; remove the whole entry if it had none), delete the "
        "`jen-investigation` entry under that logger's `user-context`, check the file with Kea's own config test, reload or restart Kea, "
        "then press Forget here"
    )


def by_hand(entry: dict) -> str:
    """The two-line config edit that undoes investigation logging on a server Jen can no longer reach."""
    where = entry.get("kea_conf") or "its kea-dhcp4.conf"
    host = entry.get("ssh_host") or "the Kea host"
    return (
        f"on {host}, in {where}: in the `kea-dhcp4` entry of Dhcp4 → loggers set severity and debuglevel back to what the marker's "
        "`restore` object under `user-context` → `jen-investigation` says (remove a key it records as absent, and remove the whole "
        "entry when it says `created`), delete that `jen-investigation` user-context, then reload or restart Kea"
    )


def _original_text(entry: dict) -> str:
    restore = entry.get("restore")
    if not isinstance(restore, dict) or _edit.restore_problem(restore):
        return "unknown (this entry is from before Jen kept the original)"
    if restore.get("created"):
        return "no `kea-dhcp4` logger entry at all (Jen created it)"
    severity, level = restore.get("severity", "absent"), restore.get("debuglevel", "absent")
    return f"severity {'not set' if severity == 'absent' else severity}, debuglevel {'not set' if level == 'absent' else level}"


def by_hand_daemon(entry: dict) -> str:
    """The config file is already restored but the RUNNING Kea is not: a person makes it re-read the file."""
    where = entry.get("kea_conf") or "its kea-dhcp4.conf"
    host = entry.get("ssh_host") or "the Kea host"
    return (
        f"on {host} run `config-reload` (or restart kea-dhcp4) yourself - the config file {where} is already back as it was "
        f"({_original_text(entry)}) and Kea is still running the DEBUG settings it loaded earlier - then press Forget here once Kea shows its original level"
    )


def by_hand_running(entry: dict) -> str:
    """The running Kea is at neither level: a person looks, sets what they want, and tells Jen."""
    where = entry.get("kea_conf") or "its kea-dhcp4.conf"
    host = entry.get("ssh_host") or "the Kea host"
    return (
        f"Check the `kea-dhcp4` logger on {host}: it was {_original_text(entry)} before. If the running level is not what you want, set it in {where}, "
        "reload or restart Kea, then press Forget here"
    )


# ── the sweep ────────────────────────────────────────────────────────────────


def _ssh_servers() -> list[dict]:
    return [s for s in extensions.KEA_SERVERS or [] if s.get("ssh_host")]


def _file_carries_marker(server: dict) -> bool | None:
    """Does the config file on `server` carry a jen-investigation marker? None when it could not be read - never a guess."""
    try:
        cfg, _sha = _host.read_config_versioned(server, "dhcp4")
    except Exception:
        return None
    if not cfg:
        return None
    return _edit.investigation_marker(cfg) is not None


#: What the last recovery attempt could and could not examine - read by the Health row (v5.68.0-beta.25, Q160). {"at", "problems", "rebuilt"}.
_recovery_status: dict = {"at": "", "problems": [], "rebuilt": None}


def record_banner() -> dict:
    """What the Servers page needs about the record: whether it is unreadable, and what the last rebuild could not examine."""
    status = recovery_status()
    return {"damaged": bool(_record().get("damaged")), "problems": status["problems"], "at": status["at"]}


def recovery_status() -> dict:
    return {
        "at": _recovery_status["at"],
        "problems": list(_recovery_status["problems"]),
        "rebuilt": _recovery_status["rebuilt"],
    }


def _candidate_ready(entry: dict, now: datetime) -> bool:
    """Make a rebuilt entry one `_record` will accept, or say it cannot be (v5.68.0-beta.27, Q162, item 2). The recovery copied an unparseable `until` from
    the marker into the entry; `_valid_entry` rejects it, so the record it wrote read as damaged on the next load and the loop repeated. An unreadable deadline
    is treated as DUE NOW (the entry carries `deadline_malformed` and the ordinary restore finishes it - it is never "no deadline, leave it on"); the
    restore object is kept. Then the entry is validated before it can be written."""
    if _edit._parse_until(entry["until"]) is None:
        entry["until"] = _iso(now)
        entry["deadline_malformed"] = True
    return _valid_entry(entry)


def _recovery_candidates(known: dict, now: datetime) -> tuple[dict, list[str]]:
    """Examine EVERY SSH server - its config file AND its running daemon - into an in-memory candidate record. Nothing is written here. A server whose
    config or whose daemon could not be read is recorded as a problem: it may be the one running DEBUG, so the record is not rebuilt without it.
    Returns (entries by server id, problems)."""
    entries: dict = {}
    problems: list[str] = []
    for sid, server in known.items():
        name = _name(server)
        try:
            cfg, _sha = _host.read_config_versioned(server, "dhcp4")
        except Exception as e:
            problems.append(f"{name}: config unreadable ({type(e).__name__})")
            continue
        if not cfg:
            problems.append(f"{name}: config unreadable")
            continue
        try:
            seen = daemon_logger(server)
        except Exception as e:
            problems.append(f"{name}: running daemon not observed ({type(e).__name__})")
            continue
        if seen is None:
            problems.append(f"{name}: running daemon not observed (Kea's API did not answer)")
            continue
        marker = _edit.investigation_marker(cfg)
        damaged_marker = _edit.validate_investigation_marker(cfg)
        if marker is not None or damaged_marker:
            until = str((marker or {}).get("until") or _iso(now))
            entry = _entry_for(server, until)
            entry["mode"] = "adopted"
            if damaged_marker:
                entry["marker_invalid"] = True
                entry["error"] = marker_invalid_text(server, entry)[:900]
            elif not _edit.restore_problem(marker.get("restore")):
                entry["restore"] = marker["restore"]
            observe_from(entry, seen)
            entry["pending"] = None if entry["daemon"] == "debug" else "reload"
            if not _candidate_ready(entry, now):
                problems.append(f"{name}: its marker cannot be read into a valid entry")
                continue
            entries[sid] = entry
        elif seen["marker"] is not None and _at_investigation_level(seen):
            # the file is clean and the running Kea is at investigation DEBUG: the daemon step is owed, and the NEXT sweep (once the record is healthy)
            # asks for it
            entry = _entry_for(server, str(seen["marker"].get("until") or _iso(now)))
            entry.update(
                file="restored",
                daemon="debug",
                pending="reload",
                mode="adopted",
                observed_at=_iso(now),
                seen=_describe(seen),
            )
            if not _edit.restore_problem(seen["marker"].get("restore")):
                entry["restore"] = seen["marker"]["restore"]
            if not _candidate_ready(entry, now):
                problems.append(f"{name}: its marker cannot be read into a valid entry")
                continue
            entries[sid] = entry
    return entries, problems


def acknowledge_damaged(actor: str, *, all_subnets: bool = False) -> bool:
    """A person's decision that the unreadable record may be replaced by an empty one (v5.68.0-beta.26, Q161, item 2). Allowed only for an admin with
    access to every subnet (the caller says so), only while the record is damaged, and only when the last rebuild recorded something it could not examine
    - there is a thing a person had to decide about. The old value is kept in `investigation_logging.damaged`, an EMPTY record is written, the problems
    and the actor go into the audit row, and the recovery status is cleared. Returns True when the record was replaced."""
    if not all_subnets:
        return False
    from jen.models import user as _user

    with _lock:
        # re-read under the lock (v5.68.0-beta.27, Q162, item 3): a second concurrent call sees a healthy record and returns False
        record = _record()
        problems = list(_recovery_status["problems"])
        if not record.get("damaged") or not problems:
            return False
        # the old value first, once - as `_save` does - and nothing is overwritten if it cannot be kept
        if (
            record.get("raw")
            and not _user.get_global_setting(DAMAGED_KEY, "")
            and _user.set_global_setting(DAMAGED_KEY, record["raw"]) is False
        ):
            return False
        # the empty record AND the audit row are ONE transaction: the decision is on record or it did not happen. `_audit` is not used on this path.
        if not _user.set_global_setting_and_audit(
            RECORD_KEY,
            "",
            "INVESTIGATION_LOGGING_RECORD_ACKNOWLEDGED",
            actor or "an admin",
            "replaced Jen's unreadable record of investigation logging with an empty one; could not be examined: "
            + "; ".join(problems),
        ):
            return False
        _recovery_status.update(at="", problems=[], rebuilt=None)
    return True


def _recover(record: dict, known: dict, now: datetime, summary: dict) -> dict:
    """The damaged-index recovery (v5.68.0-beta.25, Q160, items 1 and 2): a SEPARATE phase that writes nothing until it is complete. beta.24 rebuilt the
    record inside the ordinary full scan, where every discovery was written at once and the first write cleared the damaged flag - one adopted server
    plus one unreadable server left the index healthy with one entry, and the unreadable server may have been the one at DEBUG 55; and a clean file whose
    daemon could not be read counted as examined. Now every server's file and daemon are examined into a candidate; if any could not be, NOTHING is
    written and the record stays damaged (turn-on refused, Health naming the server, the next minute's sweep trying again); if all were, ONE `_save`
    stores the candidate, keeping the old value in `investigation_logging.damaged` first."""
    no_ssh = [
        f"{_name(s)}: no SSH, so its file and daemon cannot be examined"
        for s in (extensions.KEA_SERVERS or [])
        if not s.get("ssh_host")
    ]
    if not known:
        # v5.68.0-beta.26 (Q161, item 2): with no SSH server there is nothing to examine, and "nothing examined" used to read as "nothing found": the
        # damaged value was replaced by an empty healthy record. It stays damaged until a PERSON says (acknowledge_damaged).
        problems = ["no Kea server with SSH is configured, so nothing could be examined"] + no_ssh
        _recovery_status.update(at=_iso(now), problems=problems, rebuilt=False)
        summary["errors"].extend(problems)
        return summary
    entries, problems = _recovery_candidates(known, now)
    problems = problems + no_ssh  # a half-configured server (no ssh_host) holds the damaged state too
    if not problems and not all(_valid_entry(e) for e in entries.values()):
        problems = [
            "a rebuilt entry failed validation, so the record was not written"
        ]  # belt and braces: the write below is the one that counts
    if problems:
        _recovery_status.update(at=_iso(now), problems=problems, rebuilt=False)
        summary["errors"].extend(problems)
        return summary
    final = {"servers": entries, "damaged": True, "raw": record["raw"]}
    if not _save(final):
        note = "the rebuilt record could not be stored"
        _recovery_status.update(at=_iso(now), problems=[note], rebuilt=False)
        summary["errors"].append(
            "Jen's record of investigation logging could not be rebuilt (its database did not take the write)"
        )
        return summary
    _recovery_status.update(at=_iso(now), problems=[], rebuilt=True)
    for entry in entries.values():
        summary["adopted"].append(entry["name"])
        _audit(
            "INVESTIGATION_LOGGING_ADOPTED",
            entry["name"],
            "found while rebuilding Jen's unreadable record of investigation logging (until " + entry["until"] + ")",
        )
    return summary


def sweep(now: datetime | None = None, full: bool = False) -> dict:
    """Restore every expired investigation marker, and finish every restore that left the daemon behind. The cheap path looks only at
    the index; `full=True` also reads every SSH server's config (so a marker this Jen did not index - another Jen, a restored
    database, a person - is restored when expired and indexed when live). A failed restore keeps its index entry (with the error, which
    the Health row shows) and is retried next minute. An entry whose server is no longer in Jen is KEPT, marked removed: Jen can no
    longer reach it, and the Health row says how to restore it by hand.
    Returns {"restored": [names], "adopted": [names], "errors": [text]}."""
    now = now or _now()
    summary = {"restored": [], "adopted": [], "errors": []}
    with _lock:
        record = _record()
        known = {str(s.get("id")): s for s in _ssh_servers()}
        if record.get("damaged"):
            # a damaged record is a STOP: nothing else runs (no restores, no cheap-path observation, no orphan marking) until it has been rebuilt from
            # the servers; those run on the next minute's sweep, once the record is healthy (v5.68.0-beta.25, Q160)
            return _recover(record, known, now, summary)
        due = [
            (sid, known[sid])
            for sid, entry in record["servers"].items()
            if sid in known
            and (entry.get("file") == "restored" or (_edit._parse_until(entry.get("until")) or now) <= now)
        ]
        for sid, entry in record["servers"].items():
            if sid not in known and not entry.get("removed"):
                entry["removed"] = True
                entry["error"] = (
                    f"{entry.get('name') or 'This server'} was removed from Jen while investigation logging was on; "
                    "Jen cannot put its log level back"
                )
                _audit(
                    "INVESTIGATION_LOGGING_ORPHANED",
                    entry.get("name") or sid,
                    "its server was removed from Jen with the log level not restored",
                )
                if not _save(record):
                    logger.warning(
                        "investigation_logging: the removed-server flag for %s could not be stored",
                        entry.get("name") or sid,
                    )
        scanned = {sid for sid, _s in due}
        # v5.68.0-beta.23 (Q158): an entry whose daemon state is not KNOWN (a reload that said ok and could not be read back, a daemon seen at
        # something else) is looked at again every minute - one config-get - so the Health row says "unconfirmed" only for as long as it is true
        for sid, entry in record["servers"].items():
            if (
                sid in known
                and sid not in scanned
                and entry.get("file", "debug") == "debug"
                and entry.get("daemon") in ("unknown", "other")
                and not entry.get("marker_invalid")
            ):
                before = (entry.get("daemon"), entry.get("pending"), entry.get("file"))
                state = observe(known[sid], entry)
                carries = _file_carries_marker(known[sid])
                if carries is False:
                    # the STORED entry says the file carries DEBUG and it does not (a write after a lost reply was never stored): the file is the
                    # truth - the entry becomes "file restored", the restore path above finishes it next minute (fixup 4, F4)
                    entry["file"] = "restored"
                    entry["pending"] = entry.get("pending") or "reload"
                elif state == "debug" and carries is True:
                    entry["pending"] = None
                if (entry.get("daemon"), entry.get("pending"), entry.get("file")) != before and not _put(
                    record, sid, entry
                ):
                    logger.warning(
                        "investigation_logging: the observed state of %s could not be stored", entry.get("name") or sid
                    )
        if full:
            for sid, server in known.items():
                if sid in scanned:
                    continue
                try:
                    cfg, _sha = _host.read_config_versioned(server, "dhcp4")
                except Exception as e:
                    summary["errors"].append(f"{server.get('name')}: could not read its config ({type(e).__name__})")
                    continue
                # v5.68.0-beta.14 (Q149): every marker the scan reads is validated NOW, not at its deadline. A damaged one is
                # indexed (or its entry marked) damaged at once - Health red, the by-hand text, the DEBUG left exactly as it is
                problem = _edit.validate_investigation_marker(cfg) if cfg else ""
                if problem:
                    entry = record["servers"].get(sid) or _entry_for(server, _iso(now))
                    first_time = not entry.get("marker_invalid")
                    entry["marker_invalid"] = True
                    entry["error"] = marker_invalid_text(server, entry)[:900]
                    _put(record, sid, entry)
                    if first_time:
                        summary["errors"].append(
                            f"{_name(server)}: the investigation-logging marker is damaged ({problem})"
                        )
                        _audit(
                            "INVESTIGATION_LOGGING_MARKER_DAMAGED",
                            _name(server),
                            f"the marker's own record of the old log level is unreadable ({problem}); Jen changed nothing",
                        )
                    continue
                marker = _edit.investigation_marker(cfg) if cfg else None
                if not marker:
                    # v5.68.0-beta.23 (Q158): the FILE is clean. The scan reads the DAEMON too - a running logger at DEBUG carrying the
                    # jen-investigation marker with no entry is the "file restored, daemon DEBUG, nothing owed" state a lost reload reply used
                    # to leave, whatever caused it. It is indexed with the daemon step owed and finished below (reload, then the documented
                    # restart), and the daemon is observed again afterwards.
                    seen = daemon_logger(server)
                    if (
                        record["servers"].get(sid) is None
                        and seen is not None
                        and seen["marker"] is not None
                        and _at_investigation_level(seen)
                    ):
                        entry = _entry_for(server, str(seen["marker"].get("until") or _iso(now)))
                        entry.update(file="restored", daemon="debug", pending="reload", mode="adopted")
                        entry["observed_at"], entry["seen"] = _iso(now), _describe(seen)
                        if not _edit.restore_problem(seen["marker"].get("restore")):
                            entry["restore"] = seen["marker"]["restore"]
                        if not _put(record, sid, entry):
                            logger.warning(
                                "investigation_logging: the adopted entry for %s could not be stored", _name(server)
                            )
                        summary["adopted"].append(_name(server))
                        _audit(
                            "INVESTIGATION_LOGGING_ADOPTED",
                            _name(server),
                            "the running Kea was at investigation DEBUG with its config file already clean; Jen is asking it to re-read the file",
                        )
                        due.append((sid, server))
                    continue
                held = record["servers"].get(sid)
                if held and held.get("marker_invalid"):
                    # a person repaired the marker by hand: it reads again, so the entry stops saying it is damaged
                    held.pop("marker_invalid", None)
                    held.pop("error", None)
                    _put(record, sid, held)
                if (_edit._parse_until(marker.get("until")) or now) <= now:
                    due.append((sid, server))
                elif sid not in record["servers"]:
                    entry = _entry_for(server, marker["until"])
                    entry["mode"] = "adopted"
                    if not _edit.restore_problem(marker.get("restore")):
                        entry["restore"] = marker["restore"]
                    observe(server, entry)
                    entry["pending"] = None if entry["daemon"] == "debug" else "reload"
                    if not _put(record, sid, entry):
                        logger.warning(
                            "investigation_logging: the adopted entry for %s could not be stored", _name(server)
                        )
                    summary["adopted"].append(_name(server))
                    _audit(
                        "INVESTIGATION_LOGGING_ADOPTED",
                        _name(server),
                        f"found a live investigation-logging marker (until {marker['until']}) that this Jen had not indexed",
                    )
        for sid, server in due:
            name = _name(server)
            outcome = _restore(server, record, now, "investigation logging expired: log level put back")
            if outcome["ok"]:
                summary["restored"].append(name)
                _audit("INVESTIGATION_LOGGING_OFF", name, f"expired; restored by the sweep ({outcome['mode']})")
            else:
                text = (outcome["lines"] or ["restore failed"])[-1]
                entry = record["servers"].get(sid)
                if (
                    entry is None
                ):  # e.g. a marker found by the full scan whose restore failed: index it so the Health row sees it
                    entry = _entry_for(server, _iso(now))
                    entry["error"] = text[:300]
                    _put(record, sid, entry)
                summary["errors"].append(f"{name}: {text}")
    return summary


def run_sweep_job() -> dict:
    """What the one-minute scheduler job calls: a full scan every FULL_SCAN_EVERY-th run, the cheap path otherwise."""
    _runs["n"] += 1
    # a damaged record is rebuilt by a full read of every server on EVERY tick until it is healthy again (v5.68.0-beta.25, Q160), not every tenth
    damaged = _record().get("damaged")
    return sweep(full=bool(damaged) or (_runs["n"] % FULL_SCAN_EVERY == 1))
