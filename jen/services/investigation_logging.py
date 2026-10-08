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
"""

from __future__ import annotations

import json
import logging
import threading
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
_lock = threading.Lock()
_runs = {"n": 0}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).isoformat(timespec="seconds")


# ── the index of what this Jen knows is on ───────────────────────────────────


def _record() -> dict:
    from jen.models import user as _user

    try:
        data = json.loads(_user.get_global_setting(RECORD_KEY, "") or "{}")
    except ValueError:
        data = {}
    servers = data.get("servers") if isinstance(data, dict) else None
    return {"servers": servers if isinstance(servers, dict) else {}}


def _save(record: dict) -> None:
    from jen.models import user as _user

    _user.set_global_setting(RECORD_KEY, json.dumps(record) if record["servers"] else "")


def active(now: datetime | None = None) -> list[dict]:
    """What is on, for the banners and the Health row: [{server_id, name, until, remaining_s, overdue, error}], soonest first."""
    now = now or _now()
    out = []
    for sid, entry in _record()["servers"].items():
        due = _edit._parse_until(entry.get("until"))
        remaining = int((due - now).total_seconds()) if due else -1
        out.append(
            {
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
                "file": entry.get("file", "debug"),
                "daemon": entry.get("daemon", "debug"),
                "pending": entry.get("pending"),
                "removed": bool(entry.get("removed")),
                "ssh_host": entry.get("ssh_host", ""),
                "kea_conf": entry.get("kea_conf", ""),
                # a restore that cleaned the file but left the daemon at DEBUG 55 is the failure this module exists to prevent
                "stuck": entry.get("file") == "restored" and entry.get("daemon") != "restored",
            }
        )
    return sorted(out, key=lambda e: e["until"])


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


def _daemon_step(server: dict, use_reload: bool) -> dict:
    """Step 2: make the daemon re-read its file - `config-reload` when the daemon has it, a restart otherwise or when the reload is
    refused. Returns {"ok", "mode": "reload"|"restart"|"", "lines": [...]}."""
    if use_reload:
        reply = _kea.kea_command("config-reload", server=server)
        if reply.get("result") == 0:
            return {"ok": True, "mode": "reload", "lines": ["Kea re-read its config without a restart."]}
        refused = reply.get("text") or "refused"
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


def _put(record: dict, sid, entry: dict) -> None:
    record["servers"][str(sid)] = entry
    _save(record)


def _drop(record: dict, sid) -> None:
    if record["servers"].pop(str(sid), None) is not None:
        _save(record)


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


def turn_on(server: dict, minutes: int, actor: str = "") -> dict:
    """Investigation logging on `server` for `minutes` (one of DURATIONS), through apply_change. Refused while ANOTHER server has
    it on (one at a time per Jen). Returns {"ok", "mode", "lines", "until"}."""
    if minutes not in DURATIONS:
        return {"ok": False, "mode": "", "lines": [f"Choose {', '.join(map(str, DURATIONS))} minutes."], "until": ""}
    name = _name(server)
    sid = str(server.get("id"))
    with _lock:
        record = _record()
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
        result, use_reload, _support = _change(
            server,
            lambda cfg: _edit.set_investigation_logging(cfg, until),
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

        if result.status == "rollback_failed":
            # the change set could not put the file back after a failed restart: the file may carry the marker and the daemon is
            # in an unknown state - take responsibility for it rather than forgetting it
            entry.update(daemon="unknown", pending="restart", error=(lines[-1] if lines else "rollback failed")[:300])
            _put(record, sid, entry)
            return {"ok": False, "mode": "", "lines": lines, "until": ""}
        if result.status != "ok":
            return {"ok": False, "mode": "", "lines": lines, "until": ""}

        if not use_reload:  # the change set restarted the daemon: file and daemon moved together
            entry.update(daemon="debug", pending=None, mode="restart")
            _put(record, sid, entry)
            _audit("INVESTIGATION_LOGGING_ON", name, f"DEBUG 55 until {until} (restart)")
            return {
                "ok": True,
                "mode": "restart",
                "lines": lines + ["Kea has no config-reload here, so it was restarted."],
                "until": until,
            }

        # The file now carries DEBUG 55: Jen is responsible for it from this moment, so the entry is saved BEFORE the daemon is asked.
        entry.update(daemon="unknown", pending="reload")
        _put(record, sid, entry)
        step = _daemon_step(server, use_reload=True)
        if step["ok"]:
            entry.update(daemon="debug", pending=None, mode=step["mode"])
            _put(record, sid, entry)
            _audit("INVESTIGATION_LOGGING_ON", name, f"DEBUG 55 until {until} ({step['mode']})")
            return {"ok": True, "mode": step["mode"], "lines": lines + step["lines"], "until": until}
        # the daemon did not take it: put the file straight back (the daemon never moved, so nothing else is owed)
        restored, revert_lines = _revert_file(server, "investigation logging on failed: log level put back")
        if restored:
            _drop(record, sid)
            return {"ok": False, "mode": "", "lines": lines + revert_lines + step["lines"], "until": ""}
        note = "❌ The config file still carries the DEBUG marker and could not be put back; Jen keeps trying every minute."
        entry.update(daemon="unknown", pending="reload", error=note[:300])
        _put(record, sid, entry)
        return {"ok": False, "mode": "", "lines": lines + revert_lines + step["lines"] + [note], "until": ""}


def _restore(server: dict, record: dict, now: datetime | None, summary: str) -> dict:
    """Put `server`'s logger back and make the daemon take it. `now=None` restores unconditionally (the button); a datetime
    restores only what is due (the sweep). The entry is dropped only when the file AND the daemon are both restored. Returns
    {"ok", "mode", "lines"}; caller holds the lock."""
    sid = str(server.get("id"))
    entry = record["servers"].get(sid)
    result, use_reload, support = _change(
        server, lambda cfg: _edit.clear_investigation_logging(cfg, now=now), summary, ""
    )
    lines = [text for _kind, text in result.lines]
    if result.status == "aborted" and result.last_code == "marker-invalid":
        # v5.68.0-beta.13 (Q148): the marker's restore object is missing or malformed. Nothing was written (the change set aborted before
        # any write), the entry is KEPT so the Health row and the Servers page keep saying so, and a person is told how to finish it.
        entry = entry or _entry_for(server, _iso(now or _now()))
        text = marker_invalid_text(server, entry)
        entry.update(marker_invalid=True, error=text[:900])
        _put(record, sid, entry)
        return {"ok": False, "mode": "", "lines": [f"❌ {text}"]}
    if result.status == "ok":
        if not use_reload:  # the change set restarted the daemon: both steps done
            _drop(record, sid)
            why = (
                f"{_unreachable_note(server)}, so Kea was restarted to take the restore (DEBUG 55 has to come off)."
                if support == "unknown"
                else "Kea has no config-reload here, so it was restarted."
            )
            return {"ok": True, "mode": "restart", "lines": lines + [why]}
        # the file is clean, the daemon still at DEBUG: say so in the index before the daemon is asked
        entry = entry or _entry_for(server, _iso(now or _now()))
        entry.pop("error", None)
        entry.update(file="restored", daemon="debug", pending="reload")
        _put(record, sid, entry)
    elif result.status == "nothing":
        # no marker in the file: nothing to write. The daemon may still be at DEBUG - the very case a forgotten reload leaves.
        if entry is None or entry.get("daemon") == "restored":
            _drop(record, sid)
            return {"ok": True, "mode": "nothing", "lines": lines}
        entry.pop("error", None)
        entry.update(file="restored", pending=entry.get("pending") or "reload")
        _put(record, sid, entry)
    else:
        if entry is not None:
            entry["error"] = (lines[-1] if lines else "restore failed")[:300]
            _put(record, sid, entry)
        return {"ok": False, "mode": "", "lines": lines}
    reload_now = _reload_support(server)
    step = _daemon_step(server, use_reload=entry.get("pending") != "restart" and reload_now == "yes")
    if step["ok"]:
        _drop(record, sid)
        why = (
            [f"{_unreachable_note(server)}, so Kea was restarted to take the restore (DEBUG 55 has to come off)."]
            if reload_now == "unknown" and step["mode"] == "restart"
            else []
        )
        return {"ok": True, "mode": step["mode"], "lines": lines + step["lines"] + why}
    entry.update(
        daemon="debug",
        pending="reload" if _reload_support(server) == "yes" else "restart",
        error=step["lines"][-1][:300],
    )
    _put(record, sid, entry)
    return {"ok": False, "mode": "", "lines": lines + step["lines"]}


def turn_off(server: dict, actor: str = "", reason: str = "investigation logging off") -> dict:
    """Put `server`'s logger back now. Returns {"ok", "mode", "lines"}; the index entry is dropped only when the file AND the daemon
    are restored, so a restore the daemon did not take is retried by the sweep."""
    name = _name(server)
    with _lock:
        record = _record()
        outcome = _restore(server, record, None, reason)
        if outcome["ok"]:
            _audit("INVESTIGATION_LOGGING_OFF", name, f"{reason} ({outcome['mode']}) by {actor or 'the sweep'}")
        return outcome


def blocking_removal(server_ids) -> list[dict]:
    """The index entries of the servers in `server_ids` (ints or strings) - investigation logging is on there, or a restore is
    still owed - for the settings routes that would stop Jen from reaching them. Removing such a server is refused until turn_off
    succeeds: Jen would otherwise lose the only way it has to put the log level back."""
    wanted = {str(i) for i in server_ids}
    return [{"server_id": sid, **entry} for sid, entry in _record()["servers"].items() if sid in wanted]


def removal_refusal(server_ids, actor: str = "") -> str:
    """ "" when none of `server_ids` has an index entry, else the sentence a settings route flashes (and an audit row is written)."""
    blocked = blocking_removal(server_ids)
    if not blocked:
        return ""
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


def forget(server_id, actor: str = "") -> bool:
    """Drop the index entry of a server that was removed from Jen, or whose marker was damaged, after a person put it back by hand.
    Refuses (False) any other entry: a live server with a readable marker is put back with turn_off, never forgotten. A damaged one on
    a server Jen can still reach is forgotten only once its config no longer carries a `jen-investigation` marker at all (v5.68.0-beta.14,
    Q149) - Jen reads the file to find out, so "I fixed it" is checked, not believed."""
    with _lock:
        record = _record()
        entry = record["servers"].get(str(server_id))
        if not entry or not (entry.get("removed") or entry.get("marker_invalid")):
            return False
        if not entry.get("removed"):
            server = next((s for s in _ssh_servers() if str(s.get("id")) == str(server_id)), None)
            if server is None:
                return False
            try:
                cfg, _sha = _host.read_config_versioned(server, "dhcp4")
            except Exception:
                return False
            if not cfg or _edit.investigation_marker(cfg) is not None or _edit.validate_investigation_marker(cfg):
                return False
        _drop(record, server_id)
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


# ── the sweep ────────────────────────────────────────────────────────────────


def _ssh_servers() -> list[dict]:
    return [s for s in extensions.KEA_SERVERS or [] if s.get("ssh_host")]


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
                _save(record)
        scanned = {sid for sid, _s in due}
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
                    _put(record, sid, entry)
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
    return sweep(full=(_runs["n"] % FULL_SCAN_EVERY == 1))
