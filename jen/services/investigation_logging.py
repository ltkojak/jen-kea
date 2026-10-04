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
            }
        )
    return sorted(out, key=lambda e: e["until"])


# ── applying a change to ONE server ──────────────────────────────────────────


def _supports_reload(server: dict) -> bool:
    reply = _kea.kea_command("list-commands", server=server)
    return reply.get("result") == 0 and "config-reload" in (reply.get("arguments") or [])


def _apply(server: dict, mutate_fn, summary: str, unsupported: str) -> dict:
    """Write one mutation to ONE server through apply_change and make the daemon take it - `config-reload` when it has it, a
    restart otherwise (or when the reload is refused). Returns {"ok", "mode": "reload"|"restart"|"nothing"|"", "lines": [...]}."""
    use_reload = _supports_reload(server)
    result = _changeset.apply_change(
        "dhcp4",
        mutate_fn,
        summary,
        servers=[server],
        restart=not use_reload,
        code_messages={"unsupported": unsupported},
    )
    lines = [text for _kind, text in result.lines]
    if result.status == "nothing":
        return {"ok": True, "mode": "nothing", "lines": lines}
    if result.status != "ok":
        return {"ok": False, "mode": "", "lines": lines}
    if not use_reload:
        return {"ok": True, "mode": "restart", "lines": lines + ["Kea has no config-reload here, so it was restarted."]}
    reply = _kea.kea_command("config-reload", server=server)
    if reply.get("result") == 0:
        return {"ok": True, "mode": "reload", "lines": lines + ["Kea re-read its config without a restart."]}
    refused = reply.get("text") or "refused"
    restarted = _host.service_action(server, "dhcp4", "restart")
    if restarted.get("ok"):
        return {
            "ok": True,
            "mode": "restart",
            "lines": lines + [f"config-reload was refused ({refused}), so Kea was restarted instead."],
        }
    return {
        "ok": False,
        "mode": "",
        "lines": lines
        + [
            f"❌ The config was written but Kea did not take it: config-reload was refused ({refused}) and the restart failed "
            f"({restarted.get('detail', 'no detail')}). The daemon is still running on its previous settings."
        ],
    }


def _audit(action: str, server_name: str, detail: str) -> None:
    try:
        from jen.models import user as _user

        _user.audit(action, server_name, detail)
    except Exception as e:  # an audit failure must not undo a log level
        logger.debug(f"investigation_logging: audit failed: {e}")


# ── turn on / off ────────────────────────────────────────────────────────────


def turn_on(server: dict, minutes: int, actor: str = "") -> dict:
    """Investigation logging on `server` for `minutes` (one of DURATIONS), through apply_change. Refused while ANOTHER server has
    it on (one at a time per Jen). Returns {"ok", "mode", "lines", "until"}."""
    if minutes not in DURATIONS:
        return {"ok": False, "mode": "", "lines": [f"Choose {', '.join(map(str, DURATIONS))} minutes."], "until": ""}
    name = server.get("name") or server.get("ssh_host") or f"Server {server.get('id')}"
    with _lock:
        record = _record()
        others = [e["name"] for sid, e in record["servers"].items() if str(sid) != str(server.get("id"))]
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
        outcome = _apply(
            server,
            lambda cfg: _edit.set_investigation_logging(cfg, until),
            f"investigation logging on for {minutes} min",
            "this config has no Dhcp4 section to log from",
        )
        if outcome["ok"] and outcome["mode"] != "nothing":
            record["servers"][str(server.get("id"))] = {
                "name": name,
                "until": until,
                "by": actor,
                "mode": outcome["mode"],
            }
            _save(record)
            _audit("INVESTIGATION_LOGGING_ON", name, f"DEBUG 55 until {until} ({outcome['mode']})")
        outcome["until"] = until if outcome["ok"] else ""
        return outcome


def turn_off(server: dict, actor: str = "", reason: str = "investigation logging off") -> dict:
    """Put `server`'s logger back now. Returns {"ok", "mode", "lines"}; the index entry is dropped only when the restore worked."""
    name = server.get("name") or server.get("ssh_host") or f"Server {server.get('id')}"
    with _lock:
        outcome = _apply(server, lambda cfg: _edit.clear_investigation_logging(cfg), reason, "")
        record = _record()
        if outcome["ok"]:
            if record["servers"].pop(str(server.get("id")), None) is not None:
                _save(record)
            _audit("INVESTIGATION_LOGGING_OFF", name, f"{reason} ({outcome['mode']}) by {actor or 'the sweep'}")
        return outcome


# ── the sweep ────────────────────────────────────────────────────────────────


def _ssh_servers() -> list[dict]:
    return [s for s in extensions.KEA_SERVERS or [] if s.get("ssh_host")]


def sweep(now: datetime | None = None, full: bool = False) -> dict:
    """Restore every expired investigation marker. The cheap path looks only at the index; `full=True` also reads every SSH server's
    config (so a marker this Jen did not index - another Jen, a restored database, a person - is restored when expired and indexed
    when live). A failed restore keeps its index entry (with the error, which the Health row shows) and is retried next minute.
    Returns {"restored": [names], "adopted": [names], "errors": [text]}."""
    now = now or _now()
    summary = {"restored": [], "adopted": [], "errors": []}
    with _lock:
        record = _record()
        known = {str(s.get("id")): s for s in _ssh_servers()}
        changed = False
        due = [
            (sid, known[sid])
            for sid, entry in record["servers"].items()
            if sid in known and (_edit._parse_until(entry.get("until")) or now) <= now
        ]
        gone = [sid for sid in record["servers"] if sid not in known]
        for sid in gone:  # a server that was removed from Jen has nothing for Jen to restore
            record["servers"].pop(sid)
            changed = True
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
                marker = _edit.investigation_marker(cfg) if cfg else None
                if not marker:
                    continue
                if (_edit._parse_until(marker.get("until")) or now) <= now:
                    due.append((sid, server))
                elif sid not in record["servers"]:
                    record["servers"][sid] = {
                        "name": server.get("name") or f"Server {sid}",
                        "until": marker["until"],
                        "by": "",
                        "mode": "adopted",
                    }
                    summary["adopted"].append(server.get("name") or sid)
                    changed = True
        for sid, server in due:
            name = server.get("name") or f"Server {sid}"
            outcome = _apply(
                server,
                lambda cfg: _edit.clear_investigation_logging(cfg, now=now),
                "investigation logging expired: log level put back",
                "",
            )
            if outcome["ok"]:
                record["servers"].pop(sid, None)
                summary["restored"].append(name)
                _audit("INVESTIGATION_LOGGING_OFF", name, f"expired; restored by the sweep ({outcome['mode']})")
            else:
                text = (outcome["lines"] or ["restore failed"])[-1]
                record["servers"].setdefault(sid, {"name": name, "until": _iso(now), "by": "", "mode": ""})["error"] = (
                    text[:300]
                )
                summary["errors"].append(f"{name}: {text}")
            changed = True
        if changed:
            _save(record)
    return summary


def run_sweep_job() -> dict:
    """What the one-minute scheduler job calls: a full scan every FULL_SCAN_EVERY-th run, the cheap path otherwise."""
    _runs["n"] += 1
    return sweep(full=(_runs["n"] % FULL_SCAN_EVERY == 1))
