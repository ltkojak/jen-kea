"""
jen/services/kea_transport_switch.py
────────────────────────────────────
Q212 (BB8) - the switch of a server's configuration transport, in both directions, as a short transaction with preconditions, a baseline and a result line. There is no data to convert: the
configuration lives in the daemon on either transport and the revision store keeps every kind. `api | file | off`, six transitions:

    file -> api, off -> api   the probe passed and is fresh (it is run HERE, now), no include, the file and the daemon agree (or a named consent to discard the file's edit), the daemon may write its
                              file, the operator has been told that comments and key order go, an endpoint with no authentication has its own confirmation; then ONE `config-write` makes the file the
                              daemon's configuration in Kea's own form, `config-get` is recorded as a `kea`-kind baseline (`source="switch"`) and the setting is written.
    api -> file, off -> file  SSH and the helper are there and the file and the daemon AGREE (a `config-write` is sent first, best effort, to make them so: a daemon never granted the write must still be
                              able to leave `api`); a `raw` baseline is recorded from the file and the setting is written.
    * -> off                  the setting and nothing else: the daemon keeps serving and Jen stops writing.

The switch takes the same lock a change takes (`kea_changeset.change_lock`), so a set past its Plan completes on the transport it planned with and the next set sees the new one.
"""

from __future__ import annotations

import logging

from jen.services import config_revisions as _rev
from jen.services import kea_api_config as _api
from jen.services import kea_changeset as _cs
from jen.services import kea_host as _host
from jen.services import write_mode as _words

logger = logging.getLogger(__name__)

PROBE_FRESH_SECONDS = 300
SERVICE = "dhcp4"


def section_for(server: dict) -> str:
    """The config section a server's settings live in: `[kea]` for the primary, `[kea_server_N]` for the rest."""
    return "kea" if server.get("id") == 1 else f"kea_server_{server.get('id')}"


def _refuse(text: str, **extra) -> dict:
    return {"ok": False, "level": "error", "line": text, **extra}


def _done(text: str, **extra) -> dict:
    return {"ok": True, "level": "success", "line": text, **extra}


def _short(digest) -> str:
    return str(digest or "unknown")[:12]


def _write_guard(server: dict, name: str, live: dict | None) -> str:
    """A refusal sentence when a `config-write` of what the daemon runs must not be sent now, else "" (Q216 AA10/AA16): the switch's two `config-write` calls ask the same two questions every other
    writer of this server's file asks first - INV-005 (a write that would erase the investigation marker) and the host's restore window (BB9 d)."""
    from jen.services import investigation_logging as _inv

    refusal = _host.guard_kea_write(server, live or {}, SERVICE)
    if refusal:
        return f"{name}: {refusal}; nothing was changed"
    window = _inv.restore_window(server)
    if window:
        return f"{name}: {window}; nothing was changed"
    return ""


def _to_api(server: dict, current: str, consents: set, actor: str) -> dict:
    name = server.get("name") or f"Server {server.get('id')}"
    sid = server.get("id")
    unreadable = _api.record_unreadable(server, SERVICE)
    if unreadable:
        return _refuse(f"{name}: {unreadable}; nothing was changed")
    facts = _api.probe(server, SERVICE)  # the facts, now: the stored result a switch relies on is fresh by construction
    has_ssh = bool(server.get("ssh_host"))
    # THE one definition of "the operator's consents cover the facts" (Q216 AA1), shared with `probe(consent=True)` and the gate
    gap, needs = _api.consent_gap(name, facts, consents, has_ssh=has_ssh)
    if gap:
        return _refuse(gap, **({"needs": needs} if needs else {}))
    live, _digest, why = _api._get(server, SERVICE)
    if live is None:
        return _refuse(f"{name}: the daemon did not answer before the write ({why}); nothing was switched")
    blocked = _write_guard(server, name, live)
    if blocked:
        return _refuse(blocked)
    wrote = _api.write_file(server, SERVICE)
    if not wrote["ok"]:
        _api.remember_refusal(server, wrote.get("detail", ""))
        return _refuse(
            f"{name}: the daemon refused to write its file ({wrote.get('detail') or 'no answer'}); nothing was switched"
        )
    cfg, digest, why = _api._get(server, SERVICE)
    if cfg is None:
        return _refuse(
            f"{name}: the daemon did not confirm its configuration after the write ({why}); nothing was switched"
        )
    revision = (
        _rev.record(
            sid,
            SERVICE,
            cfg,
            digest,
            f"transport switched {current} -> api by {actor}",
            hash_kind="kea",
            source="switch",
        )
        if sid is not None
        else None
    )
    # the operator's consent is on record from this moment: the gate in `apply` reads it
    stored = _api.stored_probe(sid) or facts
    stored["consented_at"] = _api._now_iso()
    stored["consents"] = sorted(set(consents) & set(_api.CONSENTS))
    stored.pop("consent_refused", None)
    _api.store_probe(sid, stored)
    verb = (
        "consent recorded for Live API" if current == "api" else "switched to Live API"
    )  # (Q217, second pass row 2) a server already in Live API records a consent in place
    return _done(
        f"{name}: {verb}; Kea rendered its file; revision #{revision} is the baseline"
        if revision
        else f"{name}: {verb}; Kea rendered its file",
        revision=revision,
    )


def _to_file(server: dict, current: str, consents: set, actor: str) -> dict:
    name = server.get("name") or server.get("ssh_host") or "the server"
    sid = server.get("id")
    if not server.get("ssh_host"):
        return _refuse(f"{name}: File over SSH needs an SSH host (Settings → Kea → SSH); nothing was changed")
    unreadable = _api.record_unreadable(server, SERVICE)
    if unreadable:
        return _refuse(f"{name}: {unreadable}; nothing was changed")
    file_cfg, raw = _host.read_config_versioned(server, SERVICE, capture=False)
    if file_cfg is None:
        return _refuse(
            f"{name}: the file on the host could not be read (is the helper installed? Settings → Kea → SSH); nothing was changed"
        )
    live, digest, why = _api._get(server, SERVICE)
    if live is not None and not _api.compare(server, SERVICE, file_cfg, live)[0]:
        # (fix row 5) compare FIRST: the file carries something the daemon does not run (a hand edit, or a change the daemon never wrote). Overwriting it is a named consent; a daemon that was never
        # granted the write (so `config-write` is refused) still leaves `api` once they agree, and the compare decides again after the best-effort write
        if "discard_file_edit" not in consents:
            return _refuse(
                f"{name}: the file and the daemon differ (the daemon {_short(digest)}, the file {_short(raw)}); they must agree before the file becomes the thing Jen edits - restart Kea there, restore from Config history, or tick 'discard the file's edit' to overwrite it with what the daemon runs",
                needs="discard_file_edit",
                before_hash=digest,
                after_hash=raw,
            )
        blocked = _write_guard(server, name, live)
        if blocked:
            return _refuse(blocked)
        _api.write_file(server, SERVICE)
        file_cfg, raw = _host.read_config_versioned(server, SERVICE, capture=False)
        if file_cfg is None or not _api.compare(server, SERVICE, file_cfg, live)[0]:
            return _refuse(
                f"{name}: the file still differs from the daemon after the write was tried (the daemon {_short(digest)}, the file {_short(raw)}); nothing was changed",
                before_hash=digest,
                after_hash=raw,
            )
    elif live is None and current == "api":
        return _refuse(
            f"{name}: the daemon did not answer ({why}), so the file cannot be compared with it; nothing was changed"
        )
    revision = None
    if sid is not None and raw and not str(raw).startswith(_host._CANONICAL_SENTINEL_PREFIX):
        revision = _rev.record(
            sid,
            SERVICE,
            file_cfg,
            raw,
            f"transport switched {current} -> file by {actor}",
            hash_kind="raw",
            source="switch",
        )
    return _done(
        f"{name}: switched to File over SSH; revision #{revision} is the baseline"
        if revision
        else f"{name}: switched to File over SSH",
        revision=revision,
    )


def switch(server: dict, target: str, *, consents=(), actor: str = "") -> dict:
    """Switch `server` to `target` (`api | file | off`). A result dict `{"ok", "level", "line", ...}`; the caller flashes the line, audits and re-derives the capabilities.
    A refusal that a named consent would answer carries `needs` (the field to tick)."""
    from jen import config as _config

    consents = set(consents or ())
    if target not in _api.TRANSPORTS:
        return _refuse("the transport must be api, file or off")
    current = _api.declared_transport(server)
    name = server.get("name") or "the server"
    if target == current and not (target == "api" and consents):
        return _done(f"{name} is already in write mode {_words.mode_word(target)}", unchanged=True)
    try:
        with _cs.change_lock():
            if target == "api":
                result = _to_api(server, current, consents, actor)
            elif target == "file":
                result = _to_file(server, current, consents, actor)
            else:
                result = _done(f"{name}: now Read-only; the daemon keeps serving")
            if not result["ok"]:
                return result
            try:
                _config.app_config.write_value(section_for(server), "config_transport", target)
            except Exception as e:  # (Q216 AA10) the file was rendered and the setting could not be written: say so, never a 500 over a half-done switch
                logger.warning("kea_transport_switch: the setting could not be written: %s", type(e).__name__)
                return _refuse(
                    f"{name}: the switch was done but the setting could not be saved ({e}); the transport did not change - run the switch again"
                )
    except _cs.ChangeBusy:
        return _refuse(_cs.BUSY_SENTENCE)
    result.setdefault("from", current)
    result["to"] = target
    result["consents"] = sorted(consents)
    return result
