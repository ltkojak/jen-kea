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
    # (Q218 BH1 a, d) the discard is a consent of THIS act for a fact the facts called for; the file must be one the daemon has loaded or Jen rendered (`file_proof`, Q219) or the discard says otherwise
    called_before = set(_api.consents_called_for(facts, has_ssh=has_ssh))
    discard = "discard_file_edit" in (set(consents) & called_before)
    discarded_at = None
    wrote_a_file = True
    if current == "api":
        # a server already in Live API RECORDS a consent; it renders nothing, unless the file carries an edit and the operator said to discard it
        wrote_a_file = False
        if has_ssh and discard:
            proof = _api.file_proof(server, SERVICE)
            if proof["how"] == "none":
                wrote_a_file = True
                newest = _rev.latest(sid, SERVICE, exclude_kind="kea") if sid is not None else None
                discarded_at = (newest or {}).get("id")
    if wrote_a_file:
        wrote = _api.write_file(server, SERVICE, discard=discard)
        if not wrote["ok"]:
            if (
                wrote.get("code") == "unloaded-edit"
            ):  # nothing was sent and Kea refused nothing: no refusal is remembered
                return _refuse(f"{name}: {wrote.get('detail')}; nothing was switched")
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
        _api.record_rendering_after_write(
            server, SERVICE, f"transport switched {current} -> api by {actor}"
        )  # (Q218 D8, Q219) Jen's own rendering is not "changed outside Jen", and it is the file `file_proof`'s (R) accepts
        # (Q219 BI3 a, AD2) the act itself changed the facts: the file IS the daemon's rendering now. The consent is written over THESE facts, never over the ones read before the write
        facts = _api.probe(server, SERVICE)
    else:
        revision = None
    # the operator's consent is on record from this moment: the gate in `apply` reads it
    # (Q218 BH3 a, AC4) what is USED is what the facts the switch was given for called for - `consents_called_for` is the one table - never every name the form happened to send: a stray box is
    # dropped and named. (Q219 Decided 7) what is STORED is what the facts AFTER the act still call for: a consent the act used up (the discard) is never left on record to open the gate on a later edit
    used = sorted(set(consents) & called_before)
    ignored = sorted(set(consents) - called_before)
    recorded = sorted(set(used) & set(_api.consents_called_for(facts, has_ssh=has_ssh)))
    if wrote_a_file:
        recorded = [
            c for c in recorded if c != "discard_file_edit"
        ]  # (Q219 E4) a discard the act made is USED, whatever the facts afterward say - it is never left on record to open the gate on a later edit
    stored = _api.stored_probe(sid) or facts
    stored["consented_at"] = _api._now_iso()
    stored["consents"] = recorded
    stored.pop("consent_refused", None)
    _api.store_probe(sid, stored)
    if current == "api":  # (Q218 BH1 d) a consent recorded in place says so, and says what it discarded
        line = f"{name}: consent recorded for Live API"
        if wrote_a_file:
            line += (
                f", and the file's edit was discarded (Config history #{discarded_at})"
                if discarded_at
                else ", and the file's edit was discarded"
            )
        return _done(line, revision=revision, discarded=wrote_a_file, consents=used, ignored=ignored)
    return _done(
        f"{name}: switched to Live API; Kea rendered its file; revision #{revision} is the baseline"
        if revision
        else f"{name}: switched to Live API; Kea rendered its file",
        revision=revision,
        consents=used,
        ignored=ignored,
    )


def _to_file(server: dict, current: str, consents: set, actor: str) -> dict:
    name = server.get("name") or server.get("ssh_host") or "the server"
    sid = server.get("id")
    if not server.get("ssh_host"):
        return _refuse(f"{name}: File over SSH needs an SSH host (Settings → Kea → SSH); nothing was changed")
    unreadable = _api.record_unreadable(server, SERVICE)
    if unreadable:
        return _refuse(f"{name}: {unreadable}; nothing was changed")
    acted: list[
        str
    ] = []  # the consents this act USED (Q218 BH3 e): the audit row prints what was done, not what was submitted
    file_cfg, raw = _host.read_config_versioned(server, SERVICE, capture=False)
    if file_cfg is None:
        return _refuse(
            f"{name}: the file on the host could not be read (is the helper installed? Settings → Kea → SSH); nothing was changed"
        )
    live, digest, why = _api._get(server, SERVICE)
    proof = _api.file_proof(server, SERVICE) if live is not None else None
    if proof is not None and not proof["ok"]:
        # (fix row 5, Q219) the proof FIRST: the file is not one the daemon has loaded or Jen rendered (a hand edit, or a change the daemon never wrote). Overwriting it is a named consent; a daemon that
        # was never granted the write (so `config-write` is refused) still leaves `api` once the proof holds, and it is asked again after the best-effort write
        if "discard_file_edit" not in consents:
            return _refuse(
                f"{name}: the file and the daemon differ (the daemon {_short(digest)}, the file {_short(raw)}): {proof['why']}; they must agree before the file becomes the thing Jen edits - restart Kea there, restore from Config history, or tick 'discard the file's edit' to overwrite it with what the daemon runs",
                needs="discard_file_edit",
                before_hash=digest,
                after_hash=raw,
            )
        blocked = _write_guard(server, name, live)
        if blocked:
            return _refuse(blocked)
        acted.append("discard_file_edit")
        wrote = _api.write_file(
            server, SERVICE, discard=True
        )  # (Q218 BH1 b) `discard_file_edit` is in THIS act's consents (the refusal above); the sender's capturing read puts the edit in Config history first
        if wrote.get("ok"):
            _api.record_rendering_after_write(server, SERVICE, f"transport switched {current} -> file by {actor}")
        file_cfg, raw = _host.read_config_versioned(server, SERVICE, capture=False)
        again = _api.file_proof(server, SERVICE, capture=False)
        if file_cfg is None or not again["ok"]:
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
        consents=acted,
        ignored=sorted(set(consents) - set(acted)),
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
            if target in ("api", "file"):
                # (Q219 Decided 7) a switch over an unsettled change is refused with the pending sentence: the daemon may run a change whose file write never happened, and a switch would render over it
                unreadable = _api.record_unreadable(server, SERVICE)
                if unreadable:
                    return _refuse(f"{name}: {unreadable}; nothing was changed")
                blocked = _api.pending_block(server, SERVICE)
                if blocked:
                    return _refuse(f"{name}: {blocked}; nothing was changed")
            if target == "api":
                result = _to_api(server, current, consents, actor)
            elif target == "file":
                result = _to_file(server, current, consents, actor)
            else:
                result = _done(
                    f"{name}: now Read-only; the daemon keeps serving", consents=[], ignored=sorted(consents)
                )
            if not result["ok"]:
                return result
            try:
                _config.app_config.write_value(section_for(server), "config_transport", target)
            except Exception as e:  # (Q216 AA10) the file was rendered and the setting could not be written: say so, never a 500 over a half-done switch
                logger.warning("kea_transport_switch: the setting could not be written: %s", type(e).__name__)
                return _refuse(
                    f"{name}: the switch was done but the setting could not be saved ({e}); the transport did not change - run the switch again"
                )
            if current == "api" and target != "api":
                # (Q219 BI3 b, AD3) a remembered refusal of `config-write` belongs to Live API: it is cleared when the server leaves it, after the setting is written
                had = bool((_api.stored_probe(server.get("id")) or {}).get("refused"))
                result["refusal_cleared"] = bool(_api.clear_refusal(server.get("id"))) and had
    except _cs.ChangeBusy:
        return _refuse(_cs.BUSY_SENTENCE)
    result.setdefault("from", current)
    result["to"] = target
    result.setdefault(
        "consents", []
    )  # (Q218 BH3 e) each transition says what it RECORDED or USED; this is the fallback for one that said nothing
    result.setdefault("ignored", [])
    return result
