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


def _to_api(server: dict, current: str, consents: set, actor: str) -> dict:
    name = server.get("name") or f"Server {server.get('id')}"
    sid = server.get("id")
    facts = _api.probe(server, SERVICE)  # the facts, now: the stored result a switch relies on is fresh by construction
    if not facts.get("config_api"):
        return _refuse(
            f"{name}: the daemon could not be read over its API ({facts.get('read_error') or 'no answer'}); nothing was changed"
        )
    if facts.get("test_ok") is False:
        return _refuse(
            f"{name}: the daemon did not accept its own configuration in a config-test ({facts.get('test_detail') or 'refused'}); nothing was changed"
        )
    if facts.get("include"):
        return _refuse(
            f"{name}: the file carries an include ({', '.join(facts['include'])}); the daemon reports the merged configuration and config-write renders one flat file, so the API transport is not recommended here"
        )
    has_ssh = bool(server.get("ssh_host"))
    if has_ssh and (
        facts.get("agree") is None or facts.get("include") is None or not isinstance(facts.get("write"), dict)
    ):
        return _refuse(
            f"{name}: SSH is configured but the host's facts could not be read (is the helper installed at build 19 or later, and does SSH answer?), so the file could not be compared with the daemon; nothing was changed"
        )
    if not has_ssh and "confirm_no_include" not in consents:
        return _refuse(
            f"{name} has no SSH host, so Jen cannot see its file: confirm that the file carries no include and no edit the daemon has not loaded, then switch again",
            needs="confirm_no_include",
        )
    if has_ssh and facts.get("agree") is False and "discard_file_edit" not in consents:
        return _refuse(
            f"{name}: the file on the host carries a configuration the daemon is not running - restart Kea first, or tick 'discard the file's edit' (the switch makes the file the daemon's configuration)",
            needs="discard_file_edit",
        )
    write = facts.get("write")
    if has_ssh and isinstance(write, dict) and write.get("may_write") is False:
        return _refuse(
            f"{name}: the daemon's account ({write.get('account') or 'unknown'}) may not write its file ({write.get('mode')}); press Allow the daemon to write its file, then switch again",
            needs="allow_config_write",
        )
    if "consent_rendering" not in consents:
        return _refuse(
            f"{name}: Kea writes its file in its own form - comments and key order are not kept (a 1,932-byte file became 4,769). This is the one moment they are lost: tick the confirmation to go on",
            needs="consent_rendering",
        )
    if facts.get("auth") == "none" and "consent_unauthenticated" not in consents:
        return _refuse(
            f"{name}: this endpoint has no authentication; anything that can reach it can change this daemon's configuration. Confirm that, then switch again",
            needs="consent_unauthenticated",
        )
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
    stored.pop("consent_refused", None)
    _api.store_probe(sid, stored)
    return _done(
        f"{name}: switched to the API transport; Kea rendered its file; revision #{revision} is the baseline"
        if revision
        else f"{name}: switched to the API transport; Kea rendered its file",
        revision=revision,
    )


def _to_file(server: dict, current: str, consents: set, actor: str) -> dict:
    name = server.get("name") or server.get("ssh_host") or "the server"
    sid = server.get("id")
    if not server.get("ssh_host"):
        return _refuse(f"{name}: the file transport needs an SSH host (Settings → Kea → SSH); nothing was changed")
    file_cfg, raw = _host.read_config_versioned(server, SERVICE, capture=False)
    if file_cfg is None:
        return _refuse(
            f"{name}: the file on the host could not be read (is the helper installed? Settings → Kea → SSH); nothing was changed"
        )
    live, digest, why = _api._get(server, SERVICE)
    if live is not None and not _api.file_in_daemon(file_cfg, live, SERVICE):
        # (fix row 5) compare FIRST: the file carries something the daemon does not run (a hand edit, or a change the daemon never wrote). Overwriting it is a named consent; a daemon that was never
        # granted the write (so `config-write` is refused) still leaves `api` once they agree, and the compare decides again after the best-effort write
        if "discard_file_edit" not in consents:
            return _refuse(
                f"{name}: the file and the daemon differ (the daemon {_short(digest)}, the file {_short(raw)}); they must agree before the file becomes the thing Jen edits - restart Kea there, restore from Config history, or tick 'discard the file's edit' to overwrite it with what the daemon runs",
                needs="discard_file_edit",
                before_hash=digest,
                after_hash=raw,
            )
        _api.write_file(server, SERVICE)
        file_cfg, raw = _host.read_config_versioned(server, SERVICE, capture=False)
        if file_cfg is None or not _api.file_in_daemon(file_cfg, live, SERVICE):
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
        f"{name}: switched to the file transport; revision #{revision} is the baseline"
        if revision
        else f"{name}: switched to the file transport",
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
    if target == current:
        return _done(f"{name} already uses the {target} transport", unchanged=True)
    try:
        with _cs.change_lock():
            if target == "api":
                result = _to_api(server, current, consents, actor)
            elif target == "file":
                result = _to_file(server, current, consents, actor)
            else:
                result = _done(f"{name}: no longer a write target; the daemon keeps serving")
            if not result["ok"]:
                return result
            _config.app_config.write_value(section_for(server), "config_transport", target)
    except _cs.ChangeBusy:
        return _refuse(_cs.BUSY_SENTENCE)
    result.setdefault("from", current)
    result["to"] = target
    result["consents"] = sorted(consents)
    return result
