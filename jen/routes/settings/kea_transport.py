"""
jen/routes/settings/kea_transport.py
────────────────────────────────────
Q212 - the per-server card's five routes: how a change reaches a Kea server (the probe, the switch, the helper's grant and its inverse, and the operator's "I have fixed it"). Thin: parse the
request, call `kea_api_config` / `kea_transport_switch` / `kea_host`, flash, audit. Every one is a SUPERADMIN's: it changes who may write a root-owned file or which path a configuration
takes to a daemon. The switch, the two helper ops and "I have fixed it" also ask for a recent confirmation of the password.
"""

import logging

from flask import flash, jsonify, redirect, request, url_for
from flask_login import current_user, login_required

import jen.models.user as __user
import jen.services.capabilities as __caps
import jen.services.kea_api_config as __api
import jen.services.kea_changeset as __cs
import jen.services.kea_host as __host
import jen.services.kea_transport_switch as __switch
import jen.services.write_mode as __write_mode
from jen import extensions
from jen.routes.settings import bp
from jen.services.access import recent_auth_required as _recent_auth_required
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)

SWITCH_CONSENTS = ("consent_rendering", "consent_unauthenticated", "discard_file_edit", "confirm_no_include")


def _server(server_id):
    return next((s for s in extensions.KEA_SERVERS if s.get("id") == server_id), None)


def _back():
    return redirect(url_for("settings.settings_kea"))


def _gone():
    flash("That server is not configured.", "error")
    return _back()


@bp.route("/settings/infrastructure/probe-kea-config/<int:server_id>", methods=["POST"])
@login_required
@_superadmin_required
def probe_kea_config(server_id):
    """The readiness check of the Write mode card (`kea_api_config.probe`): what an operator reads before switching to Live API, stored for the capability, the card and the gate. It READS - a consent
    is not given here (Q217 BG2: the switch POST is the consent act, for the facts whose time the form carries). JSON, for `jenFetch`."""
    server = _server(server_id)
    if server is None:
        return jsonify({"ok": False, "error": "That server is not configured."}), 404
    facts = __api.probe(server, "dhcp4")
    __caps.invalidate(server_id)
    return jsonify({"ok": True, "probe": facts, "transport": __api.declared_transport(server)})


@bp.route("/settings/infrastructure/kea-transport/<int:server_id>", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def switch_kea_transport(server_id):
    """The write mode of one server: `api | file | off` (BB8; Live API, File over SSH, Read-only on the card). THIS POST is the consent act (Q217 BG2, CFG-003): the named consents arrive as fields, are
    given for the facts whose time the form carries (`probe_at`), and need the recent confirmation this route already asks for; `kea_transport_switch` applies `consent_gap`'s table."""
    server = _server(server_id)
    if server is None:
        return _gone()
    target = request.form.get("transport", "").strip()
    consents = {name for name in SWITCH_CONSENTS if request.form.get(name) == "1"}
    if target == "api" or consents:
        # (Q218 BH3 c, AC18) a consent is given for the facts whose time the form carries, whatever the target: the one the card showed is the one that was read, or nothing is changed
        stored = __api.stored_probe(server_id) or {}
        if not stored or request.form.get("probe_at", "") != str(stored.get("at") or ""):
            flash(
                f"{server.get('name') or 'The server'}: the readiness check was refreshed (or never run) since you read it - read the card again and accept what it shows; nothing was changed.",
                "error",
            )
            return _back()
    result = __switch.switch(server, target, consents=consents, actor=current_user.username)
    flash(result["line"], result["level"])
    if result["ok"] and not result.get("unchanged"):
        __user.audit(
            "KEA_TRANSPORT_SWITCHED",
            server.get("name") or str(server_id),
            f"write mode {__write_mode.mode_word(result.get('from'))} -> {__write_mode.mode_word(result.get('to'))}; consents: {', '.join(result.get('consents') or []) or 'none'}"
            + (f"; ignored: {', '.join(result['ignored'])}" if result.get("ignored") else "")
            + ("; refusal cleared" if result.get("refusal_cleared") else "")
            + (f"; baseline revision #{result['revision']}" if result.get("revision") else ""),
        )
        __caps.invalidate(server_id)
    return _back()


@bp.route("/settings/infrastructure/settle-pending-change/<int:server_id>", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def settle_pending_change(server_id):
    """Settle a change Jen's own process left half-done by content (Q216 AA19): a read only SAYS what it would be settled as; the settlement - `config-write` and the record - is made here and by the
    Plan of the next change, both under the change lock. Audited, with what was done."""
    server = _server(server_id)
    if server is None:
        return _gone()
    name = server.get("name") or str(server_id)
    try:
        with __cs.change_lock():
            lines, settled = __api.settle_pending(server, "dhcp4")
    except __cs.ChangeBusy:
        flash(__cs.BUSY_SENTENCE, "error")
        return _back()
    __user.audit("KEA_PENDING_CHANGE_SETTLED", name, "; ".join(lines)[:500])
    __caps.invalidate(server_id)
    flash(
        f"{name}: {' '.join(lines)}", "success" if settled else "warning"
    )  # (Q217 AB13) by what happened, not by the words in the lines
    return _back()


def _grant(server_id, op, verb, action):
    server = _server(server_id)
    if server is None:
        return _gone()
    if not server.get("ssh_host"):
        flash(
            f"{server.get('name') or 'This server'} has no SSH host: the file's owner and mode are changed on the host (Settings → Kea → SSH).",
            "error",
        )
        return _back()
    result = op(server, "dhcp4")
    if not result["ok"]:
        flash(f"{server.get('name') or 'The server'}: {result.get('detail') or 'the helper refused'}", "error")
        return _back()
    if result.get("changed") is False:
        flash(f"{server.get('name') or 'The server'}: {result.get('detail') or 'nothing to change'}", "success")
        __user.audit(  # (Q216 AA24) a press of the button is on the record whether or not it changed anything
            action,
            server.get("name") or str(server_id),
            f"no change: {result.get('detail') or 'already as asked'}",
        )
        return _back()
    after = result.get("after") or {}
    flash(
        f"{server.get('name') or 'The server'}: {verb} (the file is now {after.get('mode')}, group {after.get('gid')}); run the readiness check to read it back.",
        "success",
    )
    __user.audit(
        action,
        server.get("name") or str(server_id),
        f"{(result.get('before') or {}).get('mode')} -> {after.get('mode')}",
    )
    return _back()


@bp.route("/settings/infrastructure/allow-config-write/<int:server_id>", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def allow_config_write(server_id):
    """Make the daemon's `-c` FILE writable by the account its unit runs as (its group, 0660; never the directory, never an `o` bit)."""
    return _grant(server_id, __host.allow_config_write, "the daemon may write its file", "KEA_CONFIG_WRITE_ALLOWED")


@bp.route("/settings/infrastructure/deny-config-write/<int:server_id>", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def deny_config_write(server_id):
    """The way back: 0640, the group kept (the daemon can read its file, not write it)."""
    return _grant(
        server_id, __host.deny_config_write, "the daemon may no longer write its file", "KEA_CONFIG_WRITE_DENIED"
    )


@bp.route("/settings/infrastructure/config-write-fixed/<int:server_id>", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def config_write_fixed(server_id):
    """ "I have fixed it": clears a remembered refusal for a server with no SSH, where no probe can prove the permission. Nothing proves it - the audit row says who said so."""
    server = _server(server_id)
    if server is None:
        return _gone()
    stored = __api.stored_probe(server_id) or {}
    if not stored.get("refused"):
        flash(f"{server.get('name') or 'The server'} has no remembered refusal.", "info")
        return _back()
    if (
        server.get("ssh_host") and isinstance(stored.get("write"), dict) and "may_write" in stored["write"]
    ):  # (row 11) a helper that did not answer is not a proof
        # (Q216 AA9) the host can PROVE the permission: a claim is for a server where nothing can
        flash(
            f"{server.get('name') or 'The server'}: run the readiness check instead - the host can prove whether the daemon may write its file.",
            "error",
        )
        return _back()
    __api.clear_refusal(server_id)
    __user.audit(
        "KEA_CONFIG_WRITE_FIXED_CLAIM",
        server.get("name") or str(server_id),
        "the operator said the daemon's write permission was fixed; nothing proved it",
    )
    __caps.invalidate(server_id)
    flash(
        f"{server.get('name') or 'The server'}: the refusal is cleared on your word; the next change will find out.",
        "success",
    )
    return _back()
