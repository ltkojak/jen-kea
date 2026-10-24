"""
jen/routes/settings/infrastructure.py
───────────────────────────────────
Kea / database / SSH / DDNS / HA / ports / metrics settings.
"""

import functools
import ipaddress
import logging
import os
import re
import subprocess
import time
from urllib.parse import urlparse

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.config as __config
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.capabilities as __caps
import jen.services.credentials as __credentials
import jen.services.ddns_writers as __ddns_writers
import jen.services.host_match as __host_match
import jen.services.investigation_logging as __inv
import jen.services.kea as __kea
import jen.services.kea6 as __kea6
import jen.services.runtime as __runtime
from jen import extensions
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required
from jen.services.access import recent_auth_required as _recent_auth_required
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)

# v5.10.2 — every [kea_server_N] key the Additional Servers form owns.
# _rewrite_extra_servers() rebuilds each section from scratch, so anything
# NOT in this set (ssh_key that derive_kea_servers reads, a hand-added
# value) has to be copied back or it's silently lost on save.
_EXTRA_SERVER_FORM_KEYS = frozenset(
    {
        "name",
        "role",
        "api_url",
        "api_user",
        "api_pass",
        "api6_url",
        "api6_user",
        "api6_pass",
        "api_pass_shared",
        "api6_pass_shared",
        "ssh_host",
        "ssh_user",
        "kea_conf",
    }
)


def _api_pass_state(endpoint) -> str:
    """The words the Servers & HA table uses for what an additional server's API password is (from `credentials.resolve`)."""
    if endpoint is None:
        return "none"
    if endpoint.source == "own":
        return "its own"
    if endpoint.source.startswith("inherited:"):
        return "the primary's (same host)"
    if endpoint.withheld:
        return "none (the primary's is not sent to a different host)"
    return "none"


def _kea_server_section_ids(cfg) -> list[int]:
    """Every `[kea_server_N]` (N >= 2 — 1 is the primary, `[kea]`) present
    in `cfg`, sorted. v5.19.1 (Q14) — gap-tolerant: a
    `while has_section(kea_server_n): n += 1` loop stops at the first
    missing number, hiding every server after a hand-made gap. v5.20.0
    (Q15) made section numbers stable identities on the SAVE side too
    (`_rewrite_extra_servers`, below), so gaps are now a normal, expected
    shape rather than a transient one this only had to tolerate on read."""
    return sorted(
        int(m.group(1))
        for sec_name in cfg.sections()
        if (m := re.fullmatch(r"kea_server_(\d+)", sec_name)) and int(m.group(1)) >= 2
    )


@bp.route("/settings/infrastructure")
@login_required
@_admin_required
def settings_infrastructure():
    """v5.9.0 — the Infrastructure tab became the Kea page. Old bookmarks
    and the post-update overlay redirect land here; send them on."""
    return redirect(url_for("settings.settings_kea"), code=301)


def _bind_default(ssh_host: str) -> str:
    """v5.29.0 (Q29) — the bind address a "Set up direct socket" form
    starts with: the server's SSH host when it's an IP literal (the
    daemon binds an address, so a hostname is no default at all)."""
    return ssh_host.strip() if _is_ip_literal(ssh_host) else ""


def _kea_servers_with_helper_status():
    """Per-server rows for the SSH card's helper table: id, name,
    ssh_host, the persisted helper status ('v1' / null / unknown),
    `helper_want` (v5.19.1 — the version Jen wants, so the template can
    show "upgrade available" for a version below it instead of treating
    any installed version as fully current), and `legacy_grant`
    (v5.20.0 — whether the old NOPASSWD: python3 grant is still present,
    last learned the previous time Check/Update ran; never SSHes here)."""
    from jen.services import kea_host

    status = kea_host.helper_status()
    rows = []
    for s in extensions.KEA_SERVERS:
        st = status.get(str(s.get("id")), {})
        rows.append(
            {
                "id": s.get("id"),
                "name": s.get("name", f"Kea Server {s.get('id')}"),
                "ssh_host": s.get("ssh_host", ""),
                # v5.65.13 (Q102) — kea_host.effective_ssh_user(), the one derivation, used
                # everywhere the SSH user is needed (this row, _connect_ssh, install_helper).
                "ssh_user": kea_host.effective_ssh_user(s),
                "helper_version": st.get("version"),  # int, None, or missing key
                # v5.66.0-beta.2 (Q104) — build is passed through when the host reports one
                # (v7+); helper_version_label() reads "v7 (build 7)" instead of just "v7".
                "helper_label": kea_host.helper_version_label(
                    st.get("version"), kea_host.JEN_HELPER_SHIPPED_VERSION, build=st.get("build")
                ),
                "helper_want": kea_host.JEN_HELPER_WANT_VERSION,
                # v5.29.1 — the Update helper button is offered below this
                # (the shipped file's version), not just below WANT.
                "helper_shipped": kea_host.JEN_HELPER_SHIPPED_VERSION,
                # v5.68.0-beta.7 (Q142) - a helper release that changes the BUILD and not the version (builds 8, 9 and 10) was
                # invisible to the button, which compared versions alone while the label beside it already said "build 10 available".
                # `helper_build` is what the host last reported (None before v7, which reports none); the template treats that as 0.
                "helper_build": st.get("build"),
                "helper_shipped_build": kea_host.JEN_HELPER_SHIPPED_BUILD,
                "helper_known": bool(st),
                "helper_checked": st.get("checked", ""),
                "legacy_grant": st.get("legacy_grant"),  # True, False, or None (never checked)
                # v5.29.0 (Q29) — the https option of "Set up direct socket"
                # needs the v4 helper (install-tls); same fail-closed rule
                # as kea_host.tls_supported, computed from this one read.
                "tls_supported": __caps.helper_caps(st.get("version"))["tls"],
                # v5.66.0 (Q103) — "Update helper" needs no legacy grant at all on this host.
                "signed_update": __caps.helper_caps(st.get("version"))["signed_update"],
            }
        )
    return rows


def _kea_ca_summary() -> dict:
    """v5.29.0 (Q29) — what the Control Plane card says about the
    Jen-managed Kea CA: present or not, its subject and days left, whether
    Jen's client certificate is signed by it, and every server certificate
    Jen issued (from the kea-servers/ copies — never SSHes)."""
    from jen.services import kea_tls

    ca_state, ca_why = kea_tls.ca_state()  # Q192 (AH2): none / ok / damaged - there is no other reading of Jen's CA
    present = ca_state == "ok"
    ca_crt, _ca_key = kea_tls.ca_paths()
    client_state, client_why = kea_tls.client_state()
    try:
        prepared, prepared_note = kea_tls.prepared_rotation()  # a READ: the page never deletes (second pass, finding 6)
    except kea_tls.PreparedUnreadable as e:
        prepared, prepared_note = None, e.strerror or "the prepared CA cannot be read right now"
    out = {
        "present": present,
        "state": ca_state,
        "damaged": ca_state == "damaged",
        "why": ca_why,
        "advice": kea_tls.DAMAGED_CA_ADVICE,
        "ca_path": ca_crt,
        "subject": kea_tls._cn(ca_crt) if present else "",
        "days_left": kea_tls.days_left(ca_crt) if present else None,
        "client_ok": client_state == "ok",
        "client_state": client_state,
        "client_why": client_why,
        "prepared": prepared is not None,
        "prepared_fingerprint": kea_tls.prepared_fingerprint(prepared) if prepared else "",
        "prepared_note": prepared_note,
        "issued": [],
        # a [kea] api_ca whose certificates do not include Jen's = the operator brought their own CA (Q190, AF1: decided by certificate identity, never by comparing paths)
        "external_ca": bool(extensions.KEA_API_CA) and kea_tls.trust_includes_jens_ca() is False,
    }
    out["external"], out["refused"] = [], []
    if present or ca_state == "damaged":
        # Q189 (AE1): what Rotate will do is the INVENTORY (every https endpoint Jen dials), not the listing of local copy files
        inventory = kea_tls.rotation_inventory(
            extensions.KEA_SERVERS,
            url_for=_configured_url,
            recovery=ca_state == "damaged",
            prove_storage=False,  # (Q194: a page render only reads - the proof that Jen can write is the rotation's, which creates the directory)
        )
        for server, service, _bind in inventory.targets:
            name = server.get("name") or f"server {server.get('id')}"
            out["issued"].append(
                (name, service, kea_tls.days_left(kea_tls.server_copy_path(server.get("id"), service)))
            )
        out["external"] = list(inventory.external)
        out["refused"] = list(inventory.refusals)
    return out


@bp.route("/settings/kea")
@login_required
@_admin_required
def settings_kea():
    kea_up = __kea.kea_is_up()
    # v5.10.0 — fetch the Kea version so the page can warn when the
    # configured connection mode won't survive the running Kea (ca mode
    # against Kea >= 3.0, where ISC deprecated the Control Agent and
    # removes it in 3.2). One extra version-get on an already-reachable
    # server; skipped entirely when Kea is down.
    kea_version = ""
    if kea_up:
        # v5.64.0 (Q83) — the primary's version and what it implies for the
        # connection mode come from jen.services.capabilities (one cached
        # version-get per minute), not a private comparison here.
        _caps = __caps.for_primary(with_config=False)
        kea_version = _caps.kea_version_text
    else:
        _caps = __caps.derive()
    ca_deprecation_warning = _caps.ca_deprecated or _caps.ca_removed
    ca_removed = _caps.ca_removed

    ssh_pub_key = ""
    if os.path.exists(extensions.SSH_KEY_PATH + ".pub"):
        try:
            with open(extensions.SSH_KEY_PATH + ".pub") as f:
                ssh_pub_key = f.read().strip()
        except Exception:
            pass
    # Load extra servers — gap-tolerant (see _kea_server_section_ids).
    helper_rows = _kea_servers_with_helper_status()
    tls_ok_by_id = {r["id"]: r["tls_supported"] for r in helper_rows}
    extra_servers = []
    _resolved_endpoints = __credentials.resolve(extensions.cfg)
    _shared_copies = __credentials.shared_copies(
        extensions.cfg
    )  # Y3 (Q183): every endpoint whose password is a marked copy, for the rows and cards that say so
    for n in _kea_server_section_ids(extensions.cfg):
        sec = f"kea_server_{n}"
        extra_servers.append(
            {
                "id": n,
                "name": extensions.cfg.get(sec, "name", fallback=f"Kea Server {n}"),
                "api_url": extensions.cfg.get(sec, "api_url", fallback=""),
                "api_user": extensions.cfg.get(sec, "api_user", fallback=""),
                # v5.10.2 — the per-server v6 endpoint, now editable. api6_pass
                # is deliberately NOT loaded into the template (password field).
                "api6_url": extensions.cfg.get(sec, "api6_url", fallback=""),
                "api6_user": extensions.cfg.get(sec, "api6_user", fallback=""),
                "ssh_host": extensions.cfg.get(sec, "ssh_host", fallback=""),
                "ssh_user": extensions.cfg.get(sec, "ssh_user", fallback=""),
                "kea_conf": extensions.cfg.get(sec, "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
                "role": extensions.cfg.get(sec, "role", fallback="standby"),
                # v5.69.0-beta.11 (Q180, U2): this password is a COPY of the primary's, made once and no longer following it
                "api_pass_shared": f"server_{n}" in _shared_copies,
                "api6_pass_shared": f"server_{n}_v6" in _shared_copies,
                "api_d2_pass_shared": f"server_{n}_d2" in _shared_copies,
                "api_pass_state": _api_pass_state(_resolved_endpoints.get(f"server_{n}")),
                # an explicit blank: a Kea with no authentication
                "api6_pass_none": extensions.cfg.has_option(sec, "api6_pass")
                and extensions.cfg.get(sec, "api6_pass", fallback="") == "",
                "api_d2_url": extensions.cfg.get(sec, "api_d2_url", fallback=""),
                "api_d2_pass_none": extensions.cfg.has_option(sec, "api_d2_pass")
                and extensions.cfg.get(sec, "api_d2_pass", fallback="") == "",
                "api_pass_none": extensions.cfg.has_option(sec, "api_pass")
                and extensions.cfg.get(sec, "api_pass", fallback="") == "",
                # v5.29.0 (Q29) — the "Set up direct socket" form's bind
                # address default: the SSH host when it's an IP literal.
                "bind_default": _bind_default(extensions.cfg.get(sec, "ssh_host", fallback="")),
                "tls_supported": tls_ok_by_id.get(n, False),
            }
        )

    # v5.10.2 — direct mode needs an explicit port on every API URL. The
    # save routes validate their own field; this catches a URL that was
    # valid in ca mode and became invalid when the mode was switched.
    direct_port_warnings = []
    if __caps.is_direct():

        def _needs_port(u):
            # (second pass, Q190: the PORT question only - an address that also carries a user name is its own warning, and must not read as 'no port')
            from urllib.parse import urlsplit

            try:
                return bool(u) and urlsplit(u.strip()).port is None
            except ValueError:
                return bool(u)

        if __kea6.is_ipv6_enabled() and _needs_port(extensions.cfg.get("kea6", "api_url", fallback="")):
            direct_port_warnings.append(f"[kea6] api_url ({__auth.shown_url(extensions.cfg.get('kea6', 'api_url'))})")
        for srv in extensions.KEA_SERVERS:
            if _needs_port(srv.get("api_url", "")):
                direct_port_warnings.append(
                    f"{srv.get('name', 'Kea Server')} api_url ({__auth.shown_url(srv['api_url'])})"
                )
            if _needs_port(srv.get("api6_url", "")):
                direct_port_warnings.append(
                    f"{srv.get('name', 'Kea Server')} api6_url ({__auth.shown_url(srv['api6_url'])})"
                )

    # Z1/Z2 (Q184): the Remove form shows where the Control Agent will be reached and whether its own password was saved
    _prev_urls, _prev_pairs, _needs_ca_url = {}, set(), set()
    for _sid, _sec in [(1, "kea"), *[(n, f"kea_server_{n}") for n in _kea_server_section_ids(extensions.cfg)]]:
        if extensions.cfg.has_section(_sec):
            if extensions.cfg.get(_sec, "direct_prev_api_url", fallback=""):
                _prev_urls[_sid] = extensions.cfg.get(_sec, "direct_prev_api_url")
            if any(
                extensions.cfg.has_option(_sec, k)
                for k in (
                    "direct_prev_api_pass",
                    "direct_prev_api_user",
                    "direct_prev_api_user_absent",
                    "direct_prev_api_pass_absent",
                )
            ):
                _prev_pairs.add(_sid)
            # AB3 (Q186): no Control Agent address to return to (none saved, or the saved one is the socket's own): the Remove form asks for it
            _own_url = extensions.cfg.get(_sec, "api_url", fallback="").strip().rstrip("/")
            if not _prev_urls.get(_sid) or _prev_urls[_sid].strip().rstrip("/") == _own_url:
                _needs_ca_url.add(_sid)
    infra = {
        "prev_urls": _prev_urls,
        "prev_pairs": _prev_pairs,
        "needs_ca_url": _needs_ca_url,
        "shared_copies": _shared_copies,
        "kea_api_url": extensions.cfg.get("kea", "api_url", fallback=""),
        "kea_api_user": extensions.cfg.get("kea", "api_user", fallback=""),
        # v5.69.0-beta.2 (Q171): whether a password is saved, never the password - every other password field on these pages already works this way, and the save below keeps a blank
        "kea_api_pass_set": bool(extensions.cfg.get("kea", "api_pass", fallback="")),
        # v5.10.0 — Kea 3 control plane
        # AB5 (Q186): the page reads the mode the way the resolver does (a hand-edited `Direct` is direct)
        "kea_connection_mode": _mode_of(extensions.cfg),
        "kea_api_ca": extensions.cfg.get("kea", "api_ca", fallback=""),
        "kea_api_tls_verify": extensions.cfg.getboolean("kea", "api_tls_verify", fallback=True),
        "kea_api_client_cert": extensions.cfg.get("kea", "api_client_cert", fallback=""),
        "kea_api_client_key": extensions.cfg.get("kea", "api_client_key", fallback=""),
        "kea_db_host": extensions.cfg.get("kea_db", "host", fallback=""),
        "kea_db_user": extensions.cfg.get("kea_db", "user", fallback=""),
        "kea_db_name": extensions.cfg.get("kea_db", "database", fallback="kea"),
        "jen_db_host": extensions.cfg.get("jen_db", "host", fallback=""),
        "jen_db_user": extensions.cfg.get("jen_db", "user", fallback=""),
        "jen_db_name": extensions.cfg.get("jen_db", "database", fallback="jen"),
        "ssh_host": extensions.cfg.get("kea_ssh", "host", fallback=""),
        "ssh_user": extensions.cfg.get("kea_ssh", "user", fallback=""),
        "kea_conf": extensions.cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
        # v5.69.0-beta.6 (Q175): what is STORED (blank = the default), not the derived value, so the field shows what an admin set
        "dhcp4_log_path": extensions.cfg.get("kea", "dhcp4_log_path", fallback=""),
        "ddns_log": extensions.cfg.get("ddns", "log_path", fallback=""),
        "ddns_url": extensions.cfg.get("ddns", "api_url", fallback=""),
        "ddns_user": extensions.cfg.get("ddns", "api_user", fallback=""),
        "ddns_zone": extensions.cfg.get("ddns", "forward_zone", fallback=""),
        "dns_provider": __ddns_writers.effective_provider(extensions.cfg),
        # whether a token is stored (never the token): the provider blocks say "(unchanged)" only for the provider it belongs to (v5.69.0-beta.8, Q177)
        "ddns_token_set": bool(extensions.cfg.get("ddns", "api_token", fallback="").strip()),
        "ha_mode": extensions.cfg.get("kea", "ha_mode", fallback=""),
        "server_name": extensions.cfg.get("kea", "name", fallback="Kea Server 1"),
        "subnets": extensions.SUBNET_MAP,
        "extra_servers": extra_servers,
        # v5.0 Phase 1 — IPv6. kea6_api_url etc. show what's ACTUALLY in
        # [kea6] (blank if absent), not extensions.KEA6_API_URL (which is
        # already fallen back to the v4 value) — the settings UI needs to
        # distinguish "explicitly set" from "inheriting the v4 default" so
        # it can show the placeholder/fallback text correctly instead of
        # looking like v6 has its own creds when it doesn't.
        "kea6_api_url": extensions.cfg.get("kea6", "api_url", fallback=""),
        "kea6_api_user": extensions.cfg.get("kea6", "api_user", fallback=""),
        "kea6_db_host": extensions.cfg.get("kea6_db", "host", fallback=""),
        "kea6_db_user": extensions.cfg.get("kea6_db", "user", fallback=""),
        "kea6_db_name": extensions.cfg.get("kea6_db", "database", fallback=""),
        # v5.23.0 (Q19) — same "raw, not the fallen-back global" reasoning
        # as kea6_api_url above.
        "d2_api_url": extensions.cfg.get("d2", "api_url", fallback=""),
        "d2_api_user": extensions.cfg.get("d2", "api_user", fallback=""),
        # v5.29.0 (Q29) — see bind_default on the extra servers above.
        "bind_default": _bind_default(extensions.cfg.get("kea_ssh", "host", fallback="")),
        "tls_supported": tls_ok_by_id.get(1, False),
    }
    restart_pending = __user.get_global_setting("restart_pending", "false") == "true"
    # v5.29.0 (Q29) — per-daemon control sockets exist from Kea 2.7.2; hide
    # the "Set up direct socket" forms when the primary is KNOWN to be
    # older (unknown = show them; the route re-checks before writing).
    # (a SETUP path: v5.65.2 - the capability itself is now confirmed-only, so this asks the permissive twin)
    direct_socket_supported = __caps.may_attempt_direct_socket(_caps.kea_version)
    ipv6_enabled = __kea6.is_ipv6_enabled()
    # v5.38.0 (Q37) — the Kea 3.2 readiness one-liner on the servers card.
    readiness = None
    if kea_up:
        try:
            from jen.services import health as _health
            from jen.services import kea_readiness as _readiness

            # no new Kea round trips on this page: one status row from the
            # version-get above, no config-get (the Health Center has the rest)
            primary = extensions.KEA_SERVERS[0] if extensions.KEA_SERVERS else {"id": 1, "name": "Kea Server 1"}
            light_ctx = {
                "server_status": [{"server": primary, "up": True, "ha_state": None, "version": kea_version}],
                "active_server": None,
                "dhcp4_config": None,
            }
            readiness = _readiness.summarize(_health.readiness_checks(light_ctx))
        except Exception as e:
            logger.warning(f"readiness summary: {e}")
    return render_template(
        "settings_kea.html",
        readiness=readiness,
        infra=infra,
        kea_up=kea_up,
        ssh_pub_key=ssh_pub_key,
        ssh_configured=bool(ssh_pub_key),
        restart_pending=restart_pending,
        ipv6_enabled=ipv6_enabled,
        kea_version=kea_version,
        ca_deprecation_warning=ca_deprecation_warning,
        ca_removed=ca_removed,
        direct_port_warnings=direct_port_warnings,
        direct_socket_supported=direct_socket_supported,
        kea_ca=_kea_ca_summary(),
        # v5.10.3 — id + name only; the real server dicts carry passwords.
        # v5.11.0 — plus ssh_host + the persisted jen-kea-helper status
        # (never SSHes to render — see jen/services/kea_host.py).
        kea_servers=helper_rows,
        http_port=extensions.HTTP_PORT,
        https_port=extensions.HTTPS_PORT,
        worker_threads=extensions.WORKER_THREADS,
        ssl_configured=__config.ssl_configured(),
        metrics_token=extensions.cfg.get("server", "metrics_token", fallback="") if extensions.cfg else "",
        metrics_open=extensions.cfg.getboolean("server", "metrics_open", fallback=False) if extensions.cfg else False,
        # v5.66.0-beta.7 (Q109, item b) — the SSH card's own copy box for the by-hand helper
        # install, one source (kea_host._helper_download_command()) with every doc copy and
        # every flash that offers it (tests/test_kea_host.py::TestDocsCarryTheSameByHandLine).
        helper_by_hand_command=_helper_by_hand_command(),
    )


def _helper_by_hand_command() -> str:
    """The SSH card's copy box needs this even when jen-kea-helper isn't readable for some
    reason (a stripped-down container image, a permissions problem) — the page as a whole
    must still render, so a failure here degrades to an empty string rather than a 500."""
    from jen.services import kea_host

    try:
        return kea_host._helper_download_command()
    except OSError:
        return ""


@bp.route("/settings/infrastructure/save-kea", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def save_infra_kea():
    """RBAC-004 (v5.69.0-beta.10, Q179): where Jen reaches Kea, and so where its credentials go, is a superadmin's setting with a recent password (the config writer asks the
    same question for every route, `access.identity_change_needs_superadmin`; the decorators send a person to confirm rather than let them meet the sentence)."""
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_pass = request.form.get("api_pass", "").strip()
    # v5.10.0 — Kea 3 control plane. connection_mode defaults to 'ca'
    # (every prior release's behavior); api_ca / api_tls_verify only
    # matter for an https:// socket URL.
    connection_mode = request.form.get("connection_mode", "ca").strip().lower()
    api_ca = request.form.get("api_ca", "").strip()
    api_tls_verify = request.form.get("api_tls_verify", "") == "1"
    # v5.10.2 — client cert for Kea's default-mTLS https socket. Both or neither.
    api_client_cert = request.form.get("api_client_cert", "").strip()
    api_client_key = request.form.get("api_client_key", "").strip()

    if not api_url:
        flash("API URL is required.", "error")
        return redirect(url_for("settings.settings_kea"))
    if connection_mode not in ("ca", "direct"):
        flash("Connection mode must be 'ca' or 'direct'.", "error")
        return redirect(url_for("settings.settings_kea"))
    # v5.10.2 — validate against the mode being SAVED, not the current global.
    if __auth.userinfo_sentence(api_url):
        flash(__auth.userinfo_sentence(api_url), "error")  # Q190 (AF2, CRED-005)
        return redirect(url_for("settings.settings_kea"))
    if not __auth.valid_api_url(api_url, require_port=(connection_mode == "direct")):
        if connection_mode == "direct":
            flash(
                "In direct mode the API URL must include an explicit port (e.g. http://kea:8004) — "
                "a daemon control socket is never on 80/443.",
                "error",
            )
        else:
            flash("API URL must be a valid http:// or https:// URL.", "error")
        return redirect(url_for("settings.settings_kea"))
    if api_ca and not __auth.usable_file(api_ca):
        flash(__auth.unusable_file_message("CA bundle", api_ca), "error")
        return redirect(url_for("settings.settings_kea"))
    if bool(api_client_cert) != bool(api_client_key):
        flash("Set both the client certificate and key, or neither.", "error")
        return redirect(url_for("settings.settings_kea"))
    for label, path in (("client certificate", api_client_cert), ("client key", api_client_key)):
        if path and not __auth.usable_file(path):
            flash(__auth.unusable_file_message(f"client {label}", path), "error")
            return redirect(url_for("settings.settings_kea"))
    # v5.10.3 — isfile() is a stat(); it says nothing about whether the pair
    # actually loads, matches, or is readable by www-data. Check for real
    # before writing, so a bad pair can't turn every Kea call into an
    # opaque SSLError.
    tls_err = __kea.validate_client_tls_material(api_client_cert, api_client_key, api_ca)
    if tls_err:
        flash(f"TLS settings not saved: {tls_err}.", "error")
        return redirect(url_for("settings.settings_kea"))
    if api_client_cert:
        from jen.services import kea_tls as __tls

        if (
            __tls.client_kind(api_client_cert, api_client_key) == "copy"
        ):  # Q191 (AG1): nothing legitimate needs a copy of Jen's own pair; an alias and the operator's own PKI stay allowed
            flash(f"TLS settings not saved: {__tls.client_refusal('copy', api_client_cert)}.", "error")
            return redirect(url_for("settings.settings_kea"))

    refusal = _secret_for_new_endpoint(
        extensions.cfg.get("kea", "api_url", fallback=""),
        api_url,
        api_pass,
        extensions.cfg.get("kea", "api_pass", fallback=""),
        "Kea API address",
    )
    if refusal:
        flash(refusal, "error")
        return redirect(url_for("settings.settings_kea"))
    # (v5.68.0-beta.28, Q164: no identity check here - `write_values` below asks the config writer's guard, which covers this route and every other)
    items = [
        ("kea", "api_url", api_url),
        ("kea", "api_user", api_user),
        ("kea", "connection_mode", connection_mode),
        ("kea", "api_ca", api_ca),
        ("kea", "api_tls_verify", "true" if api_tls_verify else "false"),
        ("kea", "api_client_cert", api_client_cert),
        ("kea", "api_client_key", api_client_key),
    ]
    if api_pass:
        items.append(("kea", "api_pass", api_pass))
    __config.app_config.write_values(items, typed={"kea"} if api_pass else None)
    __user.set_global_setting("restart_pending", "true")
    flash("Kea API settings saved. Restart Jen to apply.", "success")
    mismatch = __host_match.api_ssh_mismatch(api_url, extensions.cfg.get("kea_ssh", "host", fallback=""))
    if mismatch:
        flash(mismatch, "warning")
    __user.audit(
        "SAVE_INFRA",
        "kea_api",
        f"url={__auth.shown_url(api_url)} user={api_user} mode={connection_mode} client_cert={'set' if api_client_cert else 'none'}",
    )
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/save-kea-db", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def save_infra_kea_db():
    """v5.69.0-beta.2 (Q171) - which database Jen reads Kea's leases and reservations from is superadmin and step-up, like Jen's own database: an admin who could repoint
    either would read or write data they were never given."""
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "").strip()
    database = request.form.get("database", "").strip()
    if not host or not user or not database:
        flash("Host, username, and database name are required.", "error")
        return redirect(url_for("database.database", tab="connections"))
    refusal = _secret_for_new_endpoint(
        extensions.cfg.get("kea_db", "host", fallback=""),
        host,
        password,
        extensions.cfg.get("kea_db", "password", fallback=""),
        "Kea database host",
    )
    if refusal:
        flash(refusal, "error")
        return redirect(url_for("database.database", tab="connections"))
    items = [("kea_db", "host", host), ("kea_db", "user", user), ("kea_db", "database", database)]
    if password:
        items.append(("kea_db", "password", password))
    __config.app_config.write_values(items, typed={"kea_db"} if password else None)
    __user.set_global_setting("restart_pending", "true")
    flash("Kea database settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "kea_db", f"host={host}")
    return redirect(url_for("database.database", tab="connections"))


@bp.route("/settings/infrastructure/save-kea6", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def save_infra_kea6():
    """
    v5.69.0-beta.2 (Q171 fixup, G2) - the sibling of `save_infra_kea_db`: it writes `[kea6_db]` (host, user, password, database), which decides where Jen reads Kea's IPv6
    data, so it is superadmin + step-up like the other two database routes.

    v5.0 Phase 1 / v5.10.2 — [kea6] / [kea6_db] connection override, with
    inheritance that actually works.

    - Text fields (api_url, api_user; db_host, db_user, db_name):
      non-empty → written; **blank → the [kea6]/[kea6_db] key is removed**,
      so Jen genuinely falls back to the v4 [kea]/[kea_db] value at load
      time (jen/config.py's AppConfig.apply()). Before v5.10.2 a blank
      field wrote nothing, leaving a stale override on disk — after
      switching direct→ca that could aim a `{"service": ["dhcp6"]}`
      payload at the v6 daemon's own port.
    - Password fields (api_pass; db_pass): non-empty → written; blank →
      kept as-is (every password field in Jen behaves this way). Tick
      "Inherit …" to actually remove it.
    - A section with no options left is removed entirely.
    - api_url, when set, must be a valid http(s):// URL — and in direct
      mode it must carry an explicit port.
    This route never touches the ipv6_enabled display flag or the remote
    kea-dhcp6-server state — see toggle_ipv6() for that.
    """
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_pass = request.form.get("api_pass", "").strip()
    inherit_api_pass = request.form.get("inherit_api_pass", "") == "1"
    no_api_pass = (
        request.form.get("no_api_pass", "") == "1"
    )  # Q180 second pass: "this daemon has no authentication" - an explicit blank, which `resolve` reads as none
    no_db_pass = request.form.get("no_db_pass", "") == "1"
    db_host = request.form.get("db_host", "").strip()
    db_user = request.form.get("db_user", "").strip()
    db_pass = request.form.get("db_pass", "").strip()
    inherit_db_pass = request.form.get("inherit_db_pass", "") == "1"
    db_name = request.form.get("db_name", "").strip()

    if api_url and __auth.userinfo_sentence(api_url):
        flash(__auth.userinfo_sentence(api_url), "error")  # Q190 (CRED-005)
        return redirect(url_for("settings.settings_kea"))
    if api_url and not __auth.valid_api_url(api_url, require_port=(__caps.is_direct())):
        if __caps.is_direct():
            flash(
                "The Kea6 API URL must be a valid http(s):// URL with an explicit port "
                "in direct mode (e.g. http://kea:8006).",
                "error",
            )
        else:
            flash("The Kea6 API URL must be a valid http:// or https:// URL.", "error")
        return redirect(url_for("settings.settings_kea"))

    # CRED-002 (Q178): a saved password stays with the endpoint it was typed for; a password INHERITED from the Kea API (no own one, or "Inherit" ticked) stays with the
    # Kea API's host - a different host needs its password typed, "Inherit" included
    v4_api_url, v4_api_pass = (
        extensions.cfg.get("kea", "api_url", fallback=""),
        extensions.cfg.get("kea", "api_pass", fallback=""),
    )
    v4_db_host, v4_db_pass = (
        extensions.cfg.get("kea_db", "host", fallback=""),
        extensions.cfg.get("kea_db", "password", fallback=""),
    )
    for stored_url, new_url, new_secret, stored_secret, inherit, v4_url, v4_secret, what, parent, no_pass in (
        (
            extensions.cfg.get("kea6", "api_url", fallback=""),
            api_url,
            api_pass,
            extensions.cfg.get("kea6", "api_pass", fallback=""),
            inherit_api_pass,
            v4_api_url,
            v4_api_pass,
            "Kea6 API address",
            "Kea6 API password|the Kea API's",
            no_api_pass,
        ),
        (
            extensions.cfg.get("kea6_db", "host", fallback=""),
            db_host,
            db_pass,
            extensions.cfg.get("kea6_db", "password", fallback=""),
            inherit_db_pass,
            v4_db_host,
            v4_db_pass,
            "Kea6 database host",
            "Kea6 database password|the Kea database's",
            no_db_pass,
        ),
    ):
        if no_pass:
            # an explicit "no password" cannot send anything anywhere; combined with Inherit or a typed password it is two answers
            if inherit or new_secret.strip():
                flash(f"Choose one for the {parent.split('|')[0]}: no password, inherit it, or type one.", "error")
                return redirect(url_for("settings.settings_kea"))
            continue
        # RBAC/CRED (Q179, T2): ONE answer for a secret - "Inherit" and a typed password at once is a contradiction, and the form does not guess which was meant. The
        # EFFECTIVE secret is what the checks below judge: nothing when Inherit is ticked, else what was typed.
        refusal = _one_answer_for_a_secret(inherit, new_secret, parent)
        effective_secret = "" if inherit else new_secret
        if refusal:
            pass
        elif (stored_secret or "").strip() and not inherit:
            refusal = _secret_for_new_endpoint(stored_url, new_url, effective_secret, stored_secret, what)
        else:
            refusal = _inherited_secret_refusal(v4_url, new_url, effective_secret, v4_secret, what)
        if refusal:
            flash(refusal, "error")
            return redirect(url_for("settings.settings_kea"))

    # (section, option, submitted value)
    text_fields = [
        ("kea6", "api_url", api_url),
        ("kea6", "api_user", api_user),
        ("kea6_db", "host", db_host),
        ("kea6_db", "user", db_user),
        ("kea6_db", "database", db_name),
    ]
    # (section, option, submitted value, inherit-checkbox)
    pw_fields = [
        ("kea6", "api_pass", api_pass, inherit_api_pass, no_api_pass),
        ("kea6_db", "password", db_pass, inherit_db_pass, no_db_pass),
    ]
    changed: list[str] = []

    def _apply(cfg):
        for section, opt, val in text_fields:
            has = cfg.has_section(section) and cfg.has_option(section, opt)
            if val:
                if not has or cfg.get(section, opt) != val:
                    if not cfg.has_section(section):
                        cfg.add_section(section)
                    cfg.set(section, opt, val)
                    changed.append(f"{section}.{opt} set")
            elif has:
                cfg.remove_option(section, opt)
                changed.append(f"{section}.{opt} cleared — inherits v4")
        for section, opt, val, inherit, none_ in pw_fields:
            has = cfg.has_section(section) and cfg.has_option(section, opt)
            if none_ or inherit or val:
                # Y3 (Q183): a password that is typed, made blank, or taken back to "inherit" in this save is not a marked COPY any more
                __credentials.clear_shared(cfg, "kea6" if section == "kea6" else "kea6_db")
            if none_:
                if not cfg.has_section(section):
                    cfg.add_section(section)
                if not has or cfg.get(section, opt) != "":
                    cfg.set(section, opt, "")
                    changed.append(f"{section}.{opt} set to no password")
            elif inherit:
                if has:
                    cfg.remove_option(section, opt)
                    changed.append(f"{section}.{opt} inherits v4")
            elif val:
                if not cfg.has_section(section):
                    cfg.add_section(section)
                cfg.set(section, opt, val)
                changed.append(f"{section}.{opt} set")
        for section in ("kea6", "kea6_db"):
            if cfg.has_section(section) and not cfg.options(section):
                cfg.remove_section(section)

    # AA2 (Q185): a literal set chosen by what the form said - the password typed and not taken back to "inherit", for each of the two endpoints this form writes
    typed_kea6 = api_pass and not inherit_api_pass
    typed_kea6_db = db_pass and not inherit_db_pass
    typed_names = (
        {"kea6", "kea6_db"}
        if (typed_kea6 and typed_kea6_db)
        else {"kea6"}
        if typed_kea6
        else {"kea6_db"}
        if typed_kea6_db
        else set()
    )
    __config.app_config.mutate(_apply, typed=typed_names)

    if not changed:
        flash("No Kea6 changes.", "info")
        return redirect(url_for("settings.settings_kea"))

    summary = "; ".join(changed)
    __user.set_global_setting("restart_pending", "true")
    flash(f"Kea6 settings saved: {summary}. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "kea6_api", summary)
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/save-d2", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def save_infra_d2():
    """v5.23.0 (Q19) — [d2] api_url/api_user/api_pass, same inheritance
    shape as save_infra_kea6 above (minus a _db companion — D2 has no
    database of its own): blank text field removes the key so ca-mode
    falls back to [kea] api_url again at the next reload; blank password
    is kept unless "Inherit" is ticked."""
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_pass = request.form.get("api_pass", "").strip()
    inherit_api_pass = request.form.get("inherit_api_pass", "") == "1"
    no_api_pass = request.form.get("no_api_pass", "") == "1"  # Q180 second pass: an explicit "no authentication"

    if api_url and __auth.userinfo_sentence(api_url):
        flash(__auth.userinfo_sentence(api_url), "error")  # Q190 (CRED-005)
        return redirect(url_for("settings.settings_kea"))
    if api_url and not __auth.valid_api_url(api_url, require_port=(__caps.is_direct())):
        if __caps.is_direct():
            flash(
                "The D2 API URL must be a valid http(s):// URL with an explicit port "
                "in direct mode (e.g. http://kea:53001).",
                "error",
            )
        else:
            flash("The D2 API URL must be a valid http:// or https:// URL.", "error")
        return redirect(url_for("settings.settings_kea"))

    # CRED-002 (Q178): D2's own saved password stays with D2's endpoint; the password it INHERITS from the Kea API (no own one, or "Inherit" ticked) stays with the Kea API's host
    own_pass = extensions.cfg.get("d2", "api_pass", fallback="")
    effective_pass = "" if inherit_api_pass else api_pass  # Q179 (T2): the secret the checks judge is the EFFECTIVE one
    refusal = _one_answer_for_a_secret(inherit_api_pass, api_pass, "D2 API password|the Kea API's")
    if no_api_pass and (inherit_api_pass or api_pass):
        refusal = "Choose one for the D2 API password: no password, inherit it, or type one."
    if refusal:
        pass
    elif no_api_pass:
        refusal = None  # an explicit "no password" sends nothing anywhere
    elif own_pass.strip() and not inherit_api_pass:
        refusal = _secret_for_new_endpoint(
            extensions.cfg.get("d2", "api_url", fallback=""), api_url, effective_pass, own_pass, "D2 API address"
        )
    else:
        refusal = _inherited_secret_refusal(
            extensions.cfg.get("kea", "api_url", fallback=""),
            api_url,
            effective_pass,
            extensions.cfg.get("kea", "api_pass", fallback=""),
            "D2 API address",
        )
    if refusal:
        flash(refusal, "error")
        return redirect(url_for("settings.settings_kea"))

    text_fields = [("d2", "api_url", api_url), ("d2", "api_user", api_user)]
    changed: list[str] = []

    def _apply(cfg):
        for section, opt, val in text_fields:
            has = cfg.has_section(section) and cfg.has_option(section, opt)
            if val:
                if not has or cfg.get(section, opt) != val:
                    if not cfg.has_section(section):
                        cfg.add_section(section)
                    cfg.set(section, opt, val)
                    changed.append(f"{section}.{opt} set")
            elif has:
                cfg.remove_option(section, opt)
                changed.append(f"{section}.{opt} cleared — inherits v4")
        has_pass = cfg.has_section("d2") and cfg.has_option("d2", "api_pass")
        if no_api_pass or inherit_api_pass or api_pass:
            __credentials.clear_shared(cfg, "d2")  # Y3 (Q183): no longer a marked copy
        if no_api_pass:
            if not cfg.has_section("d2"):
                cfg.add_section("d2")
            if not has_pass or cfg.get("d2", "api_pass") != "":
                cfg.set("d2", "api_pass", "")
                changed.append("d2.api_pass set to no password")
        elif inherit_api_pass:
            if has_pass:
                cfg.remove_option("d2", "api_pass")
                changed.append("d2.api_pass inherits v4")
        elif api_pass:
            if not cfg.has_section("d2"):
                cfg.add_section("d2")
            cfg.set("d2", "api_pass", api_pass)
            changed.append("d2.api_pass set")
        if cfg.has_section("d2") and not cfg.options("d2"):
            cfg.remove_section("d2")

    __config.app_config.mutate(_apply, typed={"d2"} if api_pass and not inherit_api_pass else None)

    if not changed:
        flash("No D2 changes.", "info")
        return redirect(url_for("settings.settings_kea"))

    summary = "; ".join(changed)
    __user.set_global_setting("restart_pending", "true")
    flash(f"D2 settings saved: {summary}. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "d2_api", summary)
    return redirect(url_for("settings.settings_kea"))


def _probe_once(url, user, pwd, omit_service, service="dhcp4", verify=None, cert=None):
    """One version-get against a candidate endpoint, independent of the
    globally-configured connection mode. Returns (version_text, error):
    exactly one is non-empty.

    v5.29.0 (Q29) — `verify` / `cert` override the configured TLS
    material: the https setup flow probes a socket with a CA and client
    certificate Jen has NOT adopted yet (it only writes them into its
    config once the socket answers).

    v5.67.0-beta.5 (Q117, item f) — delegates to kea.test_connection(),
    the one shared TLS-aware probe primitive /setup's Connect step now
    also uses, rather than keeping its own copy of this body."""
    return __kea.test_connection(url, user, pwd, service=service, omit_service=omit_service, verify=verify, cert=cert)


# v5.29.3 — a daemon that was just restarted opens its HTTP listener LAST
# (after the config is parsed and the lease backend is up — seconds, with
# MySQL), so a probe fired straight after `systemctl restart` gets
# "connection refused" and the maintainer's first https setup reported a
# failure for a socket that was fine two seconds later.
_PROBE_ATTEMPTS = 8
_PROBE_DELAY_S = 2.0


def _probe_fault_class(err: str) -> str:
    """Q193 (AI4 b): "" when the text of a failed probe is the daemon REJECTING the certificate (a TLS/certificate refusal - the evidence the new client certificate is not accepted); else the CLASS of a
    transport fault that proves nothing about trust (a timeout, a lost connection, a refused connection, anything else). `probe_command` folds the exception into its text, so the text is what there is."""
    import re as _re

    low = _re.sub(
        r"https?://\S+|host='[^']*'|host=\"[^\"]*\"", " ", (err or "").lower()
    )  # (second pass, finding 8: a host NAME such as tls-kea.lan or kea-alerts.lan is not evidence)
    if not low.strip():
        return "no answer"
    timed_out = "timed out" in low or "timeout" in low
    if (
        any(w in low for w in ("certificate", "unknown ca"))
        or _re.search(r"\balert\b", low)  # (the WORD: a host called kea-alerts is not a TLS alert)
        or (not timed_out and any(w in low for w in ("ssl", "tls", "handshake")))
    ):
        return ""
    if timed_out:
        return "a timeout"
    if "refused" in low:
        return "a refused connection"
    if "eof" in low or "reset" in low or "connection" in low or "broken pipe" in low:
        return "a lost connection"
    return "a transport error"


#: Q195 (second pass, rows 1-2): what a failed probe says when the failure is NOT about a client certificate - Jen failing to verify the daemon's own certificate, a name that does not resolve, a daemon
#: that is not there, a timeout. They are looked at FIRST, so a host called `kea-alert.lan` or a `tlsv1 alert protocol version` is never read as a rejection of the client certificate.
_NOT_ABOUT_THE_CLIENT_CERTIFICATE = (
    "verify failed",
    "timed out",
    "timeout",
    "refused",
    "failed to resolve",
    "name or service not known",
    "name resolution",
    "no route to host",
    "unreachable",
)
#: ... and what it says when the daemon turned the client certificate down. On TLS 1.3 the server's alert races its close, so a real rejection arrives about as often as a closed connection
#: ("EOF occurred in violation of protocol", "Remote end closed connection") as it does as an alert (executed against a real OpenSSL server: 88-95 percent of rejections were the closure).
_CLIENT_CERTIFICATE_REJECTED = (
    "client certificate",
    "eof occurred in violation of protocol",
    "remote end closed connection",
    "connection reset",
    "connection aborted",
)


def _rejects_the_client_certificate(err: str) -> bool:
    """Q195 (AK1): is the text of a failed probe the daemon turning the client certificate Jen presented DOWN - a certificate alert, a named client certificate, or the connection closed during the TLS
    handshake (how a TLS 1.3 server says it) - and not Jen failing to verify the daemon's OWN certificate, a name that does not resolve, a daemon that is not there or a timeout? The closure is
    ambiguous by nature (a daemon that died mid-handshake reads the same), which is why the sentence it earns says "usually because" and why acceptance of the REPLACEMENT is what lets a recovery go on."""
    import re as _re

    low = _re.sub(r"https?://\S+|host='[^']*'|host=\"[^\"]*\"", " ", (err or "").lower())
    if any(w in low for w in _NOT_ABOUT_THE_CLIENT_CERTIFICATE):
        return False
    if _re.search(
        r"alert (?:bad |unsupported |expired |revoked |unknown )?certificate|alert (?:unknown ca|handshake failure|access denied)",
        low,
    ):
        return True
    return any(w in low for w in _CLIENT_CERTIFICATE_REJECTED)


def _staged_identity_refusal(inventory, kind: str, staged: dict, recovery: bool = False) -> str:
    """Q192 (AH1, the P1): the staged identity is proved, against every https endpoint Jen PRESENTS its client pair to, BEFORE anything is installed on any host. Jen's pair is global - when it is
    Jen's own (`jens-file` / `alias`) it goes to every https endpoint, the administrator's included - and an external endpoint whose `cert-required` trust anchor is Jen's CA accepts today's client
    certificate and refuses the new one: the rotation would promote a CA that daemon never learned, and Jen would be locked out of it with 'rotated' on the screen. Each external endpoint is probed
    twice with the configured bundle - with the LIVE pair (the baseline: an endpoint that does not answer it is unreachable regardless, and the refusal says so) and with the STAGED pair; one that
    answers the first and refuses the second DEPENDS on Jen's CA for client authentication. "" when nothing depends. A client kind of `none` presents nothing; a damaged live pair is no baseline
    (Jen's dial is already broken) - and with an external endpoint present it cannot be proved, so that is a refusal that points at the repair."""
    from jen.services import kea_tls as __tls

    if kind not in ("jens-file", "alias") or not inventory.external_endpoints:
        return ""
    live_state, live_why = __tls.client_state(judge_issuer=not recovery)
    if live_state not in ("ok", "expiring"):
        what = (
            "Jen has no client certificate (jen-kea-client.pem and jen-kea-client.key are both missing)"
            if live_state == "none"
            else f"Jen's client certificate is damaged ({live_why})"
        )
        return f"{what}, so Jen cannot prove whether an endpoint it does not manage depends on it - " + (
            "replace the CA with the acknowledged Rotate only after the client pair is restored from a backup"
            if recovery
            else "set up an https socket again (it re-issues the pair from the same CA), then rotate"
        )
    live_pair = __kea._tls_client_cert()
    staged_pair = (staged["client_cert"], staged["client_key"])
    verify = __kea._tls_verify()
    for server, service, _url in inventory.external_endpoints:
        url = _service_url(server, service)
        if not url:
            continue  # Jen has no credential it may send there: it dials nothing, so it presents no pair to it
        label = f"{server.get('name') or 'Kea Server ' + str(server.get('id'))} {_DAEMON_NAME[service]} ({__auth.shown_url(url)})"
        user, pwd = _daemon_creds(server, service)
        try:
            live_version, live_err = _probe_once(
                url, user, pwd, omit_service=True, service=service, verify=verify, cert=live_pair
            )
            staged_version, staged_err = _probe_once(
                url, user, pwd, omit_service=True, service=service, verify=verify, cert=staged_pair
            )
        except Exception as e:  # a probe that raised proved nothing: the refusal is the safe reading (never a promotion with the endpoint unproved)
            return f"{label} could not be probed ({type(e).__name__}), so Jen cannot tell whether it depends on its client certificate"
        if not live_version and recovery and _rejects_the_client_certificate(live_err):
            # Q195 (AK1): in a RECOVERY the live pair fails BECAUSE the CA being replaced is the one this endpoint trusts and it can no longer vouch (expired, not a CA ...) - that is the world a
            # recovery exists for, and "it has to answer" cannot be required of it. The question is the REPLACEMENT: accepted -> the endpoint already trusts it (not a refusal); rejected too -> the
            # operator must install the new CA on it first. A transport fault proves nothing about trust and keeps the sentences below.
            if staged_version:
                continue
            staged_fault = "" if _rejects_the_client_certificate(staged_err) else _probe_fault_class(staged_err)
            if staged_fault:
                return (
                    f"{label} could not be probed with the new client certificate ({staged_fault}), so Jen cannot tell whether it accepts it - "
                    "try again when the endpoint answers"
                )
            return (
                f"{label} rejects Jen's current client certificate (usually because the damaged CA is the one it trusts) and does not accept the new one yet: "
                "Prepare the new CA, install its certificate on that endpoint, then rotate again"
            )
        if not live_version:
            return (
                f"{label} does not answer Jen's current client certificate ({__auth.scrub_urls(live_err) or _probe_fault_class(live_err) or 'no answer'}), so Jen cannot tell whether it depends on it - "
                "it has to answer before a rotation can be proved safe"
            )
        fault = _probe_fault_class(staged_err) if not staged_version else ""
        if fault:
            # (Q193, AI4 b) a transport fault proves nothing about trust - the refusal stands, but it says what happened
            return (
                f"{label} could not be probed with the new client certificate ({fault}), so Jen cannot tell whether it depends on the current one - "
                "try again when the endpoint answers"
            )
        if not staged_version:
            return (
                f"{label} accepts Jen's current client certificate and refuses the new one: its trust anchor for client certificates is Jen's current CA. "
                "Prepare the rotation first, install the new CA certificate on it (beside the current one), then rotate"
            )
    return ""


def _probe_after_restart(url, user, pwd, service, verify=None, cert=None):
    """_probe_once, retried for ~15 s while the daemon comes up. Returns
    (version_text, error) like _probe_once; `error` is the LAST failure."""
    version_text, err = "", ""
    for attempt in range(_PROBE_ATTEMPTS):
        version_text, err = _probe_once(url, user, pwd, omit_service=True, service=service, verify=verify, cert=cert)
        if version_text:
            return version_text, ""
        if attempt < _PROBE_ATTEMPTS - 1:
            time.sleep(_PROBE_DELAY_S)
    return (
        "",
        f"{__auth.scrub_urls(err)} — after {_PROBE_ATTEMPTS} attempts over {int(_PROBE_ATTEMPTS * _PROBE_DELAY_S)} s",
    )


def _identify_daemon(url, user, pwd, service, verify=None, cert=None):
    """v5.28.1 (Q26, D2) — best-effort direct-style config-get against a
    URL that has already answered version-get, to see WHICH daemon
    actually answered: a Control Agent left listening on :8000 (because
    only its unix socket, never an http one, was ever configured on the
    daemon side) answers version-get identically to a real per-daemon
    control socket — the probe used to have no way to tell them apart.
    Returns the reply's single top-level config key ("Dhcp4",
    "Control-agent", ...), or None on any failure — advisory only, this
    never raises and never changes whether the probe as a whole
    succeeded. `verify`/`cert` as in _probe_once (v5.29.0).

    v5.67.0-beta.8 (Q120, item b) — the implementation is kea.identify_daemon(),
    shared with the setup wizard so both decide a connection mode the same way."""
    return __kea.identify_daemon(url, user, pwd, verify=verify, cert=cert)


def _is_kea_url_shape(url: str) -> bool:
    """`scheme://host:port` and at most a trailing slash: no user-info, path, query or fragment. A candidate URL is probed with Jen's own Kea credentials (v5.69.0-beta.5, Q174),
    so a URL that is anything but where a Kea daemon listens - `http://internal:8080/admin?x=` - is not one to send them to."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for a port that is not a number (`kea:8004;x`)
        return not (parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"))
    except ValueError:
        return False


@bp.route("/settings/infrastructure/probe-kea", methods=["POST"])
@login_required
@_admin_required
def probe_kea():
    """
    v5.10.0 — reachability + version probe for the Kea command channel.
    Tries the configured [kea] api_url in the configured mode first; if
    that doesn't answer, tries a direct control socket at the same host
    on port 8004 (ISC's example dhcp4 port). Reports the Kea version,
    which mode answered, and a recommendation keyed on the version:
    Control Agent removed in 3.2, deprecated in 3.0, and direct sockets
    only exist from 2.7.2. Read-only — never writes config.

    v5.10.2 — with a `candidate_url` form field, probes ONLY that URL
    (direct-style, no service field, no :8004 auto-fallback) so an admin
    whose direct socket doesn't share the CA's scheme/host can test it
    before committing. The scheme is never downgraded.

    v5.10.3 — `server_id` and `service` pick WHICH endpoint to probe. The
    URL and credentials come from _endpoint_for(server, service), i.e.
    exactly what Jen will dial for that daemon on that server; before
    this, probing was always the primary's URL with the primary's
    credentials, so a standby could not be tested at all.
    """
    from urllib.parse import urlparse

    configured_mode = "direct" if __caps.is_direct() else "ca"
    attempts = []

    service = "dhcp6" if request.form.get("service", "").strip() == "dhcp6" else "dhcp4"
    raw_id = request.form.get("server_id", "").strip()
    server = None
    if raw_id.isdigit():
        server = next((s for s in extensions.KEA_SERVERS if str(s.get("id")) == raw_id), None)
    if server is None:
        server = extensions.KEA_SERVERS[0] if extensions.KEA_SERVERS else None
    server_name = (server or {}).get("name", "Kea Server 1")

    endpoint = __kea._endpoint_for(server, service)
    if isinstance(endpoint, dict):  # direct + dhcp6 with no v6 URL for this server
        return jsonify({"ok": False, "error": endpoint["text"], "server": server_name, "service": service}), 400
    configured_url, user, pwd = endpoint

    candidate = request.form.get("candidate_url", "").strip()
    if candidate:
        if not __auth.valid_api_url(candidate, require_port=True) or not _is_kea_url_shape(candidate):
            return jsonify(
                {
                    "ok": False,
                    "error": "The candidate URL must be a valid http(s):// URL with an explicit port "
                    "(e.g. https://kea:8004).",
                }
            ), 400
        # RBAC-004 / CRED-002 (Q179): the probe sends the saved Kea credentials to the address it is given. An admin may test another daemon of the host Jen already
        # reaches; sending them to a different host is a superadmin's deliberate test of an address they typed.
        if current_user.role != "superadmin" and not __auth.same_host(configured_url, candidate):
            return jsonify(
                {
                    "ok": False,
                    "error": "Only a superadmin probes an address on a different host from the one Jen reaches - the probe sends the saved Kea credentials to it.",
                }
            ), 403
        version_text, err = _probe_once(candidate, user, pwd, omit_service=True, service=service)
        attempts.append({"url": candidate, "mode": "direct", "error": err or ""})
        answered_mode = "direct" if version_text else None
        answered_url = candidate if version_text else None
    else:
        version_text, err = _probe_once(
            configured_url, user, pwd, omit_service=(configured_mode == "direct"), service=service
        )
        answered_mode = configured_mode if version_text else None
        answered_url = configured_url if version_text else None
        if not version_text:
            attempts.append({"url": configured_url, "mode": configured_mode, "error": err})
            host = urlparse(configured_url).hostname
            scheme = urlparse(configured_url).scheme or "http"
            if host and configured_mode != "direct":
                alt = f"{scheme}://{host}:{8006 if service == 'dhcp6' else 8004}"
                version_text, err2 = _probe_once(alt, user, pwd, omit_service=True, service=service)
                if version_text:
                    answered_mode, answered_url = "direct", alt
                else:
                    attempts.append({"url": alt, "mode": "direct", "error": err2})

    if not version_text:
        return jsonify(
            {
                "ok": False,
                "candidate": bool(candidate),
                "configured_mode": configured_mode,
                "server": server_name,
                "service": service,
                "attempts": attempts,
                "recommendation": {
                    "text": "Nothing answered a version-get. Check the URL, credentials, and that a Kea "
                    "control socket (or Control Agent) is actually listening.",
                    "level": "bad",
                },
            }
        )

    v = __kea.parse_kea_version(version_text)
    version = ".".join(str(n) for n in v) if v else ""

    # v5.28.1 (Q26, D2) — identify WHICH daemon answered before trusting
    # a "direct mode is working" recommendation. Only relevant when
    # something actually answered in direct mode (configured or
    # candidate) — kea_is_up() stays untouched (called per server on
    # every dashboard render; this extra config-get is too heavy there).
    identified_key = _identify_daemon(answered_url, user, pwd, service) if answered_mode == "direct" else None

    if v is None:
        rec = ("Reached Kea, but couldn't parse a version from its reply.", "warn")
    elif identified_key == "Control-agent":
        daemon_port = 8006 if service == "dhcp6" else 8004
        if __caps.may_ship_control_agent(v):
            # Maintainer decision (2026-09-13, Q26 Q1) — Kea still
            # supports the Control Agent at this version, so this is a
            # config gap to fix, not a dead end: stay on ca mode until
            # the daemon sockets exist.
            # v5.29.0 (Q28/Q29) — the maintainer hit this on 2026-09-13
            # and reported "it's not apparent where this goes": name
            # the file and key, and point at the button that now does
            # it (Set up direct socket, on this page).
            rec = (
                f"{__auth.shown_url(answered_url)} is the Control Agent, not kea-{service}'s own control socket — Kea {version} "
                f"still supports the Control Agent, so stay on Control Agent mode until kea-{service} has an "
                f"http control socket of its own (an http entry in the control-sockets list of "
                f"/etc/kea/kea-{_CONF_STEM[service]}.conf on that host, keeping the unix entry, conventionally "
                f':{daemon_port}). Let Jen add it: "Set up direct socket" on this page edits the file, restarts '
                f"kea-{service}, probes the socket and switches Jen over only once it answers — or add it by "
                'hand per the admin guide\'s "Direct control sockets" section.',
                "warn",
            )
        else:
            # Maintainer decision (2026-09-13, Q26 Q1) — on the box that
            # surfaced this, the fix was ADDING an http control socket
            # to the daemon, not just pointing at a different port, so
            # the recommendation points at where that's actually done.
            rec = (
                f"{__auth.shown_url(answered_url)} is the Control Agent, not kea-{service}'s own control socket — direct mode "
                f"needs the daemon's http socket (conventionally :{daemon_port}). Either switch back to "
                f'Control Agent mode, or give kea-{service} its own http control socket: "Set up direct '
                f"socket\" on this page adds it to /etc/kea/kea-{_CONF_STEM[service]}.conf's control-sockets "
                f"list, restarts kea-{service} and points Jen at it once it answers — or add it by hand per "
                'the admin guide\'s "Direct control sockets" section.',
                "bad",
            )
    elif candidate:
        rec = (
            f"Kea {version} answered on {__auth.shown_url(answered_url)} — set this as the API URL and switch to Direct mode.",
            "ok",
        )
    elif answered_mode == "direct":
        rec = (
            f"Kea {version} answered on its direct control socket — this is the mode to use for Kea 3.2+.",
            "ok",
        )
    elif not __caps.may_attempt_direct_socket(v):
        rec = (
            f"Kea {version} predates per-daemon control sockets (2.7.2), so the Control Agent is the only "
            "option here. Plan a Kea upgrade before moving to 3.2.",
            "warn",
        )
    elif __caps.may_ship_control_agent(v):
        # Maintainer decision (2026-09-13, Q26 Q1) — this recommendation
        # is what led a real box into direct mode with no daemon http
        # socket configured at all (D2's identity branch above is what
        # now catches that case); reworded so it never again reads as
        # "switch now" before the socket actually exists.
        rec = (
            f"Kea {version} still ships the Control Agent, but ISC deprecated it in 3.0 and removes it in "
            "3.2. Switch to direct mode — after adding an http control socket to each daemon, not before.",
            "warn",
        )
    else:
        rec = (
            f"Kea {version} removed the Control Agent (3.2). ca mode cannot work against this server — "
            "switch to direct mode.",
            "bad",
        )

    # v5.29.3 — the Control Agent answered where a daemon socket should
    # be, and Jen has issued an https certificate for this daemon on this
    # server: say whether THAT socket is listening. This is exactly the
    # state a "Set up direct socket" run that stopped at the probe leaves
    # behind, and the one question the operator has at that moment.
    jen_socket = None
    if identified_key == "Control-agent" and server is not None:
        jen_socket = _probe_jen_socket(server, service, user, pwd, urlparse(answered_url).hostname or "")
        if jen_socket is not None:
            attempts.append({"url": jen_socket["url"], "mode": "direct (Jen's CA)", "error": jen_socket["error"]})
            if jen_socket["ok"]:
                extra = (
                    f' The https socket Jen set up on {__auth.shown_url(jen_socket["url"])} answers as kea-{service} — run "Set up '
                    'direct socket" again and Jen switches over.'
                )
            else:
                extra = (
                    f" The https socket Jen set up on {__auth.shown_url(jen_socket['url'])} does not answer ({jen_socket['error']}) — "
                    f"kea-{service} isn't listening on it: check `journalctl -u kea-{_CONF_STEM[service]}-server -n 30` "
                    f"on the host (TLS files under /etc/kea/tls/{service}/ the daemon's user can't read are the usual cause)."
                )
            rec = (rec[0] + extra, rec[1])

    __user.audit(
        "PROBE_KEA",
        "kea_api",
        f"server={server_name} service={service} version={version or '?'} "
        f"answered={answered_mode} candidate={bool(candidate)}",
    )
    return jsonify(
        {
            "ok": True,
            "candidate": bool(candidate),
            "server": server_name,
            "service": service,
            "version": version,
            "version_raw": version_text.splitlines()[0] if version_text else "",
            "configured_mode": configured_mode,
            "answered_mode": answered_mode,
            "answered_url": answered_url,
            "attempts": attempts,
            "recommendation": {"text": rec[0], "level": rec[1]},
            "jen_socket": jen_socket,
        }
    )


def _probe_jen_socket(server: dict, service: str, user: str, pwd: str, fallback_host: str):
    """v5.29.3 — if Jen has issued an https certificate for `service` on
    `server` (a kea-servers/ copy exists), probe the socket it was issued
    for — bind address from the certificate's SAN (else the URL's host),
    the conventional port — with Jen's CA and client certificate, and
    check it identifies as the daemon. Returns None when Jen never issued
    one, else {"url", "ok", "error"}. Never raises."""
    import os

    from jen.services import kea_tls
    from jen.services.kea_authoring import DIRECT_SOCKET_DEFAULT_PORTS

    copy = kea_tls.server_copy_path(server.get("id"), service)
    if not os.path.isfile(copy):
        return None
    host = fallback_host
    try:
        from cryptography import x509

        san = kea_tls.load_cert(copy).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        ips = san.get_values_for_type(x509.IPAddress)
        if ips:
            host = str(ips[0])
    except Exception:
        pass
    if not host:
        return None
    url = _socket_url("https", host, DIRECT_SOCKET_DEFAULT_PORTS[service])
    ca = kea_tls.ca_paths()[0]
    cert = kea_tls.client_paths()
    version_text, err = _probe_once(url, user, pwd, omit_service=True, service=service, verify=ca, cert=cert)
    if not version_text:
        return {"url": url, "ok": False, "error": err}
    who = _identify_daemon(url, user, pwd, service, verify=ca, cert=cert)
    if who != _DAEMON_KEY[service]:
        return {"url": url, "ok": False, "error": f"answered as {who or 'an unknown daemon'}, not kea-{service}"}
    return {"url": url, "ok": True, "error": ""}


# ── Direct control sockets, set up by Jen (v5.29.0, Q29) ────────────────────

_DIRECT_SERVICES = ("dhcp4", "dhcp6", "d2")
_DAEMON_NAME = {"dhcp4": "kea-dhcp4", "dhcp6": "kea-dhcp6", "d2": "kea-dhcp-ddns"}
_CONF_STEM = {"dhcp4": "dhcp4", "dhcp6": "dhcp6", "d2": "dhcp-ddns"}
_DAEMON_KEY = {"dhcp4": "Dhcp4", "dhcp6": "Dhcp6", "d2": "DhcpDdns"}
# The [kea]/[kea_server_N] key that remembers the Control Agent URL a
# dhcp4 socket replaced, so "Switch back" can restore it. Not a form
# field: _rewrite_extra_servers copies it forward with the other
# unmanaged keys (it's not in _EXTRA_SERVER_FORM_KEYS).
_PREV_URL_KEY = "direct_prev_api_url"
# Z2 (v5.69.0-beta.15, Q184): the Control Agent's own pair is remembered beside its address, so a switch back can put the pair back - the socket's pair is the SOCKET's, and the
# Control Agent authenticates with the Control Agent's. (jen.config is private; `support_bundle` masks any `*_pass` key.)
_PREV_USER_KEY = "direct_prev_api_user"
_PREV_PASS_KEY = "direct_prev_api_pass"
_PREV_SHARED_KEY = (
    "direct_prev_api_pass_shared"  # AA3 (Q185): the saved pair was a marked copy, and a restored copy is one again
)
# AB4 (Q186): what the Control Agent had is saved as it WAS - a value, a blank, or NOTHING. "Nothing" is recorded too, so a restore puts back absence (and the page can offer a restore of
# a Control Agent that had neither a user nor a password) instead of leaving the socket's user or writing an explicit blank over an inherited password.
_PREV_USER_ABSENT_KEY = "direct_prev_api_user_absent"
_PREV_PASS_ABSENT_KEY = "direct_prev_api_pass_absent"
_PREV_PAIR_KEYS = (_PREV_USER_KEY, _PREV_PASS_KEY, _PREV_SHARED_KEY, _PREV_USER_ABSENT_KEY, _PREV_PASS_ABSENT_KEY)


def _server_by_id(server_id):
    return next((s for s in extensions.KEA_SERVERS if s.get("id") == server_id), None)


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return True


def _socket_url(scheme: str, address: str, port: int) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"{scheme}://{host}:{port}"


def _mode_of(cfg) -> str:
    """The connection mode as `credentials.resolve` and `AppConfig` read it: anything but "direct" is "ca"; stripped and lower-cased (a hand edit of `Direct` is `direct`)."""
    value = cfg.get("kea", "connection_mode", fallback="ca").strip().lower()
    return "direct" if value == "direct" else "ca"


def _endpoint_name(server: dict, service: str) -> str:
    """The `credentials.resolve` name of the endpoint one daemon of one server is reached on."""
    sid = (server or {}).get("id")
    if sid in (None, 1):
        return {"dhcp4": "kea", "dhcp6": "kea6", "d2": "d2"}[service]
    return f"server_{sid}" + {"dhcp4": "", "dhcp6": "_v6", "d2": "_d2"}[service]


def _socket_keys(server: dict, service: str) -> tuple[str, str, str, str]:
    """(section, url key, user key, password key) of the endpoint one daemon of one server is reached on."""
    sid = (server or {}).get("id")
    if sid in (None, 1):
        return {
            "dhcp4": ("kea", "api_url", "api_user", "api_pass"),
            "dhcp6": ("kea6", "api_url", "api_user", "api_pass"),
            "d2": ("d2", "api_url", "api_user", "api_pass"),
        }[service]
    return (
        f"kea_server_{sid}",
        *{
            "dhcp4": ("api_url", "api_user", "api_pass"),
            "dhcp6": ("api6_url", "api6_user", "api6_pass"),
            "d2": ("api_d2_url", "api_d2_user", "api_d2_pass"),
        }[service],
    )


def _daemon_creds(server: dict, service: str, url: str = "") -> tuple[str, str]:
    """The basic-auth pair `credentials.resolve` gives this daemon's endpoint - the form's defaults, so an operator who keeps one API user per host types nothing. v5.69.0-beta.13
    (Q182, X4): there is NO second decider here (the old fallback to the server's v4 pair was one: it handed a different host's password to the form). `url` is the address the
    endpoint is ABOUT to be given (the socket this flow creates): resolved as if it were already saved, so the pair that comes back is the one the writer will let that address
    have - the server's own on the same host, nothing on a different one."""
    parser = __config.app_config._read_parser()
    if url:
        section, url_key, _user_key, _pass_key = _socket_keys(server, service)
        if not parser.has_section(section):
            parser.add_section(section)
        parser.set(section, url_key, url)
    endpoint = __credentials.resolve(parser).get(_endpoint_name(server, service))
    return (endpoint.user, endpoint.password) if endpoint is not None else ("", "")


def _sentence_of(refusal: BaseException) -> str:
    """The words for a failed write of Jen's own settings: the writer's own sentence for a refusal, one that names the failure for anything else (a read-only file, a full disk)."""
    if getattr(refusal, "sentence", ""):
        return refusal.sentence
    # (Q187, AC6) the class and the errno's own words - never `str(error)`, which for an OSError carries the path of the file
    detail = (
        f"{type(refusal).__name__}, errno {refusal.errno}: {refusal.strerror}"
        if isinstance(refusal, OSError) and refusal.errno is not None
        else type(refusal).__name__
    )
    return f"Jen could not write its own settings ({detail}) - the file may be read-only or the disk full."


def _api_sockets_of(server: dict, service: str, errors: list | None = None):
    """AB1 (Q186): the daemon's http/https control sockets as the Kea host has them RIGHT NOW (a read that records no config revision), or None when the config could not be read.
    The route asks before it sends anything: a daemon with more than one is refused, not flattened. Q189 (AE4): `errors` collects why a read failed (the connection, a refusal) - a route that
    stops on it says so, and nothing has been sent by then."""
    from jen.services import kea_config_edit as __edit
    from jen.services import kea_host as __host

    cfg = __host.read_config(server, service, capture=False, errors=errors)
    if not isinstance(cfg, dict):
        return None
    return [s for s in __edit.control_sockets(cfg, service) if __edit._is_api_socket(s)]


def _preread_refusal(server: dict, service: str, conf: str, errors: list) -> bool:
    """Q189 (AE4): the pre-read is a call site too. When the read of the daemon's config failed for a reason a person can act on (the connection, a refusal), the route stops BEFORE it sends
    anything and says so - `nothing was changed`. A file that is simply not there (no reason collected) is the route's own business, as before."""
    if not errors:
        return False
    name = server.get("name") or f"Kea Server {server.get('id')}"
    flash(
        f"Jen could not reach {name} to read {conf} ({errors[0]}); nothing was changed. Check the SSH connection and the Kea host helper, then try again.",
        "error",
    )
    return True


def _many_sockets_sentence(daemon: str, conf: str, count: int | None = None) -> str:
    """AB1 (Q186): the refusal for a daemon whose config has more than one http/https control socket."""
    what = f"{count} API sockets" if count else "more than one API socket"
    return f"{daemon} has {what} in {conf}; Jen manages one - remove the others by hand first. Nothing was changed."


#: AB2 (Q186): where a person finds what a socket's own entry held (its authentication and TLS settings), which no flash, audit row or log line ever prints
_SOCKET_ENTRY_LIVES = "its authentication and TLS settings are in Jen's config history for this server (Settings → Kea → Config History) and in the daemon's last revision"


def _direct_socket_edit(server: dict, service: str, url: str, user: str, password: str, tls: bool = False):
    """(fn, changed): the edit `_write_direct_socket_config` makes to Jen's own config, as a `mutate`-style callback, and the list of phrases it fills in when
    it runs. The setup route hands the SAME callback to `preflight_identity_change` before it touches the Kea host (v5.68.0-beta.28, Q164), so the
    question "would the config writer refuse this?" is asked about exactly what will be written."""
    """Point Jen at the daemon socket that just answered. dhcp4 also
    flips `[kea] connection_mode` to direct (the mode is global — see
    the flash the caller adds when other servers aren't there yet);
    dhcp6/D2 only write their own per-daemon URL, since a dhcp4 socket
    is what the mode switch actually needs. `tls` (https via Jen's CA)
    also writes the GLOBAL trust anchor + client certificate — one CA,
    one Jen identity, for every server — and pins `api_tls_verify` on
    (this flow never sets it off). Returns a short phrase for the flash
    saying what was written."""
    changed: list[str] = []

    def _apply(cfg):
        before_resolved = __credentials.resolve(cfg)  # what each endpoint of the server sent BEFORE this edit
        if tls:
            from jen.services import kea_tls as __tls

            ca_crt, _ca_key = __tls.ca_paths()
            client_pem, client_key = __tls.client_paths()
            if not cfg.has_section("kea"):
                cfg.add_section("kea")
            # (second pass, Q190: not a comparison of paths - an alias or copy of Jen's CA the gate let through is left as the operator wrote it; only a missing value is filled in)
            if not cfg.get("kea", "api_ca", fallback="").strip():
                cfg.set("kea", "api_ca", ca_crt)
                changed.append("[kea] api_ca (Jen's CA)")
            if not cfg.get("kea", "api_client_cert", fallback="").strip():
                cfg.set("kea", "api_client_cert", client_pem)
                cfg.set("kea", "api_client_key", client_key)
                changed.append("[kea] api_client_cert/api_client_key (Jen's client certificate)")
            cfg.set("kea", "api_tls_verify", "true")
        sec, url_key, user_key, pass_key = _socket_keys(server, service)
        if not cfg.has_section(sec):
            cfg.add_section(sec)
        old_url = cfg.get(sec, url_key, fallback="")
        if service == "dhcp4" and old_url and old_url != url and not cfg.has_option(sec, _PREV_URL_KEY):
            # First time this server's v4 URL moves off the Control
            # Agent: remember where it was, for "Switch back" - and the pair
            # the Control Agent was reached with (Z2, Q184).
            cfg.set(sec, _PREV_URL_KEY, old_url)
            for leftover in _PREV_PAIR_KEYS:
                if cfg.has_option(sec, leftover):
                    cfg.remove_option(
                        sec, leftover
                    )  # AB5 (Q186): nothing from an earlier round trip sits beside a pair saved now
            if cfg.has_option(sec, user_key):
                cfg.set(sec, _PREV_USER_KEY, cfg.get(sec, user_key))
            else:
                cfg.set(sec, _PREV_USER_ABSENT_KEY, "1")  # AB4: the Control Agent had NO user key
            if cfg.has_option(sec, pass_key):
                cfg.set(
                    sec, _PREV_PASS_KEY, cfg.get(sec, pass_key)
                )  # a blank is kept: "the Control Agent had no password" is something to restore
                if cfg.get(sec, f"{pass_key}_shared", fallback="") == "1":
                    cfg.set(sec, _PREV_SHARED_KEY, "1")  # (read before the socket's own pair clears it below)
            else:
                cfg.set(
                    sec, _PREV_PASS_ABSENT_KEY, "1"
                )  # AB4: the Control Agent had NO password key (an extra server's then inherits the primary's)
        cfg.set(sec, url_key, url)
        changed.append(f"[{sec}] {url_key}")
        # Per-daemon credentials: only written when they differ from the
        # pair the daemon would inherit anyway (the server's v4 pair) —
        # a [kea6]/[d2] override that merely repeats [kea]'s values is
        # noise the "Inherit" checkboxes then have to undo.
        base_user, base_pass = server.get("api_user", ""), server.get("api_pass", "")
        if service == "dhcp4" or (user, password) != (base_user, base_pass):
            cfg.set(sec, user_key, user)
            cfg.set(sec, pass_key, password)
            __credentials.clear_shared(
                cfg, _endpoint_name(server, service)
            )  # Y3 (Q183): typed here, so no longer a marked copy
            if service != "dhcp4":
                changed.append(f"[{sec}] {user_key}/{pass_key}")
        elif service != "dhcp4":
            for k in (user_key, pass_key):
                if cfg.has_option(sec, k):
                    cfg.remove_option(sec, k)
            __credentials.clear_shared(
                cfg, _endpoint_name(server, service)
            )  # Y3 (Q183): the password is gone, so is the marker that said it was a copy
        if service == "dhcp4" and cfg.get("kea", "connection_mode", fallback="ca") != "direct":
            if not cfg.has_section("kea"):
                cfg.add_section("kea")
            cfg.set("kea", "connection_mode", "direct")
            changed.append("Jen switched to direct mode")
        # CRED-004 (Q180, second pass): the socket that just answered is on the SAME Kea, but its address is spelled differently (`10.0.0.5` for `kea-a.lan`), and the resolver compares
        # hosts as written. An endpoint of this server that sent a password before and would now be refused it keeps that password as its OWN (a copy, marked) instead of silently
        # losing it - the superadmin's act, named in the flash.
        after_resolved = __credentials.resolve(cfg)
        for name in sorted(_endpoints_of_server(server)):
            was, now = before_resolved.get(name), after_resolved.get(name)
            if was and now and was.password and not now.password and now.withheld:
                section, option = __credentials.password_key(name)
                if not cfg.has_section(section):
                    cfg.add_section(section)
                cfg.set(section, option, was.password)
                cfg.set(section, f"{option}_shared", "1")
                changed.append(f"[{section}] {option} (kept: the address changed spelling)")
        # Q182 (X4), after the keep above: the pair that was pushed into the daemon's config and ANSWERED the probe is what Jen must keep sending to it. When the resolver would withhold it at the new
        # address (the socket set up by IP on a server Jen reaches by name: `resolve` compares hosts as written, and the removal of an own key above made the endpoint inherit)
        # the probed pair is written as the endpoint's OWN - a copy of the server's, marked - never dropped. The superadmin's act, named in the flash.
        if service != "dhcp4":
            here = __credentials.resolve(cfg).get(_endpoint_name(server, service))
            if here is not None and here.withheld:
                cfg.set(sec, user_key, user)
                cfg.set(sec, pass_key, password)
                cfg.set(sec, f"{pass_key}_shared", "1")
                changed.append(f"[{sec}] {user_key}/{pass_key} (kept: the probed pair is the endpoint's own)")

    return _apply, changed


def _endpoints_of_server(server: dict) -> set[str]:
    """Every `credentials.resolve` endpoint name of one Kea server. The direct-socket routes point a server at the socket that has JUST ANSWERED with its saved credentials (it
    is the same Kea, reached by the address its own SSH host gave): that is the superadmin's explicit act, so the password the writer would otherwise refuse to follow an
    endpoint to a new spelling of the host (`10.0.0.1` for `kea-a`) is theirs to move (CRED-004)."""
    sid = (server or {}).get("id")
    if sid in (None, 1):
        return {"kea", "kea6", "d2"}
    return {f"server_{sid}", f"server_{sid}_v6", f"server_{sid}_d2"}


def _write_direct_socket_config(
    server: dict, service: str, url: str, user: str, password: str, tls: bool = False
) -> str:
    """Point Jen at the daemon socket that just answered (see `_direct_socket_edit`). Returns the phrase the caller flashes."""
    apply_fn, changed = _direct_socket_edit(server, service, url, user, password, tls)
    # Q182 (X4): the password typed (or confirmed by the probe) is the ONE endpoint's - not every endpoint of the server
    __config.app_config.mutate(apply_fn, typed={_endpoint_name(server, service)})
    return ", ".join(changed)


def _servers_not_on_direct_sockets(except_id) -> list[str]:
    """Names of the OTHER servers whose v4 URL doesn't answer a
    direct-style config-get as kea-dhcp4 — i.e. the ones that will show
    the Control Agent error on the Dashboard now that the (global) mode
    is direct. One config-get per server; only called right after the
    mode flipped, never on a page render."""
    names = []
    for s in extensions.KEA_SERVERS:
        if s.get("id") == except_id or not s.get("api_url"):
            continue
        if _identify_daemon(s["api_url"], s.get("api_user", ""), s.get("api_pass", ""), "dhcp4") != "Dhcp4":
            names.append(f"{s.get('name', 'Kea Server')} ({__auth.shown_url(s['api_url'])})")
    return names


def _holding_identity_lock(view):
    """Run the whole view under `identity_lock` (v5.68.0-beta.29, Q165, edge 3). The two direct-socket routes act on the Kea HOST first (the daemon is reconfigured and
    restarted) and write Jen's own settings LAST, and beta.28 asked the identity question of a copy at the start. Between that question and the final write another
    request - `turn_on`, which records an entry against the old identity - could commit, and the write would then be refused with the Kea already changed. Held from
    the first line, the check, the remote changes and the write are one critical section: `turn_on` (and every other config writer) waits behind it, for as long as
    the helper's own timeouts allow, and whichever comes second sees the first's result. Lock order is the one in jen/config.py: this is the outer lock."""

    @functools.wraps(view)
    def locked(*args, **kwargs):
        with __config.identity_lock:
            return view(*args, **kwargs)

    locked.__holds_identity_lock__ = (
        True  # (copied outward by the decorators above it; tests/test_direct_socket_lock.py reads it)
    )
    return locked


def _uses_jen_tls(sockets, service: str) -> bool:
    """Q187 (AC2): did one of these control sockets reference the TLS files Jen's `install-tls` writes (the fixed paths under /etc/kea/tls/<service>/)? Then a change that installs new
    material there replaces what that socket's certificate was issued for."""
    from jen.services import kea_tls as __tls

    remote = __tls.remote_tls_paths(service)
    return any(
        isinstance(s, dict)
        and s.get("socket-type") == "https"
        and (
            s.get("cert-file") == remote["cert_file"]
            or s.get("key-file") == remote["key_file"]
            or s.get("trust-anchor") == remote["trust_anchor"]
        )  # (any of the three: `install-tls` overwrites all of them)
        for s in (sockets or [])
    )


#: Q193 second pass (finding 3): the fixed sentence of the incident a failed recovery leaves on a daemon that took the replacement CA's pair (the category's own text is about a restored socket)
_RECOVERY_CUT_OFF = "A recovery of Jen's damaged CA stopped after this daemon was given a certificate from the replacement CA, which Jen discarded: the daemon will not answer Jen until the recovery is repeated with the acknowledgement."


def _not_put_back_reason(tls: dict) -> str:
    """Q193 (AI4 g): why the certificate could not be put back - 'there is no earlier copy' only when there is none; when the pair IS kept at `.prev` and Jen's CA became unusable between the gate and
    the undo, it says so (the install payload needs an ok CA); else the helper refused it."""
    remote = tls.get("remote")
    if remote == "none-saved":
        return (
            "the earlier copy Jen kept is incomplete or does not load"
            if tls.get("why") == "incomplete"
            else "there is no earlier copy"
        )
    if remote == "ca-unusable":
        return f"Jen's CA became unusable during the operation ({tls.get('why') or 'damaged'}); the certificate Jen kept cannot be reinstalled until the CA is restored"
    return "the helper refused it"


def _reissue_action(daemon: str = "", tail: str = "") -> str:
    """Q193 second pass (finding 4): the action that gives a daemon a certificate Jen holds - 'remove the direct socket and set it up again' while Jen's CA is usable, and while it is damaged (the https
    setup is refused) the action that works: replace the CA, which re-issues it. `tail` ("to issue a matching one") follows the first only."""
    from jen.services import kea_tls as __tls

    if __tls.ca_state()[0] == "damaged":
        return f"fix Jen's damaged CA first (the https setup is refused until then): {__tls.DAMAGED_CA_ADVICE}; the replacement re-issues this daemon's certificate"
    return f"remove the {daemon + ' ' if daemon else ''}direct socket and set it up again{tail}"


def _put_tls_back(server: dict, service: str) -> dict:
    """Q187 (AC2) / Q188 (AD3): put the certificate and key the host had BEFORE this operation back on it (the same `install-tls` op, the same atomic replace), from the `.prev` pair Jen kept, and
    make Jen's own copies agree. The answer has BOTH halves, because they fail independently and mean different things: `remote` is 'restored', 'none-saved' (a first https socket, a
    certificate installed by hand, one issued before Jen kept the key) or 'failed'; `local` is 'ok' or 'failed' - the host has the old pair but Jen's own copy (what its expiry warning and the
    NEXT recovery read) may not be it. A failed local half keeps `.prev` for a retry."""
    from jen.services import kea_host as __host
    from jen.services import kea_tls as __tls

    files = __tls.previous_material(server.get("id"), service)
    if files is None:
        ca_now, ca_now_why = __tls.ca_state()
        kept = os.path.lexists(__tls.server_copy_path(server.get("id"), service) + ".prev") or os.path.lexists(
            __tls.server_key_path(server.get("id"), service) + ".prev"
        )
        if kept and ca_now != "ok":
            # Q193 (AI4 g): the pair IS kept at `.prev`, but the install payload needs an ok CA and Jen's CA became unusable between the gate and the undo
            return {"remote": "ca-unusable", "local": "ok", "why": ca_now_why}
        if kept:
            return {
                "remote": "none-saved",
                "local": "ok",
                "why": "incomplete",
            }  # (second pass, finding 7: kept, but half a pair or one that does not load)
        return {"remote": "none-saved", "local": "ok"}
    pushed = __host.install_tls(server, service, files)
    if not pushed.get("ok"):
        logger.error(f"kea_tls: could not reinstall the previous material on server {server.get('id')}/{service}")
        return {"remote": "failed", "local": "ok"}
    try:
        if __tls.restore_previous(server.get("id"), service):
            return {"remote": "restored", "local": "ok"}
    except __tls.HostRecordLost:
        # Q189 (AE2): the host has the previous pair and Jen can record NEITHER which pair it is NOR that its live copy differs - the incident store is the only record left
        logger.error(
            f"kea_tls: the host has the previous material back and Jen cannot record which pair {server.get('id')}/{service} holds"
        )
        return {"remote": "restored", "local": "failed", "lost": True}
    logger.error(
        f"kea_tls: the host has the previous material back but Jen's copies for {server.get('id')}/{service} could not be made to agree"
    )
    return {"remote": "restored", "local": "failed"}


def _reinstall_live_material(server: dict, service: str) -> str:
    """Q188 (AD2): put Jen's LIVE pair (what the host had before this operation, once `.staged` is set aside) back on the host without touching Jen's own files: 'restored', 'none' (Jen has no
    pair for this server and service) or 'failed'."""
    from jen.services import kea_host as __host
    from jen.services import kea_tls as __tls

    files = __tls.host_material(
        server.get("id"), service
    )  # (second pass, Q188: Jen's live pair, unless a recorded divergence says the host holds the previous one)
    if files is None:
        return "none"
    return "restored" if __host.install_tls(server, service, files).get("ok") else "failed"


def _jen_endpoint(server: dict, service: str):
    """Q188 (AD4): the endpoint Jen itself dials for this daemon RIGHT NOW - url, user, password (what `credentials.resolve` gave it), the TLS context of the Jen config, and what must answer
    there (the daemon in direct mode, the Control Agent otherwise). Recorded before the first remote change: after a failed operation Jen's settings are unchanged, so THIS is the endpoint
    that has to work again before anything is called 'undone'. None when Jen has no endpoint for it (nothing to prove)."""
    ep = __kea._endpoint_for(server, service)
    if not isinstance(ep, tuple) or not ep[0]:
        return None
    url, user, pwd = ep
    return {
        "url": url,
        "user": user,
        "password": pwd,
        "verify": __kea._tls_verify() if url.startswith("https") else None,
        "cert": __kea._tls_client_cert() if url.startswith("https") else None,
        "expect": _DAEMON_KEY[service] if __caps.is_direct() else "Control-agent",
        "pair": (server.get("id"), service)
        if url.startswith("https") and __caps.is_direct()
        else None,  # AE6d: the pair Jen holds for it
    }


_ENDPOINT_WINDOWS = 3  # probe windows (each `_PROBE_ATTEMPTS` x `_PROBE_DELAY_S`) the restored endpoint is given before it is called unreachable


def _endpoint_answers(ctx: dict, service: str) -> tuple[bool, str]:
    """Q188 (AD4): does the recorded endpoint answer, with its recorded credentials and TLS context, as the daemon it should be? (True, "") or (False, <what did not happen>) - the words carry
    the class of failure, never a credential."""
    # (the system suite, Q188: a daemon restarted twice in a row on a loaded box needs longer than the ~16 s a fresh socket is given, and a false "did not answer" is an incident
    # the operator has to acknowledge - so the proof of an UNDO is asked for over `_ENDPOINT_WINDOWS` windows, and only the last failure is reported)
    version, err = "", ""
    for _window in range(_ENDPOINT_WINDOWS):
        version, err = _probe_after_restart(
            ctx["url"], ctx["user"], ctx["password"], service, verify=ctx["verify"], cert=ctx["cert"]
        )
        if version:
            break
    if not version:
        return (
            False,
            f"did not answer a version-get ({__auth.scrub_urls(err)})",
        )  # (Q190, AF2: the text came from below; it may carry the address as typed)
    who = _identify_daemon(ctx["url"], ctx["user"], ctx["password"], service, verify=ctx["verify"], cert=ctx["cert"])
    if who != ctx["expect"]:
        return False, f"answered as {who or 'an unknown daemon'}, not {ctx['expect']}"
    pair = ctx.get("pair")
    if pair and ctx["url"].startswith("https"):
        # Q189 (AE6d): the restored socket must present the certificate Jen HOLDS for it - a lost reply that was applied (a different pair on the host) is visible here and nowhere else
        from jen.services import kea_tls as __tls

        held = __tls.fingerprint(__tls.server_copy_path(*pair))
        presented = _presented_fingerprint(ctx["url"], ctx["cert"]) if held is not None else None
        if presented is not None and presented != held:
            return False, _PRESENTS_ANOTHER
    return True, ""


_PRESENTS_ANOTHER = "presented a certificate that is not the one Jen holds for it"


def _unanswered_category(why: str) -> str:
    """Q189 (AE6d): a restored socket that answered but presented a certificate Jen does not hold is `tls-local-stale` (the host presents material that is not Jen's copy - exactly what
    the category means); one that did not answer is `restored-endpoint-unreachable`."""
    return "tls-local-stale" if why == _PRESENTS_ANOTHER else "restored-endpoint-unreachable"


def _presented_fingerprint(url: str, client) -> str | None:
    """Q188 (AD2): the SHA-256 of the certificate the https listener at `url` presents (None when it cannot be read)."""
    from jen.services import kea_tls as __tls

    parts = urlparse(url)
    return __tls.presented_fingerprint(parts.hostname or "", parts.port or 443, client)


def _tls_unknown_after_failed_install(server: dict, service: str, existing_api) -> None:
    """Q187 (second pass, finding 7): `install_tls` answered not-ok - but a lost reply may mean the helper APPLIED the new pair. When the daemon's socket references Jen's TLS files the host's material
    is unknown, so the pair Jen last put there (its live local pair) is installed again; with none to install, or the helper refusing, that is a recorded incident - never 'nothing was changed'."""
    if not _uses_jen_tls(existing_api, service):
        return  # no socket references those files: whatever the helper did, nothing uses it
    name = server.get("name") or f"Kea Server {server.get('id')}"
    if _reinstall_live_material(server, service) == "restored":
        return
    flash(
        f"PARTIAL STATE on {name}: the certificate for {_DAEMON_NAME[service]}'s https socket may have been replaced and Jen could not re-assert the one it had. "
        "Remove the direct socket and set it up again to issue a matching one, or install the certificate you had by hand.",
        "error",
    )
    __user.audit("DIRECT_SOCKET_PARTIAL", "kea_api", f"server={name} service={service} certificate state unknown")
    _record_incident(server, service, f"the failed {_DAEMON_NAME[service]} certificate install", "tls-not-restored")


_RECORD_NOT_KEPT = "Jen could not keep a record of this in its recovery notes, so Servers will not show it; Health reports the notes as unknown until they can be read. Act on the lines above."


def _record_incident(server: dict, service: str, operation: str, category: str, detail: str = "") -> bool:
    """Q187 (AC3): an unproved recovery stays in front of the operator (Servers, Health) until a later operation on this server and service probes the endpoint, or a superadmin acknowledges it."""
    from jen.services import kea_changeset as __changeset

    if category in ("remote-unknown", "tls-not-restored", "tls-local-stale"):
        # Q189 (second pass, finding 2): these categories say Jen's live copy may not be the pair the host holds. A recovery note is acknowledged away by a person and resolved by a verified
        # recovery; neither makes the live copy the host's pair again - so the fact is also kept in a FILE beside the pair (unless a stale marker over a `.prev` pair already says which pair it is)
        from jen.services import kea_tls as __tls

        if not __tls.is_stale(server.get("id"), service):
            try:
                __tls.mark_unknown(server.get("id"), service)
            except OSError:
                logger.warning(
                    f"kea_tls: could not leave the 'unknown' marker for server {server.get('id')}/{service}; the incident note is the only record"
                )
    kept = __changeset.record_attention(
        server.get("id"),
        service,
        operation,
        category,
        server_name=server.get("name") or f"Kea Server {server.get('id')}",
        detail=detail,
    )
    if not kept:
        # Q189 (AE3/AE6e): the one place that says it, for every caller - the recovery record could not be updated, so the flash and the audit row are all there is
        flash(_RECORD_NOT_KEPT, "warning")
    return bool(kept)


def _undo_remote_change(
    server: dict,
    service: str,
    snapshot,
    summary: str,
    sentence: str,
    *,
    what: str,
    by_hand: str,
    tls_back: bool = False,
    done_text: str | None = None,
    orig: dict | None = None,
):
    """The compensation for a failure AFTER the Kea host was changed (v5.68.0-beta.29, Q165, edge 3): the host was changed and Jen's own settings write was refused, or the new socket never
    answered. Put the host back - one change through the same change set, the daemon restarted - and say so. When that fails too the lines name the partial state and what a person does
    about it; nothing is left half done without being said.

    AB1 (Q186): the compensation is ONE thing, `restore_control_sockets(snapshot)` - the daemon's control-sockets list becomes what it was when the change was planned, every entry in
    order, whatever the change did to it (a socket added, replaced or removed). It is never an inverse of the change. "Undone" is said only when the restored file's list EQUALS the
    snapshot and the change set restarted the daemon (its `ok`); a file that already matched is NOT undone - the daemon still runs what the failed change started - and `snapshot` None
    (the plan never read the config) cannot be undone at all. Both are the partial state, said.

    AC2/AC3 (Q187): the unit of recovery is the USABLE endpoint. With `tls_back` (this change replaced the certificate an https socket was issued for) the previous certificate and key
    are reinstalled BEFORE the restart, so the restored entry meets the certificate it was issued with; "undone" needs both. And whatever cannot be proved is a persistent incident
    (Servers, Health) in a category - never only a flash and an audit row.

    AD3/AD4 (Q188): a certificate put back on the host whose Jen-side copy could not follow is `tls-local-stale`, never "undone"; and with `orig` (the endpoint Jen dials, recorded before the
    first remote change) "undone" requires that endpoint to ANSWER, as the right daemon, with its own credentials and TLS context - a restored file and a restart are not an answer
    (`restored-endpoint-unreachable`)."""
    from jen.services import kea_changeset as __changeset
    from jen.services import kea_config_edit as __edit

    name = server.get("name") or f"Kea Server {server.get('id')}"
    daemon = _DAEMON_NAME[service]
    flash(sentence, "error")
    tls = _put_tls_back(server, service) if tls_back else None  # BEFORE the restart the compensation makes
    if snapshot is None:
        status = "no-snapshot"
    else:

        def _restore(cfg):
            after, code = __edit.restore_control_sockets(cfg, service, snapshot)
            if code == "ok" and __edit.control_sockets(after, service) != snapshot:
                return (
                    after,
                    "restore-mismatch",
                )  # the proof: what would be written IS the snapshot, or nothing is written
            return after, code

        result = __changeset.apply_change(
            service,
            _restore,
            summary,
            servers=[server],
            restart=True,
            code_messages={
                "nochange": f"{name}'s control sockets are already as they were before",
                "restore-mismatch": f"{name}: the restored control sockets did not equal the saved list",
            },
            daemon_label=daemon,
        )
        for style, text in result.lines:
            flash(text, style)
        status = result.status
    tls_bad = bool(tls) and tls["remote"] in ("none-saved", "failed", "ca-unusable")
    tls_lost = bool(tls) and bool(tls.get("lost"))
    tls_stale = bool(tls) and tls["remote"] == "restored" and tls["local"] == "failed" and not tls_lost
    endpoint_problem = None
    if status == "ok" and not tls_bad and orig is not None:
        answered, why = _endpoint_answers(orig, service)
        if not answered:
            endpoint_problem = why
    if status == "ok" and not tls_bad and not tls_stale and not tls_lost and endpoint_problem is None:
        if tls:
            # AE6a: the undo re-synced Jen's copy (marker cleared, `.prev` retired) and the endpoint answered: a standing 'Jen's copy differs' note for this server is over
            __changeset.resolve_attention(server.get("id"), service, categories=("tls-local-stale",))
        flash(
            done_text
            or f"{what} on {name} was undone and the daemon restarted, so the Kea host and Jen's settings agree again. Jen changed nothing else; a socket added to that list by hand since is not kept.",
            "info",
        )
        __user.audit("DIRECT_SOCKET_COMPENSATED", "kea_api", f"server={name} service={service} {summary}")
        return
    categories = []
    bits = [status]
    if status == "no-snapshot":
        categories.append("remote-unknown")
    elif status == "nothing":
        categories.append("restored-restart-unverified")
        by_hand = f"The file on {name} already matches what it was, but {daemon} was not restarted by this undo and may still be running the change: restart {daemon} there. {by_hand}"
    elif status in ("rolled_back", "rollback_failed"):
        categories.append("restart-failed")
    elif status != "ok":
        categories.append("aborted")
    if tls_bad:
        categories.append("tls-not-restored")
        bits.append(
            "certificate "
            + ("not restorable (Jen's CA is unusable)" if tls["remote"] == "ca-unusable" else tls["remote"])
        )
        by_hand = (
            f"The certificate Jen installed for the https socket could not be put back ({_not_put_back_reason(tls)}), so a restored https socket may meet a certificate issued for another address: "
            f"{_reissue_action(daemon, ' to issue a matching one')}, or install the certificate you had by hand. {by_hand}"
        )
    if tls_lost:
        categories.append("remote-unknown")
        bits.append("Jen cannot record which certificate the host holds")
        by_hand = (
            f"The previous certificate IS back on the host, but Jen cannot record which certificate {name} {daemon} holds (its SSL directory cannot be written): do not rely on Jen's copy of it; "
            f"once the directory is writable, {_reissue_action()}. " + by_hand
        )
    if tls_stale:
        categories.append("tls-local-stale")
        bits.append("Jen's copy of the certificate not updated")
        by_hand = (
            f"The previous certificate IS back on the host, but Jen could not refresh its own copy of it (the one its expiry warning and the next recovery read): {_reissue_action()}, once Jen's SSL directory is writable. "
            + by_hand
        )
    if endpoint_problem is not None:
        parts = urlparse(orig["url"])
        if _unanswered_category(endpoint_problem) == "tls-local-stale":
            if "tls-local-stale" not in categories:
                categories.append("tls-local-stale")
            bits.append("the endpoint presents a certificate Jen does not hold")
            by_hand = (
                f"The sockets and certificate were put back and {daemon} restarted, but {parts.hostname}:{parts.port} (the endpoint Jen uses) {endpoint_problem}: remove the direct socket and set it up again "
                "to issue a certificate it will present. " + by_hand
            )
        else:
            categories.append("restored-endpoint-unreachable")
            bits.append("the endpoint Jen uses did not answer")
            by_hand = (
                f"The sockets and certificate were put back and {daemon} restarted, but {parts.hostname}:{parts.port} (the endpoint Jen uses) {endpoint_problem}: check the daemon and the network path. "
                + by_hand
            )
    flash(
        f"PARTIAL STATE on {name}: {what} was done on the Kea host and could not be proved undone ({'; '.join(bits)}). {by_hand}",
        "error",
    )
    __user.audit("DIRECT_SOCKET_PARTIAL", "kea_api", f"server={name} service={service} {summary} compensation={status}")
    for category in categories:
        _record_incident(server, service, summary, category)


def _stop_after_failed_promotion(server: dict, service: str, error: OSError, existing_api, orig) -> None:
    """Q188 (AD2): the host accepted the new pair but Jen could not make it its own live pair. The operation STOPS: the pair the host had before is reinstalled from Jen's live files (which the
    failed promotion left untouched), the existing socket - where there is one - is probed to show the host serves again, `.prev` is NOT retired, and the socket change never starts."""
    from jen.services import kea_tls as __tls

    name = server.get("name") or f"Kea Server {server.get('id')}"
    daemon = _DAEMON_NAME[service]
    operation = f"the {daemon} https setup (Jen could not keep its own copy of the new certificate)"
    restored = _reinstall_live_material(server, service)
    __tls.discard_staged(server.get("id"), service)
    uses = _uses_jen_tls(existing_api, service)
    base = f"Jen cannot keep its own copy of the new certificate ({type(error).__name__}, errno {getattr(error, 'errno', '?')}), so the setup stopped before the socket was touched"
    if restored == "failed" or (restored == "none" and uses):
        flash(
            f"PARTIAL STATE on {name}: {base}, and the certificate the host had could not be put back - the socket {daemon} has may meet a certificate issued for another address. "
            "Fix Jen's SSL directory, then remove the direct socket and set it up again, or install the certificate you had by hand.",
            "error",
        )
        __user.audit(
            "DIRECT_SOCKET_PARTIAL",
            "kea_api",
            f"server={name} service={service} promotion failed; certificate not restored",
        )
        _record_incident(server, service, operation, "tls-not-restored")
        return
    if restored == "restored" and uses and orig is not None:
        answered, why = _endpoint_answers(orig, service)
        if not answered:
            flash(
                f"PARTIAL STATE on {name}: {base}; the certificate the host had was put back, but the endpoint Jen uses {why}.",
                "error",
            )
            __user.audit(
                "DIRECT_SOCKET_PARTIAL",
                "kea_api",
                f"server={name} service={service} promotion failed; endpoint did not answer",
            )
            _record_incident(server, service, operation, _unanswered_category(why))
            return
    flash(
        f"{base}; "
        + (
            "the certificate the host had was put back"
            if restored == "restored"
            else "no socket of the daemon uses those files, and Jen has no earlier copy to put back"
        )
        + f". Nothing else was changed on {name}.",
        "error",
    )


def _tls_after_unapplied_change(server: dict, service: str, snapshot, result, pre_read=None) -> None:
    """Q187 (AC2): the https path installs new certificate material BEFORE the socket change. When the change then does not stand (the config check failed, the restart failed and the change
    set rolled back), the daemon's previous socket entry would meet the new certificate on its next restart - so the previous material goes back, and a daemon the change set restarted on
    the new files is restarted once more. Only when the socket the daemon had was an https socket on Jen's paths; with no earlier copy that is a recorded incident, not a silence.

    Q188 (AD7/AD9): a snapshot that was never taken (the config could not be read) with nothing to put back is a `remote-unknown` incident, not a silent return; and when the change set's REVERT
    failed the NEW entry is still in the daemon's config, so the old pair is NOT reinstalled under it - the incident says which half is wrong."""
    from jen.services import kea_host as __host
    from jen.services import kea_tls as __tls

    name = server.get("name") or f"Kea Server {server.get('id')}"
    daemon = _DAEMON_NAME[service]
    # Q189 (AE6b): what the sockets referenced is known from the PLAN's read, or - when only that read failed - from the pre-read that preceded the install. Only when neither was made is it unknown.
    known = snapshot if snapshot is not None else pre_read
    operation = f"the failed {daemon} socket change"
    new_entry_still_there = result.status == "rollback_failed" and server.get("id") in (result.still_new_ids or [])
    if known is not None and not _uses_jen_tls(known, service) and not new_entry_still_there:
        # nothing references the files the failed attempt installed: the host's unreferenced files are said, not an incident, and Jen keeps no record of an endpoint that does not exist (AE6c).
        # (Second pass, finding 4: NOT when the revert failed - the NEW https entry is then still in the config and DOES reference them.)
        __tls.discard_local_record(server.get("id"), service)
        flash(
            f"The failed attempt left certificate files for {daemon} on {name} that no socket references; Jen dropped its own copy of them. Nothing else was changed.",
            "info",
        )
        return
    if new_entry_still_there:
        flash(
            f"PARTIAL STATE on {name}: the NEW socket entry is still in {daemon}'s config (its revert failed), so the previous certificate was NOT put back under it - the new certificate "
            "stays beside the entry it was issued for. Restore the last good config from Config history, then set the direct socket up again.",
            "error",
        )
        __user.audit(
            "DIRECT_SOCKET_PARTIAL",
            "kea_api",
            f"server={name} service={service} revert failed; certificate left with the new entry",
        )
        _record_incident(
            server,
            service,
            operation,
            "tls-not-restored",
            "The change's revert failed, so the new socket entry is still in the daemon's config beside the new certificate.",
        )
        return
    tls = _put_tls_back(server, service)
    if tls["remote"] == "restored":
        flash(f"The certificate and key {name} had for {daemon} were put back.", "info")
        if tls.get("lost"):
            flash(
                f"Jen cannot record which certificate {name} {daemon} holds (its SSL directory cannot be written): do not rely on Jen's copy of it; once the directory is writable, {_reissue_action()}.",
                "error",
            )
            _record_incident(server, service, operation, "remote-unknown")
        elif tls["local"] == "failed":
            flash(
                f"The previous certificate is back on the host, but Jen could not refresh its own copy of it (the one its expiry warnings read): {_reissue_action()}, once Jen's SSL directory is writable.",
                "warning",
            )
            _record_incident(server, service, operation, "tls-local-stale")
        if result.status in ("rolled_back", "rollback_failed"):
            again = __host.service_action(server, service, "restart")
            if not again.get("ok"):
                flash(
                    f"PARTIAL STATE on {name}: the previous certificate is back but {daemon} did not restart on it. Restart {daemon} there by hand.",
                    "error",
                )
                _record_incident(server, service, operation, "restart-failed")
        return
    if known is None and tls["remote"] == "none-saved":
        flash(
            f"PARTIAL STATE on {name}: Jen could not read what {daemon}'s sockets referenced before the change, and it has no earlier copy of the certificate it installed: the socket {daemon} had may meet "
            "a certificate issued for another address. Remove the direct socket and set it up again to issue a matching one, or install the certificate you had by hand.",
            "error",
        )
        __user.audit(
            "DIRECT_SOCKET_PARTIAL",
            "kea_api",
            f"server={name} service={service} config unread; certificate state unknown",
        )
        _record_incident(server, service, operation, "remote-unknown")
        return
    flash(
        f"PARTIAL STATE on {name}: the certificate Jen installed for the https socket could not be put back ({_not_put_back_reason(tls)}). "
        f"The socket {daemon} had may meet a certificate issued for another address: {_reissue_action('', ' to issue a matching one')}, or install the certificate you had by hand.",
        "error",
    )
    __user.audit(
        "DIRECT_SOCKET_PARTIAL",
        "kea_api",
        f"server={name} service={service} certificate not restored ({tls['remote']})",
    )
    _record_incident(server, service, operation, "tls-not-restored")


@bp.route("/settings/infrastructure/direct-socket/<int:server_id>/<service>", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
@_holding_identity_lock
def setup_direct_socket(server_id, service):
    """v5.29.0 (Q29, B1) — give one daemon on one server its own http
    control socket, the way an operator would by hand, but with the
    probe-then-commit order that makes the 2026-09-13 trap (direct mode
    pointed at a socket that isn't the daemon) impossible through this
    path:

      1. validate the bind address (an IP literal on the Kea host, never
         0.0.0.0), port, credentials; refuse the Control Agent's own
         address; refuse Kea < 2.7.2 when the current endpoint answers
         a version-get;
      2. kea_changeset.apply_change() on THAT server only: read the
         daemon's config, set_control_socket(), preflight with -t,
         write, restart — the same plan/preflight/commit/revert path
         every subnet edit takes;
      3. probe the NEW socket (version-get, then a config-get that must
         identify as this daemon — a Control Agent still listening on
         the same host answers version-get identically);
      4. only then write Jen's own config: the per-daemon URL (+ creds),
         and for dhcp4 `connection_mode = direct`.

    A failed probe puts the daemon's sockets - and, for https, the certificate
    it had - back as they were when the change REPLACED a working socket
    (Q187, AC1/AC2), with Jen's settings untouched and a flash naming exactly
    what didn't answer. A FIRST socket (nothing was replaced) stays in the
    Kea config - it is valid, the daemon is listening on it - as a recorded
    probe-pending incident until a later probe of it succeeds.
    """
    from jen.services import kea_changeset as __changeset
    from jen.services import kea_config_edit as __edit
    from jen.services.kea_authoring import DIRECT_SOCKET_DEFAULT_PORTS, build_control_socket

    back = redirect(url_for("settings.settings_kea"))
    if service not in _DIRECT_SERVICES:
        flash("Unknown Kea service.", "error")
        return back
    server = _server_by_id(server_id)
    if server is None:
        flash("Unknown Kea server.", "error")
        return back
    name = server.get("name") or f"Kea Server {server_id}"
    daemon = _DAEMON_NAME[service]
    conf = f"kea-{_CONF_STEM[service]}.conf"
    if not server.get("ssh_host"):
        flash(
            f"{name} has no SSH host configured — Jen edits {conf} over SSH. Set it under "
            f"{'SSH to the Kea server' if server_id == 1 else 'Kea servers & HA'} first.",
            "error",
        )
        return back

    scheme = request.form.get("scheme", "http").strip().lower()
    if scheme not in ("http", "https"):
        flash("The scheme must be http or https.", "error")
        return back
    address = request.form.get("address", "").strip()
    if not _is_ip_literal(address):
        flash(
            f"The bind address must be an IP literal on the Kea host — {daemon} binds an address, not a name. "
            f"Use the management IP Jen reaches {name} on.",
            "error",
        )
        return back
    if ipaddress.ip_address(address).is_unspecified:
        flash(
            "Refusing to bind 0.0.0.0 / :: — bind the management address Jen reaches this host on, "
            "not every interface. A control socket on every interface is a credential-guessing target "
            "on the client network too.",
            "error",
        )
        return back
    raw_port = request.form.get("port", "").strip() or str(DIRECT_SOCKET_DEFAULT_PORTS[service])
    if not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
        flash("The port must be a number between 1 and 65535.", "error")
        return back
    port = int(raw_port)
    new_url = _socket_url(scheme, address, port)
    # the defaults are what `credentials.resolve` would send to the address this socket is about to be given (Q182, X4)
    default_user, default_pass = _daemon_creds(server, service, new_url)
    user = request.form.get("user", "").strip() or default_user
    password = request.form.get("password", "").strip() or default_pass
    if not user or not password:
        flash(
            f"The socket needs a basic-auth username and password — Jen has none to send to {__auth.shown_url(new_url)} for {daemon} on "
            f"{name} (a saved password is never sent to a different host from the one it belongs to), so fill both in.",
            "error",
        )
        return back

    # The daemon socket must not be the Control Agent's own address —
    # that's the exact 2026-09-13 confusion, and Kea would fail to bind
    # a port the agent already holds (a restart failure, not a clear
    # message).
    if __caps.is_ca():
        ca = urlparse(server.get("api_url", ""))
        if ca.hostname == address and ca.port == port:
            flash(
                f"{__auth.shown_url(new_url)} is the Control Agent's own address on {name} — {daemon}'s socket needs its own port "
                f"(conventionally :{DIRECT_SOCKET_DEFAULT_PORTS[service]}).",
                "error",
            )
            return back

    # v5.68.0-beta.28 (Q164): this route's first act is on the Kea HOST (the daemon is reconfigured and restarted) and Jen's own settings are written LAST. For
    # dhcp4 that write changes the server's API URL and the global connection mode - an identity change the config writer refuses while an investigation
    # entry exists - so the same question is asked of a copy BEFORE anything is sent: refused here, nothing was touched. (Not "probe, then find out".)
    try:
        _edit_fn, _unused = _direct_socket_edit(server, service, new_url, user, password, tls=(scheme == "https"))
        __config.app_config.preflight_identity_change(_edit_fn, typed={_endpoint_name(server, service)})
    except __config.ConfigChangeRefused as refused:
        flash(refused.sentence, "error")
        flash(f"Nothing was changed on {name}.", "info")
        return back

    # Kea version: per-daemon control sockets exist from 2.7.2. Only
    # blocking when the CURRENT endpoint actually answers — a Kea 3.2 box
    # with no Control Agent answers nothing in ca mode, and the config
    # test (-t) below rejects an unknown `control-sockets` key on an old
    # Kea anyway.
    vr = __kea.kea_command("version-get", service, server=server)
    if vr.get("result") == 0:
        # an empty reply has no first line (v5.69.0-beta.5, Q174: `.splitlines()[0]` raised IndexError out of the route on one)
        ver_text = (((vr.get("arguments") or {}).get("extended", "") or vr.get("text", "")).splitlines() or [""])[
            0
        ].strip()
        v = __kea.parse_kea_version(ver_text)
        if v and not __caps.may_attempt_direct_socket(v):
            flash(
                f"Kea {'.'.join(str(n) for n in v)} on {name} predates per-daemon control sockets (2.7.2), so "
                "the Control Agent is the only option there. Plan a Kea upgrade first — nothing was changed.",
                "error",
            )
            return back

    pre_read: dict = {}  # what the pre-read saw: the sockets the daemon had before anything was sent
    orig = _jen_endpoint(
        server, service
    )  # Q188 (AD4): the endpoint Jen dials NOW - what has to answer again before a recovery is called undone

    def _refused_for_many_sockets(need_read: bool = False) -> bool:
        """AB1 (Q186): Jen manages ONE API socket. A daemon whose config has more than one is refused - before the TLS material is installed, before anything is written - not flattened.
        Asked at the last point before the first thing is sent to the host (after every check that needs no SSH, so those refusals still touch nothing).
        Q188 (AD7): with `need_read` (the https path, which replaces files at fixed paths) a config that could not be read is refused too - 'no socket uses Jen's files' is not a conclusion to
        draw from an observation that was not made."""
        read_errors: list = []
        existing_api = _api_sockets_of(server, service, errors=read_errors)
        pre_read["api"] = existing_api
        if _preread_refusal(server, service, conf, read_errors):
            return True
        if existing_api is None and need_read:
            flash(
                f"Jen could not read {conf} on {name} to see what the daemon's sockets reference, so it will not replace the certificate files they may use. Nothing was changed.",
                "error",
            )
            return True
        if existing_api is not None and len(existing_api) > 1:
            flash(_many_sockets_sentence(daemon, conf, len(existing_api)), "error")
            return True
        return False

    # ── https (v5.29.0, Q29 C3): Jen's private CA issues the material and
    # the helper's install-tls op lands it on the host BEFORE the config
    # references it; the apply then carries the three paths as tls_paths.
    tls_paths = ()
    probe_verify, probe_cert = None, None
    tls_replaced = False
    if scheme == "https":
        from jen.services import kea_host as __host
        from jen.services import kea_tls as __tls

        if not __caps.for_server(server_id, probe_kea=False).tls:
            flash(f"{name}: {__host._TLS_NEEDS_HELPER}", "error")
            return back
        jen_ca, _jen_ca_key = __tls.ca_paths()
        jen_client_cert, jen_client_key = __tls.client_paths()
        ca_refusal = __tls.ca_refusal()  # Q192 (AH2): a damaged CA (or an absent one beside evidence it existed) is a recovery condition - refused before anything is CHANGED on the host (the read-only version-get above has been asked)
        if ca_refusal:
            flash(
                f"Jen's CA is damaged ({ca_refusal}): {__tls.DAMAGED_CA_ADVICE}. Nothing was changed on {name}.",
                "error",
            )
            return back
        if extensions.KEA_API_CA and __tls.trust_kind() not in ("jens-file", "alias", "copy"):
            flash(
                f"The CA bundle above points at {extensions.KEA_API_CA}, which is not Jen's CA alone (an administrator's CA, a bundle that also holds one, or a file that cannot be read) — Jen manages one trust "
                "anchor for every Kea server. Clear the CA bundle field (and the client certificate fields) to use "
                "Jen's CA, or set up https by hand with your own CA per the admin guide.",
                "error",
            )
            return back
        client_kind_now = __tls.client_kind()  # Q191 (AG1): by certificate - none / jens-file / alias pass; a copy, a pair no Jen CA issued or one that does not load is refused
        if client_kind_now in ("copy", "other", "unreadable"):
            flash(
                __tls.client_refusal(client_kind_now)
                + " - or set up https by hand with your own CA per the admin guide. Nothing was changed.",
                "error",
            )
            return back
        if _refused_for_many_sockets(need_read=True):
            return back
        remote = __tls.remote_tls_paths(service)
        entry = build_control_socket(scheme, address, port, user, password, tls=remote)
        # Q188 (AD9): a re-run whose socket is ALREADY in the daemon's config changes nothing and restarts nothing - new files written under it would not be loaded until the next restart (and then
        # would not be the ones the running daemon was started with), so no new material is installed at all: the socket is only re-probed.
        already_there = entry in (pre_read.get("api") or [])
        if not already_there:
            # Q194 (AJ2): Jen proves, by writing, that it can keep the record of what it is about to install - before it creates a CA or a client pair of its own and before it asks the host for anything
            # (`keep=False`: a refusal changes nothing, and an empty directory would read as evidence that a CA existed); `stage_issued` is the commit that follows
            storage_now = __tls.copies_dir_writable(keep=False)
            if storage_now:
                flash(
                    f"Jen cannot write its certificate records ({storage_now}), so it did not install the certificate. Nothing was changed on {name} or in Jen's own certificates.",
                    "error",
                )
                return back
        try:
            __tls.ensure_ca()
            client_issued = __tls.issue_client_cert()
            files = None if already_there else __tls.issue_server_cert(server, service, address, commit=False)
        except __tls.CaDamaged as e:
            flash(
                f"Jen's CA is damaged ({e.why}): {__tls.DAMAGED_CA_ADVICE}. Nothing was changed on {name}.",
                "error",
            )
            return back
        except Exception as e:
            logger.error(f"kea_tls: could not issue material for {name}/{service}: {e}")
            flash("Jen could not issue the certificates — see the server log. Nothing was changed.", "error")
            return back
        if client_issued.get("issued") and client_issued.get("why"):
            flash(
                f"Jen's client certificate was re-issued ({client_issued['why']}) from the same CA - every daemon that trusts the CA keeps trusting it; the pair it replaced is kept beside it as .prev.",
                "info",
            )
        tls_err = __kea.validate_client_tls_material(jen_client_cert, jen_client_key, jen_ca)
        if tls_err:
            flash(f"Jen's own client certificate is unusable ({tls_err}) — nothing was pushed to {name}.", "error")
            return back
        if files is not None:
            # Q188 (AD2): Jen's own recovery state is committed BEFORE the host is touched - `.prev` (what the host has) and `.staged` (what it is about to be given) - and the operation stops at the
            # first step it cannot prove: no copy, no install; no promotion, the previous material back on the host and the socket change never starts.
            try:
                __tls.stage_issued(server_id, service, files)
            except OSError as e:
                logger.error(f"kea_tls: could not stage the new pair for {name}/{service}: {type(e).__name__}")
                __tls.discard_staged(server_id, service)
                flash(
                    f"Jen cannot keep its own copy of the new certificate ({type(e).__name__}, errno {getattr(e, 'errno', '?')}), so it did not install it. Nothing was changed on {name}.",
                    "error",
                )
                return back
            pushed = __host.install_tls(server, service, files)
            if not pushed.get("ok"):
                __tls.discard_staged(server_id, service)
                _tls_unknown_after_failed_install(server, service, pre_read.get("api"))
                flash(
                    f"{name}: {pushed.get('detail', 'the helper refused the TLS material')} — nothing was changed in the daemon's sockets or in Jen's settings.",
                    "error",
                )
                return back
            try:
                __tls.promote_staged(server_id, service)
            except OSError as e:
                logger.error(f"kea_tls: could not promote the staged pair for {name}/{service}: {type(e).__name__}")
                _stop_after_failed_promotion(server, service, e, pre_read.get("api"), orig)
                return back
            tls_replaced = (
                True  # the host carries NEW material at the fixed paths, and Jen's live pair is that material
            )
        tls_paths = [(remote["trust_anchor"], "file"), (remote["cert_file"], "file"), (remote["key_file"], "file")]
        probe_verify, probe_cert = jen_ca, (jen_client_cert, jen_client_key)
    else:
        if _refused_for_many_sockets():
            return back
        entry = build_control_socket(scheme, address, port, user, password)

    snapshot_taken: dict = {}  # AB1 (Q186): the daemon's control-sockets list exactly as the change was PLANNED on it - what the compensation restores

    def _add_socket(cfg):
        snapshot_taken["sockets"] = __edit.control_sockets(cfg, service)
        return __edit.set_control_socket(cfg, service, entry)

    result = __changeset.apply_change(
        service,
        _add_socket,
        f"added an {scheme} control socket on {address}:{port}",
        servers=[server],
        restart=True,
        code_messages={
            "unsupported": f"{conf} has no {_DAEMON_KEY[service]} block (or a control-sockets that isn't the "
            "daemon's list form) — is this the right file? Nothing was changed.",
            "nochange": f"{daemon} already has exactly this socket in {conf} — checking that it answers",
            "multiple": _many_sockets_sentence(daemon, conf),
        },
        daemon_label=daemon,
        tls_paths=tls_paths,
    )
    if result.status == "noservers":
        flash(f"{name} has no SSH host configured.", "error")
        return back
    for style, text in result.lines:
        flash(text, style)
    if result.status in __changeset.NOT_APPLIED:
        if tls_replaced:
            _tls_after_unapplied_change(server, service, snapshot_taken.get("sockets"), result, pre_read.get("api"))
        flash("Jen's own settings were not changed.", "info")
        return back
    mode_now = "Control Agent" if __caps.is_ca() else "direct"
    snapshot = snapshot_taken.get("sockets")
    replaced_api = [s for s in (snapshot or []) if __edit._is_api_socket(s)] if result.status == "ok" else []

    version_text, probe_err = _probe_after_restart(
        new_url, user, password, service, verify=probe_verify, cert=probe_cert
    )
    identified = (
        _identify_daemon(new_url, user, password, service, verify=probe_verify, cert=probe_cert)
        if version_text
        else None
    )
    fingerprint_problem = ""
    fingerprint_mismatch = False  # AE5: the socket ANSWERED, as the daemon, with a certificate that is not Jen's copy
    fingerprint_ok = False  # ... or answered with exactly the certificate Jen holds
    if version_text and identified == _DAEMON_KEY[service] and scheme == "https":
        # Q188 (AD2): a completed setup is reported only when local and remote identities AGREE - the certificate the socket presents is the one Jen holds for it
        from jen.services import kea_tls as __tls_fp

        presented = _presented_fingerprint(new_url, probe_cert)
        if presented is None:
            fingerprint_problem = "its certificate could not be read to check it is the one Jen holds"
        elif presented != __tls_fp.fingerprint(__tls_fp.server_copy_path(server_id, service)):
            fingerprint_problem = "it presents a certificate that is not the one Jen holds for it"
            fingerprint_mismatch = True
        else:
            fingerprint_ok = True
    if not version_text or identified != _DAEMON_KEY[service] or fingerprint_problem:
        if not version_text:
            reason = f"didn't answer a version-get ({probe_err})"
        elif fingerprint_problem:
            reason = fingerprint_problem
        else:
            who = "the Control Agent" if identified == "Control-agent" else (identified or "an unknown daemon")
            reason = f"answered as {who}, not {daemon}"
        started = (
            "restarted with the new socket"
            if result.status == "ok"
            else "was not restarted (the socket was already in its config)"
        )
        msg = (
            f"{daemon} on {name} {started}, but {__auth.shown_url(new_url)} {reason} from the Jen host — "
            f"Jen stays in {mode_now} mode and none of its settings were changed. "
            + (
                "A repeat would only re-probe the same socket, so remove the direct socket and set it up again to issue a certificate it will present."
                if fingerprint_problem
                else f"Check that {address}:{port} is reachable from here (firewall? management VLAN?) and that {daemon}'s log shows it listening, "
                f"then run this again (the socket is already in {conf}, so it will just re-probe)."
            )
        )
        __user.audit(
            "SETUP_DIRECT_SOCKET",
            "kea_api",
            f"server={name} service={service} url={__auth.shown_url(new_url)} probe=failed",
        )
        if replaced_api:
            # Q187 (AC1): the change REPLACED a working socket, so a replacement that does not answer must not leave the working one gone while Jen still dials it: the whole list - and the
            # certificate an https socket was issued for - go back, exactly as for a refused write.
            old_described = __edit.describe_socket(replaced_api[0])
            _undo_remote_change(
                server,
                service,
                snapshot,
                f"restored the control sockets as they were before the {__edit.describe_socket(entry)} socket was added (it did not answer)",
                f"{daemon} on {name} {started}, but {__edit.describe_socket(entry)} {reason} from the Jen host - Jen stays in {mode_now} mode and none of its settings were changed.",
                what=f"the {__edit.describe_socket(entry)} control socket",
                by_hand=f"Put the control-sockets of {conf} back as they were before ({_SOCKET_ENTRY_LIVES}): remove the {__edit.describe_socket(entry)} entry and put back {old_described}; then restart {daemon}.",
                tls_back=tls_replaced and _uses_jen_tls(snapshot, service),
                orig=orig,
                done_text=f"The socket you had ({old_described}) is back on {name} and {daemon} restarted; the new one ({__edit.describe_socket(entry)}) did not answer: {reason}. Check that {address}:{port} is reachable from here (firewall? management VLAN?), then run this again.",
            )
            return back
        flash(msg, "error")
        if fingerprint_mismatch:
            # AE5: the flash says the socket presents a certificate Jen does not hold and to remove it and set it up again; the incident says the same, in the category that means exactly that
            _record_incident(
                server,
                service,
                f"setup of the {__edit.describe_socket(entry)} control socket (it presents a certificate Jen does not hold)",
                "tls-local-stale",
                "The socket answers as the daemon but presents a certificate that is not the one Jen holds for it: remove the direct socket and set it up again to issue one it will present.",
            )
            return back
        # the socket is the first one (or was already there): it stays, unproved - a persistent incident until a later probe of it succeeds (Q187, AC3)
        _record_incident(
            server,
            service,
            f"setup of the {__edit.describe_socket(entry)} control socket (added, not yet answering)",
            "probe-pending",
        )
        return back

    was_ca = __caps.is_ca()
    try:
        written = _write_direct_socket_config(server, service, new_url, user, password, tls=(scheme == "https"))
    except (__config.ConfigChangeRefused, OSError) as refused:
        # v5.68.0-beta.29 (Q165, edge 3): refused AFTER the remote change (the record became unreadable between the check and the write, or a hand edit): a socket THIS
        # request added is taken out again; one that was already there (`nochange`) is not Jen's to remove. Q182 (X4): a write that FAILS (a read-only jen.config, a full disk) is
        # the same case - the daemon was changed and Jen's settings were not - so it is handled the same way, not left to be a 500
        if result.status == "ok":
            _undo_remote_change(
                server,
                service,
                snapshot_taken.get("sockets"),
                f"restored the control sockets as they were before the {__edit.describe_socket(entry)} socket was added (Jen's settings were refused)",
                _sentence_of(refused),
                what=f"the {__edit.describe_socket(entry)} control socket",
                by_hand=f"Put the control-sockets of {conf} back as they were before ({_SOCKET_ENTRY_LIVES}): remove the {__edit.describe_socket(entry)} entry, and put back the http/https entry it replaced if there was one; then restart {daemon}. Or use 'Remove socket' for {daemon} on this page when nothing else was there.",
                tls_back=tls_replaced and _uses_jen_tls(snapshot_taken.get("sockets"), service),
                orig=orig,
            )
        else:
            flash(_sentence_of(refused), "error")
            flash(f"Nothing was changed on {name}: the socket was already in {conf}.", "info")
        return back
    __user.set_global_setting("restart_pending", "true")
    from jen.services import kea_tls as __tls_done

    __tls_done.retire_previous(
        server_id, service
    )  # (Q187) the operation stands: the material before it is no longer needed
    __changeset.resolve_attention(
        server_id,
        service,
        categories=None
        if (tls_replaced or fingerprint_ok)
        else tuple(c for c in __changeset.ATTENTION_CATEGORIES if c not in ("tls-not-restored", "tls-local-stale")),
    )  # ... and the endpoint was just probed and answered as the daemon: a verified recovery of THIS server and service (of the certificate only when this run replaced it, or when the socket presented exactly the one Jen holds)
    flash(f"{daemon} on {name} answers directly at {__auth.shown_url(new_url)} — written: {written}.", "success")
    if service != "dhcp4" and __caps.is_ca():
        flash(
            "Jen is still in Control Agent mode — set up kea-dhcp4's direct socket to switch it over; "
            "until then this URL is only used in direct mode.",
            "info",
        )
    if service == "dhcp4" and was_ca and __caps.is_direct():
        others = _servers_not_on_direct_sockets(server_id)
        if others:
            flash(
                "Jen is now in direct mode for every server, but these still point at something that isn't "
                f"kea-dhcp4's own socket: {'; '.join(others)}. Set up their direct sockets next — until then "
                "their Dashboard cards show the Control Agent error.",
                "warning",
            )
    __user.audit(
        "SETUP_DIRECT_SOCKET", "kea_api", f"server={name} service={service} url={__auth.shown_url(new_url)} user={user}"
    )
    return back


def _configured_url(server: dict, service: str) -> str:
    """Q189 (second pass, finding 1): the address Jen is CONFIGURED to dial - `_service_url` is "" for an endpoint whose credential the resolver withheld, and an endpoint that drops out of an
    enumeration the day its password is withheld is the AE1 failure through another door."""
    return __kea.configured_url(server, service)


def _service_url(server: dict, service: str) -> str:
    """The URL Jen dials for `service` on `server` (its per-daemon
    override, else the v4 URL in ca mode), or "" when it has none."""
    ep = __kea._endpoint_for(server, service)
    return ep[0] if isinstance(ep, tuple) else ""


@bp.route("/settings/infrastructure/kea-ca/rotate", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
@_holding_identity_lock
def rotate_kea_ca():
    """v5.29.0 (Q29, C4) — a new Jen Kea CA and client certificate, and a
    new server certificate pushed to every (server, daemon) Jen ever
    issued one for. Staged so Jen never trusts a CA that isn't fully
    deployed: the new material is generated beside the live files
    (`.next`), every server is pushed, restarted and probed with the
    STAGED CA and client cert, and only when all of them answer is the
    staging promoted to live. A failure part-way re-issues the already-
    pushed servers from the OLD CA — still live, still the one Jen
    trusts — restarts them, and discards the staging. The one
    destructive action in this subsystem, hence superadmin + step-up
    reauth (Q6) and a confirm naming every server."""
    from jen.services import kea_changeset as __changeset
    from jen.services import kea_host as __host
    from jen.services import kea_tls as __tls

    back = redirect(url_for("settings.settings_kea"))
    ca_state, ca_why = __tls.ca_state()
    if ca_state == "none":
        flash(
            "No Jen-managed Kea CA exists yet — Jen creates it the first time you set up an https socket. "
            "Nothing to rotate.",
            "info",
        )
        return back
    recovery = ca_state == "damaged"
    if recovery and request.form.get("acknowledge_damaged_ca", "") != "1":
        # Q192 (AH2): replacing a DAMAGED CA is the recovery - allowed only once the person has read what it cannot do: the current CA cannot sign, so a server that fails part-way cannot be put
        # back on it and will need its socket set up again
        flash(
            f"Jen's CA is damaged ({ca_why}). To {__tls.DAMAGED_CA_ADVICE}. Tick the acknowledgement on the confirm and rotate again. Nothing was changed.",
            "error",
        )
        return back

    # Q189 (AE1): the targets are every https endpoint Jen DIALS (the configuration), each with a complete record of its certificate - never the listing of local copy files. A missing or
    # unreadable record, or a directory that cannot be listed, is a REFUSAL here, before the staging and before any host is touched: a rotation that dropped a live endpoint would promote
    # a CA that daemon never learned, and Jen would be cut off from it.
    inventory = __tls.rotation_inventory(extensions.KEA_SERVERS, url_for=_configured_url, recovery=recovery)
    all_targets, blocked = inventory
    blocked = list(blocked)
    targets = []  # (server, service, bind address)
    for server, service, bind in all_targets:
        label = f"{server.get('name') or 'Kea Server ' + str(server.get('id'))} kea-{service}"
        if not _service_url(server, service):
            blocked.append(
                f"{label} (Jen has no credential it may send to that address - set one under Settings → Kea)"
            )
            continue
        if not server.get("ssh_host"):
            blocked.append(f"{label} (no SSH host)")
            continue
        if not __caps.for_server(server.get("id"), probe_kea=False).tls:
            blocked.append(f"{label} (helper below v4)")
            continue
        targets.append((server, service, bind))
    for blocker in __tls.promotion_blockers():
        # Q192 (found by the worlds matrix): a live identity file the promotion cannot replace is known NOW - not after every target has moved to the new CA
        blocked.append(f"Jen cannot promote a new CA: {blocker}")
    if blocked:
        flash(
            "Rotate refused — a rotation would cut a server off from Jen's CA, or Jen cannot tell: "
            + "; ".join(blocked)
            + ". Nothing was changed.",
            "error",
        )
        return back
    if inventory.external:
        flash(
            "Not on Jen's CA, so not rotated and left alone: " + "; ".join(inventory.external) + ".",
            "info",
        )
    if inventory.stale:
        flash(
            "Jen keeps certificate copies for "
            + ", ".join(inventory.stale)
            + ", which are not https endpoints now; they are ignored.",
            "info",
        )
    trust = __tls.trust_kind()  # Q190 (AF1): how the CA bundle relates to Jen's CA, by certificate identity - what may be rewritten after the promotion follows from it
    planned = {(server.get("id"), service) for server, service, _bind in targets}
    record_lost: set = set()  # AE2: the targets whose pair Jen cannot record (the host holds one Jen cannot name)
    probed: set = (
        set()
    )  # AE1b: the targets that answered with the NEW identity - a success is proved against the configuration too

    # Q188 (AD1/AD6/AD8): the rotation is ONE transaction. Jen's own state is staged first (`stage_rotation`: the new CA and client pair beside the live files), every target is issued, installed,
    # restarted and probed with the STAGED identity, Jen's TLS settings are saved, and only then is the staging promoted as one set - each step inside one exception boundary, so a step
    # that fails (or raises) stops the rotation and every attempted target is put back on the CA Jen still trusts. The staging is discarded in a `finally`; `.prev` pairs stay until the end.
    staged = None
    promotion_attempted = False  # Q195 (AK2 b): the 'no longer a matching pair' sentence is about a PROMOTION that failed part-way; a CA that became unusable without one says what it is now
    reused = False  # Q192 (AH1): the staging came from a `Prepare only` an external daemon's trust anchor may already hold - kept when this rotation fails, discarded only by success or its button
    done: list[tuple[dict, str, str]] = []
    confirmed: set = set()  # targets the host is KNOWN to hold the staged pair for (its install was acknowledged)
    attempted: list[tuple[dict, str, str]] = []  # every target the host may now hold STAGED-CA material for
    failure = ""
    outcome: dict = {
        "rolled": [],
        "restart_stuck": [],
        "pair_stuck": [],
        "unreachable": [],
        "unknown": [],
        "local_stale": [],
    }
    try:
        try:
            prepared, prepared_note = __tls.prepared_rotation(discard=True)
            if prepared_note:
                flash(prepared_note[:1].upper() + prepared_note[1:] + ".", "info")
            if prepared is not None:
                staged, reused = prepared, True
                flash(
                    f"Rotating to the CA prepared earlier (fingerprint {__tls.prepared_fingerprint(prepared)}).",
                    "info",
                )
            else:
                staged = __tls.stage_rotation()
        except __tls.PreparedUnreadable as e:
            logger.error(f"kea_tls: the prepared CA cannot be read: {type(e).__name__}")
            flash(
                "Rotate refused - the prepared CA cannot be read right now, and Jen will not overwrite a CA it cannot read. Nothing was changed.",
                "error",
            )
            return back
        except Exception as e:
            logger.error(f"kea_tls: could not stage the new CA: {type(e).__name__}: {__auth.scrub_urls(str(e))}")
            flash(
                "Rotate refused - Jen could not write the staged CA beside the live one. Nothing was changed.", "error"
            )
            return back
        unproved = _staged_identity_refusal(inventory, __tls.client_kind(), staged, recovery=recovery)
        if unproved:
            # Q192 (AH1): BEFORE the install loop - nothing is on any host yet, so nothing is put back
            flash(f"Rotate refused - {unproved}. Nothing was changed on any host.", "error")
            return back
        # Q194 (AJ1): the staged CA is judged by the same function as the live one, once more immediately before anything is installed (a prepared CA was read earlier; a file can change in between)
        staged_ca, staged_ca_why = __tls.ca_identity(staged["ca_cert"], staged["ca_key"])
        if staged_ca != "ok":
            flash(
                f"Rotate refused - the new CA is not a certificate-signing authority ({staged_ca_why}). Nothing was changed on any host.",
                "error",
            )
            return back
        # Q194 (AJ2): the filesystem can change between the inventory and the first install - Jen proves once more, by writing, that it can keep what it is about to issue
        storage_now = __tls.copies_dir_writable()
        if storage_now:
            flash(
                f"Rotate refused - Jen cannot write its certificate records any more ({storage_now}), so it could not keep what it issues. Nothing was changed on any host.",
                "error",
            )
            return back
        try:
            for server, service, bind in targets:
                sname = server.get("name") or f"Kea Server {server.get('id')}"
                daemon = _DAEMON_NAME[service]
                try:
                    files = __tls.issue_server_cert(
                        server, service, bind, ca=(staged["ca_cert"], staged["ca_key"]), commit=False
                    )  # Jen's own pair changes only once the host has this one and it answers
                except Exception as e:
                    logger.error(
                        f"kea_tls: staged issue failed for {sname}/{service}: {type(e).__name__}: {__auth.scrub_urls(str(e))}"
                    )
                    failure = f"{sname} {daemon}: could not issue its certificate (see the server log)"
                    break
                attempted.append((server, service, bind))
                pushed = __host.install_tls(server, service, files)
                if not pushed.get("ok"):
                    failure = f"{sname} {daemon}: {pushed.get('detail', 'the helper refused the TLS material')}"
                    break
                confirmed.add((server.get("id"), service))
                restarted = __host.service_action(server, service, "restart")
                if not restarted.get("ok"):
                    failure = f"{sname}: {daemon} did NOT restart ({restarted.get('detail')})"
                    break
                url = _service_url(server, service)
                user, pwd = _daemon_creds(server, service)
                version_text, probe_err = _probe_after_restart(
                    url,
                    user,
                    pwd,
                    service,
                    verify=staged["ca_cert"],
                    cert=(staged["client_cert"], staged["client_key"]),
                )
                if not version_text:
                    failure = f"{sname} {daemon}: {__auth.shown_url(url)} did not answer with the new certificates ({probe_err})"
                    break
                probed.add((server.get("id"), service))
                try:
                    __tls.commit_issued(
                        server.get("id"), service, files
                    )  # the target answers on the staged CA: Jen's copy of its pair follows
                except OSError as e:
                    if isinstance(e, __tls.HostRecordLost):
                        record_lost.add((server.get("id"), service))
                    failure = f"{sname} {daemon}: Jen could not keep its own copy of the new certificate ({type(e).__name__}, errno {getattr(e, 'errno', '?')})"
                    break
                done.append((server, service, bind))
            if not failure and probed != planned:
                failure = (
                    "the endpoints that answered with the new certificates are not the endpoints Jen planned to rotate"
                )
            # (the endpoints, not the records: a target Jen already committed carries a certificate from the staged CA, which the live-CA record check would call 'an earlier Jen CA')
            if (
                not failure
                and __tls.rotation_inventory(
                    extensions.KEA_SERVERS, url_for=_configured_url, prove_storage=False
                ).endpoints
                != inventory.endpoints
            ):
                failure = "the set of https endpoints changed while the rotation ran"
            if not failure and targets and trust == "jens-file":
                # Q190 (AF1): the settings are rewritten only when the bundle IS Jen's own file; an alias, a copy, a bundle that contains Jen's CA or an administrator's CA is left exactly as the operator wrote it
                try:  # Jen's own settings BEFORE the promotion: a refused write stops the rotation while every target can still be put back
                    __config.app_config.write_values(
                        [
                            ("kea", "api_ca", __tls.ca_paths()[0]),
                            ("kea", "api_client_cert", __tls.client_paths()[0]),
                            ("kea", "api_client_key", __tls.client_paths()[1]),
                            ("kea", "api_tls_verify", "true"),
                        ]
                    )
                except (__config.ConfigChangeRefused, OSError) as e:
                    failure = f"Jen could not save its TLS settings ({_sentence_of(e)})"
            if not failure:
                try:
                    promotion_attempted = True
                    __tls.commit_rotation(staged)
                except OSError as e:
                    failure = f"Jen could not promote the new CA locally ({type(e).__name__}, errno {getattr(e, 'errno', '?')})"
        except Exception as e:  # the boundary: nothing escapes with the hosts on one CA and Jen on another
            logger.error(
                f"kea_tls: the rotation stopped on an unexpected {type(e).__name__}: {__auth.scrub_urls(str(e))}"
            )
            failure = failure or f"an unexpected {type(e).__name__}"

        if failure:
            ca_live = __tls.ca_paths()[0]
            client_live = __tls.client_paths()
            ca_ok = __tls.ca_consistent()  # a promotion whose own put-back failed can leave Jen's CA certificate and key apart: nothing can be issued from it
            ca_now_why = __tls.ca_state()[
                1
            ]  # (Q195 second pass: read ONCE - every sentence below names the same state)
            # Q193 (second pass, findings 2 and 3): a recovery that fails at ANY step - before the first install or in the promotion - left Jen's CA as damaged as it found it (the promotion puts its files
            # back); the daemons that took the staged pair hold a certificate from a CA Jen discarded. It is judged by the CA NOW: one an operator restored meanwhile is rolled back like any rotation.
            recovery_failed = recovery and not ca_ok
            for server, service, bind in attempted:
                sname = server.get("name") or f"Kea Server {server.get('id')}"
                label = f"{sname} {_DAEMON_NAME[service]}"
                key = (server.get("id"), service)
                if key not in confirmed:
                    # the staged install was REFUSED - maybe a lost reply after the helper applied it, so Jen re-asserts the pair it last put there (no restart: the daemon never moved); with none to
                    # re-assert, or the helper refusing again, the host's material is unknown - an incident to acknowledge, not a rollback of a host never known to have changed
                    if _reinstall_live_material(server, service) != "restored":
                        outcome["unknown"].append((server, service, label))
                    continue
                if not ca_ok:
                    outcome["pair_stuck"].append((server, service, label))
                    continue
                local_ok = True
                try:
                    old = __tls.issue_server_cert(server, service, bind, commit=False)  # the OLD CA - still live
                    installed = __host.install_tls(server, service, old).get("ok")
                    if installed:
                        try:
                            __tls.commit_issued(server.get("id"), service, old)
                            record_lost.discard(key)  # the host holds exactly this pair and Jen's record says so
                        except OSError as e:
                            # Q189 (AE2): `commit_issued` has already recorded the pair the host holds (`old`) as `.prev` and marked the live copy stale - or raised HostRecordLost
                            logger.error(
                                f"kea_tls: the previous-CA pair is on {label} but Jen could not keep its copy: {type(e).__name__}"
                            )
                            local_ok = False
                            if isinstance(e, __tls.HostRecordLost):
                                record_lost.add(key)
                except Exception as e:
                    logger.error(f"kea_tls: rollback issue failed for {label}: {type(e).__name__}: {e}")
                    installed = False
                if not installed:
                    outcome["pair_stuck"].append((server, service, label))
                    continue
                if not local_ok and key not in record_lost:
                    outcome["local_stale"].append(
                        (server, service, label)
                    )  # (the daemon is still restarted and probed below)
                try:
                    if not __host.service_action(server, service, "restart").get("ok"):
                        outcome["restart_stuck"].append((server, service, label))
                        continue
                    creds = _daemon_creds(server, service)
                    answered, _why = _endpoint_answers(
                        {
                            "url": _service_url(server, service),
                            "user": creds[0],
                            "password": creds[1],
                            "verify": ca_live,
                            "cert": client_live,
                            "expect": _DAEMON_KEY[service],
                        },
                        service,
                    )
                except Exception as e:  # nothing escapes the rollback of one target before the next is tried
                    logger.error(f"kea_tls: rollback of {label} stopped on {type(e).__name__}: {e}")
                    answered = False
                (outcome["rolled"] if answered else outcome["unreachable"]).append((server, service, label))
            for server, service, _label in outcome["local_stale"]:
                _record_incident(server, service, "the failed CA rotation", "tls-local-stale")
            for server, service, _bind in attempted:
                if (server.get("id"), service) in record_lost:
                    sname = server.get("name") or f"Kea Server {server.get('id')}"
                    flash(
                        f"Jen cannot record which certificate {sname} {_DAEMON_NAME[service]} holds (its SSL directory cannot be written): do not rely on Jen's copy of it; "
                        f"once the directory is writable, {_reissue_action()}.",
                        "error",
                    )
                    _record_incident(server, service, "the failed CA rotation", "remote-unknown")
            for server, service, _label in outcome["pair_stuck"]:
                _record_incident(
                    server,
                    service,
                    "the failed CA rotation",
                    "tls-not-restored",
                    _RECOVERY_CUT_OFF if recovery_failed else "",
                )
            for server, service, _label in outcome["unknown"]:
                # (Q193, AI4 e) the helper REFUSED the new pair and Jen could not re-assert the old one: what the host holds is UNKNOWN (`tls-not-restored` says it is known to hold the staged pair)
                _record_incident(server, service, "the failed CA rotation", "remote-unknown")
            for server, service, _label in outcome["restart_stuck"]:
                _record_incident(server, service, "the failed CA rotation", "restart-failed")
            for server, service, _label in outcome["unreachable"]:
                _record_incident(server, service, "the failed CA rotation", "restored-endpoint-unreachable")
            for server, service, _bind in targets:
                if not any(
                    server is s and service == sv
                    for s, sv, _l in outcome["pair_stuck"] + outcome["unknown"] + outcome["local_stale"]
                ):
                    __tls.retire_previous(
                        server.get("id"), service
                    )  # the pair before this attempt is not a recovery point for an operation that is over - unless it is the only copy of what a stuck host should hold
            msg = f"Rotate stopped at {failure}." + (" Jen still trusts the previous CA." if ca_ok else "")
            if recovery_failed:
                # Q193 (AI1): the CA was damaged BEFORE staging - so the text is about the recovery, not a promotion that failed part-way, and the action it names is the one that works. It says
                # what each daemon IS: a daemon that took the staged pair holds a certificate from the CA Jen discarded; one whose install was refused is unknown; the rest were not changed.
                cut_off = [lb for _s, _v, lb in outcome["pair_stuck"]]
                unknown = [lb for _s, _v, lb in outcome["unknown"]]
                other_open = [
                    lb for _s, _v, lb in outcome["restart_stuck"] + outcome["unreachable"] + outcome["local_stale"]
                ]
                left = cut_off + unknown + other_open
                untouched = [
                    f"{s.get('name') or 'Kea Server ' + str(s.get('id'))} {_DAEMON_NAME[sv]}"
                    for s, sv, _b in targets
                    if f"{s.get('name') or 'Kea Server ' + str(s.get('id'))} {_DAEMON_NAME[sv]}" not in left
                ]
                ca_now_why = ca_now_why or ca_why
                if outcome["rolled"]:
                    msg += f" Restarted and answering: {', '.join(lb for _s, _v, lb in outcome['rolled'])}."
                flash(msg, "error")
                if left:
                    details = []
                    if cut_off:
                        details.append(
                            f"{', '.join(cut_off)}: the replacement CA's certificate is installed (and the CA itself was discarded), so the daemon will not answer Jen until the recovery is repeated"
                        )
                    if unknown:
                        details.append(
                            f"{', '.join(unknown)}: the helper refused the replacement certificate and what the host holds is unknown (usually unchanged)"
                        )
                    if other_open:
                        details.append(f"{', '.join(other_open)}: left in a state recorded on Servers")
                    flash(
                        f"The recovery did not complete: {len(left)} of {len(targets)} daemon(s) were left in a state that needs it repeated - {'; '.join(details)} (each recorded on Servers). "
                        + (f"Not changed: {', '.join(untouched)}. " if untouched else "")
                        + f"Jen's CA is still damaged ({ca_now_why}). Rotate again with the acknowledgement to re-issue them all; the https setup stays refused until the CA is replaced.",
                        "error",
                    )
                else:
                    flash(
                        f"The recovery did not complete: no daemon was changed. Jen's CA is still damaged ({ca_why}). Rotate again with the acknowledgement; the https setup stays refused until the CA is replaced.",
                        "error",
                    )
            elif not ca_ok and promotion_attempted:
                flash(
                    "Jen's CA certificate and CA key are no longer a matching pair (a promotion failed part-way and its own put-back failed too), so nothing can be issued from them. "
                    f"The CA now: {ca_now_why or 'unusable'}. "
                    "Restore kea-ca.crt and kea-ca.key together from a backup, or from the .prev copies beside them, before any other CA or socket action.",
                    "error",
                )
            elif not ca_ok:
                # Q195 (AK2 b): no promotion ran - the CA became unusable DURING the rotation (a file changed, a clock stepped): say what it is now, and the action that works (the setup is refused)
                flash(
                    f"Jen's CA became unusable during the rotation ({ca_now_why or 'unusable'}), so nothing can be issued from it and a daemon that took the new certificate cannot be put back. "
                    "Rotate again with the acknowledgement to replace it and re-issue every daemon (or restore the CA files from a backup); the https setup stays refused until the CA is replaced.",
                    "error",
                )
            if not recovery_failed:
                if outcome["rolled"]:
                    msg += f" Rolled back to the previous CA, restarted and answering: {', '.join(lb for _s, _v, lb in outcome['rolled'])}."
                flash(msg, "error")
            if outcome["pair_stuck"] and not recovery_failed:
                flash(
                    f"ROLLBACK FAILED on {', '.join(lb for _s, _v, lb in outcome['pair_stuck'])} — they hold certificates from a CA Jen never adopted and won't answer Jen until fixed: "
                    f"{_reissue_action()} (for each).",
                    "error",
                )
            if outcome["restart_stuck"]:
                flash(
                    f"{', '.join(lb for _s, _v, lb in outcome['restart_stuck'])}: the previous certificate is back but the daemon did not restart on it - it may be stopped. Restart it on the Kea host.",
                    "error",
                )
            if outcome["local_stale"] and not recovery_failed:
                flash(
                    f"{', '.join(lb for _s, _v, lb in outcome['local_stale'])}: the previous-CA certificate is on the host, but Jen could not refresh its own copy of it (its expiry warning reads that copy): "
                    f"{_reissue_action()}, once Jen's SSL directory is writable.",
                    "error",
                )
            if outcome["unreachable"]:
                flash(
                    f"{', '.join(lb for _s, _v, lb in outcome['unreachable'])}: the previous certificate is back and the daemon restarted, but Jen's endpoint did not answer afterwards. Check the daemon and the network path.",
                    "error",
                )
            if outcome["unknown"]:
                flash(
                    f"{', '.join(lb for _s, _v, lb in outcome['unknown'])}: the helper refused the new certificate and Jen could not re-assert the one it had, so the host's material is unknown (usually "
                    "unchanged). Check it, then acknowledge the notice on Servers.",
                    "error",
                )
            __user.audit(
                "ROTATE_KEA_CA",
                "kea_api",
                f"failed: {failure}; rolled_back={len(outcome['rolled'])} stuck={len(outcome['pair_stuck']) + len(outcome['restart_stuck']) + len(outcome['unreachable']) + len(outcome['unknown'])}",
            )
            return back
    finally:
        if staged is not None and not reused:
            __tls.discard_rotation(staged)
        elif staged is not None and os.path.lexists(staged["ca_cert"]):
            flash(
                "The prepared CA is kept (fingerprint "
                f"{__tls.prepared_fingerprint(staged)}) so a later rotation reuses the same one; discard it under Settings → Kea if you no longer want it.",
                "info",
            )

    for server, service, _bind in targets:
        __tls.retire_previous(
            server.get("id"), service
        )  # the rotation stands: now - and only now - the pairs before it are of no use
        __changeset.resolve_attention(
            server.get("id"), service
        )  # ... and the daemon answered with the new identity: a verified recovery of THIS server and service
    names = ", ".join(
        f"{s.get('name') or 'Kea Server ' + str(s.get('id'))} {_DAEMON_NAME[svc]}" for s, svc, _b in targets
    )
    configured_ca = (extensions.KEA_API_CA or "").strip()
    if trust == "alias":
        flash(
            f"Jen's CA file changed under {configured_ca}: that path is another name for it, so Jen verifies the rotated endpoints against the new CA without a change.",
            "info",
        )
    flash(
        "Kea CA rotated — new CA and client certificate issued"
        + (
            f"; new server certificates pushed to {names}, each daemon restarted and answering with the new CA."
            if targets
            else "; no server certificate was involved (Jen has no https endpoint on its CA)."
        )
        + " The previous CA is kept beside the new one as kea-ca.crt.prev.",
        "success",
    )
    __user.audit(
        "ROTATE_KEA_CA",
        "kea_api",
        f"ok: {len(targets)} server certificate(s) re-issued"
        + (" (replaced a damaged CA: acknowledged)" if recovery else ""),
    )
    return back


@bp.route("/settings/infrastructure/kea-ca/prepare", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
@_holding_identity_lock
def prepare_kea_ca():
    """Q192 (AH1) - "Prepare only": a new CA and client pair written beside the live files (`.next`, the keys private) and KEPT, with nothing changed on any host and nothing Jen trusts changed. The
    page shows the new CA certificate's fingerprint and path for the operator to add to an external daemon's trust anchor beside the current one; a later Rotate REUSES it (the same CA-B)."""
    from jen.services import kea_tls as __tls

    back = redirect(url_for("settings.settings_kea"))
    ca_state, ca_why = __tls.ca_state()
    if ca_state == "none":
        # Q193 (AI2): only the absence of any CA is "nothing to replace" - a DAMAGED CA is exactly when an external daemon's trust has to be prepared (Prepare mints a fresh CA and reads nothing live)
        flash("Nothing to prepare: Jen has no CA to replace - set up an https socket and Jen creates one.", "error")
        return back
    try:
        staged, note = __tls.prepared_rotation(discard=True)
    except __tls.PreparedUnreadable as e:
        logger.error(f"kea_tls: the prepared CA cannot be read: {type(e).__name__}")
        flash(
            "Prepare refused - the prepared CA cannot be read right now, and Jen will not overwrite a CA it cannot read. Nothing was changed.",
            "error",
        )
        return back
    if note:
        flash(note[:1].upper() + note[1:] + ".", "info")
    if staged is None:
        try:
            staged = __tls.stage_rotation()
        except Exception as e:
            logger.error(f"kea_tls: could not prepare the new CA: {type(e).__name__}: {__auth.scrub_urls(str(e))}")
            flash("Prepare failed - Jen could not write the new CA beside the live one. Nothing was changed.", "error")
            return back
        verb = "prepared"
    else:
        verb = "already prepared"
    flash(
        f"A new CA is {verb}: {staged['ca_cert']} (SHA-256 fingerprint {__tls.prepared_fingerprint(staged)}). Add it to the trust anchor of any daemon that is not on Jen's CA and checks "
        "Jen's client certificate - beside the current CA, not instead of it - then rotate"
        + (" (Rotate Kea CA, with the acknowledgement: Jen's CA is damaged)" if ca_state == "damaged" else "")
        + ". Nothing was changed on any host.",
        "success",
    )
    __user.audit("PREPARE_KEA_CA", "kea_api", f"{verb} {os.path.basename(staged['ca_cert'])}")
    return back


@bp.route("/settings/infrastructure/kea-ca/discard", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
@_holding_identity_lock
def discard_prepared_kea_ca():
    """Q192 (AH1) - drop the prepared CA (`.next`): the one other way, beside a successful rotation, that it goes."""
    from jen.services import kea_tls as __tls

    existed = any(os.path.lexists(p) for p in __tls._staged_paths().values())
    __tls.discard_rotation(__tls._staged_paths())
    left = [os.path.basename(p) for p in __tls._staged_paths().values() if os.path.lexists(p)]
    if left:
        flash(
            f"The prepared CA could not be discarded: {', '.join(left)} could not be removed (finding 8: never 'discarded' on a failure).",
            "error",
        )
        return redirect(url_for("settings.settings_kea"))
    flash("The prepared CA was discarded." if existed else "There was no prepared CA.", "info")
    if existed:
        __user.audit("DISCARD_PREPARED_KEA_CA", "kea_api", "discarded")
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/direct-socket/<int:server_id>/<service>/remove", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
@_holding_identity_lock
def remove_direct_socket(server_id, service):
    """v5.29.0 (Q29, B2) — the reverse of setup_direct_socket for ONE
    daemon on ONE server: drop the http/https entry from the daemon's
    control-sockets (the unix entry stays), restart, then undo Jen's
    side — dhcp6/D2 lose their per-daemon URL override (ca mode inherits
    the v4 URL again); dhcp4 gets its remembered pre-direct URL back and
    `connection_mode` returns to `ca` only when no OTHER server still
    answers as kea-dhcp4 on its v4 URL. Not a delete-everything button."""
    from jen.services import kea_changeset as __changeset
    from jen.services import kea_config_edit as __edit

    back = redirect(url_for("settings.settings_kea"))
    if service not in _DIRECT_SERVICES:
        flash("Unknown Kea service.", "error")
        return back
    server = _server_by_id(server_id)
    if server is None:
        flash("Unknown Kea server.", "error")
        return back
    name = server.get("name") or f"Kea Server {server_id}"
    daemon = _DAEMON_NAME[service]
    conf = f"kea-{_CONF_STEM[service]}.conf"
    if not server.get("ssh_host"):
        flash(f"{name} has no SSH host configured — Jen edits {conf} over SSH.", "error")
        return back

    # Z1 (v5.69.0-beta.15, Q184): THE PERSON TYPES. This route infers nothing about hosts, boxes or history (beta.13 and beta.14 each defined "this box" a different way and each
    # definition was wrong for a proxy, a tunnel or a jump host): the form has the password field every other credential-moving form has, and the endpoint the route repoints is
    # typed only when the person typed a password, ticked "No password", or ticked "restore the saved one" - their act, in this request. The daemons the switch-back re-derives are
    # never typed here: the writer refuses one whose saved password would reach a new place, and the page says to type it under Settings -> Kea first.
    password = request.form.get("password", "").strip()
    user_typed = request.form.get("user", "").strip()
    no_password = request.form.get("no_password", "") == "1"
    restore_saved = request.form.get("restore_saved", "") == "1"
    ca_url = request.form.get(
        "ca_url", ""
    ).strip()  # AB3 (Q186): the Control Agent's address, typed when Jen has none to return to
    if sum(bool(x) for x in (password, no_password, restore_saved)) > 1:
        flash("Choose one for the password: type it, tick No password, or restore the saved one.", "error")
        return back
    # AA1/AA3 (Q185): "No password" means no user either, so a typed user beside it is a contradiction; the restore is the saved user AND password or neither, so a typed user beside it is too
    if user_typed and (no_password or restore_saved):
        flash(
            "Choose one for the user: type one, or tick No password / restore the saved pair (each of those sets the user itself).",
            "error",
        )
        return back
    if ca_url and (service != "dhcp4" or restore_saved):
        flash(
            "Choose one for the Control Agent's address: type it, or restore the saved pair (which belongs to the saved address)."
            if service == "dhcp4"
            else "Only kea-dhcp4's removal takes a Control Agent address.",
            "error",
        )
        return back
    _sec, _url_key, _user_key, _pass_key = _socket_keys(server, service)
    _live = __config.app_config._read_parser()
    # (second pass, Q184, finding 1: the saved pair is valid WITH its address - a pair left without one by an older release is not offered and not restored)
    has_saved_pair = (
        service == "dhcp4"
        and _live.has_section(_sec)
        and bool(_live.get(_sec, _PREV_URL_KEY, fallback=""))
        and any(
            _live.has_option(_sec, k)
            for k in (_PREV_USER_KEY, _PREV_PASS_KEY, _PREV_USER_ABSENT_KEY, _PREV_PASS_ABSENT_KEY)
        )
    )
    if restore_saved and not has_saved_pair:
        flash("There is no saved Control Agent user and password to restore - type the password instead.", "error")
        return back
    sid = server.get("id")
    changed: list[str] = []
    # Computed once, outside the mutate: does any OTHER server still
    # answer as kea-dhcp4 on its v4 URL? Then the (global) mode stays
    # direct for their sake.
    keep_direct = False
    others_still_direct: list[str] = []
    if service == "dhcp4":
        # Q187 (AC5): ONE listener is one listener. A record that names the very endpoint being removed (scheme, host and port) is not "another server on its own socket" - it answers
        # only because this socket still exists - so it never counts toward keeping direct mode, and removing the socket would leave it pointing at nothing: refused, naming it.
        _socket_now = _live.get(_sec, _url_key, fallback="").strip() if _live.has_section(_sec) else ""
        twins = []
        for s in extensions.KEA_SERVERS:
            if s.get("id") == sid or not s.get("api_url"):
                continue
            if __auth.same_endpoint(s["api_url"], _socket_now):
                twins.append(s.get("name", "Kea Server"))
                continue
            if _identify_daemon(s["api_url"], s.get("api_user", ""), s.get("api_pass", ""), "dhcp4") == "Dhcp4":
                others_still_direct.append(s.get("name", "Kea Server"))
        if twins:
            flash(
                f"{', '.join(twins)} uses this same socket ({__auth.shown_url(_socket_now)}); remove it there first or point it elsewhere. Nothing was changed on {name}.",
                "error",
            )
            return back
        keep_direct = bool(others_still_direct)
    else:
        # Q188 (AD9): the twin refusal is for every daemon - another server record whose Kea6 / D2 address is the very listener being removed would be left pointing at nothing
        _other_key = {"dhcp6": "api6_url", "d2": "api_d2_url"}[service]
        _socket_now = _live.get(_sec, _url_key, fallback="").strip() if _live.has_section(_sec) else ""
        twins = [
            s.get("name", "Kea Server")
            for s in extensions.KEA_SERVERS
            if s.get("id") != sid
            and s.get(_other_key)
            and _socket_now
            and __auth.same_endpoint(s[_other_key], _socket_now)
        ]
        if twins:
            flash(
                f"{', '.join(twins)} uses this same socket ({__auth.shown_url(_socket_now)}); remove it there first or point it elsewhere. Nothing was changed on {name}.",
                "error",
            )
            return back

    _before_users = {
        n: e.user for n, e in __credentials.resolve(_live).items()
    }  # what each endpoint sends now (a dependant inherits its parent's user)
    _before_own = {
        n: e.source == "own" for n, e in __credentials.resolve(_live).items()
    }  # AB4: whether each endpoint's password is its OWN (a dependant that inherited one has nothing of its own to keep)

    def _apply(cfg):
        sec, url_key, user_key, pass_key = _socket_keys(server, service)
        if service == "dhcp4":
            saved_prev = cfg.get(sec, _PREV_URL_KEY, fallback="") if cfg.has_section(sec) else ""
            prev = (
                "" if ca_url else saved_prev
            )  # an address typed on the form wins; the pair saved for the OTHER address is then discarded below
            if ca_url:
                cfg.set(sec, url_key, ca_url)
                if saved_prev:
                    cfg.remove_option(sec, _PREV_URL_KEY)
                changed.append(
                    f"[{sec}] {url_key} set to {__auth.shown_url(ca_url)} (the Control Agent's address, typed)"
                )
                if any(
                    cfg.has_option(sec, k)
                    for k in (_PREV_USER_KEY, _PREV_PASS_KEY, _PREV_USER_ABSENT_KEY, _PREV_PASS_ABSENT_KEY)
                ):
                    changed.append(
                        f"[{sec}] the Control Agent's saved user and password (for {__auth.shown_url(saved_prev) if saved_prev else 'the earlier address'}) were DISCARDED - the pair typed here is used"
                    )
            elif prev:
                cfg.set(sec, url_key, prev)
                cfg.remove_option(sec, _PREV_URL_KEY)
                changed.append(f"[{sec}] {url_key} restored to {__auth.shown_url(prev)}")
            else:
                changed.append(
                    f"[{sec}] {url_key} left as-is (no Control Agent URL on record; another server keeps direct mode)"
                )
            if cfg.has_section(sec):
                if prev and restore_saved:
                    # Z2: the Control Agent's own pair, put back by the person's tick - the socket's pair was the SOCKET's. AB4 (Q186): each half goes back AS IT WAS - a value (a blank
                    # included) is set, and one the Control Agent did not have is REMOVED (the socket's user must not stay behind, and an absent password is not an explicit blank)
                    if cfg.has_option(sec, _PREV_USER_KEY):
                        cfg.set(sec, "api_user", cfg.get(sec, _PREV_USER_KEY))
                    elif cfg.has_option(sec, "api_user"):
                        cfg.remove_option(sec, "api_user")
                    if cfg.has_option(sec, _PREV_PASS_KEY):
                        cfg.set(sec, "api_pass", cfg.get(sec, _PREV_PASS_KEY))
                    elif cfg.has_option(sec, "api_pass"):
                        cfg.remove_option(sec, "api_pass")
                    if cfg.get(sec, _PREV_SHARED_KEY, fallback="") == "1":
                        cfg.set(
                            sec, f"{pass_key}_shared", "1"
                        )  # the saved pair was a marked copy; so is the restored one
                    else:
                        __credentials.clear_shared(
                            cfg, _endpoint_name(server, service)
                        )  # ... and one that was not is not (a stale marker of the socket's own pair)
                    changed.append(f"[{sec}] the Control Agent's saved user and password restored")
                elif (
                    prev
                    and any(
                        cfg.has_option(sec, k)
                        for k in (_PREV_USER_KEY, _PREV_PASS_KEY, _PREV_USER_ABSENT_KEY, _PREV_PASS_ABSENT_KEY)
                    )
                    and not (password or no_password)
                ):
                    changed.append(
                        f"[{sec}] the Control Agent's saved user and password were DISCARDED - the socket's pair is now the Control Agent's (tick Restore the saved user and password to put the saved pair back)"
                    )
                for stale in _PREV_PAIR_KEYS:
                    if cfg.has_option(sec, stale):
                        cfg.remove_option(
                            sec, stale
                        )  # restored, superseded, or orphaned (no address to go with it): the saved pair is not kept
            if user_typed:
                cfg.set(sec, "api_user", user_typed)
                changed.append(f"[{sec}] api_user set to {user_typed}")
            if password:
                cfg.set(sec, "api_pass", password)
                __credentials.clear_shared(cfg, _endpoint_name(server, service))
                changed.append(f"[{sec}] api_pass set (typed for the Control Agent)")
            elif no_password:
                # AA1 (Q185): "No password" is no authentication - no user either (an empty Basic header carrying the socket's username is not "none")
                cfg.set(sec, "api_pass", "")
                if cfg.has_option(sec, "api_user"):
                    # second pass (Q185, finding 1): a dependant with a password of its own and NO user key inherits THIS user (the resolver's rule) - removing it would change what that
                    # dependant sends. It keeps the user it was sending, written as its own; the message says so.
                    removed_user = cfg.get(sec, "api_user")
                    for dep in sorted(_endpoints_of_server(server) - {_endpoint_name(server, service)}):
                        dep_section, dep_user_key = __credentials.user_key(dep)
                        if (
                            removed_user
                            and _before_own.get(dep)
                            and dep in _before_users
                            and _before_users[dep] == removed_user
                            and cfg.has_section(dep_section)
                            and not cfg.has_option(dep_section, dep_user_key)
                        ):
                            cfg.set(dep_section, dep_user_key, removed_user)
                            changed.append(
                                f"[{dep_section}] {dep_user_key} kept as {removed_user} (it was inherited from the user just cleared)"
                            )
                    cfg.remove_option(sec, "api_user")
                __credentials.clear_shared(cfg, _endpoint_name(server, service))
                changed.append(f"[{sec}] user and password cleared (no authentication)")
            if not keep_direct and _mode_of(cfg) != "ca":
                cfg.set("kea", "connection_mode", "ca")
                changed.append("Jen switched back to Control Agent mode")
        else:
            if cfg.has_section(sec) and cfg.has_option(sec, url_key):
                cfg.remove_option(sec, url_key)
                changed.append(f"[{sec}] {url_key} cleared — inherits the v4 URL in Control Agent mode")
            if _mode_of(cfg) != "direct" and cfg.has_section(sec):
                # Z2: in Control Agent mode the daemon's own user and password were the SOCKET's - the Control Agent authenticates with the Control Agent's, so no pair rides to it
                for stale in (user_key, pass_key):
                    if cfg.has_option(sec, stale):
                        cfg.remove_option(sec, stale)
                __credentials.clear_shared(cfg, _endpoint_name(server, service))
                changed.append(f"[{sec}] the daemon's own user and password cleared — it uses the Control Agent's")
            if password or no_password:
                if not cfg.has_section(sec):
                    cfg.add_section(sec)
                cfg.set(sec, pass_key, password if password else "")
                if no_password and cfg.has_option(sec, user_key):
                    cfg.remove_option(sec, user_key)  # AA1 (Q185): no authentication is no user, in either mode
                # (second pass, Q186, finding 2: AB5 first kept the daemon's own user beside a typed password in Control Agent mode. That user was the SOCKET's - Z2 clears it - so the
                # Control Agent was sent the socket's user name with the Control Agent's password. The typed password is paired with the Control Agent's user, which the daemon inherits.)
                __credentials.clear_shared(cfg, _endpoint_name(server, service))
                changed.append(
                    f"[{sec}] {pass_key} set" if password else f"[{sec}] user and password cleared (no authentication)"
                )
            if sid == 1 and cfg.has_section(sec) and not cfg.options(sec):
                cfg.remove_section(sec)

    # v5.68.0-beta.28 (Q164): Jen's own side of this (the dhcp4 URL put back, the global mode returned to `ca`) is an identity change, and the route's first act is
    # on the Kea host - so the config writer's question is asked of a COPY before the first remote write.
    # Z1: the endpoint this route repoints is typed when - and only when - the person gave it a password (or "No password", or asked for the saved one back); asked BEFORE the Kea host is touched
    # (a restore with nothing saved was refused above, so the tick alone is the claim: every term is something the form said)
    typed_names = {_endpoint_name(server, service)} if (password or no_password or restore_saved) else set()
    try:
        __config.app_config.preflight_identity_change(_apply, typed=typed_names)
    except __config.ConfigChangeRefused as refused:
        flash(refused.sentence, "error")
        if "type the password" in refused.sentence or "type each one's own password" in refused.sentence:
            flash(
                "This form types only the password of the endpoint it moves (the field above, or No password, or the saved one). A daemon named in the sentence keeps its own saved password: "
                "type it under Settings → Kea first (or clear it), then remove the socket.",
                "info",
            )
        flash(f"Nothing was changed on {name}.", "info")
        return back
    # (Q186: these two refusals come AFTER the config writer's question above, so a refusal by the writer is still the first answer - and still before the Kea host is touched)
    # AB1 (Q186): Jen manages ONE API socket; a daemon whose config has more than one is refused here, before anything is sent - not flattened.
    read_errors: list = []
    existing_api = _api_sockets_of(server, service, errors=read_errors)
    if _preread_refusal(server, service, conf, read_errors):
        return back
    if existing_api is not None and len(existing_api) > 1:
        flash(_many_sockets_sentence(daemon, conf, len(existing_api)), "error")
        return back

    # AB3 (Q186): a dhcp4 removal that would flip Jen to Control Agent mode needs a Control Agent address to flip TO. With none saved (or the saved one is the socket being removed) and no other
    # server keeping its own socket, Jen would be left pointing at the socket it just removed. Refused BEFORE the host is touched; the form's address (with the user and password it already
    # has) is validated, and must ANSWER as a Control Agent, before the socket goes.
    if service == "dhcp4":
        _has_sec = _live.has_section(_sec)
        _current_url = _live.get(_sec, _url_key, fallback="").strip().rstrip("/") if _has_sec else ""
        _saved_url = _live.get(_sec, _PREV_URL_KEY, fallback="").strip().rstrip("/") if _has_sec else ""

        def _pair_after_removal():
            """(user, password) the endpoint will SEND once this removal is done: `credentials.resolve` of the file AS THE REMOVAL WILL WRITE IT (Q187, AC4; second pass, finding 1). Not the pair it
            sends to the socket's host - an inherited password is withheld at a different host by the writer, and a probe made with it first would have sent it there."""
            preview = __config.app_config._read_parser()
            _apply(preview)
            changed.clear()  # (the callback records phrases for the flash; this run was only a preview)
            endpoint = __credentials.resolve(preview).get(_endpoint_name(server, service))
            return (endpoint.user, endpoint.password) if endpoint else ("", "")

        if ca_url:
            if __auth.userinfo_sentence(ca_url):
                flash(__auth.userinfo_sentence(ca_url) + " Nothing was changed.", "error")  # Q191 (AG3 c, CRED-005)
                return back
            if not (__auth.valid_api_url(ca_url, require_port=True) and _is_kea_url_shape(ca_url)):
                flash(
                    "The Control Agent's address must look like http://host:8000 (a scheme, a host and a port). Nothing was changed.",
                    "error",
                )
                return back
            if ca_url.rstrip("/") == _current_url:
                flash(
                    f"{__auth.shown_url(ca_url)} is the socket being removed, not a Control Agent. Type the Control Agent's address. Nothing was changed on {name}.",
                    "error",
                )
                return back
            for s in extensions.KEA_SERVERS:
                if s.get("id") != sid and s.get("api_url") and __auth.same_endpoint(s["api_url"], ca_url):
                    flash(
                        f"{__auth.shown_url(ca_url)} is {s.get('name', 'a different server')}'s own address, not {name}'s Control Agent: {name} would be managed through the wrong box. Nothing was changed on {name}.",
                        "error",
                    )
                    return back
            if not (password or no_password):
                flash(
                    "An address for the Control Agent needs its password: type it, or tick No password. Nothing was changed.",
                    "error",
                )
                return back
            _probed = _identify_daemon(ca_url, *_pair_after_removal(), "dhcp4")
            if _probed != "Control-agent":
                flash(
                    f"{__auth.shown_url(ca_url)} "
                    + ("did not answer" if not _probed else f"answered as {_probed}, not as a Control Agent")
                    + f" with that user and password. Nothing was changed on {name}.",
                    "error",
                )
                return back
        elif not _saved_url or _saved_url == _current_url:
            if not keep_direct:
                flash(
                    "Jen has no Control Agent address to return to: set it (URL, user, password) on this form. "
                    f"Nothing was changed on {name}.",
                    "error",
                )
                return back
        else:
            # second pass (Q186, finding 1): a saved address that merely DIFFERS as text from the socket (an alias, an earlier direct socket the setup replaced, another case or a trailing dot)
            # is no proof it is a Control Agent. The address Jen is about to restore is asked who it is, exactly as a typed one is, before the socket goes - whether or not another server
            # keeps direct mode (Q187, AC6: the keep_direct branch restores it just the same).
            _probed = _identify_daemon(_saved_url, *_pair_after_removal(), "dhcp4")
            if _probed != "Control-agent":
                flash(
                    f"The Control Agent address Jen saved ({__auth.shown_url(_saved_url)}) "
                    + ("did not answer" if not _probed else f"answered as {_probed}, not as a Control Agent")
                    + f". Type the Control Agent's address (URL, user, password) on this form. Nothing was changed on {name}.",
                    "error",
                )
                return back

    # second pass (Q184, finding 3): a daemon socket that INHERITED the primary's pair on the same host loses it when the primary's address changes spelling (10.0.0.5 -> kea-a.lan) - nothing
    # is sent to it any more and the daemon on the Kea host still wants that pair. Not a leak, so not a refusal; named, so the person is told rather than finding a blank card
    _before_endpoints = __credentials.resolve(_live)
    _preview = __config.app_config._read_parser()
    _apply(_preview)
    _after_endpoints = __credentials.resolve(_preview)
    lost = [
        __credentials.label(n)
        for n in sorted(_endpoints_of_server(server))
        if n != _endpoint_name(server, service)
        and n in _before_endpoints
        and n in _after_endpoints
        and _before_endpoints[n].password
        and not _after_endpoints[n].password
    ]
    changed.clear()  # the preflight ran the callback on a copy; the real run below fills the list the flash reads

    orig = _jen_endpoint(
        server, service
    )  # Q188 (AD4): the endpoint Jen dials NOW - the socket being removed, in direct mode - recorded before the first remote change
    snapshot_taken: dict = {}  # AB1 (Q186): the daemon's control-sockets list exactly as the removal was PLANNED on it - what the compensation restores

    def _remove(cfg):
        snapshot = __edit.control_sockets(cfg, service)
        snapshot_taken["sockets"] = snapshot
        singular = __edit.uses_singular_socket(cfg, service)
        api = [s for s in snapshot if __edit._is_api_socket(s)]
        if len(api) == 1:  # ONE named socket is removed: the entry's own address and port
            after, code = __edit.remove_control_socket(
                cfg, service, api[0].get("socket-address"), api[0].get("socket-port")
            )
        else:
            after, code = __edit.remove_control_socket(cfg, service)  # none: "nochange"; several: "multiple"
        snapshot_taken["singular"] = singular and code == "ok"  # (said only when the file was actually rewritten)
        return after, code

    result = __changeset.apply_change(
        service,
        _remove,
        f"removed the {daemon} http control socket",
        servers=[server],
        restart=True,
        code_messages={
            "unsupported": f"{conf} has no {_DAEMON_KEY[service]} block — is this the right file? Nothing was changed.",
            "nochange": f"{conf} has no http/https control socket to remove — only Jen's own settings change",
            "multiple": _many_sockets_sentence(daemon, conf),
        },
        daemon_label=daemon,
    )
    if result.status == "noservers":
        flash(f"{name} has no SSH host configured.", "error")
        return back
    for style, text in result.lines:
        flash(text, style)
    if result.status in __changeset.NOT_APPLIED:
        flash("Jen's own settings were not changed.", "info")
        return back

    try:
        __config.app_config.mutate(_apply, typed=typed_names)
    except (__config.ConfigChangeRefused, OSError) as refused:
        # v5.68.0-beta.29 (Q165, edge 3): refused AFTER the socket was taken out of the daemon's config - put it back as it was, the daemon restarted (Q182: a failed write too)
        if result.status == "ok":
            snapshot = snapshot_taken.get("sockets")
            removed = [s for s in (snapshot or []) if __edit._is_api_socket(s)]
            described = __edit.describe_socket(removed[0]) if removed else "http"
            _undo_remote_change(
                server,
                service,
                snapshot,
                f"put the {daemon} control socket back ({described}; Jen's settings were refused)",
                _sentence_of(refused),
                what=f"the removal of the {described} control socket",
                by_hand=f"Put the control-sockets of {conf} back as they were ({_SOCKET_ENTRY_LIVES}) and restart {daemon}, or press Remove socket again once Jen's settings can be changed.",
                orig=orig,
            )
        else:
            flash(_sentence_of(refused), "error")
            flash(f"Nothing was changed on {name}: there was no socket to remove.", "info")
        return back
    __user.set_global_setting("restart_pending", "true")
    if snapshot_taken.get("singular"):
        changed.append(
            f"{daemon}'s single control-socket entry was rewritten in the control-sockets list form (the form Kea 2.7.2 and later reads)"
        )
    if result.status == "ok":
        # (second pass, Q187, findings 4 and 16) a removal proves only that the socket it removed is gone: it clears the "never answered" note of THAT socket. It proves nothing about whether the
        # daemon runs (a Control Agent can answer while kea-dhcp4 is down), so every other category waits for a probe of the daemon or an acknowledgement.
        __changeset.resolve_attention(server_id, service, categories=("probe-pending",))
    flash(f"{daemon} on {name}: {'; '.join(changed)}.", "success")
    if lost:
        flash(
            f"{', '.join(lost)} used the password of the address that just changed and now has none: type its own under Settings → Kea (the daemon on the Kea host may still need one).",
            "warning",
        )
    if keep_direct:
        flash(
            f"Jen stays in direct mode — {', '.join(others_still_direct)} still answer on their own kea-dhcp4 "
            f"sockets. {name} will show the Control Agent error until you switch those back too, or set its "
            "socket up again. If one of them is this same Kea under another spelling of its address, Jen cannot tell (it does no DNS lookups to decide): point that record elsewhere "
            "or remove it, then remove this socket again.",
            "warning",
        )
    answer = "typed" if password else "none" if no_password else "restored" if restore_saved else "unchanged"
    # (second pass, Q185, finding 2: the user is whatever the route did to it - the form's user field exists for the Control Agent only, so a crafted one on a daemon is ignored and said so)
    user_answer = (
        "typed"
        if (user_typed and service == "dhcp4")
        else "cleared"
        if no_password
        else "restored"
        if restore_saved
        else "unchanged"
    )
    __user.audit(
        "REMOVE_DIRECT_SOCKET", "kea_api", f"server={name} service={service} password={answer} user={user_answer}"
    )
    return back


@bp.route("/settings/infrastructure/investigation-logging-enabled", methods=["POST"])
@login_required
@_superadmin_required
def toggle_investigation_logging():
    """v5.68.0-beta.30 (Q167) - investigation logging on demand is early access, off by default. Switching it on or off changes only whether the Turn on buttons exist and `turn_on`
    answers: turning off, the sweep, forget, acknowledge, Health and the Kea host's own timer are never gated, so a session that is already on is still restored and shown."""
    enable = request.form.get("enable", "").strip() == "true"
    # v5.69.0-beta.2 (Q171): the setting and its audit row are ONE transaction and the answer is what happened - the page used to say "switched on" when the write had failed
    if not __user.set_global_setting_and_audit(
        __inv.ENABLED_KEY,
        "true" if enable else "false",
        "INVESTIGATION_LOGGING_ENABLED_CHANGED",
        __inv.ENABLED_KEY,
        f"enabled={enable}",
    ):
        flash(
            "The investigation logging switch could not be saved - nothing was changed. The reason is in the Jen log.",
            "error",
        )
        return redirect(url_for("settings.settings_kea"))
    if enable:
        flash("Investigation logging is switched on (early access). Servers and Trace now offer Turn on.", "success")
    else:
        flash(
            "Investigation logging is switched off. A session that is already on is still restored by the Kea host and shown until it ends.",
            "success",
        )
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/toggle-ipv6", methods=["POST"])
@login_required
@_superadmin_required
def toggle_ipv6():
    """
    v5.0 Phase 1 — the IPv6 enable/disable toggle. Superadmin-gated: unlike
    the other infrastructure save routes (admin-level), this one has real
    infrastructure side effects — starting/stopping a service across
    potentially multiple remote machines over SSH+sudo, not a harmless
    config-file flag flip.

    Two-layer design (see the v5.0 plan doc):
    1. set_ipv6_service_state() does the actual SSH/systemctl work against
       every configured server and reports per-server success/failure.
    2. Only after seeing those results does this route decide whether to
       flip Jen's own ipv6_enabled DISPLAY flag — so a partial failure
       across an HA pair never leaves Jen showing v6 as "on" when some
       servers never actually started serving it.

    Enabling: the flag only flips to true if EVERY server with ssh_host
    configured succeeded. Any failure (including "no kea-dhcp6.conf on
    this server") leaves the flag false and the fleet unmodified.

    Disabling: the flag always flips to false — the user's intent is v6
    off, and Jen should stop showing v6 UI regardless of whether every
    remote systemctl call succeeded. Any server that failed to actually
    stop is reported so it's visible, not silently inconsistent.
    """
    enable = request.form.get("enable", "").strip() == "true"

    if not any(s.get("ssh_host") for s in extensions.KEA_SERVERS):
        flash(
            "No Kea server has SSH configured — nothing to enable/disable remotely. "
            "Configure SSH under Kea Server settings first.",
            "error",
        )
        return redirect(url_for("settings.settings_kea"))

    results = __kea6.set_ipv6_service_state(enable)
    all_ok = bool(results) and all(r["ok"] for r in results)

    for r in results:
        flash(f"{r['name']}: {r['message']}", "success" if r["ok"] else "error")

    if enable:
        if all_ok:
            __user.set_global_setting("ipv6_enabled", "true")
            flash("IPv6 support enabled.", "success")
        else:
            flash("IPv6 was NOT enabled — at least one server failed. Fix the issue above and try again.", "error")
    else:
        __user.set_global_setting("ipv6_enabled", "false")
        if not all_ok:
            flash(
                "IPv6 display turned off, but at least one server may still be "
                "running kea-dhcp6-server — see errors above.",
                "error",
            )
        else:
            flash("IPv6 support disabled.", "success")

    __user.audit("TOGGLE_IPV6", "ipv6_enabled", f"enable={enable} all_ok={all_ok} servers={len(results)}")
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/check-config-drift", methods=["POST"])
@login_required
@_admin_required
def check_config_drift_route():
    """
    Manual, on-demand check of whether Jen's own subnet map still
    agrees with what Kea's live config actually says — a config-get
    call against the active server (same "one representative server"
    convention as every other live-config read in this app; an HA
    pair's config is expected to be identical across nodes, so
    checking one is representative), not run automatically on every
    Settings page load. The background check_alerts() loop already
    runs this continuously and alerts on new/resolved drift — this
    route exists for on-demand verification without waiting for or
    digging through that alert history.
    """
    from jen.services.config_drift import check_config_drift

    try:
        issues = check_config_drift()
        return jsonify({"ok": True, "issues": issues})
    except Exception as e:
        logger.error(f"Error checking config drift: {e}")
        return jsonify({"ok": False, "error": "Could not check config drift. Check server logs for details."})


@bp.route("/settings/infrastructure/save-jen-db", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def save_infra_jen_db():
    """v5.69.0-beta.2 (Q171) - Jen's own database holds the users table. An admin who could repoint [jen_db] at a database they control and restart Jen would be whatever
    role that database says: superadmin, and step-up, because this is the one setting that decides who the superadmins are."""
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "").strip()
    database = request.form.get("database", "").strip()
    if not host or not user or not database:
        flash("Host, username, and database name are required.", "error")
        return redirect(url_for("database.database", tab="connections"))
    refusal = _secret_for_new_endpoint(
        extensions.cfg.get("jen_db", "host", fallback=""),
        host,
        password,
        extensions.cfg.get("jen_db", "password", fallback=""),
        "Jen database host",
    )
    if refusal:
        flash(refusal, "error")
        return redirect(url_for("database.database", tab="connections"))
    items = [("jen_db", "host", host), ("jen_db", "user", user), ("jen_db", "database", database)]
    if password:
        items.append(("jen_db", "password", password))
    __config.app_config.write_values(items, typed={"jen_db"} if password else None)
    __user.set_global_setting("restart_pending", "true")
    flash("Jen database settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "jen_db", f"host={host}")
    return redirect(url_for("database.database", tab="connections"))


@bp.route("/settings/infrastructure/save-ssh", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def save_infra_ssh():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    kea_conf = request.form.get("kea_conf", "").strip()
    dhcp4_log_path = request.form.get("dhcp4_log_path", "").strip()
    if host and not __auth.valid_ssh_target(host):
        flash("Invalid SSH host — must be a valid hostname or IP address.", "error")
        return redirect(url_for("settings.settings_kea"))
    if user and not __auth.valid_unix_username(user):
        flash("Invalid SSH user — must be a valid unix username.", "error")
        return redirect(url_for("settings.settings_kea"))
    if kea_conf and not __auth.valid_remote_path(kea_conf):
        flash("Invalid Kea config path — must be an absolute path with no special characters.", "error")
        return redirect(url_for("settings.settings_kea"))
    if kea_conf and not kea_conf.endswith(".conf"):
        flash(f"Invalid Kea config path — the file name must end in .conf: {kea_conf}", "error")
        return redirect(url_for("settings.settings_kea"))
    if dhcp4_log_path and not __auth.valid_log_path(dhcp4_log_path):
        # v5.69.0-beta.6 (Q175): the rule the Kea host's helper applies to a log it reads - a path outside /var/log would only be refused there
        flash(
            "Invalid Kea log path — it must be an absolute path to a .log file under /var/log (for example /var/log/kea/kea-dhcp4.log), with no special characters.",
            "error",
        )
        return redirect(url_for("settings.settings_kea"))
    if not host:
        # v5.68.0-beta.9 (Q144): without an SSH host Jen cannot put a log level back on the primary
        refusal = __inv.removal_refusal([1], actor=current_user.username)
        if refusal:
            flash(refusal, "error")
            return redirect(url_for("settings.settings_kea"))
    items = [("kea_ssh", "host", host), ("kea_ssh", "user", user)]
    if kea_conf:
        items.append(("kea_ssh", "kea_conf", kea_conf))
    if dhcp4_log_path:
        items.append(("kea", "dhcp4_log_path", dhcp4_log_path))

    def _apply(parser):
        for section, key, value in items:
            if not parser.has_section(section):
                parser.add_section(section)
            parser.set(section, key, value)
        if not dhcp4_log_path and parser.has_section("kea"):
            parser.remove_option(
                "kea", "dhcp4_log_path"
            )  # blank is the default again: the key is removed, not saved empty

    __config.app_config.mutate(_apply)  # one write: the SSH settings and the log path land together or not at all
    from jen.services import log_tail as __log_tail

    __log_tail.clear()  # where each server's log is was read under the old path; the next reader asks again
    __user.set_global_setting("restart_pending", "true")
    flash("SSH settings saved. Restart Jen to apply.", "success")
    mismatch = __host_match.api_ssh_mismatch(extensions.cfg.get("kea", "api_url", fallback=""), host)
    if mismatch:
        flash(mismatch, "warning")
    __user.audit("SAVE_INFRA", "ssh", f"host={host} user={user} log_path={dhcp4_log_path or 'default'}")
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/save-extra-servers", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def save_extra_servers():
    # v5.10.3 — extra_id[] carries each row's ORIGINAL kea_server_N number
    # (blank for a row added in the UI). It is the identity used to carry a
    # blank password and any hand-added key forward, so reordering or
    # deleting rows no longer swaps them between servers.
    ids = request.form.getlist("extra_id[]")
    names = request.form.getlist("extra_name[]")
    roles = request.form.getlist("extra_role[]")
    api_urls = request.form.getlist("extra_api_url[]")
    api_users = request.form.getlist("extra_api_user[]")
    api_passes = request.form.getlist("extra_api_pass[]")
    api6_urls = request.form.getlist("extra_api6_url[]")
    api6_users = request.form.getlist("extra_api6_user[]")
    api6_passes = request.form.getlist("extra_api6_pass[]")
    ssh_hosts = request.form.getlist("extra_ssh_host[]")
    ssh_users = request.form.getlist("extra_ssh_user[]")
    kea_confs = request.form.getlist("extra_kea_conf[]")
    # CRED-003 (Q179, T3): one "1"/"0" per row, in row order - a NEW row takes the primary's API password only through its own checkbox
    shares = request.form.getlist("extra_share_pass[]")
    no6_passes = request.form.getlist(
        "extra_api6_no_pass[]"
    )  # Q181 (V4): one "1"/"0" per row, like extra_no_pass[] - the IPv6 and D2 endpoints can say "no authentication" too
    nod2_passes = request.form.getlist("extra_d2_no_pass[]")
    no_passes = request.form.getlist("extra_no_pass[]")

    for h in ssh_hosts:
        if h.strip() and not __auth.valid_ssh_target(h.strip()):
            flash(f"Invalid SSH host: {h.strip()}", "error")
            return redirect(url_for("settings.settings_kea"))
    for u in ssh_users:
        if u.strip() and not __auth.valid_unix_username(u.strip()):
            flash(f"Invalid SSH user: {u.strip()}", "error")
            return redirect(url_for("settings.settings_kea"))
    for kc in kea_confs:
        if kc.strip() and not __auth.valid_remote_path(kc.strip()):
            flash(f"Invalid Kea config path: {kc.strip()}", "error")
            return redirect(url_for("settings.settings_kea"))
        if kc.strip() and not kc.strip().endswith(".conf"):
            flash(f"Invalid Kea config path — the file name must end in .conf: {kc.strip()}", "error")
            return redirect(url_for("settings.settings_kea"))
    _require_port = __caps.is_direct()
    for u in api_urls:
        if u.strip() and not __auth.valid_api_url(u.strip(), require_port=_require_port):
            flash(
                __auth.userinfo_sentence(u) or f"Invalid API URL: {__auth.shown_url(u.strip())}", "error"
            )  # (second pass, Q190: a refused address is shown without its user-info)
            return redirect(url_for("settings.settings_kea"))
    for u in api6_urls:
        if u.strip() and not __auth.valid_api_url(u.strip(), require_port=_require_port):
            flash(
                __auth.userinfo_sentence(u)
                or f"Invalid IPv6 API URL: {__auth.shown_url(u.strip())} (direct mode needs an explicit port)",
                "error",
            )
            return redirect(url_for("settings.settings_kea"))

    # v5.68.0-beta.9 (Q144): a server this form drops (its row removed, its API URL or its SSH host blanked) is one Jen can no longer put an
    # investigation log level back on. Refuse until turn_off has succeeded, rather than lose the only way to restore it.
    kept = {
        int(i.strip())
        for i, url, host in zip(ids, api_urls, ssh_hosts, strict=False)
        if i.strip().isdigit() and url.strip() and host.strip()
    }
    refusal = __inv.removal_refusal(
        [s["id"] for s in extensions.KEA_SERVERS if s["id"] != 1 and s["id"] not in kept], actor=current_user.username
    )
    if refusal:
        flash(refusal, "error")
        return redirect(url_for("settings.settings_kea"))

    # v5.68.0-beta.27 (Q162, item 1): the identity of a server is its id. A submitted id that appears twice, or an id that is not configured but carries
    # an SSH host, is a tampered form (Jen's own page never sends either): refused outright, before any comparison. (Whether a row that keeps a configured
    # id may change its four identity fields is the config writer's question since v5.68.0-beta.28, Q164.)
    configured_extra = {s["id"] for s in extensions.KEA_SERVERS if s["id"] != 1}
    submitted = [int(i.strip()) for i in ids if i.strip().isdigit()]
    for i, host in zip(ids, ssh_hosts, strict=False):
        n = int(i.strip()) if i.strip().isdigit() else None
        if n is not None and (submitted.count(n) > 1 or (n not in configured_extra and host.strip())):
            flash("Refused: duplicate or unknown server id in the submitted form.", "error")
            return redirect(url_for("settings.settings_kea"))

    # v5.69.0-beta.3 (Q172, item 6): a server's name is what a person reads in every flash line, banner and history row, so two servers may not share one, and it
    # is one short line (a newline would write a second key into the section's own line). A blank name is not checked: it is given "Kea Server <id>", which is
    # unique by construction. A row without an API URL is dropped by the rewrite below and is not a server, so its name is not counted.
    primary_name = extensions.cfg.get("kea", "name", fallback="Kea Server 1").strip().casefold()
    seen_names = {primary_name}
    for name, api_url in zip(names, api_urls, strict=False):
        shown = name.strip()
        if not shown or not api_url.strip():
            continue
        if "\n" in name or "\r" in name or len(shown) > 100:
            flash("Refused: a server name is one line of at most 100 characters.", "error")
            return redirect(url_for("settings.settings_kea"))
        if shown.casefold() in seen_names:
            flash(f'Refused: two servers are named "{shown}" - every server needs its own name.', "error")
            return redirect(url_for("settings.settings_kea"))
        seen_names.add(shown.casefold())

    refused: list[str] = []
    typed_names: set[str] = (
        set()
    )  # the endpoint names whose password this request TYPED (or copied by the box): `mutate`'s `typed`, read after the callback has run

    def _rewrite_extra_servers(cfg):
        before_resolved = __credentials.resolve(cfg)  # what each endpoint resolved to BEFORE this save touched it
        # v5.10.3 — snapshot every current [kea_server_N] so keys the form
        # doesn't manage (ssh_key, any hand-added value) and a blank
        # password survive the remove-and-rebuild. Preservation is by the
        # row's ORIGINAL section id (extra_id[]), NOT by position: before
        # this, reordering two rows wrote each server into the other's old
        # section number and each silently inherited the other's api_pass /
        # api6_pass / ssh_key. A row added in the UI has no id and
        # preserves nothing.
        #
        # v5.20.0 (Q15) — section numbers are now stable IDENTITIES, not
        # positions: kea_config_revisions.server_id, kea_helper_status,
        # and every /servers/<id> URL are keyed by this integer, so
        # renumbering on every save silently reassigned a deleted
        # server's history/status to whichever server next landed on its
        # old number. A row with a known, unclaimed id keeps that exact
        # number regardless of its position in the form; only a
        # genuinely new/unknown/duplicated row gets a fresh one. A
        # blank-api_url row is simply dropped — a gap left behind is
        # normal now, not a bug.
        existing = {n: dict(cfg.items(f"kea_server_{n}")) for n in _kea_server_section_ids(cfg)}
        for n in existing:
            cfg.remove_section(f"kea_server_{n}")

        # A tampered/duplicated id must not pull another server's secrets in.
        seen_ids = set()

        direct = __caps.is_direct()
        for row_idx, (
            extra_id,
            name,
            role,
            api_url,
            api_user,
            api_pass,
            api6_url,
            api6_user,
            api6_pass,
            ssh_host,
            ssh_user,
            kea_conf,
        ) in enumerate(
            zip(
                ids,
                names,
                roles,
                api_urls,
                api_users,
                api_passes,
                api6_urls,
                api6_users,
                api6_passes,
                ssh_hosts,
                ssh_users,
                kea_confs,
                strict=True,
            )
        ):
            if not api_url.strip():
                continue
            raw_id = extra_id.strip()
            orig_id = int(raw_id) if raw_id.isdigit() else None
            if orig_id is not None and (orig_id not in existing or orig_id in seen_ids):
                orig_id = None  # unknown or duplicated — treat the row as new

            out = orig_id if orig_id is not None else max({1, *existing, *seen_ids}) + 1
            seen_ids.add(out)
            prev = existing.get(orig_id, {}) if orig_id is not None else {}

            # CRED-002 (Q178, Q179 T3, Q180): a row that keeps its saved password must keep its endpoint, and the password it keeps is the one `credentials.resolve` says it USES (its
            # own, else - on the same host only - the primary's). Nothing is written until this callback returns, so raising is the refusal. A NEW row has no stored address to compare:
            # it takes the primary's password only through its own box (below), else what was typed, else none.
            who = name.strip() or f"Kea Server {out}"
            no6_ticked = row_idx < len(no6_passes) and no6_passes[row_idx] == "1"
            nod2_ticked = row_idx < len(nod2_passes) and nod2_passes[row_idx] == "1"
            if orig_id is not None and not (row_idx < len(no_passes) and no_passes[row_idx] == "1"):
                stored_api = before_resolved.get(f"server_{orig_id}")
                stored_secret = stored_api.password if stored_api else ""
                refusal = _secret_for_new_endpoint(
                    prev.get("api_url"), api_url.strip(), api_pass, stored_secret, f"API address of {who}"
                )
                if not refusal and not api6_pass.strip() and not no6_ticked:
                    # the IPv6 endpoint of a row that types no IPv6 password: judged against the password the connection will USE for it
                    stored6 = prev.get("api6_url") or ("" if direct else prev.get("api_url"))
                    new6 = api6_url.strip() or ("" if direct else api_url.strip())
                    if prev.get("api6_pass"):
                        # its own IPv6 password is kept, and follows its own endpoint
                        refusal = _secret_for_new_endpoint(
                            stored6, new6, "", prev["api6_pass"], f"IPv6 API address of {who}"
                        )
                    elif (
                        not api_pass.strip()
                        and stored_secret
                        and new6
                        and not __auth.same_host(new6, stored6)
                        and not __auth.same_host(new6, api_url)
                    ):
                        # no IPv6 password of its own: the connection uses the API password, which is KEPT here. That is fine while the IPv6 address stays on the host it was on or
                        # is on the (new) API address's host - another port of the same host is the same Kea - and a password sent to a new host otherwise
                        refusal = (
                            f"The IPv6 API address of {who} changed: enter the password for the new endpoint - "
                            "a saved password is never sent to one it was not typed for."
                        )
                    # (a typed API password is the one the IPv6 connection uses, and it was typed for this row)
                if refusal:
                    refused.append(refusal)
                    raise _EndpointNeedsItsPassword()
            share_ticked = orig_id is None and row_idx < len(shares) and shares[row_idx] == "1"
            no_ticked = row_idx < len(no_passes) and no_passes[row_idx] == "1"
            if no_ticked and (api_pass.strip() or share_ticked):
                refused.append(
                    f"Choose one for the API password of {who}: no password, share the primary's, or type one."
                )
                raise _EndpointNeedsItsPassword()
            if no6_ticked and api6_pass.strip():
                refused.append(f"Choose one for the IPv6 API password of {who}: no password, or type one.")
                raise _EndpointNeedsItsPassword()
            if share_ticked and api_pass.strip():
                # U3 (Q180): the box and a typed password are two answers for one secret
                refused.append(f"Choose one for the API password of {who}: share the primary's, or type one.")
                raise _EndpointNeedsItsPassword()

            sec = f"kea_server_{out}"
            cfg.add_section(sec)
            cfg.set(sec, "name", name.strip() or f"Kea Server {out}")
            cfg.set(sec, "role", role.strip() or "standby")
            cfg.set(sec, "api_url", api_url.strip())
            cfg.set(sec, "api_user", api_user.strip())
            if no_ticked:
                cfg.set(
                    sec, "api_pass", ""
                )  # explicit: a Kea with no authentication - `resolve` reads it as none and nothing is withheld
            elif api_pass.strip():
                cfg.set(
                    sec, "api_pass", api_pass.strip()
                )  # typed: its own from now on, and no longer "a copy of the primary's"
                typed_names.add(f"server_{out}")
            elif orig_id is not None:
                # Blank => keep THIS server's own saved password (by id), and the marker that says it is a copy of the primary's. A section that has none keeps having none:
                # `credentials.resolve` gives it the primary's only while it is on the primary's host (CRED-004) - nothing is COPIED into it here.
                if prev.get("api_pass"):
                    cfg.set(sec, "api_pass", prev["api_pass"])
                    if prev.get(__credentials.SHARED_MARKER):
                        cfg.set(sec, __credentials.SHARED_MARKER, prev[__credentials.SHARED_MARKER])
            elif share_ticked:
                # a NEW row: the primary's password only because the box "Share the primary's API password (an HA peer of the same Kea)" was ticked - a copy, marked as one. The typed claim is
                # the box alone (AA2, Q185); whether the primary HAS a password is the parser's to say, inside the callback, not a read of the configuration to decide the claim
                primary_password = cfg.get("kea", "api_pass", fallback="")
                if primary_password:
                    cfg.set(sec, "api_pass", primary_password)
                    cfg.set(sec, __credentials.SHARED_MARKER, "1")
                typed_names.add(f"server_{out}")
            # v5.10.2 — per-server v6 endpoint. Blank managed field ⇒ key
            # absent (that IS the clear). api6_pass blank ⇒ preserve by id.
            if api6_url.strip():
                cfg.set(sec, "api6_url", api6_url.strip())
            if api6_user.strip():
                cfg.set(sec, "api6_user", api6_user.strip())
            if no6_ticked:
                cfg.set(sec, "api6_pass", "")  # explicit: the IPv6 socket has no authentication
            elif api6_pass.strip():
                cfg.set(sec, "api6_pass", api6_pass.strip())
                typed_names.add(f"server_{out}_v6")
            elif prev.get("api6_pass"):
                cfg.set(sec, "api6_pass", prev["api6_pass"])
                if prev.get("api6_pass_shared"):
                    cfg.set(
                        sec, "api6_pass_shared", prev["api6_pass_shared"]
                    )  # kept as it was: still a copy (a typed or blanked one is not - see `clear_shared` below)
            cfg.set(sec, "ssh_host", ssh_host.strip())
            cfg.set(sec, "ssh_user", ssh_user.strip())
            cfg.set(sec, "kea_conf", kea_conf.strip() or "/etc/kea/kea-dhcp4.conf")
            for k, v in prev.items():
                if k not in _EXTRA_SERVER_FORM_KEYS:
                    cfg.set(sec, k, v)
            if nod2_ticked and cfg.has_option(sec, "api_d2_url"):
                cfg.set(sec, "api_d2_pass", "")  # explicit: the D2 socket has no authentication
                __credentials.clear_shared(cfg, f"server_{out}_d2")  # Y3 (Q183)
            elif (
                row_idx < len(nod2_passes) and cfg.has_option(sec, "api_d2_pass") and cfg.get(sec, "api_d2_pass") == ""
            ):
                cfg.remove_option(
                    sec, "api_d2_pass"
                )  # the box was UNTICKED on a page that carries it: back to "inherit, if the host is the same"
                __credentials.clear_shared(cfg, f"server_{out}_d2")  # Y3 (Q183)
            if no_ticked or api_pass.strip():
                __credentials.clear_shared(
                    cfg, f"server_{out}"
                )  # Y3 (Q183): typed or blanked in this save - its own now (a kept password carries its marker above)
            if no6_ticked or api6_pass.strip():
                __credentials.clear_shared(cfg, f"server_{out}_v6")  # Y3 (Q183)

        # U3 (Q180): the resolver is the proof. The IPv6 and D2 endpoint of every saved row is judged against the credential `resolve` gives IT: a typed API password authorises
        # them on the same host only, and one on a different host with no password of its own would be refused its neighbour's - so the form says so instead of saving a
        # credential-less endpoint. (One that was ALREADY in that state and did not change is not this save's doing.)
        after_resolved = __credentials.resolve(cfg)
        for name_, endpoint in after_resolved.items():
            if not name_.endswith(("_v6", "_d2")) or not endpoint.withheld:
                continue
            was = before_resolved.get(name_)
            if was is not None and was.withheld and was.url == endpoint.url:
                continue
            number = int(name_.split("_")[1])
            who_ = cfg.get(f"kea_server_{number}", "name", fallback=f"Kea Server {number}")
            refused.append(
                f"The {'IPv6' if name_.endswith('_v6') else 'D2'} address of {who_} ({__credentials.host_of(endpoint.url)}) is on a different host from its API address: "
                "enter its own password - the API password is never sent to a different host."
            )
            raise _EndpointNeedsItsPassword()

    try:
        __config.app_config.mutate(_rewrite_extra_servers, typed=typed_names)
    except _EndpointNeedsItsPassword:
        flash(refused[0], "error")  # our own sentence, appended before the raise - never the exception's text
        return redirect(url_for("settings.settings_kea"))
    except ValueError as e:
        # strict=True on the zip() inside _rewrite_extra_servers means a
        # form submission whose extra_*[] fields don't all have the same
        # number of entries — malformed or tampered, since Jen's own
        # template always submits all twelve together per server row —
        # raises here instead of silently truncating to the shortest
        # list and misaligning one server's fields with another's.
        logger.error(f"Mismatched extra-server form field lengths: {e}")
        flash("Could not save additional servers — form data was inconsistent. Please try again.", "error")
        return redirect(url_for("settings.settings_kea"))

    count = len(extensions.KEA_SERVERS) - 1
    flash(f"Additional servers saved — {count} extra server(s) configured.", "success")
    for url, host in zip(api_urls, ssh_hosts, strict=False):
        mismatch = __host_match.api_ssh_mismatch(url, host)
        if mismatch:
            flash(mismatch, "warning")
    __user.set_global_setting("restart_pending", "true")
    __user.audit("SAVE_INFRA", "extra_servers", f"{count} additional servers configured")
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/extra-server/<int:server_id>/copy-primary-password", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def copy_primary_password(server_id):
    """U2 (v5.69.0-beta.11, Q180): "Copy the primary's again" - an additional server whose password is a COPY of the primary's (`api_pass_shared`; written by the upgrade's one-time
    conversion or by the "share" box) does not follow a later change of the primary's password. This writes the primary's CURRENT password into the section again, as the
    superadmin's explicit act, with the marker, and an audit row."""
    section = f"kea_server_{server_id}"
    if server_id < 2 or not extensions.cfg.has_section(section):
        flash("That server is not configured.", "error")
        return redirect(url_for("settings.settings_kea"))
    if not extensions.cfg.get("kea", "api_pass", fallback=""):
        flash("The primary has no API password to copy.", "error")
        return redirect(url_for("settings.settings_kea"))

    class _Gone(Exception):
        pass

    class _Own(Exception):
        pass

    def _apply(cfg):
        if not cfg.has_section(section):
            raise _Gone()  # removed by another save since the check above: nothing is written
        if not cfg.get("kea", "api_pass", fallback=""):
            raise _Gone()  # the primary's password was blanked since the check above: copying "" would silently say "no authentication"
        if cfg.get(section, __credentials.SHARED_MARKER, fallback="") != "1":
            raise _Own()  # Q182 (X5b): only a COPY of the primary's is copied again - a password the server owns is not the primary's to overwrite
        cfg.set(section, "api_pass", cfg.get("kea", "api_pass", fallback=""))
        cfg.set(section, __credentials.SHARED_MARKER, "1")

    try:
        __config.app_config.mutate(_apply, typed={f"server_{server_id}"})
    except _Gone:
        flash("That server is not configured.", "error")
        return redirect(url_for("settings.settings_kea"))
    except _Own:
        flash(
            f"{extensions.cfg.get(section, 'name', fallback=f'Kea Server {server_id}')}'s password is its own - it is not a copy of the primary's, so there is nothing to copy again. "
            "Type a new one on the server's row to change it.",
            "error",
        )
        return redirect(url_for("settings.settings_kea"))
    __user.set_global_setting("restart_pending", "true")
    flash("The primary's API password was copied into that server again. It does not follow later changes.", "success")
    __user.audit("SAVE_INFRA", f"kea_server_{server_id}", "api_pass copied again from the primary")
    return redirect(url_for("settings.settings_kea"))


class _EndpointNeedsItsPassword(Exception):
    """Raised inside a config `mutate` callback: the form would keep a saved password for a new endpoint. The callback has written nothing yet - `mutate` writes only after
    it returns - so raising is the refusal (CRED-002, Q178)."""


def _secret_for_new_endpoint(stored_url, new_url, new_secret, stored_secret, what) -> str | None:
    """CRED-002 (v5.69.0-beta.9, Q178): a saved password is never sent to an endpoint it was not typed for. The refusal sentence when a form would KEEP a stored secret (the
    new secret is blank, a stored one exists) while the endpoint it names has changed (`auth.same_endpoint` - scheme, host and port); None when nothing is wrong: a secret was
    typed, none is stored, neither side names an endpoint (nothing changed), or the endpoint is the same place. Every connection form calls this BEFORE its write, so a refusal
    writes nothing. (A LOOKUP credential - the DDNS token - is not refused: it is removed, with a warning, by `save_infra_ddns`.)"""
    if (new_secret or "").strip() or not (stored_secret or "").strip():
        return None
    if not (stored_url or "").strip() and not (new_url or "").strip():
        return None
    if __auth.same_endpoint(stored_url, new_url):
        return None
    return (
        f"The {what} changed: enter the password for the new endpoint - "
        "a saved password is never sent to one it was not typed for."
    )


def _one_answer_for_a_secret(inherit: bool, typed: str, what_and_parent: str) -> str | None:
    """CRED-002 (v5.69.0-beta.10, Q179, T2): a form that offers "Inherit" and a password box gets ONE answer for the secret. Ticking Inherit AND typing a password is a contradiction
    - the old code wrote nothing for the typed one and said "saved" - so the form refuses it, with nothing written. `what_and_parent` is "<the secret>|<whose it inherits>"."""
    if not (inherit and (typed or "").strip()):
        return None
    what, parent = what_and_parent.split("|", 1)
    return f"Choose one for the {what}: inherit {parent} password, or type one."


def _inherited_secret_refusal(v4_url, new_url, new_secret, v4_secret, what) -> str | None:
    """CRED-002 for a password a form INHERITS (Kea6 and D2 use the Kea API's when they have none of their own, and "Inherit" removes theirs): the sentence when no password
    was typed, the Kea API has one, and the address this form now names - or, when it is blank, falls back to - is on a DIFFERENT HOST from the Kea API's. Another port of the
    same host is the same Kea (the daemons' own sockets); another host is a secret sent somewhere it was not typed for, whoever asked, and "Inherit" does not make it one."""
    if (new_secret or "").strip() or not (v4_secret or "").strip():
        return None
    effective = (new_url or "").strip() or (v4_url or "").strip()
    if not effective or __auth.same_host(v4_url, effective):
        return None
    return (
        f"The {what} is on a different host from the Kea API: type its password - "
        "the Kea API's password is never sent to a different host."
    )


DDNS_PROVIDERS = ("technitium", "pihole", "adguard", "ssh", "generic", "none")
# the providers whose lookups use `[ddns] api_token` (every other provider - ssh, generic, none - has no credential to keep)
_CREDENTIAL_PROVIDERS = ("technitium", "pihole", "adguard")


def _provider_field(name, provider):
    """The provider's own copy of a DDNS form field: the page renders one block per provider and submits them all, so the plain `name` would be the first block's
    value, not the visible one. A form that sends the plain name alone still works."""
    key = f"{name}_{provider}"
    return request.form.get(key if key in request.form else name, "").strip()


@bp.route("/settings/infrastructure/save-ddns", methods=["POST"])
@login_required
@_admin_required
def save_infra_ddns():
    log_path = request.form.get("log_path", "").strip()
    dns_provider = request.form.get("dns_provider", "none").strip()
    api_url = _provider_field("api_url", dns_provider)
    api_user = _provider_field("api_user", dns_provider)
    api_token = _provider_field("api_token", dns_provider)
    forward_zone = request.form.get("forward_zone", "").strip()
    # (v5.69.0-beta.7, Q176: the card lives on Settings -> Kea -> DDNS, so every way out of this route lands back on that section)
    home = url_for("settings.settings_kea", _anchor="kea-ddns")
    if log_path and not __auth.valid_log_path(log_path):
        flash("Invalid log path — must be an absolute path to a .log file under /var/log.", "error")
        return redirect(home)
    if dns_provider not in DDNS_PROVIDERS:
        flash("Unknown DNS provider.", "error")
        return redirect(home)
    if api_url and not __auth.valid_api_url(api_url):
        flash(
            __auth.userinfo_sentence(api_url) or "The DNS provider's API URL must start with http:// or https://.",
            "error",
        )
        return redirect(home)
    # v5.69.0-beta.2 (Q171): a blank field clears its key - the page used to say "saved" and keep the old value, so a provider's URL, user, zone or log path could never
    # be unset. The token is the one secret here and the page promises "leave blank to keep": it is replaced when typed and removed by its own checkbox - and, since
    # v5.69.0-beta.8 (Q177, DNS-CRED-001), kept ONLY for the provider it was typed for.
    clear_token = request.form.get("clear_api_token", "") == "1"
    seen = {}  # `mutate` returns None: the callback reports through this

    def _apply(cfg):
        if not cfg.has_section("ddns"):
            cfg.add_section("ddns")
        # what the stored provider IS (an upgraded hand-written file with a URL or token and no key reads as technitium - the provider its token was typed for)
        previous = __ddns_writers.effective_provider(cfg)
        # a different PROVIDER, or the same provider at a different ENDPOINT (CRED-002, Q178): a Technitium token typed for server A is not Technitium server B's
        stored_url = cfg.get("ddns", "api_url", fallback="")
        seen["userinfo_dropped"] = bool(__auth.userinfo_sentence(stored_url)) and not __auth.userinfo_sentence(api_url)
        url_changed = bool(stored_url.strip() or api_url) and not __auth.same_endpoint(stored_url, api_url)
        switched = seen["switched"] = previous != dns_provider or url_changed
        seen["provider_changed"] = previous != dns_provider
        had_token = seen["had_token"] = bool(cfg.get("ddns", "api_token", fallback="").strip())
        cfg.set("ddns", "dns_provider", dns_provider)
        for key, value in (
            ("log_path", log_path),
            ("api_url", api_url),
            ("api_user", api_user),
            ("forward_zone", forward_zone),
        ):
            if value:
                cfg.set("ddns", key, value)
            else:
                cfg.remove_option("ddns", key)
        # DNS-CRED-001: a stored token is kept only for the provider it was typed for; a switch, the checkbox, or a provider with no credential removes it
        # (a token posted for a provider that has no credential is not stored either: the page has no such field, so only a crafted request carries one)
        if api_token and dns_provider in _CREDENTIAL_PROVIDERS:
            cfg.set("ddns", "api_token", api_token)
            seen["token"] = "set"
        elif clear_token or switched or dns_provider not in _CREDENTIAL_PROVIDERS:
            cfg.remove_option("ddns", "api_token")
            seen["token"] = "removed" if had_token else "none"
        else:
            seen["token"] = "kept" if had_token else "none"

    __config.app_config.mutate(_apply)
    flash("DDNS settings saved.", "success")
    if seen.get("userinfo_dropped"):
        # (second pass, finding 2) the form is pre-filled WITHOUT the user name or password the stored address carried, so any save removes it; the DNS calls send no separate pair, so a proxy that
        # needed it will refuse them now. Said (names the setting, never the value) - not refused: an address with user-info can no longer be submitted, so refusing would trap every later save.
        flash(
            "The saved DNS provider address carried a user name or password inside the URL, and this save removed it (a URL never carries a password). If the provider sits behind a proxy that asked for it, "
            "DNS lookups will fail until that proxy is set up another way.",
            "warning",
        )
    if seen.get("switched") and dns_provider in _CREDENTIAL_PROVIDERS and not api_token:
        what = "Provider changed to" if seen.get("provider_changed") else "The address of"
        flash(
            f"{what} {dns_provider}: enter its token or password"
            + (" - the saved one was not carried over." if seen.get("had_token") else "."),
            "warning",
        )
    __user.audit(
        "SAVE_INFRA",
        "ddns",
        f"log={log_path} provider={dns_provider} token={seen.get('token', 'none')}"
        + (" url_userinfo_removed=yes" if seen.get("userinfo_dropped") else ""),
    )
    return redirect(home)


@bp.route("/settings/infrastructure/save-ha", methods=["POST"])
@login_required
@_admin_required
def save_ha_settings():
    """Save HA mode for primary Kea server."""
    ha_mode = request.form.get("ha_mode", "").strip()
    server_name = request.form.get("server_name", "").strip()
    if server_name:
        # the same rules as the extra servers' names (the second pass, Q172, finding 7): one short line, and not a name another server already has - the primary renamed to
        # an extra server's name was the duplicate state `Target.key` survives, and it locked the extra-servers form out ("two servers are named ...")
        if "\n" in server_name or "\r" in server_name or len(server_name) > 100:
            flash("Refused: a server name is one line of at most 100 characters.", "error")
            return redirect(url_for("settings.settings_kea"))
        taken = {str(s.get("name", "")).strip().casefold() for s in extensions.KEA_SERVERS if s.get("id") != 1}
        if server_name.casefold() in taken:
            flash(
                f'Refused: another server is already named "{server_name}" - every server needs its own name.', "error"
            )
            return redirect(url_for("settings.settings_kea"))
    items = []
    if ha_mode not in ("hot-standby", "load-balancing", "passive-backup", ""):
        # "saved" was flashed whatever was written (v5.69.0-beta.5, Q174): a mode that is none of the four refuses the whole form, with or without a valid name beside it
        flash("Refused: HA mode must be hot-standby, load-balancing, passive-backup or blank.", "error")
        return redirect(url_for("settings.settings_kea"))
    items.append(("kea", "ha_mode", ha_mode))
    if server_name:
        items.append(("kea", "name", server_name))
    __config.app_config.write_values(items)
    flash("HA settings saved.", "success")
    __user.audit("SAVE_INFRA", "ha_settings", f"mode={ha_mode}")
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/restart", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def restart_jen():
    # v5.67.0-beta.10 (Q122) — jen.services.runtime.restart_service() picks the restart by deployment
    # (systemd or Docker); on a host that is neither, it says so instead of claiming a restart.
    how = __runtime.restart_service()
    if how == "none":
        flash(__runtime.RESTART_BY_HAND, "warning")
    else:
        __user.set_global_setting("restart_pending", "false")
        flash("Jen is restarting...", "success")
    __user.audit("RESTART", "jen", f"Manual restart triggered from Infrastructure settings ({how})")
    return redirect(url_for("settings.settings_system"))


@bp.route("/settings/save-ports", methods=["POST"])
@login_required
@_admin_required
def save_ports():
    ssl_on = __config.ssl_configured()
    try:
        http_port = int(request.form.get("http_port", str(extensions.HTTP_PORT)))
        https_port = int(request.form.get("https_port", str(extensions.HTTPS_PORT)))
        threads = int(request.form.get("threads", str(extensions.WORKER_THREADS)))
    except ValueError:
        flash("Ports and thread count must be valid numbers.", "error")
        return redirect(url_for("settings.settings_system"))

    if not (1024 <= http_port <= 65535):
        flash("HTTP port must be between 1024 and 65535.", "error")
        return redirect(url_for("settings.settings_system"))

    if ssl_on and not (1024 <= https_port <= 65535):
        flash("HTTPS port must be between 1024 and 65535.", "error")
        return redirect(url_for("settings.settings_system"))

    if ssl_on and http_port == https_port:
        flash("HTTP and HTTPS ports must be different.", "error")
        return redirect(url_for("settings.settings_system"))

    if not (1 <= threads <= 64):
        flash("Worker threads must be between 1 and 64.", "error")
        return redirect(url_for("settings.settings_system"))

    items = [("server", "http_port", str(http_port)), ("server", "threads", str(threads))]
    if ssl_on:
        items.append(("server", "https_port", str(https_port)))
    __config.app_config.write_values(items)

    if ssl_on:
        msg = f"Server settings updated — HTTP: {http_port} (redirect), HTTPS: {https_port}, {threads} worker threads. Restarting Jen..."
    else:
        msg = f"Server settings updated — HTTP port {http_port}, {threads} worker threads. Restarting Jen..."

    __user.audit(
        "SAVE_PORTS",
        "settings",
        f"Server: HTTP:{http_port} HTTPS:{https_port} threads:{threads} by {current_user.username}",
    )
    flash(msg, "success")

    # v5.67.0-beta.10 (Q122) — see restart_jen() above.
    if __runtime.restart_service() == "none":
        flash(__runtime.RESTART_BY_HAND, "warning")

    return redirect(url_for("settings.settings_system"))


@bp.route("/settings/save-metrics", methods=["POST"])
@login_required
@_admin_required
def save_metrics_settings():
    """
    v5.3.3 — /metrics started defaulting to closed (401) unless
    metrics_token or metrics_open is set, per the change in
    jen/routes/dashboard.py's prometheus_metrics(). This project has
    deliberately avoided requiring config-file edits for anything a
    settings-page toggle can cover instead — some people genuinely
    don't want to touch a text file over SSH — so this exists
    specifically to make that new requirement configurable from the
    UI, not just documented as something to go edit jen.config for.

    No restart needed, unlike save_ports() above: extensions.cfg is
    read fresh on every single /metrics request
    (extensions.cfg.get("server", "metrics_token", ...)), and
    write_values() reloads AppConfig immediately by default — so this
    takes effect on the very next scrape, not after a restart.
    """
    metrics_token = request.form.get("metrics_token", "").strip()
    metrics_open = request.form.get("metrics_open", "0") == "1"

    if metrics_token and len(metrics_token) < 8:
        flash("Metrics token must be at least 8 characters — or leave it blank.", "error")
        return redirect(url_for("settings.settings_alerts"))

    items = [
        ("server", "metrics_token", metrics_token),
        ("server", "metrics_open", "true" if metrics_open else "false"),
    ]
    __config.app_config.write_values(items)

    __user.audit(
        "SAVE_METRICS_SETTINGS",
        "settings",
        f"metrics_token={'set' if metrics_token else 'empty'} metrics_open={metrics_open} by {current_user.username}",
    )

    if metrics_token:
        flash("Metrics settings saved — /metrics now requires this token.", "success")
    elif metrics_open:
        flash("Metrics settings saved — /metrics is open, no token required.", "success")
    else:
        flash("Metrics settings saved — /metrics will return 401 until a token or open access is set below.", "success")

    return redirect(url_for("settings.settings_alerts"))


@bp.route("/settings/generate-ssh-key", methods=["POST"])
@login_required
@_admin_required
@_recent_auth_required()  # replacing Jen's only SSH key cuts off every Kea host that trusts the old one: a recent password confirmation, like the other key-changing routes (Q174)
def generate_ssh_key():
    # v5.67.0 (Q115) — the setup wizard's helper step offers key generation
    # too, and needs to land back on /setup/helper instead of Settings. A
    # fixed-choice flag, not an arbitrary redirect target, so this can
    # never become an open redirect.
    if request.form.get("next") == "setup":
        redirect_target = url_for("setup.setup_helper")
    else:
        redirect_target = url_for("settings.settings_kea")
    os.makedirs(os.path.dirname(extensions.SSH_KEY_PATH), exist_ok=True)
    # v5.69.0-beta.5 (Q174): the pair is generated in a private scratch directory and installed as a SET (certs.commit_file_set: all-or-nothing, the old pair kept as a copy
    # at <key>.prev). ssh-keygen on a path that already holds a key asks "Overwrite (y/n)?", there is no terminal to answer, and it failed every time a key existed
    # ("regenerate" never worked); and it chowned the result to a hard-coded `www-data` (the service user is whoever Jen runs as, and it already owns what it creates).
    # The comment names this host, not a placeholder.
    import shutil
    import socket
    import tempfile

    from jen.services import certs as __certs

    live, live_pub = extensions.SSH_KEY_PATH, extensions.SSH_KEY_PATH + ".pub"
    try:
        scratch = tempfile.mkdtemp(
            prefix=".keygen-", dir=os.path.dirname(live)
        )  # 0700: the private half exists only here until it is installed
        try:
            made = os.path.join(scratch, "id")
            subprocess.run(
                [
                    "ssh-keygen",
                    "-t",
                    "rsa",
                    "-b",
                    "4096",
                    "-f",
                    made,
                    "-N",
                    "",
                    "-C",
                    f"jen@{socket.gethostname()}",
                ],
                capture_output=True,
                check=True,
            )
            with open(made, "rb") as f:
                private_bytes = f.read()
            with open(made + ".pub", "rb") as f:
                public_bytes = f.read()
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        had_old = os.path.exists(live)
        __certs.commit_file_set([(live, private_bytes, 0o600), (live_pub, public_bytes, 0o644)])
        pub_key = public_bytes.decode("utf-8", "replace").strip()
        previous_note = (
            f" The previous key is kept as {live}.prev - delete it once every Kea server has the new one."
            if had_old
            else ""
        )
        flash(
            f"SSH key generated. Add this public key to the Kea server's authorized_keys:\n{pub_key}{previous_note}",
            "success",
        )
        __user.audit("GENERATE_SSH_KEY", "settings", "SSH key pair generated")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate SSH key: {e.stderr.decode() if e.stderr else e}")
        flash("Failed to generate SSH key. Check server logs for details.", "error")
    except Exception as e:
        logger.error(f"Error generating SSH key: {e}")
        flash("Error generating SSH key. Check server logs for details.", "error")
    return redirect(redirect_target)
