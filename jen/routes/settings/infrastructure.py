"""
jen/routes/settings/infrastructure.py
───────────────────────────────────
Kea / database / SSH / DDNS / HA / ports / metrics settings.
"""

import ipaddress
import logging
import os
import re
import subprocess
import threading
import time
from urllib.parse import urlparse

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.config as __config
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.capabilities as __caps
import jen.services.kea as __kea
import jen.services.kea6 as __kea6
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
        "ssh_host",
        "ssh_user",
        "kea_conf",
    }
)


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
                "ssh_user": s.get("ssh_user") or extensions.KEA_SSH_USER,
                "helper_version": st.get("version"),  # int, None, or missing key
                "helper_label": kea_host.helper_version_label(st.get("version"), kea_host.JEN_HELPER_SHIPPED_VERSION),
                "helper_want": kea_host.JEN_HELPER_WANT_VERSION,
                # v5.29.1 — the Update helper button is offered below this
                # (the shipped file's version), not just below WANT.
                "helper_shipped": kea_host.JEN_HELPER_SHIPPED_VERSION,
                "helper_known": bool(st),
                "helper_checked": st.get("checked", ""),
                "legacy_grant": st.get("legacy_grant"),  # True, False, or None (never checked)
                # v5.29.0 (Q29) — the https option of "Set up direct socket"
                # needs the v4 helper (install-tls); same fail-closed rule
                # as kea_host.tls_supported, computed from this one read.
                "tls_supported": __caps.helper_caps(st.get("version"))["tls"],
            }
        )
    return rows


def _kea_ca_summary() -> dict:
    """v5.29.0 (Q29) — what the Control Plane card says about the
    Jen-managed Kea CA: present or not, its subject and days left, whether
    Jen's client certificate is signed by it, and every server certificate
    Jen issued (from the kea-servers/ copies — never SSHes)."""
    from jen.services import kea_tls

    present = kea_tls.ca_present()
    ca_crt, _ca_key = kea_tls.ca_paths()
    out = {
        "present": present,
        "ca_path": ca_crt,
        "subject": kea_tls._cn(ca_crt) if present else "",
        "days_left": kea_tls.days_left(ca_crt) if present else None,
        "client_ok": kea_tls.client_cert_ok() if present else False,
        "issued": [],
        # a [kea] api_ca that isn't Jen's = the operator brought their own CA
        "external_ca": bool(extensions.KEA_API_CA) and ca_crt != extensions.KEA_API_CA,
    }
    if present:
        for copy in kea_tls.issued_server_copies():
            sid = int(copy["server_id"]) if str(copy["server_id"]).isdigit() else None
            server = _server_by_id(sid) if sid is not None else None
            name = (server or {}).get("name") or f"server {copy['server_id']}"
            out["issued"].append((name, copy["service"], copy["days_left"]))
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
            return bool(u) and not __auth.valid_api_url(u, require_port=True)

        if __kea6.is_ipv6_enabled() and _needs_port(extensions.cfg.get("kea6", "api_url", fallback="")):
            direct_port_warnings.append(f"[kea6] api_url ({extensions.cfg.get('kea6', 'api_url')})")
        for srv in extensions.KEA_SERVERS:
            if _needs_port(srv.get("api_url", "")):
                direct_port_warnings.append(f"{srv.get('name', 'Kea Server')} api_url ({srv['api_url']})")
            if _needs_port(srv.get("api6_url", "")):
                direct_port_warnings.append(f"{srv.get('name', 'Kea Server')} api6_url ({srv['api6_url']})")

    infra = {
        "kea_api_url": extensions.cfg.get("kea", "api_url", fallback=""),
        "kea_api_user": extensions.cfg.get("kea", "api_user", fallback=""),
        "kea_api_pass": extensions.cfg.get("kea", "api_pass", fallback=""),
        # v5.10.0 — Kea 3 control plane
        "kea_connection_mode": extensions.cfg.get("kea", "connection_mode", fallback="ca"),
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
        "ddns_log": extensions.cfg.get("ddns", "log_path", fallback=""),
        "ddns_url": extensions.cfg.get("ddns", "api_url", fallback=""),
        "ddns_user": extensions.cfg.get("ddns", "api_user", fallback=""),
        "ddns_zone": extensions.cfg.get("ddns", "forward_zone", fallback=""),
        "dns_provider": extensions.cfg.get("ddns", "dns_provider", fallback="technitium"),
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
    direct_socket_supported = _caps.direct_socket
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
    )


@bp.route("/settings/infrastructure/save-kea", methods=["POST"])
@login_required
@_admin_required
def save_infra_kea():
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
    if api_ca and not os.path.isfile(api_ca):
        flash(f"CA bundle path not found on the Jen host: {api_ca}", "error")
        return redirect(url_for("settings.settings_kea"))
    if bool(api_client_cert) != bool(api_client_key):
        flash("Set both the client certificate and key, or neither.", "error")
        return redirect(url_for("settings.settings_kea"))
    for label, path in (("client certificate", api_client_cert), ("client key", api_client_key)):
        if path and not os.path.isfile(path):
            flash(f"Client {label} not found on the Jen host: {path}", "error")
            return redirect(url_for("settings.settings_kea"))
    # v5.10.3 — isfile() is a stat(); it says nothing about whether the pair
    # actually loads, matches, or is readable by www-data. Check for real
    # before writing, so a bad pair can't turn every Kea call into an
    # opaque SSLError.
    tls_err = __kea.validate_client_tls_material(api_client_cert, api_client_key, api_ca)
    if tls_err:
        flash(f"TLS settings not saved: {tls_err}.", "error")
        return redirect(url_for("settings.settings_kea"))

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
    __config.app_config.write_values(items)
    __user.set_global_setting("restart_pending", "true")
    flash("Kea API settings saved. Restart Jen to apply.", "success")
    __user.audit(
        "SAVE_INFRA",
        "kea_api",
        f"url={api_url} user={api_user} mode={connection_mode} client_cert={'set' if api_client_cert else 'none'}",
    )
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/save-kea-db", methods=["POST"])
@login_required
@_admin_required
def save_infra_kea_db():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "").strip()
    database = request.form.get("database", "").strip()
    if not host or not user or not database:
        flash("Host, username, and database name are required.", "error")
        return redirect(url_for("database.database", tab="connections"))
    items = [("kea_db", "host", host), ("kea_db", "user", user), ("kea_db", "database", database)]
    if password:
        items.append(("kea_db", "password", password))
    __config.app_config.write_values(items)
    __user.set_global_setting("restart_pending", "true")
    flash("Kea database settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "kea_db", f"host={host}")
    return redirect(url_for("database.database", tab="connections"))


@bp.route("/settings/infrastructure/save-kea6", methods=["POST"])
@login_required
@_admin_required
def save_infra_kea6():
    """
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
    db_host = request.form.get("db_host", "").strip()
    db_user = request.form.get("db_user", "").strip()
    db_pass = request.form.get("db_pass", "").strip()
    inherit_db_pass = request.form.get("inherit_db_pass", "") == "1"
    db_name = request.form.get("db_name", "").strip()

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
        ("kea6", "api_pass", api_pass, inherit_api_pass),
        ("kea6_db", "password", db_pass, inherit_db_pass),
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
        for section, opt, val, inherit in pw_fields:
            has = cfg.has_section(section) and cfg.has_option(section, opt)
            if inherit:
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

    __config.app_config.mutate(_apply)

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
@_admin_required
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
        if inherit_api_pass:
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

    __config.app_config.mutate(_apply)

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
    config once the socket answers)."""
    payload = {"command": "version-get"}
    if not omit_service:
        payload["service"] = [service]
    try:
        resp = __kea.http.post(
            url,
            json=payload,
            auth=(user, pwd),
            timeout=8,
            verify=verify if verify is not None else (extensions.KEA_API_CA or extensions.KEA_API_TLS_VERIFY),
            cert=cert if cert is not None else __kea._tls_client_cert(),
        )
        resp.raise_for_status()
        data = resp.json()
        d = data[0] if isinstance(data, list) else data
        if d.get("result") != 0:
            return "", d.get("text", "Kea returned an error")
        return (d.get("arguments", {}).get("extended", "") or d.get("text", "")).strip(), ""
    except Exception as e:
        # any transport failure is just "this endpoint didn't answer"
        return "", str(e)


# v5.29.3 — a daemon that was just restarted opens its HTTP listener LAST
# (after the config is parsed and the lease backend is up — seconds, with
# MySQL), so a probe fired straight after `systemctl restart` gets
# "connection refused" and the maintainer's first https setup reported a
# failure for a socket that was fine two seconds later.
_PROBE_ATTEMPTS = 8
_PROBE_DELAY_S = 2.0


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
    return "", f"{err} — after {_PROBE_ATTEMPTS} attempts over {int(_PROBE_ATTEMPTS * _PROBE_DELAY_S)} s"


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
    succeeded. `verify`/`cert` as in _probe_once (v5.29.0)."""
    try:
        resp = __kea.http.post(
            url,
            json={"command": "config-get"},
            auth=(user, pwd),
            timeout=8,
            verify=verify if verify is not None else (extensions.KEA_API_CA or extensions.KEA_API_TLS_VERIFY),
            cert=cert if cert is not None else __kea._tls_client_cert(),
        )
        resp.raise_for_status()
        data = resp.json()
        d = data[0] if isinstance(data, list) else data
        if d.get("result") != 0:
            return None
        return next(iter(d.get("arguments") or {}), None)
    except Exception:
        return None


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
        if not __auth.valid_api_url(candidate, require_port=True):
            return jsonify(
                {
                    "ok": False,
                    "error": "The candidate URL must be a valid http(s):// URL with an explicit port "
                    "(e.g. https://kea:8004).",
                }
            ), 400
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
        if __caps.ships_control_agent(v):
            # Maintainer decision (2026-09-13, Q26 Q1) — Kea still
            # supports the Control Agent at this version, so this is a
            # config gap to fix, not a dead end: stay on ca mode until
            # the daemon sockets exist.
            # v5.29.0 (Q28/Q29) — the maintainer hit this on 2026-09-13
            # and reported "it's not apparent where this goes": name
            # the file and key, and point at the button that now does
            # it (Set up direct socket, on this page).
            rec = (
                f"{answered_url} is the Control Agent, not kea-{service}'s own control socket — Kea {version} "
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
                f"{answered_url} is the Control Agent, not kea-{service}'s own control socket — direct mode "
                f"needs the daemon's http socket (conventionally :{daemon_port}). Either switch back to "
                f'Control Agent mode, or give kea-{service} its own http control socket: "Set up direct '
                f"socket\" on this page adds it to /etc/kea/kea-{_CONF_STEM[service]}.conf's control-sockets "
                f"list, restarts kea-{service} and points Jen at it once it answers — or add it by hand per "
                'the admin guide\'s "Direct control sockets" section.',
                "bad",
            )
    elif candidate:
        rec = (
            f"Kea {version} answered on {answered_url} — set this as the API URL and switch to Direct mode.",
            "ok",
        )
    elif answered_mode == "direct":
        rec = (
            f"Kea {version} answered on its direct control socket — this is the mode to use for Kea 3.2+.",
            "ok",
        )
    elif not __caps.supports_direct_socket(v):
        rec = (
            f"Kea {version} predates per-daemon control sockets (2.7.2), so the Control Agent is the only "
            "option here. Plan a Kea upgrade before moving to 3.2.",
            "warn",
        )
    elif __caps.ships_control_agent(v):
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
                    f' The https socket Jen set up on {jen_socket["url"]} answers as kea-{service} — run "Set up '
                    'direct socket" again and Jen switches over.'
                )
            else:
                extra = (
                    f" The https socket Jen set up on {jen_socket['url']} does not answer ({jen_socket['error']}) — "
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


def _daemon_creds(server: dict, service: str) -> tuple[str, str]:
    """The basic-auth pair Jen already presents to this daemon on this
    server — the form's defaults, so an operator who keeps one API user
    per host types nothing. Falls back to the server's v4 pair when the
    per-daemon endpoint is unresolvable (direct mode, no v6/D2 URL yet —
    exactly the state this flow exists to fix)."""
    endpoint = __kea._endpoint_for(server, service)
    if isinstance(endpoint, tuple):
        _url, user, pwd = endpoint
        if user or pwd:
            return user, pwd
    return server.get("api_user", ""), server.get("api_pass", "")


def _write_direct_socket_config(
    server: dict, service: str, url: str, user: str, password: str, tls: bool = False
) -> str:
    """Point Jen at the daemon socket that just answered. dhcp4 also
    flips `[kea] connection_mode` to direct (the mode is global — see
    the flash the caller adds when other servers aren't there yet);
    dhcp6/D2 only write their own per-daemon URL, since a dhcp4 socket
    is what the mode switch actually needs. `tls` (https via Jen's CA)
    also writes the GLOBAL trust anchor + client certificate — one CA,
    one Jen identity, for every server — and pins `api_tls_verify` on
    (this flow never sets it off). Returns a short phrase for the flash
    saying what was written."""
    sid = server.get("id")
    primary = sid == 1
    changed: list[str] = []

    def _apply(cfg):
        if tls:
            from jen.services import kea_tls as __tls

            ca_crt, _ca_key = __tls.ca_paths()
            client_pem, client_key = __tls.client_paths()
            if not cfg.has_section("kea"):
                cfg.add_section("kea")
            if cfg.get("kea", "api_ca", fallback="") != ca_crt:
                cfg.set("kea", "api_ca", ca_crt)
                cfg.set("kea", "api_client_cert", client_pem)
                cfg.set("kea", "api_client_key", client_key)
                changed.append("[kea] api_ca/api_client_cert/api_client_key (Jen's CA and client certificate)")
            cfg.set("kea", "api_tls_verify", "true")
        if primary:
            sec, url_key, user_key, pass_key = {
                "dhcp4": ("kea", "api_url", "api_user", "api_pass"),
                "dhcp6": ("kea6", "api_url", "api_user", "api_pass"),
                "d2": ("d2", "api_url", "api_user", "api_pass"),
            }[service]
        else:
            sec = f"kea_server_{sid}"
            url_key, user_key, pass_key = {
                "dhcp4": ("api_url", "api_user", "api_pass"),
                "dhcp6": ("api6_url", "api6_user", "api6_pass"),
                "d2": ("api_d2_url", "api_d2_user", "api_d2_pass"),
            }[service]
        if not cfg.has_section(sec):
            cfg.add_section(sec)
        old_url = cfg.get(sec, url_key, fallback="")
        if service == "dhcp4" and old_url and old_url != url and not cfg.has_option(sec, _PREV_URL_KEY):
            # First time this server's v4 URL moves off the Control
            # Agent: remember where it was, for "Switch back".
            cfg.set(sec, _PREV_URL_KEY, old_url)
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
            if service != "dhcp4":
                changed.append(f"[{sec}] {user_key}/{pass_key}")
        elif service != "dhcp4":
            for k in (user_key, pass_key):
                if cfg.has_option(sec, k):
                    cfg.remove_option(sec, k)
        if service == "dhcp4" and cfg.get("kea", "connection_mode", fallback="ca") != "direct":
            if not cfg.has_section("kea"):
                cfg.add_section("kea")
            cfg.set("kea", "connection_mode", "direct")
            changed.append("Jen switched to direct mode")

    __config.app_config.mutate(_apply)
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
            names.append(f"{s.get('name', 'Kea Server')} ({s['api_url']})")
    return names


@bp.route("/settings/infrastructure/direct-socket/<int:server_id>/<service>", methods=["POST"])
@login_required
@_superadmin_required
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

    A failed probe leaves the socket in the Kea config (it's valid and
    harmless — the daemon is listening on it) and Jen's settings
    untouched, with a flash naming exactly what didn't answer.
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
            f"{'SSH to the Kea host' if server_id == 1 else 'Servers & HA'} first.",
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
    default_user, default_pass = _daemon_creds(server, service)
    user = request.form.get("user", "").strip() or default_user
    password = request.form.get("password", "").strip() or default_pass
    if not user or not password:
        flash(
            f"The socket needs a basic-auth username and password — Jen has none on record for {daemon} on "
            f"{name}, so fill both in.",
            "error",
        )
        return back
    new_url = _socket_url(scheme, address, port)

    # The daemon socket must not be the Control Agent's own address —
    # that's the exact 2026-09-13 confusion, and Kea would fail to bind
    # a port the agent already holds (a restart failure, not a clear
    # message).
    if __caps.is_ca():
        ca = urlparse(server.get("api_url", ""))
        if ca.hostname == address and ca.port == port:
            flash(
                f"{new_url} is the Control Agent's own address on {name} — {daemon}'s socket needs its own port "
                f"(conventionally :{DIRECT_SOCKET_DEFAULT_PORTS[service]}).",
                "error",
            )
            return back

    # Kea version: per-daemon control sockets exist from 2.7.2. Only
    # blocking when the CURRENT endpoint actually answers — a Kea 3.2 box
    # with no Control Agent answers nothing in ca mode, and the config
    # test (-t) below rejects an unknown `control-sockets` key on an old
    # Kea anyway.
    vr = __kea.kea_command("version-get", service, server=server)
    if vr.get("result") == 0:
        ver_text = (vr.get("arguments", {}).get("extended", "") or vr.get("text", "")).splitlines()[0].strip()
        v = __kea.parse_kea_version(ver_text)
        if v and not __caps.supports_direct_socket(v):
            flash(
                f"Kea {'.'.join(str(n) for n in v)} on {name} predates per-daemon control sockets (2.7.2), so "
                "the Control Agent is the only option there. Plan a Kea upgrade first — nothing was changed.",
                "error",
            )
            return back

    # ── https (v5.29.0, Q29 C3): Jen's private CA issues the material and
    # the helper's install-tls op lands it on the host BEFORE the config
    # references it; the apply then carries the three paths as tls_paths.
    tls_paths = ()
    probe_verify, probe_cert = None, None
    if scheme == "https":
        from jen.services import kea_host as __host
        from jen.services import kea_tls as __tls

        if not __caps.for_server(server_id, probe_kea=False).tls:
            flash(f"{name}: {__host._TLS_NEEDS_HELPER}", "error")
            return back
        jen_ca, _jen_ca_key = __tls.ca_paths()
        jen_client_cert, jen_client_key = __tls.client_paths()
        if extensions.KEA_API_CA and jen_ca != extensions.KEA_API_CA:
            flash(
                f"The CA bundle above points at {extensions.KEA_API_CA}, not Jen's own CA — Jen manages one trust "
                "anchor for every Kea server. Clear the CA bundle field (and the client certificate fields) to use "
                "Jen's CA, or set up https by hand with your own CA per the admin guide.",
                "error",
            )
            return back
        if extensions.KEA_API_CLIENT_CERT and jen_client_cert != extensions.KEA_API_CLIENT_CERT:
            flash(
                f"The client certificate above is {extensions.KEA_API_CLIENT_CERT}, not the one Jen's CA issues — "
                "clear the client certificate fields to use Jen's CA, or set up https by hand.",
                "error",
            )
            return back
        try:
            __tls.ensure_ca()
            __tls.issue_client_cert()
            files = __tls.issue_server_cert(server, service, address)
        except Exception as e:
            logger.error(f"kea_tls: could not issue material for {name}/{service}: {e}")
            flash("Jen could not issue the certificates — see the server log. Nothing was changed.", "error")
            return back
        tls_err = __kea.validate_client_tls_material(jen_client_cert, jen_client_key, jen_ca)
        if tls_err:
            flash(f"Jen's own client certificate is unusable ({tls_err}) — nothing was pushed to {name}.", "error")
            return back
        pushed = __host.install_tls(server, service, files)
        if not pushed.get("ok"):
            flash(
                f"{name}: {pushed.get('detail', 'the helper refused the TLS material')} — nothing was changed.",
                "error",
            )
            return back
        remote = __tls.remote_tls_paths(service)
        tls_paths = [(remote["trust_anchor"], "file"), (remote["cert_file"], "file"), (remote["key_file"], "file")]
        probe_verify, probe_cert = jen_ca, (jen_client_cert, jen_client_key)
        entry = build_control_socket(scheme, address, port, user, password, tls=remote)
    else:
        entry = build_control_socket(scheme, address, port, user, password)

    result = __changeset.apply_change(
        service,
        lambda cfg: __edit.set_control_socket(cfg, service, entry),
        f"added an {scheme} control socket on {address}:{port}",
        servers=[server],
        restart=True,
        code_messages={
            "unsupported": f"{conf} has no {_DAEMON_KEY[service]} block (or a control-sockets that isn't the "
            "daemon's list form) — is this the right file? Nothing was changed.",
            "nochange": f"{daemon} already has exactly this socket in {conf} — checking that it answers",
        },
        daemon_label=daemon,
        tls_paths=tls_paths,
    )
    if result.status == "noservers":
        flash(f"{name} has no SSH host configured.", "error")
        return back
    for style, text in result.lines:
        flash(text, style)
    if result.status in ("aborted", "rollback_failed"):
        flash("Jen's own settings were not changed.", "info")
        return back
    mode_now = "Control Agent" if __caps.is_ca() else "direct"
    if result.status == "restart_failed":
        flash(
            f"The socket is in {conf} on {name} but {daemon} did NOT restart, so it isn't listening yet. "
            f"Restart it by hand, then Probe {new_url} (candidate URL, above) and run this again — Jen stays "
            f"in {mode_now} mode and none of its settings were changed.",
            "warning",
        )
        return back

    version_text, probe_err = _probe_after_restart(
        new_url, user, password, service, verify=probe_verify, cert=probe_cert
    )
    identified = (
        _identify_daemon(new_url, user, password, service, verify=probe_verify, cert=probe_cert)
        if version_text
        else None
    )
    if not version_text or identified != _DAEMON_KEY[service]:
        if not version_text:
            reason = f"didn't answer a version-get ({probe_err})"
        else:
            who = "the Control Agent" if identified == "Control-agent" else (identified or "an unknown daemon")
            reason = f"answered as {who}, not {daemon}"
        msg = (
            f"{daemon} on {name} restarted with the new socket, but {new_url} {reason} from the Jen host — "
            f"Jen stays in {mode_now} mode and none of its settings were changed. Check that {address}:{port} "
            f"is reachable from here (firewall? management VLAN?) and that {daemon}'s log shows it listening, "
            f"then run this again (the socket is already in {conf}, so it will just re-probe)."
        )
        flash(msg, "error")
        __user.audit("SETUP_DIRECT_SOCKET", "kea_api", f"server={name} service={service} url={new_url} probe=failed")
        return back

    was_ca = __caps.is_ca()
    written = _write_direct_socket_config(server, service, new_url, user, password, tls=(scheme == "https"))
    __user.set_global_setting("restart_pending", "true")
    flash(f"{daemon} on {name} answers directly at {new_url} — written: {written}.", "success")
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
    __user.audit("SETUP_DIRECT_SOCKET", "kea_api", f"server={name} service={service} url={new_url} user={user}")
    return back


def _service_url(server: dict, service: str) -> str:
    """The URL Jen dials for `service` on `server` (its per-daemon
    override, else the v4 URL in ca mode), or "" when it has none."""
    ep = __kea._endpoint_for(server, service)
    return ep[0] if isinstance(ep, tuple) else ""


@bp.route("/settings/infrastructure/kea-ca/rotate", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
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
    from jen.services import kea_host as __host
    from jen.services import kea_tls as __tls

    back = redirect(url_for("settings.settings_kea"))
    if not __tls.ca_present():
        flash(
            "No Jen-managed Kea CA exists yet — Jen creates it the first time you set up an https socket. "
            "Nothing to rotate.",
            "info",
        )
        return back

    targets = []  # (server, service, bind address)
    blocked = []
    for copy in __tls.issued_server_copies():
        sid = int(copy["server_id"]) if str(copy["server_id"]).isdigit() else None
        server = _server_by_id(sid) if sid is not None else None
        if server is None:
            continue  # a server since removed from Jen's config — its copy is just stale
        label = f"{server.get('name') or f'Kea Server {sid}'} kea-{copy['service']}"
        url = _service_url(server, copy["service"])
        if not url.startswith("https://"):
            blocked.append(
                f"{label} (its URL is {url or 'unset'}, not an https socket — remove the stale copy at {copy['path']} if it's no longer on Jen's CA)"
            )
            continue
        if not server.get("ssh_host"):
            blocked.append(f"{label} (no SSH host)")
            continue
        if not __caps.for_server(sid, probe_kea=False).tls:
            blocked.append(f"{label} (helper below v4)")
            continue
        targets.append((server, copy["service"], urlparse(url).hostname or ""))
    if blocked:
        flash(
            "Rotate refused — every server on Jen's CA must be reachable for a new certificate, or it would be cut "
            "off by the new CA: " + "; ".join(blocked),
            "error",
        )
        return back

    staged = __tls.stage_rotation()
    done: list[tuple[dict, str, str]] = []
    failure = ""
    for server, service, bind in targets:
        sname = server.get("name") or f"Kea Server {server.get('id')}"
        daemon = _DAEMON_NAME[service]
        try:
            files = __tls.issue_server_cert(server, service, bind, ca=(staged["ca_cert"], staged["ca_key"]))
        except Exception as e:
            logger.error(f"kea_tls: staged issue failed for {sname}/{service}: {e}")
            failure = f"{sname} {daemon}: could not issue its certificate (see the server log)"
            break
        pushed = __host.install_tls(server, service, files)
        if not pushed.get("ok"):
            failure = f"{sname} {daemon}: {pushed.get('detail', 'the helper refused the TLS material')}"
            break
        restarted = __host.service_action(server, service, "restart")
        if not restarted.get("ok"):
            failure = f"{sname}: {daemon} did NOT restart ({restarted.get('detail')})"
            break
        url = _service_url(server, service)
        user, pwd = _daemon_creds(server, service)
        version_text, probe_err = _probe_after_restart(
            url, user, pwd, service, verify=staged["ca_cert"], cert=(staged["client_cert"], staged["client_key"])
        )
        if not version_text:
            failure = f"{sname} {daemon}: {url} did not answer with the new certificates ({probe_err})"
            break
        done.append((server, service, bind))

    if failure:
        rolled, rollback_failed = [], []
        for server, service, bind in done:
            sname = server.get("name") or f"Kea Server {server.get('id')}"
            label = f"{sname} {_DAEMON_NAME[service]}"
            try:
                files = __tls.issue_server_cert(server, service, bind)  # the OLD CA — still live
                r1 = __host.install_tls(server, service, files)
                r2 = __host.service_action(server, service, "restart") if r1.get("ok") else {"ok": False}
            except Exception as e:
                logger.error(f"kea_tls: rollback issue failed for {label}: {e}")
                r1, r2 = {"ok": False}, {"ok": False}
            (rolled if r1.get("ok") and r2.get("ok") else rollback_failed).append(label)
        __tls.discard_rotation(staged)
        msg = f"Rotate stopped at {failure}. Jen still trusts the previous CA; nothing in Jen's settings changed."
        if rolled:
            msg += f" Rolled back to the previous CA: {', '.join(rolled)}."
        flash(msg, "error")
        if rollback_failed:
            flash(
                f"ROLLBACK FAILED on {', '.join(rollback_failed)} — they hold certificates from a CA Jen never "
                "adopted and won't answer Jen until fixed: run Set up direct socket (https) again for each.",
                "error",
            )
        __user.audit("ROTATE_KEA_CA", "kea_api", f"failed: {failure}; rolled_back={len(rolled)}")
        return back

    __tls.commit_rotation(staged)
    ca_crt, _k = __tls.ca_paths()
    client_pem, client_key = __tls.client_paths()
    if targets:
        __config.app_config.write_values(
            [
                ("kea", "api_ca", ca_crt),
                ("kea", "api_client_cert", client_pem),
                ("kea", "api_client_key", client_key),
                ("kea", "api_tls_verify", "true"),
            ]
        )
    names = ", ".join(
        f"{s.get('name') or 'Kea Server ' + str(s.get('id'))} {_DAEMON_NAME[svc]}" for s, svc, _b in targets
    )
    flash(
        "Kea CA rotated — new CA and client certificate issued"
        + (f"; new server certificates pushed to {names}, each daemon restarted and answering." if targets else ".")
        + " The previous CA is kept beside the new one as kea-ca.crt.prev.",
        "success",
    )
    __user.audit("ROTATE_KEA_CA", "kea_api", f"ok: {len(targets)} server certificate(s) re-issued")
    return back


@bp.route("/settings/infrastructure/direct-socket/<int:server_id>/<service>/remove", methods=["POST"])
@login_required
@_superadmin_required
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

    result = __changeset.apply_change(
        service,
        lambda cfg: __edit.remove_control_socket(cfg, service),
        f"removed the {daemon} http control socket",
        servers=[server],
        restart=True,
        code_messages={
            "unsupported": f"{conf} has no {_DAEMON_KEY[service]} block — is this the right file? Nothing was changed.",
            "nochange": f"{conf} has no http/https control socket to remove — only Jen's own settings change",
        },
        daemon_label=daemon,
    )
    if result.status == "noservers":
        flash(f"{name} has no SSH host configured.", "error")
        return back
    for style, text in result.lines:
        flash(text, style)
    if result.status in ("aborted", "rollback_failed"):
        flash("Jen's own settings were not changed.", "info")
        return back

    sid = server.get("id")
    changed: list[str] = []
    # Computed once, outside the mutate: does any OTHER server still
    # answer as kea-dhcp4 on its v4 URL? Then the (global) mode stays
    # direct for their sake.
    keep_direct = False
    others_still_direct: list[str] = []
    if service == "dhcp4":
        for s in extensions.KEA_SERVERS:
            if s.get("id") == sid or not s.get("api_url"):
                continue
            if _identify_daemon(s["api_url"], s.get("api_user", ""), s.get("api_pass", ""), "dhcp4") == "Dhcp4":
                others_still_direct.append(s.get("name", "Kea Server"))
        keep_direct = bool(others_still_direct)

    def _apply(cfg):
        if sid == 1:
            sec, url_key = {"dhcp4": ("kea", "api_url"), "dhcp6": ("kea6", "api_url"), "d2": ("d2", "api_url")}[service]
        else:
            sec = f"kea_server_{sid}"
            url_key = {"dhcp4": "api_url", "dhcp6": "api6_url", "d2": "api_d2_url"}[service]
        if service == "dhcp4":
            prev = cfg.get(sec, _PREV_URL_KEY, fallback="") if cfg.has_section(sec) else ""
            if prev:
                cfg.set(sec, url_key, prev)
                cfg.remove_option(sec, _PREV_URL_KEY)
                changed.append(f"[{sec}] {url_key} restored to {prev}")
            else:
                changed.append(f"[{sec}] {url_key} left as-is (no Control Agent URL on record — set it above)")
            if not keep_direct and cfg.get("kea", "connection_mode", fallback="ca") != "ca":
                cfg.set("kea", "connection_mode", "ca")
                changed.append("Jen switched back to Control Agent mode")
        else:
            if cfg.has_section(sec) and cfg.has_option(sec, url_key):
                cfg.remove_option(sec, url_key)
                changed.append(f"[{sec}] {url_key} cleared — inherits the v4 URL in Control Agent mode")
            if sid == 1 and cfg.has_section(sec) and not cfg.options(sec):
                cfg.remove_section(sec)

    __config.app_config.mutate(_apply)
    __user.set_global_setting("restart_pending", "true")
    flash(f"{daemon} on {name}: {'; '.join(changed)}.", "success")
    if keep_direct:
        flash(
            f"Jen stays in direct mode — {', '.join(others_still_direct)} still answer on their own kea-dhcp4 "
            f"sockets. {name} will show the Control Agent error until you switch those back too, or set its "
            "socket up again.",
            "warning",
        )
    __user.audit("REMOVE_DIRECT_SOCKET", "kea_api", f"server={name} service={service}")
    return back


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
@_admin_required
def save_infra_jen_db():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "").strip()
    database = request.form.get("database", "").strip()
    if not host or not user or not database:
        flash("Host, username, and database name are required.", "error")
        return redirect(url_for("database.database", tab="connections"))
    items = [("jen_db", "host", host), ("jen_db", "user", user), ("jen_db", "database", database)]
    if password:
        items.append(("jen_db", "password", password))
    __config.app_config.write_values(items)
    __user.set_global_setting("restart_pending", "true")
    flash("Jen database settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "jen_db", f"host={host}")
    return redirect(url_for("database.database", tab="connections"))


@bp.route("/settings/infrastructure/save-ssh", methods=["POST"])
@login_required
@_admin_required
def save_infra_ssh():
    host = request.form.get("host", "").strip()
    user = request.form.get("user", "").strip()
    kea_conf = request.form.get("kea_conf", "").strip()
    if host and not __auth.valid_ssh_target(host):
        flash("Invalid SSH host — must be a valid hostname or IP address.", "error")
        return redirect(url_for("settings.settings_kea"))
    if user and not __auth.valid_unix_username(user):
        flash("Invalid SSH user — must be a valid unix username.", "error")
        return redirect(url_for("settings.settings_kea"))
    if kea_conf and not __auth.valid_remote_path(kea_conf):
        flash("Invalid Kea config path — must be an absolute path with no special characters.", "error")
        return redirect(url_for("settings.settings_kea"))
    items = [("kea_ssh", "host", host), ("kea_ssh", "user", user)]
    if kea_conf:
        items.append(("kea_ssh", "kea_conf", kea_conf))
    __config.app_config.write_values(items)
    __user.set_global_setting("restart_pending", "true")
    flash("SSH settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "ssh", f"host={host} user={user}")
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/save-extra-servers", methods=["POST"])
@login_required
@_admin_required
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
    _require_port = __caps.is_direct()
    for u in api_urls:
        if u.strip() and not __auth.valid_api_url(u.strip(), require_port=_require_port):
            flash(f"Invalid API URL: {u.strip()}", "error")
            return redirect(url_for("settings.settings_kea"))
    for u in api6_urls:
        if u.strip() and not __auth.valid_api_url(u.strip(), require_port=_require_port):
            flash(f"Invalid IPv6 API URL: {u.strip()} (direct mode needs an explicit port)", "error")
            return redirect(url_for("settings.settings_kea"))

    def _rewrite_extra_servers(cfg):
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

        for (
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
        ) in zip(
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

            sec = f"kea_server_{out}"
            cfg.add_section(sec)
            cfg.set(sec, "name", name.strip() or f"Kea Server {out}")
            cfg.set(sec, "role", role.strip() or "standby")
            cfg.set(sec, "api_url", api_url.strip())
            cfg.set(sec, "api_user", api_user.strip())
            if api_pass.strip():
                cfg.set(sec, "api_pass", api_pass.strip())
            else:
                # Blank ⇒ keep THIS server's existing password (by id), or
                # fall back to the primary's for a genuinely new row.
                cfg.set(sec, "api_pass", prev.get("api_pass") or extensions.KEA_API_PASS)
            # v5.10.2 — per-server v6 endpoint. Blank managed field ⇒ key
            # absent (that IS the clear). api6_pass blank ⇒ preserve by id.
            if api6_url.strip():
                cfg.set(sec, "api6_url", api6_url.strip())
            if api6_user.strip():
                cfg.set(sec, "api6_user", api6_user.strip())
            if api6_pass.strip():
                cfg.set(sec, "api6_pass", api6_pass.strip())
            elif prev.get("api6_pass"):
                cfg.set(sec, "api6_pass", prev["api6_pass"])
            cfg.set(sec, "ssh_host", ssh_host.strip())
            cfg.set(sec, "ssh_user", ssh_user.strip())
            cfg.set(sec, "kea_conf", kea_conf.strip() or "/etc/kea/kea-dhcp4.conf")
            for k, v in prev.items():
                if k not in _EXTRA_SERVER_FORM_KEYS:
                    cfg.set(sec, k, v)

    try:
        __config.app_config.mutate(_rewrite_extra_servers)
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
    __user.set_global_setting("restart_pending", "true")
    __user.audit("SAVE_INFRA", "extra_servers", f"{count} additional servers configured")
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/save-ddns", methods=["POST"])
@login_required
@_admin_required
def save_infra_ddns():
    log_path = request.form.get("log_path", "").strip()
    dns_provider = request.form.get("dns_provider", "technitium").strip()
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_token = request.form.get("api_token", "").strip()
    forward_zone = request.form.get("forward_zone", "").strip()
    if log_path and not __auth.valid_remote_path(log_path):
        flash("Invalid log path — must be an absolute path with no special characters.", "error")
        return redirect(url_for("settings.settings_alerts"))
    items = [("ddns", "dns_provider", dns_provider)]
    if log_path:
        items.append(("ddns", "log_path", log_path))
    if api_url:
        items.append(("ddns", "api_url", api_url))
    if api_user:
        items.append(("ddns", "api_user", api_user))
    if api_token:
        items.append(("ddns", "api_token", api_token))
    if forward_zone:
        items.append(("ddns", "forward_zone", forward_zone))
    __config.app_config.write_values(items)
    flash("DDNS settings saved.", "success")
    __user.audit("SAVE_INFRA", "ddns", f"log={log_path} provider={dns_provider}")
    return redirect(url_for("settings.settings_alerts"))


@bp.route("/settings/infrastructure/save-ha", methods=["POST"])
@login_required
@_admin_required
def save_ha_settings():
    """Save HA mode for primary Kea server."""
    ha_mode = request.form.get("ha_mode", "").strip()
    server_name = request.form.get("server_name", "").strip()
    items = []
    if ha_mode in ("hot-standby", "load-balancing", "passive-backup", ""):
        items.append(("kea", "ha_mode", ha_mode))
    if server_name:
        items.append(("kea", "name", server_name))
    if items:
        __config.app_config.write_values(items)
    flash("HA settings saved.", "success")
    __user.audit("SAVE_INFRA", "ha_settings", f"mode={ha_mode}")
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/restart", methods=["POST"])
@login_required
@_admin_required
def restart_jen():
    flash("Jen is restarting...", "success")
    __user.set_global_setting("restart_pending", "false")
    __user.audit("RESTART", "jen", "Manual restart triggered from Infrastructure settings")

    def do_restart():
        import time

        time.sleep(2)
        subprocess.run(["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"])

    threading.Thread(target=do_restart, daemon=True).start()
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

    def do_restart():
        import time

        time.sleep(2)
        subprocess.run(["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"])

    threading.Thread(target=do_restart, daemon=True).start()

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
def generate_ssh_key():
    os.makedirs("/etc/jen/ssh", exist_ok=True)
    try:
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "rsa",
                "-b",
                "4096",
                "-f",
                extensions.SSH_KEY_PATH,
                "-N",
                "",
                "-C",
                "jen@your-jen-server",
            ],
            capture_output=True,
            check=True,
        )
        os.chmod(extensions.SSH_KEY_PATH, 0o600)
        subprocess.run(
            ["chown", "www-data:www-data", extensions.SSH_KEY_PATH, extensions.SSH_KEY_PATH + ".pub"],
            capture_output=True,
        )
        with open(extensions.SSH_KEY_PATH + ".pub") as f:
            pub_key = f.read().strip()
        flash(f"SSH key generated. Add this public key to your-kea-server:\n{pub_key}", "success")
        __user.audit("GENERATE_SSH_KEY", "settings", "SSH key pair generated")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate SSH key: {e.stderr.decode() if e.stderr else e}")
        flash("Failed to generate SSH key. Check server logs for details.", "error")
    except Exception as e:
        logger.error(f"Error generating SSH key: {e}")
        flash("Error generating SSH key. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_kea"))
