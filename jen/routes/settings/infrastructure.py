"""
jen/routes/settings/infrastructure.py
───────────────────────────────────
Kea / database / SSH / DDNS / HA / ports / metrics settings.
"""

import logging
import os
import re
import subprocess
import threading

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.config as __config
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.kea as __kea
import jen.services.kea6 as __kea6
from jen import extensions
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required
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


@bp.route("/settings/infrastructure")
@login_required
@_admin_required
def settings_infrastructure():
    """v5.9.0 — the Infrastructure tab became the Kea page. Old bookmarks
    and the post-update overlay redirect land here; send them on."""
    return redirect(url_for("settings.settings_kea"), code=301)


def _kea_servers_with_helper_status():
    """Per-server rows for the SSH card's helper table: id, name,
    ssh_host, the persisted helper status ('v1' / null / unknown), and
    `helper_want` (v5.19.1 — the version Jen wants, so the template can
    show "upgrade available" for a version below it instead of treating
    any installed version as fully current)."""
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
                "helper_version": st.get("version"),  # int, None, or missing key
                "helper_want": kea_host.JEN_HELPER_WANT_VERSION,
                "helper_known": bool(st),
                "helper_checked": st.get("checked", ""),
            }
        )
    return rows


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
    kea_version_tuple = None
    if kea_up:
        _vr = __kea.kea_command("version-get")
        if _vr.get("result") == 0:
            kea_version = (_vr.get("arguments", {}).get("extended", "") or _vr.get("text", "")).splitlines()[0].strip()
            kea_version_tuple = __kea.parse_kea_version(kea_version)
    ca_mode = extensions.KEA_CONNECTION_MODE == "ca"
    ca_deprecation_warning = ca_mode and kea_version_tuple is not None and kea_version_tuple >= (3, 0, 0)
    ca_removed = ca_mode and kea_version_tuple is not None and kea_version_tuple >= (3, 2, 0)

    ssh_pub_key = ""
    if os.path.exists(extensions.SSH_KEY_PATH + ".pub"):
        try:
            with open(extensions.SSH_KEY_PATH + ".pub") as f:
                ssh_pub_key = f.read().strip()
        except Exception:
            pass
    # Load extra servers. v5.19.1 — gap-tolerant enumeration (same fix as
    # config.py::derive_kea_servers): a `while has_section(kea_server_n)`
    # loop stops at the first missing number, hiding every server after a
    # hand-made gap.
    extra_servers = []
    nums = sorted(
        int(m.group(1))
        for sec_name in extensions.cfg.sections()
        if (m := re.fullmatch(r"kea_server_(\d+)", sec_name)) and int(m.group(1)) >= 2
    )
    for n in nums:
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
            }
        )

    # v5.10.2 — direct mode needs an explicit port on every API URL. The
    # save routes validate their own field; this catches a URL that was
    # valid in ca mode and became invalid when the mode was switched.
    direct_port_warnings = []
    if extensions.KEA_CONNECTION_MODE == "direct":

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
    }
    restart_pending = __user.get_global_setting("restart_pending", "false") == "true"
    ipv6_enabled = __kea6.is_ipv6_enabled()
    return render_template(
        "settings_kea.html",
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
        # v5.10.3 — id + name only; the real server dicts carry passwords.
        # v5.11.0 — plus ssh_host + the persisted jen-kea-helper status
        # (never SSHes to render — see jen/services/kea_host.py).
        kea_servers=_kea_servers_with_helper_status(),
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

    if api_url and not __auth.valid_api_url(api_url, require_port=(extensions.KEA_CONNECTION_MODE == "direct")):
        if extensions.KEA_CONNECTION_MODE == "direct":
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


def _probe_once(url, user, pwd, omit_service, service="dhcp4"):
    """One version-get against a candidate endpoint, independent of the
    globally-configured connection mode. Returns (version_text, error):
    exactly one is non-empty."""
    payload = {"command": "version-get"}
    if not omit_service:
        payload["service"] = [service]
    try:
        resp = __kea.http.post(
            url,
            json=payload,
            auth=(user, pwd),
            timeout=8,
            verify=extensions.KEA_API_CA or extensions.KEA_API_TLS_VERIFY,
            cert=__kea._tls_client_cert(),
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

    configured_mode = extensions.KEA_CONNECTION_MODE
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
    if v is None:
        rec = ("Reached Kea, but couldn't parse a version from its reply.", "warn")
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
    elif v < (2, 7, 2):
        rec = (
            f"Kea {version} predates per-daemon control sockets (2.7.2), so the Control Agent is the only "
            "option here. Plan a Kea upgrade before moving to 3.2.",
            "warn",
        )
    elif v < (3, 2, 0):
        rec = (
            f"Kea {version} still ships the Control Agent, but ISC deprecated it in 3.0 and removes it in "
            "3.2. Add an http control socket to each daemon and switch this to direct mode now.",
            "warn",
        )
    else:
        rec = (
            f"Kea {version} removed the Control Agent (3.2). ca mode cannot work against this server — "
            "switch to direct mode.",
            "bad",
        )

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
        }
    )


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
        flash(f"{'✅' if r['ok'] else '❌'} {r['name']}: {r['message']}", "success" if r["ok"] else "error")

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
    _require_port = extensions.KEA_CONNECTION_MODE == "direct"
    for u in api_urls:
        if u.strip() and not __auth.valid_api_url(u.strip(), require_port=_require_port):
            flash(f"Invalid API URL: {u.strip()}", "error")
            return redirect(url_for("settings.settings_kea"))
    for u in api6_urls:
        if u.strip() and not __auth.valid_api_url(u.strip(), require_port=_require_port):
            flash(f"Invalid IPv6 API URL: {u.strip()} (direct mode needs an explicit port)", "error")
            return redirect(url_for("settings.settings_kea"))

    renumbered = []

    def _rewrite_extra_servers(cfg):
        # v5.10.3 — snapshot every current [kea_server_N] so keys the form
        # doesn't manage (ssh_key, any hand-added value) and a blank
        # password survive the remove-and-rebuild. Preservation is by the
        # row's ORIGINAL section id (extra_id[]), NOT by position: before
        # this, reordering two rows wrote each server into the other's old
        # section number and each silently inherited the other's api_pass /
        # api6_pass / ssh_key. A row added in the UI has no id and
        # preserves nothing.
        existing = {}
        n = 2
        while cfg.has_section(f"kea_server_{n}"):
            existing[n] = dict(cfg.items(f"kea_server_{n}"))
            cfg.remove_section(f"kea_server_{n}")
            n += 1

        # A tampered/duplicated id must not pull another server's secrets in.
        seen_ids = set()

        # Sections are renumbered contiguously from 2, skipping blank rows —
        # a gap would make derive_kea_servers() stop early and hide every
        # server after it.
        out = 2
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
            if orig_id is not None:
                seen_ids.add(orig_id)
                if orig_id != out:
                    renumbered.append(f"{orig_id}->{out}")
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
            out += 1

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
    note = " (renumbered)" if renumbered else ""
    flash(f"Additional servers saved — {count} extra server(s) configured{note}.", "success")
    __user.set_global_setting("restart_pending", "true")
    __user.audit(
        "SAVE_INFRA",
        "extra_servers",
        f"{count} additional servers configured" + (f" renumbered={','.join(renumbered)}" if renumbered else ""),
    )
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
