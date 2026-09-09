"""
jen/routes/settings/infrastructure.py
───────────────────────────────────
Kea / database / SSH / DDNS / HA / ports / metrics settings.
"""

import logging
import os
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


@bp.route("/settings/infrastructure")
@login_required
@_admin_required
def settings_infrastructure():
    """v5.9.0 — the Infrastructure tab became the Kea page. Old bookmarks
    and the post-update overlay redirect land here; send them on."""
    return redirect(url_for("settings.settings_kea"), code=301)


@bp.route("/settings/kea")
@login_required
@_admin_required
def settings_kea():
    kea_up = __kea.kea_is_up()
    ssh_pub_key = ""
    if os.path.exists(extensions.SSH_KEY_PATH + ".pub"):
        try:
            with open(extensions.SSH_KEY_PATH + ".pub") as f:
                ssh_pub_key = f.read().strip()
        except Exception:
            pass
    # Load extra servers
    extra_servers = []
    n = 2
    while extensions.cfg.has_section(f"kea_server_{n}"):
        sec = f"kea_server_{n}"
        extra_servers.append(
            {
                "id": n,
                "name": extensions.cfg.get(sec, "name", fallback=f"Kea Server {n}"),
                "api_url": extensions.cfg.get(sec, "api_url", fallback=""),
                "api_user": extensions.cfg.get(sec, "api_user", fallback=""),
                "ssh_host": extensions.cfg.get(sec, "ssh_host", fallback=""),
                "ssh_user": extensions.cfg.get(sec, "ssh_user", fallback=""),
                "kea_conf": extensions.cfg.get(sec, "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
                "role": extensions.cfg.get(sec, "role", fallback="standby"),
            }
        )
        n += 1

    infra = {
        "kea_api_url": extensions.cfg.get("kea", "api_url", fallback=""),
        "kea_api_user": extensions.cfg.get("kea", "api_user", fallback=""),
        "kea_api_pass": extensions.cfg.get("kea", "api_pass", fallback=""),
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
    if not api_url:
        flash("API URL is required.", "error")
        return redirect(url_for("settings.settings_kea"))
    items = [("kea", "api_url", api_url), ("kea", "api_user", api_user)]
    if api_pass:
        items.append(("kea", "api_pass", api_pass))
    __config.app_config.write_values(items)
    __user.set_global_setting("restart_pending", "true")
    flash("Kea API settings saved. Restart Jen to apply.", "success")
    __user.audit("SAVE_INFRA", "kea_api", f"url={api_url} user={api_user}")
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
    v5.0 Phase 1 — [kea6] API connection override. Every field is
    optional; leaving them blank (or clearing a previously-set value)
    means Jen falls back to the v4 [kea] connection info at load time
    (jen/config.py's AppConfig.apply()) — the common same-CA case. This
    route only ever writes to [kea6]/[kea6_db]; it does not touch the
    ipv6_enabled display flag or the remote kea-dhcp6-server state — see
    toggle_ipv6() for that.
    """
    api_url = request.form.get("api_url", "").strip()
    api_user = request.form.get("api_user", "").strip()
    api_pass = request.form.get("api_pass", "").strip()
    db_host = request.form.get("db_host", "").strip()
    db_user = request.form.get("db_user", "").strip()
    db_pass = request.form.get("db_pass", "").strip()
    db_name = request.form.get("db_name", "").strip()

    items = []
    if api_url:
        items.append(("kea6", "api_url", api_url))
    if api_user:
        items.append(("kea6", "api_user", api_user))
    if api_pass:
        items.append(("kea6", "api_pass", api_pass))
    if db_host:
        items.append(("kea6_db", "host", db_host))
    if db_user:
        items.append(("kea6_db", "user", db_user))
    if db_pass:
        items.append(("kea6_db", "password", db_pass))
    if db_name:
        items.append(("kea6_db", "database", db_name))

    if items:
        __config.app_config.write_values(items)
        __user.set_global_setting("restart_pending", "true")
        flash("Kea6 API settings saved. Restart Jen to apply.", "success")
        __user.audit("SAVE_INFRA", "kea6_api", f"url={api_url or '(inherits v4)'}")
    else:
        flash("No Kea6 values provided — leaving [kea6] as inheriting v4 settings.", "info")
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
    names = request.form.getlist("extra_name[]")
    roles = request.form.getlist("extra_role[]")
    api_urls = request.form.getlist("extra_api_url[]")
    api_users = request.form.getlist("extra_api_user[]")
    api_passes = request.form.getlist("extra_api_pass[]")
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

    def _rewrite_extra_servers(cfg):
        # Remove all existing extra server sections
        n = 2
        while cfg.has_section(f"kea_server_{n}"):
            cfg.remove_section(f"kea_server_{n}")
            n += 1
        # Add new ones
        for i, (name, role, api_url, api_user, api_pass, ssh_host, ssh_user, kea_conf) in enumerate(
            zip(names, roles, api_urls, api_users, api_passes, ssh_hosts, ssh_users, kea_confs, strict=True), start=2
        ):
            if not api_url.strip():
                continue
            sec = f"kea_server_{i}"
            cfg.add_section(sec)
            cfg.set(sec, "name", name.strip() or f"Kea Server {i}")
            cfg.set(sec, "role", role.strip() or "standby")
            cfg.set(sec, "api_url", api_url.strip())
            cfg.set(sec, "api_user", api_user.strip())
            if api_pass.strip():
                cfg.set(sec, "api_pass", api_pass.strip())
            else:
                # Preserve existing password from the current config
                try:
                    existing_pass = extensions.cfg.get(sec, "api_pass", fallback=extensions.KEA_API_PASS)
                    cfg.set(sec, "api_pass", existing_pass)
                except Exception:
                    cfg.set(sec, "api_pass", extensions.KEA_API_PASS)
            cfg.set(sec, "ssh_host", ssh_host.strip())
            cfg.set(sec, "ssh_user", ssh_user.strip())
            cfg.set(sec, "kea_conf", kea_conf.strip() or "/etc/kea/kea-dhcp4.conf")

    try:
        __config.app_config.mutate(_rewrite_extra_servers)
    except ValueError as e:
        # strict=True on the zip() inside _rewrite_extra_servers means a
        # form submission whose extra_*[] fields don't all have the same
        # number of entries — malformed or tampered, since Jen's own
        # template always submits all eight together per server row —
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
