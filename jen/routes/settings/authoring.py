"""
jen/routes/settings/authoring.py
──────────────────────────────
Generate a starter Kea config over SSH; check/install Kea binaries.
"""

import logging

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

import jen.config as __config
import jen.models.user as __user
import jen.services.kea6 as __kea6
import jen.services.kea_authoring as __authoring
from jen import extensions
from jen.config import AppConfig
from jen.routes.settings import bp
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)


def _author_kea_detect(service: str):
    """Shared detection logic for the GET form and both POST routes below —
    connects to the first server with ssh_host configured, prefers reading
    the sibling protocol's real config over autodetecting, and only
    autodetects live interfaces when there's nothing to inherit from.
    Returns (target_server, detected, autodetected_interfaces, ca_socket)
    or (None, ...) if no server has SSH configured at all."""
    target_server = next((s for s in extensions.KEA_SERVERS if s.get("ssh_host")), None)
    if not target_server:
        return None, None, [], None
    detected = {
        "found": False,
        "interfaces": [],
        "lease_db_type": "",
        "lease_db_host": "",
        "lease_db_name": "",
        "hooks": [],
    }
    autodetected_interfaces = []
    ca_socket = None
    try:
        ssh = __kea6._connect_ssh(target_server)
        try:
            detected = __authoring.detect_sibling_config(ssh, target_server, service)
            if not detected["found"]:
                autodetected_interfaces = __authoring.autodetect_interfaces(ssh, service)
            ca_socket = __authoring.detect_ca_socket_path(ssh, target_server, service)
        finally:
            ssh.close()
    except Exception as e:
        flash(f"Could not connect to {target_server.get('name', target_server.get('ssh_host'))}: {e}", "error")
    return target_server, detected, autodetected_interfaces, ca_socket


def _author_kea_subnets_and_db(service: str):
    """Default DB connection info comes from Jen's own already-
    authoritative config, never re-typed. The EXISTING subnet map
    (possibly empty — that's expected and fine here) is returned too,
    to pre-fill the wizard's editable subnet list; it is NOT the source
    of truth for what gets built into the generated config — see
    _parse_subnet_lines() below for that. Authoring a config from
    scratch is exactly the case where nothing may exist in Jen yet."""
    if service == "dhcp4":
        existing_subnets = extensions.SUBNET_MAP
        db = {
            "host": extensions.KEA_DB_HOST,
            "user": extensions.KEA_DB_USER,
            "password": extensions.KEA_DB_PASS,
            "name": extensions.KEA_DB_NAME,
        }
    else:
        existing_subnets = extensions.SUBNET6_MAP
        db = {
            "host": extensions.KEA6_DB_HOST,
            "user": extensions.KEA6_DB_USER,
            "password": extensions.KEA6_DB_PASS,
            "name": extensions.KEA6_DB_NAME,
        }
    return existing_subnets, db


def _subnets_to_lines(subnets: dict, service: str) -> str:
    """Render Jen's existing subnet map into the same editable line
    format the wizard's textarea uses (and jen.config's own
    [subnets]/[subnets6] line syntax) — id = name, cidr[, paired_id]."""
    lines = []
    for sid, info in subnets.items():
        line = f"{sid} = {info['name']}, {info['cidr']}"
        if service == "dhcp6" and info.get("paired_subnet4_id") is not None:
            line += f", {info['paired_subnet4_id']}"
        lines.append(line)
    return "\n".join(lines)


def _parse_subnet_lines(text: str, service: str):
    """
    Parse the wizard's editable subnet textarea — one subnet per line,
    `id = name, cidr[, paired_v4_subnet_id]`, the exact same syntax
    jen.config's own [subnets]/[subnets6] sections already use.
    Deliberately reuses AppConfig.derive_subnet_map() (already tested
    against malformed lines, invalid CIDRs, etc. in Phase 1/2) rather
    than writing new parsing logic — the wizard is just letting the
    operator define what would otherwise have to be hand-added to
    jen.config directly. Returns (subnet_dict, error).
    """
    import configparser

    section = "subnets" if service == "dhcp4" else "subnets6"
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(f"[{section}]\n{text}\n")
    except configparser.Error as e:
        return None, f"Could not parse subnet list: {e}"
    subnets = AppConfig.derive_subnet_map(parser, section=section)
    if not subnets:
        return None, 'At least one subnet is required — one per line, e.g. "1 = LAN, 192.168.1.0/24".'
    return subnets, None


@bp.route("/settings/infrastructure/author-kea/<service>")
@login_required
@_superadmin_required
def author_kea_config(service):
    if service not in ("dhcp4", "dhcp6"):
        flash("Invalid service.", "error")
        return redirect(url_for("settings.settings_kea"))

    target_server, detected, autodetected_interfaces, ca_socket = _author_kea_detect(service)
    if not target_server:
        flash(
            "No Kea server has SSH configured — nothing to author against. "
            "Configure SSH under Kea Server settings first.",
            "error",
        )
        return redirect(url_for("settings.settings_kea"))

    existing_subnets, default_db = _author_kea_subnets_and_db(service)
    conf_path = __authoring.conf_path_for(target_server, service)
    # ISC's conventional per-daemon unix socket name when there's no
    # Control Agent config to read the real one from (the common case in
    # direct mode). Editable in the form; kea-dhcpX -t validates it.
    default_socket = ca_socket or f"/run/kea/kea{'4' if service == 'dhcp4' else '6'}-ctrl-socket"
    direct_mode = extensions.KEA_CONNECTION_MODE == "direct"
    http_socket_info = _direct_http_socket(service) if direct_mode else None
    subnet_lines = _subnets_to_lines(existing_subnets, service)
    return render_template(
        "author_kea_config.html",
        service=service,
        target_server=target_server,
        conf_path=conf_path,
        detected=detected,
        autodetected_interfaces=autodetected_interfaces,
        default_socket=default_socket,
        direct_mode=direct_mode,
        http_socket_info=http_socket_info,
        subnet_lines=subnet_lines,
        has_existing_subnets=bool(existing_subnets),
        default_db=default_db,
    )


def _direct_http_socket(service: str):
    """The `http` control-socket entry an authored config needs in
    connection_mode = direct — address 0.0.0.0 so the Jen host can reach
    it, port from the daemon's own [kea]/[kea6] api_url, basic-auth creds
    from api_user/api_pass. Returns None when the creds aren't set (the
    caller turns that into a form error rather than authoring an
    unauthenticated socket on 0.0.0.0)."""
    if service == "dhcp4":
        api_url, api_user, api_pass, fallback_port = (
            extensions.KEA_API_URL,
            extensions.KEA_API_USER,
            extensions.KEA_API_PASS,
            8000,
        )
    else:
        api_url, api_user, api_pass, fallback_port = (
            extensions.KEA6_API_URL,
            extensions.KEA6_API_USER,
            extensions.KEA6_API_PASS,
            8006,
        )
    if not (api_user and api_pass):
        return None
    return {
        # nosec B104 — goes into the authored Kea daemon's own config, not
        # a bind Jen performs; Kea must listen on all interfaces for the
        # (remote) Jen host to reach it, and the http socket carries
        # required basic auth. See build_new_kea_config().
        "address": "0.0.0.0",  # nosec B104
        "port": __authoring.socket_port_from_url(api_url, fallback_port),
        "user": api_user,
        "password": api_pass,
    }


def _author_kea_build_config(service, form):
    interfaces = [i.strip() for i in form.get("interfaces", "").replace(",", "\n").splitlines() if i.strip()]
    control_socket_path = form.get("control_socket", "").strip()
    db_host = form.get("db_host", "").strip()
    db_user = form.get("db_user", "").strip()
    db_name = form.get("db_name", "").strip()

    if not interfaces:
        return None, None, "At least one interface is required."
    if not control_socket_path:
        return None, None, "Control socket path is required."
    if not (db_host and db_user and db_name):
        return None, None, "Database host, username, and name are required."

    # v5.10.1 — in direct mode the generated config must expose the
    # daemon's own http command socket, or Jen can't talk to the Kea it
    # just authored (Kea 3.2 removed the Control Agent).
    http_socket = None
    if extensions.KEA_CONNECTION_MODE == "direct":
        http_socket = _direct_http_socket(service)
        if http_socket is None:
            return (
                None,
                None,
                (
                    "Direct connection mode needs a Kea API username and password "
                    f"(Settings → Kea{' → Kea6' if service == 'dhcp6' else ''}) — they become the "
                    "http control socket's basic-auth credentials in the generated config."
                ),
            )

    subnets, error = _parse_subnet_lines(form.get("subnets", ""), service)
    if error:
        return None, None, error

    _, default_db = _author_kea_subnets_and_db(service)
    lease_db = {
        "host": db_host,
        "user": db_user,
        "name": db_name,
        "password": default_db["password"],
    }  # Jen's own stored password — never re-typed in the form
    config = __authoring.build_new_kea_config(
        service, interfaces, lease_db, control_socket_path, subnets, http_socket=http_socket
    )
    return config, subnets, None


@bp.route("/settings/infrastructure/author-kea/<service>/preview", methods=["POST"])
@login_required
@_superadmin_required
def author_kea_config_preview(service):
    if service not in ("dhcp4", "dhcp6"):
        return jsonify({"ok": False, "error": "Invalid service."}), 400

    config, subnets, error = _author_kea_build_config(service, request.form)
    if error:
        return jsonify({"ok": False, "error": error}), 400

    server_results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            conf_path = __authoring.conf_path_for(server, service)
            script = __authoring.render_author_config_script(
                service, conf_path, config, allow_overwrite=False, dry_run=True
            )
            ssh = __kea6._connect_ssh(server)
            try:
                import base64

                enc = base64.b64encode(script.encode()).decode()
                _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
            finally:
                ssh.close()
            if out == "preview-ok":
                server_results.append({"name": name, "ok": True, "message": "Config test passed"})
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:") :]
                server_results.append(
                    {
                        "name": name,
                        "ok": False,
                        "missing_binary": binary,
                        "message": f"{binary} is not installed on this server.",
                    }
                )
            elif out.startswith("testerror:"):
                server_results.append({"name": name, "ok": False, "message": out[len("testerror:") :]})
            else:
                server_results.append({"name": name, "ok": False, "message": err or out or "Unknown error"})
        except Exception as e:
            server_results.append({"name": name, "ok": False, "message": str(e)})

    all_passed = all(r["ok"] for r in server_results) if server_results else True
    return jsonify({"ok": True, "config": config, "servers": server_results, "all_passed": all_passed})


@bp.route("/settings/infrastructure/author-kea/<service>", methods=["POST"])
@login_required
@_superadmin_required
def author_kea_config_post(service):
    if service not in ("dhcp4", "dhcp6"):
        flash("Invalid service.", "error")
        return redirect(url_for("settings.settings_kea"))

    config, subnets, error = _author_kea_build_config(service, request.form)
    if error:
        flash(error, "error")
        return redirect(url_for("settings.author_kea_config", service=service))

    allow_overwrite = request.form.get("allow_overwrite", "") == "true"
    errors, results = [], []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            conf_path = __authoring.conf_path_for(server, service)
            script = __authoring.render_author_config_script(
                service, conf_path, config, allow_overwrite=allow_overwrite, dry_run=False
            )
            ssh = __kea6._connect_ssh(server)
            try:
                import base64

                enc = base64.b64encode(script.encode()).decode()
                _, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3")
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
            finally:
                ssh.close()
            if out == "ok":
                results.append(f"✅ {name}: {conf_path} written. Enable/restart the service to use it.")
            elif out == "exists":
                errors.append(f'❌ {name}: {conf_path} already exists — check "overwrite" to replace it.')
            elif out.startswith("missingbinary:"):
                binary = out[len("missingbinary:") :]
                errors.append(f"❌ {name}: {binary} is not installed on this server — install it and try again.")
            elif out.startswith("testerror:"):
                errors.append(f"❌ {name}: config test failed, nothing written. Error: {out[len('testerror:') :]}")
            else:
                errors.append(f"❌ {name}: {err or out}")
        except Exception as e:
            errors.append(f"❌ {name}: {str(e)}")

    # Persist the subnets used to author this config into Jen's own
    # [subnets]/[subnets6] — only when at least one server genuinely
    # wrote the file. This is what closes the loop this whole flow
    # exists for: authoring a config from a blank slate must leave Jen
    # actually able to see/edit those subnets afterward, not just Kea.
    # Merges with (doesn't replace) any subnets Jen already knew about,
    # so authoring never silently drops existing entries.
    if results:
        existing, _ = _author_kea_subnets_and_db(service)
        merged = dict(existing)
        merged.update(subnets)
        if service == "dhcp4":
            __config.write_subnets_config(merged)
        else:
            __config.write_subnets6_config(merged)

    for r in results:
        flash(r, "success")
    for e in errors:
        flash(e, "error")
    __user.audit("AUTHOR_KEA_CONFIG", service, f"overwrite={allow_overwrite} servers={len(results) + len(errors)}")
    return redirect(url_for("settings.settings_kea"))


@bp.route("/settings/infrastructure/check-kea-binaries", methods=["POST"])
@login_required
@_superadmin_required
def check_kea_binaries():
    """
    Whether kea-dhcp4/kea-dhcp6 are actually installed on each
    configured server — for both protocols, checked together, since a
    reasonable next question after "why did dhcp6 fail" is "is dhcp4
    actually fine, or was I wrong about that too." A manual check
    (button-triggered), not run automatically on every Settings page
    load — an SSH round trip per server isn't something every visitor
    to this page should pay for.
    """
    results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            ssh = __kea6._connect_ssh(server)
            try:
                installed = __authoring.detect_installed_kea_services(ssh)
            finally:
                ssh.close()
            results.append({"name": name, "ok": True, **installed})
        except Exception as e:
            results.append({"name": name, "ok": False, "error": str(e)})
    return jsonify({"servers": results})


@bp.route("/settings/infrastructure/install-kea-binary/<service>", methods=["POST"])
@login_required
@_superadmin_required
def install_kea_binary(service):
    """
    Installs kea-{dhcp4,dhcp6}-server via apt on every configured
    server with SSH set up. Superadmin only — this runs a real
    system-level package install with sudo, a bigger blast radius than
    anything else reachable from this page short of the config-authoring
    write itself.
    """
    if service not in ("dhcp4", "dhcp6"):
        return jsonify({"ok": False, "error": "Invalid service."}), 400

    results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            ssh = __kea6._connect_ssh(server)
            try:
                ok, output = __authoring.install_kea_service(ssh, service)
            finally:
                ssh.close()
            results.append({"name": name, "ok": ok, "output": output})
        except Exception as e:
            results.append({"name": name, "ok": False, "output": str(e)})

    all_ok = bool(results) and all(r["ok"] for r in results)
    __user.audit("INSTALL_KEA_BINARY", service, f"all_ok={all_ok} servers={len(results)}")
    return jsonify({"ok": all_ok, "servers": results})
