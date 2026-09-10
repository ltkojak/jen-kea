"""
jen/routes/settings/authoring.py
──────────────────────────────
Generate a starter Kea config over SSH; check/install Kea binaries.
"""

import ipaddress
import logging
from urllib.parse import urlparse

from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

import jen.config as __config
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.kea6 as __kea6
import jen.services.kea_authoring as __authoring
import jen.services.kea_host as __host
from jen import extensions
from jen.config import AppConfig
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required
from jen.services.access import superadmin_required as _superadmin_required

logger = logging.getLogger(__name__)


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _author_kea_detect(service: str):
    """Shared detection logic for the GET form and both POST routes below —
    connects to the first server with ssh_host configured, prefers reading
    the sibling protocol's real config over autodetecting, and only
    autodetects live interfaces when there's nothing to inherit from.
    Returns (target_server, detected, autodetected_interfaces, ca_socket,
    detected_addresses) or (None, ...) if no server has SSH configured.
    detected_addresses is only populated in direct mode (for the
    bind-address picker) — one extra exec_command on the same session."""
    target_server = next((s for s in extensions.KEA_SERVERS if s.get("ssh_host")), None)
    if not target_server:
        return None, None, [], None, []
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
    detected_addresses = []
    direct_mode = extensions.KEA_CONNECTION_MODE == "direct"
    try:
        ssh = __kea6._connect_ssh(target_server)
        try:
            detected = __authoring.detect_sibling_config(ssh, target_server, service)
            if not detected["found"]:
                autodetected_interfaces = __authoring.autodetect_interfaces(ssh, service)
            ca_socket = __authoring.detect_ca_socket_path(ssh, target_server, service)
            if direct_mode:
                detected_addresses = __authoring.autodetect_addresses(ssh)
        finally:
            ssh.close()
    except Exception as e:
        flash(f"Could not connect to {target_server.get('name', target_server.get('ssh_host'))}: {e}", "error")
    return target_server, detected, autodetected_interfaces, ca_socket, detected_addresses


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

    target_server, detected, autodetected_interfaces, ca_socket, detected_addresses = _author_kea_detect(service)
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

    # v5.10.3 — every ssh-configured server gets its own bind picker. An
    # HA pair has two management IPs; 5.10.2 detected one address on the
    # first server and wrote it into every server's socket.
    bind_candidates = _author_bind_candidates(service, target_server, detected_addresses) if direct_mode else []
    target_candidate = next((c for c in bind_candidates if c["id"] == target_server.get("id")), None)
    # The scheme drives whether the form asks for TLS paths; "" means the
    # target server's endpoint couldn't be resolved at all (bug 8).
    endpoint_scheme = target_candidate["endpoint_scheme"] if target_candidate else ""
    endpoint_error = target_candidate["endpoint_error"] if target_candidate else ""
    any_http = direct_mode and [c["name"] for c in bind_candidates if c["endpoint_scheme"] == "http"]

    cert_required = bool(extensions.KEA_API_CLIENT_CERT and extensions.KEA_API_CLIENT_KEY)
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
        endpoint_scheme=endpoint_scheme,
        endpoint_error=endpoint_error,
        any_http=any_http,
        bind_candidates=bind_candidates,
        cert_required=cert_required,
        subnet_lines=subnet_lines,
        has_existing_subnets=bool(existing_subnets),
        default_db=default_db,
    )


def _author_bind_candidates(service: str, target_server: dict = None, target_addresses=None):
    """
    v5.10.3 — one bind-address picker per ssh-configured server, direct
    mode only. Each entry: {id, name, endpoint_scheme, endpoint_host,
    endpoint_error, options, preselect}.

    A server's options are ITS OWN detected global addresses plus the host
    Jen dials for it (when that's an IP literal), and the preselect is
    that endpoint host — never 0.0.0.0, never another server's address.
    One best-effort SSH session per server; a connection failure just
    leaves that server with whatever the endpoint tells us. `target_server`
    / `target_addresses` let the caller pass in what _author_kea_detect()
    already fetched so the same host isn't dialled twice.
    """
    from jen.services.kea import _endpoint_for

    target_id = (target_server or {}).get("id")
    out = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        entry = {
            "id": server.get("id"),
            "name": server.get("name") or server.get("ssh_host") or "server",
            "endpoint_scheme": "",
            "endpoint_host": "",
            "endpoint_error": "",
            "options": [],
            "preselect": "",
        }
        ep = _endpoint_for(server, service)
        if isinstance(ep, dict):  # direct + dhcp6 with no v6 URL for this server
            entry["endpoint_error"] = ep["text"]
            out.append(entry)
            continue
        p = urlparse(ep[0] or "")
        entry["endpoint_scheme"] = p.scheme or "http"
        entry["endpoint_host"] = p.hostname or ""

        if server.get("id") == target_id and target_addresses is not None:
            detected = list(target_addresses)
        else:
            detected = []
            try:
                ssh = __kea6._connect_ssh(server)
                try:
                    detected = __authoring.autodetect_addresses(ssh)
                finally:
                    ssh.close()
            except Exception as e:
                # a picker with fewer options, not a page failure
                logger.warning(f"_author_bind_candidates({entry['name']}): {e}")

        options = list(detected)
        if _looks_like_ip(entry["endpoint_host"]):
            if entry["endpoint_host"] not in options:
                options.insert(0, entry["endpoint_host"])
            entry["preselect"] = entry["endpoint_host"]
        elif options:
            entry["preselect"] = options[0]
        entry["options"] = options
        out.append(entry)
    return out


def _direct_control_socket(service: str, server: dict, form_tls: dict):
    """v5.10.2 — the http/https control-socket entry an authored config
    needs in connection_mode = direct, for ONE server. URL / scheme /
    port / credentials come from kea._endpoint_for(server, service) — the
    exact endpoint Jen will dial for this server — never from globals, so
    a standby with its own api_url/creds gets a config Jen can actually
    reach. The bind address is added by the caller (_author_kea_config_for).

    Returns (socket_dict, None) or (None, error_text)."""
    from jen.services.kea import _endpoint_for

    name = server.get("name") or server.get("ssh_host") or "server"
    ep = _endpoint_for(server, service)
    if isinstance(ep, dict):  # direct + dhcp6 + no v6 URL
        return None, f"{name}: {ep['text']}"
    url, user, pwd = ep
    p = urlparse(url or "")
    if p.scheme not in ("http", "https"):
        return None, f"{name}: API URL {url!r} must be http:// or https://."
    port = __authoring.socket_port_from_url(url)
    if port is None:
        return None, (
            f"{name}: API URL {url} has no explicit port — direct mode requires one "
            "(Settings → Kea / Additional Servers)."
        )
    if not (user and pwd):
        return None, (
            f"{name}: direct mode needs a Kea API username and password "
            "(Settings → Kea) — they become the http control socket's basic-auth credentials."
        )
    return {
        "scheme": p.scheme,
        "port": port,
        "user": user,
        "password": pwd,
        "endpoint_host": p.hostname or "",
        "tls": form_tls if p.scheme == "https" else None,
    }, None


def _author_kea_common(service, form):
    """Form validation shared by preview + post. Returns (common, subnets,
    error). `common` carries everything that's the same for every target
    server; per-server config is built by _author_kea_config_for()."""
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

    direct = extensions.KEA_CONNECTION_MODE == "direct"
    bind_addresses = {}
    tls = None
    if direct:
        # v5.10.3 — one bind address PER SERVER. An HA pair has two
        # management IPs; a single shared value meant kea02 was told to
        # bind kea01's address.
        for srv in extensions.KEA_SERVERS:
            if not srv.get("ssh_host"):
                continue
            sid = srv.get("id")
            raw = form.get(f"bind_address_custom_{sid}", "").strip() or form.get(f"bind_address_{sid}", "").strip()
            if not raw:
                continue  # no picker rendered (unresolvable endpoint) — a per-server error later
            if not _looks_like_ip(raw):
                name = srv.get("name") or srv.get("ssh_host")
                return None, None, f"Bind address for {name} must be an IP address, not a hostname (Kea binds it)."
            bind_addresses[sid] = raw

        # TLS paths are required only if a target endpoint is https.
        from jen.services.kea import _endpoint_for

        any_https = False
        for srv in extensions.KEA_SERVERS:
            if not srv.get("ssh_host"):
                continue
            _ep = _endpoint_for(srv, service)
            if not isinstance(_ep, dict) and urlparse(_ep[0] or "").scheme == "https":
                any_https = True
                break
        if any_https:
            cert_file = form.get("tls_cert_file", "").strip()
            key_file = form.get("tls_key_file", "").strip()
            trust_anchor = form.get("tls_trust_anchor", "").strip()
            for label, val in (
                ("TLS certificate file", cert_file),
                ("TLS key file", key_file),
                ("trust anchor", trust_anchor),
            ):
                if not val:
                    return None, None, f"{label} is required — the Kea endpoint is https://."
                if not __auth.valid_remote_path(val):
                    return None, None, f"{label} must be an absolute path with no special characters: {val}"
            tls = {
                "trust_anchor": trust_anchor,
                "cert_file": cert_file,
                "key_file": key_file,
                # Jen presents a client cert ⇒ Kea can demand one. Never
                # emit cert-required:true when Jen has no client cert —
                # that's the mTLS handshake failure authored into a file.
                "cert_required": bool(extensions.KEA_API_CLIENT_CERT and extensions.KEA_API_CLIENT_KEY),
            }

    subnets, error = _parse_subnet_lines(form.get("subnets", ""), service)
    if error:
        return None, None, error

    _, default_db = _author_kea_subnets_and_db(service)
    common = {
        "interfaces": interfaces,
        "control_socket_path": control_socket_path,
        "bind_addresses": bind_addresses,
        "tls": tls,
        "lease_db": {
            "host": db_host,
            "user": db_user,
            "name": db_name,
            "password": default_db["password"],  # Jen's own stored password, never re-typed
        },
    }
    return common, subnets, None


def _author_kea_config_for(service, server, common, subnets):
    """Build the config for ONE target server. Returns
    (config, tls_paths, warning, error) — warning is amber (bind-address
    mismatch / all-interfaces), error skips just this server."""
    if extensions.KEA_CONNECTION_MODE != "direct":
        config = __authoring.build_new_kea_config(
            service, common["interfaces"], common["lease_db"], common["control_socket_path"], subnets, api_socket=None
        )
        return config, [], None, None

    sock, err = _direct_control_socket(service, server, common["tls"])
    if err:
        return None, [], None, err
    bind = common["bind_addresses"].get(server.get("id"))
    if not bind:
        name = server.get("name") or server.get("ssh_host") or "server"
        return None, [], None, f"{name}: no bind address chosen for the control API."
    sock["address"] = bind
    config = __authoring.build_new_kea_config(
        service, common["interfaces"], common["lease_db"], common["control_socket_path"], subnets, api_socket=sock
    )

    tls_paths = []
    if sock["scheme"] == "https":
        t = common["tls"]
        tls_paths = [(t["cert_file"], "file"), (t["key_file"], "file"), (t["trust_anchor"], "dir")]

    warning = None
    if bind == "0.0.0.0":  # nosec B104 — comparing an operator-chosen value to warn; not a bind Jen performs
        warning = f"{server.get('name', 'server')}: the control API will bind every interface (0.0.0.0)."
    elif _looks_like_ip(sock["endpoint_host"]) and bind != sock["endpoint_host"]:
        warning = (
            f"{server.get('name', 'server')}: Jen connects to {sock['endpoint_host']} but the socket binds {bind}."
        )
    return config, tls_paths, warning, None


def _run_author_script(server, service, config, tls_paths, *, dry_run, allow_overwrite):
    """Test or apply an authored config on `server` via
    jen.services.kea_host — one helper op (`test-config` / `apply-config`,
    with the TLS-file existence check inside it) or, on a host without the
    helper, the legacy sudo-python3 engine. Returns (HostResult,
    conf_path)."""
    conf_path = __authoring.conf_path_for(server, service)
    if dry_run:
        res = __host.test_config(server, service, config, tls_paths=tls_paths)
    else:
        res = __host.apply_config(server, service, config, tls_paths=tls_paths, allow_overwrite=allow_overwrite)
    return res, conf_path


@bp.route("/settings/infrastructure/author-kea/<service>/preview", methods=["POST"])
@login_required
@_superadmin_required
def author_kea_config_preview(service):
    if service not in ("dhcp4", "dhcp6"):
        return jsonify({"ok": False, "error": "Invalid service."}), 400

    common, subnets, error = _author_kea_common(service, request.form)
    if error:
        return jsonify({"ok": False, "error": error}), 400

    server_results = []
    first_config = None
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        config, tls_paths, warning, cfg_err = _author_kea_config_for(service, server, common, subnets)
        if cfg_err:
            server_results.append({"name": name, "ok": False, "message": cfg_err})
            continue
        try:
            res, _ = _run_author_script(server, service, config, tls_paths, dry_run=True, allow_overwrite=False)
            row = {"name": name, "config": __authoring.redact_secrets(config)}
            bind = common["bind_addresses"].get(server.get("id"))
            if bind:
                row["bind_address"] = bind
            if warning:
                row["warning"] = warning
            if res["ok"]:
                row.update({"ok": True, "message": "Config test passed"})
            elif res["code"] == "missingbinary":
                row.update(
                    {
                        "ok": False,
                        "missing_binary": res["binary"],
                        "message": f"{res['binary']} is not installed on this server.",
                    }
                )
            elif res["code"] == "tlsmissing":
                row.update({"ok": False, "message": f"TLS file not found on this server: {res['path']}"})
            elif res["code"] == "testerror":
                row.update({"ok": False, "message": res["detail"]})
            else:
                row.update({"ok": False, "message": res["detail"] or "Unknown error"})
            server_results.append(row)
            if first_config is None and row["ok"]:
                first_config = row["config"]
        except Exception as e:
            server_results.append({"name": name, "ok": False, "message": str(e)})

    all_passed = all(r["ok"] for r in server_results) if server_results else True
    return jsonify({"ok": True, "config": first_config, "servers": server_results, "all_passed": all_passed})


@bp.route("/settings/infrastructure/author-kea/<service>", methods=["POST"])
@login_required
@_superadmin_required
def author_kea_config_post(service):
    if service not in ("dhcp4", "dhcp6"):
        flash("Invalid service.", "error")
        return redirect(url_for("settings.settings_kea"))

    common, subnets, error = _author_kea_common(service, request.form)
    if error:
        flash(error, "error")
        return redirect(url_for("settings.author_kea_config", service=service))

    allow_overwrite = request.form.get("allow_overwrite", "") == "true"
    errors, results = [], []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        config, tls_paths, _warning, cfg_err = _author_kea_config_for(service, server, common, subnets)
        if cfg_err:
            errors.append(f"❌ {name}: {cfg_err}")
            continue
        try:
            res, conf_path = _run_author_script(
                server, service, config, tls_paths, dry_run=False, allow_overwrite=allow_overwrite
            )
            if res["code"] == "ok":
                results.append(f"✅ {name}: {conf_path} written. Enable/restart the service to use it.")
            elif res["code"] == "exists":
                errors.append(f'❌ {name}: {conf_path} already exists — check "overwrite" to replace it.')
            elif res["code"] == "missingbinary":
                errors.append(f"❌ {name}: {res['binary']} is not installed on this server — install it and try again.")
            elif res["code"] == "tlsmissing":
                errors.append(f"❌ {name}: TLS file not found on this server: {res['path']}")
            elif res["code"] == "testerror":
                errors.append(f"❌ {name}: config test failed, nothing written. Error: {res['detail']}")
            else:
                errors.append(f"❌ {name}: {res['detail']}")
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
            res = __host.install_package(server, service)
            results.append({"name": name, "ok": res["ok"], "output": res.get("output", res.get("detail", ""))})
        except Exception as e:
            results.append({"name": name, "ok": False, "output": str(e)})

    all_ok = bool(results) and all(r["ok"] for r in results)
    __user.audit("INSTALL_KEA_BINARY", service, f"all_ok={all_ok} servers={len(results)}")
    return jsonify({"ok": all_ok, "servers": results})


def _find_server(server_id):
    return next((s for s in extensions.KEA_SERVERS if s.get("id") == server_id), None)


@bp.route("/settings/infrastructure/check-kea-helper/<int:server_id>", methods=["POST"])
@login_required
@_admin_required
def check_kea_helper(server_id):
    """Probe jen-kea-helper on one server and record its status."""
    server = _find_server(server_id)
    if not server or not server.get("ssh_host"):
        flash("Server not found or SSH not configured.", "error")
        return redirect(url_for("settings.settings_kea") + "#kea-ssh")
    res = __host.check_helper(server)
    if res.get("version"):
        flash(f"{server.get('name', server_id)}: jen-kea-helper v{res['version']}.", "success")
    else:
        flash(
            f"{server.get('name', server_id)}: the helper did not answer — it isn't installed, "
            "or the sudoers line is missing. Jen is using the legacy root python3 path for this host.",
            "warning",
        )
    return redirect(url_for("settings.settings_kea") + "#kea-ssh")


@bp.route("/settings/infrastructure/install-kea-helper/<int:server_id>", methods=["POST"])
@login_required
@_superadmin_required
def install_kea_helper(server_id):
    """Deploy jen-kea-helper onto one server via the legacy sudo-python3
    path (the one time it's needed) + write its one-line sudoers file."""
    server = _find_server(server_id)
    if not server or not server.get("ssh_host"):
        flash("Server not found or SSH not configured.", "error")
        return redirect(url_for("settings.settings_kea") + "#kea-ssh")
    name = server.get("name", server_id)
    res = __host.install_helper(server)
    if res["ok"] and res["code"] == "already":
        flash(f"{name}: jen-kea-helper v{res['version']} is already installed.", "success")
    elif res["ok"]:
        __user.audit("INSTALL_KEA_HELPER", str(name), f"helper v{res['version']}")
        flash(
            f"{name}: jen-kea-helper v{res['version']} installed. Once every host shows the helper "
            "you can remove the legacy /etc/sudoers.d/jen (the python3 = root grant).",
            "success",
        )
    elif res["code"] == "no-path":
        flash(
            f"{name}: neither the helper nor the legacy python3 grant is present — "
            "install the helper by hand (Admin Guide → Kea host helper).",
            "error",
        )
    elif res["code"] == "no-source":
        flash("jen-kea-helper is missing from this Jen install — reinstall Jen.", "error")
    elif res["code"] == "sudoerror":
        flash(f"{name}: the sudoers file failed validation, nothing was installed: {res['detail']}", "error")
    else:
        flash(f"{name}: helper install failed: {res['detail']}", "error")
    return redirect(url_for("settings.settings_kea") + "#kea-ssh")
