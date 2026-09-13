"""
jen/routes/ddns.py
───────────────────
DDNS status and configuration routes.

v5.23.0 (Q19) — grew from a single status/log page into in-page tabs:
Status, Naming, D2 Configuration, and Verify. Sub-navigation reuses
base.html's shared `_settings_subtabs.html` macro directly rather than
nav.py's SUBTABS table — that table is keyed by Settings groups only,
and /ddns lives under the "network" section strip, not Settings, so
there's no natural entry there. Viewers see the Status tab only;
everything else is admin+.
"""

import logging
import shlex
import socket
import subprocess

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.services.auth as __auth
import jen.services.kea as __kea
import jen.services.kea_changeset as __changeset
import jen.services.kea_config_edit as __edit
import jen.services.kea_ddns as __d2
import jen.services.kea_host as __host
from jen import extensions
from jen.services.access import admin_required as _admin_required

logger = logging.getLogger(__name__)
bp = Blueprint("ddns", __name__)

TABS = ("status", "naming", "d2config", "verify")


def _stat_value(args: dict, key: str) -> int:
    """Kea statistic-get-all shape: {key: [[value, timestamp], ...]}
    newest first. Missing key or malformed sample → 0. Mirrors
    jen/services/health.py's own _stat_value — small enough, and pure
    enough, that duplicating it beats coupling these two modules."""
    samples = args.get(key)
    try:
        return int(samples[0][0])
    except (TypeError, IndexError, ValueError):
        return 0


def _ddns_mode(dhcp4_enable_updates: bool) -> str:
    """[ddns] mode ∈ provider | d2 | both. Explicit config wins; absent,
    it's derived at read time (never written back) — provider when a
    real provider is configured, else d2 when dhcp4 already has DDNS
    updates enabled, else provider (the historical default — a page
    with nothing configured shows the provider tab, same as always)."""
    configured = extensions.cfg.get("ddns", "mode", fallback="").strip()
    if configured in ("provider", "d2", "both"):
        return configured
    provider = extensions.cfg.get("ddns", "dns_provider", fallback="technitium")
    if provider and provider != "none":
        return "provider"
    if dhcp4_enable_updates:
        return "d2"
    return "provider"


def _status_tab_context():
    """Everything the Status tab needs: the existing log tail + hostname
    lookup (unchanged since before v5.23.0 — tests/test_ddns.py pins
    this exact behavior), plus mode, per-server dhcp4 enable-updates,
    and D2 up/version/stats."""
    lines = []
    log_status = "ok"
    log_message = ""
    if not extensions.KEA_SSH_HOST:
        log_status = "error"
        log_message = "SSH host not configured. Set it in Settings → Kea → SSH."
    else:
        # v5.11.0 — the DDNS log read goes through jen.services.kea_host
        # (helper op `tail-log`, or the legacy `sudo tail` over SSH). The
        # primary server carries the SSH details.
        primary = next(iter(extensions.KEA_SERVERS), None) or {
            "id": 1,
            "ssh_host": extensions.KEA_SSH_HOST,
            "ssh_user": extensions.KEA_SSH_USER,
        }
        try:
            res = __host.tail_log(primary, extensions.DDNS_LOG, 200)
            if res["code"] == "missing":
                log_status = "missing"
                log_message = f"Log file not found on Kea server: {extensions.DDNS_LOG}"
            elif not res["ok"]:
                log_status = "error"
                log_message = f"SSH error: {res.get('detail') or 'unknown error'}"
                logger.error(f"DDNS log read error: {res.get('detail')}")
            else:
                lines = list(reversed(res.get("lines", [])))
                if not lines:
                    log_status = "empty"
                    log_message = "Log file exists but contains no entries yet."
        except Exception as e:
            log_status = "error"
            log_message = "Could not read DDNS log. Check server logs for details."
            logger.error(f"DDNS error: {e}")

    lookup_host = request.args.get("host", "").strip()
    lookup_result = ""
    if lookup_host and not __auth.valid_dns_lookup_host(lookup_host):
        lookup_result = "Invalid hostname or IP address."
    elif lookup_host:
        lookup_result = _provider_lookup(lookup_host)

    # v5.23.0 — per-server enable-updates comes from the Kea API
    # (config-get), the same live source /servers and Health Center
    # already use, NOT an SSH file read: kea_command() never raises and
    # needs no SSH configured at all, so a Status-tab page view can't
    # hang or 500 a server that only has API access. kea_host.read_config
    # is for the Naming tab's own edit flow below, which genuinely needs
    # the raw file + sha for the write guard.
    # get_active_kea_server() indexes KEA_SERVERS[0] as its last resort —
    # safe in real deployments (derive_kea_servers() always seeds at
    # least the primary) but not against a test's deliberately-empty
    # list, so guard it explicitly rather than relying on that.
    active_server = __kea.get_active_kea_server() if extensions.KEA_SERVERS else None
    server_updates = []
    active_enabled = False
    for server in extensions.KEA_SERVERS:
        name = server.get("name") or server.get("ssh_host") or f"Server {server.get('id')}"
        r = __kea.kea_command("config-get", server=server)
        cfg = r.get("arguments") if r.get("result") == 0 else None
        enabled = bool((cfg or {}).get("Dhcp4", {}).get("dhcp-ddns", {}).get("enable-updates")) if cfg else None
        if server is active_server:
            active_enabled = bool(enabled)
        server_updates.append({"name": name, "enabled": enabled})

    mode = _ddns_mode(active_enabled)

    d2_status = "skip"
    d2_detail = "DDNS updates disabled in dhcp4"
    d2_stats = None
    if any(s["enabled"] for s in server_updates):
        r = __kea.kea_command("version-get", service="d2", server=active_server)
        if r.get("result") == 0:
            ver = __kea.parse_kea_version(r.get("arguments", {}).get("extended", "") or r.get("text", ""))
            d2_status = "ok"
            d2_detail = f"answered{' v' + '.'.join(map(str, ver)) if ver else ''}"
            stats_r = __kea.kea_command("statistic-get-all", service="d2", server=active_server)
            if stats_r.get("result") == 0:
                args = stats_r.get("arguments", {})
                d2_stats = {
                    k: _stat_value(args, k)
                    for k in (
                        "ncr-received",
                        "ncr-invalid",
                        "ncr-error",
                        "update-sent",
                        "update-signed",
                        "update-unsigned",
                        "update-timeout",
                        "update-error",
                    )
                }
        else:
            d2_status = "warn"
            d2_detail = r.get("text") or "D2 did not answer version-get"

    return {
        "lines": lines,
        "lookup_host": lookup_host,
        "lookup_result": lookup_result,
        "log_status": log_status,
        "log_message": log_message,
        "ddns_log": extensions.DDNS_LOG,
        "dns_provider": extensions.cfg.get("ddns", "dns_provider", fallback="technitium"),
        "mode": mode,
        "server_updates": server_updates,
        "d2_status": d2_status,
        "d2_detail": d2_detail,
        "d2_stats": d2_stats,
    }


def _provider_lookup(lookup_host: str):
    """The existing dns_provider-backed hostname lookup — unchanged
    behavior/return shape from before v5.23.0 (see tests/test_ddns.py's
    TestDdnsSshLookupProvider, which still calls this with no ?tab= and
    expects it to run)."""
    try:
        dns_provider = extensions.cfg.get("ddns", "dns_provider", fallback="technitium")
        if dns_provider == "technitium":
            dns_url = extensions.cfg.get("ddns", "api_url", fallback="")
            dns_token = extensions.cfg.get("ddns", "api_token", fallback="")
            forward_zone = extensions.cfg.get("ddns", "forward_zone", fallback="")
            if dns_url and dns_token:
                import requests as req

                r = req.get(
                    f"{dns_url}/api/zones/records/get",
                    params={"token": dns_token, "domain": lookup_host, "zone": forward_zone},
                    timeout=5,
                )
                data = r.json()
                records = data.get("response", {}).get("records", [])
                return records if records else f"No DNS records found for {lookup_host}"
            return "Technitium API not configured."

        if dns_provider == "pihole":
            dns_url = extensions.cfg.get("ddns", "api_url", fallback="")
            dns_pass = extensions.cfg.get("ddns", "api_token", fallback="")
            if dns_url:
                import requests as req

                try:
                    auth = req.post(f"{dns_url}/api/auth", json={"password": dns_pass}, timeout=5)
                    if auth.status_code == 200 and auth.json().get("session", {}).get("valid"):
                        sid = auth.json()["session"]["sid"]
                        r = req.get(
                            f"{dns_url}/api/dns/records",
                            params={"domain": lookup_host},
                            headers={"X-FTL-SID": sid},
                            timeout=5,
                        )
                        data = r.json()
                        records = data.get("records", [])
                        return records if records else f"No DNS records found for {lookup_host}"
                    raise Exception("Auth failed")
                except Exception:
                    r = req.get(
                        f"{dns_url}/admin/api.php",
                        params={"customdns": "", "action": "get", "auth": dns_pass},
                        timeout=5,
                    )
                    data = r.json()
                    matches = [e for e in data.get("data", []) if lookup_host in str(e)]
                    return matches if matches else f"No records found for {lookup_host} (Pi-hole v5 API)"
            return "Pi-hole API URL not configured."

        if dns_provider == "adguard":
            dns_url = extensions.cfg.get("ddns", "api_url", fallback="")
            dns_user = extensions.cfg.get("ddns", "api_user", fallback="")
            dns_pass = extensions.cfg.get("ddns", "api_token", fallback="")
            if dns_url:
                import requests as req

                r = req.get(f"{dns_url}/control/rewrite/list", auth=(dns_user, dns_pass), timeout=5)
                data = r.json()
                matches = [e for e in data if lookup_host in str(e.get("domain", ""))]
                return matches if matches else f"No rewrite rules found for {lookup_host}"
            return "AdGuard Home URL not configured."

        if dns_provider in ("ssh", "generic"):
            active = __kea.get_active_kea_server()
            ssh_host = active.get("ssh_host") or extensions.KEA_SSH_HOST
            ssh_user = active.get("ssh_user") or extensions.KEA_SSH_USER
            if ssh_host:
                quoted_host = shlex.quote(lookup_host)
                result = subprocess.run(
                    ["ssh"]
                    + __auth.ssh_cli_opts()
                    + ["-o", "ConnectTimeout=10"]
                    + [
                        f"{ssh_user}@{ssh_host}",
                        f"dig +short {quoted_host} 2>/dev/null || host {quoted_host} 2>/dev/null",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return result.stdout.strip() or f"No DNS result for {lookup_host}"
            import socket

            return socket.gethostbyname(lookup_host)

        return "DNS lookup not configured."
    except Exception as e:
        return f"Lookup error: {str(e)}"


# Kea's own documented defaults for the naming knobs — used to fill in
# a key absent from the live config, so the form shows what Kea would
# actually do today, not a blank/unchecked field that looks unset.
_NAMING_DEFAULTS = {
    "ddns-send-updates": True,
    "ddns-override-no-update": False,
    "ddns-override-client-update": False,
    "ddns-replace-client-name": "never",
    "ddns-generated-prefix": "myhost",
    "ddns-qualifying-suffix": "",
    "ddns-update-on-renew": False,
    "ddns-conflict-resolution-mode": "check-with-dhcid",
    "hostname-char-set": "[^A-Za-z0-9.-]",
    "hostname-char-replacement": "",
}


def _naming_tab_context():
    """The Naming tab reads from the active server — every SSH-reachable
    server is kept in sync by _save_ddns4 below, so any one of them is
    representative to display from. The save itself re-reads and guards
    each server by its OWN sha (Q11) at write time, so there's no
    meaningful single "as of" sha to round-trip through this form."""
    server = __kea.get_active_kea_server()
    cfg = __host.read_config(server, "dhcp4") if server.get("ssh_host") else None
    dhcp4 = (cfg or {}).get("Dhcp4", {})
    return {
        "config_unavailable": cfg is None,
        "ddns_block": dhcp4.get("dhcp-ddns", {}),
        # dhcp4.get(k, default) rather than a .setdefault-shaped dict
        # comprehension — a key genuinely present but explicitly `null`
        # in Kea's own JSON is not the same as "absent," but Kea never
        # emits that for these fields, so the simple .get() reads right
        # either way.
        "naming": {k: dhcp4.get(k, _NAMING_DEFAULTS[k]) for k in __edit.DDNS_NAMING_KEYS},
    }


def _save_ddns4(values: dict):
    """Push the dhcp-ddns block + naming knobs to every SSH-reachable Kea
    server, guarded by each server's OWN freshly-read sha (Q11) — same
    read/mutate/apply/restart shape as subnets.py's _apply_dhcp4_change,
    slimmed down since set_ddns4 has no managed/notfound outcome to
    branch on. There's no single "the" base_sha to check against up
    front — the Naming tab reflects one representative server, but a
    save touches all of them — so each server's own guard is what
    actually protects it, not a value read from a possibly-different
    server's form. v5.28.0 (Q24, C2) — a thin wrapper over
    kea_changeset.apply_change()."""
    result = __changeset.apply_change(
        "dhcp4",
        lambda cfg: __edit.set_ddns4(cfg, values),
        "DDNS naming updated",
        conflict_phrase=lambda name: "the config on this server changed since you opened the form",
    )
    if result.status == "noservers":
        flash("No Kea server has SSH configured.", "error")
        return
    for style, text in result.lines:
        flash(text, style)


@bp.route("/ddns")
@login_required
def ddns():
    tab = request.args.get("tab", "status")
    if tab not in TABS:
        tab = "status"
    if tab != "status" and current_user.role == "viewer":
        # Viewers see Status only (v5.23.0) — the other tabs are all
        # write surfaces or things a viewer has no matching action for.
        tab = "status"

    ctx = {"tab": tab, "tabs": TABS}
    if tab == "status":
        ctx.update(_status_tab_context())
    elif tab == "naming":
        ctx.update(_naming_tab_context())
    elif tab == "d2config":
        ctx.update(_d2config_tab_context())
    elif tab == "verify":
        ctx.update(_verify_tab_context())
    return render_template("ddns.html", **ctx)


@bp.route("/ddns/naming/save", methods=["POST"])
@login_required
@_admin_required
def ddns_naming_save():
    values = {
        "enable-updates": request.form.get("enable-updates") == "1",
        "server-ip": request.form.get("server-ip", "").strip() or "127.0.0.1",
        "server-port": int(request.form.get("server-port") or 53001),
        "ncr-protocol": request.form.get("ncr-protocol", "UDP"),
        "ncr-format": request.form.get("ncr-format", "JSON"),
        "ddns-send-updates": request.form.get("ddns-send-updates") == "1",
        "ddns-override-no-update": request.form.get("ddns-override-no-update") == "1",
        "ddns-override-client-update": request.form.get("ddns-override-client-update") == "1",
        "ddns-replace-client-name": request.form.get("ddns-replace-client-name", "never"),
        "ddns-generated-prefix": request.form.get("ddns-generated-prefix", "").strip() or "myhost",
        "ddns-qualifying-suffix": request.form.get("ddns-qualifying-suffix", "").strip(),
        "ddns-update-on-renew": request.form.get("ddns-update-on-renew") == "1",
        "ddns-conflict-resolution-mode": request.form.get("ddns-conflict-resolution-mode", "check-with-dhcid"),
        "hostname-char-set": request.form.get("hostname-char-set", "").strip() or "[^A-Za-z0-9.-]",
        "hostname-char-replacement": request.form.get("hostname-char-replacement", "x"),
    }
    if values["ddns-replace-client-name"] not in ("never", "always", "when-present", "when-not-present"):
        values["ddns-replace-client-name"] = "never"
    _save_ddns4(values)
    return redirect(url_for("ddns.ddns", tab="naming"))


# ── D2 configuration (v5.23.0 — Q19) ────────────────────────────────────────


def _d2config_tab_context():
    """Reads D2's own config (kea-dhcp-ddns.conf) from the active
    server, same "one representative server" reasoning as the Naming
    tab — _save_d2_change below pushes to every SSH-configured server."""
    server = __kea.get_active_kea_server() if extensions.KEA_SERVERS else None
    cfg = __host.read_config(server, "d2") if server and server.get("ssh_host") else None
    d2cfg = (cfg or {}).get("DhcpDdns", {})
    tsig_keys = [
        {"name": k.get("name"), "algorithm": k.get("algorithm")}
        for k in d2cfg.get("tsig-keys", [])
        if isinstance(k, dict)
    ]
    reverse_hints = sorted(
        {s for s in (__d2.suggest_reverse_zone(info.get("cidr", "")) for info in extensions.SUBNET_MAP.values()) if s}
    )
    return {
        "config_unavailable": cfg is None,
        "forward_domains": d2cfg.get("forward-ddns", {}).get("ddns-domains", []),
        "reverse_domains": d2cfg.get("reverse-ddns", {}).get("ddns-domains", []),
        "tsig_keys": tsig_keys,
        "tsig_algorithms": __d2.TSIG_ALGORITHMS,
        "reverse_zone_hints": reverse_hints,
    }


def _parse_dns_servers(raw: str):
    """One "ip[:port]" per line (or comma-separated) → [(ip, port), ...].
    Port defaults to 53. Returns (servers, error) — error is a message
    string on the first bad entry, else None."""
    servers = []
    for chunk in raw.replace(",", "\n").splitlines():
        chunk = chunk.strip()
        if not chunk:
            continue
        ip, _, port_s = chunk.partition(":")
        ip = ip.strip()
        if not __auth.valid_ip(ip):
            return [], f"'{ip}' is not a valid IP address."
        port = 53
        if port_s:
            try:
                port = int(port_s)
            except ValueError:
                return [], f"'{port_s}' is not a valid port."
        servers.append((ip, port))
    if not servers:
        return [], "At least one DNS server is required."
    return servers, None


def _apply_d2_change(mutate_fn, done_phrase: str):
    """Push a D2 config mutation to every SSH-configured Kea server,
    each guarded by its OWN freshly-read sha (Q11) — same shape as
    _save_ddns4 above, targeting kea-dhcp-ddns.conf instead of
    kea-dhcp4.conf. mutate_fn(cfg) -> (cfg, "ok"|"notfound"|"referenced").
    v5.28.0 (Q24, C2) — a thin wrapper over kea_changeset.apply_change().
    "notfound"/"referenced" are both genuinely per-server, informational,
    skip-and-continue outcomes here (unlike subnets.py's callers, where a
    non-"ok" code aborts the whole change set) — so both are passed as
    skip_codes, overriding the default ("notfound", "nochange")."""
    result = __changeset.apply_change(
        "d2",
        mutate_fn,
        done_phrase,
        skip_codes=("notfound", "referenced"),
        code_messages={"referenced": "still referenced by a domain — remove that first", "notfound": "not found"},
        conflict_phrase=lambda name: "the D2 config on this server changed since you opened the form",
        daemon_label="D2",
    )
    if result.status == "noservers":
        flash("No Kea server has SSH configured.", "error")
        return
    for style, text in result.lines:
        flash(text, style)


@bp.route("/ddns/d2config/domain/add", methods=["POST"])
@login_required
@_admin_required
def ddns_d2_domain_add():
    direction = request.form.get("direction", "")
    name = request.form.get("name", "").strip()
    key_name = request.form.get("key_name", "").strip()
    servers_raw = request.form.get("servers", "")

    if direction not in ("forward", "reverse"):
        flash("Invalid direction.", "error")
        return redirect(url_for("ddns.ddns", tab="d2config"))
    if not __auth.valid_ddns_zone_name(name):
        flash("Zone name must be fully-qualified with a trailing dot, e.g. example.com.", "error")
        return redirect(url_for("ddns.ddns", tab="d2config"))
    servers, err = _parse_dns_servers(servers_raw)
    if err:
        flash(err, "error")
        return redirect(url_for("ddns.ddns", tab="d2config"))

    def mutate(cfg):
        return __d2.add_ddns_domain(cfg, direction, name, key_name or None, servers)

    _apply_d2_change(mutate, f"{direction} domain {name} saved")
    return redirect(url_for("ddns.ddns", tab="d2config"))


@bp.route("/ddns/d2config/domain/remove", methods=["POST"])
@login_required
@_admin_required
def ddns_d2_domain_remove():
    direction = request.form.get("direction", "")
    name = request.form.get("name", "").strip()
    if direction not in ("forward", "reverse") or not name:
        flash("Invalid request.", "error")
        return redirect(url_for("ddns.ddns", tab="d2config"))

    def mutate(cfg):
        return __d2.remove_ddns_domain(cfg, direction, name)

    _apply_d2_change(mutate, f"{direction} domain {name} removed")
    return redirect(url_for("ddns.ddns", tab="d2config"))


@bp.route("/ddns/d2config/tsig/add", methods=["POST"])
@login_required
@_admin_required
def ddns_d2_tsig_add():
    name = request.form.get("name", "").strip()
    algorithm = request.form.get("algorithm", "")
    secret = request.form.get("secret", "")

    if not __auth.valid_class_name(name):
        # TSIG key names have no Kea-mandated shape; reusing this
        # validator just keeps it to a sane, shell/JSON-safe identifier.
        flash("Key name must start with a letter and contain only letters, digits, - or _.", "error")
        return redirect(url_for("ddns.ddns", tab="d2config"))
    if algorithm not in __d2.TSIG_ALGORITHMS:
        flash("Invalid TSIG algorithm.", "error")
        return redirect(url_for("ddns.ddns", tab="d2config"))
    if not secret:
        flash("A secret is required.", "error")
        return redirect(url_for("ddns.ddns", tab="d2config"))

    def mutate(cfg):
        return __d2.set_tsig_key(cfg, name, algorithm, secret)

    _apply_d2_change(mutate, f"TSIG key {name} saved")
    return redirect(url_for("ddns.ddns", tab="d2config"))


@bp.route("/ddns/d2config/tsig/remove", methods=["POST"])
@login_required
@_admin_required
def ddns_d2_tsig_remove():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Invalid request.", "error")
        return redirect(url_for("ddns.ddns", tab="d2config"))

    def mutate(cfg):
        return __d2.remove_tsig_key(cfg, name)

    _apply_d2_change(mutate, f"TSIG key {name} removed")
    return redirect(url_for("ddns.ddns", tab="d2config"))


# ── Verify (v5.23.0 — Q19) ───────────────────────────────────────────────────


def _run_verify(hostname: str, ip: str) -> dict:
    """Forward (hostname -> IP) and reverse (IP -> hostname) lookups via
    the Jen host's OWN system resolver — not Kea, not D2 directly; this
    confirms what a client actually sees, whatever put that record there
    (D2 or a provider)."""
    out = {"hostname": hostname, "ip": ip}
    if hostname:
        try:
            infos = socket.getaddrinfo(hostname, None)
            out["forward_ips"] = sorted({info[4][0] for info in infos})
            if ip:
                out["forward_ok"] = ip in out["forward_ips"]
        except socket.gaierror as e:
            out["forward_error"] = str(e)
    if ip:
        try:
            resolved_name, _aliases, _ips = socket.gethostbyaddr(ip)
            out["reverse_name"] = resolved_name
            if hostname:
                out["reverse_ok"] = resolved_name.rstrip(".").lower() == hostname.rstrip(".").lower()
        except (OSError, socket.herror) as e:
            out["reverse_error"] = str(e)
    return out


def _verify_tab_context():
    hostname = request.args.get("hostname", "").strip()
    ip = request.args.get("ip", "").strip()
    result = None
    error = None
    if hostname and not __auth.valid_hostname(hostname):
        error = "Invalid hostname."
    elif ip and not __auth.valid_ip(ip):
        error = "Invalid IP address."
    elif hostname or ip:
        result = _run_verify(hostname, ip)

    active_server = __kea.get_active_kea_server() if extensions.KEA_SERVERS else None
    qualifying_suffix = ""
    if active_server is not None:
        r = __kea.kea_command("config-get", server=active_server)
        if r.get("result") == 0:
            qualifying_suffix = (r.get("arguments") or {}).get("Dhcp4", {}).get("ddns-qualifying-suffix", "")

    return {
        "verify_hostname": hostname,
        "verify_ip": ip,
        "verify_error": error,
        "verify_result": result,
        "forward_zone": extensions.cfg.get("ddns", "forward_zone", fallback=""),
        "qualifying_suffix": qualifying_suffix,
    }
