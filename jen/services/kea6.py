"""
jen/services/kea6.py
─────────────────────
v5.0 Phase 1 — IPv6. Thin wrappers around jen/services/kea.py's existing
kea_command()/kea_is_up()/get_active_kea_server(), NOT a parallel module.

Why thin wrappers and not a duplicate module
─────────────────────────────────────────────
kea_command() already sends {"command": ..., "service": [service]} with
service defaulting to "dhcp4" — Kea's Control Agent is commonly configured
to proxy to both kea-dhcp4 and kea-dhcp6 through the same HTTP endpoint
(confirmed against theelders' real kea-ctrl-agent.conf during Phase 0: one
CA, one `control-sockets` block, entries keyed per service). So the v6 API
layer only needs to pass service="dhcp6" through to the same functions,
using the v6-specific connection info from jen.extensions when configured,
and falling back to the v4 connection info otherwise (jen/config.py's
AppConfig.apply() already does that fallback at load time — KEA6_API_URL
etc. are simply equal to KEA_API_URL etc. when [kea6] is absent from
jen.config).

Everything in this module is inert on a v4-only install: is_ipv6_enabled()
is the gate every other function here should be called behind, and it
reads the ipv6_enabled global setting, which defaults to false and is
never set true except through the (not yet built, Phase 1 checklist item)
Settings -> Infrastructure toggle.
"""

import logging

from jen import extensions
from jen.services.kea import kea_command

logger = logging.getLogger(__name__)


def is_ipv6_enabled() -> bool:
    """
    The v6 *display* gate — checked before SUBNET6_MAP is ever populated,
    before any v6 nav item is injected, before any v6 route does anything
    beyond returning "IPv6 support is not enabled."

    Deliberately NOT cached on jen.extensions the way KEA_SERVERS etc. are:
    this is a settings-table value (get_global_setting already has its own
    30s cache — see jen/models/user.py), not a jen.config value, so it
    follows the exact same live-read pattern restart_pending already uses
    in jen/__init__.py's context processor rather than requiring its own
    reload-and-re-derive plumbing.
    """
    from jen.models.user import get_global_setting
    try:
        return get_global_setting("ipv6_enabled", "false") == "true"
    except Exception as e:
        # Fail closed — if the settings table can't be reached, v6 stays
        # off rather than risk surfacing an inconsistent half-enabled state.
        logger.error(f"is_ipv6_enabled: {e}")
        return False


def _v6_server(server: dict = None) -> dict:
    """
    Build the server dict kea_command() expects, using v6 connection info
    with a fallback to the given v4 server's own values — covers the
    same-CA-multi-service common case (extensions.KEA6_API_URL already
    equals KEA_API_URL when [kea6] is absent) as well as an explicit
    per-server v6 override, should that ever be needed.
    """
    if server is None:
        return {
            "api_url":  extensions.KEA6_API_URL,
            "api_user": extensions.KEA6_API_USER,
            "api_pass": extensions.KEA6_API_PASS,
        }
    return {
        "api_url":  server.get("api6_url")  or extensions.KEA6_API_URL  or server["api_url"],
        "api_user": server.get("api6_user") or extensions.KEA6_API_USER or server["api_user"],
        "api_pass": server.get("api6_pass") or extensions.KEA6_API_PASS or server["api_pass"],
    }


def kea6_command(command: str, arguments: dict = None, server: dict = None) -> dict:
    """Send a command to kea-dhcp6 via the same Control Agent plumbing v4 uses."""
    return kea_command(command, service="dhcp6", arguments=arguments,
                        server=_v6_server(server))


def kea6_is_up(server: dict = None) -> bool:
    """Return True if kea-dhcp6 responds to version-get on the given server."""
    return kea6_command("version-get", server=server).get("result") == 0


# ── Service-state orchestration (Phase 1 enable/disable toggle) ────────────
#
# This is the second, real-infrastructure layer of the toggle described in
# the v5.0 plan doc — distinct from is_ipv6_enabled() above, which is only
# Jen's own *display* gate. Flipping this actually reaches every configured
# Kea server over SSH and starts or stops kea-dhcp6-server. Superadmin-only
# gating happens at the route level (jen/routes/settings.py), not here —
# this module has no notion of the logged-in user, matching how the rest
# of jen/services/ stays decoupled from Flask/auth.

def _dual_name_systemctl(ssh, action: str) -> tuple:
    """
    Run `systemctl <action> kea-dhcp6-server`, falling back to the
    `isc-kea-dhcp6-server` unit name — same dual-name handling the v4
    restart logic already has (Debian/Ubuntu package names the unit
    differently depending on how Kea was installed). Returns (out, err).
    """
    _, stdout, stderr = ssh.exec_command(
        f"sudo systemctl {action} kea-dhcp6-server 2>/dev/null || "
        f"sudo systemctl {action} isc-kea-dhcp6-server 2>/dev/null; echo done"
    )
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    return out, err


def _config_exists(ssh, kea6_conf: str) -> bool:
    """Confirm kea-dhcp6.conf actually exists on the remote server before
    attempting to enable — Jen never authors a v6 config from nothing on
    first enable (see plan doc); if it's missing, report that plainly."""
    _, stdout, _ = ssh.exec_command(f"test -f {kea6_conf} && echo yes || echo no")
    return stdout.read().decode().strip() == "yes"


def _connect_ssh(server: dict):
    """Open a paramiko connection to a server dict, matching the exact
    pattern jen/routes/subnets.py's preview endpoint already uses (known
    hosts loading, AutoAddPolicy, key-based auth from extensions.SSH_KEY_PATH,
    save_host_keys best-effort)."""
    import paramiko
    from jen.services import auth as __auth

    ssh = paramiko.SSHClient()
    __auth.paramiko_load_known_hosts(ssh)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server["ssh_host"],
                username=server.get("ssh_user", extensions.KEA_SSH_USER),
                key_filename=extensions.SSH_KEY_PATH, timeout=10)
    try:
        ssh.save_host_keys(extensions.SSH_KNOWN_HOSTS)
    except Exception:
        pass
    return ssh


def _kea6_conf_path(server: dict) -> str:
    """kea-dhcp6.conf lives alongside kea-dhcp4.conf on the same server —
    same directory, sibling filename. No separate per-server config value
    exists yet for this (nothing in the Phase 1 checklist calls for one);
    derive it from the v4 kea_conf path rather than hardcoding /etc/kea/."""
    import os as _os
    kea4_conf = server.get("kea_conf") or extensions.KEA_CONF
    return _os.path.join(_os.path.dirname(kea4_conf), "kea-dhcp6.conf")


def set_ipv6_service_state(enable: bool) -> list:
    """
    SSH to every server in extensions.KEA_SERVERS with ssh_host set, and
    enable/disable kea-dhcp6-server accordingly. Returns a list of dicts
    in the exact same {"name", "ok", "message"} shape the subnet-preview
    server_results work already established, so the settings UI can reuse
    the same rendering pattern.

    Enable: confirms kea-dhcp6.conf exists on each server first (Jen never
    authors one from nothing), then `systemctl enable --now`.
    Disable: `systemctl disable --now` — stop it AND disable at boot, so it
    can't silently come back after a reboot while Jen still thinks it's off.

    Never touches Jen's own ipv6_enabled display flag — the caller (the
    settings route) is responsible for that, after inspecting these
    results, so a partial failure across an HA pair doesn't leave Jen
    claiming v6 is enabled when some servers never actually started it.
    """
    action = "enable --now" if enable else "disable --now"
    results = []
    for server in extensions.KEA_SERVERS:
        if not server.get("ssh_host"):
            continue
        name = server.get("name", server["ssh_host"])
        try:
            ssh = _connect_ssh(server)
            try:
                kea6_conf = _kea6_conf_path(server)
                if enable and not _config_exists(ssh, kea6_conf):
                    results.append({
                        "name": name, "ok": False,
                        "message": f"No {kea6_conf} on this server — Jen doesn't "
                                   f"author a v6 config from scratch. Create it "
                                   f"manually first, then retry.",
                    })
                    continue
                out, err = _dual_name_systemctl(ssh, action)
                if out == "done":
                    results.append({
                        "name": name, "ok": True,
                        "message": f"kea-dhcp6-server {'enabled and started' if enable else 'stopped and disabled'}",
                    })
                else:
                    results.append({"name": name, "ok": False,
                                     "message": err or out or "Unknown systemctl result"})
            finally:
                ssh.close()
        except Exception as e:
            results.append({"name": name, "ok": False, "message": str(e)})
    return results


# ── lease6/hosts/ipv6_reservations read layer (Phase 1, backend only) ──────
#
# Jen doesn't own any of these tables — same relationship it already has to
# lease4/hosts. Everything here is a read query built from the real schema
# confirmed against isc-projects/kea's dhcpdb_create.mysql during Phase 0/1
# research, not guessed: lease6.address is VARCHAR(39) (NOT the INET_ATON
# INT lease4 uses), duid is VARBINARY like hwaddr, hwaddr/hwtype/
# hwaddr_source were added in a later ALTER so are nullable, and
# ipv6_reservations is a genuine one-to-many junction table off hosts
# (type 0=IA_NA address, 2=IA_PD delegated prefix; prefix_len is 128 for a
# plain address reservation).
#
# No route/template calls any of this yet — that's Phase 2. These exist now
# so Phase 2's Leases/Devices/Reservations pages have a tested layer to
# build on rather than writing raw SQL inline in each route the way lease4
# currently does.

LEASE6_TYPE_NAMES = {0: "IA_NA", 1: "IA_TA", 2: "IA_PD"}
IPV6_RESERVATION_TYPE_NAMES = {0: "IA_NA", 2: "IA_PD"}


def _hex_to_colon_mac(hex_str: str) -> str:
    """Same formatting jen/services/kea.py's format_mac() produces, for a
    HEX()-selected column rather than raw bytes."""
    if not hex_str:
        return ""
    return ":".join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2)).lower()


def extract_mac_from_duid(duid_hex: str):
    """
    Extract an embedded MAC from a DUID-LL or DUID-LLT hex string, per
    RFC 8415 section 11. Returns None for DUID-EN/DUID-UUID (no embedded
    link-layer address) or malformed input — never raises.

    DUID layout (first 2 bytes = DUID type, big-endian):
      1 = DUID-LLT: type(2) + hw-type(2) + time(4) + link-layer-address
      2 = DUID-EN:  type(2) + enterprise-number(4) + identifier  (no MAC)
      3 = DUID-LL:  type(2) + hw-type(2) + link-layer-address
      4 = DUID-UUID: type(2) + 128-bit UUID                      (no MAC)

    Confirmed against the real lease6.hwaddr Phase 0 finding: Kea itself
    already does this extraction (among other sources) when populating
    hwaddr, so this is only the fallback for rows where hwaddr is NULL —
    callers should prefer lease6.hwaddr when present (see get_lease6_mac).
    """
    if not duid_hex or len(duid_hex) < 4:
        return None
    try:
        duid_type = int(duid_hex[0:4], 16)
    except ValueError:
        return None
    if duid_type == 1:      # DUID-LLT
        ll = duid_hex[16:]  # skip type(4) + hwtype(4) + time(8) hex chars
    elif duid_type == 3:    # DUID-LL
        ll = duid_hex[8:]   # skip type(4) + hwtype(4) hex chars
    else:
        return None
    if len(ll) != 12:       # not a 6-byte (48-bit) link-layer address — don't guess
        return None
    return _hex_to_colon_mac(ll)


def get_lease6_mac(hwaddr_hex: str, duid_hex: str):
    """
    Prefer lease6.hwaddr when Kea populated it (raw socket capture, EUI-64
    from the link-local address, extraction from DUID-LL/DUID-LLT, or a
    relay-agent option — Kea already does this work more thoroughly than
    Jen could from the DUID alone). Fall back to manual DUID inspection
    only when hwaddr is NULL. Returns None (not a guess) when neither
    source yields a usable MAC — callers should label the device plainly
    as IPv6-only rather than show a wrong vendor guess.
    """
    if hwaddr_hex:
        return _hex_to_colon_mac(hwaddr_hex)
    return extract_mac_from_duid(duid_hex)


def list_lease6(subnet_id: int = None, lease_type: int = None,
                search: str = None, show_expired: bool = False) -> list:
    """
    Read lease6 rows, optionally filtered by subnet/type/search. Mirrors
    the shape jen/routes/leases.py's lease4 query builds, adapted for v6's
    real columns — IA_NA/IA_TA/IA_PD via lease_type, DUID instead of MAC,
    IAID as an extra identity dimension, no INET_NTOA (address is already
    a string).

    Each dict: address, duid_hex, mac (best-effort, see get_lease6_mac),
    valid_lifetime, expire, obtained, subnet_id, pref_lifetime,
    lease_type, lease_type_name, iaid, prefix_len, hostname, state,
    expired.
    """
    from jen.models.db import kea6_db

    where = []
    params = []
    if not show_expired:
        where.append("state=0")
    if subnet_id is not None:
        where.append("subnet_id=%s")
        params.append(subnet_id)
    if lease_type is not None:
        where.append("lease_type=%s")
        params.append(lease_type)
    if search:
        where.append("(address LIKE %s OR hostname LIKE %s OR HEX(duid) LIKE %s)")
        s = f"%{search}%"
        params += [s, s, s.replace(":", "")]
    where_str = " AND ".join(where) if where else "1=1"

    results = []
    with kea6_db() as db:
        with db.cursor() as cur:
            cur.execute(f"""
                SELECT address, HEX(duid) AS duid_hex, HEX(hwaddr) AS hwaddr_hex,
                       valid_lifetime, expire,
                       (expire - INTERVAL valid_lifetime SECOND) AS obtained,
                       subnet_id, pref_lifetime, lease_type, iaid, prefix_len,
                       hostname, state
                FROM lease6 WHERE {where_str}
                ORDER BY address
            """, params)
            for row in cur.fetchall():
                results.append({
                    "address":         row["address"],
                    "duid_hex":        row["duid_hex"] or "",
                    "mac":             get_lease6_mac(row["hwaddr_hex"], row["duid_hex"]) or "",
                    "valid_lifetime":  row["valid_lifetime"],
                    "expire":          row["expire"],
                    "obtained":        row["obtained"],
                    "subnet_id":       row["subnet_id"],
                    "pref_lifetime":   row["pref_lifetime"],
                    "lease_type":      row["lease_type"],
                    "lease_type_name": LEASE6_TYPE_NAMES.get(row["lease_type"], "?"),
                    "iaid":            row["iaid"],
                    "prefix_len":      row["prefix_len"],
                    "hostname":        row["hostname"] or "",
                    "state":           row["state"],
                    "expired":         (row["state"] or 0) != 0,
                })
    return results


def get_ipv6_reservations(subnet_id: int = None) -> list:
    """
    Read v6 reservations from hosts + ipv6_reservations, genuinely
    representing the one-to-many shape rather than retrofitting it: each
    returned dict is one hosts row (one DUID) with a `reservations` list
    that can hold an IA_NA (address) entry, an IA_PD (delegated prefix)
    entry, or both — matching what a single device can actually hold
    simultaneously per the real schema (confirmed in Phase 0).

    Filters on hosts.dhcp6_subnet_id, NOT the v4 dhcp4_subnet_id column
    that's on the same row — a host can carry both a v4 and a v6
    reservation at once, and this function only cares about the v6 one.
    """
    from jen.models.db import kea6_db

    where = ["dhcp6_subnet_id IS NOT NULL"]
    params = []
    if subnet_id is not None:
        where.append("dhcp6_subnet_id=%s")
        params.append(subnet_id)
    where_str = " AND ".join(where)

    hosts_by_id = {}
    order = []
    with kea6_db() as db:
        with db.cursor() as cur:
            cur.execute(f"""
                SELECT host_id, HEX(dhcp_identifier) AS duid_hex,
                       dhcp_identifier_type, dhcp6_subnet_id, hostname,
                       dhcp6_client_classes
                FROM hosts WHERE {where_str}
                ORDER BY host_id
            """, params)
            for row in cur.fetchall():
                hosts_by_id[row["host_id"]] = {
                    "host_id":              row["host_id"],
                    "duid_hex":             row["duid_hex"] or "",
                    "dhcp_identifier_type": row["dhcp_identifier_type"],
                    "subnet_id":            row["dhcp6_subnet_id"],
                    "hostname":             row["hostname"] or "",
                    "client_classes":       row["dhcp6_client_classes"] or "",
                    "reservations":         [],
                }
                order.append(row["host_id"])

            if hosts_by_id:
                placeholders = ",".join(["%s"] * len(hosts_by_id))
                cur.execute(f"""
                    SELECT reservation_id, address, prefix_len, type,
                           dhcp6_iaid, host_id
                    FROM ipv6_reservations WHERE host_id IN ({placeholders})
                """, list(hosts_by_id.keys()))
                for row in cur.fetchall():
                    host = hosts_by_id.get(row["host_id"])
                    if host is None:
                        continue
                    host["reservations"].append({
                        "reservation_id": row["reservation_id"],
                        "address":        row["address"],
                        "prefix_len":     row["prefix_len"],
                        "type":           row["type"],
                        "type_name":      IPV6_RESERVATION_TYPE_NAMES.get(row["type"], "?"),
                        "iaid":           row["dhcp6_iaid"],
                    })

    return [hosts_by_id[hid] for hid in order]


def list_lease6_devices(subnet_id: int = None, search: str = None) -> list:
    """
    v5.0 Phase 2 — Devices page IPv6 view. Groups list_lease6() rows by
    DUID into one device row each — a single device commonly holds both
    an IA_NA (address) lease and an IA_PD (delegated prefix) lease
    simultaneously, and those must collapse to one row, not two, the same
    way the plan's one-to-many reservation shape does.

    Deliberately NOT correlated with Jen's v4 `devices` table (per the
    plan's open question #2: privacy-extension addresses rotate, and
    DUID-to-MAC extraction only works for two of several DUID types, so a
    wrong automatic v4/v6 match is worse than no match) — this returns a
    genuinely separate v6-only device list. mac/manufacturer/device_type/
    icon are best-effort via get_lease6_mac() + jen.services.fingerprint's
    existing OUI table; when no MAC can be determined at all (DUID-EN,
    DUID-UUID, or malformed), those fields are empty rather than guessed
    — callers should render that state as "IPv6 device" with no vendor
    icon, never a wrong one.
    """
    from jen.services import fingerprint as __fp

    leases = list_lease6(subnet_id=subnet_id, search=search, show_expired=False)
    by_duid = {}
    order = []
    for l in leases:
        key = l["duid_hex"] or f"__no_duid_{l['address']}"
        if key not in by_duid:
            manufacturer, device_type, icon = (
                __fp.lookup_oui(l["mac"]) if l["mac"] else ("", "", "")
            )
            by_duid[key] = {
                "duid_hex":     l["duid_hex"],
                "mac":          l["mac"],
                "manufacturer": manufacturer if manufacturer != "Unknown" else "",
                "device_type":  device_type if device_type != "unknown" else "",
                "icon":         icon if manufacturer != "Unknown" else "",
                "hostname":     l["hostname"],
                "subnet_id":    l["subnet_id"],
                "addresses":    [],
                "last_expire":  l["expire"],
            }
            order.append(key)
        dev = by_duid[key]
        if not dev["hostname"] and l["hostname"]:
            dev["hostname"] = l["hostname"]
        if l["expire"] and (not dev["last_expire"] or l["expire"] > dev["last_expire"]):
            dev["last_expire"] = l["expire"]
        dev["addresses"].append({
            "address":    l["address"],
            "type_name":  l["lease_type_name"],
            "prefix_len": l["prefix_len"],
        })
    return [by_duid[k] for k in order]


# ── Write-side: v6 reservations (Phase 3) ───────────────────────────────────
#
# Uses Kea's reservation-add/reservation-del commands (the host_cmds hook —
# already required and loaded for the v4 add/edit-reservation flow this
# mirrors) rather than SQL INSERT/DELETE against hosts/ipv6_reservations
# directly: going through Kea keeps its in-memory host cache and the DB in
# sync automatically, exactly matching how jen/routes/reservations.py's
# existing v4 add_reservation_post()/delete already work. Command/argument
# shapes (duid, ip-addresses, prefixes) are Kea's own config-file host
# reservation schema, confirmed against Kea's ARM and example configs
# during Phase 3 research — reservation-add wraps that same object shape
# in {"reservation": {...}}, identical to how the v4 add flow already
# wraps hw-address/ip-address today.

def normalize_duid(duid: str) -> str:
    """
    Accept a DUID as either bare hex ("00030001001a2b3c4d5e") or already
    colon-separated ("00:03:00:01:00:1a:2b:3c:4d:5e") and return Kea's
    expected colon-separated lowercase form. Raises ValueError on
    anything that isn't valid hex once colons are stripped, or has an
    odd number of hex digits (not a whole number of bytes) — callers
    should catch this and surface it as a form validation error, not let
    a malformed DUID reach the Kea API.
    """
    hex_only = duid.replace(":", "").replace("-", "").strip().lower()
    if not hex_only or len(hex_only) % 2 != 0:
        raise ValueError(f"DUID must be a whole number of bytes: {duid!r}")
    try:
        int(hex_only, 16)
    except ValueError:
        raise ValueError(f"DUID must be hex: {duid!r}")
    return ":".join(hex_only[i:i + 2] for i in range(0, len(hex_only), 2))


def add_v6_reservation(subnet_id: int, duid: str, hostname: str = "",
                       addresses: list = None, prefix: str = None,
                       prefix_len: int = None, server: dict = None) -> dict:
    """
    Add a v6 host reservation — an address (IA_NA) reservation, a
    delegated-prefix (IA_PD) reservation, or both at once (the same
    one-to-many shape get_ipv6_reservations() already reads back).
    At least one of `addresses` or `prefix` must be given.

    Returns the raw kea6_command() result — callers check result["result"]
    == 0 for success, same convention as the v4 reservation-add call this
    mirrors in jen/routes/reservations.py.
    """
    if not addresses and not prefix:
        return {"result": 1, "text": "Must specify at least one address or a prefix"}
    reservation = {"subnet-id": subnet_id, "duid": normalize_duid(duid)}
    if hostname:
        reservation["hostname"] = hostname
    if addresses:
        reservation["ip-addresses"] = list(addresses)
    if prefix:
        if not prefix_len:
            return {"result": 1, "text": "prefix_len is required when reserving a prefix"}
        reservation["prefixes"] = [f"{prefix}/{prefix_len}"]
    return kea6_command("reservation-add", arguments={"reservation": reservation}, server=server)


def delete_v6_reservation(subnet_id: int, duid: str, server: dict = None) -> dict:
    """Delete a v6 host reservation by subnet + DUID (identifier-type
    fixed at 'duid' — Jen's v6 reservation UI is DUID-only, matching how
    Jen only builds v4 reservations by hw-address, not the other v4
    identifier types Kea itself also supports)."""
    return kea6_command("reservation-del", arguments={
        "subnet-id": subnet_id,
        "identifier-type": "duid",
        "identifier": normalize_duid(duid),
    }, server=server)


# ── Write-side: v6 subnet editing (Phase 3) ─────────────────────────────────
#
# Mirrors jen/routes/subnets.py's v4 _get_subnet_kea_data() /
# _build_subnet_patch_script() pattern exactly — same dry-run-first
# safety net (kea-dhcp6 -t against a temp file before ever touching the
# live config), same base64-python-over-SSH delivery, same backup-before-
# write discipline — adapted for what's genuinely different about v6:
#   - preferred-lifetime AND valid-lifetime are distinct fields (v4 only
#     has one); T1/T2 (renew/rebind) are the same concept as v4.
#   - DNS is delivered via the "dns-servers" DHCPv6 option (code 23,
#     space dhcp6), not v4's "domain-name-servers" (code 6, space dhcp4).
#   - No "routers" equivalent — DHCPv6 doesn't carry a default-gateway
#     option; that's Router Advertisement's job, outside Kea entirely.
#     Deliberately NOT offering a routers field here, rather than adding
#     one that would silently do nothing.
#   - Scope is address-pool editing only, matching the plan's stated
#     Phase 3 boundary — PD-pool (prefix delegation pool) editing is not
#     included here.

def get_subnet6_kea_data(subnet_id: int, server: dict = None) -> dict:
    """Fetch current v6 subnet config from Kea for pre-populating the edit
    form — same shape/intent as jen/routes/subnets.py's
    _get_subnet_kea_data(), read via kea6_command("config-get") against
    Dhcp6 rather than Dhcp4."""
    empty = {"pools": [], "pool_str": "", "preferred_lifetime": "",
             "valid_lifetime": "", "renew_timer": "", "rebind_timer": "",
             "dns_servers": ""}
    try:
        result = kea6_command("config-get", server=server)
        if result.get("result") != 0:
            return empty
        cfg = result["arguments"]["Dhcp6"]
        global_pref    = cfg.get("preferred-lifetime", 0)
        global_valid   = cfg.get("valid-lifetime", 0)
        global_renew   = cfg.get("renew-timer", 0)
        global_rebind  = cfg.get("rebind-timer", 0)
        for s in cfg.get("subnet6", []):
            if s["id"] != subnet_id:
                continue
            pools = []
            for p in s.get("pools", []):
                pool_str = p.get("pool", "") if isinstance(p, dict) else str(p)
                if pool_str:
                    pools.append(pool_str.strip())
            dns_servers = ""
            for opt in s.get("option-data", []):
                if opt.get("name") == "dns-servers":
                    dns_servers = opt.get("data", "")
            return {
                "pools":              pools,
                "pool_str":           pools[0] if pools else "",
                "preferred_lifetime": s.get("preferred-lifetime", global_pref)   or "",
                "valid_lifetime":     s.get("valid-lifetime",     global_valid)  or "",
                "renew_timer":        s.get("renew-timer",        global_renew)  or "",
                "rebind_timer":       s.get("rebind-timer",       global_rebind) or "",
                "dns_servers":        dns_servers,
            }
    except Exception:
        pass
    return empty


def build_subnet6_patch_script(subnet_id, kea6_conf, new_pool, extra_pools,
                               new_preferred, new_valid, new_renew, new_rebind,
                               new_dns, dry_run=False):
    """
    Build the remote Python script that patches subnet_id's v6 config,
    writes it to a temp file, and runs `kea-dhcp6 -t` against it.
    Same dry_run contract as the v4 _build_subnet_patch_script() this
    mirrors: dry_run=True never writes to the live config under any
    outcome (pass or fail), only dry_run=False (the real apply path)
    ever calls os.replace(tmp, path).
    """
    if dry_run:
        backup_step = ""
        on_pass = "os.unlink(tmp)\nprint('preview-ok')"
    else:
        backup_step = "# Make a backup before touching anything\nshutil.copy2(path, backup)\n\n"
        on_pass = "# Config test passed — move temp into place\nos.replace(tmp, path)\nprint('ok')"

    return f"""
import json, sys, shutil, subprocess, os, tempfile

path   = {repr(kea6_conf)}
backup = path + '.jen_backup'

{backup_step}with open(path) as f:
    cfg = json.load(f)

changed = False
for s in cfg.get('Dhcp6', {{}}).get('subnet6', []):
    if s['id'] != {subnet_id}:
        continue
    new_pool = {repr(new_pool)}
    if new_pool:
        extra_pools = {repr(extra_pools)}
        s['pools'] = [{{'pool': new_pool}}] + [{{'pool': p}} for p in extra_pools]
        changed = True
    new_preferred = {repr(new_preferred)}
    new_valid     = {repr(new_valid)}
    new_renew     = {repr(new_renew)}
    new_rebind    = {repr(new_rebind)}
    if new_preferred:
        s['preferred-lifetime'] = int(new_preferred); changed = True
    if new_valid:
        s['valid-lifetime'] = int(new_valid); changed = True
    if new_renew:
        s['renew-timer'] = int(new_renew); changed = True
    if new_rebind:
        s['rebind-timer'] = int(new_rebind); changed = True
    new_dns = {repr(new_dns)}
    if new_dns:
        opts = s.get('option-data', [])
        found = False
        for o in opts:
            if o.get('name') == 'dns-servers':
                o['data'] = new_dns; found = True; break
        if not found:
            opts.append({{'name': 'dns-servers', 'code': 23, 'space': 'dhcp6',
                          'csv-format': True, 'data': new_dns}})
        s['option-data'] = opts
        changed = True
    break

if not changed:
    print('nochange')
    sys.exit(0)

# Write to a temp file first, test it, then move into place
tmp = path + '.jen_tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f, indent=2)

# Run kea-dhcp6 -t against the temp file
result = subprocess.run(
    ['kea-dhcp6', '-t', tmp],
    capture_output=True, text=True
)
combined = result.stdout + result.stderr

if result.returncode != 0 or 'ERROR' in combined:
    # Config test failed — clean up temp, leave original untouched
    os.unlink(tmp)
    error_lines = [l for l in combined.splitlines() if 'ERROR' in l or 'Error' in l]
    print('testerror:' + ' | '.join(error_lines[:3]))
    sys.exit(1)

{on_pass}
"""
