"""
Switch Port Locator plugin for Jen.
Answers the one question Client Investigation can't: which switch
port is this MAC on? Polls managed switches' MAC address tables over
SNMP every 10 minutes, resolves port names/aliases, auto-detects
uplinks by MAC count, and alerts when a known MAC's port changes.
Version lives in manifest.json — not duplicated here.

Verify-first (read 2026-09-24, pinned here per CLAUDE.md's round-5
recipe — every OID below is quoted from the MIB text itself, not a
blog post or a guess): fetched from https://mibs.pysnmp.com/asn1/
{BRIDGE-MIB,Q-BRIDGE-MIB,IF-MIB}.

BRIDGE-MIB (RFC 4188):
  * dot1dTpFdbAddress — SYNTAX MacAddress — { dot1dTpFdbEntry 1 } —
    1.3.6.1.2.1.17.4.3.1.1 (this plugin never walks it directly: it IS
    the table's own index, so its value is recovered from the OID
    suffix of the OTHER columns below instead).
  * dot1dTpFdbPort — SYNTAX INTEGER — { dot1dTpFdbEntry 2 } —
    1.3.6.1.2.1.17.4.3.1.2. Indexed by dot1dTpFdbAddress alone, so a
    walk's OID suffix past the base OID is exactly the MAC's 6 octets
    as decimal sub-identifiers (0-255 each).
  * dot1dBasePortIfIndex — SYNTAX INTEGER — { dot1dBasePortEntry 2 } —
    1.3.6.1.2.1.17.1.4.1.2. Indexed by the single bridge port number;
    value is the ifIndex IF-MIB actually names things by.

Q-BRIDGE-MIB (RFC 4363):
  * dot1qTpFdbPort — SYNTAX Integer32 — { dot1qTpFdbEntry 2 } —
    1.3.6.1.2.1.17.7.1.2.2.1.2. INDEX { dot1qFdbId, dot1qTpFdbAddress }
    — a walk's OID suffix is 7 sub-identifiers: the FDB id (the VLAN id
    itself in the common single-VLAN-per-FDB case this plugin targets)
    then the MAC's 6 octets.

IF-MIB (RFC 2863):
  * ifName — SYNTAX DisplayString — { ifXEntry 1 }, ifXEntry =
    { ifXTable 1 }, ifXTable = { ifMIBObjects 1 }, ifMIBObjects =
    { ifMIB 1 }, ifMIB = { mib-2 31 } — 1.3.6.1.2.1.31.1.1.1.1.
  * ifAlias — SYNTAX DisplayString(SIZE(0..64)) — { ifXEntry 18 } —
    1.3.6.1.2.1.31.1.1.1.18.

Two FDB-reading strategies (manifest `vlan_indexing`), matching how
real switches actually expose per-VLAN forwarding tables over SNMPv2c
(no single walk sees every VLAN's table on a VLAN-aware bridge, since
the community string usually IS the VLAN-selection mechanism):
  * `none` — the switch (HP/Aruba ProCurve and most non-Cisco gear)
    answers Q-BRIDGE-MIB `dot1qTpFdbPort` directly with the plain
    community string, one walk covering every VLAN's table at once.
  * `community` — Cisco's `community@vlan` indexing: BRIDGE-MIB
    `dot1dTpFdbPort` is walked once per VLAN in the switch's own
    `vlans` list, each with community `"<community>@<vlan>"` — each
    walk only ever sees that one VLAN's table, so the VLAN number is
    already known from which walk it came from rather than the OID.

Design notes
────────────
**Located vs. uplink.** A port carrying more than `_UPLINK_THRESHOLD`
MACs is treated as a trunk/uplink and none of the MACs seen through it
are considered "located" there — the same reasoning a human doing this
by hand would use (a port with 40 MACs on it is a link to another
switch, not a desk). An admin can override any port's classification
by hand (`sp_ports.is_uplink`: NULL = auto, 1/0 = pinned); a pinned
non-uplink port stays "located" even past the MAC-count threshold, and
a pinned uplink stays excluded even below it.

**Moves.** `detect_moves()` compares a MAC's GLOBAL most recent
position (any switch, not just the one being polled right now) against
where this poll just found it — a MAC that hops from one access switch
to another is exactly the case this plugin exists to catch, and
per-switch-scoped tracking alone would miss it.

**Uplinks are visible (v1.0.1).** The located-MAC table only ever holds
MACs that were NOT behind an uplink, so counting rows in it showed 0 MACs
on exactly the port the heuristic had just excluded. The poll now stores
each port's real MAC count (`sp_ports.mac_count`, uplinks included) and
the page shows "Auto (uplink, 37 MACs)" — the operator can see the
heuristic fired, and why.

**Who sees what (v1.0.1).** A MAC is shown only when its CURRENT subnet
(device, active lease, reservation, in that order) is one the caller may
see; "no attributable subnet" is for unrestricted callers only, for API
keys and the search provider too (`plugin_api.can_access_subnet` /
`api_key_can_access_subnet`). A switch belongs to the subnet its
management address is in (`derive_subnet_id`): a scoped account sees, and
may change, only switches whose address is in its own subnets; a switch
addressed by hostname, or by an address in no Kea subnet, is for
unrestricted accounts. The subnet is derived server-side; a value the
caller types is never the subject of a decision.

**The community string is an argv.** net-snmp's `snmpbulkwalk -c` takes
the SNMPv2c community on the command line, so it is visible in `ps` on the
Jen host for the few seconds a walk runs. net-snmp has no alternative for
v2c (a config file or the environment would move the same secret, not
protect it), which is one more reason to use a read-only community and
one that opens nothing else.
"""

import ipaddress
import logging
import os as _os
import re
import subprocess

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

PLUGIN_ID = "switchport"

bp = Blueprint(
    "switchport",
    __name__,
    template_folder="templates",
    root_path=_os.path.dirname(_os.path.abspath(__file__)),
    url_prefix="/network/switchport",
)

# ── Verified OIDs (see module docstring) ────────────────────────────────────────
OID_DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
OID_DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
OID_DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

_VLAN_INDEXING_CHOICES = ("none", "community")
_UPLINK_THRESHOLD = 8
_SNMP_TIMEOUT_S = 20

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_WALK_LINE_RE = re.compile(r"^\.?([\d.]+)\s*=\s*[A-Za-z][\w-]*\s*:\s*(.*)$")


class _PollError(Exception):
    pass


# ── Pure: walk-line parsing, OID-index MAC decoding ─────────────────────────────


def parse_walk_line(line):
    """Pure: one `snmpbulkwalk -On -Oe` output line -> (oid, value) |
    None for a line that doesn't parse (blank, an error line like "No
    Such Object..."). `oid` has its leading dot stripped; a
    STRING-typed value has its surrounding quotes stripped."""
    m = _WALK_LINE_RE.match((line or "").strip())
    if not m:
        return None
    oid, value = m.group(1), m.group(2).strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return oid, value


def _trailing_subids(oid, base_oid):
    """Pure: the sub-identifiers after `base_oid` in `oid`, or None if
    `oid` doesn't start with `base_oid`."""
    prefix = base_oid + "."
    if not oid.startswith(prefix):
        return None
    return oid[len(prefix) :].split(".")


def decode_mac_from_subids(subids):
    """Pure: 6 decimal sub-identifiers (each 0-255) -> 'aa:bb:cc:dd:ee:ff'."""
    return ":".join(f"{int(b):02x}" for b in subids)


def parse_bridge_fdb(text, base_oid=OID_DOT1D_TP_FDB_PORT):
    """Pure: a BRIDGE-MIB dot1dTpFdbPort walk -> {mac: bridge_port}.
    The OID's trailing 6 sub-ids ARE the MAC's bytes (the table is
    indexed directly by dot1dTpFdbAddress)."""
    out = {}
    for line in (text or "").splitlines():
        parsed = parse_walk_line(line)
        if not parsed:
            continue
        oid, value = parsed
        subids = _trailing_subids(oid, base_oid)
        if subids is None or len(subids) != 6:
            continue
        try:
            mac = decode_mac_from_subids(subids)
            port = int(value)
        except (ValueError, TypeError):
            continue
        out[mac] = port
    return out


def parse_qbridge_fdb(text, base_oid=OID_DOT1Q_TP_FDB_PORT):
    """Pure: a Q-BRIDGE-MIB dot1qTpFdbPort walk -> {mac: (vlan, port)}.
    Indexed by {dot1qFdbId, dot1qTpFdbAddress} — 7 trailing sub-ids:
    the FDB id (VLAN id in the common case) then the MAC's 6 bytes."""
    out = {}
    for line in (text or "").splitlines():
        parsed = parse_walk_line(line)
        if not parsed:
            continue
        oid, value = parsed
        subids = _trailing_subids(oid, base_oid)
        if subids is None or len(subids) != 7:
            continue
        try:
            vlan = int(subids[0])
            mac = decode_mac_from_subids(subids[1:])
            port = int(value)
        except (ValueError, TypeError):
            continue
        out[mac] = (vlan, port)
    return out


def parse_single_index_walk(text, base_oid):
    """Pure: a walk whose OID index is one plain integer (bridge port
    number, or ifIndex) -> {index: raw_value_string}."""
    out = {}
    for line in (text or "").splitlines():
        parsed = parse_walk_line(line)
        if not parsed:
            continue
        oid, value = parsed
        subids = _trailing_subids(oid, base_oid)
        if subids is None or len(subids) != 1:
            continue
        try:
            idx = int(subids[0])
        except ValueError:
            continue
        out[idx] = value
    return out


def parse_base_port_ifindex(text, base_oid=OID_DOT1D_BASE_PORT_IFINDEX):
    """Pure: {bridge_port: ifindex}, both cast to int."""
    out = {}
    for port, value in parse_single_index_walk(text, base_oid).items():
        try:
            out[port] = int(value)
        except ValueError:
            continue
    return out


def parse_vlan_list(raw):
    """Pure: the `vlans` column ('10,20,30') -> [10, 20, 30]; blank or
    non-numeric entries are skipped, never raised on."""
    out = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(int(part))
        except ValueError:
            continue
    return out


# ── Pure: resolving bridge ports to ifindex, the uplink heuristic, moves ───────


def resolve_bridge_ports(fdb, port_to_ifindex, vlan):
    """Pure: BRIDGE-MIB (community) mode — {mac: bridge_port} +
    {bridge_port: ifindex} -> {mac: (ifindex, vlan)}; `vlan` is fixed
    for the whole walk (the community string itself selected it). A
    port with no known ifindex mapping is dropped, never guessed."""
    out = {}
    for mac, port in fdb.items():
        ifindex = port_to_ifindex.get(port)
        if ifindex is not None:
            out[mac] = (ifindex, vlan)
    return out


def resolve_qbridge_ports(fdb, port_to_ifindex):
    """Pure: Q-BRIDGE-MIB mode — {mac: (vlan, bridge_port)} +
    {bridge_port: ifindex} -> {mac: (ifindex, vlan)}."""
    out = {}
    for mac, (vlan, port) in fdb.items():
        ifindex = port_to_ifindex.get(port)
        if ifindex is not None:
            out[mac] = (ifindex, vlan)
    return out


def mac_counts_by_ifindex(mac_positions):
    """Pure: {mac: (ifindex, vlan)} -> {ifindex: mac_count}."""
    counts = {}
    for _mac, (ifindex, _vlan) in mac_positions.items():
        counts[ifindex] = counts.get(ifindex, 0) + 1
    return counts


def auto_uplinks(counts, threshold=_UPLINK_THRESHOLD):
    """Pure: {ifindex: count} -> the set of ifindex whose MAC count
    exceeds `threshold` — auto-marked uplink, so MACs seen through one
    are never treated as 'located' there."""
    return {ifindex for ifindex, n in counts.items() if n > threshold}


def located_macs(mac_positions, auto_uplink_ifindexes, manual_uplinks=(), manual_non_uplinks=()):
    """Pure: {mac: (ifindex, vlan)} filtered to exclude any MAC whose
    ifindex is an uplink — auto-detected OR manually pinned — unless
    that ifindex was manually pinned NOT an uplink, which overrides
    the count heuristic either way."""
    effective = (set(auto_uplink_ifindexes) | set(manual_uplinks)) - set(manual_non_uplinks)
    return {mac: pos for mac, pos in mac_positions.items() if pos[0] not in effective}


def detect_moves(old_positions, new_positions):
    """Pure: {mac: (switch_id, ifindex)} old (a MAC's most recent known
    position, from ANY switch) vs new -> [(mac, old_pos, new_pos)] for
    every MAC whose position genuinely changed. A MAC absent from
    `old_positions` (never seen before) is not a move."""
    moves = []
    for mac, new_pos in new_positions.items():
        old_pos = old_positions.get(mac)
        if old_pos is not None and old_pos != new_pos:
            moves.append((mac, old_pos, new_pos))
    return moves


def port_is_uplink(is_uplink, mac_count, threshold=_UPLINK_THRESHOLD):
    """Pure: is a port treated as an uplink? A manual pin (1/0) wins; unpinned
    (None) follows the MAC-count heuristic — strictly more than `threshold`."""
    if is_uplink is None:
        return (mac_count or 0) > threshold
    return bool(is_uplink)


_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")


def valid_switch_host(host):
    """Pure: a hostname or an IPv4 address, and never anything that could be read as
    an option. `host` becomes an argument of `snmpbulkwalk` (list-args, so no shell),
    and an argument starting with `-` would still be parsed by it as a flag."""
    host = (host or "").strip()
    if not host or host.startswith("-") or len(host) > 255:
        return False
    return bool(_HOST_RE.match(host))


def derive_subnet_id(ip, subnet_map):
    """Pure: the Kea subnet id (from `subnet_map`, {id: {"cidr": ...}}) whose CIDR
    contains `ip`, or None — for a hostname, garbage, or an address in no Kea subnet."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    for sid, info in subnet_map.items():
        try:
            if addr in ipaddress.IPv4Network(info["cidr"], strict=False):
                return sid
        except ValueError:
            continue
    return None


def _in_placeholders(values):
    return ",".join(["%s"] * len(values))


def _normalize_mac(raw):
    if not raw:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(cleaned) != 12:
        return ""
    mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac if _MAC_RE.match(mac) else ""


# ── DB helpers (same shape as every other bundled plugin) ──────────────────────


def _get_db():
    from jen.plugin_api import get_jen_db

    return get_jen_db()


def _get_kea_db():
    from jen.plugin_api import get_kea_db

    return get_kea_db()


def _subnet_map():
    from jen.plugin_api import subnet_map

    return subnet_map()


def _can(subnet_id):
    """May the session user act on something in `subnet_id`? None ("no attributable
    subnet") is for unrestricted users only — plugin_api decides (v5.65.2)."""
    from jen.plugin_api import can_access_subnet

    return can_access_subnet(subnet_id)


def _is_admin():
    try:
        from jen.plugin_api import is_admin_or_above

        return is_admin_or_above()
    except Exception:
        role = getattr(current_user, "role", None)
        if role is not None:
            return role in ("superadmin", "admin")
        return bool(getattr(current_user, "is_admin", False))


def _require_write():
    if _is_admin():
        return True
    flash("Viewers can look at Switch Ports but not change it.", "error")
    return False


def _audit(action, target, detail):
    try:
        from jen.plugin_api import audit

        audit(action, target, detail)
    except Exception as e:
        logger.error(f"Switch Port Locator: audit failed: {e}")


# ── The MAC's current subnet — filter_client_view's rule (v3 plugin API doesn't
# export that helper directly), reimplemented against the same three sources it
# judges from, in the same priority order: a device's own last-known placement,
# then an active lease, then a reservation. ──────────────────────────────────


def _current_subnet_for_mac(mac):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT last_subnet_id FROM devices WHERE mac=%s", (mac,))
            row = cur.fetchone()
            if row and row.get("last_subnet_id") is not None:
                return row["last_subnet_id"]
    except Exception as e:
        logger.warning(f"Switch Port Locator: device subnet lookup failed: {e}")
    finally:
        if db:
            db.close()

    hex_mac = mac.replace(":", "").upper()
    kdb = None
    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            cur.execute("SELECT subnet_id FROM lease4 WHERE HEX(hwaddr)=%s AND state=0", (hex_mac,))
            row = cur.fetchone()
            if row:
                return row["subnet_id"]
            cur.execute(
                "SELECT dhcp4_subnet_id AS subnet_id FROM hosts WHERE dhcp_identifier_type=0 AND HEX(dhcp_identifier)=%s",
                (hex_mac,),
            )
            row = cur.fetchone()
            if row:
                return row["subnet_id"]
    except Exception as e:
        logger.warning(f"Switch Port Locator: lease/reservation subnet lookup failed: {e}")
    finally:
        if kdb:
            kdb.close()
    return None


def _mac_visible(mac):
    """May the session user see where this MAC is? Judged on the MAC's current subnet;
    a MAC with none (or an unknown one) is for unrestricted users only."""
    if _can(None):
        return True
    return _can(_current_subnet_for_mac(mac))


def _switch_subnet(host):
    """The Kea subnet a switch's management address is in, or None."""
    return derive_subnet_id(host, _subnet_map())


def _load_switch(switch_id):
    """(row, refusal): the sp_switches row when the caller may act on it, else
    (None, why) — a switch in a subnet the caller cannot see reads as one that does
    not exist."""
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, host, enabled FROM sp_switches WHERE id=%s", (switch_id,))
            row = cur.fetchone()
    finally:
        if db:
            db.close()
    if row is None or not _can(_switch_subnet(row["host"])):
        return None, "Switch not found."
    return row, ""


# ── SNMP polling (impure: subprocess) ───────────────────────────────────────────


def _run_snmpbulkwalk(host, community, oid, timeout=_SNMP_TIMEOUT_S):
    """One `snmpbulkwalk` call, list-args (never shell-interpolated).
    Raises _PollError on anything that isn't a usable result."""
    try:
        proc = subprocess.run(
            ["snmpbulkwalk", "-v2c", "-c", community, "-On", "-Oe", host, oid],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise _PollError("snmpbulkwalk is not installed") from e
    except subprocess.TimeoutExpired as e:
        raise _PollError(f"timed out after {timeout}s") from e
    if proc.returncode != 0 and not proc.stdout.strip():
        raise _PollError((proc.stderr or "snmpbulkwalk failed").strip()[:200])
    return proc.stdout


def _fdb_positions(switch, community, port_to_ifindex):
    """Impure: the switch's chosen FDB-reading strategy -> {mac: (ifindex, vlan)}."""
    if switch["vlan_indexing"] == "community":
        combined = {}
        for vlan in parse_vlan_list(switch.get("vlans")):
            text = _run_snmpbulkwalk(switch["host"], f"{community}@{vlan}", OID_DOT1D_TP_FDB_PORT)
            fdb = parse_bridge_fdb(text)
            combined.update(resolve_bridge_ports(fdb, port_to_ifindex, vlan))
        return combined
    text = _run_snmpbulkwalk(switch["host"], community, OID_DOT1Q_TP_FDB_PORT)
    fdb = parse_qbridge_fdb(text)
    return resolve_qbridge_ports(fdb, port_to_ifindex)


def _poll_switch(switch):
    from jen.plugin_api import decrypt_secret

    community = decrypt_secret(switch["community"]) if switch.get("community") else ""
    db = None
    try:
        port_text = _run_snmpbulkwalk(switch["host"], community, OID_DOT1D_BASE_PORT_IFINDEX)
        port_to_ifindex = parse_base_port_ifindex(port_text)
        name_text = _run_snmpbulkwalk(switch["host"], community, OID_IF_NAME)
        alias_text = _run_snmpbulkwalk(switch["host"], community, OID_IF_ALIAS)
        ifnames = parse_single_index_walk(name_text, OID_IF_NAME)
        ifaliases = parse_single_index_walk(alias_text, OID_IF_ALIAS)
        positions = _fdb_positions(switch, community, port_to_ifindex)
    except _PollError as e:
        _record_poll_result(switch["id"], str(e))
        return

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            counts = mac_counts_by_ifindex(positions)
            for ifindex, name in ifnames.items():
                cur.execute(
                    "INSERT INTO sp_ports (switch_id, ifindex, ifname, ifalias, mac_count) VALUES (%s, %s, %s, %s, %s) "
                    "ON DUPLICATE KEY UPDATE ifname=VALUES(ifname), ifalias=VALUES(ifalias), "
                    "mac_count=VALUES(mac_count)",
                    (switch["id"], ifindex, name, ifaliases.get(ifindex, ""), counts.get(ifindex, 0)),
                )
            cur.execute("SELECT ifindex, is_uplink FROM sp_ports WHERE switch_id=%s", (switch["id"],))
            overrides = {r["ifindex"]: r["is_uplink"] for r in cur.fetchall()}
            manual_up = {ix for ix, v in overrides.items() if v == 1}
            manual_down = {ix for ix, v in overrides.items() if v == 0}

            auto_up = auto_uplinks(counts)
            located = located_macs(positions, auto_up, manual_up, manual_down)
            new_positions = {mac: (switch["id"], ifindex) for mac, (ifindex, _vlan) in located.items()}

            old_positions = {}
            if new_positions:
                cur.execute(
                    f"SELECT mac, switch_id, ifindex, last_seen FROM sp_mac_ports "  # nosec B608 - only `%s` placeholders are interpolated; every value is bound
                    f"WHERE mac IN ({_in_placeholders(new_positions)}) ORDER BY last_seen DESC",
                    tuple(new_positions),
                )
                for row in cur.fetchall():
                    old_positions.setdefault(row["mac"], (row["switch_id"], row["ifindex"]))
            moves = detect_moves(old_positions, new_positions)

            cur.execute("SELECT mac FROM sp_mac_ports WHERE switch_id=%s", (switch["id"],))
            previously_here = {r["mac"] for r in cur.fetchall()}
            for mac in previously_here - set(located):
                cur.execute("DELETE FROM sp_mac_ports WHERE switch_id=%s AND mac=%s", (switch["id"], mac))
            for mac, (ifindex, vlan) in located.items():
                cur.execute(
                    "INSERT INTO sp_mac_ports (mac, switch_id, ifindex, vlan, first_seen, last_seen) "
                    "VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP()) "
                    "ON DUPLICATE KEY UPDATE ifindex=VALUES(ifindex), vlan=VALUES(vlan), last_seen=UTC_TIMESTAMP()",
                    (mac, switch["id"], ifindex, vlan),
                )
        db.commit()
    except Exception as e:
        logger.error(f"Switch Port Locator: recording poll results for {switch['name']!r} failed: {e}")
        _record_poll_result(switch["id"], str(e)[:300])
        return
    finally:
        if db:
            db.close()

    _record_poll_result(switch["id"], "")
    for mac, old_pos, new_pos in moves:
        _emit_move(mac, old_pos, new_pos)


def _record_poll_result(switch_id, error):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE sp_switches SET last_poll_at=UTC_TIMESTAMP(), last_error=%s WHERE id=%s",
                (error[:300], switch_id),
            )
        db.commit()
    except Exception as e:
        logger.error(f"Switch Port Locator: could not record poll result: {e}")
    finally:
        if db:
            db.close()


def _port_label(switch_id, ifindex):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT name FROM sp_switches WHERE id=%s", (switch_id,))
            switch = cur.fetchone()
            cur.execute("SELECT ifname FROM sp_ports WHERE switch_id=%s AND ifindex=%s", (switch_id, ifindex))
            port = cur.fetchone()
        sw_name = switch["name"] if switch else f"switch {switch_id}"
        port_name = port["ifname"] if port else f"ifindex {ifindex}"
        return f"{sw_name} {port_name}"
    except Exception:
        return f"switch {switch_id} ifindex {ifindex}"
    finally:
        if db:
            db.close()


_MOVED_ALERT_TYPE = "switchport_moved"
_MOVED_TEMPLATE = "ℹ️ <b>{mac}</b> moved: {old} → {new}"


def _emit_move(mac, old_pos, new_pos):
    old_label = _port_label(*old_pos)
    new_label = _port_label(*new_pos)
    subnet_id = _current_subnet_for_mac(mac)
    try:
        from jen.plugin_api import send_alert

        send_alert(_MOVED_ALERT_TYPE, subnet_id=subnet_id, mac=mac, old=old_label, new=new_label)
    except Exception as e:
        logger.warning(f"Switch Port Locator: could not send move alert for {mac}: {e}")
    try:
        from jen.plugin_api import emit

        emit(
            "plugin.switchport.moved",
            mac=mac,
            subnet_id=subnet_id,
            detail=f"{old_label} → {new_label}",
        )
    except Exception as e:
        logger.warning(f"Switch Port Locator: could not emit move event for {mac}: {e}")


def _tick():
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM sp_switches WHERE enabled=1")
            switches = cur.fetchall()
    except Exception as e:
        logger.error(f"Switch Port Locator: could not list switches: {e}")
        return
    finally:
        if db:
            db.close()
    for switch in switches:
        try:
            _poll_switch(switch)
        except Exception as e:
            logger.error(f"Switch Port Locator: polling {switch.get('name')!r} failed: {e}")


# ── Locate: the answer to "where is this MAC" ───────────────────────────────────


def _locate_mac(mac):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT mp.switch_id, s.name AS switch_name, mp.ifindex, p.ifname, p.ifalias, "
                "mp.vlan, mp.last_seen FROM sp_mac_ports mp "
                "JOIN sp_switches s ON s.id = mp.switch_id "
                "LEFT JOIN sp_ports p ON p.switch_id = mp.switch_id AND p.ifindex = mp.ifindex "
                "WHERE mp.mac=%s ORDER BY mp.last_seen DESC LIMIT 1",
                (mac,),
            )
            return cur.fetchone()
    except Exception as e:
        logger.error(f"Switch Port Locator: locate failed for {mac}: {e}")
        return None
    finally:
        if db:
            db.close()


# ── Search provider ──────────────────────────────────────────────────────────


def _switchport_search(query, accessible_subnet_ids, all_subnets):
    q = (query or "").strip()
    if not q:
        return []
    mac = _normalize_mac(q)
    like = f"%{q}%"
    db = None
    out = []
    try:
        db = _get_db()
        with db.cursor() as cur:
            if mac:
                cur.execute(
                    "SELECT mp.mac, s.name AS switch_name, p.ifname FROM sp_mac_ports mp "
                    "JOIN sp_switches s ON s.id = mp.switch_id "
                    "LEFT JOIN sp_ports p ON p.switch_id = mp.switch_id AND p.ifindex = mp.ifindex "
                    "WHERE mp.mac=%s ORDER BY mp.last_seen DESC LIMIT 5",
                    (mac,),
                )
            else:
                cur.execute(
                    "SELECT mp.mac, s.name AS switch_name, p.ifname FROM sp_mac_ports mp "
                    "JOIN sp_switches s ON s.id = mp.switch_id "
                    "LEFT JOIN sp_ports p ON p.switch_id = mp.switch_id AND p.ifindex = mp.ifindex "
                    "WHERE p.ifname LIKE %s OR p.ifalias LIKE %s ORDER BY mp.last_seen DESC LIMIT 20",
                    (like, like),
                )
            for row in cur.fetchall():
                # the MAC's own current subnet: Jen drops any row whose subnet_id is not in the
                # caller's scope, so a None here made every result vanish for a restricted user
                sid = _current_subnet_for_mac(row["mac"])
                if not _can(sid):
                    continue
                out.append(
                    {
                        "title": row["mac"],
                        "subtitle": f"{row['switch_name']} · {row.get('ifname') or '?'}",
                        "href": url_for("switchport.index", mac=row["mac"]),
                        "subnet_id": sid,
                    }
                )
    except Exception as e:
        logger.error(f"Switch Port Locator: search provider failed: {e}")
    finally:
        if db:
            db.close()
    return out


# ── Routes: page ────────────────────────────────────────────────────────────


def _switch_rows():
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, name, host, vlan_indexing, vlans, enabled, last_poll_at, last_error "
                "FROM sp_switches ORDER BY name"
            )
            switches = [s for s in cur.fetchall() if _can(_switch_subnet(s["host"]))]
            for s in switches:
                cur.execute(
                    "SELECT ifindex, ifname, ifalias, is_uplink, mac_count FROM sp_ports "
                    "WHERE switch_id=%s ORDER BY ifname",
                    (s["id"],),
                )
                s["ports"] = cur.fetchall()
                for port in s["ports"]:
                    port["uplink"] = port_is_uplink(port["is_uplink"], port["mac_count"])
    except Exception as e:
        logger.error(f"Switch Port Locator: index error: {e}")
        switches = []
    finally:
        if db:
            db.close()
    return switches


@bp.route("/")
@login_required
def index():
    switches = _switch_rows()

    located = None
    query_mac = (request.args.get("mac") or "").strip()
    if query_mac:
        mac = _normalize_mac(query_mac)
        if mac and _mac_visible(mac):
            located = _locate_mac(mac)
            located = {"mac": mac, **located} if located else {"mac": mac}

    return render_template(
        "switchport/index.html",
        switches=switches,
        located=located,
        query_mac=query_mac,
        vlan_indexing_choices=_VLAN_INDEXING_CHOICES,
        uplink_threshold=_UPLINK_THRESHOLD,
        is_admin=_is_admin(),
    )


@bp.route("/switches/add", methods=["POST"])
@login_required
def add_switch():
    if not _require_write():
        return redirect(url_for("switchport.index"))

    name = request.form.get("name", "").strip()[:100]
    host = request.form.get("host", "").strip()[:255]
    if not name or not host:
        flash("Name and host are required.", "error")
        return redirect(url_for("switchport.index"))
    if not valid_switch_host(host):
        flash("Host must be a hostname or an IPv4 address (it cannot start with a dash).", "error")
        return redirect(url_for("switchport.index"))
    if not _can(_switch_subnet(host)):
        flash("A switch must be addressed by an IP in a subnet you can access.", "error")
        return redirect(url_for("switchport.index"))
    vlan_indexing = request.form.get("vlan_indexing", "none")
    if vlan_indexing not in _VLAN_INDEXING_CHOICES:
        vlan_indexing = "none"
    vlans = request.form.get("vlans", "").strip()[:255]
    community_raw = request.form.get("community", "")
    community = ""
    if community_raw:
        from jen.plugin_api import encrypt_secret

        community = encrypt_secret(community_raw)

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO sp_switches (name, host, community, vlan_indexing, vlans, created_by) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (name, host, community, vlan_indexing, vlans or None, current_user.username),
            )
        db.commit()
        flash(f"{name} added.", "success")
        _audit("SWITCHPORT_ADD_SWITCH", name, f"host={host}")
    except Exception as e:
        flash(f"Could not add switch: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("switchport.index"))


@bp.route("/switches/<int:switch_id>/toggle", methods=["POST"])
@login_required
def toggle_switch(switch_id):
    if not _require_write():
        return redirect(url_for("switchport.index"))
    row, refusal = _load_switch(switch_id)
    if row is None:
        flash(refusal, "error")
        return redirect(url_for("switchport.index"))
    new_enabled = 0 if row["enabled"] else 1
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("UPDATE sp_switches SET enabled=%s WHERE id=%s", (new_enabled, switch_id))
        db.commit()
        flash("Switch enabled." if new_enabled else "Switch paused.", "success")
    except Exception as e:
        flash(f"Could not update switch: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("switchport.index"))


@bp.route("/switches/<int:switch_id>/delete", methods=["POST"])
@login_required
def delete_switch(switch_id):
    if not _require_write():
        return redirect(url_for("switchport.index"))
    row, refusal = _load_switch(switch_id)
    if row is None:
        flash(refusal, "error")
        return redirect(url_for("switchport.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM sp_mac_ports WHERE switch_id=%s", (switch_id,))
            cur.execute("DELETE FROM sp_ports WHERE switch_id=%s", (switch_id,))
            cur.execute("DELETE FROM sp_switches WHERE id=%s", (switch_id,))
        db.commit()
        flash("Switch removed.", "success")
        _audit("SWITCHPORT_DELETE_SWITCH", str(switch_id), "switch removed")
    except Exception as e:
        flash(f"Could not remove switch: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("switchport.index"))


@bp.route("/ports/<int:switch_id>/<int:ifindex>/uplink", methods=["POST"])
@login_required
def set_uplink(switch_id, ifindex):
    if not _require_write():
        return redirect(url_for("switchport.index"))
    row, refusal = _load_switch(switch_id)
    if row is None:
        flash(refusal, "error")
        return redirect(url_for("switchport.index"))
    value = request.form.get("value", "auto")
    is_uplink = {"auto": None, "up": 1, "down": 0}.get(value)
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE sp_ports SET is_uplink=%s WHERE switch_id=%s AND ifindex=%s",
                (is_uplink, switch_id, ifindex),
            )
        db.commit()
        flash("Port updated.", "success")
    except Exception as e:
        flash(f"Could not update port: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("switchport.index"))


# ── Row action target: "Find switch port" (lease/reservation/device rows) ──────
# The row action itself just points at index() with ?mac= — no separate route.


# ── JSON API (v1.0.0) ────────────────────────────────────────────────────────
# Undecorated on purpose: api_key_required() is applied in register(app), not
# here, so plugin.py's top level never imports jen.plugin_api — the standalone
# harness (tools/test_plugin.py) stubs only flask/flask_login.

api_bp = Blueprint("switchport_api", __name__, url_prefix="/api/v1/plugins/switchport")


def _api_locate(mac):
    from flask import g

    from jen.plugin_api import api_key_can_access_subnet

    normalized = _normalize_mac(mac)
    if not normalized:
        return jsonify({"error": "invalid mac"}), 400
    sid = _current_subnet_for_mac(normalized)
    # a MAC with no attributable subnet is for an unrestricted key only — a scoped key read it as "allow"
    if not api_key_can_access_subnet(g.api_key, sid):
        return jsonify({"error": "subnet not accessible to this key"}), 403
    row = _locate_mac(normalized)
    if not row:
        return jsonify({"mac": normalized, "located": False})
    return jsonify(
        {
            "mac": normalized,
            "located": True,
            "switch": row["switch_name"],
            "ifname": row.get("ifname"),
            "ifalias": row.get("ifalias"),
            "vlan": row.get("vlan"),
            "last_seen": row["last_seen"].isoformat() if row.get("last_seen") else None,
        }
    )


def register(app):
    app.register_blueprint(bp)

    from jen.plugin_api import (
        api_key_required,
        register_alert_type,
        register_periodic,
        register_row_action,
        register_search_provider,
    )

    api_bp.add_url_rule("/locate/<mac>", "api_locate", api_key_required(write=False)(_api_locate), methods=["GET"])
    app.register_blueprint(api_bp)

    for surface in ("lease", "reservation", "device"):
        register_row_action(
            PLUGIN_ID,
            surface,
            label="Find switch port",
            icon="cable",
            href="/network/switchport?mac={mac}",
            method="GET",
            roles=("viewer", "admin", "superadmin"),
        )
    register_alert_type(
        PLUGIN_ID,
        _MOVED_ALERT_TYPE,
        label="Switch Port: device moved",
        icon="info",
        default_template=_MOVED_TEMPLATE,
    )
    register_search_provider(PLUGIN_ID, title="Switch Ports", fn=_switchport_search)
    register_periodic(PLUGIN_ID, "poll", _tick, 10)

    logger.info("Switch Port Locator plugin registered")
