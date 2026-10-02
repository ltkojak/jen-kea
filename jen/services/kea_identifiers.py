"""
jen/services/kea_identifiers.py
───────────────────────────────
v5.67.0-beta.11 (Q123) — finding, and repairing, the damage the binary-column bug already did.

Until this release an export, a restore of any Kea backup and a Kea database migration wrote Kea's
binary columns as the ASCII of their own hex: the six-byte MAC 34:13:43:e6:0e:2a became the twelve
bytes of the text "341343e60e2a" (see jen/services/dbexport.py, EXPORT_FORMAT). The reservation row is
still there, still looks right in a hex dump, and never matches the client again.

What can be recognised, and what cannot — stated plainly because a repair that guesses corrupts good rows:

  * `hosts.dhcp_identifier` of type 0 (hw-address), 1 (duid) or 3 (client-id) that is an even number of
    ASCII hex digits and the right length is recognised. A genuine hardware address, DUID or client-id is
    binary (a client-id begins with a hardware-type byte, a DUID with a two-byte type); the chance that
    six to twenty real bytes are ALL printable hex digits is vanishing.
  * type 2 (circuit-id) and type 4 (flex-id) are NEVER flagged: an operator may legitimately use ASCII
    hex text there, and "looks like hex" is not evidence of damage for them.
  * `dhcp4_options.value` / `dhcp6_options.value` and the v6 tables cannot be told apart from a value
    somebody meant, so they are not repaired; the docs say to re-check reservation-level options after a
    restore made before this release.

Only Kea's `hosts` table is read, and only `hosts.dhcp_identifier` is changed, only for rows the dry-run
listed, only when the row still holds the exact bytes the dry-run showed. Jen never changes Kea's schema
(CLAUDE.md "Databases"); this is data, through the table Kea's own tooling would write.
"""

import ipaddress
import re

_ASCII_HEX = re.compile(rb"^(?:[0-9A-Fa-f]{2})+$")

# dhcp_identifier_type → (name, lengths in ASCII characters that are plausible, or None = any even length ≥ 12)
# 12/16/40 characters are the hex of a 6-byte Ethernet, 8-byte EUI-64 and 20-byte InfiniBand address.
_TYPE_RULES = {
    0: ("hw-address", {12, 16, 40}),
    1: ("duid", None),
    3: ("client-id", None),
}
_MIN_ANY = 12


def type_name(t: int) -> str:
    return {0: "hw-address", 1: "duid", 2: "circuit-id", 3: "client-id", 4: "flex-id"}.get(t, f"type {t}")


def looks_like_hex_of_itself(ident, ident_type) -> bool:
    """True when `ident` (bytes) is the ASCII text of a hex string for an identifier type where that is
    recognisable evidence of the Q123 bug. Pure."""
    if not isinstance(ident, (bytes, bytearray)):
        return False
    rule = _TYPE_RULES.get(ident_type)
    if rule is None:
        return False
    n = len(ident)
    if n % 2 or n < _MIN_ANY or not _ASCII_HEX.match(bytes(ident)):
        return False
    lengths = rule[1]
    return lengths is None or n in lengths


def _ip(n) -> str:
    try:
        return str(ipaddress.IPv4Address(int(n))) if n else ""
    except (ValueError, TypeError):
        return ""


def _colon(hexstr: str) -> str:
    return ":".join(hexstr[i : i + 2] for i in range(0, len(hexstr), 2))


def find_damaged(conn) -> list[dict]:
    """Every `hosts` row whose identifier looks like the hex of itself, with the before/after a human
    needs to judge it. Reads only. `conn` is a Kea DB connection (DictCursor). A missing `hosts` table is
    an empty result, not an error."""
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES LIKE 'hosts'")
        if not cur.fetchone():
            return []
        cur.execute(
            "SELECT host_id, dhcp_identifier, dhcp_identifier_type, ipv4_address, hostname, dhcp4_subnet_id "
            "FROM hosts WHERE LENGTH(dhcp_identifier) >= %s AND MOD(LENGTH(dhcp_identifier), 2) = 0 "
            "ORDER BY host_id",
            (_MIN_ANY,),
        )
        rows = cur.fetchall()
    out = []
    for r in rows:
        ident = r["dhcp_identifier"]
        if not looks_like_hex_of_itself(ident, r["dhcp_identifier_type"]):
            continue
        text = bytes(ident).decode("ascii")
        out.append(
            {
                "host_id": r["host_id"],
                "type": r["dhcp_identifier_type"],
                "type_name": type_name(r["dhcp_identifier_type"]),
                "stored_text": text,
                "repaired": _colon(text.lower()),
                "repaired_bytes": len(text) // 2,
                "ipv4": _ip(r.get("ipv4_address")),
                "hostname": r.get("hostname") or "",
                "subnet_id": r.get("dhcp4_subnet_id"),
            }
        )
    return out


def count_checked(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES LIKE 'hosts'")
        if not cur.fetchone():
            return 0
        cur.execute("SELECT COUNT(*) AS n FROM hosts")
        return int(cur.fetchone()["n"])


def repair(conn, host_ids=None) -> list[dict]:
    """Convert the damaged identifiers back: `UNHEX(CONVERT(dhcp_identifier USING ascii))`, one row at a time,
    each guarded by the exact bytes the dry-run showed (so a row somebody edited in between is left alone).
    `host_ids` limits the repair to the ones the operator confirmed; None means every damaged row.

    One row failing never takes the others with it: a unique-key collision (the correct identifier already
    exists on another host row — the operator had re-created the reservation) is reported as skipped with
    the reason, and that row is left exactly as it was. Commits once at the end. Returns a result per
    candidate: {"host_id", "status": "repaired"|"skipped", "detail"}."""
    wanted = None if host_ids is None else {int(h) for h in host_ids}
    results = []
    for d in find_damaged(conn):
        if wanted is not None and d["host_id"] not in wanted:
            continue
        stored = d["stored_text"].encode("ascii")
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE hosts SET dhcp_identifier = UNHEX(CONVERT(dhcp_identifier USING ascii)) "
                    "WHERE host_id = %s AND dhcp_identifier_type = %s AND dhcp_identifier = %s",
                    (d["host_id"], d["type"], stored),
                )
                changed = cur.rowcount
        except Exception as e:
            results.append(
                {
                    "host_id": d["host_id"],
                    "status": "skipped",
                    "detail": f"left unchanged — {type(e).__name__}: another reservation may already hold the "
                    f"correct identifier ({d['repaired']})",
                }
            )
            continue
        if changed:
            results.append(
                {"host_id": d["host_id"], "status": "repaired", "detail": f"{d['stored_text']} → {d['repaired']}"}
            )
        else:
            results.append({"host_id": d["host_id"], "status": "skipped", "detail": "changed since the preview"})
    conn.commit()
    return results
