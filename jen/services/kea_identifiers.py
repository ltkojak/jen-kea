"""
jen/services/kea_identifiers.py
───────────────────────────────
v5.67.0-beta.11 (Q123) — finding, and repairing, the damage the binary-column bug already did.

Until this release an export, a restore of any Kea backup and a Kea database migration wrote Kea's
binary columns as the ASCII of their own hex: the six-byte MAC 34:13:43:e6:0e:2a became the twelve
bytes of the text "341343e60e2a" (see jen/services/dbexport.py, EXPORT_FORMAT). The reservation row is
still there, still looks right in a hex dump, and never matches the client again.

What can be recognised, and what cannot — stated plainly because a repair that guesses corrupts good rows:

  * `hosts.dhcp_identifier` of type 0 (hw-address) that is 12, 16 or 40 ASCII hex digits is recognised: a
    genuine hardware address is binary, and the chance that six real bytes are ALL printable hex digits is
    about 4e-7.
  * type 1 (duid) is recognised the same way and additionally validated by its DECODED type word: a DUID
    begins with a two-byte type of 1 to 4, so text that decodes to anything else is not a DUID and is left alone.
  * type 3 (client-id) is OPAQUE (option 61): embedded clients that send their MAC as ASCII text
    (`001122334455`) exist, so "looks like hex" is not evidence. A client-id row is "damaged" (offered, ticked)
    only with corroboration from `lease4` — a lease whose `client_id` equals the DECODED bytes, or (12 characters)
    whose `hwaddr` equals them. With no lease evidence it is "ambiguous" (listed, UNTICKED, for a human). A lease
    whose `client_id` equals the stored TEXT proves the client sends exactly that text: "legitimate", never
    offered and never repaired. The lease evidence is shown either way.
  * type 2 (circuit-id) and type 4 (flex-id) are NEVER flagged: an operator may legitimately use ASCII
    hex text there, and "looks like hex" is not evidence of damage for them.
  * `dhcp4_options.value` is checked for FIXED-WIDTH option codes only (a short allowlist below, with their
    widths): a host-scoped value whose length is exactly twice the width, all hex pairs, whose decoded bytes are a
    plausible value. These are listed UNTICKED for review. Text-typed codes (domain-name, boot-file, ...) are
    never listed — their text may legitimately be anything — and neither are the v6 option tables.

Only Kea's `hosts`, `lease4` (read) and `dhcp4_options` (read) are looked at; only `hosts.dhcp_identifier` and a
`dhcp4_options.value` the operator ticked are changed, only when the row still holds the exact bytes the dry-run
showed. Jen never changes Kea's schema (CLAUDE.md "Databases"); this is data, through the tables Kea's own
tooling would write.
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
    a CANDIDATE for the Q123 bug (a candidate is not yet a verdict: a client-id also needs lease corroboration,
    see classify_client_id). A DUID must also decode to a type word of 1 to 4 (v5.67.0-beta.15, Q129). Pure."""
    if not isinstance(ident, (bytes, bytearray)):
        return False
    rule = _TYPE_RULES.get(ident_type)
    if rule is None:
        return False
    n = len(ident)
    if n % 2 or n < _MIN_ANY or not _ASCII_HEX.match(bytes(ident)):
        return False
    lengths = rule[1]
    if lengths is not None and n not in lengths:
        return False
    if ident_type == 1:
        return int.from_bytes(bytes.fromhex(bytes(ident).decode("ascii"))[:2], "big") in _DUID_TYPES
    return True


_DUID_TYPES = (1, 2, 3, 4)  # LLT, EN, LL, UUID


def classify_client_id(stored_text: bytes, evidence: list[dict]) -> str:
    """ "damaged" | "ambiguous" | "legitimate" for a type-3 candidate, from its lease evidence (a list of
    {"matches": set of "decoded" / "hwaddr" / "text"}). A lease that shows the client sending exactly the stored
    TEXT makes it legitimate; a lease that shows the DECODED bytes (as client-id, or as hwaddr for a 12-character
    text) corroborates the damage; both, or neither, is ambiguous. Pure."""
    kinds = set()
    for e in evidence:
        kinds |= set(e["matches"])
    text = "text" in kinds
    decoded = bool(kinds & {"decoded", "hwaddr"})
    if text and not decoded:
        return "legitimate"
    if decoded and not text:
        return "damaged"
    return "ambiguous"


def _ip(n) -> str:
    try:
        return str(ipaddress.IPv4Address(int(n))) if n else ""
    except (ValueError, TypeError):
        return ""


def _colon(hexstr: str) -> str:
    return ":".join(hexstr[i : i + 2] for i in range(0, len(hexstr), 2))


def _lease_evidence(cur, stored: bytes) -> list[dict]:
    """Up to five `lease4` rows that bear on a type-3 candidate: a client-id equal to the decoded bytes or to the
    stored text, or (12-character text) a hardware address equal to the decoded bytes. Both columns are indexed
    in Kea's schema."""
    decoded = bytes.fromhex(stored.decode("ascii"))
    sql = "SELECT address, client_id, hwaddr FROM lease4 WHERE client_id IN (%s, %s)"
    args = [decoded, stored]
    if len(decoded) == 6:
        sql += " OR hwaddr = %s"
        args.append(decoded)
    cur.execute(sql + " LIMIT 5", args)
    out = []
    for r in cur.fetchall():
        matches = set()
        if r["client_id"] == decoded:
            matches.add("decoded")
        if r["client_id"] == stored:
            matches.add("text")
        if len(decoded) == 6 and r["hwaddr"] == decoded:
            matches.add("hwaddr")
        out.append(
            {
                "address": _ip(r.get("address")),
                "client_id": bytes(r["client_id"]).hex() if r["client_id"] else "",
                "hwaddr": bytes(r["hwaddr"]).hex() if r["hwaddr"] else "",
                "matches": matches,
            }
        )
    return out


def find_damaged(conn) -> list[dict]:
    """Every `hosts` row whose identifier looks like the hex of itself, with the before/after a human
    needs to judge it. Reads only. `conn` is a Kea DB connection (DictCursor). A missing `hosts` table is
    an empty result, not an error.

    Each candidate carries `confidence` — "damaged" (offered, ticked), "ambiguous" (offered, UNTICKED: only a
    client-id with no lease evidence) or "legitimate" (a lease proves the client sends this text; never offered,
    never repaired) — and, for a client-id, the `evidence` (lease rows) that decided it (v5.67.0-beta.15, Q129)."""
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES LIKE 'hosts'")
        if not cur.fetchone():
            return []
        cur.execute("SHOW TABLES LIKE 'lease4'")
        have_leases = bool(cur.fetchone())
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
        confidence, evidence = "damaged", []
        if r["dhcp_identifier_type"] == 3:
            if have_leases:
                with conn.cursor() as cur:
                    evidence = _lease_evidence(cur, bytes(ident))
            confidence = classify_client_id(bytes(ident), evidence)
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
                "confidence": confidence,
                "evidence": evidence,
            }
        )
    return out


# ── fixed-width option values (v5.67.0-beta.15, Q129) ────────────────────────
#
# DHCPv4 option codes whose value has a fixed, binary width. A value stored as the ASCII hex of itself is exactly
# twice as long. code → (name, bytes per item, how many items are plausible, kind). Text-typed options (15
# domain-name, 66 tftp-server-name, 67 boot-file-name, ...) are deliberately absent: their text may be anything.
_FIXED_OPTIONS = {
    1: ("subnet-mask", 4, (1,), "mask"),
    2: ("time-offset", 4, (1,), "int32"),
    3: ("routers", 4, (1, 2, 3, 4), "ipv4"),
    4: ("time-servers", 4, (1, 2, 3, 4), "ipv4"),
    5: ("name-servers", 4, (1, 2, 3, 4), "ipv4"),
    6: ("domain-name-servers", 4, (1, 2, 3, 4), "ipv4"),
    7: ("log-servers", 4, (1, 2, 3, 4), "ipv4"),
    26: ("interface-mtu", 2, (1,), "mtu"),
    28: ("broadcast-address", 4, (1,), "ipv4"),
    42: ("ntp-servers", 4, (1, 2, 3, 4), "ipv4"),
    44: ("netbios-name-servers", 4, (1, 2, 3, 4), "ipv4"),
    51: ("dhcp-lease-time", 4, (1,), "lease"),
    54: ("dhcp-server-identifier", 4, (1,), "ipv4"),
    58: ("dhcp-renewal-time", 4, (1,), "lease"),
    59: ("dhcp-rebinding-time", 4, (1,), "lease"),
}
_TEN_YEARS = 10 * 365 * 86400


def _plausible_option(kind: str, raw: bytes) -> str | None:
    """The human text of `raw` when it is a plausible value of `kind`, else None. Pure."""
    if kind == "ipv4":
        parts = [raw[i : i + 4] for i in range(0, len(raw), 4)]
        if any(p in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff") for p in parts):
            return None
        return ", ".join(str(ipaddress.IPv4Address(p)) for p in parts)
    n = int.from_bytes(raw, "big")
    if kind == "mask":
        bits = bin(n)[2:].zfill(32)
        return str(ipaddress.IPv4Address(raw)) if re.fullmatch(r"1+0*", bits) else None
    if kind == "mtu":
        return str(n) if 68 <= n <= 65535 else None
    if kind == "lease":
        return f"{n} seconds" if 1 <= n <= _TEN_YEARS else None
    if kind == "int32":
        signed = n - (1 << 32) if n >= (1 << 31) else n
        return f"{signed} seconds" if abs(signed) <= 86400 else None
    return None


def find_option_candidates(conn) -> list[dict]:
    """Host-scoped `dhcp4_options.value` rows of a fixed-width code whose value is the ASCII hex of a plausible
    value (exactly twice the width, every pair a hex digit, the decoded bytes plausible). Reads only; every row is
    for REVIEW — listed unticked, because a value cannot be proven damaged the way a hosts identifier can. A missing
    table is an empty result."""
    with conn.cursor() as cur:
        cur.execute("SHOW TABLES LIKE 'dhcp4_options'")
        if not cur.fetchone():
            return []
        marks = ", ".join(["%s"] * len(_FIXED_OPTIONS))
        sql = f"SELECT o.option_id, o.host_id, o.code, o.value, h.hostname, h.ipv4_address FROM dhcp4_options o LEFT JOIN hosts h ON h.host_id = o.host_id WHERE o.host_id IS NOT NULL AND o.scope_id = 3 AND o.code IN ({marks}) ORDER BY o.option_id"  # nosec B608 - only the %s placeholders are interpolated; the codes are bound parameters
        cur.execute(sql, tuple(_FIXED_OPTIONS))
        rows = cur.fetchall()
    out = []
    for r in rows:
        value = r["value"]
        if not isinstance(value, (bytes, bytearray)):
            continue
        name, width, counts, kind = _FIXED_OPTIONS[r["code"]]
        value = bytes(value)
        if len(value) not in [2 * width * c for c in counts] or not _ASCII_HEX.match(value):
            continue
        raw = bytes.fromhex(value.decode("ascii"))
        shown = _plausible_option(kind, raw)
        if shown is None:
            continue
        out.append(
            {
                "option_id": r["option_id"],
                "host_id": r["host_id"],
                "code": r["code"],
                "name": name,
                "stored_text": value.decode("ascii"),
                "repaired": shown,
                "hostname": r.get("hostname") or "",
                "ipv4": _ip(r.get("ipv4_address")),
            }
        )
    return out


def repair_options(conn, option_ids) -> list[dict]:
    """Convert the option values the operator ticked from the text of their hex back to bytes, one row each,
    guarded by the exact bytes the review listed (a row edited since is left alone) and by being in the candidate
    list at all. Commits once. Returns {"option_id", "status", "detail"} per requested id that is a candidate."""
    wanted = {int(i) for i in option_ids}
    results = []
    for c in find_option_candidates(conn):
        if c["option_id"] not in wanted:
            continue
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE dhcp4_options SET value = UNHEX(CONVERT(value USING ascii)) "
                "WHERE option_id = %s AND host_id IS NOT NULL AND scope_id = 3 AND value = %s",
                (c["option_id"], c["stored_text"].encode("ascii")),
            )
            changed = cur.rowcount
        results.append(
            {
                "option_id": c["option_id"],
                "status": "repaired" if changed else "skipped",
                "detail": f"option {c['code']} ({c['name']}): {c['stored_text']} → {c['repaired']}"
                if changed
                else "changed since the preview",
            }
        )
    conn.commit()
    return results


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
    `host_ids` limits the repair to the ones the operator confirmed; None means every row whose confidence is
    "damaged" (an "ambiguous" client-id is repaired only when the operator names it; a "legitimate" one never).

    One row failing never takes the others with it: a unique-key collision (the correct identifier already
    exists on another host row — the operator had re-created the reservation) is reported as skipped with
    the reason, and that row is left exactly as it was. Commits once at the end. Returns a result per
    candidate: {"host_id", "status": "repaired"|"skipped", "detail"}."""
    wanted = None if host_ids is None else {int(h) for h in host_ids}
    results = []
    for d in find_damaged(conn):
        if wanted is not None and d["host_id"] not in wanted:
            continue
        if wanted is None and d["confidence"] != "damaged":
            continue
        if d["confidence"] == "legitimate":
            results.append(
                {
                    "host_id": d["host_id"],
                    "status": "skipped",
                    "detail": "left unchanged — a lease shows this client sends exactly this text as its client-id",
                }
            )
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
