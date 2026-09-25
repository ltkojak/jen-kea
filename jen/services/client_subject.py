"""
jen/services/client_subject.py
───────────────────────────────
v5.63.0 (Q82) — ClientSubject: one identity, one way to answer "which
client is this" and "what may THIS caller see about them".

Five features used to resolve "which client is this" independently before
this module existed — jen/services/timeline.py::build_timeline,
jen/routes/explain.py's `_load_lease`/`_load_reservations`,
jen/routes/trace.py's subnet gate, and the client-shaped REST API
(api_v1_device_by_mac / api_v1_timeline, the latter via build_timeline) —
and every Q54-Q56 cross-subnet leak was two of them disagreeing about the
answer. `resolve()` is now the one place that turns a typed identifier
into device + lease(s) + reservation(s) + v6 addresses; `authorize()` is
the one place that applies one of the three subnet policies
docs/ARCHITECTURE.md §2 names.

`detect_kind()` and `authorize()` are pure — no I/O — and unit-tested
without a database. `resolve()` is DB-backed: real queries against
jen_db/kea_db, the same tables and shapes timeline.py/explain.py already
used, each moved here as its own small public function (`load_device`,
`load_leases4`, `load_reservations4`, ...) so a caller with its own
identifier shape (Explain's separate mac + client-id fields) can call the
loader it needs directly instead of going through `resolve()`'s
single-identifier convenience wrapper.
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

import jen.models.db as __db

logger = logging.getLogger(__name__)

# ── Identifier kind detection (pure) ────────────────────────────────────────────

_SEPARATORS_RE = re.compile(r"[:\-. ]")
_HOST_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)


def _hex_body(raw: str) -> str:
    """`raw` with any of `:-. ` separators stripped, or "" if what's left
    isn't purely hex digits (so a hostname like "printer-1" never reads as
    hex just because "1" is a hex digit)."""
    body = _SEPARATORS_RE.sub("", raw)
    return body if body and all(c in "0123456789abcdefABCDEF" for c in body) else ""


def detect_kind(identifier: str) -> tuple[str, str]:
    """(kind, normalized) for a raw, user-typed identifier. `kind` is one
    of "mac" / "ipv4" / "ipv6" / "duid" / "hostname" / "unknown".

    MAC: any separator (colon, hyphen, dot-grouped, or none) over exactly
    12 hex digits, normalized to `aa:bb:cc:dd:ee:ff`. DUID: an explicit
    `duid:` prefix, or bare/separated hex longer than a MAC's 12 digits
    (a MAC is exactly 6 bytes; every real DUID type is longer). IPv4/IPv6:
    `ipaddress.ip_address`. Anything else that looks like a hostname
    (RFC 1123 label shape) falls back to "hostname"; otherwise "unknown".
    """
    raw = (identifier or "").strip()
    if not raw:
        return "unknown", ""

    if raw.lower().startswith("duid:"):
        body = _hex_body(raw[5:])
        return ("duid", body.lower()) if body else ("unknown", raw)

    try:
        addr = ipaddress.ip_address(raw)
        return ("ipv6", raw) if addr.version == 6 else ("ipv4", raw)
    except ValueError:
        pass

    body = _hex_body(raw)
    if body and len(body) == 12:
        return "mac", ":".join(body[i : i + 2] for i in range(0, 12, 2)).lower()
    if body and len(body) > 12 and len(body) % 2 == 0:
        return "duid", body.lower()

    if len(raw) <= 253 and _HOST_RE.match(raw):
        return "hostname", raw.lower()
    return "unknown", raw


def mac_hex(mac: str) -> str:
    return mac.replace(":", "").upper()


def hex_to_mac(hexed: str) -> str:
    return ":".join(hexed[i : i + 2] for i in range(0, 12, 2)).lower() if hexed and len(hexed) == 12 else ""


_hex_to_mac = hex_to_mac  # internal alias used throughout this module


# ── ClientSubject ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ClientSubject:
    kind: str  # "mac" | "ipv4" | "ipv6" | "duid" | "hostname" | "unknown"
    identifier: str = ""  # the raw, as-typed identifier
    mac: str = ""
    ip: str = ""
    duid: str = ""
    hostname: str = ""
    leases4: list = field(default_factory=list)
    leases6: list = field(default_factory=list)
    reservations: list = field(default_factory=list)
    reservations6: list = field(default_factory=list)
    device: dict | None = None
    subnet_ids: frozenset = field(default_factory=frozenset)
    holder_mac: str = ""
    previous_holders: list = field(default_factory=list)
    candidates: list = field(default_factory=list)  # ambiguous hostname lookups
    fetched_at: dict = field(default_factory=dict)
    config_sha: str = ""

    @property
    def lease(self) -> dict | None:
        """The newest active v4 lease, or None — the single-object shape
        every pre-Q82 caller (Timeline, Explain, the API) used."""
        return self.leases4[0] if self.leases4 else None

    @property
    def reservation(self) -> dict | None:
        """The first v4 reservation, or None — same single-object shape."""
        return self.reservations[0] if self.reservations else None

    @property
    def found(self) -> bool:
        return bool(self.device or self.leases4 or self.reservations or self.candidates)

    def with_fetched(self, **stamps) -> "ClientSubject":
        """A copy with `fetched_at` merged (frozen dataclass — callers
        that do their own separate lookup, e.g. the Kea config for the
        Config tab, stamp it in after the fact)."""
        merged = dict(self.fetched_at)
        merged.update(stamps)
        return replace(self, fetched_at=merged)


class ClientNotAuthorized(Exception):
    """Raised by `authorize()` for the two whole-subject policies
    (`all_known`, `unrestricted`) when the caller doesn't qualify. Routes
    catch it and abort(403) with `.reason` as the message."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# ── DB-backed loaders (timeline.py's/explain.py's own queries, moved here
#    so every caller uses exactly the same SQL — public: Explain and
#    Trace call these directly for their own dual-identifier lookups
#    rather than going through resolve()'s single-identifier model) ─────────


def load_device(mac: str) -> dict | None:
    if not mac:
        return None
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT mac, device_name, owner, notes, first_seen, last_seen, last_ip, last_hostname, "
                "last_subnet_id FROM devices WHERE mac=%s",
                (mac,),
            )
            return cur.fetchone()
    except Exception as e:
        logger.error(f"client_subject: device lookup failed for mac={mac!r}: {e}")
        return None


def load_leases4(mac: str, ip: str = "") -> list[dict]:
    """Every active (state=0) v4 lease for this identifier — MAC first, or
    the single lease at this address when only an IP is known — newest
    first."""
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            if mac:
                cur.execute(
                    "SELECT inet_ntoa(address) AS ip, subnet_id, IFNULL(hostname,'') AS hostname, expire, "
                    "valid_lifetime FROM lease4 WHERE HEX(hwaddr)=%s AND state=0 ORDER BY expire DESC",
                    (mac_hex(mac),),
                )
            else:
                cur.execute(
                    "SELECT inet_ntoa(address) AS ip, subnet_id, IFNULL(hostname,'') AS hostname, expire, "
                    "valid_lifetime FROM lease4 WHERE address=inet_aton(%s) AND state=0",
                    (ip,),
                )
            return cur.fetchall()
    except Exception as e:
        logger.error(f"client_subject: lease4 lookup failed for mac={mac!r} ip={ip!r}: {e}")
        return []


def load_reservations4(hw_hex: str = "", cid_hex: str = "") -> list[dict]:
    """Host-DB reservations matching either identifier — Explain's own
    dual match (hw-address OR client-id), moved here verbatim so it isn't
    duplicated between Explain and this module."""
    if not hw_hex and not cid_hex:
        return []
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT host_id, dhcp4_subnet_id AS subnet_id, dhcp_identifier_type AS identifier_type, "
                "HEX(dhcp_identifier) AS identifier, inet_ntoa(ipv4_address) AS ip, hostname, dhcp4_client_classes "
                "FROM hosts WHERE (HEX(dhcp_identifier)=%s AND dhcp_identifier_type=0) "
                "OR (HEX(dhcp_identifier)=%s AND dhcp_identifier_type=3)",
                (hw_hex or "", cid_hex or ""),
            )
            rows = []
            for r in cur.fetchall():
                classes = [c.strip() for c in str(r.get("dhcp4_client_classes") or "").split(",") if c.strip()]
                cur.execute(
                    "SELECT code, formatted_value, HEX(value) AS value_hex FROM dhcp4_options WHERE host_id=%s",
                    (r["host_id"],),
                )
                options = [
                    {
                        "code": o["code"],
                        "data": o["formatted_value"] if o["formatted_value"] else (o["value_hex"] or ""),
                    }
                    for o in cur.fetchall()
                ]
                rows.append(
                    {
                        "subnet_id": r["subnet_id"] or 0,
                        "identifier_type": int(r["identifier_type"] or 0),
                        "identifier": (r["identifier"] or "").lower(),
                        "ip": r["ip"],
                        "hostname": r["hostname"] or "",
                        "classes": classes,
                        "options": options,
                        "source": "host database",
                    }
                )
            return rows
    except Exception as e:
        logger.error(f"client_subject: reservation lookup failed for hw_hex={hw_hex!r}: {e}")
        return []


def load_leases6(mac: str, accessible_v4_ids=None) -> list[dict]:
    """This client's v6 addresses — only ones Kea captured a real hwaddr
    for (never Jen's own DUID guess), same rule as Devices/Timeline. When
    `accessible_v4_ids` is given, an address is kept only when its v6
    subnet is paired to one of them (the Devices-page rule)."""
    if not mac:
        return []
    try:
        from jen.services import kea6 as __kea6

        if not __kea6.is_ipv6_enabled():
            return []
        addrs = __kea6.lease6_by_hwaddr_mac().get(mac, [])
        if accessible_v4_ids is not None:
            from jen import extensions

            def visible(a):
                info = extensions.SUBNET6_MAP.get(a.get("subnet_id"))
                paired = info.get("paired_subnet4_id") if info else None
                return paired is not None and paired in accessible_v4_ids

            addrs = [a for a in addrs if visible(a)]
        return addrs
    except Exception as e:
        logger.error(f"client_subject: v6 lease lookup failed for mac={mac!r}: {e}")
        return []


def mac_from_ip(ip: str) -> str:
    """The active lease's MAC for this IP, or '' — who currently holds
    this address (an IP subject's `holder_mac`)."""
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute("SELECT HEX(hwaddr) AS mac_hex FROM lease4 WHERE address=inet_aton(%s) AND state=0", (ip,))
            row = cur.fetchone()
    except Exception:
        return ""
    return _hex_to_mac(row["mac_hex"]) if row and row.get("mac_hex") else ""


def previous_holders_for_ip(ip: str, exclude_mac: str) -> list[str]:
    """Every OTHER MAC the `events` table has ever recorded at this
    address — an IP subject's history, excluding whoever holds it now."""
    if not ip:
        return []
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT mac FROM events WHERE ip=%s AND mac IS NOT NULL AND mac != '' ORDER BY mac",
                (ip,),
            )
            return sorted({(r["mac"] or "").lower() for r in cur.fetchall()} - {exclude_mac.lower()})
    except Exception as e:
        logger.error(f"client_subject: previous-holder lookup failed for ip={ip!r}: {e}")
        return []


def macs_for_hostname(hostname: str, accessible_ids=None) -> set[str]:
    """Every distinct MAC currently associated with `hostname`, across the
    three places a hostname can live: an active lease, a reservation, or
    Jen's own device tracking.

    v5.65.2 (Q91) - `accessible_ids` is `None` for an unrestricted caller, else
    the set of v4 subnet ids they may see, and EVERY source is filtered by it: a
    row in a subnet the caller cannot see contributes no MAC (a row with no
    subnet at all is for unrestricted callers only). This used to be unfiltered,
    so `/client?q=printer` handed a subnet-scoped admin the MACs of every
    `printer` in the fleet. Each statement is fixed SQL and the subnet is judged in
    Python, so no query text is built from the id list."""
    ids = None if accessible_ids is None else {int(i) for i in accessible_ids}

    def keep(subnet_id) -> bool:
        if ids is None:
            return True
        try:
            return subnet_id is not None and int(subnet_id) in ids
        except (TypeError, ValueError):
            return False

    macs: set[str] = set()
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute("SELECT HEX(hwaddr) AS h, subnet_id FROM lease4 WHERE hostname=%s AND state=0", (hostname,))
            macs |= {_hex_to_mac(r["h"]) for r in cur.fetchall() if r["h"] and keep(r["subnet_id"])}
            cur.execute(
                "SELECT HEX(dhcp_identifier) AS h, dhcp4_subnet_id AS subnet_id FROM hosts "
                "WHERE hostname=%s AND dhcp_identifier_type=0",
                (hostname,),
            )
            macs |= {_hex_to_mac(r["h"]) for r in cur.fetchall() if r["h"] and keep(r["subnet_id"])}
    except Exception as e:
        logger.error(f"client_subject: hostname lease/reservation lookup failed for {hostname!r}: {e}")
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT mac, last_subnet_id FROM devices WHERE last_hostname=%s OR device_name=%s",
                (hostname, hostname),
            )
            macs |= {r["mac"].lower() for r in cur.fetchall() if r["mac"] and keep(r["last_subnet_id"])}
    except Exception as e:
        logger.error(f"client_subject: hostname device lookup failed for {hostname!r}: {e}")
    return {m for m in macs if m}


# ── resolve() ────────────────────────────────────────────────────────────────


def resolve(identifier: str, *, accessible_ids=None, all_subnets: bool = True, now=None) -> ClientSubject:
    """Turn a typed identifier into a `ClientSubject`. `accessible_ids` is
    `None` for an unrestricted caller, else the set of v4 subnet ids they
    may see — used only for the v6-pairing rule here. Visibility of what's
    found is left entirely to `authorize()`: `resolve()` always finds the
    real objects; deciding what the caller may be TOLD about them is
    `authorize()`'s job alone, so the same resolved subject can be
    authorized under different rules by different callers (e.g. Trace vs.
    Timeline) without two different lookups."""
    now = now or datetime.now(timezone.utc)

    kind, normalized = detect_kind(identifier)

    if kind == "hostname":
        macs = macs_for_hostname(normalized, accessible_ids)
        if len(macs) > 1:
            return ClientSubject(
                kind="hostname",
                identifier=identifier,
                hostname=normalized,
                candidates=[{"mac": m, "hostname": normalized} for m in sorted(macs)],
                fetched_at={"device": now, "leases": now, "reservations": now},
            )
        if len(macs) == 1:
            kind, normalized = "mac", next(iter(macs))
        else:
            return ClientSubject(
                kind="hostname",
                identifier=identifier,
                hostname=normalized,
                fetched_at={"device": now, "leases": now, "reservations": now},
            )

    if kind == "mac":
        mac = normalized
        device = load_device(mac)
        t_device = datetime.now(timezone.utc)
        leases4 = load_leases4(mac)
        t_leases = datetime.now(timezone.utc)
        reservations = load_reservations4(mac_hex(mac))
        t_res = datetime.now(timezone.utc)
        leases6 = load_leases6(mac, accessible_ids)
        ip = (leases4[0]["ip"] if leases4 else "") or ((device or {}).get("last_ip") or "")
        subnet_ids = {
            *([device["last_subnet_id"]] if device and device.get("last_subnet_id") else []),
            *(row["subnet_id"] for row in leases4 if row.get("subnet_id")),
            *(row["subnet_id"] for row in reservations if row.get("subnet_id")),
        }
        return ClientSubject(
            kind="mac",
            identifier=identifier,
            mac=mac,
            ip=ip,
            hostname=(leases4[0]["hostname"] if leases4 else "") or ((device or {}).get("last_hostname") or ""),
            leases4=leases4,
            leases6=leases6,
            reservations=reservations,
            device=device,
            subnet_ids=frozenset(subnet_ids),
            fetched_at={"device": t_device, "leases": t_leases, "reservations": t_res},
        )

    if kind == "ipv4":
        ip = normalized
        holder = mac_from_ip(ip)
        t_leases = datetime.now(timezone.utc)
        leases4 = load_leases4("", ip)
        device = load_device(holder) if holder else None
        t_device = datetime.now(timezone.utc)
        reservations = load_reservations4(mac_hex(holder)) if holder else []
        t_res = datetime.now(timezone.utc)
        previous = previous_holders_for_ip(ip, holder)
        leases6 = load_leases6(holder, accessible_ids) if holder else []
        subnet_ids = {
            *([device["last_subnet_id"]] if device and device.get("last_subnet_id") else []),
            *(row["subnet_id"] for row in leases4 if row.get("subnet_id")),
            *(row["subnet_id"] for row in reservations if row.get("subnet_id")),
        }
        return ClientSubject(
            kind="ipv4",
            identifier=identifier,
            mac=holder,
            ip=ip,
            hostname=(leases4[0]["hostname"] if leases4 else "") or ((device or {}).get("last_hostname") or ""),
            leases4=leases4,
            leases6=leases6,
            reservations=reservations,
            device=device,
            subnet_ids=frozenset(subnet_ids),
            holder_mac=holder,
            previous_holders=previous,
            fetched_at={"device": t_device, "leases": t_leases, "reservations": t_res},
        )

    # ipv6 / duid / unknown — not yet backed by a real lookup; returned as
    # an honestly-empty subject rather than guessing. The Investigation
    # page (step 2) shows "nothing found" the same way it does for a MAC
    # or IP that resolves to nothing.
    return ClientSubject(
        kind=kind,
        identifier=identifier,
        ip=normalized if kind == "ipv6" else "",
        duid=normalized if kind == "duid" else "",
        fetched_at={"device": now, "leases": now, "reservations": now},
    )


# ── authorize() ──────────────────────────────────────────────────────────────


def _subnet_ok(subnet_id, accessible_ids) -> bool:
    try:
        return subnet_id is not None and int(subnet_id) in accessible_ids
    except (TypeError, ValueError):
        return False


def _is_global(row) -> bool:
    """A reservation with no subnet (Kea's global reservation): nothing to restrict it on."""
    try:
        return int(row.get("subnet_id") or 0) == 0
    except (TypeError, ValueError):
        return False


def _names_a_subnet(view: "ClientSubject") -> bool:
    """Did anything survive that places this client in a subnet (the question Timeline asks)."""
    from jen.services.timeline import subnet_id_for

    return subnet_id_for(view.device, view.lease, view.reservation) is not None


def authorize(
    subject: ClientSubject, *, rule: str, accessible_ids=None, all_subnets: bool = True, resolver=None
) -> ClientSubject:
    """The view `subject` a caller may see under one of three policies
    (docs/ARCHITECTURE.md §2):

    * `per_object` — each object (device/lease/reservation) is judged on
      its OWN subnet independently, the Q55/Q56 "moved client" rule; an
      unrestricted caller (`accessible_ids is None`) gets `subject` back
      unchanged. Never raises — an object that isn't accessible is simply
      dropped from the view, the same as Timeline/the API have always done.
      v5.65.2 (Q91): EVERYTHING the resolver derived is judged, not just the
      three object lists — the MAC a typed address resolved to, `holder_mac`,
      `previous_holders`, `subnet_ids`, and each hostname candidate (resolved
      and judged like a subject of its own; `resolver` overrides `resolve`
      for tests). A global reservation (no subnet) is kept for everyone.
    * `all_known` — the subject qualifies only when EVERY subnet it is
      known in (`subject.subnet_ids`) is accessible; raises
      `ClientNotAuthorized` otherwise. A subject with no known subnet at
      all (never leased or reserved) requires `all_subnets`, the same as
      an unattributed device does elsewhere.
    * `unrestricted` — the caller needs `all_subnets` outright, regardless
      of this particular client (Trace, Doctor, config history); raises
      `ClientNotAuthorized` otherwise.
    """
    if rule == "per_object":
        if accessible_ids is None:
            return subject
        ids = {int(i) for i in accessible_ids}
        leases4 = [row for row in subject.leases4 if _subnet_ok(row.get("subnet_id"), ids)]
        reservations = [row for row in subject.reservations if _subnet_ok(row.get("subnet_id"), ids) or _is_global(row)]
        device = subject.device
        if device and not _subnet_ok(device.get("last_subnet_id"), ids):
            from jen.services.access import _DEVICE_PLACEMENT_FIELDS

            device = {**device, **dict.fromkeys(_DEVICE_PLACEMENT_FIELDS)}
        mac, holder_mac = subject.mac, subject.holder_mac
        previous, leases6 = list(subject.previous_holders), subject.leases6
        if subject.kind == "ipv4" and not leases4:
            # v5.65.2 (Q91) - the client holding a typed address was found through a lease in a subnet
            # the caller cannot see. Its MAC, its device, its reservations, its v6 addresses and the
            # MACs that held the address before are all derived from that lease, so none of them may
            # show; the address alone is what the caller typed.
            mac = holder_mac = ""
            device = None
            reservations = []
            leases6 = []
            previous = []
        # v5.63.0 (Q82) fix — `ip`/`hostname` were set from the UNFILTERED
        # leases4/device during resolve() and, unlike device/leases4/
        # reservations above, were never recomputed here: a MAC subject
        # whose only lease sat in an inaccessible subnet kept showing that
        # lease's IP even after the lease itself was correctly dropped from
        # `leases4` — a real leak, caught by the moved-client fixture run
        # against the Investigation page. `ip` is only ever DERIVED for a
        # "mac"-kind subject; an "ipv4"-kind subject's `ip` is the identifier
        # the caller already typed, never overwritten (matching
        # build_timeline's own `supplied_ip` guard).
        hostname = (leases4[0].get("hostname") if leases4 else "") or ((device or {}).get("last_hostname") or "")
        ip = subject.ip
        if subject.kind == "mac":
            ip = (leases4[0].get("ip") if leases4 else "") or ((device or {}).get("last_ip") or "")
        candidates = []
        if subject.candidates:
            resolve_fn = resolver or resolve
            for cand in subject.candidates:
                judged = authorize(
                    resolve_fn(cand["mac"], accessible_ids=ids, all_subnets=False),
                    rule="per_object",
                    accessible_ids=ids,
                )
                if _names_a_subnet(judged):
                    candidates.append(cand)
        return replace(
            subject,
            device=device,
            leases4=leases4,
            leases6=leases6,
            reservations=reservations,
            ip=ip,
            hostname=hostname,
            mac=mac,
            holder_mac=holder_mac,
            previous_holders=previous,
            subnet_ids=frozenset(i for i in subject.subnet_ids if _subnet_ok(i, ids)),
            candidates=candidates,
        )

    if rule == "all_known":
        if all_subnets:
            return subject
        if not subject.subnet_ids:
            raise ClientNotAuthorized("This client has no known subnet, and you don't have access to all subnets.")
        if not subject.subnet_ids.issubset(set(accessible_ids or ())):
            raise ClientNotAuthorized("You do not have access to every subnet this client is known in.")
        return subject

    if rule == "unrestricted":
        if not all_subnets:
            raise ClientNotAuthorized("This view needs access to all subnets.")
        return subject

    raise ValueError(f"unknown authorize() rule: {rule!r}")
