"""
jen/services/kea_log_trace.py
──────────────────────────────
v5.48.0 (Q49) — "what actually happened to this client": parse kea-dhcp4's
own log for the lines that name one MAC, translate each message id into
plain English, and group them into DISCOVER/OFFER/REQUEST/ACK exchanges.
Pure — the caller tails the log (helper op `tail-log`) and hands the
lines in. Nothing here captures packets or needs any new privilege.

The message ids below were checked against ISC's own
src/bin/dhcp4/dhcp4_messages.mes and dhcp4_srv.cc at tag Kea-3.0.0
(the log LEVEL of each is noted, because a server at Kea's default INFO
never emits the DEBUG ones), not written from memory. Ids this module
does NOT list simply render as their raw text — an unknown id is shown,
never dropped or guessed at.

Log line shape (Kea's default pattern):
    2026-09-19 10:00:00.123 INFO  [kea-dhcp4.lease4-logger/1234.140] \
DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[01:aa:..], \
tid=0x1a2b: lease 10.0.0.5 has been allocated for 3600 seconds
"""

from __future__ import annotations

import re
from datetime import datetime

# Gap between consecutive events above which a new exchange starts.
EXCHANGE_GAP_SECONDS = 2.0

_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<level>[A-Z]+)\s+\[[^\]]*\]\s+"
    r"(?P<id>DHCP4_[A-Z0-9_]+)\s*(?P<rest>.*)$"
)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_LEASE_RE = re.compile(r"lease (\d{1,3}(?:\.\d{1,3}){3})")
_ADDR_RE = re.compile(r"(?:address|addr) (\d{1,3}(?:\.\d{1,3}){3})")
_SUBNET_ID_RE = re.compile(r"subnet with ID (\d+)")
_PKT_RE = re.compile(r": (DHCP[A-Z]+) \(type \d+\) received from (\S+)")
_SEND_RE = re.compile(r"packet (DHCP[A-Z]+) \(type \d+\)")
_SECS_RE = re.compile(r"for (\d+) seconds")
_HINT_RE = re.compile(r"hint=(\S+)")

# id -> (log level Kea emits it at, outcome tag). Outcome drives grouping
# and the badge colour; "info" is context that decides nothing.
MESSAGES: dict[str, tuple[str, str]] = {
    "DHCP4_PACKET_RECEIVED": ("INFO", "received"),
    "DHCP4_PACKET_SEND": ("INFO", "sent"),
    "DHCP4_LEASE_OFFER": ("INFO", "offer"),
    "DHCP4_LEASE_ALLOC": ("INFO", "ack"),
    "DHCP4_LEASE_REUSE": ("INFO", "ack"),
    "DHCP4_INIT_REBOOT": ("INFO", "info"),
    "DHCP4_RELEASE": ("INFO", "release"),
    "DHCP4_RELEASE_EXPIRED": ("INFO", "release"),
    "DHCP4_RELEASE_DELETED": ("INFO", "release"),
    "DHCP4_RELEASE_FAIL": ("ERROR", "problem"),
    "DHCP4_RELEASE_FAIL_NO_LEASE": ("DEBUG", "problem"),
    "DHCP4_RELEASE_FAIL_WRONG_CLIENT": ("DEBUG", "problem"),
    "DHCP4_DECLINE_LEASE": ("INFO", "decline"),
    "DHCP4_DECLINE_LEASE_MISMATCH": ("WARN", "problem"),
    "DHCP4_DECLINE_LEASE_NOT_FOUND": ("WARN", "problem"),
    "DHCP4_PACKET_NAK_0001": ("ERROR", "nak"),
    "DHCP4_PACKET_NAK_0002": ("DEBUG", "nak"),
    "DHCP4_PACKET_NAK_0003": ("DEBUG", "nak"),
    "DHCP4_PACKET_NAK_0004": ("DEBUG", "nak"),
    "DHCP4_DISCOVER": ("DEBUG", "info"),
    "DHCP4_REQUEST": ("DEBUG", "info"),
    "DHCP4_SUBNET_SELECTED": ("DEBUG", "info"),
    "DHCP4_SUBNET_SELECTION_FAILED": ("DEBUG", "problem"),
    "DHCP4_CLIENT_FQDN_DATA": ("DEBUG", "info"),
    "DHCP4_CLIENT_FQDN_PROCESS": ("DEBUG", "info"),
    "DHCP4_CLASS_ASSIGNED": ("DEBUG", "info"),
    "DHCP4_CLASSES_ASSIGNED": ("DEBUG", "info"),
    "DHCP4_PACKET_DROP_0007": ("DEBUG", "problem"),
    "DHCP4_PACKET_DROP_0008": ("DEBUG", "problem"),
    "DHCP4_DDNS_REQUEST_SEND_FAILED": ("ERROR", "problem"),
}

# What a server at each log level can and cannot show for this trace.
DEBUG_ONLY_IDS = sorted(i for i, (lvl, _o) in MESSAGES.items() if lvl == "DEBUG")


def norm_mac(mac: str) -> str:
    body = "".join(ch for ch in (mac or "").lower() if ch in "0123456789abcdef")
    return ":".join(body[i : i + 2] for i in range(0, len(body), 2)) if len(body) == 12 else ""


def _parse_ts(text: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _summarize(msg_id: str, rest: str) -> tuple[str, str]:
    """(plain-English summary, ip or '') for one message. `rest` is the
    text after the id (label + ': ' + the message body)."""
    ip = ""
    if msg_id == "DHCP4_PACKET_RECEIVED":
        m = _PKT_RE.search(rest)
        return (f"{m.group(1)} received from {m.group(2)}" if m else "packet received"), ip
    if msg_id == "DHCP4_PACKET_SEND":
        m = _SEND_RE.search(rest)
        return (f"{m.group(1)} sent" if m else "packet sent"), ip
    if msg_id in ("DHCP4_LEASE_OFFER", "DHCP4_LEASE_ALLOC", "DHCP4_LEASE_REUSE"):
        m = _LEASE_RE.search(rest)
        ip = m.group(1) if m else ""
        secs = _SECS_RE.search(rest)
        if msg_id == "DHCP4_LEASE_OFFER":
            return f"offered {ip}", ip
        verb = "reused" if msg_id == "DHCP4_LEASE_REUSE" else "allocated"
        return f"{verb} {ip}" + (f" for {secs.group(1)} s" if secs else ""), ip
    if msg_id == "DHCP4_INIT_REBOOT":
        m = _ADDR_RE.search(rest)
        ip = m.group(1) if m else ""
        return f"client is rebooting and asks for {ip}".strip(), ip
    if msg_id.startswith("DHCP4_RELEASE"):
        m = _ADDR_RE.search(rest)
        ip = m.group(1) if m else ""
        return {
            "DHCP4_RELEASE": f"released {ip}",
            "DHCP4_RELEASE_EXPIRED": f"released {ip} (already expired)",
            "DHCP4_RELEASE_DELETED": f"released {ip} (lease deleted)",
            "DHCP4_RELEASE_FAIL": f"release of {ip} failed",
            "DHCP4_RELEASE_FAIL_NO_LEASE": f"tried to release {ip}, which has no lease",
            "DHCP4_RELEASE_FAIL_WRONG_CLIENT": f"tried to release {ip}, which belongs to a different client",
        }.get(msg_id, f"release problem for {ip}"), ip
    if msg_id.startswith("DHCP4_DECLINE_LEASE"):
        m = _ADDR_RE.search(rest)
        ip = m.group(1) if m else ""
        if msg_id == "DHCP4_DECLINE_LEASE":
            return f"client declined {ip} (address conflict?) — Kea keeps it out of service for a while", ip
        return (
            f"decline of {ip} did not match the lease" if "MISMATCH" in msg_id else f"decline of {ip}: no such lease",
            ip,
        )
    if msg_id == "DHCP4_PACKET_NAK_0001":
        return "NAK: Kea could not select a subnet for this packet (relay/interface not matching any subnet)", ip
    if msg_id == "DHCP4_PACKET_NAK_0002":
        m = _ADDR_RE.search(rest)
        ip = m.group(1) if m else ""
        return f"NAK: INIT-REBOOT address {ip} is not valid here", ip
    if msg_id in ("DHCP4_PACKET_NAK_0003", "DHCP4_PACKET_NAK_0004"):
        what = "offer" if msg_id.endswith("0003") else "grant"
        return f"NAK: Kea could not {what} a lease (requested address not usable in the selected subnet)", ip
    if msg_id == "DHCP4_DISCOVER":
        h = _HINT_RE.search(rest)
        return "processing DISCOVER" + (f" (hint {h.group(1)})" if h else ""), ip
    if msg_id == "DHCP4_REQUEST":
        h = _HINT_RE.search(rest)
        return "processing REQUEST" + (f" (hint {h.group(1)})" if h else ""), ip
    if msg_id == "DHCP4_SUBNET_SELECTED":
        m = _SUBNET_ID_RE.search(rest)
        return f"subnet {m.group(1)} selected" if m else "subnet selected", ip
    if msg_id == "DHCP4_SUBNET_SELECTION_FAILED":
        return "no subnet could be selected for this client", ip
    if msg_id == "DHCP4_DDNS_REQUEST_SEND_FAILED":
        return "sending a DNS update request to kea-dhcp-ddns failed", ip
    if msg_id.startswith("DHCP4_PACKET_DROP"):
        return "packet dropped", ip
    if msg_id.startswith("DHCP4_CLIENT_FQDN"):
        return "client FQDN option processed", ip
    if msg_id.startswith("DHCP4_CLASS"):
        return "client class assigned", ip
    return rest.split(":", 1)[-1].strip()[:200], ip


def parse_lines(lines: list[str], mac: str, client_id: str = "") -> list[dict]:
    """Events for `mac` (and/or `client_id`, hex with or without colons)
    from kea-dhcp4 log `lines`, in log order:
    `{ts, level, id, kind, summary, ip, raw}`. `kind` is the outcome tag
    from MESSAGES ("unknown" for an id this module doesn't list).

    Lines that name the MAC are kept. One exception: a
    DHCP4_DDNS_REQUEST_SEND_FAILED line carries no client label at all,
    so it is attached only when it mentions an IP this client was
    offered/allocated elsewhere in the same lines."""
    needle_mac = norm_mac(mac)
    needle_cid = "".join(ch for ch in (client_id or "").lower() if ch in "0123456789abcdef")
    if not needle_mac and not needle_cid:
        return []

    parsed: list[dict] = []
    for raw in lines:
        m = _LINE_RE.match(raw.strip())
        if not m:
            continue
        parsed.append({"m": m, "raw": raw.rstrip(), "low": raw.lower()})

    def _names_client(low: str) -> bool:
        if needle_mac and needle_mac in low:
            return True
        return bool(needle_cid) and needle_cid in low.replace(":", "").replace(" ", "")

    events: list[dict] = []
    own_ips: set[str] = set()
    for p in parsed:
        if not _names_client(p["low"]):
            continue
        msg_id = p["m"].group("id")
        level, kind = MESSAGES.get(msg_id, (p["m"].group("level"), "unknown"))
        summary, ip = _summarize(msg_id, p["m"].group("rest"))
        if ip:
            own_ips.add(ip)
        events.append(
            {
                "ts": _parse_ts(p["m"].group("ts")),
                "level": p["m"].group("level"),
                "id": msg_id,
                "kind": kind,
                "summary": summary,
                "ip": ip,
                "raw": p["raw"],
            }
        )
    for p in parsed:
        if p["m"].group("id") != "DHCP4_DDNS_REQUEST_SEND_FAILED" or _names_client(p["low"]):
            continue
        if own_ips & set(_IP_RE.findall(p["m"].group("rest"))):
            summary, ip = _summarize("DHCP4_DDNS_REQUEST_SEND_FAILED", p["m"].group("rest"))
            events.append(
                {
                    "ts": _parse_ts(p["m"].group("ts")),
                    "level": p["m"].group("level"),
                    "id": "DHCP4_DDNS_REQUEST_SEND_FAILED",
                    "kind": "problem",
                    "summary": summary,
                    "ip": ip,
                    "raw": p["raw"],
                }
            )
    events.sort(key=lambda e: (e["ts"] is None, e["ts"] or datetime.min))
    return events


_OUTCOME_ORDER = ("nak", "decline", "release", "ack", "offer")


def group_exchanges(events: list[dict], gap: float = EXCHANGE_GAP_SECONDS) -> list[dict]:
    """Group `events` (already time-ordered) into exchanges: a new one
    starts when the gap to the previous event is >= `gap` seconds.
    Each: `{start, end, events, outcome, ip}`. `outcome` is the most
    decisive tag present (nak > decline > release > ack > offer), else
    "activity"; `ip` is the last address any event named."""
    groups: list[dict] = []
    for ev in events:
        last = groups[-1] if groups else None
        if last is None or ev["ts"] is None or last["end"] is None or (ev["ts"] - last["end"]).total_seconds() >= gap:
            groups.append({"start": ev["ts"], "end": ev["ts"], "events": [], "outcome": "activity", "ip": ""})
            last = groups[-1]
        last["events"].append(ev)
        last["end"] = ev["ts"] or last["end"]
        if ev["ip"]:
            last["ip"] = ev["ip"]
    for g in groups:
        kinds = {e["kind"] for e in g["events"]}
        g["outcome"] = next((k for k in _OUTCOME_ORDER if k in kinds), "activity")
    return groups


def visibility_note(events_seen: list[dict], lines_scanned: int) -> str:
    """One honest sentence about what this trace can and can't see."""
    debug_seen = any(e["level"] == "DEBUG" for e in events_seen)
    if debug_seen:
        return f"Scanned {lines_scanned} log lines — this server logs at DEBUG, so DISCOVER/REQUEST detail is included."
    return (
        f"Scanned {lines_scanned} log lines. No DEBUG-level lines for this client were seen: at Kea's default INFO level "
        "the log shows packets received/sent, offers, allocations, releases, declines and errors, but not "
        "DISCOVER/REQUEST processing, subnet selection or most NAK reasons (those are DEBUG)."
    )
