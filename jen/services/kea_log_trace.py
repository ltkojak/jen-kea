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

import posixpath
import re
from datetime import datetime

from jen import extensions
from jen.services import kea_config_edit as _edit

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
# and the badge color; "info" is context that decides nothing.
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


# ── Problems across every client (v5.68.0-beta.5, Q140) ───────────────────────────────────────────────────────────────────
#
# parse_lines() above answers "what happened to THIS client". The Problems inbox asks the opposite question of the same lines -
# "which clients had trouble?" - so the extractor below reads the problem messages and takes the client from each line's own
# label ("[hwtype=1 aa:bb:cc:dd:ee:ff]") instead of from a MAC it was handed. Pure, like everything here.

_LABEL_MAC_RE = re.compile(r"\[hwtype=\d+ (?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\]")
_TID_RE = re.compile(r"\btid=(0x[0-9a-fA-F]+)")
_REQ_IP_RE = re.compile(r"requested-ip-address (\d{1,3}(?:\.\d{1,3}){3})")

# the five kinds Kea's own log can name a client for (the two database-derived kinds need no log)
LOG_PROBLEM_KINDS = ("nak", "decline", "drop", "subnet-selection-failed", "ddns-failed")

_PROBLEM_KIND_OF_ID = {
    "DHCP4_PACKET_NAK_0001": "nak",
    "DHCP4_PACKET_NAK_0002": "nak",
    "DHCP4_PACKET_NAK_0003": "nak",
    "DHCP4_PACKET_NAK_0004": "nak",
    "DHCP4_DECLINE_LEASE": "decline",
    "DHCP4_DECLINE_LEASE_MISMATCH": "decline",
    "DHCP4_DECLINE_LEASE_NOT_FOUND": "decline",
    "DHCP4_PACKET_DROP_0007": "drop",
    "DHCP4_PACKET_DROP_0008": "drop",
    "DHCP4_SUBNET_SELECTION_FAILED": "subnet-selection-failed",
    "DHCP4_DDNS_REQUEST_SEND_FAILED": "ddns-failed",
}


def _client_ip(msg_id: str, rest: str) -> str:
    """The CLIENT's address when the line names one (a requested or declined or allocated address) - never one of the
    addresses on a "from 10.1.0.218:67 to 10.99.0.1:67" line, which are Kea's and its relay's."""
    if msg_id == "DHCP4_PACKET_SEND":
        return ""
    for rx in (_REQ_IP_RE, _ADDR_RE, _LEASE_RE):
        m = rx.search(rest)
        if m:
            return m.group(1)
    return ""


def newest_ts(lines: list[str]) -> datetime | None:
    """The newest timestamp on any DHCP4_ line of `lines`, in the log's own clock (None when there is none)."""
    best = None
    for raw in lines:
        m = _LINE_RE.match(raw.strip())
        ts = _parse_ts(m.group("ts")) if m else None
        if ts is not None and (best is None or ts > best):
            best = ts
    return best


def allocations(lines: list[str]) -> list[dict]:
    """The lease allocations the log shows, in log order: `{ts, ip, seconds}` - `DHCP4_LEASE_ALLOC` / `DHCP4_LEASE_REUSE` lines
    ("lease 10.0.0.5 has been allocated for 3600 seconds"). The Problems sweep matches them to the lease database's `expire` to
    learn the Kea host's clock offset (jen.services.client_problems.clock_offset)."""
    out = []
    for raw in lines:
        m = _LINE_RE.match(raw.strip())
        if not m or m.group("id") not in ("DHCP4_LEASE_ALLOC", "DHCP4_LEASE_REUSE"):
            continue
        ts, lease, secs = _parse_ts(m.group("ts")), _LEASE_RE.search(m.group("rest")), _SECS_RE.search(m.group("rest"))
        if ts is not None and lease and secs:
            out.append({"ts": ts, "ip": lease.group(1), "seconds": int(secs.group(1))})
    return out


def problem_events(lines: list[str]) -> list[dict]:
    """Every problem the log names a client for, in log order: `{ts, level, id, kind, mac, ip, detail, tid, subnet_id}`, `kind` one of
    LOG_PROBLEM_KINDS. A NAK is visible at INFO as the DHCPNAK Kea sends (DHCP4_PACKET_SEND) and, at DEBUG, as its own
    DHCP4_PACKET_NAK_000x line too - both carry the same transaction id, so a NAK is one event, keeping whichever line
    named the requested address. A DHCP4_DDNS_REQUEST_SEND_FAILED line has no client label at all, so it is attached to the
    client the same lines show being offered or allocated an address it mentions, and dropped when none does. The DEBUG-only
    kinds (drop, subnet-selection-failed, the other NAK reasons) appear only while the server logs at DEBUG."""
    parsed = []
    for raw in lines:
        m = _LINE_RE.match(raw.strip())
        if m:
            parsed.append((m, raw))
    # v5.68.0-beta.9 (Q144): the walk is IN ORDER and keeps two maps as it goes - who was last given each address, and (for a
    # transaction) which subnet Kea selected - so an event is attributed to what the log showed BEFORE it, never to whoever
    # held the address or the client's subnet at the end of the tail.
    ip_to_mac: dict[str, str] = {}
    ip_tid_to_mac: dict[tuple[str, str], str] = {}
    subnet_of_tx: dict[tuple[str, str], tuple[datetime, int]] = {}
    events: list[dict] = []
    naks: dict[tuple[str, str], dict] = {}
    for m, _raw in parsed:
        msg_id, rest = m.group("id"), m.group("rest")
        if msg_id in ("DHCP4_LEASE_OFFER", "DHCP4_LEASE_ALLOC", "DHCP4_LEASE_REUSE"):
            label = _LABEL_MAC_RE.search(rest)
            lease = _LEASE_RE.search(rest)
            if label and lease:
                owner = norm_mac(label.group("mac"))
                ip_to_mac[lease.group(1)] = owner
                tid_here = _TID_RE.search(rest)
                if tid_here:
                    ip_tid_to_mac[(lease.group(1), tid_here.group(1))] = owner
        if msg_id == "DHCP4_SUBNET_SELECTED":
            label, tid_here, sel = _LABEL_MAC_RE.search(rest), _TID_RE.search(rest), _SUBNET_ID_RE.search(rest)
            sel_ts = _parse_ts(m.group("ts"))
            if label and tid_here and sel and sel_ts is not None:
                subnet_of_tx[(norm_mac(label.group("mac")), tid_here.group(1))] = (sel_ts, int(sel.group(1)))
        kind = _PROBLEM_KIND_OF_ID.get(msg_id)
        if msg_id.startswith("DHCP4_PACKET_DROP") and kind is None:
            kind = "drop"
        if msg_id == "DHCP4_PACKET_SEND" and "DHCPNAK" in rest:
            kind = "nak"
        if kind is None:
            continue
        ts = _parse_ts(m.group("ts"))
        if ts is None:
            continue
        label = _LABEL_MAC_RE.search(rest)
        mac = norm_mac(label.group("mac")) if label else ""
        ip = _client_ip(msg_id, rest)
        tid_m = _TID_RE.search(rest)
        if kind == "ddns-failed":
            # the nearest allocation BEFORE the failure (ip_to_mac is as of this line), preferring the one in the same transaction
            # when the failure line names a transaction at all
            named = [a for a in _IP_RE.findall(rest) if a in ip_to_mac]
            if tid_m:
                named.sort(key=lambda a: (a, tid_m.group(1)) not in ip_tid_to_mac)
            ip = named[0] if named else ""
            mac = (ip_tid_to_mac.get((ip, tid_m.group(1))) if tid_m else None) or (ip_to_mac.get(ip, "") if ip else "")
        if not mac:
            continue
        if msg_id == "DHCP4_PACKET_SEND":
            detail = "Kea sent a DHCPNAK"
        else:
            detail = _summarize(msg_id, rest)[0]
        selected = subnet_of_tx.get((mac, tid_m.group(1))) if tid_m else None
        event = {
            "ts": ts,
            "level": m.group("level"),
            "id": msg_id,
            "kind": kind,
            "mac": mac,
            "ip": ip,
            "detail": detail[:200],
            "tid": tid_m.group(1) if tid_m else "",
            # the subnet Kea itself selected for this very transaction (DEBUG logging only), else None: never a later guess
            "subnet_id": selected[1] if selected and 0 <= (ts - selected[0]).total_seconds() <= 60 else None,
        }
        if kind == "nak" and event["tid"]:
            seen = naks.get((mac, event["tid"]))
            if seen is not None:
                if ip and not seen["ip"]:
                    seen["ip"] = ip
                if event["subnet_id"] is not None and seen.get("subnet_id") is None:
                    seen["subnet_id"] = event["subnet_id"]
                if msg_id != "DHCP4_PACKET_SEND":
                    seen["detail"] = detail[:200]  # the NAK's own line says why; the send line only says that
                continue
            naks[(mac, event["tid"])] = event
        events.append(event)
    events.sort(key=lambda e: e["ts"])
    return events


# ── where the log is: ONE definition (v5.69.0-beta.6, Q175) ─────────────────────────────────────────────────────────


def host_log_path(path) -> str:
    """`path` when the Kea host's helper would accept it as a log to read - an absolute, normalized `*.log` under /var/log (the helper's `_allowed_log_path`, without the symlink
    resolution only the host can do) - else "" (v5.69.0-beta.1, Q170). Anything else made the arm refuse with `bad-log-path` even where the control socket could answer on its own."""
    if (
        isinstance(path, str)
        and path.startswith("/var/log/")
        and path.endswith(".log")
        and posixpath.normpath(path) == path
        and ".." not in path.split("/")
    ):
        return path
    return ""


def logger_file_outputs(cfg) -> list[str]:
    """Every `output` of the `kea-dhcp4` logger in `cfg` (a whole `{"Dhcp4": ...}` config) that starts with "/" - the files the daemon says it writes, in order. Empty for
    stdout, stderr, syslog and a config with no such logger. Not judged: `host_log_path` decides whether the host would read one."""
    section = cfg.get("Dhcp4") if isinstance(cfg, dict) else None
    loggers = section.get("loggers") if isinstance(section, dict) else None
    out = []
    for logger_entry in loggers if isinstance(loggers, list) else []:
        if isinstance(logger_entry, dict) and logger_entry.get("name") == _edit.INVESTIGATION_LOGGER:
            for option in logger_entry.get("output-options") or []:
                path = option.get("output") if isinstance(option, dict) else None
                if isinstance(path, str) and path.startswith("/"):
                    out.append(path)
    return out


def log_path_for(cfg) -> str:
    """Where kea-dhcp4 writes the log Jen reads: the `kea-dhcp4` logger's first file output in `cfg` that the host's helper would read (`host_log_path`), else the
    configured `[kea] dhcp4_log_path` when it would, else "". EVERY reader of the daemon's log goes through here - the Problems inbox sweep, Trace, Explain's log
    evidence and the investigation arm (v5.68.0-beta.30 Q167 / beta.1 Q170 had the rule for the arm alone; the sweep read the configured path for 1447 sweeps of a host
    whose logger wrote to stdout). `cfg` None (the config could not be read) is the configured path."""
    for path in logger_file_outputs(cfg):
        accepted = host_log_path(path)
        if accepted:
            return accepted
    return host_log_path(extensions.DHCP4_LOG)


# ── changing where the log is (Q249, INV-017) ───────────────────────────────────────────────────────────────────────
#
# Settings → Kea → Kea logging. Measured on kea-dhcp4 3.0.5: `config-set` moves the logger's output live and Kea makes the file itself; a path that is not directly in
# /var/log/kea is Kea's own refusal; and a file the daemon may not write is ACCEPTED ("Configuration successful.") and Kea then logs nothing anywhere. So an accepted change
# proves nothing: `change_log_output` reads the tail of the new file before and after, and puts the previous logger back when the file did not move. The imports of the
# services it drives are inside the functions: this module stays importable by the pure ones (`config_doctor`).

LOG_OUTPUT_PATH = re.compile(r"^/var/log/kea/[A-Za-z0-9._-]+\.log$")
LOG_OUTPUT_MB = (1, 1024)  # "Rotate at (MB)"
LOG_OUTPUT_KEPT = (1, 50)  # "Old files kept"
LOG_OUTPUT_TRIES = 5  # reads of the new file after the change, one second apart
LOG_OUTPUT_TAIL = 20  # lines of the file compared before and after
_MB = 1024 * 1024


def _proof_sleep(seconds: float) -> None:  # a name the tests replace
    import time

    time.sleep(seconds)


def _server_name(server: dict) -> str:
    return server.get("name") or server.get("ssh_host") or f"Server {server.get('id')}"


def investigation_sentence(name: str) -> str:
    return (
        f"Investigation logging is on for {name} (or its last session is not resolved). Turn it off or resolve it on the Kea Servers page first; "
        "a restore would undo this change."
    )


def no_ssh_sentence(name: str) -> str:
    return f"Jen reads Kea's log over SSH, and {name} has no SSH configured (or no helper). Set that up first; without it a file would be written that Jen cannot read."


def running_logger_config(server: dict, timeout: int = 10) -> tuple[dict | None, str]:
    """What the RUNNING kea-dhcp4 on `server` says its configuration is (`config-get`): `({"Dhcp4": ...}, "")`, or `(None, <reason>)`. Only the Dhcp4 section is kept and
    nothing of the reply is ever logged or printed: it carries the Kea database password."""
    from jen.services import kea as _kea

    reply = _kea.kea_command("config-get", server=server, timeout=timeout)
    if not isinstance(reply, dict) or reply.get("result") != 0:
        text = str((reply or {}).get("text") or "").strip()[:200] if isinstance(reply, dict) else ""
        return None, text or "Kea did not answer"
    arguments = reply.get("arguments")
    section = arguments.get("Dhcp4") if isinstance(arguments, dict) else None
    if not isinstance(section, dict):
        return None, "the answer carries no Dhcp4 configuration"
    return {"Dhcp4": section}, ""


def investigation_blocks_log_output(server: dict, cfg) -> bool:
    """Is investigation logging on for `server`, or its last session unresolved? The running config carries the marker (readable or damaged), Jen's own record has an entry
    for the server (`investigation_logging.blocking_removal`, the reading the settings routes already refuse on), or the Kea host holds an unresolved session
    (`investigation_logging.host_session_refusal`, the predicate a turn-on refuses on). The restore of a session that CREATED the logger entry removes the whole entry."""
    from jen.services import investigation_logging as _inv

    if _edit.logger_marker_present(cfg):
        return True
    if _inv.blocking_removal([server.get("id")]):
        return True
    return bool(server.get("ssh_host") and _inv.host_session_refusal(server))


def _log_tail(server: dict, path: str) -> tuple[list | None, str]:
    """The last lines of `path` on the Kea host through the helper's log read: `(lines, "")` - a file that is not there is an empty tail - or `(None, code)` when the read
    itself failed (`no-helper`, or the read's own detail)."""
    from jen.services import kea_host as _host

    res = _host.tail_log(server, path, lines=LOG_OUTPUT_TAIL, timeout=20, helper_only=True)
    if res.get("ok"):
        return [str(line) for line in res.get("lines") or []], ""
    if res.get("code") == "missing":
        return [], ""
    return None, "no-helper" if res.get("code") == "no-helper" else str(res.get("detail") or res.get("code") or "error")


def _applies_words(server: dict) -> str:
    """How a change reaches THIS server, for the confirm: the transport the Write mode card prints (`kea_changeset._transport`, the one reading)."""
    from jen.services import kea_changeset as _cs

    return "Kea applies it at once." if _cs._transport(server, "dhcp4") == "api" else "Kea is restarted to apply it."


def log_output_card(server: dict, timeout: int = 3) -> dict:
    """One server's block of the Kea logging card, from what the RUNNING daemon says (never Jen's memory): what it writes to, what Jen reads and where that came from,
    its severity, and the form's starting values. `readable` False (with `reason`) when `config-get` gave nothing: the block then shows no form."""
    name = _server_name(server)
    card = {
        "id": server.get("id"),
        "name": name,
        "readable": False,
        "reason": "",
        "has_ssh": bool(server.get("ssh_host")),
    }
    cfg, why = running_logger_config(server, timeout=timeout)
    if cfg is None:
        card["reason"] = why
        return card
    described = _edit.describe_logger_output(cfg)
    reads = log_path_for(cfg)
    from_logger = bool(reads) and reads in [host_log_path(p) for p in logger_file_outputs(cfg)]
    choice = described["choice"]
    default = _edit.LOGGER_OUTPUT_FILE_DEFAULT
    size = described["maxsize"] if isinstance(described["maxsize"], int) else default["maxsize"]
    kept = described["maxver"] if isinstance(described["maxver"], int) else default["maxver"]
    replaces = choice == "custom"
    card.update(
        readable=True,
        writes=_edit.logger_output_words(described),
        reads=reads,
        reads_from=("from Kea's logger" if from_logger else "from the Kea Log Path setting") if reads else "",
        severity=_edit.logger_severity_words(cfg),
        investigation=_edit.logger_marker_present(cfg),
        choice=choice,
        checked={"none": "journal", "custom": ""}.get(choice, choice),
        file=described["file"] or default["output"],
        mb=min(LOG_OUTPUT_MB[1], max(LOG_OUTPUT_MB[0], round(size / _MB))),
        kept=min(LOG_OUTPUT_KEPT[1], max(LOG_OUTPUT_KEPT[0], kept)),
        replaces=replaces,
        confirm=f"Change where {name} writes its log? {_applies_words(server)}"
        + (" The outputs it has now are replaced." if replaces else ""),
    )
    return card


def _result(ok: bool, code: str, level: str, lines: list, **extra) -> dict:
    return {"ok": ok, "code": code, "level": level, "lines": lines, **extra}


def change_log_output(server: dict, choice: str, path: str = "", maxsize: int = 0, maxver: int = 0) -> dict:
    """Make kea-dhcp4 on ONE server write its log to the journal (`journal`), to a file Jen can read (`file`) or to both (`both`) - THE choke point of INV-017: a change of
    Kea's log output is proven by the log itself or put back.

    Returns `{"ok", "code", "level", "lines", "old", "new"}`; `ok` only when the change stands. Refused before anything is sent: a choice, path or number outside the form's
    rules, a daemon whose configuration cannot be read, investigation logging on or unresolved (`investigation_blocks_log_output`), a file choice for a server Jen cannot read
    a log from. The write is one change set for that one server (`kea_changeset.apply_change`: its transport, preflight, config history and revert). For a file choice the
    tail of the new file is read through the helper BEFORE the change and again after the daemon was asked a harmless command, up to `LOG_OUTPUT_TRIES` times one second
    apart; a tail that is still empty or unchanged puts the previous logger back through the same change path."""
    from jen.services import kea as _kea
    from jen.services import kea_changeset as _cs

    name = _server_name(server)
    if choice not in _edit.LOGGER_OUTPUT_CHOICES:
        return _result(False, "bad-choice", "error", ["Choose where Kea writes its log."])
    wants_file = choice != "journal"
    if wants_file:
        if not (isinstance(path, str) and LOG_OUTPUT_PATH.fullmatch(path) and host_log_path(path)):
            return _result(
                False,
                "bad-path",
                "error",
                ["The file must be a .log file directly in /var/log/kea, for example /var/log/kea/kea-dhcp4.log."],
            )
        if (
            isinstance(maxsize, bool)
            or not isinstance(maxsize, int)
            or not LOG_OUTPUT_MB[0] * _MB <= maxsize <= LOG_OUTPUT_MB[1] * _MB
        ):
            return _result(
                False,
                "bad-size",
                "error",
                [f"Rotate at (MB) is a whole number from {LOG_OUTPUT_MB[0]} to {LOG_OUTPUT_MB[1]}."],
            )
        if (
            isinstance(maxver, bool)
            or not isinstance(maxver, int)
            or not LOG_OUTPUT_KEPT[0] <= maxver <= LOG_OUTPUT_KEPT[1]
        ):
            return _result(
                False,
                "bad-kept",
                "error",
                [f"Old files kept is a whole number from {LOG_OUTPUT_KEPT[0]} to {LOG_OUTPUT_KEPT[1]}."],
            )
    else:
        path, maxsize, maxver = "", 0, 0

    cfg, why = running_logger_config(server)
    if cfg is None:
        return _result(
            False,
            "unreadable",
            "error",
            [f"{name}: Kea's configuration could not be read: {why}. Nothing was changed."],
        )
    if investigation_blocks_log_output(server, cfg):
        return _result(False, "investigation", "error", [investigation_sentence(name)])
    old = _edit.logger_output_words(_edit.describe_logger_output(cfg))
    new = _edit.logger_output_words({"options": _edit.logger_output_options(choice, path, maxsize, maxver)})
    _after, code = _edit.set_logger_output(cfg, choice, path, maxsize, maxver)
    if code == "nochange":
        return _result(False, "nochange", "info", ["Nothing to change."], old=old, new=new)
    unsupported = f"{name}: the loggers of this configuration are not a list Jen can change. Nothing was changed."
    if code != "ok":
        return _result(False, "unsupported", "error", [unsupported])

    before: list = []
    if wants_file:
        if not server.get("ssh_host"):
            return _result(False, "no-ssh", "error", [no_ssh_sentence(name)])
        tail, failed = _log_tail(server, path)
        if tail is None:
            if failed == "no-helper":
                return _result(False, "no-ssh", "error", [no_ssh_sentence(name)])
            return _result(
                False,
                "no-read",
                "error",
                [f"Jen could not read {path} on {name} over SSH ({failed}). Nothing was changed."],
            )
        before = tail

    captured: dict = {}

    def mutate(current):
        captured.setdefault("snapshot", _edit.logger_output_snapshot(current))
        return _edit.set_logger_output(current, choice, path, maxsize, maxver)

    messages = {
        "nochange": "its configuration already has this output",
        "unsupported": "the loggers of this configuration are not a list Jen can change",
        "investigation": investigation_sentence(name),
    }
    result = _cs.apply_change("dhcp4", mutate, f"Kea logging: {new}", servers=[server], code_messages=messages)
    lines = [text for _level, text in result.lines]
    if result.status != "ok":
        if result.status == "nothing" and result.last_code == "nochange":
            return _result(False, "nochange", "info", ["Nothing to change."], old=old, new=new)
        if result.last_code == "investigation":
            return _result(False, "investigation", "error", [investigation_sentence(name)])
        return _result(False, "refused", "error", lines or [f"{name}: the change was not applied."], old=old, new=new)
    if not wants_file:
        return _result(True, "ok", "success", lines, old=old, new=new)

    # the proof: the daemon is asked a harmless command (every command logs COMMAND_RECEIVED), and the file must have moved
    for attempt in range(LOG_OUTPUT_TRIES):
        _kea.kea_command("config-get", server=server)  # the reply is not read: only the line it makes Kea write matters
        tail, _failed = _log_tail(server, path)
        if tail and tail != before:
            return _result(True, "ok", "success", lines + [f"Kea is writing to {path} on {name}."], old=old, new=new)
        if attempt < LOG_OUTPUT_TRIES - 1:
            _proof_sleep(1)

    # A logger above INFO writes no line for a command, so the unchanged tail is not evidence that Kea cannot write the file: the change stands and says what was not checked
    severity = _edit.logger_severity_above_info(cfg)
    if severity:
        return _result(
            True,
            "unchecked",
            "warning",
            [
                f"Kea accepted the change on {name}. Its severity is {severity}, so it wrote no line Jen could check; the file {path} will fill when Kea next logs at that "
                "level. If it stays empty, check that the account kea-dhcp4 runs as may write it."
            ],
            old=old,
            new=new,
            note=f" (not checked: severity {severity})",
        )

    def put_back(current):
        return _edit.restore_logger_output(current, captured["snapshot"])

    undone = _cs.apply_change("dhcp4", put_back, "Kea logging put back", servers=[server], code_messages=messages)
    if undone.status in ("ok", "nothing"):
        return _result(
            False,
            "put-back",
            "error",
            [
                f"Kea accepted the change but wrote nothing to {path} on {name}, so the previous logging was put back. "
                f"Check that {path} is writable by the account kea-dhcp4 runs as."
            ],
            old=old,
            new=new,
        )
    now_cfg, _why = running_logger_config(server)
    runs = (
        _edit.logger_output_words(_edit.describe_logger_output(now_cfg))
        if now_cfg is not None
        else "something Jen could not read"
    )
    return _result(
        False,
        "put-back-failed",
        "error",
        [
            f"Kea accepted the change but wrote nothing to {path} on {name}, and putting the previous logging back failed: "
            + " ".join(text for _level, text in undone.lines)
            + f" {name} now writes its log to {runs}. Check that {path} is writable by the account kea-dhcp4 runs as, then choose again."
        ],
        old=old,
        new=new,
        now=runs,
    )
