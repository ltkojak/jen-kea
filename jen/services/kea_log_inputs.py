"""
jen/services/kea_log_inputs.py
───────────────────────────────
v5.68.0-beta.2 (Q135) — the facts about ONE client that Kea's own kea-dhcp4 log (and the lease row) carry, read for Explain.

Explain decides a client-class test only for the inputs it has. The MAC it has; the rest — client id, hostname, vendor class
(option 60), user class (option 77), the relay agent's circuit and remote id — it used to be told by the person at the keyboard.
What a real daemon actually writes was MEASURED, not assumed (tests/kea_compat/test_log_levels.py, the same on Kea 3.0.3, 3.2.0
and 3.3.1 — the findings are in the user guide's "What Explain can and cannot know"):

* every message about a client — at ANY level, INFO included — carries its label `[hwtype=1 aa:bb:cc:dd:ee:ff], cid=[01:aa:…],
  tid=0x…`, so the CLIENT ID is always readable from the log;
* at debuglevel 45 and up, `DHCP4_CLASSES_ASSIGNED` (and `…_AFTER_SUBNET_SELECTION`) names the classes Kea assigned, built-ins
  included — and the built-in `VENDOR_CLASS_<option 60>` among them IS the vendor class;
* at debuglevel 55 and up, `DHCP4_QUERY_DATA` dumps the whole packet over several lines: hostname (12), vendor class (60),
  client id (61), user class (77) and the relay agent's circuit id (82/1) and remote id (82/2);
* the LEASE ROW's `user_context`, when the daemon runs with `store-extended-info`, keeps the relay agent's options
  (`ISC.relay-agent-info`: `remote-id`, and the raw `sub-options` TLVs, circuit id among them) at any log level.

Pure — the caller tails the log (helper op `tail-log`) and reads the lease; nothing here does I/O. Lines the module cannot
read are skipped, never guessed at.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

_TS = r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
_HEADER_RE = re.compile(rf"^(?P<ts>{_TS})\s+(?P<level>[A-Z]+)\s+\[[^\]]*\]\s+(?P<id>[A-Z0-9_]+)\s*(?P<rest>.*)$")
_LABEL_RE = re.compile(r"\[hwtype=\d+ (?P<mac>[0-9a-fA-F:]{17})\],\s*cid=\[(?P<cid>[^\]]*)\]")
_CLASSES_RE = re.compile(r"to the following classes?: (?P<classes>.+?)\s*$")
_OPTION_RE = re.compile(r"^(?P<indent>\s*)type=(?P<code>\d+), len=\d+:\s*(?P<value>.*?)\s*$")

_TID_RE = re.compile(r"\btid=(0x[0-9a-fA-F]+)")

#: one transaction id (a client's xid) repeats over time; lines of one tid further apart than this are a different exchange
TRANSACTION_GAP_S = 60

#: the message ids that list the classes assigned to a client, newest-wins; the unsuffixed one is the final list
CLASS_LIST_IDS = ("DHCP4_CLASSES_ASSIGNED", "DHCP4_CLASSES_ASSIGNED_AFTER_SUBNET_SELECTION")

#: the debuglevels the measured facts need — named in the hint when an input is missing
LEVEL_FOR_CLASSES = 45
LEVEL_FOR_PACKET = 55


def _norm_mac(mac: str) -> str:
    body = "".join(ch for ch in (mac or "").lower() if ch in "0123456789abcdef")
    return ":".join(body[i : i + 2] for i in range(0, 12, 2)) if len(body) == 12 else ""


def _hex_text(value: str) -> str:
    """`65:74:68` / `657468` -> `657468`; '' when it is not hex."""
    body = re.sub(r"[:\s]", "", value or "")
    return body.lower() if body and re.fullmatch(r"[0-9a-fA-F]+", body) and len(body) % 2 == 0 else ""


def _printable(raw: bytes) -> str:
    """The bytes as text when they are printable ASCII, else the hex (a relay's circuit id is often not text)."""
    if raw and all(32 <= b < 127 for b in raw):
        return raw.decode("ascii")
    return raw.hex()


def client_id_from_log(lines: list[str], mac: str) -> dict | None:
    """The client id (`cid=[…]`) on the newest line that names `mac`: {"client_id": "01:aa:…", "at": ts} or None.
    `cid=[]` (no client id) is None."""
    needle = _norm_mac(mac)
    if not needle:
        return None
    found = None
    for raw in lines:
        m = _HEADER_RE.match(raw.strip())
        label = _LABEL_RE.search(raw)
        if not m or not label or _norm_mac(label.group("mac")) != needle:
            continue
        cid = _hex_text(label.group("cid"))
        if cid:
            found = {"client_id": ":".join(cid[i : i + 2] for i in range(0, len(cid), 2)), "at": m.group("ts")}
    return found


def latest_classes(lines: list[str], mac: str) -> dict | None:
    """The newest class list Kea logged for `mac`: {"classes": [names…], "at": ts, "id": message id, "message": "DHCPDISCOVER"|""}
    or None. A final DHCP4_CLASSES_ASSIGNED beats the AFTER_SUBNET_SELECTION line of the same packet (later in the log)."""
    needle = _norm_mac(mac)
    if not needle:
        return None
    found = None
    for raw in lines:
        m = _HEADER_RE.match(raw.strip())
        if not m or m.group("id") not in CLASS_LIST_IDS:
            continue
        label = _LABEL_RE.search(raw)
        if not label or _norm_mac(label.group("mac")) != needle:
            continue
        listed = _CLASSES_RE.search(m.group("rest"))
        if not listed:
            continue
        names = [c.strip() for c in listed.group("classes").split(",") if c.strip()]
        on = re.search(r"assigned on (\w+) message", m.group("rest"))
        found = {"classes": names, "at": m.group("ts"), "id": m.group("id"), "message": on.group(1) if on else ""}
    return found


def _when(text: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def transactions(lines: list[str], mac: str) -> list[dict]:
    """Every exchange (one transaction id) the log shows for `mac`, oldest first. Each is
    {"tid", "first", "last" (the timestamps of its first and last line, as the log wrote them), "cid" ({"client_id", "at"} or None),
    "classes" (latest_classes' shape or None), "query" (latest_query_data's shape or None), "complete"}. `complete` means the exchange
    has a class list or a packet dump - what the evidence is for. A tid is the client's own xid and repeats, so the same tid more
    than TRANSACTION_GAP_S after its last line starts a new exchange.

    v5.68.0-beta.10 (Q145): the newest cid, the newest class list and the newest packet dump used to be taken INDEPENDENTLY, so an
    "observation" could be stitched from three different exchanges (a DISCOVER's classes, an old REQUEST's options, a later cid).
    Everything Explain reads from the log now comes from ONE of these."""
    needle = _norm_mac(mac)
    if not needle:
        return []
    open_by_tid: dict[str, dict] = {}
    done: list[dict] = []
    order = 0
    i = 0
    while i < len(lines):
        raw = lines[i]
        m = _HEADER_RE.match(raw.strip())
        label = _LABEL_RE.search(raw)
        tid_m = _TID_RE.search(raw)
        if not m or not label or not tid_m or _norm_mac(label.group("mac")) != needle:
            i += 1
            continue
        tid, ts_text = tid_m.group(1), m.group("ts")
        ts = _when(ts_text)
        tx = open_by_tid.get(tid)
        if (
            tx is not None
            and ts is not None
            and tx["_last_dt"] is not None
            and (ts - tx["_last_dt"]).total_seconds() > TRANSACTION_GAP_S
        ):
            done.append(open_by_tid.pop(tid))
            tx = None
        if tx is None:
            tx = open_by_tid[tid] = {
                "tid": tid, "first": ts_text, "last": ts_text, "cid": None, "classes": None, "query": None,
                "_last_dt": ts, "_order": 0,
            }  # fmt: skip
        order += 1
        tx["last"], tx["_last_dt"], tx["_order"] = ts_text, ts, order
        cid = _hex_text(label.group("cid"))
        if cid:
            tx["cid"] = {"client_id": ":".join(cid[k : k + 2] for k in range(0, len(cid), 2)), "at": ts_text}
        msg_id = m.group("id")
        if msg_id in CLASS_LIST_IDS:
            listed = _CLASSES_RE.search(m.group("rest"))
            if listed:
                names = [c.strip() for c in listed.group("classes").split(",") if c.strip()]
                on = re.search(r"assigned on (\w+) message", m.group("rest"))
                tx["classes"] = {"classes": names, "at": ts_text, "id": msg_id, "message": on.group(1) if on else ""}
        elif msg_id == "DHCP4_QUERY_DATA":
            block = []
            j = i + 1
            while j < len(lines) and not _HEADER_RE.match(lines[j].strip()):
                block.append(lines[j].rstrip("\n"))
                j += 1
            tx["query"] = _read_dump(ts_text, block)
            i = j
            continue
        i += 1
    done.extend(open_by_tid.values())
    done.sort(key=lambda t: t["_order"])
    for tx in done:
        tx["complete"] = bool(tx["classes"] or tx["query"])
        tx.pop("_last_dt", None)
        tx.pop("_order", None)
    return done


def latest_transaction(lines: list[str], mac: str) -> dict | None:
    """The ONE exchange Explain reads the log from: the newest COMPLETE transaction for `mac` (one with a class list or a packet dump),
    else - when the log shows the client but never at a level that lists anything - the newest exchange of any kind, which can
    still say the client id. {"tid", "first", "last", "cid", "classes", "query", "complete"} or None when the log never names the
    client. Its `cid`, `classes` and `query` are that exchange's own: nothing here is borrowed from another."""
    seen = transactions(lines, mac)
    if not seen:
        return None
    complete = [t for t in seen if t["complete"]]
    return (complete or seen)[-1]


def vendor_class_from(classes: list[str]) -> str:
    """The option-60 string Kea turned into its built-in `VENDOR_CLASS_<string>` class, or ''."""
    for name in classes or []:
        if name.startswith("VENDOR_CLASS_") and len(name) > len("VENDOR_CLASS_"):
            return name[len("VENDOR_CLASS_") :]
    return ""


def latest_query_data(lines: list[str], mac: str) -> dict | None:
    """The options of the newest DHCP4_QUERY_DATA packet dump for `mac`:
    {"at": ts, "hostname", "vendor_class", "client_id", "user_class", "circuit_id", "remote_id"} (each '' when the packet had none)
    or None when no dump names the client. The dump is several lines — a header, then `options:` and indented `type=NNN, len=NNN:`
    rows, the relay agent's two sub-options nested under type 082 — until the next timestamped line."""
    needle = _norm_mac(mac)
    if not needle:
        return None
    best = None
    i = 0
    while i < len(lines):
        m = _HEADER_RE.match(lines[i].strip())
        label = _LABEL_RE.search(lines[i])
        if m and m.group("id") == "DHCP4_QUERY_DATA" and label and _norm_mac(label.group("mac")) == needle:
            block = []
            j = i + 1
            while j < len(lines) and not _HEADER_RE.match(lines[j].strip()):
                block.append(lines[j].rstrip("\n"))
                j += 1
            best = _read_dump(m.group("ts"), block)
            i = j
            continue
        i += 1
    return best


def _read_dump(ts: str, block: list[str]) -> dict:
    out = {
        "at": ts,
        "hostname": "",
        "vendor_class": "",
        "client_id": "",
        "user_class": "",
        "circuit_id": "",
        "remote_id": "",
    }
    in_relay = False
    for row in block:
        m = _OPTION_RE.match(row)
        if not m:
            continue
        nested = len(m.group("indent")) >= 4
        code, value = int(m.group("code")), m.group("value")
        if not nested:
            in_relay = code == 82
            quoted = re.match(r'^"(.*)" \(string\)$', value)
            if code == 12 and quoted:
                out["hostname"] = quoted.group(1)
            elif code == 60 and quoted:
                out["vendor_class"] = quoted.group(1)
            elif code == 61:
                out["client_id"] = ":".join(re.findall(r"[0-9a-fA-F]{2}", value)).lower()
            elif code == 77:
                out["user_class"] = _user_class_text(value)
        elif in_relay:
            hexed = re.match(r"^((?:[0-9a-fA-F]{2}:?)+)", value)
            raw = bytes.fromhex(_hex_text(hexed.group(1))) if hexed and _hex_text(hexed.group(1)) else b""
            if code == 1:
                out["circuit_id"] = _printable(raw)
            elif code == 2:
                out["remote_id"] = raw.hex()
    return out


def _user_class_text(value: str) -> str:
    """Option 77 as Kea dumps it — hex of RFC 3004's length-prefixed entries; the first entry as text, or the hex when it is
    not printable (or not length-prefixed at all: an old client sends the bare string)."""
    body = _hex_text(value)
    if not body:
        return ""
    raw = bytes.fromhex(body)
    if raw and raw[0] == len(raw) - 1 and all(32 <= b < 127 for b in raw[1:]):
        return raw[1:].decode("ascii")
    return _printable(raw)


def relay_info_from_user_context(user_context) -> dict:
    """{"circuit_id", "remote_id"} (each '' when absent) from a lease row's `user_context` — the JSON text, or an already
    parsed dict — as written with `store-extended-info`: `ISC.relay-agent-info` holds `remote-id` (hex) and `sub-options`
    (`0x` + the raw TLVs: 01 <len> circuit-id, 02 <len> remote-id, …). Anything unreadable gives empty strings."""
    out = {"circuit_id": "", "remote_id": ""}
    try:
        ctx = json.loads(user_context) if isinstance(user_context, (str, bytes)) and user_context else user_context
        info = (ctx or {}).get("ISC", {}).get("relay-agent-info", {}) if isinstance(ctx, dict) else {}
    except (ValueError, AttributeError):
        return out
    if not isinstance(info, dict):
        return out
    if info.get("remote-id"):
        out["remote_id"] = _hex_text(str(info["remote-id"]))
    sub = str(info.get("sub-options") or "")
    body = _hex_text(sub[2:] if sub[:2].lower() == "0x" else sub)
    raw = bytes.fromhex(body) if body else b""
    pos = 0
    while pos + 2 <= len(raw):
        code, length = raw[pos], raw[pos + 1]
        data = raw[pos + 2 : pos + 2 + length]
        if len(data) < length:
            break
        if code == 1 and not out["circuit_id"]:
            out["circuit_id"] = _printable(data)
        elif code == 2 and not out["remote_id"]:
            out["remote_id"] = data.hex()
        pos += 2 + length
    return out


def level_hint(missing: list[str]) -> str:
    """One sentence naming the kea-dhcp4 log setting that would let Explain read the inputs still missing, or ''."""
    packet = [m for m in missing if m in ("hostname", "vendor_class", "user_class", "circuit_id", "remote_id")]
    parts = []
    if packet:
        parts.append(
            f"set kea-dhcp4's logger to severity DEBUG with debuglevel {LEVEL_FOR_PACKET} or higher (Kea then dumps each packet: "
            "hostname, vendor class, user class and the relay agent's circuit and remote ids)"
        )
    if "vendor_class" in missing or "classes" in missing:
        parts.append(
            f"debuglevel {LEVEL_FOR_CLASSES} lists the classes Kea assigned, and its built-in VENDOR_CLASS_… class IS the vendor class"
        )
    if {"circuit_id", "remote_id"} & set(missing):
        parts.append(
            "or run Kea with `store-extended-info: true`, which keeps the relay agent's options on the lease at any log level"
        )
    return ("To have Explain read them from Kea itself: " + "; ".join(parts) + ".") if parts else ""
