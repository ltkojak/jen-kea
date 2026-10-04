"""
jen/services/explain_inputs.py
───────────────────────────────
v5.68.0-beta.2 (Q135) — the client Explain evaluates, built from everything Jen can know, with each input labelled by where
it came from. Pure: the caller hands in the lease row, what Kea's log said (jen/services/kea_log_inputs.py) and what the
person typed.

`jen.services.dhcp_explain.explain()` takes a client {mac, client_id, vendor_class, user_class, hostname, circuit_id,
remote_id, giaddr}; a class test that reads an input the client lacks is "undecided — supply …". Until v5.68.0-beta.2 the
Investigation page handed it the MAC alone. Now each input is filled from the best source there is, in this order (a later
source overrides an earlier one, and what was typed overrides everything):

    the VENDOR_CLASS_<…> class Kea listed as assigned   → vendor class                       ("Kea's log, assigned classes")
    the current lease row                               → client id, hostname                ("the lease")
    the lease's extended info (store-extended-info)     → circuit id, remote id              ("the lease's extended info")
    the client-id label on Kea's log lines              → client id                          ("Kea's log")
    the newest packet dump in Kea's log                 → hostname, vendor class, client id,
                                                          user class, circuit id, remote id  ("Kea's log, packet dump")
    typed into the form                                 → anything                           ("typed")

`giaddr` is never inferred: Kea logs it only inside the dump, and the dump's value belongs to a packet, not to the client.
"""

from __future__ import annotations

from jen.services import kea_log_inputs as _li

FIELDS = ("mac", "client_id", "vendor_class", "user_class", "hostname", "circuit_id", "remote_id", "giaddr")

SOURCE_LABELS = {
    "mac": "the MAC you asked about",
    "lease": "the current lease",
    "lease-relay": "the lease's extended info",
    "log-classes": "Kea's log (assigned classes)",
    "log-label": "Kea's log",
    "log-packet": "Kea's log (packet dump)",
    "typed": "typed",
}


def _colon_hex(value: str) -> str:
    body = "".join(ch for ch in str(value or "") if ch in "0123456789abcdefABCDEF").lower()
    return ":".join(body[i : i + 2] for i in range(0, len(body), 2)) if body and len(body) % 2 == 0 else ""


def build(
    mac: str, *, typed: dict | None = None, lease: dict | None = None, log: dict | None = None, auto: bool = True
) -> dict:
    """The client and its provenance.

    `typed`: the form's values (any of FIELDS; blanks are ignored). `lease`: the newest active lease row
    (`client_subject.load_leases4` shape: `client_id` hex, `hostname`, `user_context`). `log`: {"classes": latest_classes(),
    "query": latest_query_data(), "cid": client_id_from_log()} — any may be None. `auto=False` turns every inferred source
    off, leaving the MAC and what was typed (the old behaviour; `?auto=0`).

    Returns {"client": {field: value}, "sources": {field: key of SOURCE_LABELS}, "when": {field: "at <log timestamp>"},
    "assigned": the class list for explain(assigned_classes=) or None}."""
    client = dict.fromkeys(FIELDS, "")
    sources: dict[str, str] = {}
    when: dict[str, str] = {}
    client["mac"], sources["mac"] = (mac or "").lower(), "mac"

    def put(field, value, source, at=""):
        value = (value or "").strip() if isinstance(value, str) else value
        if value:
            client[field], sources[field] = value, source
            if at:
                when[field] = f"at {at}"
            else:
                when.pop(field, None)

    assigned = None
    if auto:
        log = log or {}
        classes = log.get("classes")
        if classes:
            assigned = {"classes": classes["classes"], "at": classes["at"]}
            put("vendor_class", _li.vendor_class_from(classes["classes"]), "log-classes", classes["at"])
        if lease:
            put("client_id", _colon_hex(lease.get("client_id")), "lease")
            put("hostname", lease.get("hostname"), "lease")
            relay = _li.relay_info_from_user_context(lease.get("user_context"))
            put("circuit_id", relay["circuit_id"], "lease-relay")
            put("remote_id", relay["remote_id"], "lease-relay")
        cid = log.get("cid")
        if cid:
            put("client_id", cid["client_id"], "log-label", cid["at"])
        query = log.get("query")
        if query:
            for field in ("hostname", "vendor_class", "client_id", "user_class", "circuit_id", "remote_id"):
                put(field, query.get(field), "log-packet", query["at"])
    for field, value in (typed or {}).items():
        if field in FIELDS and field != "mac":
            put(field, (value or "").strip(), "typed")
    return {"client": client, "sources": sources, "when": when, "assigned": assigned}


def provenance(built: dict) -> list[dict]:
    """The inputs that have a value, for the 'inputs used' table: [{field, value, source, label, when}] in FIELDS order."""
    rows = []
    for field in FIELDS:
        value = built["client"].get(field)
        if value:
            key = built["sources"].get(field, "")
            rows.append(
                {
                    "field": field,
                    "value": value,
                    "source": key,
                    "label": SOURCE_LABELS.get(key, key),
                    "when": built["when"].get(field, ""),
                }
            )
    return rows
