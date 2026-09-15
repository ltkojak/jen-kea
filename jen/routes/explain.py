"""
jen/routes/explain.py
─────────────────────
v5.35.0 (Q34) — "Why did this client get this?" — /tools/explain. Thin:
read the client attributes from the query string, look up the client's
reservations and current lease, hand everything to
jen/services/dhcp_explain.py, render.

Subnet-restricted users only ever see the decision for subnets they can
access: the answer reveals a subnet's pools and options.
"""

import logging

from flask import Blueprint, flash, render_template, request
from flask_login import login_required

import jen.models.db as __db
import jen.services.auth as __auth
from jen.services.access import get_accessible_subnet_map
from jen.services.dhcp_explain import INPUT_LABELS, explain
from jen.services.subnet_context import dhcp4_config

logger = logging.getLogger(__name__)
bp = Blueprint("explain", __name__)

FIELDS = ("mac", "client_id", "vendor_class", "user_class", "hostname", "circuit_id", "remote_id", "giaddr")


def _client_from_args(args) -> dict:
    return {f: (args.get(f) or "").strip()[:255] for f in FIELDS}


def _hex_identifier(value: str) -> str:
    """aa:bb:… / aabb… → uppercase hex for HEX() comparisons, or ''."""
    body = "".join(ch for ch in (value or "") if ch.isalnum()).upper()
    return body if body and all(c in "0123456789ABCDEF" for c in body) and len(body) % 2 == 0 else ""


def _load_reservations(mac_hex: str, cid_hex: str) -> list[dict]:
    """Host-DB reservations for either identifier, with their option-data."""
    if not mac_hex and not cid_hex:
        return []
    rows: list[dict] = []
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            # One fixed statement; an absent identifier is passed as '' and
            # can't match anything (HEX() of a real identifier is never empty).
            cur.execute(
                "SELECT host_id, dhcp4_subnet_id AS subnet_id, dhcp_identifier_type AS identifier_type, "
                "HEX(dhcp_identifier) AS identifier, inet_ntoa(ipv4_address) AS ip, hostname, dhcp4_client_classes "
                "FROM hosts WHERE (HEX(dhcp_identifier)=%s AND dhcp_identifier_type=0) "
                "OR (HEX(dhcp_identifier)=%s AND dhcp_identifier_type=3)",
                (mac_hex or "", cid_hex or ""),
            )
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
    except Exception as e:
        logger.error(f"explain: reservation lookup failed: {e}")
    return rows


def _load_lease(mac_hex: str) -> dict | None:
    if not mac_hex:
        return None
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(address) AS ip, subnet_id, expire FROM lease4 "
                "WHERE HEX(hwaddr)=%s AND state=0 ORDER BY expire DESC LIMIT 1",
                (mac_hex,),
            )
            return cur.fetchone()
    except Exception as e:
        logger.error(f"explain: lease lookup failed: {e}")
        return None


@bp.route("/tools/explain")
@login_required
def explain_page():
    subnet_map = get_accessible_subnet_map()
    client = _client_from_args(request.args)
    result = None
    subnet_id = None
    chosen_how = ""
    raw_subnet = (request.args.get("subnet") or "").strip()

    if client["mac"] and not __auth.valid_mac(client["mac"].lower()):
        flash("That isn't a MAC address (expected aa:bb:cc:dd:ee:ff).", "error")
        client["mac"] = ""

    if client["mac"]:
        client["mac"] = client["mac"].lower()
        mac_hex = _hex_identifier(client["mac"])
        cid_hex = _hex_identifier(client["client_id"])
        reservations = _load_reservations(mac_hex, cid_hex)
        lease = _load_lease(mac_hex)
        if raw_subnet.isdigit():
            subnet_id = int(raw_subnet)
            chosen_how = "chosen"
        elif lease and lease.get("subnet_id"):
            subnet_id = int(lease["subnet_id"])
            chosen_how = "from the current lease"
        elif reservations and any(r["subnet_id"] for r in reservations):
            subnet_id = next(r["subnet_id"] for r in reservations if r["subnet_id"])
            chosen_how = "from a reservation"
        elif subnet_map:
            subnet_id = next(iter(subnet_map))
            chosen_how = "first subnet you can see — pick one above if that's wrong"
        if subnet_id is not None and subnet_id not in subnet_map:
            flash("You do not have access to that subnet.", "error")
            subnet_id = None
        cfg = dhcp4_config() if subnet_id is not None else None
        if subnet_id is not None and not cfg:
            flash("Could not read the Kea configuration (config-get failed) — see Settings → Kea → Probe.", "error")
        elif subnet_id is not None:
            # Only reservations in accessible subnets (or global ones) feed the decision.
            reservations = [r for r in reservations if r["subnet_id"] == 0 or r["subnet_id"] in subnet_map]
            result = explain(cfg, client, subnet_id=subnet_id, reservations=reservations, lease=lease)
            if not result.get("ok"):
                flash(result.get("error", "Could not explain this client."), "error")
                result = None

    return render_template(
        "explain.html",
        client=client,
        subnet_map=subnet_map,
        subnet_id=subnet_id,
        chosen_how=chosen_how,
        result=result,
        input_labels=INPUT_LABELS,
    )
