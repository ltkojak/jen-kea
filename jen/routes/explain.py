"""
jen/routes/explain.py
─────────────────────
v5.35.0 (Q34) — "Why did this client get this?" — /tools/explain. Thin:
read the client attributes from the query string, look up the client's
reservations and current lease, hand everything to
jen/services/dhcp_explain.py, render.

Subnet-restricted users only ever see the decision for subnets they can
access: the answer reveals a subnet's pools and options.

v5.63.0 (Q82) — the reservation/lease lookups are
`jen.services.client_subject`'s `load_reservations4`/`load_leases4` now
(the same queries, moved verbatim) — Explain's own private resolver is
gone; `_hex_identifier` stays here since Trace still imports it for its
own mac-only lookups.
"""

import logging

from flask import Blueprint, flash, render_template, request
from flask_login import login_required

import jen.services.auth as __auth
from jen.services import client_subject as __subject
from jen.services.access import diagnostic_surface, get_accessible_subnet_map
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
    return __subject.load_reservations4(mac_hex, cid_hex)


def _load_lease(mac_hex: str) -> dict | None:
    """The newest active lease for this hw-address hex, or None — the
    single-object shape this route (and Trace, which imports this) has
    always used; client_subject.load_leases4 returns every active lease."""
    if not mac_hex:
        return None
    leases = __subject.load_leases4(__subject.hex_to_mac(mac_hex))
    return leases[0] if leases else None


@bp.route("/tools/explain")
@login_required
@diagnostic_surface(subject="client")
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

    # v5.63.0 (Q82) — the Investigation page's Explain tab embeds this
    # exact result via htmx (the same result-only partial, no duplicated
    # subnet-selection/reservation-filtering logic), same pattern as
    # Trace's own HX-partial branch below.
    if request.headers.get("HX-Request") == "true":
        return render_template("_explain_result.html", client=client, chosen_how=chosen_how, result=result)
    return render_template(
        "explain.html",
        client=client,
        subnet_map=subnet_map,
        subnet_id=subnet_id,
        chosen_how=chosen_how,
        result=result,
        input_labels=INPUT_LABELS,
    )
