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
from flask_login import current_user, login_required

import jen.services.auth as __auth
from jen.services import client_subject as __subject
from jen.services import explain_context as __ctx
from jen.services.access import diagnostic_surface, get_accessible_subnet_map
from jen.services.dhcp_explain import INPUT_LABELS
from jen.services.subnet_context import dhcp4_config

logger = logging.getLogger(__name__)
bp = Blueprint("explain", __name__)

FIELDS = (
    "mac",
    "client_id",
    "vendor_class",
    "user_class",
    "user_class_bytes",
    "hostname",
    "circuit_id",
    "circuit_id_hex",
    "remote_id",
    "giaddr",
)


def _client_from_args(args) -> dict:
    return {f: (args.get(f) or "").strip()[:255] for f in FIELDS}


def _may_read_kea_log() -> bool:
    """The Kea log has no per-line subnet boundary Jen can trust, so, as for Trace, only an admin who may see every
    subnet gets the inputs Explain can read out of it (docs/ARCHITECTURE.md section 2)."""
    return bool(current_user.role in ("superadmin", "admin") and current_user.all_subnets)


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

    typed = dict(client)
    built = None
    log_view = None
    if client["mac"]:
        client["mac"] = client["mac"].lower()
        mac_hex = _hex_identifier(client["mac"])
        lease = _load_lease(mac_hex)
        # v5.68.0-beta.2 (Q135): the client Explain evaluates is the MAC, the lease row's client id and hostname, what Kea's
        # own log says (for a caller allowed to read it), and what was typed - each input labelled by where it came from.
        # `auto=0` is the old behaviour: the MAC and what was typed, nothing inferred.
        auto = request.args.get("auto") != "0"
        log_view = __ctx.read_log(client["mac"], allowed=_may_read_kea_log() and auto)
        # a lease in a subnet the caller may not see contributes nothing: its client id and hostname are that client's.
        # v5.68.0-beta.10 (Q145): and from here on it is not "the lease" at all - `usable_lease` is the ONLY lease this route knows,
        # for the subnet it picks, for the engine and for the wording. (It used to be filtered for the inputs and then the
        # unfiltered one chose the subnet, was refused, and still reached the engine.)
        usable_lease = (
            lease if lease and (not lease.get("subnet_id") or int(lease["subnet_id"]) in subnet_map) else None
        )
        lease = usable_lease
        built = __ctx.build_inputs(client["mac"], typed=typed, lease=usable_lease, log=log_view, auto=auto)
        client = built["client"]
        cid_hex = _hex_identifier(client["client_id"])
        # v5.68.0-beta.21 (Q156): only the reservations the caller may see - global ones, or in a subnet of theirs - exist for this route, and they are
        # chosen from BEFORE the subnet is. It filtered them after: a MAC whose only reservation sat in a hidden subnet picked that subnet, was refused
        # ("You do not have access to that subnet") and got a different page from a MAC nobody has ever seen - an existence oracle. A denial and a
        # not-found are one message (docs/ARCHITECTURE.md section 2).
        reservations = [
            r for r in _load_reservations(mac_hex, cid_hex) if r["subnet_id"] == 0 or r["subnet_id"] in subnet_map
        ]
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
            result = __ctx.run(
                cfg,
                built,
                subnet_id=subnet_id,
                lease=lease,
                reservations=reservations,
                accessible_ids=None if current_user.all_subnets else set(subnet_map),
            )
            if not result.get("ok"):
                flash(result.get("error", "Could not explain this client."), "error")
                result = None

    # v5.63.0 (Q82) — the Investigation page's Explain tab embeds this
    # exact result via htmx (the same result-only partial, no duplicated
    # subnet-selection/reservation-filtering logic), same pattern as
    # Trace's own HX-partial branch below.
    extra = _result_context(built, log_view, result, subnet_id)
    if request.headers.get("HX-Request") == "true":
        # the Investigation page's Explain tab: the same result, plus the form that re-runs it THERE (it names the
        # identifier the person typed, so the form goes back to /client, not to this tool's own page)
        embed_q = (request.args.get("embed_q") or "").strip()[:255]
        form = (
            {"action": "/client", "hidden": {"q": embed_q, "tab": "explain", "subnet": subnet_id or ""}}
            if embed_q and client["mac"]
            else None
        )
        return render_template(
            "_explain_result.html",
            client=client,
            chosen_how=chosen_how,
            result=result,
            form=form,
            link_q=embed_q,
            **extra,
        )
    return render_template(
        "explain.html",
        client=client,
        subnet_map=subnet_map,
        subnet_id=subnet_id,
        chosen_how=chosen_how,
        result=result,
        form=None,
        link_q=client["mac"],
        **extra,
    )


def _result_context(built, log_view, result, subnet_id) -> dict:
    """What the result partial shows besides the decision: where each input came from, what is still missing and how to
    unlock it, and whether the viewer may follow a why-not to the Changes tab (an admin who may see every subnet)."""
    transaction = (log_view or {}).get("transaction")
    log_server = ((log_view or {}).get("server") or {}).get("name", "")
    return {
        "exchange": {**transaction, "server": log_server} if transaction else None,
        "log_server": log_server,
        "other_complete": list((log_view or {}).get("other_complete") or []),
        "not_checked": list((log_view or {}).get("not_checked") or []),
        "provenance": __ctx.provenance(built) if built else [],
        "source_hint": __ctx.hint_for(result, log_view) if result else "",
        "can_changes": _may_read_kea_log(),
        "input_labels": INPUT_LABELS,
        "form_fields": FIELDS[1:],
    }
