"""
jen/routes/client.py
──────────────────────
v5.63.0 (Q82) — GET /client?q=<identifier>&tab=<name>: the Investigation
page. One identifier, resolved once through jen.services.client_subject,
with six tabs onto it: Overview (the subject itself, freshness stamps),
Explain, Trace and Timeline (each embedded via htmx from the existing
page's own HX-partial branch — the identical result, not a re-derived
one), DNS (dns_reconcile.reconcile over just this subject's own names),
Config (the same Explain evaluation, presented as effective subnet/pool/
options/classes, plus the config SHA).

Tabs are real query-string state (`?tab=`), not a client-side fragment —
each is independently linkable, reloadable, and (Explain/Trace/Timeline)
loads its own htmx fetch only when it's the active tab, so a page load
never pays for six tabs' worth of work when the caller looked at one.
"""

import hashlib
import logging
import re
import secrets
from datetime import datetime, timezone

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from jen.services import client_subject as __subject
from jen.services import config_revisions as __rev
from jen.services import dns_reconcile as __reconcile
from jen.services.access import diagnostic_surface, get_accessible_subnet_map
from jen.services.dhcp_explain import explain
from jen.services.subnet_context import dhcp4_config

logger = logging.getLogger(__name__)
bp = Blueprint("client", __name__)

TABS = ("overview", "explain", "trace", "timeline", "dns", "config")


def _alert_matcher(mac: str, ip: str):
    """A compiled pattern that finds this client's MAC or IP in alert text as a WHOLE token:
    `10.0.0.5` must not match `10.0.0.50` (v5.65.2, Q91 c')."""
    parts = []
    if mac:
        parts.append(r"(?<![0-9a-f:])" + re.escape(mac.lower()) + r"(?![0-9a-f:])")
    if ip:
        parts.append(r"(?<![0-9.])" + re.escape(ip) + r"(?![0-9.])")
    return re.compile("|".join(parts), re.IGNORECASE) if parts else None


def _alert_status(mac: str, ip: str) -> dict | None:
    """The most recent alert_log row mentioning this client, or None — a
    lightweight status line for the Overview tab, not the full Timeline.

    alert_log rows carry no subnet, so (docs/ARCHITECTURE.md §2: audit/alert matches are
    unrestricted-only, as Timeline enforces) the caller only asks for a subnet-unrestricted
    user. The SQL LIKE is a cheap prefilter; the decision is a word-boundary match in Python."""
    matcher = _alert_matcher(mac, ip)
    if matcher is None:
        return None
    import jen.models.db as __db

    mac_pat = f"%{mac}%" if mac else "\x00\x00\x00"
    ip_pat = f"%{ip}%" if ip else "\x00\x00\x00"
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT sent_at, alert_type, status, message FROM alert_log WHERE message LIKE %s OR message LIKE %s "
                "ORDER BY sent_at DESC LIMIT 200",
                (mac_pat, ip_pat),
            )
            for row in cur.fetchall():
                if matcher.search(row.get("message") or ""):
                    return {k: row[k] for k in ("sent_at", "alert_type", "status")}
    except Exception as e:
        logger.error(f"client: alert status lookup failed for mac={mac!r} ip={ip!r}: {e}")
    return None


def _explain_inputs(view) -> tuple[dict, int | None, str]:
    """The subnet the Explain and Config tabs evaluate against, over an already
    resolved/authorized ClientSubject: an explicit `?subnet=` > the current lease >
    a reservation, and NOTHING else. (v5.65.2, Q91 f: it used to fall through to
    "the first subnet you can see", so a client known only by a device row got an
    "effective configuration" evaluated against whichever subnet happened to come
    first. With no subnet fixed, the tabs show a picker and evaluate nothing.)"""
    subnet_map = get_accessible_subnet_map()
    client = {"mac": view.mac}
    raw_subnet = (request.args.get("subnet") or "").strip()
    subnet_id = None
    chosen_how = ""
    if raw_subnet.isdigit():
        subnet_id = int(raw_subnet)
        chosen_how = "chosen"
    elif view.lease and view.lease.get("subnet_id"):
        subnet_id = int(view.lease["subnet_id"])
        chosen_how = "from the current lease"
    elif view.reservation and view.reservation.get("subnet_id"):
        subnet_id = int(view.reservation["subnet_id"])
        chosen_how = "from a reservation"
    if subnet_id is not None and subnet_id not in subnet_map:
        subnet_id, chosen_how = None, ""
    return client, subnet_id, chosen_how


def _config_tab(view):
    """Config tab: the same Explain evaluation, read for its
    subnet/pool/options/classes rather than its step-by-step narrative,
    plus the live config's SHA (config_revisions' own hasher — the same
    one every Kea-config-history record uses)."""
    client, subnet_id, chosen_how = _explain_inputs(view)
    if subnet_id is None:
        return None, ""
    cfg = dhcp4_config()
    if not cfg:
        return None, ""
    # view.reservations was judged by authorize() (global reservations kept for everyone)
    result = explain(cfg, client, subnet_id=subnet_id, reservations=view.reservations, lease=view.lease)
    config_sha = hashlib.sha256(__rev.canonical(cfg).encode()).hexdigest()
    return (result if result.get("ok") else None), config_sha


def _dns_tab(view):
    """DNS tab: dns_reconcile.reconcile() over just this subject's own
    reservation/lease names — never the fleet-wide rows /ddns/reconcile
    builds. `import jen.routes.ddns` for `_run_verify`/`_reconcile_suffix`
    reuses the exact same resolver and DDNS-suffix lookup that page uses."""
    rows = []
    if view.reservation and view.reservation.get("hostname"):
        rows.append({"name": view.reservation["hostname"], "ip": view.reservation["ip"], "source": "reservation"})
    if view.lease and view.lease.get("hostname"):
        rows.append({"name": view.lease["hostname"], "ip": view.lease["ip"], "source": "lease"})
    if not rows:
        return [], ""
    from jen.routes.ddns import _reconcile_suffix, _run_verify

    try:
        suffix = _reconcile_suffix()
        results = __reconcile.reconcile(rows, _run_verify, suffix=suffix, limit=10)
        return results, ""
    except __reconcile.ReconcileBusy:
        return [], "A fleet-wide reconciliation is running right now — try again in a moment."
    except Exception as e:
        logger.error(f"client: DNS tab reconcile failed: {e}")
        return [], "Could not check DNS. Check server logs for details."


@bp.route("/client")
@login_required
@diagnostic_surface(subject="client")
def client_page():
    q = (request.args.get("q") or "").strip()
    tab = request.args.get("tab", "overview")
    if tab not in TABS:
        tab = "overview"

    investigation_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(3)

    subject = None
    view = None
    unsupported = ""
    if q:
        accessible_ids = None if current_user.all_subnets else set(get_accessible_subnet_map())
        subject = __subject.resolve(q, accessible_ids=accessible_ids, all_subnets=current_user.all_subnets)
        if subject.kind in ("ipv6", "duid"):
            unsupported = "IPv6 and DUID lookups are not supported yet — search by the client's MAC."
        elif subject.kind in ("mac", "ipv4", "hostname") and subject.found:
            view = __subject.authorize(subject, rule="per_object", accessible_ids=accessible_ids)
            # v5.63.0 (Q82) — `view.found` alone isn't the right signal here:
            # a blanked device dict (placement fields None, bookends kept)
            # is still non-None, so it's still "found". The real question,
            # the same one timeline_page() asks via subnet_id_for(), is
            # whether ANYTHING SURVIVED that actually names a subnet.
            # v5.65.2 (Q91): a hostname shared by several clients is answered from
            # `view.candidates` (each judged like a subject of its own), never from
            # `subject.candidates`; and a denial is the same "no client matched"
            # answer as not-found, so the page is not an existence oracle.
            if not view.candidates and not current_user.all_subnets and not __subject.names_a_subnet(view):
                view = None

    # alert_log rows carry no subnet: unrestricted callers only (docs/ARCHITECTURE.md §2)
    alert = _alert_status(view.mac, view.ip) if view and current_user.all_subnets else None

    trace_allowed = bool(current_user.role in ("superadmin", "admin") and current_user.all_subnets)

    config_result = None
    config_sha = ""
    dns_results: list = []
    dns_error = ""
    chosen_subnet = None
    chosen_how = ""
    if view and view.mac:
        if tab in ("explain", "config"):
            _client, chosen_subnet, chosen_how = _explain_inputs(view)
        if tab == "config" and chosen_subnet is not None:
            config_result, config_sha = _config_tab(view)
        if tab == "dns":
            dns_results, dns_error = _dns_tab(view)

    return render_template(
        "client.html",
        q=q,
        tab=tab,
        tabs=TABS,
        subject=subject,
        view=view,
        unsupported=unsupported,
        chosen_subnet=chosen_subnet,
        chosen_how=chosen_how,
        subnet_choices=get_accessible_subnet_map(),
        alert=alert,
        trace_allowed=trace_allowed,
        config_result=config_result,
        config_sha=config_sha,
        dns_results=dns_results,
        dns_error=dns_error,
        investigation_id=investigation_id,
    )
