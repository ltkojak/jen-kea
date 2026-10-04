"""
jen/routes/client.py
──────────────────────
v5.63.0 (Q82) — GET /client?q=<identifier>&tab=<name>: the Investigation
page. One identifier, resolved once through jen.services.client_subject,
with seven tabs onto it: Overview (the subject itself, freshness stamps),
Explain, Trace and Timeline (each embedded via htmx from the existing
page's own HX-partial branch — the identical result, not a re-derived
one), DNS (dns_reconcile.reconcile over just this subject's own names),
Config (the same Explain evaluation, presented as effective subnet/pool/
options/classes, plus the config SHA) and, since v5.68.0-beta.1 (Q134),
Changes (the config revisions that touched this client's path —
jen.services.client_changes — for an admin who may see every subnet).
An IPv6 address or a DUID is a subject too (client_subject._resolve_v6).

Tabs are real query-string state (`?tab=`), not a client-side fragment —
each is independently linkable, reloadable, and (Explain/Trace/Timeline)
loads its own htmx fetch only when it's the active tab, so a page load
never pays for seven tabs' worth of work when the caller looked at one.
"""

import hashlib
import logging
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

import jen.services.kea6 as __kea6
from jen import extensions
from jen.services import client_changes as __changes
from jen.services import client_subject as __subject
from jen.services import config_revisions as __rev
from jen.services import dns_reconcile as __reconcile
from jen.services import explain_context as __ctx
from jen.services import investigation_providers as __providers
from jen.services.access import diagnostic_surface, get_accessible_subnet_map
from jen.services.subnet_context import dhcp4_config

logger = logging.getLogger(__name__)
bp = Blueprint("client", __name__)

TABS = ("overview", "explain", "trace", "timeline", "dns", "config", "changes")


_ALERT_TOKEN_SLOTS = 6  # the LIKE slots of _alert_status's one fixed statement


def _alert_matcher(mac: str, ip: str, addresses=()):
    """A compiled pattern that finds this client's MAC or an address of it in alert text as a WHOLE token:
    `10.0.0.5` must not match `10.0.0.50` (v5.65.2, Q91 c'), nor `2001:db8::1` match inside `2001:db8::10`
    (v5.68.0-beta.1, Q134: IPv6 addresses are tokens too, bounded by hex digits and colons)."""
    parts = []
    if mac:
        parts.append(r"(?<![0-9a-f:])" + re.escape(mac.lower()) + r"(?![0-9a-f:])")
    for token in dict.fromkeys(a for a in (ip, *addresses) if a):
        if ":" in token:
            parts.append(r"(?<![0-9a-f:])" + re.escape(token.lower()) + r"(?![0-9a-f:])")
        else:
            parts.append(r"(?<![0-9.])" + re.escape(token) + r"(?![0-9.])")
    return re.compile("|".join(parts), re.IGNORECASE) if parts else None


def _alert_status(mac: str, ip: str, addresses=()) -> dict | None:
    """The most recent alert_log row mentioning this client, or None — a
    lightweight status line for the Overview tab, not the full Timeline.

    alert_log rows carry no subnet (docs/ARCHITECTURE.md §2), so the CALLER decides whether this client's
    alert may be shown at all: an unrestricted user always, a restricted one only for a client whose view names
    a subnet they may see. Only type, status and time come back - never the message. The SQL LIKE is a cheap
    prefilter; the decision is a word-boundary match in Python."""
    matcher = _alert_matcher(mac, ip, addresses)
    if matcher is None:
        return None
    import jen.models.db as __db

    # one LIKE per token (the MAC, an address, up to four more) — a cheap prefilter over ONE fixed statement (no
    # SQL is built from the tokens); an unused slot is a pattern that matches nothing. The decision is `matcher`.
    tokens = list(dict.fromkeys(t for t in (mac, ip, *addresses) if t))[:_ALERT_TOKEN_SLOTS]
    patterns = [f"%{t}%" for t in tokens] + ["\x00\x00\x00"] * (_ALERT_TOKEN_SLOTS - len(tokens))
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT sent_at, alert_type, status, message FROM alert_log WHERE message LIKE %s OR message LIKE %s "
                "OR message LIKE %s OR message LIKE %s OR message LIKE %s OR message LIKE %s "
                "ORDER BY sent_at DESC LIMIT 200",
                tuple(patterns),
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


_TYPED_INPUTS = ("client_id", "vendor_class", "user_class", "hostname", "circuit_id", "remote_id", "giaddr")


def _typed_inputs() -> dict:
    """Explain inputs the person typed into the Explain tab's form (they ride the query string of /client)."""
    return {f: (request.args.get(f) or "").strip()[:255] for f in _TYPED_INPUTS if (request.args.get(f) or "").strip()}


def _may_read_kea_log() -> bool:
    """Kea's log has no subnet boundary Jen can trust: only an admin with access to every subnet gets log-derived inputs
    (the Trace rule, docs/ARCHITECTURE.md section 2)."""
    return bool(current_user.role in ("superadmin", "admin") and current_user.all_subnets)


def _built_inputs(view, *, fetch_log: bool = True) -> dict:
    """The client Explain evaluates for this view (v5.68.0-beta.2, Q135): the MAC, the lease row's client id and hostname
    (the view's lease was already judged by authorize()), what Kea's log said when the caller may read it, and what was
    typed - each labelled by source. `fetch_log=False` uses only a log read already cached (the Overview must not pay an SSH
    round trip for its one line). `?auto=0` turns every inferred source off."""
    auto = request.args.get("auto") != "0"
    log_view = __ctx.read_log(view.mac, allowed=_may_read_kea_log() and auto, fetch=fetch_log)
    built = __ctx.build_inputs(view.mac, typed=_typed_inputs(), lease=view.lease, log=log_view, auto=auto)
    built["log_view"] = log_view
    return built


def _explain_run(view, subnet_id, built):
    """explain() for the view's own subnet, with the pool-occupancy and holder lookups bound to this caller's scope."""
    cfg = dhcp4_config()
    if not cfg:
        return None
    # view.reservations was judged by authorize() (global reservations kept for everyone)
    return __ctx.run(
        cfg,
        built,
        subnet_id=subnet_id,
        lease=view.lease,
        reservations=view.reservations,
        accessible_ids=None if current_user.all_subnets else set(get_accessible_subnet_map()),
    )


def _overview_line(view) -> str:
    """The one sentence of what Kea would do with this client (the Overview, Q135 c): Explain's own answer line for the
    subnet its lease or reservation fixes, from the lease-derived inputs plus a Kea-log read that is already cached - never
    a fresh SSH round trip. '' when there is no subnet to evaluate, no Kea answer, or anything fails."""
    if not view.mac:
        return ""
    try:
        _client, subnet_id, _how = _explain_inputs(view)
        if subnet_id is None:
            return ""
        result = _explain_run(view, subnet_id, _built_inputs(view, fetch_log=False))
        return (result or {}).get("summary", "") if result and result.get("ok") else ""
    except Exception as e:
        logger.warning(f"client: overview answer line failed: {e}")
        return ""


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
    result = _explain_run(view, subnet_id, _built_inputs(view))
    config_sha = hashlib.sha256(__rev.canonical(cfg).encode()).hexdigest()
    return (result if result and result.get("ok") else None), config_sha


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


def _matched_classes(view) -> list[str]:
    """The client classes the Explain evaluation says this client matches, for the Changes tab's path (a class it matches
    belongs to its path whether or not any subnet names it). Never raises: no Kea answer, no subnet fixed or no MAC is
    simply no classes."""
    if not view.mac:
        return []
    try:
        _client, subnet_id, _how = _explain_inputs(view)
        result = _explain_run(view, subnet_id, _built_inputs(view)) if subnet_id is not None else None
        if not result:
            return []
        return [c["name"] for c in (result.get("classes") or []) if c.get("matched") is True]
    except Exception as e:
        logger.warning(f"client: matched-class lookup for the Changes tab failed: {e}")
        return []


@bp.route("/client")
@login_required
@diagnostic_surface(subject="client")
def client_page():
    q = (request.args.get("q") or "").strip()
    # v5.68.0-beta.1 (Q134 c): the Changes tab reads config revisions, which are admin content under
    # /servers/<id>/config-history (an admin who may see every subnet) - the tab follows that rule and is not even
    # offered to anyone else
    changes_allowed = bool(current_user.role in ("superadmin", "admin") and current_user.all_subnets)
    tabs = tuple(t for t in TABS if t != "changes" or changes_allowed)
    tab = request.args.get("tab", "overview")
    if tab not in tabs:
        tab = "overview"

    investigation_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(3)

    subject = None
    view = None
    unsupported = ""
    if q:
        accessible_ids = None if current_user.all_subnets else set(get_accessible_subnet_map())
        subject = __subject.resolve(q, accessible_ids=accessible_ids, all_subnets=current_user.all_subnets)
        if subject.kind in ("ipv6", "duid") and not __kea6.is_ipv6_enabled():
            unsupported = (
                "IPv6 is turned off in Jen, so an IPv6 address or a DUID cannot be looked up. "
                "Turn it on under Settings → Kea, or search by the client's MAC."
            )
        elif subject.kind in ("mac", "ipv4", "hostname", "ipv6", "duid") and subject.found:
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

    # alert_log rows carry no subnet, so the match is judged on the CLIENT: shown to a caller who may see every
    # subnet, and to a restricted one only when the resolved view names a subnet they may see (an alert about THEIR
    # client). What is shown is the alert's type, status and time - never its message, which can name a subnet.
    # (v5.68.0-beta.1, Q134; docs/ARCHITECTURE.md §2.)
    alert = None
    if view and not view.candidates and (current_user.all_subnets or __subject.names_a_subnet(view)):
        alert = _alert_status(view.mac, view.ip, [a["address"] for a in view.leases6])

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

    explain_qs = ""
    explain_line = ""
    if view and view.mac:
        if tab == "explain" and chosen_subnet is not None:
            # what the embedded Explain fetch is told: the MAC, the subnet, the identifier to go back to (so its form returns
            # HERE), and whatever the person has typed into that form so far
            params = {"mac": view.mac, "subnet": chosen_subnet, "embed_q": q, **_typed_inputs()}
            if request.args.get("auto") == "0":
                params["auto"] = "0"
            explain_qs = urlencode(params)
        if tab == "overview":
            explain_line = _overview_line(view)

    # v5.68.0-beta.4 (Q139): what each plugin knows about this client, one card per plugin. The view handed to them is the one
    # `authorize` already judged for this caller, and a client the caller cannot place in a subnet never got this far (the
    # `names_a_subnet` gate above), so a provider sees only what the caller may and an outside client is not an existence oracle.
    plugin_cards: list = []
    plugin_warnings: list = []
    if view and tab == "overview" and not view.candidates and view.found:
        plugin_cards = __providers.run_investigation_providers(
            view, set(get_accessible_subnet_map()), current_user.all_subnets
        )
        plugin_warnings = __providers.warnings_line(plugin_cards)

    element = (request.args.get("element") or "").strip()[:200]
    changes = None
    if view and not view.candidates and tab == "changes" and changes_allowed:
        changes = __changes.for_view(
            view,
            extensions.KEA_SERVERS,
            subnet_map=extensions.SUBNET_MAP,
            subnet6_map=extensions.SUBNET6_MAP,
            ipv6_on=__kea6.is_ipv6_enabled(),
            classes=_matched_classes(view),
            element=element,
        )

    return render_template(
        "client.html",
        q=q,
        tab=tab,
        tabs=tabs,
        changes=changes,
        element=element,
        explain_qs=explain_qs,
        explain_line=explain_line,
        plugin_cards=plugin_cards,
        plugin_warnings=plugin_warnings,
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
