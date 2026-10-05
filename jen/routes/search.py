"""
jen/routes/search.py
─────────────────────
Global search and saved searches routes.
"""

import logging

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.models.db as __db
import jen.services.auth as __auth
import jen.services.client_subject as __subject
import jen.services.kea6 as __kea6
from jen import extensions
from jen.services.access import accessible_subnet6_map, diagnostic_surface

logger = logging.getLogger(__name__)
bp = Blueprint("search", __name__)


def _JEN_VERSION():
    from jen import JEN_VERSION

    return JEN_VERSION


# the kinds of identifier jen.services.client_subject.detect_kind names that the search box hands to /client
_GOES_TO_CLIENT_PAGE = frozenset({"mac", "ipv4"})
_GOES_WHEN_V6_IS_ON = frozenset({"ipv6", "duid"})


def __ip_to_int(ip):
    parts = ip.split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


@bp.route("/search")
@login_required
@diagnostic_surface(subject="client")
def global_search():
    typed = request.args.get("q", "").strip()
    # v5.68.0-beta.1 (Q134) - one whole identifier (a MAC or an IPv4 address) is a question about ONE client, and the
    # Investigation page is the answer to it, so the search box goes straight there instead of to a list with an
    # Investigate button on every row. `list=1` is the way back to the list (the Investigation page links to it).
    # Anything that is not exactly one identifier - a hostname, a fragment, a partial MAC - still searches.
    # An IPv6 address or a DUID goes the same way once IPv6 is on (the page resolves them through lease6 and the v6
    # reservations); with it off the results page is what the box has always shown.
    if request.args.get("list") != "1":
        kind = __subject.detect_kind(typed)[0]
        if kind in _GOES_TO_CLIENT_PAGE or (kind in _GOES_WHEN_V6_IS_ON and __kea6.is_ipv6_enabled()):
            return redirect(url_for("client.client_page", q=typed))
    q = __auth.sanitize_search(typed)
    results = {"leases": [], "reservations": [], "devices": [], "leases6": [], "reservations6": []}
    if len(q) >= 2:
        try:
            with __db.kea_db() as kdb, __db.jen_db() as jdb:
                s = f"%{q}%"
                s_mac = s.replace(":", "")

                # Subnet-restricted users only ever see results from
                # subnets they're assigned — same rule list/detail views
                # already enforce. Applied identically to all three
                # result sets below (v4.4.4 — this route previously
                # leaked leases/reservations/devices across subnets to
                # restricted admins/viewers).
                from jen.services.access import add_subnet_restriction

                # Search leases
                where, params = (
                    ["(inet_ntoa(l.address) LIKE %s OR l.hostname LIKE %s OR HEX(l.hwaddr) LIKE %s)"],
                    [s, s, s_mac],
                )
                where, params = add_subnet_restriction(where, params, "l", "subnet_id")
                with kdb.cursor() as cur:
                    cur.execute(
                        f"""
                            SELECT inet_ntoa(l.address) AS ip,
                                   l.hostname,
                                   HEX(l.hwaddr) AS mac_hex,
                                   l.subnet_id,
                                   l.expire, l.state
                            FROM lease4 l
                            WHERE {" AND ".join(where)}
                            LIMIT 20
                        """,
                        params,
                    )
                    for row in cur.fetchall():
                        mac = ":".join(row["mac_hex"][i : i + 2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                        results["leases"].append(
                            {
                                "ip": row["ip"],
                                "hostname": row["hostname"] or "",
                                "mac": mac,
                                "subnet_id": row["subnet_id"],
                            }
                        )

                # Search reservations
                where, params = (
                    [
                        "h.dhcp4_subnet_id > 0",
                        "(inet_ntoa(h.ipv4_address) LIKE %s OR h.hostname LIKE %s OR HEX(h.dhcp_identifier) LIKE %s)",
                    ],
                    [s, s, s_mac],
                )
                where, params = add_subnet_restriction(where, params, "h", "dhcp4_subnet_id")
                with kdb.cursor() as cur:
                    cur.execute(
                        f"""
                            SELECT inet_ntoa(h.ipv4_address) AS ip,
                                   h.hostname,
                                   HEX(h.dhcp_identifier) AS mac_hex,
                                   h.dhcp4_subnet_id AS subnet_id
                            FROM hosts h
                            WHERE {" AND ".join(where)}
                            LIMIT 20
                        """,
                        params,
                    )
                    for row in cur.fetchall():
                        mac = ":".join(row["mac_hex"][i : i + 2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                        results["reservations"].append(
                            {
                                "ip": row["ip"],
                                "hostname": row["hostname"] or "",
                                "mac": mac,
                                "subnet_id": row["subnet_id"],
                            }
                        )

                # Search devices — devices.last_subnet_id is nullable (a device
                # Jen has never placed in a subnet). An unattributed object is
                # visible to all_subnets users only, the same rule as the v6
                # search below; a restricted user gets only devices in a subnet
                # they can access, and with none, nothing.
                where, params = (
                    ["(mac LIKE %s OR last_ip LIKE %s OR device_name LIKE %s OR owner LIKE %s)"],
                    [s, s, s, s],
                )
                if not current_user.all_subnets:
                    ids = current_user.accessible_subnet_ids(extensions.SUBNET_MAP)
                    if ids:
                        placeholders = ",".join(["%s"] * len(ids))
                        where.append(f"last_subnet_id IN ({placeholders})")
                        params.extend(ids)
                    else:
                        where.append("1=0")
                with jdb.cursor() as cur:
                    cur.execute(
                        f"""
                            SELECT mac, last_ip, device_name AS name, owner, notes, last_subnet_id
                            FROM devices
                            WHERE {" AND ".join(where)}
                            LIMIT 20
                        """,
                        params,
                    )
                    results["devices"] = cur.fetchall()

                # v5.0 Phase 4 — IPv6 leases/reservations. Only searched
                # when v6 is genuinely on (display gate, same as every
                # other v6 code path) and there's something configured
                # to search. Subnet restriction is the one v6 rule
                # (access.accessible_subnet6_map, v5.68.0-beta.8 / Q143).
                if __kea6.is_ipv6_enabled() and extensions.SUBNET6_MAP:
                    searchable_v6_ids = list(accessible_subnet6_map())
                    for sid in searchable_v6_ids:
                        try:
                            for lease in __kea6.list_lease6(subnet_id=sid, search=q)[:20]:
                                results["leases6"].append(
                                    {
                                        "address": lease["address"],
                                        "hostname": lease["hostname"],
                                        "duid_hex": lease["duid_hex"],
                                        "subnet_id": lease["subnet_id"],
                                        "lease_type_name": lease["lease_type_name"],
                                    }
                                )
                        except Exception:
                            pass
                    for sid in searchable_v6_ids:
                        try:
                            # filter EVERY reservation of the subnet through the one predicate, THEN cap
                            # (v5.67.0-beta.17, Q131): capping first never found the 21st host of a subnet
                            matching = [
                                h
                                for h in __kea6.get_ipv6_reservations(subnet_id=sid)
                                if __kea6._reservation6_matches(h, q)
                            ]
                            for h in matching[:20]:
                                results["reservations6"].append(
                                    {
                                        "hostname": h["hostname"],
                                        "duid_hex": h["duid_hex"],
                                        "subnet_id": h["subnet_id"],
                                        "addresses": [r["address"] for r in h["reservations"]],
                                    }
                                )
                        except Exception:
                            pass

        except Exception as e:
            logger.error(f"Search error: {e}")
            flash("Search failed. Check server logs for details.", "error")

    total = sum(len(v) for v in results.values())
    subnet_names = {sid: info["name"] for sid, info in current_user.filter_subnet_map(extensions.SUBNET_MAP).items()}
    subnet6_names = {sid: info["name"] for sid, info in accessible_subnet6_map().items()}

    # v5.57.0 (Q73) — one card per plugin search provider, after the core
    # sections. Same q>=2 gate as everything above; accessible_subnet_ids
    # is this restricted user's own view, the same one add_subnet_restriction
    # enforces for the core searches — a provider is handed it to filter by,
    # and Jen filters again on the way back out (the Q55 rule).
    provider_results = []
    if len(q) >= 2:
        from jen.services.search_providers import run_search_providers

        accessible_subnet_ids = list(current_user.filter_subnet_map(extensions.SUBNET_MAP).keys())
        try:
            provider_results = run_search_providers(q, accessible_subnet_ids, current_user.all_subnets)
        except Exception as e:
            logger.error(f"Search providers error: {e}")

    return render_template(
        "search_results.html",
        q=q,
        results=results,
        total=total,
        subnet_map=current_user.filter_subnet_map(extensions.SUBNET_MAP),
        subnet_names=subnet_names,
        subnet6_names=subnet6_names,
        provider_results=provider_results,
    )


# ─────────────────────────────────────────
# MFA Routes
# ─────────────────────────────────────────


@bp.route("/saved-searches", methods=["GET"])
@login_required
def saved_searches():
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT * FROM saved_searches WHERE user_id=%s ORDER BY created_at DESC", (current_user.id,))
            searches = cur.fetchall()
    except Exception:
        searches = []
    return render_template("saved_searches.html", searches=searches)


@bp.route("/saved-searches/save", methods=["POST"])
@login_required
def save_search():
    name = request.form.get("name", "").strip()[:100]
    page = request.form.get("page", "").strip()[:50]
    params = request.form.get("params", "").strip()[:1000]
    if not name or not page:
        return jsonify({"error": "Name and page required"}), 400
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                # Max 20 saved searches per user
                cur.execute("SELECT COUNT(*) as cnt FROM saved_searches WHERE user_id=%s", (current_user.id,))
                if cur.fetchone()["cnt"] >= 20:
                    cur.execute(
                        """DELETE FROM saved_searches WHERE user_id=%s
                                   ORDER BY created_at ASC LIMIT 1""",
                        (current_user.id,),
                    )
                cur.execute(
                    "INSERT INTO saved_searches (user_id, name, page, params) VALUES (%s,%s,%s,%s)",
                    (current_user.id, name, page, params),
                )
            db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        logger.error(f"Error saving search for {current_user.username}: {e}")
        return jsonify({"error": "Could not save search."}), 500


@bp.route("/saved-searches/delete/<int:search_id>", methods=["POST"])
@login_required
def delete_saved_search(search_id):
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM saved_searches WHERE id=%s AND user_id=%s", (search_id, current_user.id))
            db.commit()
    except Exception:
        pass
    return redirect(url_for("search.saved_searches"))


@bp.route("/api/saved-searches")
@login_required
def api_saved_searches():
    page = request.args.get("page", "")
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            if page:
                cur.execute(
                    "SELECT * FROM saved_searches WHERE user_id=%s AND page=%s ORDER BY name",
                    (current_user.id, page),
                )
            else:
                cur.execute("SELECT * FROM saved_searches WHERE user_id=%s ORDER BY name", (current_user.id,))
            searches = cur.fetchall()
        return jsonify([dict(s) for s in searches])
    except Exception:
        return jsonify([])


# ─────────────────────────────────────────
