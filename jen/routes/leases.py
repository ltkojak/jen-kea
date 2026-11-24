"""
jen/routes/leases.py
─────────────────────
Lease management routes.
"""

import ipaddress
import logging

from flask import Blueprint, flash, make_response, redirect, render_template, request, url_for
from flask_login import current_user, login_required

import jen.models.db as __db
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.fingerprint as __fp
import jen.services.kea as __kea
import jen.services.kea6 as __kea6
import jen.services.view_prefs as __view_prefs
from jen import extensions
from jen.services.access import accessible_subnet6_map, assert_subnet6_access, sees_reservation_in
from jen.services.access import admin_required as _admin_required
from jen.services.leases_sql import ACTIVE_LEASE4, active_lease4
from jen.services.pools import parse_pool
from jen.services.reltime import plural as _plural

logger = logging.getLogger(__name__)
bp = Blueprint("leases", __name__)

# Q248 (addition 5) - the two conditions the summary line's counts link to, each ONE MORE condition of the list's own query (fixed text; the one value is a parameter).
#: "expires within the hour": the condition the summary has counted with since Q206, on the one clock every connection runs in (UTC)
EXPIRING_SOON = "l.expire <= NOW() + INTERVAL 1 HOUR"
#: Q249 - "this lease has a reservation" reads only a host row that is an IPv4 reservation: one whose `dhcp4_subnet_id` is not NULL. Kea keeps an IPv6
#: reservation in the same table with `dhcp4_subnet_id` NULL, and one identified by the same hardware address marked the client's IPv4 lease Reserved (and broke
#: the page for a subnet-restricted account). Subnet 0 is Kea's GLOBAL IPv4 reservation and is one: it marks the lease for every account (Q250: it belongs to
#: no subnet an account can be scoped out of - `access.sees_reservation_in` is the one rule of who counts which reservation).
#: `{h}` is the alias of the hosts table, with its dot, or nothing.
V4_RESERVATION = "{h}dhcp4_subnet_id IS NOT NULL"
#: "reserved": the lease's client has a reservation - what the summary's "N reserved" has counted since Q206 ...
#: (written out as ONE literal: `tests/test_q249_b.py` holds it to `V4_RESERVATION`, and a string built with `+` reads as assembled SQL to bandit, B608)
RESERVED_ANY = "EXISTS (SELECT 1 FROM hosts h WHERE h.dhcp_identifier = l.hwaddr AND h.dhcp4_subnet_id IS NOT NULL)"
#: ... in a subnet the caller may see (Q206, SP-1: a hidden subnet's reservation never changes a visible answer), or a global one (Q250: subnet 0; the SQL of
#: `access.sees_reservation_in`). The parameter is the caller's own subnet ids, "1,3". A NULL id (an IPv6 reservation) matches neither half.
RESERVED_VISIBLE = "EXISTS (SELECT 1 FROM hosts h WHERE h.dhcp_identifier = l.hwaddr AND (h.dhcp4_subnet_id = 0 OR FIND_IN_SET(h.dhcp4_subnet_id, %s)))"


def _stored_subnet_ids(account) -> str:
    """Q251 - the subnet ids an account that does not see every subnet STORES, as the "1,3" `RESERVED_VISIBLE` is given: the same list
    `User.can_access_subnet` answers from (`subnet_access_list`), so the Reserved filter and the row's Reserved mark ask one set."""
    return ",".join(
        str(i) for i in (account.subnet_access_list or []) if isinstance(i, int) and not isinstance(i, bool)
    )


def _JEN_VERSION():
    from jen import JEN_VERSION

    return JEN_VERSION


@bp.route("/leases")
@login_required
def leases():
    view_mode = request.args.get("view", "v4")
    # v5.69.0-beta.2 (Q171): IPv6 is off until the superadmin turns it on, and a `[subnets6]` section in the config does not turn it on - the view falls back to the v4 page
    if view_mode == "v6" and __kea6.is_ipv6_enabled():
        return _leases_v6()

    subnet_filter = request.args.get("subnet", "all")
    minutes = request.args.get("minutes", "")
    search = __auth.sanitize_search(request.args.get("search", "").strip())
    show_expired = request.args.get("expired", "0") == "1"
    # Q248 (addition 5): the two filters of the live list. The history has neither a count nor a mark for them, so it has neither filter.
    reserved_only = request.args.get("reserved") == "1" and not show_expired
    expiring_only = request.args.get("expiring") == "1" and not show_expired
    sort = request.args.get("sort", "expires")
    direction = request.args.get("dir", "desc")
    if direction not in ("asc", "desc"):
        direction = "desc"
    sort_map = {
        "ip": "l.address",
        "hostname": "COALESCE(l.hostname, '')",  # (Q205 AU10: NULL and an empty name sort together)
        "mac": "l.hwaddr",
        "subnet": "l.subnet_id",
        "obtained": "(l.expire - INTERVAL l.valid_lifetime SECOND)",
        "expires": "l.expire",
    }
    # Q210 (AZ6 a): the EFFECTIVE sort reaches the template, so ?sort=bogus (or an empty or mistyped one) marks the default column the rows are really ordered by
    sort = sort if sort in sort_map else "expires"
    sort_col = sort_map[sort]
    # Pagination — default is "all" (no limit). User can opt-in to per-page, and the choice is remembered per browser (Q206, AV5: view_prefs, the `jen_view` cookie).
    per_page_param, remembered = __view_prefs.resolve("leases", request.args, request.cookies)
    try:
        per_page = int(per_page_param) if per_page_param != "all" else None
    except ValueError:
        per_page = None
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    if per_page is None:
        page = 1  # no pagination = always page 1
    if subnet_filter != "all":
        try:
            if int(subnet_filter) not in extensions.SUBNET_MAP or not current_user.can_access_subnet(
                int(subnet_filter)
            ):
                subnet_filter = "all"
        except ValueError:
            subnet_filter = "all"

    # Build accessible subnet map for this user
    accessible_subnet_map = current_user.filter_subnet_map(extensions.SUBNET_MAP)
    leases_list = []
    total = 0
    expiring_soon = 0
    reserved_visible = set()
    reserved_listed = set()
    minutes_applied = None
    try:
        with __db.kea_db() as db:
            with db.cursor() as cur:
                where = []
                params = []
                if not show_expired:
                    where.append(active_lease4("l"))
                if subnet_filter != "all":
                    where.append("l.subnet_id=%s")
                    params.append(int(subnet_filter))
                elif not current_user.all_subnets:
                    # Restrict to accessible subnets
                    from jen.services.access import add_subnet_restriction

                    where, params = add_subnet_restriction(where, params, "l", "subnet_id")
                if minutes:
                    try:
                        mins = int(minutes)
                        minutes_applied = mins
                        where.append("FROM_UNIXTIME(l.expire) >= DATE_SUB(NOW(), INTERVAL %s MINUTE)")
                        params.append(mins)
                    except ValueError:
                        pass
                if search:
                    where.append("(inet_ntoa(l.address) LIKE %s OR l.hostname LIKE %s OR HEX(l.hwaddr) LIKE %s)")
                    s = f"%{search}%"
                    params += [s, s, s.replace(":", "")]
                # Q248 (addition 5): each filter is one more condition of this same `where` - inside the subnet restriction above, counted by the same COUNT, paged by
                # the same LIMIT. "Reserved" asks about the hosts table, so it carries the caller's scope itself: a restricted account's filter matches a reservation
                # only in a subnet it may see, or a global one, which is what its "N reserved" counts.
                if expiring_only:
                    where.append(EXPIRING_SOON)
                if reserved_only:
                    if current_user.all_subnets:
                        where.append(RESERVED_ANY)
                    else:
                        where.append(RESERVED_VISIBLE)
                        # (Q251) the account's STORED subnet ids, the list `can_access_subnet` (and so the row's mark, `sees_reservation_in`) reads. This was
                        # the stored list cut to Jen's subnet map: an account scoped to a subnet the map does not name read "1 reserved" above a filter
                        # that listed nothing.
                        params.append(_stored_subnet_ids(current_user))
                where_str = " AND ".join(where) if where else "1=1"
                cur.execute(f"SELECT COUNT(*) as cnt FROM lease4 l WHERE {where_str}", params)
                total = cur.fetchone()["cnt"]
                if not show_expired and total:
                    # Q206 (AV4): the summary line says how many of THIS filtered set expire within the hour - the same `where`, one more condition, one clock (every connection runs in UTC)
                    cur.execute(
                        f"SELECT COUNT(*) as cnt FROM lease4 l WHERE {where_str} AND {EXPIRING_SOON}",
                        params,
                    )
                    expiring_soon = cur.fetchone()["cnt"]
                if per_page:
                    offset = (page - 1) * per_page
                    limit_clause = f"LIMIT {per_page} OFFSET {offset}"
                else:
                    limit_clause = ""
                cur.execute(
                    f"""
                    SELECT inet_ntoa(l.address) AS ip, l.hostname,
                           HEX(l.hwaddr) AS mac_hex, l.subnet_id, l.state,
                           l.expire,
                           (l.expire - INTERVAL l.valid_lifetime SECOND) AS obtained,
                           l.expire AS expires,
                           ({EXPIRING_SOON}) AS expires_soon
                    FROM lease4 l WHERE {where_str}
                    ORDER BY {sort_col} {direction}
                    {limit_clause}
                """,
                    params,
                )
                for row in cur.fetchall():
                    mac = ":".join(row["mac_hex"][i : i + 2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                    leases_list.append(
                        {
                            **row,
                            "mac": mac,
                            "subnet_id": row["subnet_id"],
                            "subnet_name": extensions.SUBNET_MAP.get(row["subnet_id"], {}).get("name", ""),
                        }
                    )
            # Build set of MACs that have reservations — single query, O(1) lookup per lease
            if leases_list:
                mac_hexes = [row["mac"].replace(":", "") for row in leases_list if row.get("mac")]
                if mac_hexes:
                    placeholders = ",".join(["%s"] * len(mac_hexes))
                    with db.cursor() as res_cur:
                        res_cur.execute(
                            # (Q249) only a reservation with an IPv4 subnet: V4_RESERVATION
                            f"SELECT HEX(dhcp_identifier) AS mac_hex, dhcp4_subnet_id AS subnet_id FROM hosts WHERE HEX(dhcp_identifier) IN ({placeholders}) "
                            f"AND {V4_RESERVATION.format(h='')}",
                            mac_hexes,
                        )
                        host_rows = res_cur.fetchall()
                        # Q206 (SP-1): the summary's "N reserved" is a number a viewer reads, so it counts only a reservation the caller may see; a hidden subnet's
                        # reservation never changes a visible answer. Q250: ONE rule (`sees_reservation_in`: the caller's subnets and Kea's global ones), and the admin's
                        # checkbox and menu read it too. `has_reservation` read every subnet, so a one-subnet admin's row for a client reserved only in a hidden
                        # subnet had a disabled box titled Reserved and "View reservation" where Create, Explain and Release belong.
                        reserved_visible = {
                            row["mac_hex"].upper()
                            for row in host_rows
                            if sees_reservation_in(current_user, row["subnet_id"])
                        }
                        # (Q251) of those, the ones the Reservations list can show: it lists a reservation of a subnet (an id above 0), never Kea's global
                        # ones. A client reserved only globally has "View reservation (global)" in its menu, to its Investigate page.
                        reserved_listed = {
                            row["mac_hex"].upper()
                            for row in host_rows
                            if row["subnet_id"]
                            and row["subnet_id"] > 0
                            and sees_reservation_in(current_user, row["subnet_id"])
                        }
            for lease in leases_list:
                # Q248 (addition 5): the row's "Reserved" mark is what the summary counts - a reservation the caller may see. (Q250) `has_reservation`, which the
                # admin's checkbox and menu read, is the same answer.
                lease["reserved"] = lease["mac"].replace(":", "").upper() in reserved_visible
                lease["has_reservation"] = lease["reserved"]
                lease["reservation_listed"] = lease["mac"].replace(":", "").upper() in reserved_listed
    except Exception as e:
        logger.error(f"Could not load leases: {e}")
        flash("Could not load leases. Check server logs for details.", "error")
    pages = max(1, (total + per_page - 1) // per_page) if per_page else 1
    mac_list = [row["mac"] for row in leases_list if row.get("mac")]
    device_info = __fp.get_device_info_map(mac_list)
    template_vars = {
        "leases": leases_list,
        "page": page,
        "pages": pages,
        "total": total,
        "subnet_filter": subnet_filter,
        "minutes": minutes,
        "search": search,
        "show_expired": show_expired,
        "subnet_map": accessible_subnet_map,
        "sort": sort,
        "direction": direction,
        "device_info": device_info,
        "per_page": per_page_param,
        "get_manufacturer_icon_url": __fp.get_manufacturer_icon_url,
        "device_type_display": __fp.DEVICE_TYPE_DISPLAY,
        "view_mode": "v4",
        "subnet6_map": accessible_subnet6_map(),
        # Q206 (AV4): what the summary line inside the results partial says. The subnet's name is the FILTER's own - `subnet_filter` was reset to "all" above for a subnet the caller may
        # not see, so a hidden subnet's name never reaches the page.
        "subnet_filter_name": __view_prefs.subnet_filter_name(subnet_filter, accessible_subnet_map),
        "expiring_soon": expiring_soon,
        # Q249: the lease ROWS shown that carry the mark - what the link beside the number (?reserved=1) lists. It counted hardware addresses, so one reserved
        # client holding two leases read "1 reserved" above a filter that lists two.
        "reserved_count": sum(1 for lease in leases_list if lease.get("reserved")),
        "minutes_applied": minutes_applied,
        "reserved_only": reserved_only,
        "expiring_only": expiring_only,
    }
    if request.headers.get("HX-Request") == "true" and request.headers.get("HX-History-Restore-Request") != "true":
        # v4.4.6 fix: previously rendered only _lease_rows.html (the
        # <tbody> contents), leaving the sort-link headers and pagination
        # controls — both rendered outside the htmx swap target — stuck
        # with whatever subnet/minutes/search/per_page values were in the
        # URL at the last full page load. Any filter change made via the
        # form's htmx-triggered dropdowns/search box would silently go
        # stale on those, so clicking a sort header or a page number right
        # after changing a filter would "revert" it. Rendering the whole
        # results partial (headers + rows + pagination) keeps everything
        # in sync with the live filter state on every htmx update.
        # Q206 (AV4): the summary line is part of that partial now, for the same reason.
        return __view_prefs.remember(
            make_response(render_template("_leases_results.html", **template_vars), 200), request, remembered
        )
    return __view_prefs.remember(make_response(render_template("leases.html", **template_vars)), request, remembered)


def _leases_v6():
    """
    v5.0 Phase 2 — read-only IPv6 leases view. Deliberately a separate
    function from the v4 branch above rather than threading v6 through
    the same code path: the columns (DUID/IAID/lease-type instead of
    MAC/client-id), the query layer (list_lease6() from jen/services/
    kea6.py, not raw SQL against lease4), and the sort semantics are
    different enough that merging them would make both harder to follow.
    The well-tested v4 path above is completely untouched by this.

    No column-header sorting or numeric pagination yet — Phase 2 is
    explicitly read-only/basic per the plan; that polish is deferred
    rather than adding untested complexity here.
    """
    visible6 = accessible_subnet6_map()
    if not visible6:
        # Should be unreachable via the UI — the segmented control itself
        # is hidden whenever SUBNET6_MAP is empty (see leases.html) — but
        # guard directly in case of a stale bookmark or direct URL hit.
        flash("No IPv6 subnets are configured.", "error")
        return redirect(url_for("leases.leases"))

    subnet_filter = request.args.get("subnet", "all")
    search = __auth.sanitize_search(request.args.get("search", "").strip())
    show_expired = request.args.get("expired", "0") == "1"

    subnet_id = None
    if subnet_filter != "all":
        try:
            subnet_id = int(subnet_filter)
        except ValueError:
            subnet_filter = "all"
        else:
            # v5.68.0-beta.8 (Q143) — an explicit subnet the caller may not see (or that does not exist) is a 404, the same answer
            # for both. It used to fall back to "all", and "all" was never filtered, so the fallback was the leak.
            assert_subnet6_access(subnet_id)

    leases_list = []
    try:
        leases_list = __kea6.list_lease6(subnet_id=subnet_id, search=search or None, show_expired=show_expired)
        # the "all" view reads every v6 subnet; keep only the ones this caller may see
        leases_list = [lease for lease in leases_list if lease["subnet_id"] in visible6]
        for lease in leases_list:
            lease["subnet_name"] = extensions.SUBNET6_MAP.get(lease["subnet_id"], {}).get("name", "")
    except Exception as e:
        logger.error(f"Could not load IPv6 leases: {e}")
        flash("Could not load IPv6 leases. Check server logs for details.", "error")

    template_vars = {
        "leases6": leases_list,
        "total": len(leases_list),
        "subnet_filter": subnet_filter,
        "search": search,
        "show_expired": show_expired,
        "subnet6_map": visible6,
        "view_mode": "v6",
    }
    if request.headers.get("HX-Request") == "true" and request.headers.get("HX-History-Restore-Request") != "true":
        return render_template("_leases6_results.html", **template_vars), 200
    return render_template("leases.html", **template_vars)


@bp.route("/leases/delete-stale", methods=["POST"])
@login_required
@_admin_required
def delete_stale_leases():
    # v4.4.9: previously deleted stale leases across every subnet
    # system-wide regardless of the acting admin's subnet_access — a
    # subnet-restricted admin clicking this button on their own filtered
    # view was actually wiping stale leases everywhere, not just their
    # own subnets. Scoped to accessible subnets, same pattern as every
    # read-side subnet restriction elsewhere in the app.
    from jen.services.access import add_subnet_restriction

    where, params = ["state != 0"], []
    where, params = add_subnet_restriction(where, params, "", "subnet_id")
    # add_subnet_restriction prefixes the column with "{table_alias}.",
    # which is wrong for this unaliased single-table DELETE — strip the
    # leading "." it leaves behind when table_alias is empty.
    where = [w.lstrip(".") for w in where]
    try:
        with __db.kea_db() as db:
            with db.cursor() as cur:
                cur.execute(f"DELETE FROM lease4 WHERE {' AND '.join(where)}", params)
                deleted = cur.rowcount
            db.commit()
        flash(f"Deleted {_plural(deleted, 'expired/stale lease')}.", "success")
        __user.audit("DELETE_STALE_LEASES", "leases", f"Deleted {deleted}")
    except Exception as e:
        logger.error(f"Error deleting stale leases: {e}")
        flash("Error deleting stale leases. Check server logs for details.", "error")
    return redirect(url_for("leases.leases"))


@bp.route("/leases/release", methods=["POST"])
@login_required
@_admin_required
def release_lease():
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("No IP address specified.", "error")
        return redirect(url_for("leases.leases"))
    try:
        with __db.kea_db() as db:
            with db.cursor() as cur:
                # v4.4.9: check which subnet this IP actually belongs to
                # before touching it — previously any admin could release
                # any lease system-wide by IP alone, no subnet check at all.
                cur.execute(
                    f"SELECT subnet_id FROM lease4 WHERE inet_ntoa(address)=%s AND {ACTIVE_LEASE4}",  # nosec B608 - a fixed constant
                    (ip,),
                )
                row = cur.fetchone()
                if not row:
                    flash(f"No active lease found for {ip}.", "warning")
                    return redirect(url_for("leases.leases"))
                if not current_user.can_access_subnet(row["subnet_id"]):
                    # v5.69.0-beta.2 (Q171): the same sentence and status as an IP with no lease - a different one told a restricted admin which hidden addresses are leased
                    flash(f"No active lease found for {ip}.", "warning")
                    return redirect(url_for("leases.leases"))
                cur.execute("UPDATE lease4 SET state=1 WHERE inet_ntoa(address)=%s", (ip,))
                affected = cur.rowcount
            db.commit()
        if affected:
            flash(f"Lease for {ip} released.", "success")
            __user.audit("RELEASE_LEASE", "leases", f"Released {ip} by {current_user.username}")
        else:
            flash(f"No active lease found for {ip}.", "warning")
    except Exception as e:
        logger.error(f"Error releasing lease {ip}: {e}")
        flash("Error releasing lease. Check server logs for details.", "error")
    return redirect(url_for("leases.leases"))


@bp.route("/leases/bulk-release", methods=["POST"])
@login_required
@_admin_required
def bulk_release_leases():
    """
    Release multiple active, non-reserved leases at once — e.g.
    clearing a block of leases before subnet maintenance, or a bulk
    cleanup of devices that are clearly gone. Mirrors
    reservations.py's bulk_delete_reservations() in shape: per-item
    subnet-access check (a bulk action can't be used to touch a
    subnet a restricted admin couldn't touch one at a time), and a
    single summary flash rather than one per lease.

    Reserved leases are excluded here the same way they're excluded
    from the single-lease "Release lease" action — releasing a
    reserved IP's active binding doesn't accomplish much, since Kea
    will just reissue the same reservation on the next renewal. The
    template only renders a checkbox for non-reserved rows in the
    first place, but this is re-checked server-side too, since a
    request here isn't required to have come from that exact form.
    """
    ips = request.form.getlist("ips[]")
    if not ips:
        flash("No leases selected.", "error")
        return redirect(url_for("leases.leases"))

    released = 0
    errors = 0
    try:
        with __db.kea_db() as db:
            with db.cursor() as cur:
                for ip in ips:
                    try:
                        cur.execute(
                            f"SELECT l.subnet_id, HEX(l.hwaddr) AS mac_hex FROM lease4 l WHERE inet_ntoa(l.address)=%s AND {active_lease4('l')}",  # nosec B608 - a fixed constant
                            (ip,),
                        )
                        row = cur.fetchone()
                        if not row:
                            errors += 1
                            continue
                        if not current_user.can_access_subnet(row["subnet_id"]):
                            errors += 1
                            continue
                        # (Q251) "reserved" is the rule of the row's checkbox (`sees_reservation_in` over the client's IPv4 `hosts` rows, the query of the
                        # list): this asked only for a reservation in the lease's OWN subnet, so a hand-made post released the lease of a client with a
                        # global reservation, whose box the page disables.
                        cur.execute(
                            "SELECT dhcp4_subnet_id AS subnet_id FROM hosts WHERE HEX(dhcp_identifier)=%s AND dhcp4_subnet_id IS NOT NULL",
                            (row["mac_hex"] or "",),
                        )
                        if any(sees_reservation_in(current_user, h["subnet_id"]) for h in cur.fetchall()):
                            errors += 1
                            continue
                        cur.execute("UPDATE lease4 SET state=1 WHERE inet_ntoa(address)=%s", (ip,))
                        if cur.rowcount:
                            released += 1
                        else:
                            errors += 1
                    except Exception:
                        errors += 1
            db.commit()
    except Exception as e:
        logger.error(f"Bulk release leases error: {e}")
        flash("Bulk release failed. Check server logs for details.", "error")
        return redirect(url_for("leases.leases"))

    flash(
        f"Released {_plural(released, 'lease')}." + (f" {errors} failed or skipped." if errors else ""),
        "success" if errors == 0 else "warning",
    )
    __user.audit("BULK_RELEASE_LEASES", "leases", f"Released={released} Errors={errors} by {current_user.username}")
    return redirect(url_for("leases.leases"))


MAX_IPMAP_ADDRESSES = 2048  # sanity cap so a misconfigured huge pool can't render tens of thousands of cells


def _get_pools(subnet_id):
    """Fetch ALL pool ranges (start, end) from live Kea config for a subnet.

    A subnet can have more than one pool stanza (very common on larger
    subnets, e.g. a /23 split into two /24-sized pools) — every pool must be
    returned, not just the first.
    """
    pools = []
    try:
        result = __kea.kea_command("config-get", server=__kea.get_active_kea_server())
        if result.get("result") == 0:
            from jen.services.kea_config_view import iter_subnet4

            for s, _sn in iter_subnet4(result["arguments"].get("Dhcp4", {})):
                if s["id"] == subnet_id:
                    for p in s.get("pools", []):
                        pool_str = p.get("pool", "") if isinstance(p, dict) else str(p)
                        # v5.69.0-beta.3 (Q172): what a pool IS is `jen.services.pools.parse_pool`'s question (`a - b`, `a-b` or a CIDR); this used to keep only
                        # the strings with a "-" in them, so a pool written as `10.0.0.0/25` - which Kea accepts - had no cells on the map at all
                        span = parse_pool(pool_str)
                        if span is not None:
                            pools.append((str(ipaddress.IPv4Address(span[0])), str(ipaddress.IPv4Address(span[1]))))
    except Exception:
        pass
    return pools


def _build_pool_blocks(pools):
    """Turn [(start, end), ...] into renderable blocks of individual IPs,
    handling ranges that cross octet boundaries (e.g. 10.0.0.250-10.0.1.10),
    and capping total size so a bad config can't blow up the page."""
    blocks = []
    truncated = False
    total = 0
    for start, end in pools:
        try:
            start_ip = ipaddress.IPv4Address(start)
            end_ip = ipaddress.IPv4Address(end)
        except ValueError:
            continue
        if int(end_ip) < int(start_ip):
            continue
        remaining_budget = MAX_IPMAP_ADDRESSES - total
        if remaining_budget <= 0:
            truncated = True
            break
        span = int(end_ip) - int(start_ip) + 1
        if span > remaining_budget:
            end_ip = ipaddress.IPv4Address(int(start_ip) + remaining_budget - 1)
            truncated = True
        ips = [str(ipaddress.IPv4Address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
        blocks.append({"start": start, "end": str(end_ip), "ips": ips})
        total += len(ips)
        if truncated:
            break
    return blocks, truncated


@bp.route("/ipmap")
@login_required
def ipmap():
    # v4.4.9: subnet_filter was validated against the full SUBNET_MAP
    # only — the dropdown UI correctly only offered accessible subnets,
    # but the URL parameter itself wasn't enforced, so a restricted user
    # could edit the URL and view leases/reservations for any subnet.
    accessible_map = current_user.filter_subnet_map(extensions.SUBNET_MAP)
    if not accessible_map:
        # v5.68.0-beta.22 (Q157): a user who may see no subnet at all - a restricted account whose access list names only subnets that have since left
        # `[subnets]`, or an empty one - used to fall back to the FIRST CONFIGURED subnet, and the page then queried and printed that subnet's leases,
        # reservations and CIDR. Nothing is queried and nothing of any subnet is rendered.
        return render_template(
            "ipmap.html",
            no_subnets=True,
            leases={},
            reservations={},
            used={},
            pool_blocks=[],
            pool_truncated=False,
            max_ipmap_addresses=MAX_IPMAP_ADDRESSES,
            subnet_filter=None,
            subnet_id=None,
            subnet_map={},
            cidr="",
        )
    default_subnet = list(accessible_map.keys())[0]
    subnet_filter = request.args.get("subnet", default_subnet)
    try:
        subnet_filter = int(subnet_filter)
        if subnet_filter not in accessible_map:
            subnet_filter = default_subnet
    except (ValueError, IndexError):
        subnet_filter = default_subnet
    leases_by_ip = {}
    reservations_by_ip = {}
    cidr = extensions.SUBNET_MAP.get(subnet_filter, {}).get("cidr", "")
    try:
        with __db.kea_db() as db, db.cursor() as cur:
            cur.execute(
                f"SELECT inet_ntoa(address) AS ip, hostname, HEX(hwaddr) AS mac_hex FROM lease4 WHERE {ACTIVE_LEASE4} AND subnet_id=%s",  # nosec B608 - a fixed constant
                (subnet_filter,),
            )
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i : i + 2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                leases_by_ip[row["ip"]] = {"hostname": row["hostname"] or "", "mac": mac, "type": "dynamic"}
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS mac_hex FROM hosts WHERE dhcp4_subnet_id=%s",
                (subnet_filter,),
            )
            for row in cur.fetchall():
                mac = ":".join(row["mac_hex"][i : i + 2] for i in range(0, 12, 2)) if row["mac_hex"] else ""
                reservations_by_ip[row["ip"]] = {"hostname": row["hostname"] or "", "mac": mac, "type": "reserved"}
    except Exception as e:
        logger.error(f"Could not load IP map: {e}")
        flash("Could not load IP map. Check server logs for details.", "error")

    pools = _get_pools(subnet_filter)
    pool_blocks, pool_truncated = _build_pool_blocks(pools)
    used = {}
    used.update(leases_by_ip)
    used.update(reservations_by_ip)  # a reservation on a leased IP shows as "reserved"

    return render_template(
        "ipmap.html",
        leases=leases_by_ip,
        reservations=reservations_by_ip,
        used=used,
        pool_blocks=pool_blocks,
        pool_truncated=pool_truncated,
        max_ipmap_addresses=MAX_IPMAP_ADDRESSES,
        subnet_filter=subnet_filter,
        subnet_id=subnet_filter,
        subnet_map=current_user.filter_subnet_map(extensions.SUBNET_MAP),
        cidr=cidr,
    )


# ─────────────────────────────────────────
# Reservations
# ─────────────────────────────────────────
