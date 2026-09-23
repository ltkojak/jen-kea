"""
jen/services/dashboard_catalog.py
──────────────────────────────────
v5.54.0 (Q61) — the seven catalog widgets Q61 added to the dashboard, each a
thin builder over an already-existing read: Reports' own forecast
(`health.lease_history_window` + `capacity.forecast`), the Servers page's
packet-health assessment, Health Center's Kea 3.2 readiness group and D2
error-counter check, the event stream, a small HA summary, and the nav
pill's cached getting-started count.

None of this runs unless its widget is enabled AND visible on the dashboard
— every builder here is called lazily, from `GET /api/dashboard/catalog-data`,
the same way the pre-Q61 sparklines/top-devices/alert-summary widgets were
already lazy. A widget with nothing to say (a single-server install for
`ha_state`, DDNS off for `ddns_errors`) returns None rather than an empty
card, so the page can skip rendering it instead of showing a blank one.

`readiness_widget()` and `ddns_errors_widget()` both need `health.run_checks()`
(every group, not just the one each wants) — the same round trips a visit to
Health Center itself makes. v5.56.1 (Q68k): the route computes that pass
ONCE, lazily (only when one of the two widgets is actually requested), and
hands the same `checks` list to both — no module-level or cross-request
cache, just not doubling the work within a single catalog-data request.
"""

from __future__ import annotations

import json
import logging

import jen.models.db as __db
import jen.services.capacity as __capacity
import jen.services.events as __events
import jen.services.health as __health
import jen.services.onboarding as __onboarding
import jen.services.packet_health as __packet_health
from jen import extensions

logger = logging.getLogger(__name__)

_PACKET_HEALTH_WINDOW_MINUTES = 60
_HEALTHY_HA_STATES = ("hot-standby", "load-balancing")


def forecast_widget(accessible_subnet_ids) -> list[dict]:
    """Days-to-90% per subnet, the same number Reports' own forecast column
    shows. A subnet with under a week of history (`trend == "insufficient"`)
    is left out rather than shown with nothing useful to say."""
    try:
        window = __health.lease_history_window()
    except Exception as e:
        logger.warning(f"dashboard forecast widget: {e}")
        return []
    out = []
    for sid in accessible_subnet_ids:
        rows = window.get(sid)
        if not rows:
            continue
        f = __capacity.forecast(rows)
        if f["trend"] == "insufficient":
            continue
        info = extensions.SUBNET_MAP.get(sid, {})
        out.append(
            {
                "subnet_id": sid,
                "name": info.get("name", str(sid)),
                "trend": f["trend"],
                "days_to_90pct": f["days_to_90pct"],
                "line": __capacity.summary_line(f),
            }
        )
    return out


def packet_health_widget(servers) -> list[dict]:
    """One row per server with two or more recent `server_stats` snapshots
    (`alerts.take_server_stats_snapshot`); a server with fewer than two is
    left out rather than shown as a false-clean reading. `servers` is
    `[{"id": ..., "name": ...}, ...]`."""
    out = []
    for s in servers:
        try:
            with __db.jen_db() as db, db.cursor() as cur:
                cur.execute(
                    "SELECT snapshot_time, stats FROM server_stats WHERE server_id=%s "
                    "AND snapshot_time > DATE_SUB(NOW(), INTERVAL 90 MINUTE) ORDER BY snapshot_time",
                    (s["id"],),
                )
                raw_rows = cur.fetchall()
        except Exception as e:
            logger.warning(f"dashboard packet_health widget (server {s.get('id')}): {e}")
            continue
        rows = []
        for r in raw_rows:
            stats = r["stats"]
            if isinstance(stats, str):
                stats = json.loads(stats)
            rows.append({"snapshot_time": r["snapshot_time"], "stats": stats})
        if len(rows) < 2:
            continue
        deltas = __packet_health.deltas(rows)
        rates = __packet_health.rates(deltas, window_minutes=_PACKET_HEALTH_WINDOW_MINUTES)
        assessment = __packet_health.assess(rates)
        out.append(
            {"server_id": s["id"], "name": s["name"], "status": assessment["status"], "notes": assessment["notes"]}
        )
    return out


def readiness_widget(checks) -> dict | None:
    """The Kea 3.2 readiness group's one-liner + its rows — the same output
    Health Center's own readiness section shows. `checks` is the caller's
    own run_checks() result (v5.56.1, Q68k — shared with ddns_errors_widget
    rather than each calling run_checks() itself); None if that call failed,
    or if the group produced no checks at all (never happens in practice;
    the five readiness checks always run)."""
    if not checks:
        return None
    group_checks = [c for c in checks if c.group == "readiness"]
    if not group_checks:
        return None
    counts = __health.summarize(group_checks)
    worst = "ok"
    for level in ("fail", "warn"):
        if counts.get(level):
            worst = level
            break
    line = ", ".join(f"{counts[k]} {k}" for k in ("ok", "warn", "fail", "skip") if counts.get(k))
    return {"status": worst, "line": line, "rows": [c.as_dict() for c in group_checks]}


def events_feed_widget(accessible_subnet_ids, all_subnets, limit=10) -> list[dict]:
    """The last `limit` events this account can see — the same fail-closed
    rule `/api/v1/events` uses: with a restricted scope, an event carrying
    no subnet_id is dropped rather than shown, since it cannot be
    attributed to a subnet the caller is confirmed to have access to.

    v5.56.1 (Q68l) — the restriction now filters in SQL, before LIMIT, the
    same shape `jen.services.access.add_subnet_restriction()` builds (not
    that helper itself: it reads `current_user`, and this widget is built
    to run with explicit args so tests/test_dashboard_catalog.py can cover
    it without a request context). Before this, a restricted account could
    see "No recent events" while older accessible ones existed, whenever
    the newest `limit * 5` rows (the old over-fetch window) all happened
    to belong to subnets outside their scope."""
    where = ["1=1"]
    params: list = []
    if not all_subnets:
        ids = list(accessible_subnet_ids)
        if not ids:
            return []
        placeholders = ",".join(["%s"] * len(ids))
        where.append(f"subnet_id IN ({placeholders})")
        params.extend(ids)
    out: list[dict] = []
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT ts, kind, mac, ip, subnet_id, hostname, server, actor, detail "
                f"FROM events WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT %s",
                (*params, limit),
            )
            for r in cur.fetchall():
                row = dict(r)
                row["ts"] = row["ts"].isoformat() if row["ts"] else None
                # v5.57.0 (Q73) — a plugin kind (plugin.<id>.<name>) shows
                # as the plugin's display name + a puzzle icon on the
                # dashboard, same as Timeline; kind_label/kind_icon are
                # None for a core kind, i.e. no change from before.
                desc = __events.describe_kind(row["kind"])
                row["kind_label"] = desc["label"]
                row["kind_icon"] = desc["icon"] if desc["is_plugin"] else None
                out.append(row)
    except Exception as e:
        logger.warning(f"dashboard events_feed widget: {e}")
    return out


def ha_state_widget(server_statuses) -> list[dict] | None:
    """The Servers page's is_active/ha_state pair, one row per server. None
    (skip) on a single-server install — it has no HA state to show."""
    if len(server_statuses) < 2:
        return None
    out = []
    for s in server_statuses:
        state = s.get("ha_state")
        role = (s.get("server") or {}).get("role", "")
        if state == "load-balancing":
            is_active = True
        elif state == "hot-standby":
            is_active = role == "primary"
        elif state == "partner-down":
            is_active = True
        else:
            is_active = False
        out.append(
            {
                "name": (s.get("server") or {}).get("name", "?"),
                "up": s.get("up"),
                "state": state,
                "is_active": is_active,
                "healthy": state in _HEALTHY_HA_STATES,
            }
        )
    return out


def ddns_errors_widget(checks) -> dict | None:
    """The `d2_errors` Health check's own reading. None only when the check
    itself is absent from this run (`checks` came back empty, or the id
    isn't in it) — a skip still returns a dict (v5.57.0, Q73) carrying
    WHICH of three things is true (DDNS off, direct mode without a D2
    control socket, or D2 stats unreachable) and the check's own fix_url,
    so the dashboard and the Health Center page always agree on both
    whether DDNS is worth watching here and why. `checks` is the caller's
    own run_checks() result (v5.56.1, Q68k — shared with readiness_widget
    rather than each calling run_checks() itself)."""
    if not checks:
        return None
    by_id = {c.id: c for c in checks}
    c = by_id.get("d2_errors")
    if c is None:
        return None
    if c.status == "skip":
        # v5.57.0 (Q73, Q72's missed item e) — the check already says
        # WHICH of three things is true (DDNS off, direct mode with no D2
        # socket, or D2 stats unreachable); the widget used to collapse
        # all three into one generic sentence with no way to act on it.
        return {"status": "skip", "detail": c.detail, "fix_url": c.fix_url}
    return {"status": c.status, "detail": c.detail}


def getting_started_widget(user, is_superadmin: bool) -> dict | None:
    """The nav pill's own cached count (5-minute TTL) — never a fresh Kea
    round trip just because this widget is on the dashboard too."""
    return __onboarding.cached_pill(user, is_superadmin)
