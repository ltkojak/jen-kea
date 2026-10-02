"""
jen/services/onboarding.py
───────────────────────────
v5.39.0 (Q39) — the getting-started checklist. Rows are computed from
things Jen already knows: the Health Center's own checks (one
run_checks() round trip, reused rather than repeated) plus a handful of
cheap settings/DB reads. `checklist()` itself takes an assembled `ctx`
dict and is pure — testable with a fabricated ctx, no Kea or DB access
required.
"""

from __future__ import annotations

import time

_DISMISSED_KEY = "getting_started_dismissed"
_PILL_CACHE_TTL = 300  # seconds — the nav pill must never trigger a Kea round trip per page load.
_PILL_CACHE_MAX = 64  # distinct (role, scope) keys kept — a handful in practice; the bound is only a ceiling.
# v5.67.0-beta.8 (Q120, item o) — {(role, is_superadmin, subnet scope): (computed_at, (done, total))}. This
# used to be ONE process-wide slot, filled by whichever user rendered first, so an admin saw a superadmin's
# count (the superadmin-only HTTPS and MFA rows are in it) — or the reverse — for the whole TTL.
_pill_cache: dict = {}


def _from_check(rows: list, checks: dict, check_id: str, title: str, link: str, ok_statuses=("ok",)) -> None:
    c = checks.get(check_id)
    if c is None:
        rows.append({"title": title, "done": False, "detail": "check unavailable", "link": link})
        return
    rows.append({"title": title, "done": c.status in ok_statuses, "detail": c.detail, "link": c.fix_url or link})


def _control_transport_row(ctx: dict) -> dict:
    checks = ctx.get("checks", {})
    link = "/health-center"
    c = checks.get("kea32_control_transport")
    if c is None:
        return {"title": "Control transport ready for 3.2", "done": False, "detail": "check unavailable", "link": link}
    if c.status == "ok":
        return {"title": c.title, "done": True, "detail": c.detail, "link": c.fix_url or link}
    if c.status == "warn" and ctx.get("kea_connection_mode") != "direct":
        # Same condition the check itself uses for "nothing reachable is
        # 3.0+ yet" — fine to defer, so it counts as done here.
        return {
            "title": c.title,
            "done": True,
            "detail": "fine for now — switch to direct sockets before upgrading to Kea 3.2",
            "link": c.fix_url or link,
        }
    return {"title": c.title, "done": False, "detail": c.detail, "link": c.fix_url or link}


def checklist(ctx: dict) -> dict:
    """Pure — everything it needs is already in `ctx` (see build_ctx()
    for how the route assembles one). Returns
    `{"rows": [...], "done": int, "total": int, "all_done": bool}`.
    Rows 5 (HTTPS) and 6 (MFA) only show for a superadmin — a plain
    admin can't act on either."""
    checks = ctx.get("checks", {})
    rows: list[dict] = []

    # v5.67.0 (Q115) — a row whose matching wizard step is still open (not
    # done or skipped) links into /setup/<step> instead of the Settings
    # page it would otherwise land on; once that step is resolved the link
    # reverts to its usual target. wizard_open() is pure (get_state() does
    # one settings read, no side effect), safe to call on every page load.
    # v5.67.0-beta.8 (Q120, item h) — /setup/* is superadmin-only (routes/setup.py), so a plain admin
    # is only ever sent to the Settings page the row would have linked to anyway.
    def _link(step: str, fallback: str) -> str:
        if not ctx.get("is_superadmin") or step in ctx.get("wizard_state", {}):
            return fallback
        return f"/setup/{step}"

    _from_check(rows, checks, "kea_reachable", "Kea is reachable", _link("connect", "/servers"))
    _from_check(rows, checks, "kea_subnets_declared", "Every subnet is named", _link("found", "/settings/kea"))

    helper = checks.get("helper_installed")
    helper_ver = checks.get("kea32_helper_version")
    helper_done = bool(helper and helper.status == "ok") and (helper_ver is None or helper_ver.status in ("ok", "skip"))
    rows.append(
        {
            "title": "SSH and the Kea host helper are current",
            "done": helper_done,
            "detail": helper.detail if helper else "check unavailable",
            "link": _link("helper", "/settings/kea"),
        }
    )

    rows.append(_control_transport_row(ctx))

    if ctx.get("is_superadmin"):
        ssl_on = bool(ctx.get("ssl_configured"))
        rows.append(
            {
                "title": "HTTPS is on",
                "done": ssl_on,
                "detail": "certificate installed" if ssl_on else "running on plain HTTP",
                "link": "/settings/security",
            }
        )

        has_mfa = bool(ctx.get("current_user_has_mfa"))
        mfa_on = ctx.get("mfa_mode", "off") != "off"
        rows.append(
            {
                "title": "MFA is enabled for your account",
                "done": mfa_on and has_mfa,
                "detail": "enrolled" if has_mfa else "no second factor enrolled",
                "link": "/mfa/enroll",
            }
        )

    channels = ctx.get("alert_channels_enabled", 0)
    rows.append(
        {
            "title": "At least one alert channel is enabled",
            "done": channels > 0,
            "detail": f"{channels} enabled" if channels else "none configured",
            "link": "/settings/alerts",
        }
    )

    has_backup = ctx.get("backup_count", 0) > 0 or bool(ctx.get("backup_schedule_enabled"))
    rows.append(
        {
            "title": "A backup exists or is scheduled",
            "done": has_backup,
            "detail": "present" if has_backup else "no backups yet",
            "link": _link("recovery", "/settings/databases?tab=backups"),
        }
    )

    # v5.67.0-beta.5 (Q117, item i) — a recovery bundle is a distinct
    # thing from a database backup (encrypted, includes config/keys, a
    # one-time download rather than a standing schedule) and had no row
    # of its own; "A backup exists" could read as covering it when it
    # never did.
    recovery_bundle_at = ctx.get("last_recovery_bundle_at", "")
    rows.append(
        {
            "title": "A recovery bundle exists",
            "done": bool(recovery_bundle_at),
            "detail": f"downloaded {recovery_bundle_at}" if recovery_bundle_at else "none downloaded yet",
            "link": _link("recovery", "/settings/databases?tab=recovery"),
        }
    )

    _from_check(rows, checks, "lease_snapshot_fresh", "Lease snapshots are flowing", "/settings/system")

    if ctx.get("ha_mode"):
        server_count = ctx.get("server_count", 1)
        rows.append(
            {
                "title": "A second server is added for HA",
                "done": server_count > 1,
                "detail": f"{server_count} server(s) configured",
                "link": "/servers",
            }
        )

    done = sum(1 for r in rows if r["done"])
    return {"rows": rows, "done": done, "total": len(rows), "all_done": done == len(rows) if rows else False}


def build_ctx(user, is_superadmin: bool) -> dict:
    """One run_checks() round trip (the only Kea traffic this page ever
    causes) plus the cheap reads checklist() needs. Not pure — this is
    the I/O boundary; checklist() above is what's unit-tested."""
    from jen import extensions
    from jen.models.db import jen_db
    from jen.services import dbexport, health, mfa
    from jen.services import setup_wizard as __setup_wizard

    checks = {c.id: c for c in health.run_checks({"subnet_filter": user.can_access_subnet})}

    channels = 0
    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM alert_channels WHERE enabled=1")
            channels = cur.fetchone()["cnt"]
    except Exception:
        channels = 0

    schedule = dbexport.get_schedule()

    from jen import config as jen_config

    return {
        "checks": checks,
        "is_superadmin": is_superadmin,
        "kea_connection_mode": extensions.KEA_CONNECTION_MODE,
        "ssl_configured": jen_config.ssl_configured(),
        "mfa_mode": mfa.get_mfa_mode(),
        "current_user_has_mfa": mfa.user_has_mfa(user.id),
        "alert_channels_enabled": channels,
        "backup_count": dbexport.backup_count(),
        "backup_schedule_enabled": bool(schedule.get("enabled")) if schedule else False,
        "last_recovery_bundle_at": __setup_wizard.recovery_bundle_status()["at"],
        "ha_mode": bool(extensions.cfg.get("kea", "ha_mode", fallback="")),
        "server_count": len(extensions.KEA_SERVERS),
        "wizard_state": __setup_wizard.get_state(),
    }


def is_dismissed() -> bool:
    from jen.models.user import get_global_setting

    return get_global_setting(_DISMISSED_KEY, "false") == "true"


def dismiss() -> None:
    from jen.models.user import set_global_setting

    set_global_setting(_DISMISSED_KEY, "true")


def _pill_key(user, is_superadmin: bool) -> tuple:
    """What a pill's number depends on: the role (a superadmin's list has the HTTPS and MFA rows, an
    admin's does not), and the subnet scope (the checks it counts are filtered through the user's own
    subnet access). Two users with the same role and the same scope see the same number."""
    scope = getattr(user, "subnet_access_list", None)
    if scope is not None:
        try:
            scope = tuple(sorted(int(s) for s in scope))
        except (TypeError, ValueError):
            scope = (-1,)
    return (str(getattr(user, "role", "")), bool(is_superadmin), scope)


def cached_pill(user, is_superadmin: bool) -> dict | None:
    """`{"done": n, "total": m}` for the nav pill, or None when dismissed
    or complete. Refreshed at most once per `_PILL_CACHE_TTL` seconds per
    process *per role and subnet scope* (`_pill_key`) — the page itself
    (build_ctx + checklist) always recomputes."""
    if is_dismissed():
        return None
    now = time.time()
    key = _pill_key(user, is_superadmin)
    hit = _pill_cache.get(key)
    if hit is None or now - hit[0] > _PILL_CACHE_TTL:
        summary = checklist(build_ctx(user, is_superadmin))
        hit = (now, (summary["done"], summary["total"]))
        if key not in _pill_cache and len(_pill_cache) >= _PILL_CACHE_MAX:
            _pill_cache.pop(min(_pill_cache, key=lambda k: _pill_cache[k][0]))
        _pill_cache[key] = hit
    done, total = hit[1]
    if total == 0 or done >= total:
        return None
    return {"done": done, "total": total}
