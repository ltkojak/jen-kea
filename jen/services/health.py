"""
jen/services/health.py
──────────────────────
v5.12.0 — the Health Center's check engine.

A fixed list of **read-only** checks over data Jen already has: the Kea
HTTP API, the two databases, local files, and state Jen persisted. No
SSH, ever — that's what makes the page safe to open on a phone and safe
to poll. Every check is wrapped so a failure yields a `fail` row with the
message, never a 500.

Groups and check ids are stable (tests and the JSON twin key off them):

  kea       kea_reachable · kea_version_supported · kea_ha_state ·
            kea_hooks · kea_time_sync · kea_config_drift ·
            kea_subnets_declared
  capacity  pool_utilization · lease_snapshot_fresh
  ddns      d2_reachable · d2_errors
  jen       cert_expiry · db_jen · db_kea · schema_current ·
            helper_installed · background_workers · update_available
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import jen.models.db as __db
import jen.services.kea as __kea
from jen import extensions

logger = logging.getLogger(__name__)

# Same set servers.py derives "healthy backup" from.
HEALTHY_HA_STATES = {"hot-standby", "load-balancing"}

_ADMIN_GUIDE_HOOKS = "/docs/admin-guide.md#kea-hooks"  # anchor referenced by kea_hooks detail


@dataclass
class Check:
    id: str
    title: str
    group: str
    status: str = "skip"  # ok | warn | fail | skip
    detail: str = ""
    fix_hint: str = ""
    fix_url: str = ""
    elapsed_ms: int = 0

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "group": self.group,
            "status": self.status,
            "detail": self.detail,
            "fix_hint": self.fix_hint,
            "fix_url": self.fix_url,
            "elapsed_ms": self.elapsed_ms,
        }


# ── shared context ─────────────────────────────────────────────────────────


def _log_err(check_id: str, exc: Exception) -> None:
    """A check's real error goes to the log; the page shows a generic
    line. The Health Center is viewer-visible — a raw pymysql/requests
    error can carry a host, port, or path a viewer shouldn't see."""
    logger.warning(f"health check {check_id}: {exc}")


def _fetch_dhcp4_config(server) -> dict | None:
    try:
        r = __kea.kea_command("config-get", server=server)
        if r.get("result") == 0:
            return r.get("arguments", {}).get("Dhcp4", {})
    except Exception as e:
        logger.warning(f"health: config-get failed: {e}")
    return None


def _build_ctx(ctx: dict | None) -> dict:
    ctx = dict(ctx or {})
    ctx.setdefault("subnet_filter", lambda _sid: True)
    if "server_status" not in ctx:
        try:
            ctx["server_status"] = __kea.get_all_server_status()
        except Exception as e:
            logger.warning(f"health: get_all_server_status failed: {e}")
            ctx["server_status"] = []
    if "active_server" not in ctx:
        try:
            ctx["active_server"] = __kea.get_active_kea_server()
        except Exception:
            ctx["active_server"] = None
    if "dhcp4_config" not in ctx:
        ctx["dhcp4_config"] = _fetch_dhcp4_config(ctx["active_server"])
    return ctx


def _ha_configured() -> bool:
    return len(extensions.KEA_SERVERS) > 1 and bool(extensions.cfg.get("kea", "ha_mode", fallback=""))


def _server_name(server: dict) -> str:
    return server.get("name") or f"Kea Server {server.get('id', '?')}"


# ── kea group ──────────────────────────────────────────────────────────────


def _kea_reachable(ctx) -> Check:
    c = Check("kea_reachable", "Kea servers reachable", "kea", fix_url="/servers")
    statuses = ctx["server_status"]
    if not statuses:
        c.status, c.detail = "fail", "no server status available (Kea unreachable?)"
        return c
    down = [_server_name(s["server"]) for s in statuses if not s.get("up")]
    total = len(statuses)
    if not down:
        c.status, c.detail = "ok", f"{total}/{total} reachable"
    elif len(down) == total:
        c.status, c.detail = "fail", "no Kea server is reachable"
    else:
        c.status, c.detail = "fail", f"{', '.join(down)} not reachable"
    return c


def _kea_version_supported(ctx) -> Check:
    c = Check("kea_version_supported", "Kea version supported", "kea", fix_url="/settings/kea")
    direct = extensions.KEA_CONNECTION_MODE == "direct"
    worst = "ok"
    notes = []
    seen_version = False
    for s in ctx["server_status"]:
        if not s.get("up"):
            continue
        v = __kea.parse_kea_version(s.get("version", ""))
        if v is None:
            continue
        seen_version = True
        name = _server_name(s["server"])
        if direct:
            if v < (2, 7, 2):
                worst = _worse(worst, "fail")
                notes.append(f"{name} is {_vstr(v)} — direct control sockets need Kea 2.7.2+")
        elif v >= (3, 2, 0):
            worst = _worse(worst, "fail")
            notes.append(f"{name} is {_vstr(v)} — the Control Agent is removed; switch to direct mode")
        elif v >= (3, 0, 0):
            worst = _worse(worst, "warn")
            notes.append(f"{name} is {_vstr(v)} — the Control Agent is deprecated; switch to direct mode")
        elif v < (2, 0, 0):
            worst = _worse(worst, "warn")
            notes.append(f"{name} is {_vstr(v)} — older than any supported Kea")
    if not seen_version:
        c.status, c.detail = "skip", "no reachable server reported a version"
        return c
    c.status = worst
    c.detail = "; ".join(notes) if notes else "all reachable servers on a supported Kea"
    return c


def _kea_ha_state(ctx) -> Check:
    c = Check("kea_ha_state", "HA state healthy", "kea", fix_url="/servers")
    if not _ha_configured():
        c.status, c.detail = "skip", "not an HA deployment"
        return c
    states = [(s["server"], s.get("ha_state")) for s in ctx["server_status"]]
    reported = [st for _srv, st in states if st]
    if not reported:
        c.status, c.detail = "warn", "no server has reported an HA state yet"
        return c
    if any(st == "terminated" for st in reported):
        bad = [_server_name(srv) for srv, st in states if st == "terminated"]
        c.status, c.detail = "fail", f"{', '.join(bad)} in 'terminated' — HA has stopped"
        return c
    unhealthy = [(srv, st) for srv, st in states if st and st not in HEALTHY_HA_STATES]
    if unhealthy:
        c.status = "warn"
        c.detail = "; ".join(f"{_server_name(srv)}: {st}" for srv, st in unhealthy)
        return c
    c.status, c.detail = "ok", f"{', '.join(sorted(set(reported)))}"
    return c


_REQUIRED_HOOKS = {
    "libdhcp_host_cmds.so": "reservation-add / reservation-del (reservations page, CSV import)",
    "libdhcp_lease_cmds.so": "lease4-get-all / lease4-del (leases page, stale-lease cleanup)",
}


def _kea_hooks(ctx) -> Check:
    c = Check("kea_hooks", "Kea hooks loaded", "kea", fix_url="/settings/kea")
    cfg = ctx["dhcp4_config"]
    if cfg is None:
        c.status, c.detail = "skip", "config-get unavailable"
        return c
    libs = cfg.get("hooks-libraries", []) or []
    loaded = {_basename(h.get("library", "")) for h in libs if isinstance(h, dict)}
    missing = []
    for lib, why in _REQUIRED_HOOKS.items():
        if lib not in loaded:
            missing.append(f"{lib} ({why})")
    if _ha_configured() and "libdhcp_ha.so" not in loaded:
        missing.append("libdhcp_ha.so (HA is configured but the hook isn't loaded)")
    if missing:
        c.status = "fail"
        c.detail = "missing: " + "; ".join(missing) + f" — see {_ADMIN_GUIDE_HOOKS}"
        return c
    c.status, c.detail = "ok", f"{len(loaded)} hook librar{'y' if len(loaded) == 1 else 'ies'} loaded"
    return c


def _kea_time_sync(ctx) -> Check:
    c = Check("kea_time_sync", "Kea clock in sync", "kea")
    offset = None
    try:
        offset = __kea.server_clock_offset(ctx["active_server"])
    except Exception as e:
        logger.warning(f"health: clock offset failed: {e}")
    if offset is None:
        c.status, c.detail = "skip", "Kea did not send a Date header"
        return c
    secs = abs(offset)
    ahead = "ahead of" if offset > 0 else "behind"
    if secs > 300:
        c.status = "fail"
        c.detail = f"Kea clock is {secs:.0f}s {ahead} Jen — HA and lease timers assume synchronised clocks"
    elif secs > 30:
        c.status = "warn"
        c.detail = f"Kea clock is {secs:.0f}s {ahead} Jen"
    else:
        c.status, c.detail = "ok", f"within {secs:.0f}s"
    return c


def _kea_config_drift(ctx) -> Check:
    c = Check("kea_config_drift", "Subnet map matches Kea", "kea", fix_url="/servers")
    try:
        from jen.services.config_drift import check_config_drift

        issues = check_config_drift()
    except Exception as e:
        _log_err("kea_config_drift", e)
        c.status, c.detail = "fail", "drift check errored — see server logs"
        return c
    if not issues:
        c.status, c.detail = "ok", "Jen's subnet map agrees with Kea's live config"
        return c
    c.status = "warn"
    first = issues[0].get("message", "")
    c.detail = f"{len(issues)} issue(s): {first}" if len(issues) > 1 else first
    return c


def _kea_subnets_declared(ctx) -> Check:
    # v5.15.0 — via kea_config_view so a subnet nested in a shared-network
    # is seen too (before, it was flagged as orphaned).
    from jen.services.kea_config_view import iter_subnet4

    c = Check("kea_subnets_declared", "Every Kea subnet is named", "kea", fix_url="/settings/kea")
    cfg = ctx["dhcp4_config"]
    if cfg is None:
        c.status, c.detail = "skip", "config-get unavailable"
        return c
    kea_ids = {s.get("id") for s, _sn in iter_subnet4(cfg) if s.get("id") is not None}
    jen_ids = set(extensions.SUBNET_MAP.keys())
    undeclared = sorted(kea_ids - jen_ids)
    orphaned = sorted(jen_ids - kea_ids)
    parts = []
    if undeclared:
        parts.append(
            f"Kea subnet id(s) {', '.join(map(str, undeclared))} have no name in Jen — declare them in Settings → Kea"
        )
    if orphaned:
        parts.append(f"Jen names subnet id(s) {', '.join(map(str, orphaned))} that Kea's live config no longer has")
    if parts:
        c.status, c.detail = "warn", "; ".join(parts)
    else:
        c.status, c.detail = "ok", f"{len(kea_ids)} subnet(s), all named"
    return c


# ── capacity group ─────────────────────────────────────────────────────────


def _latest_lease_history() -> list[dict]:
    """One row per subnet — the newest snapshot for each. lease_history
    lives in jen_db (take_lease_snapshot writes it there)."""
    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute(
            """
            SELECT lh.subnet_id, lh.active_leases, lh.pool_size, lh.snapshot_time
            FROM lease_history lh
            INNER JOIN (
                SELECT subnet_id, MAX(snapshot_time) AS mx
                FROM lease_history GROUP BY subnet_id
            ) m ON m.subnet_id = lh.subnet_id AND m.mx = lh.snapshot_time
            """
        )
        return list(cur.fetchall())


def _pool_utilization(ctx) -> Check:
    c = Check("pool_utilization", "Pool utilization", "capacity", fix_url="/subnets")
    try:
        threshold = int(__get_setting("alert_threshold_pct", "80"))
    except (TypeError, ValueError):
        threshold = 80
    try:
        rows = _latest_lease_history()
    except Exception as e:
        _log_err("pool_utilization", e)
        c.status, c.detail = "fail", "could not read lease history — see server logs"
        return c
    rows = [r for r in rows if ctx["subnet_filter"](r["subnet_id"])]
    if not rows:
        c.status, c.detail = "skip", "first snapshot pending"
        return c
    warn, crit = [], []
    for r in rows:
        size = r["pool_size"] or 0
        if size <= 0:
            continue
        pct = 100.0 * (r["active_leases"] or 0) / size
        label = f"{_subnet_label(r['subnet_id'])} {pct:.0f}%"
        if pct >= 95:
            crit.append(label)
        elif pct >= threshold:
            warn.append(label)
    if crit:
        c.status, c.detail = "fail", "near exhaustion: " + ", ".join(crit)
    elif warn:
        c.status, c.detail = "warn", f"over {threshold}%: " + ", ".join(warn)
    else:
        c.status, c.detail = "ok", f"{len(rows)} subnet(s) below {threshold}%"
    return c


def _lease_snapshot_fresh(ctx) -> Check:
    c = Check("lease_snapshot_fresh", "Lease snapshots current", "capacity", fix_url="/settings/system")
    try:
        interval = int(__get_setting("snapshot_interval_minutes", "30")) * 60
    except (TypeError, ValueError):
        interval = 30 * 60
    try:
        with __db.jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT MAX(snapshot_time) AS mx FROM lease_history")
            row = cur.fetchone()
    except Exception as e:
        _log_err("lease_snapshot_fresh", e)
        c.status, c.detail = "fail", "could not read lease history — see server logs"
        return c
    mx = row["mx"] if row else None
    if mx is None:
        c.status, c.detail = "skip", "no snapshot recorded yet"
        return c
    if mx.tzinfo is None:
        mx = mx.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - mx).total_seconds()
    if age > 2 * interval:
        c.status = "warn"
        c.detail = f"newest snapshot is {age / 60:.0f} min old (interval {interval // 60} min) — background worker not running?"
    else:
        c.status, c.detail = "ok", f"newest snapshot {age / 60:.0f} min ago"
    return c


# ── ddns group ─────────────────────────────────────────────────────────────


def _ddns_updates_enabled(ctx) -> bool:
    cfg = ctx["dhcp4_config"] or {}
    return bool(cfg.get("dhcp-ddns", {}).get("enable-updates"))


def _d2_reachable(ctx) -> Check:
    c = Check("d2_reachable", "kea-dhcp-ddns reachable", "ddns", fix_url="/ddns")
    if ctx["dhcp4_config"] is None:
        c.status, c.detail = "skip", "config-get unavailable"
        return c
    if not _ddns_updates_enabled(ctx):
        c.status, c.detail = "skip", "DDNS updates disabled in dhcp4"
        return c
    if extensions.KEA_CONNECTION_MODE == "direct":
        c.status, c.detail = "skip", "direct mode needs a D2 control-socket URL ([d2] api_url — 5.22.0)"
        return c
    r = __kea.kea_command("version-get", service="d2", server=ctx["active_server"])
    if r.get("result") == 0:
        ver = __kea.parse_kea_version(r.get("arguments", {}).get("extended", "") or r.get("text", ""))
        c.status, c.detail = "ok", f"D2 answered{' v' + _vstr(ver) if ver else ''}"
    else:
        logger.warning(f"health check d2_reachable: {r.get('text', '')}")
        c.status, c.detail = "warn", "D2 did not answer version-get"
    return c


def _d2_errors(ctx) -> Check:
    c = Check("d2_errors", "kea-dhcp-ddns error counters", "ddns", fix_url="/ddns")
    if ctx["dhcp4_config"] is None or not _ddns_updates_enabled(ctx):
        c.status, c.detail = "skip", "DDNS updates disabled"
        return c
    if extensions.KEA_CONNECTION_MODE == "direct":
        c.status, c.detail = "skip", "direct mode needs a D2 control-socket URL ([d2] api_url — 5.22.0)"
        return c
    r = __kea.kea_command("statistic-get-all", service="d2", server=ctx["active_server"])
    if r.get("result") != 0:
        logger.warning(f"health check d2_errors: {r.get('text', '')}")
        c.status, c.detail = "skip", "D2 statistics unavailable"
        return c
    args = r.get("arguments", {})
    ncr = _stat_value(args, "ncr-error")
    upd = _stat_value(args, "update-error")
    if ncr + upd > 0:
        c.status = "warn"
        c.detail = f"ncr-error={ncr}, update-error={upd} — DNS updates are failing"
    else:
        c.status, c.detail = "ok", "no NCR or update errors"
    return c


# ── jen group ──────────────────────────────────────────────────────────────


def cert_days_left() -> int | None:
    """Days until the installed SSL cert expires (negative = already
    expired), or None when HTTPS isn't configured or the cert can't be
    read. Shared by the cert_expiry check and the cert-expiring alert."""
    import jen.config as _config

    if not _config.ssl_configured():
        return None
    from jen.services import certs

    return certs.cert_info(certs.installed_cert_path()).get("days_left")


def _cert_expiry(ctx) -> Check:
    c = Check("cert_expiry", "TLS certificate expiry", "jen", fix_url="/settings/security")
    days = cert_days_left()
    if days is None:
        c.status, c.detail = "skip", "HTTPS not configured or certificate unreadable"
        return c
    if days < 0:
        c.status, c.detail = "fail", f"the TLS certificate expired {abs(days)} day(s) ago"
    elif days <= 7:
        c.status, c.detail = "fail", f"the TLS certificate expires in {days} day(s)"
    elif days <= 30:
        c.status, c.detail = "warn", f"the TLS certificate expires in {days} day(s)"
    else:
        c.status, c.detail = "ok", f"valid for {days} more day(s)"
    return c


def _db_roundtrip(cm, cid: str, title: str) -> Check:
    c = Check(cid, title, "jen")
    try:
        t0 = time.monotonic()
        with cm() as db, db.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        c.status, c.detail = "ok", f"responded in {(time.monotonic() - t0) * 1000:.0f} ms"
    except Exception as e:
        _log_err(cid, e)
        c.status, c.detail = "fail", "unreachable — see server logs"
    return c


def _db_jen(ctx) -> Check:
    return _db_roundtrip(__db.jen_db, "db_jen", "Jen database")


def _db_kea(ctx) -> Check:
    return _db_roundtrip(__db.kea_db, "db_kea", "Kea database")


def _schema_current(ctx) -> Check:
    c = Check("schema_current", "Database schema current", "jen")
    try:
        from jen.models.migrations import applied_versions, latest_version

        latest = latest_version()
        applied = applied_versions()
    except Exception as e:
        _log_err("schema_current", e)
        c.status, c.detail = "fail", "could not read schema_migrations — see server logs"
        return c
    if latest in applied:
        c.status, c.detail = "ok", f"at migration {latest}"
    else:
        pending = sorted(v for v in range(1, latest + 1) if v not in applied)
        c.status = "fail"
        c.detail = f"migration(s) {', '.join(map(str, pending))} not applied — restart Jen to migrate"
    return c


def _helper_installed(ctx) -> Check:
    c = Check("helper_installed", "Kea host helper installed", "jen", fix_url="/settings/kea")
    ssh_servers = [s for s in extensions.KEA_SERVERS if s.get("ssh_host")]
    if not ssh_servers:
        c.status, c.detail = "skip", "no Kea host has SSH configured"
        return c
    from jen.services import kea_host

    status = kea_host.helper_status()
    behind = []
    for s in ssh_servers:
        v = status.get(str(s.get("id")), {}).get("version")
        if not isinstance(v, int) or v < kea_host.JEN_HELPER_MIN_VERSION:
            behind.append(_server_name(s))
    if behind:
        c.status = "warn"
        c.detail = f"{', '.join(behind)} still on the legacy root path — install the helper from Settings → Kea → SSH"
    else:
        c.status, c.detail = "ok", f"helper recorded on {len(ssh_servers)}/{len(ssh_servers)} host(s)"
    return c


def _background_workers(ctx) -> Check:
    c = Check("background_workers", "Background workers running", "jen")
    from jen.services import background

    if background.STARTED_AT is None:
        c.status, c.detail = "skip", "workers start with gunicorn, not the test server"
        return c
    started = background.STARTED_AT
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    up = (datetime.now(timezone.utc) - started).total_seconds()
    c.status, c.detail = "ok", f"scheduler + alert loop running for {up / 3600:.1f} h"
    return c


def _update_available(ctx) -> Check:
    c = Check("update_available", "Jen up to date", "jen", fix_url="/settings/system")
    c.status = "skip"
    c.detail = "not checked here — run the check from Settings → System · Updates"
    return c


# ── helpers ────────────────────────────────────────────────────────────────

_STATUS_RANK = {"ok": 0, "skip": 1, "warn": 2, "fail": 3}


def _worse(a: str, b: str) -> str:
    return a if _STATUS_RANK.get(a, 0) >= _STATUS_RANK.get(b, 0) else b


def _vstr(v) -> str:
    return ".".join(map(str, v)) if v else ""


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else ""


def _stat_value(args: dict, key: str) -> int:
    """Kea statistic-get-all shape: {key: [[value, timestamp], ...]} newest
    first. Missing key or malformed sample → 0."""
    samples = args.get(key)
    try:
        return int(samples[0][0])
    except (TypeError, IndexError, ValueError):
        return 0


def __get_setting(key: str, default: str) -> str:
    from jen.models.user import get_global_setting

    return get_global_setting(key, default)


def _subnet_label(subnet_id) -> str:
    info = extensions.SUBNET_MAP.get(subnet_id, {})
    return info.get("name") or f"Subnet {subnet_id}"


# ── runner ─────────────────────────────────────────────────────────────────

_CHECKS = [
    _kea_reachable,
    _kea_version_supported,
    _kea_ha_state,
    _kea_hooks,
    _kea_time_sync,
    _kea_config_drift,
    _kea_subnets_declared,
    _pool_utilization,
    _lease_snapshot_fresh,
    _d2_reachable,
    _d2_errors,
    _cert_expiry,
    _db_jen,
    _db_kea,
    _schema_current,
    _helper_installed,
    _background_workers,
    _update_available,
]

# id → (title, group), for the try/except fallback and the tests.
_CHECK_META = {
    "kea_reachable": ("Kea servers reachable", "kea"),
    "kea_version_supported": ("Kea version supported", "kea"),
    "kea_ha_state": ("HA state healthy", "kea"),
    "kea_hooks": ("Kea hooks loaded", "kea"),
    "kea_time_sync": ("Kea clock in sync", "kea"),
    "kea_config_drift": ("Subnet map matches Kea", "kea"),
    "kea_subnets_declared": ("Every Kea subnet is named", "kea"),
    "pool_utilization": ("Pool utilization", "capacity"),
    "lease_snapshot_fresh": ("Lease snapshots current", "capacity"),
    "d2_reachable": ("kea-dhcp-ddns reachable", "ddns"),
    "d2_errors": ("kea-dhcp-ddns error counters", "ddns"),
    "cert_expiry": ("TLS certificate expiry", "jen"),
    "db_jen": ("Jen database", "jen"),
    "db_kea": ("Kea database", "jen"),
    "schema_current": ("Database schema current", "jen"),
    "helper_installed": ("Kea host helper installed", "jen"),
    "background_workers": ("Background workers running", "jen"),
    "update_available": ("Jen up to date", "jen"),
}

CHECK_IDS = list(_CHECK_META.keys())
GROUP_ORDER = ["kea", "capacity", "ddns", "jen"]
GROUP_LABELS = {"kea": "Kea", "capacity": "Capacity", "ddns": "DDNS", "jen": "Jen"}


def run_checks(ctx: dict | None = None) -> list[Check]:
    """Run every check in a fixed order. Each is wrapped: a check that
    raises becomes a `fail` row with the message, and the rest still run.
    `ctx` carries the shared reads (server status, config-get) so the page
    hits Kea once, not once per check; pass `subnet_filter` to scope the
    capacity group for a subnet-restricted viewer."""
    ctx = _build_ctx(ctx)
    out: list[Check] = []
    for fn, cid in zip(_CHECKS, CHECK_IDS, strict=True):
        t0 = time.monotonic()
        try:
            c = fn(ctx)
        except Exception as e:
            title, group = _CHECK_META[cid]
            logger.warning(f"health check {cid} errored: {e}")
            c = Check(cid, title, group, "fail", f"check errored: {e}")
        c.elapsed_ms = int((time.monotonic() - t0) * 1000)
        out.append(c)
    return out


def summarize(checks: list[Check]) -> dict:
    out = {"ok": 0, "warn": 0, "fail": 0, "skip": 0}
    for c in checks:
        out[c.status] = out.get(c.status, 0) + 1
    return out


def group_checks(checks: list[Check]) -> list[tuple[str, str, list[Check]]]:
    """`[(group_id, group_label, [checks]), ...]` in GROUP_ORDER, for the
    page and its partial."""
    by_group: dict[str, list[Check]] = {}
    for c in checks:
        by_group.setdefault(c.group, []).append(c)
    return [(g, GROUP_LABELS.get(g, g.title()), by_group[g]) for g in GROUP_ORDER if g in by_group]
