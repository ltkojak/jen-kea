"""
Host Watchdog plugin for Jen.
Probes chosen hosts on a schedule and alerts when one stops answering,
and again when it comes back. Network Discovery alerts when an unknown
host appears; nothing alerts when a KNOWN host disappears — this fills
that gap.
Version lives in manifest.json — not duplicated here.

Probing (v1.0.0)
─────────────────
`ping` targets use `ping -c 1 -W 1 <ip>` as list-args — Ubuntu's
/usr/bin/ping carries cap_net_raw, so this works unprivileged the same
way Network Discovery's neighbour-table read does. `tcp:<port>[,<port>]`
targets try each port in order with a 2s connect timeout; any one
succeeding counts as up. Every due target is probed through one
module-level 8-thread pool, one run at a time (a lock, like Discovery's
_scan_lock), budgeted at 30s total per periodic tick — a run that runs
long just leaves the stragglers for the next tick rather than blocking
it.

State machine (v1.0.0, pure — see next_state())
─────────────────────────────────────────────────
A target starts 'unknown'. Any single successful probe moves it (or
keeps it) 'up'. A run of `fails_to_down` CONSECUTIVE failures moves it
to 'down' — a lone blip while 'up' or 'unknown' does not flip it early.
Once 'down', it only leaves on the next success. Transitions (not
every check) send an alert and emit an event.
"""

import ipaddress
import logging
import os as _os
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

PLUGIN_ID = "watchdog"

bp = Blueprint(
    "watchdog",
    __name__,
    template_folder="templates",
    root_path=_os.path.dirname(_os.path.abspath(__file__)),
    url_prefix="/network/watchdog",
)

_PROBE_CHOICES = ("ping", "tcp")
_SOURCES = ("reservation", "ipam", "manual")
_INTERVAL_CHOICES = (1, 5, 15, 30, 60)
_FAILS_CHOICES = (1, 2, 3, 5, 10)

# Probing.
_PING_TIMEOUT_S = 3
_TCP_CONNECT_TIMEOUT_S = 2
_POOL_WORKERS = 8
_RUN_BUDGET_S = 30

# History retention.
_KEEP_CHECKS_DAYS = 7
_HISTORY_LIMIT = 50

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_PING_RTT_RE = re.compile(r"time=([\d.]+)\s*ms")
_TCP_PROBE_RE = re.compile(r"^tcp:(\d{1,5}(?:,\d{1,5})*)$")

_run_lock = threading.Lock()
_pool = ThreadPoolExecutor(max_workers=_POOL_WORKERS, thread_name_prefix="wd-probe")


# ── Pure: probe strings, ping output, the state machine, due targets, uptime ──


def parse_probe(probe):
    """Pure: ('ping', None) | ('tcp', [ports]) | (None, error message).
    Each port must be 1-65535; 'tcp:80,443' probes both in order."""
    probe = (probe or "").strip()
    if probe == "ping":
        return "ping", None
    m = _TCP_PROBE_RE.match(probe)
    if not m:
        return None, f"Unknown probe {probe!r} — use 'ping' or 'tcp:<port>[,<port>]'."
    ports = [int(p) for p in m.group(1).split(",")]
    bad = [p for p in ports if not (1 <= p <= 65535)]
    if bad:
        return None, f"Invalid port(s): {bad}"
    return "tcp", ports


def parse_ping(returncode, stdout):
    """Pure: (ok, rtt_ms) from `ping -c 1`'s exit code and stdout. rtt_ms
    is None when there's no reply line to parse (unreachable/timeout)."""
    ok = returncode == 0
    m = _PING_RTT_RE.search(stdout or "")
    rtt = float(m.group(1)) if m else None
    return ok, rtt


def next_state(state, consecutive_fails, fails_to_down, ok):
    """Pure: (new_state, new_consecutive_fails, transitioned). A single
    success always recovers to 'up' from anywhere. A failure only flips
    'up' or 'unknown' to 'down' once `fails_to_down` consecutive
    failures have been seen — a lone blip doesn't flip it early;
    'down' simply stays 'down' (its fail count keeps climbing but that
    never fires a second alert — the caller only alerts on a
    transition)."""
    if ok:
        return "up", 0, (state != "up")
    fails = consecutive_fails + 1
    if fails >= fails_to_down and state != "down":
        return "down", fails, True
    return state, fails, False


def due_targets(targets, last_checked, now):
    """Pure: ids of `targets` (each {id, interval_min, enabled}) whose
    last check (from `last_checked`, {id: datetime or None}) is at
    least interval_min old, or that have never been checked."""
    due = []
    for t in targets:
        if not t.get("enabled"):
            continue
        last = last_checked.get(t["id"])
        if last is None or (now - last) >= timedelta(minutes=t["interval_min"]):
            due.append(t["id"])
    return due


def uptime_pct(checks):
    """Pure: rounded % of `checks` ({"ok": bool}, any window) that were
    ok, or None when the window has no checks at all."""
    if not checks:
        return None
    return round(sum(1 for c in checks if c["ok"]) / len(checks) * 100)


def derive_subnet_id(ip, subnet_map):
    """Pure: the Kea subnet id (from `subnet_map`, {id: {"cidr": ...}})
    whose CIDR contains `ip`, or None when no accessible subnet does —
    a target on an address in no Kea subnet at all, per the Q55 rule
    IPAM's unmanaged subnets already use."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    for sid, info in subnet_map.items():
        try:
            if addr in ipaddress.IPv4Network(info["cidr"], strict=False):
                return sid
        except ValueError:
            continue
    return None


def _format_identifier(hex_str, ident_type):
    """Format a Kea host identifier for display. Only type 0 (hw-address) is a MAC."""
    if not hex_str:
        return ""
    if ident_type == 0 and len(hex_str) == 12:
        return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2)).lower()
    return f"id:{hex_str.lower()}"


# ── DB helpers ────────────────────────────────────────────────────────────────


def _get_db():
    from jen.plugin_api import get_jen_db

    return get_jen_db()


def _get_kea_db():
    from jen.plugin_api import get_kea_db

    return get_kea_db()


def _subnet_map():
    from jen.plugin_api import subnet_map

    return subnet_map()


def _accessible_subnets():
    from jen.plugin_api import get_accessible_subnet_map

    return get_accessible_subnet_map()


def _is_admin():
    try:
        from jen.plugin_api import is_admin_or_above

        return is_admin_or_above()
    except Exception:
        role = getattr(current_user, "role", None)
        if role is not None:
            return role in ("superadmin", "admin")
        return bool(getattr(current_user, "is_admin", False))


def _require_write():
    if _is_admin():
        return True
    flash("Viewers can look at Watchdog but not change it.", "error")
    return False


def _all_subnets_user():
    return bool(getattr(current_user, "all_subnets", False))


def _visible_rows(rows):
    """Filters DB rows carrying a `subnet_id` column to accessible Kea
    subnets; a NULL subnet_id (no Kea subnet contains the target's IP)
    is unrestricted-only, per the Q55 rule."""
    accessible = _accessible_subnets()
    all_subnets = _all_subnets_user()
    out = []
    for r in rows:
        sid = r.get("subnet_id")
        if sid is None:
            if all_subnets:
                out.append(r)
        elif sid in accessible:
            out.append(r)
    return out


def _normalize_mac(raw):
    if not raw:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(cleaned) != 12:
        return ""
    mac = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac if _MAC_RE.match(mac) else ""


def _audit(action, target, detail):
    try:
        from jen.plugin_api import audit

        audit(action, target, detail)
    except Exception as e:
        logger.error(f"Watchdog: audit failed: {e}")


# ── Candidates for the Add Target picker ───────────────────────────────────────


def _candidate_hosts():
    """Reservations (Kea's hosts table, incl. global ones) plus IPAM
    Lite static/planned entries, across accessible subnets only."""
    accessible = _accessible_subnets()
    out = []
    kdb = None
    try:
        kdb = _get_kea_db()
        with kdb.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, hostname, HEX(dhcp_identifier) AS ident_hex, "
                "dhcp_identifier_type AS ident_type, dhcp4_subnet_id AS subnet_id FROM hosts "
                "WHERE ipv4_address IS NOT NULL AND ipv4_address > 0"
            )
            for row in cur.fetchall():
                if not row["ip"]:
                    continue
                sid = row.get("subnet_id") or None
                if sid and sid not in accessible:
                    continue
                mac = _format_identifier(row.get("ident_hex"), row.get("ident_type"))
                out.append(
                    {
                        "ip": row["ip"],
                        "mac": mac if not mac.startswith("id:") else "",
                        "label": row.get("hostname") or "",
                        "subnet_id": sid,
                        "source": "reservation",
                    }
                )
    except Exception as e:
        logger.warning(f"Watchdog: reservation candidates failed: {e}")
    finally:
        if kdb:
            kdb.close()
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT ip, mac, label, subnet_id FROM ipam_static_entries "
                "WHERE subnet_kind='kea' AND entry_status IN ('static','planned')"
            )
            for row in cur.fetchall():
                if row["subnet_id"] not in accessible:
                    continue
                out.append(
                    {
                        "ip": row["ip"],
                        "mac": row.get("mac") or "",
                        "label": row.get("label") or "",
                        "subnet_id": row["subnet_id"],
                        "source": "ipam",
                    }
                )
    except Exception:
        pass  # IPAM Lite not installed, or its table not yet migrated
    finally:
        if db:
            db.close()
    return out


# ── Probing (impure: subprocess / socket) ──────────────────────────────────────


def _probe_target(target):
    """One target's probe -> (ok, rtt_ms, error)."""
    kind, spec = parse_probe(target["probe"])
    if kind == "ping":
        try:
            proc = subprocess.run(
                ["ping", "-c", "1", "-W", "1", target["ip"]],
                capture_output=True,
                text=True,
                timeout=_PING_TIMEOUT_S,
            )
            ok, rtt = parse_ping(proc.returncode, proc.stdout)
            return ok, rtt, "" if ok else "no reply"
        except Exception as e:
            return False, None, str(e)[:200]
    if kind == "tcp":
        last_err = ""
        for port in spec:
            try:
                start = time.monotonic()
                with socket.create_connection((target["ip"], port), timeout=_TCP_CONNECT_TIMEOUT_S):
                    return True, round((time.monotonic() - start) * 1000), ""
            except Exception as e:
                last_err = str(e)[:150]
                continue
        return False, None, f"no response on port(s) {','.join(str(p) for p in spec)}: {last_err}"
    return False, None, "invalid probe configuration"


def _tick():
    """The periodic job (every minute): probe every due, enabled
    target through the module pool, one run at a time. Records a
    wd_checks row and updates wd_state per target; alerts + emits only
    on a state transition. Prunes wd_checks older than 7 days."""
    if not _run_lock.acquire(blocking=False):
        return
    try:
        db = None
        try:
            db = _get_db()
            with db.cursor() as cur:
                cur.execute(
                    "SELECT id, ip, probe, interval_min, fails_to_down, label, subnet_id, mac "
                    "FROM wd_targets WHERE enabled=1"
                )
                targets = cur.fetchall()
                cur.execute("SELECT target_id, MAX(checked_at) AS last FROM wd_checks GROUP BY target_id")
                last_checked = {r["target_id"]: r["last"] for r in cur.fetchall()}
        finally:
            if db:
                db.close()
        if not targets:
            return
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        due_ids = set(due_targets(targets, last_checked, now))
        due = [t for t in targets if t["id"] in due_ids]
        if not due:
            return

        deadline = time.monotonic() + _RUN_BUDGET_S
        futures = {_pool.submit(_probe_target, t): t for t in due}
        results = {}
        try:
            for fut in as_completed(futures, timeout=max(0.1, deadline - time.monotonic())):
                t = futures[fut]
                try:
                    results[t["id"]] = fut.result()
                except Exception as e:
                    results[t["id"]] = (False, None, str(e)[:200])
        except FuturesTimeoutError:
            pass  # whatever finished in budget gets recorded; stragglers wait for the next tick

        _record_results({t["id"]: t for t in due}, results)
    finally:
        _run_lock.release()


def _record_results(by_id, results):
    if not results:
        return
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            for target_id, (ok, rtt, error) in results.items():
                cur.execute(
                    "INSERT INTO wd_checks (target_id, ok, rtt_ms, error) VALUES (%s, %s, %s, %s)",
                    (target_id, 1 if ok else 0, rtt, (error or "")[:200]),
                )
                cur.execute(
                    "SELECT state, consecutive_fails FROM wd_state WHERE target_id=%s",
                    (target_id,),
                )
                row = cur.fetchone()
                state = row["state"] if row else "unknown"
                fails = row["consecutive_fails"] if row else 0
                target = by_id[target_id]
                new_state, new_fails, transitioned = next_state(state, fails, target["fails_to_down"], ok)
                if row:
                    cur.execute(
                        "UPDATE wd_state SET state=%s, consecutive_fails=%s, "
                        "last_ok_at=IF(%s, UTC_TIMESTAMP(), last_ok_at), "
                        "last_fail_at=IF(%s, last_fail_at, UTC_TIMESTAMP()), "
                        "last_error=%s, since=IF(%s, UTC_TIMESTAMP(), since) WHERE target_id=%s",
                        (new_state, new_fails, ok, ok, (error or "")[:200], transitioned, target_id),
                    )
                else:
                    cur.execute(
                        "INSERT INTO wd_state (target_id, state, consecutive_fails, since, last_ok_at, "
                        "last_fail_at, last_error) VALUES (%s, %s, %s, UTC_TIMESTAMP(), "
                        "IF(%s, UTC_TIMESTAMP(), NULL), IF(%s, NULL, UTC_TIMESTAMP()), %s)",
                        (target_id, new_state, new_fails, ok, ok, (error or "")[:200]),
                    )
                if transitioned:
                    _alert_transition(target, new_state)
            cur.execute(
                "DELETE FROM wd_checks WHERE checked_at < UTC_TIMESTAMP() - INTERVAL %s DAY", (_KEEP_CHECKS_DAYS,)
            )
        db.commit()
    except Exception as e:
        logger.error(f"Watchdog: recording results failed: {e}")
    finally:
        if db:
            db.close()


def _alert_transition(target, new_state):
    alert_type = "watchdog_down" if new_state == "down" else "watchdog_up"
    label = target.get("label") or target["ip"]
    subnet_name = _subnet_map().get(target.get("subnet_id"), {}).get("name", "") if target.get("subnet_id") else ""
    try:
        from jen.plugin_api import send_alert

        send_alert(
            alert_type,
            subnet_id=target.get("subnet_id"),
            label=label,
            ip=target["ip"],
            subnet=subnet_name or "no Kea subnet",
        )
    except Exception as e:
        logger.warning(f"Watchdog: could not send {alert_type} alert: {e}")
    try:
        from jen.plugin_api import emit

        emit(
            f"plugin.watchdog.{'down' if new_state == 'down' else 'up'}",
            mac=target.get("mac") or None,
            ip=target["ip"],
            subnet_id=target.get("subnet_id"),
            detail=f"{label} is {new_state}",
        )
    except Exception as e:
        logger.warning(f"Watchdog: could not emit transition event: {e}")


# ── Search provider (register_search_provider) ────────────────────────────────


def _watchdog_search(query, accessible_subnet_ids, all_subnets):
    q = (query or "").strip()
    if not q:
        return []
    like = f"%{q}%"
    out = []
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT t.id, t.ip, t.label, t.subnet_id, s.state FROM wd_targets t "
                "LEFT JOIN wd_state s ON s.target_id = t.id "
                "WHERE t.label LIKE %s OR t.ip LIKE %s ORDER BY t.created_at DESC LIMIT 20",
                (like, like),
            )
            for row in cur.fetchall():
                out.append(
                    {
                        "title": row.get("label") or row["ip"],
                        "subtitle": f"{row['ip']} · {row.get('state') or 'unknown'}",
                        "href": url_for("watchdog.index"),
                        "subnet_id": row["subnet_id"],
                    }
                )
    except Exception as e:
        logger.error(f"Watchdog: search provider failed: {e}")
    finally:
        if db:
            db.close()
    return out


# ── Routes: page ────────────────────────────────────────────────────────────


def _target_rows():
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT t.id, t.ip, t.mac, t.label, t.subnet_id, t.source, t.probe, t.interval_min, "
                "t.fails_to_down, t.enabled, s.state, s.since, s.last_ok_at, s.last_error "
                "FROM wd_targets t LEFT JOIN wd_state s ON s.target_id = t.id ORDER BY t.label, t.ip"
            )
            rows = cur.fetchall()
            for r in rows:
                cur.execute(
                    "SELECT ok FROM wd_checks WHERE target_id=%s AND checked_at >= UTC_TIMESTAMP() - INTERVAL 7 DAY",
                    (r["id"],),
                )
                r["uptime_pct"] = uptime_pct([{"ok": bool(c["ok"])} for c in cur.fetchall()])
    except Exception as e:
        logger.error(f"Watchdog: index error: {e}")
        rows = []
    finally:
        if db:
            db.close()
    return rows


@bp.route("/")
@login_required
def index():
    rows = _visible_rows(_target_rows())
    subnet_map = _subnet_map()
    for r in rows:
        r["subnet_name"] = subnet_map.get(r["subnet_id"], {}).get("name", "") if r["subnet_id"] else "—"
    candidates = _candidate_hosts() if _is_admin() else []
    return render_template(
        "watchdog/index.html",
        rows=rows,
        candidates=candidates,
        interval_choices=_INTERVAL_CHOICES,
        fails_choices=_FAILS_CHOICES,
        is_admin=_is_admin(),
    )


@bp.route("/targets/add", methods=["POST"])
@login_required
def add_target():
    if not _require_write():
        return redirect(url_for("watchdog.index"))

    ip = request.form.get("ip", "").strip()
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        flash("Invalid IP address.", "error")
        return redirect(url_for("watchdog.index"))

    label = request.form.get("label", "").strip()[:100]
    mac = _normalize_mac(request.form.get("mac", ""))
    source = request.form.get("source", "manual")
    if source not in _SOURCES:
        source = "manual"
    probe = request.form.get("probe", "ping").strip()
    kind, err = parse_probe(probe)
    if kind is None:
        flash(err, "error")
        return redirect(url_for("watchdog.index"))
    try:
        interval_min = int(request.form.get("interval_min", 5))
        fails_to_down = int(request.form.get("fails_to_down", 3))
    except ValueError:
        flash("Invalid interval or failure threshold.", "error")
        return redirect(url_for("watchdog.index"))
    if interval_min not in _INTERVAL_CHOICES or fails_to_down not in _FAILS_CHOICES:
        flash("Pick one of the offered interval/threshold values.", "error")
        return redirect(url_for("watchdog.index"))

    subnet_id = derive_subnet_id(ip, _subnet_map())
    if subnet_id is not None and subnet_id not in _accessible_subnets():
        flash("That address is outside your accessible subnets.", "error")
        return redirect(url_for("watchdog.index"))
    if subnet_id is None and not _all_subnets_user():
        flash("That address isn't in any subnet you have full access to.", "error")
        return redirect(url_for("watchdog.index"))

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO wd_targets (ip, mac, subnet_id, label, source, probe, interval_min, "
                "fails_to_down, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (ip, mac or None, subnet_id, label, source, probe, interval_min, fails_to_down, current_user.username),
            )
        db.commit()
        flash(f"Now watching {label or ip}.", "success")
        _audit("WATCHDOG_ADD", ip, f"label={label} probe={probe}")
    except Exception as e:
        flash(f"Could not add target: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("watchdog.index"))


@bp.route("/targets/<int:target_id>/toggle", methods=["POST"])
@login_required
def toggle_target(target_id):
    if not _require_write():
        return redirect(url_for("watchdog.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT enabled FROM wd_targets WHERE id=%s", (target_id,))
            row = cur.fetchone()
            if row is None:
                flash("Target not found.", "error")
                return redirect(url_for("watchdog.index"))
            new_enabled = 0 if row["enabled"] else 1
            cur.execute("UPDATE wd_targets SET enabled=%s WHERE id=%s", (new_enabled, target_id))
        db.commit()
        flash("Target resumed." if new_enabled else "Target paused.", "success")
    except Exception as e:
        flash(f"Could not update target: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("watchdog.index"))


@bp.route("/targets/<int:target_id>/delete", methods=["POST"])
@login_required
def delete_target(target_id):
    if not _require_write():
        return redirect(url_for("watchdog.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM wd_checks WHERE target_id=%s", (target_id,))
            cur.execute("DELETE FROM wd_state WHERE target_id=%s", (target_id,))
            cur.execute("DELETE FROM wd_targets WHERE id=%s", (target_id,))
        db.commit()
        flash("Target removed.", "success")
        _audit("WATCHDOG_DELETE", str(target_id), "target removed")
    except Exception as e:
        flash(f"Could not remove target: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("watchdog.index"))


@bp.route("/targets/<int:target_id>/history")
@login_required
def target_history(target_id):
    db = None
    rows = []
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT checked_at, ok, rtt_ms, error FROM wd_checks WHERE target_id=%s "
                "ORDER BY checked_at DESC LIMIT %s",
                (target_id, _HISTORY_LIMIT),
            )
            for r in cur.fetchall():
                rows.append(
                    {
                        "checked_at": r["checked_at"].strftime("%Y-%m-%d %H:%M") if r.get("checked_at") else "",
                        "ok": bool(r["ok"]),
                        "rtt_ms": r.get("rtt_ms"),
                        "error": r.get("error") or "",
                    }
                )
    except Exception as e:
        logger.error(f"Watchdog: history error: {e}")
    finally:
        if db:
            db.close()
    return jsonify({"rows": rows})


# ── Row action target: "Watch this host" (reservation rows) ───────────────────


@bp.route("/watch", methods=["POST"])
@login_required
def watch_from_row():
    if not _require_write():
        return redirect(url_for("watchdog.index"))
    ip = request.args.get("ip", "").strip()
    mac = _normalize_mac(request.args.get("mac", ""))
    hostname = request.args.get("hostname", "").strip()[:100]
    try:
        subnet_id = int(request.args.get("subnet_id", ""))
    except (TypeError, ValueError):
        subnet_id = derive_subnet_id(ip, _subnet_map())
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        flash("Invalid IP address.", "error")
        return redirect(url_for("watchdog.index"))
    if subnet_id is not None and subnet_id not in _accessible_subnets():
        flash("That address is outside your accessible subnets.", "error")
        return redirect(url_for("watchdog.index"))

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT id FROM wd_targets WHERE ip=%s", (ip,))
            if cur.fetchone():
                flash(f"{hostname or ip} is already being watched.", "warning")
                return redirect(url_for("watchdog.index"))
            cur.execute(
                "INSERT INTO wd_targets (ip, mac, subnet_id, label, source, probe, created_by) "
                "VALUES (%s, %s, %s, %s, 'reservation', 'ping', %s)",
                (ip, mac or None, subnet_id, hostname, current_user.username),
            )
        db.commit()
        flash(f"Now watching {hostname or ip}.", "success")
        _audit("WATCHDOG_ADD", ip, f"label={hostname} source=reservation")
    except Exception as e:
        flash(f"Could not add target: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("watchdog.index"))


# ── JSON API (v1.0.0, plugin API v3) ───────────────────────────────────────────
# Undecorated on purpose: api_key_required() is applied in register(app), not
# here, so plugin.py's top level never imports jen.plugin_api — the standalone
# harness (tools/test_plugin.py) stubs only flask/flask_login.

api_bp = Blueprint("watchdog_api", __name__, url_prefix="/api/v1/plugins/watchdog")


def _api_list_targets():
    from flask import g

    from jen.plugin_api import filter_subnet_ids

    rows = _target_rows()
    kea_ids = [r["subnet_id"] for r in rows if r["subnet_id"] is not None]
    allowed = set(filter_subnet_ids(g.api_key, kea_ids))
    out = []
    for r in rows:
        if r["subnet_id"] is not None and r["subnet_id"] not in allowed:
            continue
        out.append(
            {
                "id": r["id"],
                "ip": r["ip"],
                "mac": r.get("mac") or "",
                "label": r.get("label") or "",
                "subnet_id": r["subnet_id"],
                "probe": r["probe"],
                "enabled": bool(r["enabled"]),
                "state": r.get("state") or "unknown",
                "uptime_pct": r.get("uptime_pct"),
            }
        )
    return jsonify({"targets": out})


def _api_add_target():
    from flask import g

    from jen.plugin_api import filter_subnet_ids

    body = request.get_json(silent=True) or {}
    ip = str(body.get("ip", "")).strip()
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return jsonify({"error": "invalid ip"}), 400
    probe = str(body.get("probe", "ping"))
    kind, err = parse_probe(probe)
    if kind is None:
        return jsonify({"error": err}), 400
    subnet_id = derive_subnet_id(ip, _subnet_map())
    if subnet_id is not None and subnet_id not in filter_subnet_ids(g.api_key, [subnet_id]):
        return jsonify({"error": "subnet not accessible to this key"}), 403
    label = str(body.get("label", "") or "")[:100]
    mac = _normalize_mac(body.get("mac", ""))
    interval_min = body.get("interval_min", 5)
    fails_to_down = body.get("fails_to_down", 3)
    if interval_min not in _INTERVAL_CHOICES or fails_to_down not in _FAILS_CHOICES:
        return jsonify({"error": "invalid interval_min/fails_to_down"}), 400

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO wd_targets (ip, mac, subnet_id, label, source, probe, interval_min, "
                "fails_to_down, created_by) VALUES (%s, %s, %s, %s, 'manual', %s, %s, %s, %s)",
                (ip, mac or None, subnet_id, label, probe, interval_min, fails_to_down, f"api:{g.api_key['name']}"),
            )
            new_id = cur.lastrowid
        db.commit()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if db:
            db.close()
    return jsonify({"ok": True, "id": new_id, "ip": ip})


def register(app):
    app.register_blueprint(bp)

    from jen.plugin_api import (
        api_key_required,
        register_alert_type,
        register_periodic,
        register_row_action,
        register_search_provider,
    )

    api_bp.add_url_rule(
        "/targets", "api_list_targets", api_key_required(write=False)(_api_list_targets), methods=["GET"]
    )
    api_bp.add_url_rule("/targets", "api_add_target", api_key_required(write=True)(_api_add_target), methods=["POST"])
    app.register_blueprint(api_bp)

    register_alert_type(
        PLUGIN_ID,
        "watchdog_down",
        label="Watchdog: host down",
        icon="circle-x",
        default_template="🚨 <b>{label}</b> ({ip}, {subnet}) has stopped answering.",
    )
    register_alert_type(
        PLUGIN_ID,
        "watchdog_up",
        label="Watchdog: host back up",
        icon="circle-check",
        default_template="✅ <b>{label}</b> ({ip}, {subnet}) is answering again.",
    )
    register_row_action(
        PLUGIN_ID,
        "reservation",
        label="Watch this host",
        icon="activity",
        href="/network/watchdog/watch?mac={mac}&ip={ip}&subnet_id={subnet_id}&hostname={hostname}",
        method="POST",
    )
    register_search_provider(PLUGIN_ID, title="Host Watchdog", fn=_watchdog_search)
    register_periodic(PLUGIN_ID, "probe-tick", _tick, 1)

    logger.info("Host Watchdog plugin registered")
