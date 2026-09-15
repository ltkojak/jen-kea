"""
jen/services/events.py
───────────────────────
v5.42.0 (Q43) — a best-effort, in-process event stream. `emit()` writes
one row to `events` (migration 27) and then calls every subscriber
registered via `subscribe()`/`unsubscribe()` (the plugin API,
`PLUGIN_API_VERSION` 2). A failing DB write or a raising subscriber is
logged, never raised — this is telemetry for the `/timeline` page and
plugins, not a transaction anything else depends on.
"""

import logging
import threading

logger = logging.getLogger(__name__)

# Pinned kind vocabulary (Q43 design) — a module constant so callers and
# tests validate against it rather than typo a string. `discovery.unknown`
# is reserved for the network-discovery plugin's next release; nothing in
# core emits it yet.
KINDS = (
    "lease.new",
    "lease.expired",
    "lease.ip_changed",
    "lease.hostname_changed",
    "device.first_seen",
    "reservation.added",
    "reservation.deleted",
    "reservation.changed",
    "config.applied",
    "ha.state_changed",
    "drift.detected",
    "drift.resolved",
    "alert.sent",
    "discovery.unknown",
)

_SUBSCRIBERS: list[tuple[str, object]] = []  # (kind_or_"*", fn)
_lock = threading.Lock()


def subscribe(kind_or_star: str, fn) -> None:
    """Register `fn(event: dict)` to be called after every `emit()` whose
    kind matches `kind_or_star` (`"*"` for every kind). `event` carries
    `{id, kind, mac, ip, subnet_id, hostname, server, actor, detail}` —
    `id` is `None` if the DB write itself failed."""
    if not callable(fn):
        raise TypeError("fn must be callable")
    with _lock:
        _SUBSCRIBERS.append((kind_or_star, fn))


def unsubscribe(fn) -> None:
    """Remove every subscription registered for this callable. Uses `==`,
    not `is` — a bound method (e.g. `list.append`) is a fresh wrapper
    object on every attribute access, so `obj.method is obj.method` is
    False even though they're `==` (same `__self__` and `__func__`)."""
    with _lock:
        _SUBSCRIBERS[:] = [(k, f) for k, f in _SUBSCRIBERS if f != fn]


def emit(kind, *, mac=None, ip=None, subnet_id=None, hostname=None, server=None, actor=None, detail=""):
    """Write one `events` row and notify subscribers. Never raises."""
    event_id = None
    try:
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute(
                "INSERT INTO events (kind, mac, ip, subnet_id, hostname, server, actor, detail) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (kind, mac, ip, subnet_id, hostname, server, actor, detail or ""),
            )
            event_id = cur.lastrowid
    except Exception as e:
        logger.error(f"events.emit({kind!r}) DB write failed: {e}")

    event = {
        "id": event_id,
        "kind": kind,
        "mac": mac,
        "ip": ip,
        "subnet_id": subnet_id,
        "hostname": hostname,
        "server": server,
        "actor": actor,
        "detail": detail or "",
    }
    with _lock:
        subs = list(_SUBSCRIBERS)
    for kind_or_star, fn in subs:
        if kind_or_star != "*" and kind_or_star != kind:
            continue
        try:
            fn(event)
        except Exception as e:
            logger.error(f"events subscriber for {kind_or_star!r} raised on kind={kind!r}: {e}")

    return event
