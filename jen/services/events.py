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
import queue
import threading
import time

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

# v5.49.0-beta.2 — subscribers run on ONE shared worker thread, not the
# emitter's. `emit()` (called from the alert loop and request handlers)
# writes its DB row, then enqueues the event; a slow subscriber therefore
# delays the next subscriber, never Jen. The queue is bounded: when it is
# full the event is dropped (the DB row is already written) and that is
# logged at most once a minute. When the dispatcher is not running — tests,
# CLI tools, the werkzeug fallback — `emit()` dispatches inline, exactly as
# before.
QUEUE_MAX = 1000
_queue: "queue.Queue" = queue.Queue(maxsize=QUEUE_MAX)
_dispatcher: threading.Thread | None = None
_last_drop_log = 0.0
_STOP = object()


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


def start_dispatcher() -> bool:
    """Start the one dispatcher thread (idempotent). Called from
    `jen.services.background.start_background_workers()`. Returns True if
    this call started it."""
    global _dispatcher
    with _lock:
        if _alive(_dispatcher):
            return False
        _dispatcher = threading.Thread(target=_dispatch_loop, name="jen-events", daemon=True)
        _dispatcher.start()
        return True


def stop_dispatcher(timeout: float = 5.0) -> None:
    """Stop the dispatcher after it drains what is queued (tests, shutdown)."""
    global _dispatcher
    with _lock:
        t = _dispatcher
    if not _alive(t):
        with _lock:
            if _dispatcher is t:
                _dispatcher = None
        return
    # Keep the reference until STOP is actually queued: clearing it first let
    # start_dispatcher() launch a SECOND thread while a wedged first one (behind
    # a full queue) was still alive.
    try:
        _queue.put(_STOP, timeout=1)
    except queue.Full:
        logger.error("events.stop_dispatcher: queue full, could not queue STOP; dispatcher left running")
        return
    t.join(timeout)
    if not _alive(t):
        with _lock:
            if _dispatcher is t:
                _dispatcher = None


def dispatcher_running() -> bool:
    return _alive(_dispatcher)


def _alive(t) -> bool:
    """True for a live thread. Tolerates a stand-in with no `is_alive` (tests
    that replace `threading.Thread` and call start_background_workers())."""
    try:
        return t is not None and bool(t.is_alive())
    except Exception:
        return False


def _dispatch_loop() -> None:
    while True:
        item = _queue.get()
        if item is _STOP:
            return
        try:
            _dispatch(item)
        except Exception as e:  # never let the worker die
            logger.error(f"events dispatcher error: {e}")


def _dispatch(event: dict) -> None:
    """Call every matching subscriber for one event; a raising subscriber is
    logged and the rest still run."""
    kind = event["kind"]
    with _lock:
        subs = list(_SUBSCRIBERS)
    for kind_or_star, fn in subs:
        if kind_or_star != "*" and kind_or_star != kind:
            continue
        try:
            fn(event)
        except Exception as e:
            logger.error(f"events subscriber for {kind_or_star!r} raised on kind={kind!r}: {e}")


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
    if dispatcher_running():
        try:
            _queue.put_nowait(event)
        except queue.Full:
            global _last_drop_log
            now = time.monotonic()
            if now - _last_drop_log >= 60:
                _last_drop_log = now
                logger.error(f"events queue full ({QUEUE_MAX}); dropping subscriber delivery (rows are still written)")
    else:
        _dispatch(event)

    return event
