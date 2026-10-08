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

import collections
import logging
import queue
import re
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
    "plugin.schema_repaired",
)

KIND_MAX_LENGTH = 40  # events.kind is VARCHAR(40) (jen/models/migrations.py)

# v5.57.0 (Q73) — a plugin kind emit() will accept, lowercase, matching a
# manifest id's own charset (letters/digits/hyphens) for the plugin id.
_PLUGIN_KIND_RE = re.compile(r"^plugin\.[a-z0-9-]+\.[a-z_]+$")

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
#: v5.68.0-beta.22 (Q157): judged by what is waiting NOW. `_last_dispatch_at` is stamped when an event FINISHES, so after an idle hour the first burst (or
#: one slow first subscriber) read as "stuck" while the first event had been in flight for milliseconds, and the lifetime drop total warned for the
#: rest of the process after one historical overflow. Each queued event now carries its enqueue time, the dispatcher stamps when it STARTED the event
#: it is on, and drops are remembered with their times (a window of DROP_WINDOW_S).
_current_started_at: float | None = (
    None  # monotonic, when the event being dispatched right now was taken off the queue; None between events
)
_drop_times: "collections.deque" = collections.deque(maxlen=1000)
DROP_WINDOW_S = 600
#: v5.68.0-beta.21 (Q156): what Health needs to tell a WEDGED dispatcher from a live one. The thread is alive when a subscriber blocks, so `is_alive()`
#: stays green while the queue grows and - at QUEUE_MAX - subscriber delivery is dropped with one log line a minute.
_last_dispatch_at: float | None = (
    None  # monotonic, when the dispatcher last FINISHED an event (or started, until it has)
)
_dropped_total = (
    0  # events whose subscriber delivery was dropped because the queue was full, since this process started
)


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
        global _last_dispatch_at
        _last_dispatch_at = time.monotonic()
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


def queue_depth() -> int:
    """How many events are waiting for the dispatcher thread (v5.68.0-beta.20, Q155 - Health shows it beside the dispatcher's liveness)."""
    try:
        return int(_queue.qsize())
    except Exception:
        return 0


def dispatcher_status() -> dict:
    """{"running", "queue_depth", "last_dispatch_age_s", "dropped"} (v5.68.0-beta.21, Q156). `last_dispatch_age_s` is how long ago the dispatcher last
    finished an event (or, before it has finished one, how long ago it started); None when it is not running. A queue with events in it and an age of
    a minute or more is a dispatcher stuck inside a subscriber; `dropped` counts deliveries lost to a full queue since the process started."""
    running = dispatcher_running()
    now = time.monotonic()
    age = None
    if running and _last_dispatch_at is not None:
        age = max(0.0, now - _last_dispatch_at)
    current = max(0.0, now - _current_started_at) if running and _current_started_at is not None else None
    oldest = None
    try:
        with _queue.mutex:
            head = _queue.queue[0] if _queue.queue else None
        if isinstance(head, tuple) and len(head) == 2 and isinstance(head[1], float):
            oldest = max(0.0, now - head[1])
    except Exception:
        oldest = None
    recent = sum(1 for t in list(_drop_times) if now - t <= DROP_WINDOW_S)
    return {
        "running": running,
        "queue_depth": queue_depth(),
        "current_age_s": current,
        "oldest_queued_age_s": oldest,
        "last_dispatch_age_s": age,
        "dropped_recent": recent,
        "dropped_total": _dropped_total,
        "dropped": _dropped_total,  # kept for older readers: the lifetime total
    }


def _alive(t) -> bool:
    """True for a live thread. Tolerates a stand-in with no `is_alive` (tests
    that replace `threading.Thread` and call start_background_workers())."""
    try:
        return t is not None and bool(t.is_alive())
    except Exception:
        return False


def _dispatch_loop() -> None:
    global _last_dispatch_at, _current_started_at
    while True:
        item = _queue.get()
        if item is _STOP:
            return
        event = item[0] if isinstance(item, tuple) and len(item) == 2 else item
        _current_started_at = time.monotonic()
        try:
            _dispatch(event)
        except Exception as e:  # never let the worker die
            logger.error(f"events dispatcher error: {e}")
        _current_started_at = None
        _last_dispatch_at = time.monotonic()


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


def describe_kind(kind: str) -> dict:
    """Display info for one event kind: {"label", "icon", "is_plugin"}. A
    core (or audit.*/alert.* — timeline.py's own synthetic kinds) label
    is the kind string itself, unchanged, icon None. A plugin kind's
    label is "<plugin display name>: <name>" with icon "puzzle" —
    templates/timeline.html and the dashboard's events feed
    (dashboard_catalog.py::events_feed_widget) both use this instead of
    showing the raw plugin.<id>.<name> string."""
    m = _PLUGIN_KIND_RE.match(kind or "")
    if not m:
        return {"label": kind, "icon": None, "is_plugin": False}
    _, plugin_id, name = kind.split(".", 2)
    from jen.services.plugins import get_loaded_plugins

    plugin_name = get_loaded_plugins().get(plugin_id, {}).get("name", plugin_id)
    return {"label": f"{plugin_name}: {name}", "icon": "puzzle", "is_plugin": True}


def emit(kind, *, mac=None, ip=None, subnet_id=None, hostname=None, server=None, actor=None, detail=""):
    """Write one `events` row and notify subscribers. Never raises.

    v5.57.0 (Q73) — `emit` is now re-exported to plugins (jen.plugin_api),
    which had no way to write to the stream before, only observe it via
    subscribe(). A plugin kind must match `plugin.<plugin_id>.<name>`
    (lowercase, `<plugin_id>` allowing hyphens same as a manifest id);
    anything else — including a core-looking string a plugin didn't
    actually earn — is refused and logged, never raised, matching
    emit()'s own contract for every other failure mode here."""
    if kind not in KINDS and not _PLUGIN_KIND_RE.match(kind or ""):
        logger.error(f"events.emit(): refusing unrecognized kind {kind!r}")
        return None
    if len(kind) > KIND_MAX_LENGTH:
        # events.kind is VARCHAR(40): a longer kind fails the INSERT in strict mode, the row is lost, and
        # every subscriber would still run with id=None. Refused like any other bad kind (emit never raises).
        logger.error(
            f"events.emit(): refusing kind {kind!r}: {len(kind)} characters, the column holds {KIND_MAX_LENGTH}"
        )
        return None
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
            _queue.put_nowait((event, time.monotonic()))
        except queue.Full:
            global _last_drop_log, _dropped_total
            _dropped_total += 1
            now = time.monotonic()
            _drop_times.append(now)
            if now - _last_drop_log >= 60:
                _last_drop_log = now
                logger.error(f"events queue full ({QUEUE_MAX}); dropping subscriber delivery (rows are still written)")
    else:
        _dispatch(event)

    return event
