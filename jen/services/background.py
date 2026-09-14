"""
jen/services/background.py
──────────────────────────
Startup for Jen's in-process background work: the APScheduler backup
scheduler and the `check_alerts` monitoring loop.

Why this isn't in the app factory (v5.5.0)
──────────────────────────────────────────
`create_app()` used to call `start_scheduler(app)` directly. That was a
latent bug: the factory is imported by the test suite, by
`flask routes`-style tooling, and — once Jen moved to gunicorn — would
be by every worker process. A factory that starts threads starts them
in all of those contexts.

Now the factory only builds the app. The entrypoint decides whether
this process should own the background work:

- `jen/wsgi.py` (the gunicorn entrypoint) calls `start_background_workers()`
  once at import. Jen runs gunicorn with `--workers 1`, so "once per
  worker" is "once", full stop. If the worker is recycled the new
  process re-imports wsgi and starts its own — correct, the old
  process's threads died with it.
- `run.py`'s werkzeug fallback path calls it too.
- The test suite never calls it.

`start_background_workers()` is idempotent within a process regardless,
guarded by a module flag, so a double call is a harmless no-op.
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

_started = False
_lock = threading.Lock()

# ── Periodic jobs for plugins (v5.30.0, Q30, A2) ─────────────────────────────
# A plugin's register(app) runs inside create_app(), which must start
# nothing — so a plugin that wants "scan this subnet every N hours" can't
# own a thread. It registers a callable here instead, and the ONE loop this
# module starts (only ever from start_background_workers, i.e. never in the
# factory or the test suite) ticks every registered job on its interval.
# Each run is its own daemon thread, wrapped so a plugin exception can never
# stop the loop; a job still running when its next tick comes is skipped,
# never stacked.
PERIODIC_MIN_MINUTES = 5
_PERIODIC_TICK_SECONDS = 30
_periodic: list[dict] = []
_periodic_lock = threading.Lock()


def register_periodic(plugin_id: str, name: str, fn, every_minutes: int) -> None:
    """Register `fn()` to run every `every_minutes` (≥ PERIODIC_MIN_MINUTES).
    Re-registering the same (plugin_id, name) replaces the earlier entry.
    The first run is one interval after registration, never at boot."""
    if not callable(fn):
        raise TypeError("fn must be callable")
    every = int(every_minutes)
    if every < PERIODIC_MIN_MINUTES:
        raise ValueError(f"every_minutes must be at least {PERIODIC_MIN_MINUTES}")
    key = (str(plugin_id), str(name))
    entry = {
        "plugin_id": key[0],
        "name": key[1],
        "fn": fn,
        "every_minutes": every,
        "next_due": datetime.now(timezone.utc) + timedelta(minutes=every),
        "running": False,
        "last_started": None,
        "last_error": "",
    }
    with _periodic_lock:
        _periodic[:] = [j for j in _periodic if (j["plugin_id"], j["name"]) != key]
        _periodic.append(entry)
    logger.info(f"Periodic job registered: {key[0]}/{key[1]} every {every} min")


def unregister_periodic(plugin_id: str, name: str | None = None) -> None:
    with _periodic_lock:
        _periodic[:] = [
            j for j in _periodic if not (j["plugin_id"] == plugin_id and (name is None or j["name"] == name))
        ]


def periodic_jobs() -> list[dict]:
    """Introspection (Health, tests): copies without the callable."""
    with _periodic_lock:
        return [{k: v for k, v in j.items() if k != "fn"} for j in _periodic]


def _run_one_periodic(job: dict) -> None:
    try:
        job["fn"]()
        job["last_error"] = ""
    except Exception as e:  # a plugin bug must never take the loop down
        job["last_error"] = str(e)
        logger.error(f"Periodic job {job['plugin_id']}/{job['name']} failed: {e}")
    finally:
        job["running"] = False


def run_due_periodic_jobs(now: datetime | None = None, spawn=None) -> int:
    """Start every job whose next_due has passed and isn't still running;
    returns how many were started. `spawn(job)` defaults to a daemon
    thread per run (tests pass a synchronous callable)."""
    now = now or datetime.now(timezone.utc)
    started = 0
    with _periodic_lock:
        due = [j for j in _periodic if j["next_due"] <= now and not j["running"]]
        for j in due:
            j["running"] = True
            j["last_started"] = now
            j["next_due"] = now + timedelta(minutes=j["every_minutes"])
    for j in due:
        started += 1
        if spawn is not None:
            spawn(j)
        else:
            threading.Thread(
                target=_run_one_periodic, args=(j,), name=f"jen-periodic-{j['plugin_id']}", daemon=True
            ).start()
    return started


def _periodic_loop() -> None:
    while True:
        time.sleep(_PERIODIC_TICK_SECONDS)
        try:
            run_due_periodic_jobs()
        except Exception as e:  # pragma: no cover - defensive
            logger.error(f"periodic loop tick failed: {e}")


# v5.12.0 — set to a UTC datetime the first time this process actually
# starts the workers; stays None in the test suite and anywhere else that
# imports the factory without a real entrypoint. The Health Center reads
# it to tell "workers running" from "started under the test server".
STARTED_AT = None


def start_background_workers(app) -> bool:
    """Start the backup scheduler and the alert-monitoring loop for this
    process. Idempotent — returns True if this call started them, False
    if they were already running."""
    global _started, STARTED_AT
    with _lock:
        if _started:
            return False
        _started = True

    STARTED_AT = datetime.now(timezone.utc)

    from jen.services.alerts import check_alerts
    from jen.services.scheduler import start_scheduler

    start_scheduler(app)

    t = threading.Thread(target=check_alerts, name="jen-alerts", daemon=True)
    t.start()
    # v5.30.0 (Q30, A2) — the plugins' periodic-job loop, started here and
    # only here (never by the factory).
    threading.Thread(target=_periodic_loop, name="jen-periodic", daemon=True).start()
    logger.info("Background workers started (scheduler + alert loop + periodic jobs)")
    return True


def stop_background_workers() -> None:
    """Best-effort shutdown of the scheduler. The alert loop is a daemon
    thread and dies with the process; there's nothing to join."""
    global _started, STARTED_AT
    try:
        from jen.services.scheduler import stop_scheduler

        stop_scheduler()
    except Exception:
        pass
    with _lock:
        _started = False
        STARTED_AT = None
