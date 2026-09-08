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

logger = logging.getLogger(__name__)

_started = False
_lock = threading.Lock()


def start_background_workers(app) -> bool:
    """Start the backup scheduler and the alert-monitoring loop for this
    process. Idempotent — returns True if this call started them, False
    if they were already running."""
    global _started
    with _lock:
        if _started:
            return False
        _started = True

    from jen.services.alerts import check_alerts
    from jen.services.scheduler import start_scheduler

    start_scheduler(app)

    t = threading.Thread(target=check_alerts, name="jen-alerts", daemon=True)
    t.start()
    logger.info("Background workers started (scheduler + alert loop)")
    return True


def stop_background_workers() -> None:
    """Best-effort shutdown of the scheduler. The alert loop is a daemon
    thread and dies with the process; there's nothing to join."""
    global _started
    try:
        from jen.services.scheduler import stop_scheduler

        stop_scheduler()
    except Exception:
        pass
    with _lock:
        _started = False
