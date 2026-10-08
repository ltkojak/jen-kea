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
        "last_finished": None,  # v5.68.0-beta.21 (Q156)
        "last_error": "",
        "history": [],  # the outcome (True = ran clean) of the last three runs, oldest first
        "start_failures": 0,  # consecutive failed Thread.start() calls (v5.68.0-beta.22, Q157)
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


def _record_run(job: dict, ok: bool) -> None:
    job["history"] = [*job.get("history", []), ok][-3:]
    job["last_finished"] = datetime.now(timezone.utc)


def _run_one_periodic(job: dict) -> None:
    try:
        job["fn"]()
        job["last_error"] = ""
        _record_run(job, True)
    except Exception as e:  # a plugin bug must never take the loop down
        job["last_error"] = str(e)
        _record_run(job, False)
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
        # v5.68.0-beta.21 (Q156): `running` was set above, under the lock, and the thread started here OUTSIDE it with no rollback - a `Thread.start()`
        # that raised (the process out of threads) left `running=True` for ever, and a running job is skipped for ever. A start that fails is a failed
        # run: running goes back to False, the error is recorded - and (v5.68.0-beta.22, Q157) its SCHEDULE is put back: `next_due` was advanced by a
        # whole interval above, before the spawn, so "the next tick tries again" was a comment - the job waited out its interval. A failed start is
        # retried after `min(interval, 60 s x 2^(failures - 1))`: 60 s, 120 s, 240 s ... never later than the interval itself; a start that works
        # resets the count.
        try:
            if spawn is not None:
                spawn(j)
            else:
                threading.Thread(
                    target=_run_one_periodic, args=(j,), name=f"jen-periodic-{j['plugin_id']}", daemon=True
                ).start()
            started += 1
            j["start_failures"] = 0
        except Exception as e:
            j["running"] = False
            j["last_error"] = f"could not start: {e}"
            _record_run(j, False)
            j["start_failures"] = j.get("start_failures", 0) + 1
            wait_s = min(j["every_minutes"] * 60, 60 * 2 ** (j["start_failures"] - 1))
            with _periodic_lock:
                j["next_due"] = now + timedelta(seconds=wait_s)
            logger.error(
                f"Periodic job {j['plugin_id']}/{j['name']} could not be started ({j['start_failures']} in a row): {e}; trying again in {wait_s} s"
            )
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

# v5.68.0-beta.19 (Q154): the worker threads, kept so the Health Center can ask whether they are still alive instead of inferring it
# from the fact that `start_background_workers` was once called.
_alert_thread = None
_periodic_thread = None


def liveness() -> dict:
    """{"started_at", "alert_thread", "periodic_thread" (is_alive each), "dispatcher" (the event dispatcher thread, v5.68.0-beta.20 - `emit()` runs
    its subscribers inline without it), "queue_depth" (events waiting for it), "scheduler" (scheduler.scheduler_status())} - what is PROVEN about
    the background work, not what was once attempted."""
    from jen.services import events
    from jen.services.scheduler import scheduler_status

    dispatcher = (
        events.dispatcher_status()
    )  # v5.68.0-beta.21 (Q156): depth, last-dispatch age, drops - a wedged dispatcher is still alive
    return {
        "started_at": STARTED_AT,
        "alert_thread": bool(_alert_thread is not None and _alert_thread.is_alive()),
        "periodic_thread": bool(_periodic_thread is not None and _periodic_thread.is_alive()),
        "dispatcher": bool(dispatcher["running"]),
        "queue_depth": dispatcher["queue_depth"],
        "dispatcher_status": dispatcher,
        "periodic_jobs": periodic_jobs(),
        "scheduler": scheduler_status(),
    }


def start_background_workers(app) -> bool:
    """Start the backup scheduler and the alert-monitoring loop for this
    process. Idempotent — returns True if this call started them, False
    if they were already running."""
    global _started, STARTED_AT, _alert_thread, _periodic_thread
    with _lock:
        if _started:
            return False
        _started = True

    STARTED_AT = datetime.now(timezone.utc)

    from jen.services.alerts import check_alerts
    from jen.services.scheduler import start_scheduler

    start_scheduler(app)

    from jen.services.events import start_dispatcher

    start_dispatcher()

    t = threading.Thread(target=check_alerts, name="jen-alerts", daemon=True)
    t.start()
    _alert_thread = t
    # v5.30.0 (Q30, A2) — the plugins' periodic-job loop, started here and
    # only here (never by the factory).
    _periodic_thread = threading.Thread(target=_periodic_loop, name="jen-periodic", daemon=True)
    _periodic_thread.start()
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
    try:
        from jen.services.events import stop_dispatcher

        stop_dispatcher(timeout=2.0)
    except Exception:
        pass
    with _lock:
        _started = False
        STARTED_AT = None
