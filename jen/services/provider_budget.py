"""
jen/services/provider_budget.py
────────────────────────────────
v5.68.0-beta.11 (Q146) — the one place a plugin's investigation or search provider is actually run, so the one-second budget the
docs always promised is a bound and not a log line. Both kinds used to run in the request thread and compare the elapsed time
afterwards: a provider that hung (a database that stopped answering, a socket with no timeout) held the web worker for as long as it
liked and the page waited with it.

  * ONE module-level `ThreadPoolExecutor` (`MAX_WORKERS` threads - `[server] threads`, see `configure`) runs every provider call, and the request waits on each call's
    future for at most the budget (`future.result(timeout=...)`), counted from the moment all of a page's calls were submitted - so
    seven slow providers cost one second, not seven. A call that has not answered by then is shown as "unavailable (over 1 s)" and the
    request goes on; a call still queued is cancelled, one already running cannot be stopped (Python has no safe way to), so it is
    logged ONCE, counted, and its answer dropped when it arrives.
  * A `BoundedSemaphore` of `MAX_OUTSTANDING` bounds the calls in flight or abandoned. A slot is returned only when the call really
    ends, not when the request stops waiting - so providers that hang do not pile up without limit. v5.68.0-beta.17 (Q152): the
    bound is a CEILING sized for the whole server, `max(16, 2 x [server] threads x registered providers)`, not for one page. It was
    8 with seven providers per page, so a second admin's page opened while the first's seven calls were in flight got one slot and six
    "unavailable (busy)" cards. A call over the ceiling now WAITS for a slot until its page's deadline and is shown "busy" only if the
    deadline passes while it waits (every call of a page is submitted together, so the wait is inside the same one budget).
  * A provider is written against the caller's own request (`current_user`, `request`, `url_for`), and the pool's threads have
    none, so each call runs inside a copy of the request's context with the SAME authenticated user the page already loaded - the
    provider answers for the caller who asked, never for "whoever the worker last served".

Called outside any request (the pure tests of the registries, a plugin's own contract test) a call simply runs in a worker with no
context, as before.
"""

import logging
import threading
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from flask import copy_current_request_context, g, has_request_context

logger = logging.getLogger(__name__)

MIN_OUTSTANDING = 16
MAX_WORKERS = 8  # replaced by configure() from `[server] threads` once the app has loaded its plugins
MAX_OUTSTANDING = MIN_OUTSTANDING

_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="jen-provider")
_slots = threading.BoundedSemaphore(MAX_OUTSTANDING)
_lock = threading.Lock()
_stats = {"overruns": 0, "refused": 0}


def sizing(threads: int, providers: int) -> tuple[int, int]:
    """(workers, ceiling) for a server running `threads` request threads and `providers` registered providers: one worker per request
    thread, and a ceiling of twice what every thread could have outstanding if each ran a page of every provider at once."""
    threads = max(1, int(threads))
    return threads, max(MIN_OUTSTANDING, 2 * threads * max(0, int(providers)))


def configure(threads: int, providers: int) -> None:
    """Size the pool and the ceiling for this server. Called once by the app factory after the plugins have registered their
    providers (a plugin install or removal needs a restart, so the count is fixed for the life of the process). Calls that were
    started on the pool being replaced keep releasing the semaphore they took, so nothing leaks."""
    global MAX_WORKERS, MAX_OUTSTANDING, _executor, _slots
    workers, ceiling = sizing(threads, providers)
    old = _executor
    MAX_WORKERS, MAX_OUTSTANDING = workers, ceiling
    _executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="jen-provider")
    _slots = threading.BoundedSemaphore(ceiling)
    old.shutdown(wait=False)  # what it already started finishes; nothing new goes to it


def stats() -> dict:
    """{"overruns": calls still running when their budget ran out, "refused": calls turned away because every slot was taken}
    since the process started - for the tests, and for whoever reads a log and wants the count."""
    with _lock:
        return dict(_stats)


def _label(budget: float) -> str:
    return f"over {budget:g} s"


def _with_context(fn):
    """`fn` wrapped so it runs inside a copy of this request's context, as the same user. Outside a request, `fn` itself."""
    if not has_request_context():
        return fn
    from flask_login import current_user

    try:
        user = current_user._get_current_object()
    except Exception:
        user = None

    def call():
        if user is not None:
            g._login_user = user  # flask-login's own per-request cache: the user the page already loaded, not a reload
        return fn()

    return copy_current_request_context(call)


def run_bounded(kind: str, calls: list, budget: float) -> list[dict]:
    """Run `calls` - a list of (label, zero-argument callable) - and answer one outcome per call, in order:
    {"label", "state": "ok" | "error" | "timeout" | "busy", "value", "error", "reason"}. `reason` is the short text the page shows
    after "unavailable" ("over 1 s", "busy"); empty for "ok" and "error" (a provider that raised is logged by the caller, the
    page's wording for it is unchanged). `kind` names the sort of provider in the log lines."""
    started = time.monotonic()
    slots, executor = _slots, _executor  # this page's pair, even if configure() swaps them meanwhile
    pending = []
    for label, fn in calls:
        # Q152: wait for a slot until THIS PAGE's deadline instead of being turned away on arrival; "busy" only if the deadline passes
        if not slots.acquire(timeout=max(0.0, started + budget - time.monotonic())):
            with _lock:
                _stats["refused"] += 1
            logger.warning(
                f"{kind} provider {label!r} not run: {MAX_OUTSTANDING} provider calls are already outstanding"
                f" and none ended within the {budget:g}s budget"
            )
            pending.append((label, None))
            continue
        try:
            future = executor.submit(_with_context(fn))
        except Exception:
            slots.release()
            raise
        # the slot goes back when the call REALLY ends, not when the page stops waiting
        future.add_done_callback(lambda _f, _s=slots: _s.release())
        pending.append((label, future))

    outcomes = []
    for label, future in pending:
        out = {"label": label, "state": "ok", "value": None, "error": None, "reason": ""}
        if future is None:
            out.update(state="busy", reason="busy")
        else:
            try:
                out["value"] = future.result(timeout=max(0.0, started + budget - time.monotonic()))
            except FutureTimeout:
                if future.cancel():
                    out.update(state="timeout", reason=_label(budget))  # never started: queued behind running calls
                elif future.done():
                    try:  # it finished in the instant between the wait and the cancel
                        out["value"] = future.result()
                    except Exception as e:
                        out.update(state="error", error=e)
                else:
                    with _lock:
                        _stats["overruns"] += 1
                    logger.warning(
                        f"{kind} provider {label!r} is still running after its {budget:g}s budget; the page went on without it"
                        " and its answer will be dropped"
                    )
                    out.update(state="timeout", reason=_label(budget))
            except CancelledError:
                out.update(state="timeout", reason=_label(budget))
            except Exception as e:
                out.update(state="error", error=e)
        outcomes.append(out)
    return outcomes
