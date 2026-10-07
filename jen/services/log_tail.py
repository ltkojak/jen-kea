"""
jen/services/log_tail.py
────────────────────────
v5.68.0-beta.17 (Q152) - one cached read of a Kea server's log per (server, path), shared by every reader.

The live watch on Trace re-tails every `WATCH_STEP_S` seconds for up to ten minutes, and each poll was its own SSH round trip that makes the
helper read the last thousand lines of the log. Two admins watching the same server (or one watching and a third opening an Investigation
page, whose Explain tab reads the same log) cost the Kea host two, three, four tails every three seconds - the cost grew with the number of
watchers. Here a read is kept for `TTL_S` seconds per `(server id, path)` and every reader inside that window gets the same lines, and a
reader that arrives while one is in flight WAITS for it instead of starting another, so N watchers cost one tail per step.

  * The cache holds the lines of the largest request made inside the window; a request for fewer lines gets the newest ones of those (the
    log's tail is the log's tail whatever its length), a request for more starts a new read.
  * A failed read (host unreachable, no helper, log missing) is kept for the window too: a hanging host must not be asked again by every
    watcher every three seconds.
  * Everything goes through `kea_host.tail_log(..., helper_only=True)` exactly as the callers did, looked up at call time.
  * The Problems inbox sweep does NOT use this: it needs a read that is current when it runs (its watermark logic is built on that) and
    runs every five minutes, so there is nothing to coalesce.
"""

import threading
import time

TTL_S = 3.0  # == routes/trace.WATCH_STEP_S: a watcher's next poll is just past the window, so it reads once per step

_lock = threading.Lock()
_per_key: dict[tuple, threading.Lock] = {}
_cache: dict[tuple, tuple[float, int, dict]] = {}
_reads = 0  # tail_log calls actually made (the tests, and anyone who wants the count)


def reads() -> int:
    return _reads


def clear() -> None:
    with _lock:
        _cache.clear()


def _slice(res: dict, lines: int) -> dict:
    got = res.get("lines")
    if isinstance(got, list) and len(got) > lines:
        return {**res, "lines": got[-lines:]}
    return res


def tail(server: dict, path: str, lines: int, timeout: float | None = None) -> dict:
    """`kea_host.tail_log(server, path, lines, timeout=timeout, helper_only=True)`, coalesced per (server id, path) for `TTL_S`."""
    global _reads
    # at call time: callers and tests patch `kea_host.tail_log`, and this module is imported early
    from jen.services import kea_host as _host

    key = (server.get("id"), path)
    with _lock:
        gate = _per_key.setdefault(key, threading.Lock())
    with gate:  # a second reader waits here for the first one's read, then finds it in the cache
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < TTL_S and hit[1] >= lines:
            return _slice(hit[2], lines)
        res = _host.tail_log(server, path, lines, timeout=timeout, helper_only=True)
        with _lock:
            _reads += 1
            if len(_cache) > 64:
                _cache.clear()
            _cache[key] = (time.monotonic(), lines, res)
        return res
