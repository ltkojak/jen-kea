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
  * The Problems inbox sweep does NOT use this for the READ: it needs a read that is current when it runs (its watermark logic is built on that) and
    runs every five minutes, so there is nothing to coalesce. It does use `path_for`.

v5.69.0-beta.6 (Q175) - `path_for(server)` is where that server's kea-dhcp4 writes its log: `kea_log_trace.log_path_for` of the server's own config file,
read once per server and kept for `PATH_TTL_S` (so a live watch costs the Kea host one config read per two minutes, not one per step, and a sweep every
five minutes reads fresh). The sweep, Trace and Explain all ask here; none of them reads the configured path itself.
"""

import logging
import threading
import time

logger = logging.getLogger(__name__)

TTL_S = 3.0  # == routes/trace.WATCH_STEP_S: a watcher's next poll is just past the window, so it reads once per step

_lock = threading.Lock()
# LOG-CACHE-002 (v5.69.0-beta.9, Q178): the gates that make a second reader wait for the first one's read are a FIXED set, striped by key. They were one Lock per distinct
# key, kept for the life of the process (the key carries the host, user and config path, so every endpoint ever read left one behind). Two unrelated keys may wait on each
# other for one 3 s read; a key never gets two locks, and nothing here grows. The path cache's gates are their own stripes: no thread holds one of each.
_GATES = tuple(threading.Lock() for _ in range(64))
_PATH_GATES = tuple(threading.Lock() for _ in range(64))
_cache: dict[tuple, tuple[float, int, dict]] = {}
_reads = 0  # tail_log calls actually made (the tests, and anyone who wants the count)

PATH_TTL_S = 120.0
FAIL_TTL_S = 15.0
_paths: dict = {}  # server id -> (monotonic time, path, identity, how long it is kept)
_generation = 0  # bumped by clear(): a read that began before it does not store its answer


def reads() -> int:
    return _reads


def clear() -> None:
    global _generation
    with _lock:
        _cache.clear()
        _paths.clear()
        _generation += 1


READ_TIMEOUT_S = 10  # the config read is bounded well below the log read's own: a host whose helper hangs costs one short wait, not a minute


def _read_server_config(server: dict):
    """The parsed config FILE of `server`'s kea-dhcp4 (`{"Dhcp4": ...}`), or None when it cannot be read - or when the host is recorded as having no helper, which is not
    asked (`tail_log` refuses such a host without SSH too). Helper only, bounded, and recording no config revision: the answer is one value out of the file, asked every
    few minutes, and must neither write history nor race a write of Jen's own. The seam the tests replace: no unit test opens an SSH session for a log path."""
    from jen.services import capabilities as _caps
    from jen.services import kea_host as _host

    c = _caps.for_server(server.get("id"), probe_kea=False)
    if c.helper_known and not c.helper:
        return None
    return _host.read_config(server, "dhcp4", timeout=READ_TIMEOUT_S, helper_only=True, capture=False)


def identity(server: dict) -> tuple:
    """What makes it a different host or file: a server edited to point elsewhere is not answered from the old one's cache - and its persisted progress (the Problems
    sweep's watermark, clock and read record) is not carried over to it. A display name is not part of it."""
    return (server.get("ssh_host"), server.get("ssh_user"), server.get("kea_conf"))


_identity = identity


def path_for(server: dict, read: bool = True) -> str:
    """Where `server`'s kea-dhcp4 writes the log Jen reads (`kea_log_trace.log_path_for` of the config file on that host), "" when neither the logger's file nor `[kea]
    dhcp4_log_path` is one the helper would read. One config read per server per `PATH_TTL_S`, kept only while the server's host, user and config path are the ones it was
    read for. A config that cannot be read is the configured path - what every reader used before - kept for `FAIL_TTL_S` only, so one SSH blip does not choose the file for
    two minutes. `read=False` never opens a session: the cached answer, else the configured path (a page that only SHOWS the path)."""
    from jen.services import kea_log_trace as _klt

    sid = server.get("id")
    who = _identity(server)
    gate = _PATH_GATES[hash(sid) % len(_PATH_GATES)]
    with _lock:
        hit = _paths.get(sid)
    if hit and hit[2] == who and time.monotonic() - hit[0] < hit[3]:
        return hit[1]
    if not read:
        return _klt.log_path_for(None)
    with gate:
        with _lock:
            hit = _paths.get(sid)
            generation = _generation
        if hit and hit[2] == who and time.monotonic() - hit[0] < hit[3]:
            return hit[1]
        try:
            cfg = _read_server_config(server)
        except Exception as e:
            logger.warning(
                f"log_tail: could not read {server.get('name')}'s config to find its log: {type(e).__name__}: {e}"
            )
            cfg = None
        path = _klt.log_path_for(cfg)
        with _lock:
            if (
                generation == _generation
            ):  # a clear() while the read was in flight means it was read under a configuration that has since changed
                if len(_paths) > 64:
                    _paths.clear()
                _paths[sid] = (time.monotonic(), path, who, PATH_TTL_S if cfg is not None else FAIL_TTL_S)
        return path


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

    # v5.69.0-beta.8 (Q177, LOG-IDENTITY-001): a read belongs to the endpoint it came from. The key is the server's identity (host, user, config path) as well as its id
    # and the path - `path_for` already keys by it - so a server edited to point at a different host under the same id is never answered with the old host's lines
    key = (*identity(server), server.get("id"), path)
    gate = _GATES[hash(key) % len(_GATES)]
    with gate:  # a second reader waits here for the first one's read, then finds it in the cache
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < TTL_S and hit[1] >= lines:
            return _slice(hit[2], lines)
        with _lock:
            generation = _generation
        res = _host.tail_log(server, path, lines, timeout=timeout, helper_only=True)
        with _lock:
            _reads += 1
            if (
                generation == _generation
            ):  # a clear() while the read was on the wire means it was read under a configuration that has since changed: not kept
                if len(_cache) > 64:
                    _cache.clear()
                _cache[key] = (time.monotonic(), lines, res)
        return res
