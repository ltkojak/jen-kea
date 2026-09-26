"""
jen/services/api_auth.py
──────────────────────────
v5.57.0 (Q73) — Bearer API-key auth, moved out of jen/routes/api.py so
`api_key_required()` (the plugin-API v3 decorator for routes mounted
under /api/v1/plugins/<plugin_id>/…) can reuse the exact same validation
without importing a route module. jen/routes/api.py's own REST v1 routes
import `api_auth`/`key_subnet_ids` from here unchanged.
"""

import hashlib
import json
import logging
from functools import wraps

from flask import g, jsonify, request

logger = logging.getLogger(__name__)


def api_auth():
    """Validate Bearer token. Returns key row (id, name, subnet_access,
    can_write) or None.

    v5.2.10 — last_used used to be written on every single authenticated
    API request, unconditionally, regardless of how recently it was last
    updated. Harmless at low traffic, but unnecessary write amplification
    for a value whose only real use (showing roughly when a key was last
    used, in the API keys list) doesn't need second-level precision. Now
    only updates once per 5-minute window per key, via a single
    conditional UPDATE — atomic and one round trip, not a separate
    SELECT-then-maybe-UPDATE that could race with itself under
    concurrent requests.
    """
    from jen.models.db import jen_db

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    raw_key = auth[7:].strip()
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    try:
        with jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT id, name, subnet_access, can_write FROM api_keys WHERE key_hash=%s AND active=1", (key_hash,)
            )
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE api_keys SET last_used=NOW() WHERE id=%s "
                    "AND (last_used IS NULL OR last_used < NOW() - INTERVAL 5 MINUTE)",
                    (row["id"],),
                )
                db.commit()
        return row
    except Exception:
        return None


def key_subnet_ids(key_row):
    """Return the set of subnet_ids this key is scoped to, or None for
    unrestricted (all subnets) — same NULL-means-all convention as
    users.subnet_access. Malformed JSON is treated as unrestricted-deny
    (empty set) rather than unrestricted-allow, so a corrupt value can
    never silently grant more access than intended."""
    raw = key_row.get("subnet_access") if key_row else None
    if raw is None:
        return None
    try:
        ids = json.loads(raw) if isinstance(raw, str) else raw
        return {int(i) for i in ids}
    except Exception:
        return set()


def filter_subnet_ids(key_row, subnet_ids):
    """`subnet_ids` narrowed to what `key_row` can access (a list,
    unchanged in order) — the whole list back, unmodified, when the key
    is unrestricted."""
    scope = key_subnet_ids(key_row)
    if scope is None:
        return list(subnet_ids)
    return [sid for sid in subnet_ids if sid in scope]


# v5.65.8 (Q97) - the per-key write limiter used to live in jen/routes/api.py's own write gate, so a
# plugin's write endpoint (a wake packet per call, an IPAM entry) had no limit at all. It is here, and
# `api_key_required(write=True)` applies it, so every write - core or plugin - shares one budget per key.
WRITE_RATE_PER_MINUTE = 60
_write_hits: dict = {}


def write_rate_limited(key_id) -> bool:
    """In-memory per-key limiter for the write endpoints: at most WRITE_RATE_PER_MINUTE calls in
    any rolling 60 s window."""
    import time as _time

    now = _time.monotonic()
    hits = [t for t in _write_hits.get(key_id, []) if now - t < 60]
    if len(hits) >= WRITE_RATE_PER_MINUTE:
        _write_hits[key_id] = hits
        return True
    hits.append(now)
    _write_hits[key_id] = hits
    return False


RATE_LIMIT_MESSAGE = "Rate limit: at most 60 write requests per minute per key."


def api_key_required(write: bool = False):
    """Decorator for plugin routes mounted under
    /api/v1/plugins/<plugin_id>/… — the same Bearer auth jen/routes/api.py
    uses for its own REST v1 endpoints. Sets flask.g.api_key on success;
    401 JSON without a valid Bearer key, 403 JSON when write=True and the
    key's can_write flag is off. Bearer requests under /api/v1/ are
    already CSRF-exempt (jen/services/csrf.py)."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = api_auth()
            if not key:
                return jsonify({"error": "Invalid or missing API key."}), 401
            if write and not key.get("can_write"):
                return jsonify(
                    {"error": "This API key is read-only. Create one with write access under Settings → API Keys."}
                ), 403
            if write and write_rate_limited(key["id"]):
                return jsonify({"error": RATE_LIMIT_MESSAGE}), 429
            g.api_key = key
            return fn(*args, **kwargs)

        return wrapper

    return decorator
