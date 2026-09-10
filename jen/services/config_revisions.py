"""
jen/services/config_revisions.py
────────────────────────────────
v5.16.0 — a history of every Kea config Jen writes to a host, plus the
external changes it notices, stored in `kea_config_revisions` (migration
20). Each row is `(server_id, service, sha256, config, summary,
username, source, created_at)` where `config` is
`json.dumps(cfg, indent=2, sort_keys=True)` — canonical so a unified
diff between two rows is stable.

`source ∈ {jen, external, restore}`:
- `jen`      — a config Jen applied via a form or route.
- `external` — the file changed on the host between Jen writes (detected
               by `read_config_versioned`, v2 helper only — no SHA, no
               capture).
- `restore`  — a prior revision re-applied from the history page.

The number kept per (server, service) is the global setting
`config_revision_keep` (default 50), pruned oldest-first after each
`record()`.
"""

from __future__ import annotations

import difflib
import json
import logging

logger = logging.getLogger(__name__)

DEFAULT_KEEP = 50


def _jen_db():
    from jen.models.db import jen_db

    return jen_db()


def canonical(cfg: dict) -> str:
    """The stored form — indent=2, sorted keys — so diffs don't churn on
    key order or Kea's own formatting."""
    return json.dumps(cfg, indent=2, sort_keys=True)


def _keep() -> int:
    from jen.models.user import get_global_setting

    try:
        return max(1, int(get_global_setting("config_revision_keep", str(DEFAULT_KEEP))))
    except (TypeError, ValueError):
        return DEFAULT_KEEP


def _current_username() -> str:
    try:
        from flask_login import current_user

        return (getattr(current_user, "username", "") or "")[:64]
    except Exception:
        return ""


def record(server_id: int, service: str, cfg: dict, sha256: str, summary: str, source: str = "jen") -> int | None:
    """Insert a revision (config canonicalised here) and prune. Returns
    the new row id, or None on a DB error (never raises — a failed
    history write must not fail the config apply that triggered it)."""
    body = canonical(cfg)
    try:
        with _jen_db() as db, db.cursor() as cur:
            cur.execute(
                "INSERT INTO kea_config_revisions "
                "(server_id, service, sha256, config, summary, username, source) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (server_id, service, sha256 or "", body, (summary or "")[:255], _current_username(), source),
            )
            rev_id = cur.lastrowid
        prune(server_id, service)
        return rev_id
    except Exception as e:
        logger.warning(f"config_revisions.record failed for server {server_id}/{service}: {e}")
        return None


def latest(server_id: int, service: str) -> dict | None:
    try:
        with _jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT * FROM kea_config_revisions WHERE server_id=%s AND service=%s ORDER BY id DESC LIMIT 1",
                (server_id, service),
            )
            return cur.fetchone()
    except Exception as e:
        logger.warning(f"config_revisions.latest failed: {e}")
        return None


def list_revisions(server_id: int, service: str, limit: int = 100) -> list[dict]:
    try:
        with _jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT id, server_id, service, sha256, summary, username, source, created_at "
                "FROM kea_config_revisions WHERE server_id=%s AND service=%s ORDER BY id DESC LIMIT %s",
                (server_id, service, max(1, min(int(limit), 500))),
            )
            return list(cur.fetchall())
    except Exception as e:
        logger.warning(f"config_revisions.list failed: {e}")
        return []


def get(rev_id: int) -> dict | None:
    try:
        with _jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT * FROM kea_config_revisions WHERE id=%s", (rev_id,))
            return cur.fetchone()
    except Exception as e:
        logger.warning(f"config_revisions.get failed: {e}")
        return None


def previous(rev_id: int, server_id: int, service: str) -> dict | None:
    """The revision immediately before `rev_id` for the same server/service."""
    try:
        with _jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT * FROM kea_config_revisions "
                "WHERE server_id=%s AND service=%s AND id < %s ORDER BY id DESC LIMIT 1",
                (server_id, service, rev_id),
            )
            return cur.fetchone()
    except Exception as e:
        logger.warning(f"config_revisions.previous failed: {e}")
        return None


def diff(a_text: str, b_text: str, a_label: str = "previous", b_label: str = "this") -> list[str]:
    """Unified diff, 3 lines of context. Each element is one line WITHOUT
    a trailing newline — the caller escapes it for HTML."""
    return list(
        difflib.unified_diff(
            (a_text or "").splitlines(),
            (b_text or "").splitlines(),
            fromfile=a_label,
            tofile=b_label,
            lineterm="",
            n=3,
        )
    )


def prune(server_id: int, service: str, keep: int | None = None) -> int:
    """Delete all but the newest `keep` revisions for this (server,
    service). Returns the number removed."""
    keep = _keep() if keep is None else max(1, int(keep))
    try:
        with _jen_db() as db, db.cursor() as cur:
            # id of the oldest row we keep; everything below it goes.
            cur.execute(
                "SELECT id FROM kea_config_revisions WHERE server_id=%s AND service=%s ORDER BY id DESC LIMIT 1 OFFSET %s",
                (server_id, service, keep - 1),
            )
            row = cur.fetchone()
            if row is None:
                return 0  # fewer than `keep` rows
            cur.execute(
                "DELETE FROM kea_config_revisions WHERE server_id=%s AND service=%s AND id < %s",
                (server_id, service, row["id"]),
            )
            return cur.rowcount
    except Exception as e:
        logger.warning(f"config_revisions.prune failed: {e}")
        return 0
