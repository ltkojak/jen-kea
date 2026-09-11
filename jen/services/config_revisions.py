"""
jen/services/config_revisions.py
────────────────────────────────
v5.16.0 — a history of every Kea config Jen writes to a host, plus the
external changes it notices, stored in `kea_config_revisions` (migration
20). Each row is `(server_id, service, sha256, hash_kind, config,
summary, username, source, created_at)` where `config` is stored as
`encrypt_secret(canonical(cfg))` (v5.20.0 — a "v1:"-prefixed Fernet
token; `canonical()` is indent=2/sort_keys=True JSON so a unified diff
of the DECRYPTED bodies is stable) and decrypted transparently by every
reader below (a legacy plaintext row from before v5.20.0 passes through
`decrypt_secret()` unchanged).

`source ∈ {jen, external, restore, baseline}`:
- `jen`      — a config Jen applied via a form or route.
- `external` — the file changed on the host between Jen writes (detected
               by `read_config_versioned`, v2 helper only).
- `restore`  — a prior revision re-applied from the history page.
- `baseline` — the first config Jen ever saw on a host, or the first one
               it saw with a raw (helper v2) hash after only ever having
               a canonical one (v1/legacy) — v5.20.0, so the very first
               write is guarded and the very first diff has a "before".

`hash_kind ∈ {raw, canonical, legacy}` records what `sha256` actually
hashes (v5.20.0) — `raw` = sha256 of the live config file's own bytes
(helper v2's `read-config`/`apply-config`), `canonical` = sha256 of
`canonical(cfg)` (no raw hash available: v1 helper or the legacy path),
`legacy` = a pre-5.20.0 row whose kind was never recorded. The two
non-legacy kinds are NOT interchangeable — comparing a `raw` sha against
a `canonical` one (or vice versa) always mismatches even when nothing
changed.

The number kept per (server, service) is the global setting
`config_revision_keep` (default 50), pruned oldest-first after each
`record()`.
"""

from __future__ import annotations

import difflib
import json
import logging

from jen.services.crypto import decrypt_secret, encrypt_secret

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


def record(
    server_id: int,
    service: str,
    cfg: dict,
    sha256: str,
    summary: str,
    *,
    hash_kind: str,
    source: str = "jen",
) -> int | None:
    """Insert a revision (config canonicalised and encrypted here) and
    prune. Returns the new row id, or None on a DB error (never raises
    — a failed history write must not fail the config apply that
    triggered it). `hash_kind` is required (v5.20.0) — every caller
    knows whether `sha256` is a raw-bytes hash or a canonical-JSON one;
    guessing here would be exactly the ambiguity this column exists to
    remove."""
    body = encrypt_secret(canonical(cfg))
    try:
        with _jen_db() as db, db.cursor() as cur:
            cur.execute(
                "INSERT INTO kea_config_revisions "
                "(server_id, service, sha256, hash_kind, config, summary, username, source) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (server_id, service, sha256 or "", hash_kind, body, (summary or "")[:255], _current_username(), source),
            )
            rev_id = cur.lastrowid
        prune(server_id, service)
        return rev_id
    except Exception as e:
        logger.warning(f"config_revisions.record failed for server {server_id}/{service}: {e}")
        return None


def _decrypted(row: dict | None) -> dict | None:
    """Decrypt `row["config"]` in place. Raises SecretDecryptError (from
    jen.services.crypto) if the row is encrypted but the key can't
    decrypt it — deliberately NOT caught here, so a caller can tell that
    apart from "no such revision" / a DB error and show it as its own
    condition (a bad/missing /etc/jen/mfa_key), not silently return
    None or garbled text."""
    if row is not None and row.get("config") is not None:
        row["config"] = decrypt_secret(row["config"], what="config revision")
    return row


def latest(server_id: int, service: str) -> dict | None:
    try:
        with _jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT * FROM kea_config_revisions WHERE server_id=%s AND service=%s ORDER BY id DESC LIMIT 1",
                (server_id, service),
            )
            row = cur.fetchone()
    except Exception as e:
        logger.warning(f"config_revisions.latest failed: {e}")
        return None
    return _decrypted(row)


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


def count(server_id: int, service: str | None = None) -> int:
    """How many revisions are stored for a server (optionally one service).
    Used for the "Config history (N)" link on the /servers page."""
    try:
        with _jen_db() as db, db.cursor() as cur:
            if service is None:
                cur.execute("SELECT COUNT(*) AS n FROM kea_config_revisions WHERE server_id=%s", (server_id,))
            else:
                cur.execute(
                    "SELECT COUNT(*) AS n FROM kea_config_revisions WHERE server_id=%s AND service=%s",
                    (server_id, service),
                )
            return int(cur.fetchone()["n"])
    except Exception as e:
        logger.warning(f"config_revisions.count failed: {e}")
        return 0


def get(rev_id: int) -> dict | None:
    try:
        with _jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT * FROM kea_config_revisions WHERE id=%s", (rev_id,))
            row = cur.fetchone()
    except Exception as e:
        logger.warning(f"config_revisions.get failed: {e}")
        return None
    return _decrypted(row)


def previous(rev_id: int, server_id: int, service: str) -> dict | None:
    """The revision immediately before `rev_id` for the same server/service."""
    try:
        with _jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT * FROM kea_config_revisions "
                "WHERE server_id=%s AND service=%s AND id < %s ORDER BY id DESC LIMIT 1",
                (server_id, service, rev_id),
            )
            row = cur.fetchone()
    except Exception as e:
        logger.warning(f"config_revisions.previous failed: {e}")
        return None
    return _decrypted(row)


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
