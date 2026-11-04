"""
tests/_kea_api_world.py
───────────────────────
Q212 - what the tests of `jen/services/kea_api_config.py` and of the change set's api targets share: an in-memory `config_revisions` (no database) and the fixtures that install it.
"""

import copy
import json


class Store:
    """An in-memory `config_revisions` for one server: the functions the module and the file reader call, with the stored body a canonical JSON string as the real one decrypts to."""

    def __init__(self):
        self.rows = []
        self._next = 1
        self.unreadable = False  # Q216 (AA11): the store cannot be READ - `pending()` raises, as `config_revisions.pending` does, never answers None

    def record(self, server_id, service, cfg, sha256, summary, *, hash_kind, source="jen"):
        row = {
            "id": self._next,
            "server_id": server_id,
            "service": service,
            "sha256": sha256 or "",
            "hash_kind": hash_kind,
            "config": json.dumps(cfg, indent=2, sort_keys=True),
            "summary": summary,
            "source": source,
            "created_at": "2026-11-03 12:00:00",
        }
        self._next += 1
        self.rows.append(row)
        return row["id"]

    def _of(self, server_id, service):
        return [r for r in self.rows if r["server_id"] == server_id and r["service"] == service]

    def latest(self, server_id, service, exclude_kind=None):
        rows = [r for r in self._of(server_id, service) if r["hash_kind"] != exclude_kind]
        return copy.deepcopy(rows[-1]) if rows else None

    def latest_of_kind(self, server_id, service, hash_kind):
        rows = [r for r in self._of(server_id, service) if r["hash_kind"] == hash_kind]
        return copy.deepcopy(rows[-1]) if rows else None

    def pending(self, server_id, service):
        if self.unreadable:
            from jen.services.config_revisions import RevisionStoreUnreadable

            raise RevisionStoreUnreadable("the revision store could not be read (the test's fault)")
        rows = [r for r in self._of(server_id, service) if r["source"] == "pending"]
        return copy.deepcopy(rows[-1]) if rows else None

    def finish(self, rev_id, *, source, sha256, summary=None, cfg=None):
        for r in self.rows:
            if r["id"] == rev_id:
                r["source"], r["sha256"] = source, sha256
                if cfg is not None:
                    r["config"] = json.dumps(cfg, indent=2, sort_keys=True)
                return True
        return False

    def discard_pending(self, server_id, service):
        before = len(self.rows)
        self.rows = [
            r
            for r in self.rows
            if not (r["server_id"] == server_id and r["service"] == service and r["source"] == "pending")
        ]
        return before - len(self.rows)

    def discard(self, rev_id):
        before = len(self.rows)
        self.rows = [r for r in self.rows if r["id"] != rev_id]
        return len(self.rows) < before

    def canonical(self, cfg):
        return json.dumps(cfg, indent=2, sort_keys=True)


def install_store(monkeypatch):
    """Patch `config_revisions` with a fresh `Store`; a test module wraps this in its own `store` fixture."""
    s = Store()
    for name in ("record", "latest", "latest_of_kind", "pending", "finish", "discard", "discard_pending"):
        monkeypatch.setattr(f"jen.services.config_revisions.{name}", getattr(s, name))
    return s


def install_probes(monkeypatch, *, valid=True):
    """Patch the stored probe (`kea_api_config.stored_probe` / `store_probe`) with a dict. With `valid` every server id reads as a server whose probe passed, was consented to and is fresh - the
    state a server is in after its operator has used the card - until a test stores something else for it."""
    from datetime import datetime, timezone

    from jen.services import kea_api_config as api

    data = {}

    def stored(server_id):
        if server_id in data:
            return copy.deepcopy(data[server_id])
        if not valid:
            return None
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return {"at": now, "config_api": True, "consented_at": now}

    def store(server_id, value):
        data[server_id] = copy.deepcopy(value)
        return True

    monkeypatch.setattr(api, "stored_probe", stored)
    monkeypatch.setattr(api, "store_probe", store)
    return data
