"""
tests/_kea_api_world.py
───────────────────────
Q212 - what the tests of `jen/services/kea_api_config.py` and of the change set's api targets share: an in-memory `config_revisions` (no database) and the fixtures that install it.
"""

import copy
import json

from jen.services import kea_api_config as _real_api

REAL_BOUND = (
    _real_api._bound
)  # the real `bound` hash, kept before `install_probes` stands one endpoint in for every server (Q218 BH3 d)


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
        # (Q218 BH2 e) the real one never returns a pending or a damaged row: it is the record of a change in flight, not the last known state
        rows = [
            r
            for r in self._of(server_id, service)
            if r["hash_kind"] == hash_kind and r["source"] not in ("pending", "damaged")
        ]
        return copy.deepcopy(rows[-1]) if rows else None

    def by_digest(self, server_id, service, sha256, hash_kind="kea"):
        if not sha256:
            return None
        rows = [
            r
            for r in self._of(server_id, service)
            if r["hash_kind"] == hash_kind and r["sha256"] == sha256 and r["source"] not in ("pending", "damaged")
        ]
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

    def mark_damaged(self, rev_id):
        for r in self.rows:
            if r["id"] == rev_id and r["source"] == "pending":
                r["source"] = "damaged"
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
    for name in (
        "record",
        "latest",
        "latest_of_kind",
        "by_digest",
        "pending",
        "finish",
        "discard",
        "discard_pending",
        "mark_damaged",
    ):
        monkeypatch.setattr(f"jen.services.config_revisions.{name}", getattr(s, name))
    return s


def install_probes(monkeypatch, *, valid=True):
    """Patch the stored probe (`kea_api_config.stored_probe` / `store_probe`) with a dict. With `valid` every server id reads as a server whose probe passed, was consented to and is fresh - the
    state a server is in after its operator has used the card - until a test stores something else for it."""
    from datetime import datetime, timezone

    from jen.services import kea_api_config as api

    data = {}
    # (Q218 BH3 d) a stored result that names no endpoint is checked again, so the fake stands one endpoint in for every server (`bound` is a hash of the address, and a test that is not about the re-point
    # has no business computing it): a record a test stores WITHOUT the key reads as bound to that endpoint, a record with `"bound": ""` is the no-endpoint shape, and a test about the re-point itself
    # puts `api._bound` back (`monkeypatch.setattr(api, "_bound", real_bound)`).
    monkeypatch.setattr(api, "_bound", lambda server: "t")

    def stored(server_id):
        if server_id in data:
            out = copy.deepcopy(data[server_id])
            out.setdefault("bound", "t")
            return out
        if not valid:
            return None
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return {"at": now, "config_api": True, "consented_at": now, "bound": "t"}

    def store(server_id, value):
        data[server_id] = copy.deepcopy(value)
        return True

    monkeypatch.setattr(api, "stored_probe", stored)
    monkeypatch.setattr(api, "store_probe", store)
    return data


def host_reads_the_fakes_file(monkeypatch, fake, store=None, server_id=None):
    """Q218 - the Kea HOST's file for a test whose daemon is `fake` (tests/e2e/_fake_kea_server.py::StatefulKeaServer): `kea_host.read_config_versioned` answers the fake's own held FILE (`fake.file`,
    which `config-write` overwrites with what runs, as Kea does), never a canned value, so "the operator's edit is gone" is observed and not inferred. With a `store`, a CAPTURING read records what the
    real one records - a `baseline` for a file never seen, an `external` row for content the store has not seen (the sha is the content's own). Returns `{"reads": [capture flags], "sha": fn}`."""
    import hashlib

    from jen.services import kea_host as host

    seen = {"reads": []}

    def sha_of(cfg):
        return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()

    def read(server, service="dhcp4", *, errors=None, timeout=None, helper_only=False, capture=True):
        cfg = {"Dhcp4": copy.deepcopy(fake.file)}
        sha = sha_of(cfg)
        seen["reads"].append(capture)
        if capture and store is not None:
            sid = server_id if server_id is not None else server.get("id")
            raws = [r for r in store.rows if r["server_id"] == sid and r["hash_kind"] == "raw"]
            if not raws:
                store.record(sid, service, cfg, sha, "initial baseline", hash_kind="raw", source="baseline")
            elif not any(r["sha256"] == sha for r in raws):
                store.record(sid, service, cfg, sha, "changed outside Jen", hash_kind="raw", source="external")
        return cfg, sha

    monkeypatch.setattr(host, "read_config_versioned", read)
    seen["sha"] = sha_of
    return seen
