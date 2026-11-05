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

    def record(self, server_id, service, cfg, sha256, summary, *, hash_kind, source="jen", file_sha256=None):
        if source == "pending" and any(r["source"] == "pending" for r in self._of(server_id, service)):
            return None  # (Q219 BI2 b) at most one pending row per (server, service) is the STORE's rule
        row = {
            "id": self._next,
            "server_id": server_id,
            "service": service,
            "sha256": sha256 or "",
            "hash_kind": hash_kind,
            "config": json.dumps(cfg, indent=2, sort_keys=True),
            "summary": summary,
            "source": source,
            "file_sha256": file_sha256 or None,
            "created_at": "2026-11-03 12:00:00",
        }
        self._next += 1
        self.rows.append(row)
        return row["id"]

    def _of(self, server_id, service):
        return [r for r in self.rows if r["server_id"] == server_id and r["service"] == service]

    def latest(self, server_id, service, exclude_kind=None):
        # (Q218 D3) the real one never returns a pending or a damaged row
        rows = [
            r
            for r in self._of(server_id, service)
            if r["hash_kind"] != exclude_kind and r["source"] not in ("pending", "damaged")
        ]
        return copy.deepcopy(rows[-1]) if rows else None

    def latest_of_kind(self, server_id, service, hash_kind):
        # (Q218 BH2 e) the real one never returns a pending or a damaged row: it is the record of a change in flight, not the last known state
        rows = [
            r
            for r in self._of(server_id, service)
            if r["hash_kind"] == hash_kind and r["source"] not in ("pending", "damaged")
        ]
        return copy.deepcopy(rows[-1]) if rows else None

    def list_revisions(self, server_id, service, limit=100):
        return [
            {k: v for k, v in r.items() if k not in ("config", "hash_kind", "file_sha256")}
            for r in reversed(self._of(server_id, service))
        ][:limit]

    def latest_rendering(self, server_id, service):
        # (Q219, Decided 14) the file Kea wrote after a change over the API: `raw`, source `rendering`, and nothing else
        rows = [r for r in self._of(server_id, service) if r["hash_kind"] == "raw" and r["source"] == "rendering"]
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
        "latest_rendering",
        "list_revisions",
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

    clock = HostClock(fake)
    clock.seen_sha = clock._sha()
    seen["clock"] = clock

    def read_proof(server, service="dhcp4", *, capture=True):
        cfg, sha = read(server, service, capture=capture)
        clock.reads += 1
        return cfg, sha, clock.times()

    # the daemon's own events move the host's clock: `config-set` and a restart are loads, `config-write` rewrites the file
    answer = fake._answer

    def answered(command, arguments):
        if command == "config-set":
            clock.observe()
        reply = answer(command, arguments)
        if reply.get("result") == 0:
            if command == "config-set":
                clock.loaded()
            elif command == "config-write":
                clock.observe()
        return reply

    fake._answer = answered
    restart = fake.restart
    set_running = fake.set_running

    def restarted():
        clock.observe()
        restart()
        clock.loaded()

    def hand_set(section):
        set_running(section)
        clock.loaded()

    fake.restart = restarted
    fake.set_running = hand_set
    monkeypatch.setattr(host, "read_config_versioned", read)
    monkeypatch.setattr(host, "read_config_proof", read_proof)
    seen["sha"] = sha_of
    return seen


# ── the host's own clock (Q219): the file's mtime, the daemon's last load, one `now` ─────────────────────────────────────────────

TIME_ZERO = 1_800_000_000


class HostClock:
    """What `jen-kea-helper config-loaded` answers for a Kea host whose daemon is the stateful fake: ONE clock (`t`, advanced a step at every event), the file's `mtime` (bumped whenever the file's content
    changes - a hand edit, Kea's own `config-write` - as a real filesystem does) and the moment the daemon last loaded a configuration (`config-set`, a restart, a reload). `times()` is the answer
    `kea_host.read_config_proof` returns; `has_op=False` is a host below build 22, `daemon=False` one whose control socket does not answer, `reload_field=False` an older daemon whose `status-get` carries
    no `reload`. Nothing here decides anything: it is the host as the proof sees it."""

    def __init__(self, fake):
        self.fake = fake
        self.t = TIME_ZERO
        self.started = self.t - 3600
        self.loaded_at = self.t - 50  # the daemon loaded its configuration long after the file was written ...
        self.mtime = self.t - 100  # ... which is why a file that agrees with it is one the daemon has loaded
        self.seen_sha = None
        self.has_op = True
        self.daemon = True
        self.reload_field = True
        self.socket_note = "the socket did not answer"
        self.reads = 0

    def tick(self, seconds=10):
        self.t += seconds
        return self.t

    def _sha(self):
        return sha_of({"Dhcp4": self.fake.file})

    def observe(self):
        """The file changed since the clock last looked: that is a write, and its mtime is now."""
        sha = self._sha()
        if self.seen_sha is None:
            self.seen_sha = sha
        elif sha != self.seen_sha:
            self.seen_sha = sha
            self.mtime = self.tick()

    def loaded(self):
        """The daemon committed a configuration now (`config-set`, a restart, `config-reload`)."""
        self.observe()
        self.loaded_at = self.tick()

    def edit(self, section):
        """A hand edit of the file: new content, mtime now (after the daemon's last load)."""
        self.fake.file = copy.deepcopy(section)
        self.observe()

    def reload(self):
        """`config-reload` / a restart: the daemon takes its file."""
        self.observe()
        self.fake.running = copy.deepcopy(self.fake.file)
        self.loaded_at = self.tick()

    def touch(self):
        """The file is rewritten with the same bytes: its mtime moves and its content does not."""
        self.mtime = self.tick()

    def times(self):
        if not self.has_op:
            return None
        self.observe()
        now = self.tick(1)
        daemon = None
        if self.daemon:
            daemon = {"pid": 4242, "uptime": now - self.started}
            if self.reload_field:
                daemon["reload"] = now - self.loaded_at
        note = (
            ""
            if daemon and "reload" in daemon
            else (self.socket_note if not self.daemon else "status-get carries no reload")
        )
        return {
            "mtime": self.mtime,
            "now": now,
            "size": 1,
            "daemon": daemon if daemon and "reload" in daemon else None,
            "socket_note": note,
        }


def sha_of(cfg):
    import hashlib

    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()


def proof_follows_the_read(monkeypatch, *, loaded=True):
    """`kea_host.read_config_proof` derived from whatever `read_config_versioned` answers AT THE TIME OF THE CALL (so a test's own stub of the read is the file the proof sees): the file was written
    before the daemon's last load (`loaded=True`) or after it. A test that is about the clock uses `host_reads_the_fakes_file`, which installs a `HostClock` instead."""
    from jen.services import kea_host as host

    def read_proof(server, service, *, capture=True):
        cfg, sha = host.read_config_versioned(server, service, capture=capture)
        if cfg is None:
            return None, None, None
        now = TIME_ZERO
        times = {
            "mtime": now - 100 if loaded else now - 5,
            "now": now,
            "size": 1,
            "daemon": {"pid": 1, "uptime": 3600, "reload": 50},
            "socket_note": "",
        }
        return cfg, sha, times

    monkeypatch.setattr(host, "read_config_proof", read_proof)


class ProofWorld:
    """Q219 - a Kea host the proof can be asked about: a stateful fake daemon whose `config-set` writes Kea's defaults out (`code` from a name, `space`, `csv-format`, `always-send`), a HostClock that
    answers `config-loaded` as the helper does, and the store. `loaded_file(section)` is a file the operator wrote BEFORE the daemon's last load; `hand_edit(section)` one written AFTER it. Nothing
    here knows what the proof decides: the worlds the tests build are the ones the product is for - a hand-authored file and a Jen-authored one."""

    CODES = {"routers": 3, "domain-name-servers": 6}

    def __init__(self, fake, server, store, monkeypatch):
        from jen.services import kea_host as host

        self.fake, self.server, self.store = fake, server, store
        server["ssh_host"] = "10.0.0.9"
        monkeypatch.setattr(host, "guard_kea_write", lambda *a, **k: "")
        self.seen = host_reads_the_fakes_file(monkeypatch, fake, store, server_id=server.get("id"))
        self.clock = self.seen["clock"]
        fake.expand = self.render_defaults
        host.read_config_versioned(server, "dhcp4")  # the baseline of the clean file

    @classmethod
    def render_defaults(cls, section):
        """What Kea writes out on `config-set`: the option's `code` from its name, `space`, `csv-format` and `always-send`."""
        out = copy.deepcopy(section)

        def options(entries):
            for o in entries or []:
                if isinstance(o, dict):
                    o.setdefault("code", cls.CODES.get(o.get("name"), 0))
                    o.setdefault("space", "dhcp4")
                    o.setdefault("csv-format", True)
                    o.setdefault("always-send", False)

        options(out.get("option-data"))
        for s in out.get("subnet4", []):
            options(s.get("option-data"))
        return out

    # the running configuration and the file, as the AD1 world has them ----------------------------------------------------------
    @staticmethod
    def ad1_running(fake_cfg):
        """Global `valid-lifetime` 7200 and a subnet that runs 3600 of its own (Jen's Subnets editor writes that value; so does a hand edit)."""
        out = copy.deepcopy(fake_cfg)
        out["valid-lifetime"] = 7200
        out["subnet4"][0]["valid-lifetime"] = 3600
        return out

    def start(self, running):
        """The daemon runs `running` (defaults written out) and the file IS that rendering, loaded."""
        self.fake.running = self.render_defaults(running)
        self.loaded_file(self.fake.running)

    def loaded_file(self, section):
        """A file the operator wrote BEFORE the daemon's last load: its mtime is older than the load."""
        self.fake.file = copy.deepcopy(section)
        self.clock.seen_sha = self.clock._sha()
        self.clock.mtime = self.clock.loaded_at - 100

    def hand_edit(self, section):
        """A file written AFTER the daemon's last load (and not loaded): the hand edit the proof exists to find."""
        self.clock.edit(section)

    def reload(self):
        self.clock.reload()

    def writes(self):
        return self.fake.commands.count("config-write")

    def sets(self):
        return self.fake.commands.count("config-set")


def without(section, *path):
    """A deep copy of `section` with the key at `path` removed (an integer is a list index)."""
    out = copy.deepcopy(section)
    node = out
    for step in path[:-1]:
        node = node[step]
    node.pop(path[-1])
    return out
