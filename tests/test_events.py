"""
tests/test_events.py
─────────────────────
v5.42.0 (Q43) — the event stream. `TestDiffLeases` is pure (no DB —
`python -m pytest --noconftest tests/test_events.py -k DiffLeases`);
everything else needs the real `events` table (migration 27).
"""

import pytest

from jen.services import events
from jen.services.alerts import diff_leases
from jen.services.events import KINDS, emit, subscribe, unsubscribe


def _row(mac, hostname="", subnet_id=1, is_reserved=False):
    return {"mac": mac, "hostname": hostname, "subnet_id": subnet_id, "is_reserved": is_reserved}


class TestDiffLeases:
    def test_new_ip_with_no_prior_state(self):
        events = diff_leases({}, {"10.0.0.5": _row("aa:bb:cc:dd:ee:01")})
        assert len(events) == 1
        assert events[0]["kind"] == "lease.new"
        assert events[0]["ip"] == "10.0.0.5"
        assert events[0]["mac"] == "aa:bb:cc:dd:ee:01"

    def test_renewal_is_not_an_event(self):
        row = _row("aa:bb:cc:dd:ee:01")
        events = diff_leases({"10.0.0.5": row}, {"10.0.0.5": row})
        assert events == []

    def test_expired_when_no_other_ip_of_the_same_mac_appears(self):
        prev = {"10.0.0.5": _row("aa:bb:cc:dd:ee:01")}
        events = diff_leases(prev, {})
        assert len(events) == 1
        assert events[0]["kind"] == "lease.expired"
        assert events[0]["ip"] == "10.0.0.5"

    def test_ip_change_pairs_the_gone_and_new_ip_of_the_same_mac(self):
        prev = {"10.0.0.5": _row("aa:bb:cc:dd:ee:01")}
        cur = {"10.0.0.9": _row("aa:bb:cc:dd:ee:01")}
        events = diff_leases(prev, cur)
        assert len(events) == 1
        assert events[0]["kind"] == "lease.ip_changed"
        assert events[0]["ip"] == "10.0.0.9"
        assert events[0]["old_ip"] == "10.0.0.5"

    def test_different_macs_on_gone_and_new_ip_is_expired_plus_new_not_ip_changed(self):
        prev = {"10.0.0.5": _row("aa:bb:cc:dd:ee:01")}
        cur = {"10.0.0.9": _row("aa:bb:cc:dd:ee:02")}
        events = diff_leases(prev, cur)
        kinds = {e["kind"] for e in events}
        assert kinds == {"lease.expired", "lease.new"}

    def test_hostname_change_on_the_same_ip(self):
        prev = {"10.0.0.5": _row("aa:bb:cc:dd:ee:01", hostname="old-name")}
        cur = {"10.0.0.5": _row("aa:bb:cc:dd:ee:01", hostname="new-name")}
        events = diff_leases(prev, cur)
        assert len(events) == 1
        assert events[0]["kind"] == "lease.hostname_changed"
        assert events[0]["hostname"] == "new-name"
        assert events[0]["old_hostname"] == "old-name"

    def test_hostname_becoming_empty_is_not_a_change(self):
        """A client that stops sending option 12 isn't 'renamed' to
        nothing — losing the hostname shouldn't read as an event."""
        prev = {"10.0.0.5": _row("aa:bb:cc:dd:ee:01", hostname="old-name")}
        cur = {"10.0.0.5": _row("aa:bb:cc:dd:ee:01", hostname="")}
        assert diff_leases(prev, cur) == []

    def test_multiple_leases_of_the_same_mac_pair_independently(self):
        prev = {
            "10.0.0.5": _row("aa:bb:cc:dd:ee:01"),
            "10.0.0.6": _row("aa:bb:cc:dd:ee:01"),
        }
        cur = {
            "10.0.0.7": _row("aa:bb:cc:dd:ee:01"),
            "10.0.0.8": _row("aa:bb:cc:dd:ee:01"),
        }
        events = diff_leases(prev, cur)
        assert len(events) == 2
        assert {e["kind"] for e in events} == {"lease.ip_changed"}
        assert {e["old_ip"] for e in events} == {"10.0.0.5", "10.0.0.6"}
        assert {e["ip"] for e in events} == {"10.0.0.7", "10.0.0.8"}

    def test_deterministic_order_for_the_same_input(self):
        prev = {"10.0.0.5": _row("aa:bb:cc:dd:ee:01"), "10.0.0.6": _row("aa:bb:cc:dd:ee:02")}
        cur = {"10.0.0.9": _row("aa:bb:cc:dd:ee:03")}
        first = diff_leases(prev, cur)
        second = diff_leases(prev, cur)
        assert first == second

    def test_is_reserved_and_subnet_id_carried_through(self):
        prev = {}
        cur = {"10.0.0.5": _row("aa:bb:cc:dd:ee:01", subnet_id=7, is_reserved=True)}
        events = diff_leases(prev, cur)
        assert events[0]["subnet_id"] == 7
        assert events[0]["is_reserved"] is True


class TestEmit:
    def test_writes_a_row(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM events")
        db.commit()
        ev = emit("lease.new", mac="aa:bb:cc:dd:ee:01", ip="10.0.0.5", subnet_id=1, hostname="host1", detail="x")
        assert ev["id"] is not None
        with db.cursor() as cur:
            cur.execute("SELECT * FROM events WHERE id=%s", (ev["id"],))
            row = cur.fetchone()
        assert row["kind"] == "lease.new"
        assert row["mac"] == "aa:bb:cc:dd:ee:01"
        assert row["ip"] == "10.0.0.5"
        assert row["subnet_id"] == 1
        assert row["hostname"] == "host1"
        assert row["detail"] == "x"

    def test_null_fields_stay_null(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM events")
        db.commit()
        ev = emit("config.applied", server="kea-a", detail="subnet added")
        with db.cursor() as cur:
            cur.execute("SELECT * FROM events WHERE id=%s", (ev["id"],))
            row = cur.fetchone()
        assert row["mac"] is None
        assert row["ip"] is None
        assert row["subnet_id"] is None
        assert row["server"] == "kea-a"

    def test_every_kind_is_a_valid_column_value(self, db):
        """KINDS is the pinned vocabulary — every one of them must
        actually insert (VARCHAR(40) is wide enough, no other
        constraint rejects it)."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM events")
        db.commit()
        for kind in KINDS:
            ev = emit(kind)
            assert ev["id"] is not None

    def test_subscriber_is_called_with_the_event(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM events")
        db.commit()
        seen = []
        subscribe("lease.new", seen.append)
        try:
            emit("lease.new", mac="aa:bb:cc:dd:ee:01", ip="10.0.0.5")
            emit("lease.expired", mac="aa:bb:cc:dd:ee:01", ip="10.0.0.5")
        finally:
            unsubscribe(seen.append)
        assert len(seen) == 1
        assert seen[0]["kind"] == "lease.new"

    def test_wildcard_subscriber_sees_every_kind(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM events")
        db.commit()
        seen = []
        subscribe("*", seen.append)
        try:
            emit("lease.new")
            emit("reservation.added")
        finally:
            unsubscribe(seen.append)
        assert [e["kind"] for e in seen] == ["lease.new", "reservation.added"]

    def test_raising_subscriber_does_not_break_the_emitter_or_other_subscribers(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM events")
        db.commit()

        def bad(_event):
            raise RuntimeError("boom")

        seen = []
        subscribe("lease.new", bad)
        subscribe("lease.new", seen.append)
        try:
            ev = emit("lease.new", mac="aa:bb:cc:dd:ee:01")
        finally:
            unsubscribe(bad)
            unsubscribe(seen.append)
        assert ev["id"] is not None
        assert len(seen) == 1

    def test_unsubscribe_removes_only_that_callable(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM events")
        db.commit()
        seen_a, seen_b = [], []
        subscribe("lease.new", seen_a.append)
        subscribe("lease.new", seen_b.append)
        unsubscribe(seen_a.append)
        try:
            emit("lease.new")
        finally:
            unsubscribe(seen_b.append)
        assert seen_a == []
        assert len(seen_b) == 1


class TestEmitKindValidation:
    """v5.57.0 (Q73) — emit() is now re-exported to plugins
    (jen.plugin_api), which had no way to write to the stream before.
    A plugin kind must be plugin.<plugin_id>.<name>; anything else is
    refused before emit() ever touches the DB."""

    def test_a_plugin_kind_is_accepted(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM events")
        db.commit()
        ev = emit("plugin.fake.thing")
        assert ev is not None and ev["id"] is not None

    @pytest.mark.parametrize(
        "kind",
        [
            "bad kind",
            "plugin.fake",  # missing the <name> segment
            "plugin.fake.",  # empty <name>
            "Plugin.fake.thing",  # not lowercase
            "plugin.fa ke.thing",  # space in the plugin id
            "plugin..thing",  # empty plugin id
            "",
            None,
        ],
    )
    def test_a_bad_kind_is_refused_without_touching_the_db(self, kind):
        # No `db` fixture on purpose — the refusal must happen before
        # emit() ever opens a connection.
        assert emit(kind) is None


class TestBoundedDispatcher:
    """v5.49.0-beta.2 (audit I) - subscribers run on one shared worker when
    it is running; inline when it is not. DB-free: the row write is stubbed."""

    @pytest.fixture(autouse=True)
    def _no_db(self, monkeypatch):
        import jen.models.db as dbmod

        def boom():
            raise RuntimeError("no db in this test")

        monkeypatch.setattr(dbmod, "jen_db", boom)
        yield
        events.stop_dispatcher()
        with events._lock:
            events._SUBSCRIBERS.clear()

    def test_inline_when_the_worker_is_not_running(self):
        seen = []
        subscribe("*", seen.append)
        emit("lease.new", mac="aa:bb:cc:dd:ee:01")
        assert len(seen) == 1  # delivered before emit() returned

    def test_queued_when_the_worker_is_running_and_delivered_on_another_thread(self):
        import threading

        got = threading.Event()
        threads = []

        def sub(event):
            threads.append(threading.current_thread().name)
            got.set()

        subscribe("*", sub)
        assert events.start_dispatcher() is True
        assert events.start_dispatcher() is False  # idempotent
        emit("lease.new")
        assert got.wait(3)
        assert threads == ["jen-events"]

    def test_a_slow_subscriber_does_not_block_the_emitter(self):
        import threading
        import time

        release = threading.Event()
        subscribe("*", lambda e: release.wait(5))
        events.start_dispatcher()
        t0 = time.monotonic()
        for _ in range(5):
            emit("lease.new")
        assert time.monotonic() - t0 < 1.0
        release.set()

    def test_full_queue_drops_without_raising(self, monkeypatch):
        import queue
        import threading

        # a "running" dispatcher that never drains, and a tiny queue
        monkeypatch.setattr(events, "_queue", queue.Queue(maxsize=2))
        monkeypatch.setattr(events, "_dispatcher", threading.Thread(target=lambda: threading.Event().wait(2)))
        events._dispatcher.start()
        monkeypatch.setattr(events, "_last_drop_log", 0.0)
        for _ in range(5):
            emit("lease.new")  # 3 of these overflow; none may raise
        assert events._queue.qsize() == 2

    def test_a_raising_subscriber_logs_and_the_next_one_still_runs(self):
        import threading

        done = threading.Event()

        def bad(_e):
            raise RuntimeError("boom")

        subscribe("*", bad)
        subscribe("*", lambda e: done.set())
        events.start_dispatcher()
        emit("lease.new")
        assert done.wait(3)


class TestDispatcherStopRace:
    """v5.49.0-beta.4 (Q55-G) - stop_dispatcher() must not forget a thread it
    could not stop, or start_dispatcher() launches a second one."""

    def test_full_queue_stop_then_start_does_not_create_a_second_thread(self, monkeypatch):
        import queue
        import threading

        release = threading.Event()
        wedged = threading.Thread(target=lambda: release.wait(5), name="wedged-dispatcher")
        wedged.start()
        full = queue.Queue(maxsize=1)
        full.put("filler")
        monkeypatch.setattr(events, "_queue", full)
        monkeypatch.setattr(events, "_dispatcher", wedged)
        try:
            events.stop_dispatcher()  # STOP cannot be queued (full)
            assert events._dispatcher is wedged  # still referenced
            assert events.start_dispatcher() is False  # so no second thread
            assert [t for t in threading.enumerate() if t.name == "jen-events"] == []
        finally:
            release.set()
            wedged.join(5)
