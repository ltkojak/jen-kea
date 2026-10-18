"""
tests/test_incident_store_locking.py
────────────────────────────────────
v5.69.0-beta.19 (Q188, AD5) - the incident note is ONE settings row read-modified-written by several workers (a request recording an incident, another acknowledging one, a subnet edit's
`record_outcome`). `get_global_setting` then `set_global_setting` let two of them each read the old value and the second write erase the first's change. `kea_changeset._with_attention` runs
the whole read-modify-write as one locked transaction (`user.update_global_setting`: `INSERT IGNORE`, `SELECT ... FOR UPDATE`, one UPDATE, commit).

These tests run against the REAL settings table (MariaDB / MySQL, like the rest of the database tests): two threads, two pooled connections, a barrier so the transactions overlap.
"""

import threading

import pytest

from jen.models import user as user_mod
from jen.models.db import jen_db
from jen.services import kea_changeset as cs


@pytest.fixture(autouse=True)
def clean_note(db):
    def wipe():
        with jen_db() as c, c.cursor() as cur:
            cur.execute("DELETE FROM settings WHERE setting_key = %s", (cs.ATTENTION_KEY,))
        user_mod._invalidate_settings_cache()

    wipe()
    yield
    wipe()


def _stored():
    with jen_db() as c, c.cursor() as cur:
        cur.execute("SELECT setting_value FROM settings WHERE setting_key = %s", (cs.ATTENTION_KEY,))
        row = cur.fetchone()
    raw = (row["setting_value"] if isinstance(row, dict) else row[0]) if row else ""
    return cs._incidents_of(raw)


def _rows():
    with jen_db() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM settings WHERE setting_key = %s", (cs.ATTENTION_KEY,))
        row = cur.fetchone()
    return row["n"] if isinstance(row, dict) else row[0]


def _together(*jobs):
    """Run each job in its own thread, released together by a barrier; re-raise the first failure."""
    barrier = threading.Barrier(len(jobs))
    errors = []

    def run(job):
        try:
            barrier.wait(10)
            job()
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=run, args=(j,)) for j in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not errors, errors


@pytest.mark.parametrize("round_", range(8))
def test_two_workers_recording_two_servers_both_land(round_):
    _together(
        lambda: cs.record_attention(1, "dhcp4", "x", "aborted", server_name="kea-a"),
        lambda: cs.record_attention(2, "dhcp4", "y", "aborted", server_name="standby"),
    )
    assert sorted(i["server_id"] for i in _stored()) == [1, 2]


@pytest.mark.parametrize("round_", range(8))
def test_recording_concurrent_with_an_acknowledgement_keeps_the_new_and_drops_the_acknowledged(round_):
    cs.record_attention(9, "dhcp4", "old", "aborted")
    _together(
        lambda: cs.record_attention(1, "dhcp4", "new", "probe-pending"),
        lambda: cs.acknowledge_recovery(9, "dhcp4", "aborted"),
    )
    assert [i["server_id"] for i in _stored()] == [1]


@pytest.mark.parametrize("round_", range(8))
def test_two_first_writers_make_one_row_with_two_incidents(round_):
    assert _rows() == 0
    _together(
        lambda: cs.record_attention(1, "dhcp4", "x", "aborted"),
        lambda: cs.record_attention(2, "dhcp6", "y", "restart-failed"),
    )
    assert _rows() == 1
    assert len(_stored()) == 2


def test_an_outcome_recorded_while_an_incident_is_recorded_loses_neither():
    result = cs.ChangeSetResult("rolled_back", "x", [], needs_hands=["kea-a"], needs_hands_ids=[1])
    _together(
        lambda: cs.record_outcome(result, "dhcp4", "a pool edit"),
        lambda: cs.record_attention(2, "dhcp4", "y", "tls-not-restored"),
    )
    assert sorted(i.get("status") for i in _stored()) == ["rolled_back", "tls-not-restored"]


def test_a_commit_that_fails_is_reported_false_and_leaves_the_stored_list_unchanged(monkeypatch):
    cs.record_attention(1, "dhcp4", "kept", "aborted")
    real = jen_db

    class FailingCommit:
        """A real pooled connection whose COMMIT fails (the lock was taken, the UPDATE ran, the commit did not)."""

        def __init__(self, conn):
            self._conn = conn

        def cursor(self, *a, **k):
            return self._conn.cursor(*a, **k)

        def commit(self):
            raise RuntimeError("commit failed")

        def rollback(self):
            return self._conn.rollback()

        def close(self):
            return self._conn.close()

    import contextlib

    @contextlib.contextmanager
    def failing():
        with real() as conn:
            yield FailingCommit(conn)

    monkeypatch.setattr("jen.models.db.jen_db", failing)
    assert cs.record_attention(2, "dhcp4", "lost", "probe-pending") is False
    monkeypatch.setattr("jen.models.db.jen_db", real)
    assert [i["server_id"] for i in _stored()] == [1], "the failed transaction changed nothing"
    assert cs.resolve_attention(1, "dhcp4") == 1, "and the note is still usable afterwards"


@pytest.mark.parametrize("round_", range(12))
def test_two_workers_on_a_row_that_already_exists_neither_deadlocks_nor_loses_its_update(round_):
    """Second pass (Q188): `INSERT IGNORE` of an EXISTING row takes a shared lock on the duplicate; two transactions holding it and then asking for `FOR UPDATE` deadlock and one update is lost.
    The row is made in its own autocommitted statement now, so only the exclusive lock is ever asked for."""
    cs.record_attention(9, "dhcp4", "already there", "aborted")
    assert _rows() == 1
    _together(
        lambda: cs.record_attention(1, "dhcp4", "x", "probe-pending"),
        lambda: cs.record_attention(2, "dhcp4", "y", "restart-failed"),
        lambda: cs.record_attention(3, "dhcp6", "z", "tls-not-restored"),
    )
    assert sorted(i["server_id"] for i in _stored()) == [1, 2, 3, 9]


def test_a_deadlock_victim_retries_instead_of_losing_the_update(monkeypatch):
    """A 1213 (deadlock victim) or 1205 (lock wait timeout) rolled everything back, so the same read-modify-write is tried again; any other error is reported False at once."""
    real = jen_db
    state = {"raised": 0}

    class Boom(Exception):
        pass

    def flaky():
        if state["raised"] == 0:
            state["raised"] += 1
            raise Boom(1213, "Deadlock found when trying to get lock; try restarting transaction")
        return real()

    monkeypatch.setattr("jen.models.db.jen_db", flaky)
    assert cs.record_attention(1, "dhcp4", "x", "aborted") is True
    assert state["raised"] == 1 and [i["server_id"] for i in _stored()] == [1]

    def broken():
        raise Boom(1045, "Access denied")

    monkeypatch.setattr("jen.models.db.jen_db", broken)
    assert cs.record_attention(2, "dhcp4", "y", "aborted") is False
