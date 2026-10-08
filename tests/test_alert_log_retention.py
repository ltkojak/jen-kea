"""
tests/test_alert_log_retention.py
─────────────────────────────────
v5.68.0-beta.17 (Q152, item c) - `alert_log` was the one history table nothing pruned. Rows older than `alert_log_retention_days`
(default 180) are removed by the same job as the other history tables, the Alert Log page says how long a row is kept, and the
Prometheus counter built from the table never goes down because of it (what is removed is counted into a stored total first).

v5.68.0-beta.20 (Q155, items 2 and 9) - the pass SERIALISES FIRST. It used to count the expiring rows and only then take `FOR UPDATE` on the
totals row, so two overlapping passes (the alert thread every `snapshot_interval_minutes` and the daily 00:05 cleanup) both counted the same rows
and `jen_alerts_sent_total` - a counter that by design never decreases - was permanently high; a `FOR UPDATE` on a row that does not exist yet
(the first purge) serialised nothing. This file held only this docstring: nothing pinned the pruned totals, their monotonicity, the first purge or
concurrency. Needs the MariaDB the suite runs against (CI).
"""

import json
import threading
import time

import pytest

from jen.models.db import jen_db
from jen.models.user import get_global_setting, set_global_setting
from jen.services import alerts

KEY = alerts.ALERT_LOG_PRUNED_KEY
TYPE = "q155_purge"
DAYS = 30


def _seed(n, status="ok", age=90):
    with jen_db() as db, db.cursor() as cur:
        for _ in range(n):
            cur.execute(
                "INSERT INTO alert_log (channel_type, alert_type, message, status, sent_at) "
                "VALUES ('t', %s, 'm', %s, DATE_SUB(NOW(), INTERVAL %s DAY))",
                (TYPE, status, age),
            )
        db.commit()


def _rows():
    with jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM alert_log WHERE alert_type=%s", (TYPE,))
        return cur.fetchone()["n"]


def _stored():
    with jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT setting_value FROM settings WHERE setting_key=%s", (KEY,))
        row = cur.fetchone()
        return row["setting_value"] if row else None


def _exported(status="ok"):
    """What Prometheus' jen_alerts_sent_total reports for this alert type: the rows still there plus those already pruned."""
    with jen_db() as db, db.cursor() as cur:
        return alerts.alert_sent_totals(cur).get((TYPE, status), 0)


@pytest.fixture
def retention():
    """30 days' retention, no old row of anyone's left, the pruned totals row absent (the FIRST purge) - and everything put back after."""
    previous = get_global_setting("alert_log_retention_days")
    set_global_setting("alert_log_retention_days", str(DAYS))
    with jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM alert_log WHERE sent_at < DATE_SUB(NOW(), INTERVAL %s DAY)", (DAYS,))
        cur.execute("DELETE FROM alert_log WHERE alert_type=%s", (TYPE,))
        cur.execute("DELETE FROM settings WHERE setting_key=%s", (KEY,))
        db.commit()
    yield
    set_global_setting("alert_log_retention_days", previous or "180")
    with jen_db() as db, db.cursor() as cur:
        cur.execute("DELETE FROM alert_log WHERE alert_type=%s", (TYPE,))
        cur.execute("DELETE FROM settings WHERE setting_key=%s", (KEY,))
        db.commit()


class TestOnePurge:
    def test_it_counts_what_it_removes_into_the_totals_and_keeps_recent_rows(self, retention):
        _seed(5, "ok", age=90)
        _seed(2, "failed", age=90)
        _seed(3, "ok", age=1)
        removed = alerts._purge_old_alert_log()
        assert removed == 7
        totals = json.loads(_stored())
        assert totals[f"{TYPE}|ok"] == 5 and totals[f"{TYPE}|failed"] == 2
        assert _rows() == 3, "the recent rows stay"

    def test_the_exported_total_is_the_same_before_and_after(self, retention):
        """The Prometheus counter never goes down because retention removed rows."""
        _seed(6, "ok", age=90)
        _seed(2, "ok", age=1)
        before = _exported()
        alerts._purge_old_alert_log()
        assert before == 8 and _exported() == before

    def test_a_second_purge_changes_nothing(self, retention):
        _seed(4, "ok", age=90)
        assert alerts._purge_old_alert_log() == 4
        stored = _stored()
        assert alerts._purge_old_alert_log() == 0
        assert _stored() == stored and json.loads(stored)[f"{TYPE}|ok"] == 4

    def test_the_first_purge_with_no_totals_row_creates_it(self, retention):
        assert _stored() is None
        _seed(3, "ok", age=90)
        assert alerts._purge_old_alert_log() == 3
        assert json.loads(_stored())[f"{TYPE}|ok"] == 3

    def test_a_purge_with_nothing_to_remove_leaves_an_empty_totals_object(self, retention):
        assert alerts._purge_old_alert_log() == 0
        assert json.loads(_stored()) == {}

    def test_malformed_stored_totals_fail_safely_nothing_overwritten_and_rows_kept(self, retention):
        _seed(4, "ok", age=90)
        with jen_db() as db, db.cursor() as cur:
            cur.execute("INSERT INTO settings (setting_key, setting_value) VALUES (%s, %s)", (KEY, "{not json"))
            db.commit()
        assert alerts._purge_old_alert_log() is None, "a failed purge is None, never 'nothing to remove'"
        assert _stored() == "{not json", "the damaged value is not overwritten with a guess"
        assert _rows() == 4, "the rows stay"
        with jen_db() as db, db.cursor() as cur:
            cur.execute("UPDATE settings SET setting_value='[1, 2]' WHERE setting_key=%s", (KEY,))
            db.commit()
        assert alerts._purge_old_alert_log() is None and _stored() == "[1, 2]" and _rows() == 4

    def test_a_delete_that_removes_a_different_number_than_was_counted_rolls_everything_back(
        self, retention, monkeypatch
    ):
        """The rowcount is asserted: if it is not what was counted into the totals, the totals are not saved and the rows are not deleted."""
        _seed(4, "ok", age=90)
        real = alerts.__dict__["__jen_db_ctx"]

        class LyingCursor:
            def __init__(self, cur):
                self._cur = cur

            def __getattr__(self, name):
                return getattr(self._cur, name)

            def __enter__(self):
                self._cur.__enter__()
                return self

            def __exit__(self, *a):
                return self._cur.__exit__(*a)

            def execute(self, sql, args=None):
                result = self._cur.execute(sql, args)
                self.executed_delete = str(sql).startswith("DELETE FROM alert_log")
                return result

            @property
            def rowcount(self):
                return self._cur.rowcount + (1 if getattr(self, "executed_delete", False) else 0)

        class LyingConnection:
            def __init__(self, conn):
                self._conn = conn

            def __getattr__(self, name):
                return getattr(self._conn, name)

            def cursor(self, *a, **k):
                return LyingCursor(self._conn.cursor(*a, **k))

        import contextlib

        @contextlib.contextmanager
        def lying():
            with real() as conn:
                yield LyingConnection(conn)

        monkeypatch.setitem(alerts.__dict__, "__jen_db_ctx", lying)
        assert alerts._purge_old_alert_log() is None
        monkeypatch.undo()
        assert _rows() == 4, "the DELETE was rolled back"
        assert json.loads(_stored() or "{}").get(f"{TYPE}|ok", 0) == 0, "the totals were not saved"

    def test_purge_history_reports_a_failed_alert_log_purge_as_none_not_zero(self, retention, monkeypatch):
        """Every other table records None when its purge raised; alert_log used to record 0, so a failed purge read as 'nothing to remove'."""
        monkeypatch.setattr(alerts, "_purge_old_alert_log", lambda: None)
        assert alerts.purge_history()["alert_log"] is None


class TestTwoPassesCountOnce:
    def test_a_pass_that_waits_for_the_totals_lock_counts_after_the_first_has_finished(self, retention):
        """Deterministic: this connection holds the totals row, a purge starts and must WAIT on it BEFORE counting. While it waits the 'first
        purge' (done here) deletes the rows and adds them to the totals. The waiting pass then finds nothing to count: the total is 5, not 10.
        With the count taken before the lock (beta.19) the waiting pass had already counted the same five rows."""
        _seed(5, "ok", age=90)
        alerts._purge_old_alert_log()  # creates the totals row (and, being a purge, empties what is expiring)
        _seed(5, "ok", age=90)
        with jen_db() as holder, holder.cursor() as hcur:
            hcur.execute("SELECT setting_value FROM settings WHERE setting_key=%s FOR UPDATE", (KEY,))
            hcur.fetchone()
            results = []
            thread = threading.Thread(target=lambda: results.append(alerts._purge_old_alert_log()))
            thread.start()
            time.sleep(1.0)
            assert thread.is_alive(), "the purge did not wait for the totals row before counting"
            # what a first, concurrent purge does while this one waits
            hcur.execute(
                "DELETE FROM alert_log WHERE alert_type=%s AND sent_at < DATE_SUB(NOW(), INTERVAL %s DAY)", (TYPE, DAYS)
            )
            hcur.execute("SELECT setting_value FROM settings WHERE setting_key=%s", (KEY,))
            totals = json.loads(hcur.fetchone()["setting_value"])
            totals[f"{TYPE}|ok"] = int(totals.get(f"{TYPE}|ok", 0)) + 5
            hcur.execute("UPDATE settings SET setting_value=%s WHERE setting_key=%s", (json.dumps(totals), KEY))
            holder.commit()
        thread.join(30)
        assert results == [0], "the waiting pass counted rows the first had already removed"
        assert json.loads(_stored())[f"{TYPE}|ok"] == 10, (
            "5 from the setup purge + 5 from the 'first' pass, counted once each"
        )

    @pytest.mark.parametrize("round_", range(6))
    def test_two_concurrent_real_purges_count_every_row_exactly_once(self, retention, round_):
        n = 20
        _seed(n, "ok", age=90)
        # the totals row must exist before the race in one variant and not in the other
        if round_ % 2 == 0:
            alerts._purge_old_alert_log()
            _seed(n, "ok", age=90)
        barrier = threading.Barrier(2)
        results = []

        def run():
            barrier.wait(10)
            results.append(alerts._purge_old_alert_log())

        threads = [threading.Thread(target=run) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        assert sorted(results) == [0, n], results
        stored = json.loads(_stored())
        expected = n if round_ % 2 else 2 * n
        assert stored[f"{TYPE}|ok"] == expected, (
            f"the pruned total is {stored[f'{TYPE}|ok']}, expected {expected}: a row was counted twice"
        )
        assert _rows() == 0 and _exported() == expected
