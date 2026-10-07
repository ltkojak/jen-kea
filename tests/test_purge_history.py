"""
tests/test_purge_history.py
───────────────────────────
v5.68.0-beta.19 (Q154) - retention needs no live Kea. The deletes of `lease_history` and `lease6_history` ran inside `take_lease_snapshot` after the
Kea database was opened, and `server_stats`' inside the stats snapshot: a Kea outage stopped Jen's own retention. `purge_history()` touches
`jen_db` alone, lists every history table in one place, and the snapshot job runs it after the Kea snapshots in a `finally`.
"""

import pytest

from jen.models.db import jen_db
from jen.models.user import set_global_setting
from jen.services import alerts

TABLES = {
    "lease_history": (
        "INSERT INTO lease_history (subnet_id, snapshot_time, active_leases) VALUES (991, DATE_SUB(NOW(), INTERVAL %s DAY), 1)",
        "subnet_id=991",
    ),
    "lease6_history": (
        "INSERT INTO lease6_history (subnet_id, snapshot_time, active_na) VALUES (991, DATE_SUB(NOW(), INTERVAL %s DAY), 1)",
        "subnet_id=991",
    ),
    "server_stats": (
        "INSERT INTO server_stats (server_id, snapshot_time, stats) VALUES (991, DATE_SUB(NOW(), INTERVAL %s DAY), '{}')",
        "server_id=991",
    ),
    "events": (
        "INSERT INTO events (ts, kind, detail) VALUES (DATE_SUB(NOW(), INTERVAL %s DAY), 'q154.test', 'x')",
        "kind='q154.test'",
    ),
    "alert_log": (
        "INSERT INTO alert_log (channel_type, alert_type, message, status, sent_at) VALUES ('t', 'q154_test', 'm', 'ok', DATE_SUB(NOW(), INTERVAL %s DAY))",
        "alert_type='q154_test'",
    ),
    "audit_log": (
        "INSERT INTO audit_log (username, action, entity, details, created_at) VALUES ('q154', 'Q154_TEST', 'x', 'x', DATE_SUB(NOW(), INTERVAL %s DAY))",
        "action='Q154_TEST'",
    ),
}


def _count(table):
    where = TABLES[table][1]
    with jen_db() as db, db.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS n FROM {table} WHERE {where}")  # nosec B608 - test constants
        return cur.fetchone()["n"]


@pytest.fixture
def old_and_new():
    """Per table: one row 400 days old (past every default retention) and one 1 day old."""
    with jen_db() as db, db.cursor() as cur:
        for table, (sql, where) in TABLES.items():
            cur.execute(f"DELETE FROM {table} WHERE {where}")  # nosec B608 - test constants
            cur.execute(sql, (400,))
            cur.execute(sql, (1,))
        db.commit()
    yield
    with jen_db() as db, db.cursor() as cur:
        for table, (_sql, where) in TABLES.items():
            cur.execute(f"DELETE FROM {table} WHERE {where}")  # nosec B608 - test constants
        db.commit()


class TestPurgeHistory:
    def test_every_table_loses_its_old_rows_and_keeps_the_recent_one(self, old_and_new):
        alerts.purge_history()
        assert {t: _count(t) for t in TABLES} == dict.fromkeys(TABLES, 1)

    def test_the_settings_are_honoured_per_table(self, old_and_new):
        set_global_setting("history_retention_days", "500")
        set_global_setting("events_retention_days", "500")
        set_global_setting("alert_log_retention_days", "500")
        set_global_setting("audit_retention_days", "500")
        alerts.purge_history()
        assert {t: _count(t) for t in TABLES} == dict.fromkeys(TABLES, 2), (
            "400 days is inside a 500-day retention: nothing is removed"
        )

    def test_audit_retention_zero_keeps_the_audit_log_forever(self, old_and_new):
        set_global_setting("audit_retention_days", "0")
        alerts.purge_history()
        assert _count("audit_log") == 2 and _count("lease_history") == 1

    def test_it_reports_what_it_removed(self, old_and_new):
        removed = alerts.purge_history()
        assert removed["lease_history"] == 1 and removed["lease6_history"] == 1 and removed["server_stats"] == 1
        assert removed["events"] == 1 and removed["audit_log"] == 1 and removed["alert_log"] >= 1

    def test_one_table_failing_does_not_stop_the_others(self, old_and_new, monkeypatch):
        real = alerts.__dict__["__jen_db_ctx"]
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:  # the first table's purge
                raise RuntimeError("lease_history is locked")
            return real()

        monkeypatch.setattr(alerts, "__jen_db_ctx", flaky)
        removed = alerts.purge_history()
        assert removed["lease_history"] is None
        assert _count("lease_history") == 2 and _count("lease6_history") == 1 and _count("events") == 1


class TestNeedsNoLiveKea:
    def test_a_raising_kea_database_does_not_stop_retention(self, old_and_new, monkeypatch):
        """The Kea snapshot opens kea_db first; with it raising, the job still removes Jen's own old rows."""

        def no_kea():
            raise ConnectionError("Kea's database is down")

        monkeypatch.setattr(alerts, "__kea_db_ctx", no_kea)
        alerts.run_snapshot_pass()
        assert {t: _count(t) for t in TABLES} == dict.fromkeys(TABLES, 1)

    def test_a_snapshot_that_raises_outright_still_purges(self, old_and_new, monkeypatch):
        def boom():
            raise RuntimeError("the snapshot itself blew up")

        monkeypatch.setattr(alerts, "take_lease_snapshot", boom)
        with pytest.raises(RuntimeError):
            alerts.run_snapshot_pass()
        assert _count("lease_history") == 1, "purge_history ran in the finally"

    def test_the_snapshot_functions_no_longer_delete_anything(self):
        import inspect

        for fn in (alerts.take_lease_snapshot, alerts.take_server_stats_snapshot, alerts.take_lease6_snapshot):
            assert "DELETE FROM" not in inspect.getsource(fn), fn.__name__

    def test_the_daily_cleanup_job_calls_the_same_function(self):
        import inspect

        from jen.services import scheduler

        assert "purge_history" in inspect.getsource(scheduler._run_audit_cleanup)
