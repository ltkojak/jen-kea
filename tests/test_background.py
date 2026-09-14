"""
tests/test_background.py
────────────────────────
v5.5.0 — the backup scheduler and the alert-monitoring loop used to be
started by create_app(). They aren't anymore: the app factory only
builds the app, and the entrypoint that owns the process
(jen/wsgi.py under gunicorn, or run.py's fallback) starts the workers.

This guards the property that matters for the test suite and for
gunicorn: importing/creating the app starts nothing.
"""

from unittest.mock import patch

import pytest

from jen.services import background


class TestFactoryStartsNothing:
    """The `app` fixture (conftest) has already run create_app() for the
    session. If the factory started background work, it would show in
    the module-level state below."""

    def test_scheduler_not_started_by_the_factory(self, app):
        from jen.services import scheduler

        assert scheduler._scheduler is None or not getattr(scheduler._scheduler, "running", False)

    def test_background_workers_not_started_by_the_factory(self, app):
        assert background._started is False


class TestStartBackgroundWorkers:
    def setup_method(self):
        background._started = False

    def teardown_method(self):
        background._started = False

    def test_starts_scheduler_and_alert_thread_once(self):
        calls = {"sched": 0, "thread": 0}

        def fake_thread(*a, **kw):
            if kw.get("name") == "jen-alerts":
                calls["thread"] += 1

            class _T:
                def start(self_):
                    pass

            return _T()

        with (
            patch(
                "jen.services.scheduler.start_scheduler",
                side_effect=lambda app: calls.__setitem__("sched", calls["sched"] + 1),
            ),
            patch("threading.Thread", side_effect=fake_thread),
        ):
            first = background.start_background_workers(object())
            second = background.start_background_workers(object())

        assert first is True
        assert second is False  # idempotent — second call is a no-op
        assert calls["sched"] == 1
        assert calls["thread"] == 1

    def test_stop_resets_started_flag(self):
        background._started = True
        with patch("jen.services.scheduler.stop_scheduler"):
            background.stop_background_workers()
        assert background._started is False


class TestPeriodicJobs:
    """v5.30.0 (Q30, A2) — plugins register a callable + interval; the
    ONE loop start_background_workers() owns runs them. Nothing here
    starts a thread: run_due_periodic_jobs() takes a synchronous spawn."""

    def setup_method(self):
        background._periodic.clear()

    def teardown_method(self):
        background._periodic.clear()

    def test_register_validates_and_replaces(self):
        from datetime import datetime, timedelta, timezone

        with pytest.raises(ValueError):
            background.register_periodic("nd", "scan", lambda: None, 1)
        with pytest.raises(TypeError):
            background.register_periodic("nd", "scan", "not callable", 60)
        before = datetime.now(timezone.utc)
        background.register_periodic("nd", "scan", lambda: None, 60)
        background.register_periodic("nd", "scan", lambda: None, 120)  # replaces, not stacks
        jobs = background.periodic_jobs()
        assert [(j["plugin_id"], j["name"], j["every_minutes"]) for j in jobs] == [("nd", "scan", 120)]
        # first run is one interval out, never at boot
        assert jobs[0]["next_due"] >= before + timedelta(minutes=120)
        assert "fn" not in jobs[0]

    def test_due_jobs_run_once_and_reschedule(self):
        from datetime import datetime, timedelta, timezone

        ran = []
        background.register_periodic("nd", "scan", lambda: ran.append(1), 60)
        background.register_periodic("ipam", "sync", lambda: ran.append(2), 60)
        now = datetime.now(timezone.utc)

        def sync_spawn(job):
            background._run_one_periodic(job)

        assert background.run_due_periodic_jobs(now, spawn=sync_spawn) == 0  # not due yet
        later = now + timedelta(minutes=61)
        assert background.run_due_periodic_jobs(later, spawn=sync_spawn) == 2
        assert sorted(ran) == [1, 2]
        assert background.run_due_periodic_jobs(later, spawn=sync_spawn) == 0  # rescheduled an hour out
        assert all(j["next_due"] == later + timedelta(minutes=60) for j in background.periodic_jobs())
        assert all(j["running"] is False for j in background.periodic_jobs())

    def test_a_failing_job_is_recorded_and_never_raises(self):
        from datetime import datetime, timedelta, timezone

        def boom():
            raise RuntimeError("nmap exploded")

        background.register_periodic("nd", "scan", boom, 60)
        later = datetime.now(timezone.utc) + timedelta(minutes=61)
        assert background.run_due_periodic_jobs(later, spawn=background._run_one_periodic) == 1
        job = background.periodic_jobs()[0]
        assert job["last_error"] == "nmap exploded" and job["running"] is False

    def test_a_job_still_running_is_skipped_not_stacked(self):
        from datetime import datetime, timedelta, timezone

        background.register_periodic("nd", "scan", lambda: None, 60)
        later = datetime.now(timezone.utc) + timedelta(minutes=61)
        started = []
        assert background.run_due_periodic_jobs(later, spawn=lambda j: started.append(j)) == 1  # left "running"
        assert background.run_due_periodic_jobs(later + timedelta(minutes=120), spawn=started.append) == 0
        assert background.periodic_jobs()[0]["running"] is True

    def test_unregister(self):
        background.register_periodic("nd", "scan", lambda: None, 60)
        background.register_periodic("nd", "prune", lambda: None, 60)
        background.unregister_periodic("nd", "scan")
        assert [j["name"] for j in background.periodic_jobs()] == ["prune"]
        background.unregister_periodic("nd")
        assert background.periodic_jobs() == []

    def test_start_background_workers_starts_the_periodic_loop(self):
        background._started = False
        names = []

        def fake_thread(*a, **kw):
            names.append(kw.get("name"))

            class _T:
                def start(self_):
                    pass

            return _T()

        try:
            with (
                patch("jen.services.scheduler.start_scheduler", side_effect=lambda app: None),
                patch("threading.Thread", side_effect=fake_thread),
            ):
                background.start_background_workers(object())
            assert "jen-periodic" in names and "jen-alerts" in names
        finally:
            background._started = False
