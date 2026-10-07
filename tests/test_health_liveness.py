"""
tests/test_health_liveness.py
─────────────────────────────
v5.68.0-beta.19 (Q154) - Health proves liveness, not "was started once". `_background_workers` read "scheduler + alert loop running" from
`STARTED_AT is not None`, and `start_scheduler` catches its own failure and logs it, so a scheduler that never started was green forever; the
Problems sweep row said "skip - has not run yet" with no age limit. Both now look at what is actually alive and give a grace period, then fail.
No database: `background.liveness` and `client_problems.read_status` are stand-ins. `pytest --noconftest tests/test_health_liveness.py`.
"""

from datetime import datetime, timedelta, timezone

import pytest

from jen import extensions
from jen.services import background, health
from jen.services import client_problems as cp
from jen.services import scheduler as sched

CORE = list(sched.CORE_JOB_IDS)
NOW = datetime(2026, 10, 7, 12, 0, 0)  # naive UTC, the module's own convention


def _live(*, scheduler_exists=True, running=True, jobs=None, alert=True, periodic=True, error=""):
    return {
        "started_at": datetime.now(timezone.utc),
        "alert_thread": alert,
        "periodic_thread": periodic,
        "scheduler": {
            "exists": scheduler_exists,
            "running": running,
            "jobs": CORE if jobs is None else jobs,
            "error": error,
        },
    }


@pytest.fixture
def started(monkeypatch):
    monkeypatch.setattr(background, "STARTED_AT", datetime.now(timezone.utc) - timedelta(hours=2))


def _workers(monkeypatch, live):
    monkeypatch.setattr(background, "liveness", lambda: live)
    return health._background_workers({})


class TestBackgroundWorkersProveLiveness:
    def test_healthy_is_ok_and_says_what_is_alive(self, started, monkeypatch):
        c = _workers(monkeypatch, _live())
        assert c.status == "ok" and "alert loop" in c.detail and "4 jobs" in c.detail

    def test_the_test_server_is_still_a_skip(self, monkeypatch):
        monkeypatch.setattr(background, "STARTED_AT", None)
        assert health._background_workers({}).status == "skip"

    def test_a_scheduler_that_never_existed_fails_with_the_reason(self, started, monkeypatch):
        c = _workers(
            monkeypatch, _live(scheduler_exists=False, running=False, jobs=[], error="APScheduler is not installed")
        )
        assert (
            c.status == "fail"
            and "the scheduler is not running" in c.detail
            and "APScheduler is not installed" in c.detail
        )

    def test_a_scheduler_whose_start_raised_fails_with_the_exception(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(running=False, error="the scheduler failed to start (RuntimeError: boom)"))
        assert c.status == "fail" and "RuntimeError: boom" in c.detail

    def test_a_scheduler_stopped_later_fails(self, started, monkeypatch):
        assert _workers(monkeypatch, _live(running=False)).status == "fail"

    def test_a_missing_core_job_is_named(self, started, monkeypatch):
        c = _workers(monkeypatch, _live(jobs=[j for j in CORE if j != "jen_client_problems_sweep"]))
        assert c.status == "fail" and "jen_client_problems_sweep" in c.detail

    @pytest.mark.parametrize(
        "kwargs,words", [({"alert": False}, "alert loop thread"), ({"periodic": False}, "periodic-job thread")]
    )
    def test_a_dead_thread_is_named(self, started, monkeypatch, kwargs, words):
        c = _workers(monkeypatch, _live(**kwargs))
        assert c.status == "fail" and words in c.detail


class TestTheSchedulerReportsItself:
    def test_status_before_anything_started(self, monkeypatch):
        monkeypatch.setattr(sched, "_scheduler", None)
        monkeypatch.setattr(sched, "_start_error", "")
        assert sched.scheduler_status() == {"exists": False, "running": False, "jobs": [], "error": ""}

    def test_start_scheduler_records_a_start_failure(self, monkeypatch):
        pytest.importorskip("apscheduler")
        from apscheduler.schedulers.background import BackgroundScheduler

        def refuse(self, *a, **k):
            raise RuntimeError("cannot start")

        monkeypatch.setattr(BackgroundScheduler, "start", refuse)
        monkeypatch.setattr(sched, "_scheduler", None)
        sched.start_scheduler(app=object())
        status = sched.scheduler_status()
        assert status["exists"] and not status["running"] and "cannot start" in status["error"]
        assert set(status["jobs"]) == set(CORE), "every core job is registered even though the start failed"

    def test_a_running_scheduler_lists_its_core_jobs(self, monkeypatch):
        pytest.importorskip("apscheduler")
        monkeypatch.setattr(sched, "_scheduler", None)
        sched.start_scheduler(app=object())
        try:
            status = sched.scheduler_status()
            assert status["running"] and status["error"] == "" and set(CORE) <= set(status["jobs"])
        finally:
            sched.stop_scheduler()

    def test_liveness_reads_real_threads(self, monkeypatch):
        import threading

        gate = threading.Event()
        t = threading.Thread(target=gate.wait, daemon=True)
        t.start()
        monkeypatch.setattr(background, "_alert_thread", t)
        monkeypatch.setattr(background, "_periodic_thread", None)
        live = background.liveness()
        assert live["alert_thread"] is True and live["periodic_thread"] is False
        gate.set()
        t.join(2)
        assert background.liveness()["alert_thread"] is False


class TestTheProblemsSweepRowHasANoRunLimit:
    @pytest.fixture(autouse=True)
    def _world(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])
        monkeypatch.setattr(cp, "_now", lambda: NOW)
        monkeypatch.setattr(cp, "read_status", lambda servers=None: {"swept_at": None, "servers": []})

    def _started(self, monkeypatch, minutes_ago):
        monkeypatch.setattr(
            background, "STARTED_AT", (NOW - timedelta(minutes=minutes_ago)).replace(tzinfo=timezone.utc)
        )

    def test_the_first_minutes_after_start_are_a_skip(self, monkeypatch):
        self._started(monkeypatch, 3)
        c = health._problems_sweep({})
        assert c.status == "skip" and "has not run yet" in c.detail

    def test_thirty_minutes_with_no_run_is_a_failure(self, monkeypatch):
        self._started(monkeypatch, 31)
        c = health._problems_sweep({})
        assert c.status == "fail" and "has never run" in c.detail and "31 minutes" in c.detail

    def test_exactly_inside_the_grace_period_is_still_a_skip(self, monkeypatch):
        self._started(monkeypatch, cp.MISS_LIMIT * cp.SWEEP_INTERVAL_S // 60 - 1)
        assert health._problems_sweep({}).status == "skip"

    def test_the_test_server_with_no_workers_stays_a_skip(self, monkeypatch):
        monkeypatch.setattr(background, "STARTED_AT", None)
        assert health._problems_sweep({}).status == "skip"

    def test_a_sweep_that_has_run_is_judged_as_before(self, monkeypatch):
        self._started(monkeypatch, 600)
        monkeypatch.setattr(
            cp,
            "read_status",
            lambda servers=None: {
                "swept_at": NOW - timedelta(minutes=2),
                "servers": [
                    {"id": 1, "name": "kea-a", "last_read": NOW - timedelta(minutes=2), "last_error": "", "misses": 0}
                ],
            },
        )
        assert health._problems_sweep({}).status == "ok"
