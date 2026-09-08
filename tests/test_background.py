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
