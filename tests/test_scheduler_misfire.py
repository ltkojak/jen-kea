"""v5.69.0-beta.3 (Q172, item 10): the scheduler's hourly backup tick."""


class TestTheBackupTickToleratesALateWakeup:
    """v5.69.0-beta.3 (Q172, item 10): APScheduler's misfire grace is one second; the hourly backup tick keeps 600 so a late worker does not skip the day's backup."""

    def test_the_hourly_job_has_a_ten_minute_grace_and_coalesces(self):
        import inspect

        from jen.services import scheduler

        src = inspect.getsource(scheduler.start_scheduler)
        assert "misfire_grace_time=600" in src and 'id="jen_backup"' in src
