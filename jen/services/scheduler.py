"""
jen/services/scheduler.py
─────────────────────────
APScheduler wrapper for scheduled backups.
Started by the app factory after DB init.
"""

import contextlib
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_scheduler = None
_start_error = (
    ""  # why the scheduler is not running, for the Health Center (v5.68.0-beta.19, Q154); empty when it started
)

#: the jobs `start_scheduler` registers - the Health Center's liveness row requires every one of them
CORE_JOB_IDS = ("jen_backup", "jen_audit_cleanup", "jen_investigation_sweep", "jen_client_problems_sweep")


def scheduler_status() -> dict:
    """What the Health Center can prove about the scheduler: {"exists", "running", "jobs" (registered job ids), "error" (why it did not
    start, or "")}. A scheduler that was never created or whose start raised is reported as exactly that, never as "running"."""
    exists = _scheduler is not None
    running = bool(exists and _scheduler.running)
    jobs = []
    if exists:
        with contextlib.suppress(Exception):
            jobs = sorted(j.id for j in _scheduler.get_jobs())
    return {"exists": exists, "running": running, "jobs": jobs, "error": _start_error}


def start_scheduler(app):
    global _scheduler, _start_error
    _start_error = ""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
        from apscheduler.triggers.interval import IntervalTrigger
    except ImportError:
        logger.warning("APScheduler not installed — scheduled backups disabled")
        _start_error = "APScheduler is not installed"
        return

    _scheduler = BackgroundScheduler(daemon=True)
    # Run every hour — the job itself checks frequency/hour settings
    _scheduler.add_job(_run_backup_job, CronTrigger(minute=0), id="jen_backup", replace_existing=True, args=[app])
    _scheduler.add_job(
        _run_audit_cleanup, CronTrigger(hour=0, minute=5), id="jen_audit_cleanup", replace_existing=True, args=[app]
    )
    # v5.68.0-beta.3 (Q138): every minute, put back any investigation logging whose time is up
    _scheduler.add_job(
        _run_investigation_sweep,
        IntervalTrigger(minutes=1),
        id="jen_investigation_sweep",
        replace_existing=True,
        args=[app],
        max_instances=1,
        coalesce=True,
    )
    # v5.68.0-beta.5 (Q140): every five minutes, read each Kea server's log and the lease database for clients that had DHCP trouble
    _scheduler.add_job(
        _run_client_problems_sweep,
        IntervalTrigger(minutes=5),
        id="jen_client_problems_sweep",
        replace_existing=True,
        args=[app],
        max_instances=1,
        coalesce=True,
    )
    try:
        _scheduler.start()
        logger.info("Backup scheduler started")
    except Exception as e:
        logger.warning(f"Backup scheduler failed to start: {e}")
        _start_error = f"the scheduler failed to start ({type(e).__name__}: {e})"


def _run_backup_job(app):
    """Called by APScheduler every hour. Checks if a backup is due."""
    with app.app_context():
        try:
            from jen.services.dbexport import get_schedule, run_scheduled_backup

            sched = get_schedule()
            if not sched or not sched.get("enabled"):
                return
            now = datetime.now(timezone.utc)  # utcnow() is deprecated in 3.12
            hour = int(sched.get("hour", 2))
            freq = sched.get("frequency", "daily")
            if now.hour != hour:
                return
            if freq == "weekly" and now.weekday() != 6:  # Sunday
                return
            # Check not already run today
            last_run = sched.get("last_run")
            if last_run:
                try:
                    lr_date = (
                        last_run.date()
                        if hasattr(last_run, "date")
                        else datetime.strptime(str(last_run)[:10], "%Y-%m-%d").date()
                    )
                    if lr_date == now.date():
                        return
                except Exception:
                    pass  # Can't parse last_run — allow backup to proceed
            run_scheduled_backup()
        except Exception as e:
            logger.error(f"Scheduled backup error: {e}")


def _run_investigation_sweep(app):
    """Called every minute: restore any expired investigation logging on every server (jen.services.investigation_logging)."""
    with app.app_context():
        try:
            from jen.services import investigation_logging

            result = investigation_logging.run_sweep_job()
            if result["restored"] or result["errors"]:
                logger.info(f"investigation logging sweep: {result}")
        except Exception as e:
            logger.error(f"Investigation logging sweep error: {e}")


def _run_client_problems_sweep(app):
    """Called every five minutes: the Problems inbox sweep (jen.services.client_problems)."""
    with app.app_context():
        try:
            from jen.services import client_problems

            result = client_problems.run_sweep_job()
            if result["events"] or result["alerts_attempted"] or result["errors"]:
                logger.info(f"client problems sweep: {result}")
        except Exception as e:
            logger.error(f"Client problems sweep error: {e}")


def stop_scheduler():
    if _scheduler and _scheduler.running:
        with contextlib.suppress(Exception):
            _scheduler.shutdown(wait=False)


def _run_audit_cleanup(app):
    """Called at 00:05 daily — prune audit_log based on retention setting."""
    with app.app_context():
        # v5.68.0-beta.5 (Q140): the Problems inbox keeps 30 days, whatever the audit retention below says (0 = keep forever)
        try:
            from jen.services import client_problems

            pruned = client_problems.prune()
            if pruned:
                logger.info(f"Problems inbox cleanup: removed {pruned} rows not seen for 30 days")
        except Exception as e:
            logger.error(f"Problems inbox cleanup error: {e}")
        try:
            from jen.services import alerts

            removed = (
                alerts.purge_history()
            )  # v5.68.0-beta.19 (Q154): one place lists every history table (audit_log: 0 = keep forever)
            # v5.68.0-beta.20 (Q155): a table whose purge FAILED is reported as failed, never as 0 rows removed
            summary = {table: ("failed" if n is None else n) for table, n in removed.items()}
            if any(n is None for n in removed.values()):
                logger.warning(f"History cleanup: {summary}")
            elif any(removed.values()):
                logger.info(f"History cleanup: removed {summary}")
        except Exception as e:
            logger.error(f"History cleanup error: {e}")
