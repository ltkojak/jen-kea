"""
jen/services/scheduler.py
─────────────────────────
APScheduler wrapper for scheduled backups.
Started by the app factory after DB init.
"""
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

_scheduler = None


def start_scheduler(app):
    global _scheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
    except ImportError:
        logger.warning("APScheduler not installed — scheduled backups disabled")
        return

    _scheduler = BackgroundScheduler(daemon=True)
    # Run every hour — the job itself checks frequency/hour settings
    _scheduler.add_job(
        _run_backup_job,
        CronTrigger(minute=0),
        id="jen_backup",
        replace_existing=True,
        args=[app]
    )
    try:
        _scheduler.start()
        logger.info("Backup scheduler started")
    except Exception as e:
        logger.warning(f"Backup scheduler failed to start: {e}")


def _run_backup_job(app):
    """Called by APScheduler every hour. Checks if a backup is due."""
    with app.app_context():
        try:
            from jen.services.dbexport import get_schedule, run_scheduled_backup
            sched = get_schedule()
            if not sched or not sched.get("enabled"):
                return
            now  = datetime.utcnow()
            hour = int(sched.get("hour", 2))
            freq = sched.get("frequency", "daily")
            if now.hour != hour:
                return
            if freq == "weekly" and now.weekday() != 6:  # Sunday
                return
            # Check not already run today
            last_run = sched.get("last_run")
            if last_run and hasattr(last_run, "date") and last_run.date() == now.date():
                return
            run_scheduled_backup()
        except Exception as e:
            logger.error(f"Scheduled backup error: {e}")


def stop_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        try:
            _scheduler.shutdown(wait=False)
        except Exception:
            pass
