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
    _scheduler.add_job(
        _run_audit_cleanup,
        CronTrigger(hour=0, minute=5),
        id="jen_audit_cleanup",
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
            if last_run:
                try:
                    lr_date = last_run.date() if hasattr(last_run, "date") else \
                              datetime.strptime(str(last_run)[:10], "%Y-%m-%d").date()
                    if lr_date == now.date():
                        return
                except Exception:
                    pass  # Can't parse last_run — allow backup to proceed
            run_scheduled_backup()
        except Exception as e:
            logger.error(f"Scheduled backup error: {e}")


def stop_scheduler():
    if _scheduler and _scheduler.running:
        try:
            _scheduler.shutdown(wait=False)
        except Exception:
            pass


def _run_audit_cleanup(app):
    """Called at 00:05 daily — prune audit_log based on retention setting."""
    with app.app_context():
        try:
            from jen.models import user as __user
            from jen.models import db as __db
            days_str = __user.get_global_setting("audit_retention_days", "90")
            days = int(days_str) if days_str else 90
            if days <= 0:
                return  # 0 = keep forever
            db = __db.get_jen_db()
            with db.cursor() as cur:
                cur.execute(
                    "DELETE FROM audit_log WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)",
                    (days,)
                )
                deleted = cur.rowcount
            db.commit()
            db.close()
            if deleted:
                logger.info(f"Audit log cleanup: removed {deleted} entries older than {days} days")
        except Exception as e:
            logger.error(f"Audit log cleanup error: {e}")
