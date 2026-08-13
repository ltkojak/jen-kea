"""
jen/logging_config.py
──────────────────────
v4.4.15: Jen previously had zero explicit logging configuration
anywhere — no logging.basicConfig(), no handlers, no formatter. In
practice this meant every INFO-level log call in the app was silently
discarded (Python's logging module falls back to `logging.lastResort`,
a bare StreamHandler(stderr) that only handles WARNING and above, when
no handler is configured anywhere in the logger hierarchy). The
workaround visible in jen/models/db.py before this fix — logging
routine "connection pool initialised" events at WARNING instead of
INFO — existed specifically so those messages would actually appear.
That's no longer necessary once logging is properly configured; see
the corresponding fix in db.py.

Two output formats:
- "plain" (default): human-readable, single-line-per-record, safe for
  `journalctl -u jen -f` — this is what everyone's eyes have adjusted
  to already visible in the logs since a plain default doesn't change
  operator experience for existing installs.
- "json": one JSON object per line — timestamp, level, logger name,
  message, and any extra fields — for feeding Loki/ELK/Promtail
  without a log-parsing regex. Opt-in via [server] log_format = json
  or the JEN_LOG_FORMAT env var, since flipping the default would be a
  breaking change for anyone currently reading raw journal output.

Destination: stdout/stderr by default (systemd's Type=simple services
capture this into the journal automatically, which already has its own
rotation/retention via journald.conf — Jen doesn't need to reinvent
that). An optional rotating file handler is available for anyone who
wants to tail a file directly (e.g. shipping via Promtail without
journal export tooling), configured via [server] log_file and
log_retention_days.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler


class JsonFormatter(logging.Formatter):
    """One JSON object per line. UTC timestamps throughout, matching
    Jen's existing convention everywhere else in the app."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Anything passed via logger.info(..., extra={...}) rides along too,
        # rather than being silently dropped the way plain-text logging
        # would drop it.
        standard_keys = set(logging.LogRecord(
            "", 0, "", 0, "", (), None
        ).__dict__.keys()) | {"message", "asctime"}
        for key, value in record.__dict__.items():
            if key not in standard_keys and key not in payload:
                try:
                    json.dumps(value)  # only include JSON-serializable extras
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = str(value)
        return json.dumps(payload)


def configure_logging(cfg=None) -> None:
    """
    Call once, early, before anything else logs. Idempotent — safe to
    call more than once (clears existing handlers first) so tests can
    call it repeatedly without accumulating duplicate handlers.

    Reads from jen.config's [server] section if cfg is provided,
    falling back to JEN_LOG_LEVEL / JEN_LOG_FORMAT / JEN_LOG_FILE /
    JEN_LOG_RETENTION_DAYS env vars, then hardcoded defaults. This
    mirrors the same env-var-fallback pattern run.py already uses for
    Docker deployments without a mounted config file.
    """
    def _get(section, key, env_var, default):
        if cfg is not None:
            try:
                val = cfg.get(section, key, fallback=None)
                if val:
                    return val
            except Exception:
                pass
        return os.environ.get(env_var, default)

    level_name = _get("server", "log_level", "JEN_LOG_LEVEL", "INFO").upper()
    log_format = _get("server", "log_format", "JEN_LOG_FORMAT", "plain").lower()
    log_file = _get("server", "log_file", "JEN_LOG_FILE", "")
    retention_days = int(_get("server", "log_retention_days", "JEN_LOG_RETENTION_DAYS", "14"))

    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)

    if log_format == "json":
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        formatter.converter = lambda *args: datetime.now(timezone.utc).timetuple()

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = TimedRotatingFileHandler(
                log_file, when="midnight", backupCount=retention_days, utc=True
            )
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
        except Exception as e:
            # Don't let a bad log_file path take the whole app down —
            # stdout logging above already succeeded, that's enough to
            # not lose visibility entirely.
            root.warning(f"Could not set up log file at {log_file}: {e}")

    logging.getLogger(__name__).info(
        f"Logging configured: level={level_name} format={log_format}"
        + (f" file={log_file} (retain {retention_days}d)" if log_file else "")
    )
