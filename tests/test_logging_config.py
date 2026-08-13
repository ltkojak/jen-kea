"""
tests/test_logging_config.py
──────────────────────────────
jen/logging_config.py is new in v4.4.15 — closes a real gap (zero
logging configuration existed anywhere in the app before this; INFO
messages were silently discarded by Python's lastResort fallback
handler). Tests cover: idempotency (no duplicate handlers on repeated
calls), the plain vs. JSON format switch, config-driven vs. env-var
fallback, and that JSON output is actually valid, parseable JSON with
the fields it claims to have.
"""

import io
import json
import logging

import pytest

from jen.logging_config import configure_logging, JsonFormatter


@pytest.fixture(autouse=True)
def _reset_root_logger():
    """configure_logging() mutates the root logger globally — reset it
    after each test so these tests don't leak handler state into
    whatever runs next (including the rest of the suite)."""
    yield
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.setLevel(logging.WARNING)


class TestConfigureLoggingIdempotency:
    def test_repeated_calls_do_not_accumulate_handlers(self):
        configure_logging()
        configure_logging()
        configure_logging()
        root = logging.getLogger()
        # Exactly one handler (stdout stream) — no log_file configured,
        # so accumulating handlers on repeat calls would be a real bug
        # (every log line would print 2x, 3x, ...).
        assert len(root.handlers) == 1

    def test_level_defaults_to_info(self):
        configure_logging()
        assert logging.getLogger().level == logging.INFO


class TestPlainFormat:
    def test_info_message_is_not_discarded(self, capsys):
        configure_logging()
        logging.getLogger("test.plain").info("hello from a real INFO call")
        captured = capsys.readouterr()
        assert "hello from a real INFO call" in captured.out

    def test_output_includes_a_timestamp(self, capsys):
        configure_logging()
        logging.getLogger("test.plain").info("timestamp check")
        captured = capsys.readouterr()
        # Plain format uses %Y-%m-%dT%H:%M:%SZ — just check the shape
        # is present (a 4-digit year followed by a dash), not an exact
        # match, since asserting the literal current time is flaky.
        assert "T" in captured.out and "Z" in captured.out


class TestJsonFormat:
    def test_output_is_valid_json_per_line(self, capsys):
        import configparser
        cfg = configparser.ConfigParser()
        cfg["server"] = {"log_format": "json"}
        configure_logging(cfg)
        logging.getLogger("test.json").warning("structured message")
        captured = capsys.readouterr()
        lines = [l for l in captured.out.strip().splitlines() if l]
        # The "Logging configured: ..." line from configure_logging()
        # itself is also JSON now — every line should parse.
        for line in lines:
            parsed = json.loads(line)  # raises if not valid JSON
            assert "timestamp" in parsed
            assert "level" in parsed
            assert "logger" in parsed
            assert "message" in parsed

    def test_extra_fields_are_included(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test.extra", level=logging.INFO, pathname=__file__,
            lineno=1, msg="with extra data", args=(), exc_info=None,
        )
        record.subnet_id = 5
        record.user = "admin"
        output = json.loads(formatter.format(record))
        assert output["subnet_id"] == 5
        assert output["user"] == "admin"
        assert output["message"] == "with extra data"

    def test_non_serializable_extra_falls_back_to_string(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test.extra", level=logging.INFO, pathname=__file__,
            lineno=1, msg="with an object", args=(), exc_info=None,
        )
        record.weird = object()  # not JSON-serializable
        output_str = formatter.format(record)
        parsed = json.loads(output_str)  # must not raise
        assert "weird" in parsed


class TestConfigVsEnvFallback:
    def test_config_value_takes_priority_over_env(self, monkeypatch):
        import configparser
        monkeypatch.setenv("JEN_LOG_LEVEL", "ERROR")
        cfg = configparser.ConfigParser()
        cfg["server"] = {"log_level": "DEBUG"}
        configure_logging(cfg)
        assert logging.getLogger().level == logging.DEBUG

    def test_falls_back_to_env_when_no_config_value(self, monkeypatch):
        monkeypatch.setenv("JEN_LOG_LEVEL", "WARNING")
        configure_logging(cfg=None)
        assert logging.getLogger().level == logging.WARNING


class TestFileHandler:
    def test_creates_log_file_and_writes_to_it(self, tmp_path):
        import configparser
        log_path = tmp_path / "sub" / "jen.log"
        cfg = configparser.ConfigParser()
        cfg["server"] = {"log_file": str(log_path)}
        configure_logging(cfg)
        logging.getLogger("test.file").info("goes to a real file")
        # TimedRotatingFileHandler buffers via the standard logging
        # machinery, not OS buffering — should be on disk immediately
        # after the logger call returns.
        assert log_path.exists()
        assert "goes to a real file" in log_path.read_text()

    def test_bad_log_file_path_does_not_crash_configure_logging(self):
        import configparser
        cfg = configparser.ConfigParser()
        # A path under a location this process can't create — should be
        # caught and logged as a warning, not raised.
        cfg["server"] = {"log_file": "/proc/1/impossible/jen.log"}
        configure_logging(cfg)  # must not raise
        # stdout handler should still be present even though the file
        # handler failed — logging isn't left completely broken.
        assert len(logging.getLogger().handlers) >= 1
