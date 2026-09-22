"""
tests/test_dashboard_catalog.py
─────────────────────────────────
v5.54.0 (Q61) — the seven catalog widget builders. Most take their inputs
already assembled (like `packet_health.assess()` itself), so the shaping
logic is pure and testable without Kea or a live DB; a few genuinely need
the DB (packet_health, events_feed) or Kea (readiness, ddns_errors,
ha_state indirectly via the route) and are covered as pure shaping tests
here with the DB/Kea calls monkeypatched, plus one route smoke test each
in tests/test_dashboard_arrangement.py-style DB tests below.

Pure: `py -m pytest --noconftest tests/test_dashboard_catalog.py -k "not Shape"`
(the two Shape classes use the `db` fixture and need the CI database).
"""

from datetime import datetime, timedelta

from jen.services import dashboard_catalog as dc
from jen.services.health import Check


class TestForecastWidget:
    def test_skips_a_subnet_with_no_history(self, monkeypatch):
        from jen.services import health as h

        monkeypatch.setattr(h, "lease_history_window", dict)
        assert dc.forecast_widget([1, 2]) == []

    def test_skips_a_subnet_with_insufficient_trend(self, monkeypatch):
        from jen.services import capacity, health

        monkeypatch.setattr(health, "lease_history_window", lambda: {1: [{"x": 1}]})
        monkeypatch.setattr(capacity, "forecast", lambda rows: {"trend": "insufficient"})
        assert dc.forecast_widget([1]) == []

    def test_a_real_trend_is_shaped_with_a_summary_line(self, monkeypatch):
        from jen import extensions
        from jen.services import capacity, health

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "Office"}})
        monkeypatch.setattr(health, "lease_history_window", lambda: {1: [{"x": 1}] * 10})
        monkeypatch.setattr(capacity, "forecast", lambda rows: {"trend": "rising", "days_to_90pct": 5})
        monkeypatch.setattr(capacity, "summary_line", lambda f: "on track for 90% in 5 days")
        rows = dc.forecast_widget([1])
        assert rows == [
            {
                "subnet_id": 1,
                "name": "Office",
                "trend": "rising",
                "days_to_90pct": 5,
                "line": "on track for 90% in 5 days",
            }
        ]

    def test_a_kea_error_returns_an_empty_list_not_an_exception(self, monkeypatch):
        from jen.services import health

        def boom():
            raise RuntimeError("db down")

        monkeypatch.setattr(health, "lease_history_window", boom)
        assert dc.forecast_widget([1]) == []


class TestReadinessWidget:
    def test_filters_to_the_readiness_group_and_summarises(self, monkeypatch):
        from jen.services import health

        checks = [
            Check("kea32_control_transport", "Control transport", "readiness", "ok", "fine"),
            Check("kea32_helper_version", "Helper current", "readiness", "warn", "old helper"),
            Check("kea_reachable", "Kea reachable", "kea", "ok", "1/1"),  # a different group — excluded
        ]
        monkeypatch.setattr(health, "run_checks", lambda: checks)
        w = dc.readiness_widget()
        assert w["status"] == "warn"
        assert len(w["rows"]) == 2
        assert "1 ok" in w["line"] and "1 warn" in w["line"]

    def test_all_ok_status_is_ok(self, monkeypatch):
        from jen.services import health

        monkeypatch.setattr(health, "run_checks", lambda: [Check("a", "A", "readiness", "ok", "fine")])
        assert dc.readiness_widget()["status"] == "ok"

    def test_a_kea_error_returns_none(self, monkeypatch):
        from jen.services import health

        def boom():
            raise RuntimeError("kea down")

        monkeypatch.setattr(health, "run_checks", boom)
        assert dc.readiness_widget() is None


class TestHaStateWidget:
    def test_single_server_skips(self):
        assert dc.ha_state_widget([{"server": {"name": "A"}, "up": True, "ha_state": None}]) is None

    def test_load_balancing_is_always_active(self):
        rows = dc.ha_state_widget(
            [
                {"server": {"name": "A", "role": "primary"}, "up": True, "ha_state": "load-balancing"},
                {"server": {"name": "B", "role": "secondary"}, "up": True, "ha_state": "load-balancing"},
            ]
        )
        assert all(r["is_active"] for r in rows)

    def test_hot_standby_only_the_primary_is_active(self):
        rows = dc.ha_state_widget(
            [
                {"server": {"name": "A", "role": "primary"}, "up": True, "ha_state": "hot-standby"},
                {"server": {"name": "B", "role": "secondary"}, "up": True, "ha_state": "hot-standby"},
            ]
        )
        by_name = {r["name"]: r for r in rows}
        assert by_name["A"]["is_active"] and not by_name["B"]["is_active"]

    def test_partner_down_is_active_and_unhealthy(self):
        rows = dc.ha_state_widget(
            [
                {"server": {"name": "A"}, "up": True, "ha_state": "partner-down"},
                {"server": {"name": "B"}, "up": False, "ha_state": None},
            ]
        )
        a = next(r for r in rows if r["name"] == "A")
        assert a["is_active"] and not a["healthy"]


class TestDdnsErrorsWidget:
    def test_skip_status_becomes_none(self, monkeypatch):
        from jen.services import health

        monkeypatch.setattr(health, "run_checks", lambda: [Check("d2_errors", "D2 errors", "ddns", "skip", "off")])
        assert dc.ddns_errors_widget() is None

    def test_missing_check_becomes_none(self, monkeypatch):
        from jen.services import health

        monkeypatch.setattr(health, "run_checks", list)
        assert dc.ddns_errors_widget() is None

    def test_a_real_status_passes_through(self, monkeypatch):
        from jen.services import health

        monkeypatch.setattr(
            health, "run_checks", lambda: [Check("d2_errors", "D2 errors", "ddns", "warn", "ncr-error=3")]
        )
        w = dc.ddns_errors_widget()
        assert w == {"status": "warn", "detail": "ncr-error=3"}


class TestGettingStartedWidget:
    def test_delegates_to_the_cached_pill(self, monkeypatch):
        from jen.services import onboarding

        monkeypatch.setattr(onboarding, "cached_pill", lambda user, is_superadmin: {"done": 3, "total": 9})
        assert dc.getting_started_widget(object(), True) == {"done": 3, "total": 9}


class TestPacketHealthWidgetShape:
    def test_a_server_with_fewer_than_two_snapshots_is_left_out(self, db):
        assert dc.packet_health_widget([{"id": 999999, "name": "Nowhere"}]) == []


class TestEventsFeedWidgetShape:
    def test_empty_table_returns_an_empty_list(self, db):
        assert dc.events_feed_widget([1], True) == []

    def test_restricted_scope_drops_subnetless_events(self, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO events (ts, kind, subnet_id, detail) VALUES (%s, 'test.kind', NULL, 'no subnet')",
                (datetime.utcnow(),),
            )
            cur.execute(
                "INSERT INTO events (ts, kind, subnet_id, detail) VALUES (%s, 'test.kind', 1, 'has subnet')",
                (datetime.utcnow() + timedelta(seconds=1),),
            )
        db.commit()
        try:
            restricted = dc.events_feed_widget([1], False)
            assert all(e["subnet_id"] is not None for e in restricted)
            assert any(e["detail"] == "has subnet" for e in restricted)
            unrestricted = dc.events_feed_widget([1], True)
            assert any(e["detail"] == "no subnet" for e in unrestricted)
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM events WHERE kind='test.kind'")
            db.commit()
