"""
tests/test_dashboard.py
───────────────────────
Tests for dashboard page and api/stats endpoint.
"""

import json

import pytest


class TestDashboard:
    """Dashboard page — GET /"""

    def test_dashboard_loads(self, logged_in_client, mock_kea):
        """Dashboard returns 200 for authenticated user."""
        r = logged_in_client.get("/")
        assert r.status_code == 200

    def test_dashboard_contains_subnet_cards(self, logged_in_client, mock_kea):
        """Dashboard renders subnet cards from SUBNET_MAP."""
        r = logged_in_client.get("/")
        assert b"Test Network" in r.data

    def test_dashboard_no_kea_graceful(self, logged_in_client, monkeypatch):
        """Dashboard loads even when Kea is unreachable."""
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: False)
        monkeypatch.setattr(
            kea_svc,
            "get_all_server_status",
            lambda: [
                {
                    "server": {"id": 1, "name": "Test Kea"},
                    "up": False,
                    "ha_state": None,
                    "version": "",
                    "role": "primary",
                }
            ],
        )
        r = logged_in_client.get("/")
        assert r.status_code == 200

    def test_dashboard_hours_param(self, logged_in_client, mock_kea):
        """Dashboard accepts valid hours parameter."""
        for hours in ["0.5", "1", "4", "8", "12", "24"]:
            r = logged_in_client.get(f"/?hours={hours}")
            assert r.status_code == 200

    def test_dashboard_invalid_hours_defaults(self, logged_in_client, mock_kea):
        """Invalid hours parameter falls back to default."""
        r = logged_in_client.get("/?hours=999")
        assert r.status_code == 200

    def test_dashboard_shows_banner_when_kea_config_unavailable(self, logged_in_client, monkeypatch):
        """v5.28.1 (Q26, D3) — a config-get error (e.g. D1's direct-mode
        wrong-daemon detection) used to be swallowed silently, leaving
        every subnet card's gateway/DNS fields just blank with no
        explanation. The cards themselves must still render (Rule 7 —
        this asserts the same "Test Network" string
        test_dashboard_contains_subnet_cards does, alongside the new
        banner)."""
        from jen.services import kea as kea_svc

        def fake_kea_command(command, *a, **kw):
            if command == "config-get":
                return {"result": 1, "text": "kea:8000 answered config-get as the Control Agent, not kea-dhcp4"}
            return {"result": 0, "text": "mocked", "arguments": {"subnet4": [], "Dhcp4": {}, "hosts": []}}

        monkeypatch.setattr(kea_svc, "kea_command", fake_kea_command)
        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: True)
        monkeypatch.setattr(
            kea_svc,
            "get_active_kea_server",
            lambda: {"id": 1, "name": "Test Kea", "api_url": "http://localhost:18000"},
        )
        monkeypatch.setattr(
            kea_svc,
            "get_all_server_status",
            lambda: [
                {
                    "server": {"id": 1, "name": "Test Kea"},
                    "up": True,
                    "ha_state": None,
                    "version": "",
                    "role": "primary",
                }
            ],
        )
        r = logged_in_client.get("/")
        assert r.status_code == 200
        assert b"Kea config unavailable" in r.data
        assert b"Test Network" in r.data


class TestApiStats:
    """API stats endpoint — GET /api/stats"""

    def test_api_stats_returns_json(self, logged_in_client, mock_kea):
        """api/stats returns valid JSON."""
        r = logged_in_client.get("/api/stats")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, dict)

    def test_api_stats_has_kea_up(self, logged_in_client, mock_kea):
        """api/stats includes kea_up field."""
        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        assert "kea_up" in data

    def test_api_stats_has_servers(self, logged_in_client, mock_kea):
        """api/stats includes servers array."""
        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        assert "servers" in data
        assert isinstance(data["servers"], list)

    def test_api_stats_has_subnets(self, logged_in_client, mock_kea):
        """api/stats includes subnets data."""
        r = logged_in_client.get("/api/stats")
        data = json.loads(r.data)
        assert "subnets" in data or "stats" in data

    def test_api_stats_kea_down_graceful(self, logged_in_client, monkeypatch):
        """api/stats returns valid JSON even when Kea is down."""
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: False)
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 1, "text": "error"})
        monkeypatch.setattr(kea_svc, "get_all_server_status", list)
        r = logged_in_client.get("/api/stats")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data.get("kea_up") is False


class TestPrometheusMetrics:
    """v4.4.15: /metrics expanded from 2 metric families to 7. This
    endpoint never required Flask-Login session auth (by design, for
    scraper compatibility) — that's still true — but as of v5.3.3 it
    does require either a configured metrics_token or an explicit
    metrics_open=true opt-in; neither configured means 401. Tests
    whose actual focus is the metric OUTPUT (not the auth behavior
    itself) use the metrics_open fixture below to get past that check
    without needing to fabricate a token for every single test."""

    @pytest.fixture
    def metrics_open(self, monkeypatch):
        """Opts into the old default-open behavior for tests that are
        actually about metric content/format, not about the access
        control this class also tests directly."""
        import configparser

        from jen import extensions

        test_cfg = configparser.ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        if "server" not in test_cfg:
            test_cfg["server"] = {}
        test_cfg["server"]["metrics_open"] = "true"
        monkeypatch.setattr(extensions, "cfg", test_cfg)

    def test_default_denies_access_with_no_configuration(self, client, mock_kea):
        """v5.3.3 — the actual behavior change: no metrics_token and no
        metrics_open means denied, not the old wide-open default."""
        r = client.get("/metrics")
        assert r.status_code == 401

    def test_metrics_open_true_restores_old_behavior_without_a_token(self, client, mock_kea, metrics_open):
        """The explicit opt-out for someone who's already decided the
        old default-open tradeoff is fine for their setup — confirms
        this doesn't ALSO require Flask-Login session auth, just that
        it's reachable at all once opted in."""
        r = client.get("/metrics")
        assert r.status_code == 200
        assert r.mimetype == "text/plain"

    def test_output_is_valid_prometheus_exposition_format(self, client, mock_kea, metrics_open):
        r = client.get("/metrics")
        text = r.data.decode()
        # Every metric line must be preceded by its own HELP and TYPE
        # comment — this is the actual Prometheus exposition format
        # contract, not just "doesn't crash".
        for family in [
            "jen_subnet_active_leases",
            "jen_subnet_reserved_hosts",
            "jen_subnet_pool_size",
            "jen_subnet_utilization_ratio",
            "jen_subnet_days_to_90pct",
            "jen_alerts_sent_total",
            "jen_kea_up",
            "jen_server_up",
        ]:
            assert f"# HELP {family}" in text, f"missing HELP for {family}"
            assert f"# TYPE {family}" in text, f"missing TYPE for {family}"

    def test_alerts_sent_total_is_declared_a_counter(self, client, mock_kea, metrics_open):
        # The one genuinely-monotonic metric here — everything else is a
        # gauge. Getting this TYPE line wrong would make Grafana's
        # rate()/increase() panels silently misbehave.
        r = client.get("/metrics")
        text = r.data.decode()
        assert "# TYPE jen_alerts_sent_total counter" in text

    def test_server_up_reflects_mock_kea_server(self, client, mock_kea, metrics_open):
        r = client.get("/metrics")
        text = r.data.decode()
        assert 'jen_server_up{server="Test Kea"} 1' in text

    def test_token_protection_when_configured(self, client, mock_kea, monkeypatch):
        import configparser

        from jen import extensions

        test_cfg = configparser.ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        test_cfg["server"] = {"metrics_token": "s3cret"}
        monkeypatch.setattr(extensions, "cfg", test_cfg)

        r_no_token = client.get("/metrics")
        assert r_no_token.status_code == 401

        r_wrong_token = client.get("/metrics", headers={"Authorization": "Bearer wrong"})
        assert r_wrong_token.status_code == 401

        r_right_token = client.get("/metrics", headers={"Authorization": "Bearer s3cret"})
        assert r_right_token.status_code == 200

    def test_survives_kea_down(self, client, monkeypatch, metrics_open):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: False)
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 1, "text": "error"})
        monkeypatch.setattr(kea_svc, "get_all_server_status", list)
        r = client.get("/metrics")
        assert r.status_code == 200
        assert "jen_kea_up 0" in r.data.decode()

    def test_days_to_90pct_is_minus_one_without_enough_history(self, client, mock_kea, metrics_open, db):
        """v5.43.0 (Q44) — capacity.forecast()'s days_to_90pct is None for
        flat/falling/insufficient trends; -1 is the metric's stand-in,
        since a Prometheus gauge has no native way to say "unknown"."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
        db.commit()
        r = client.get("/metrics")
        text = r.data.decode()
        assert "jen_subnet_days_to_90pct{" in text
        assert "} -1" in text

    def test_pkt4_counters_from_latest_server_stats_row(self, client, mock_kea, metrics_open, db):
        """v5.43.0 (Q44) — one metric family per pkt4-* counter name, all
        of one family's samples grouped together (the Prometheus
        exposition format requires it); v4-* keys are out of scope for
        this metric family."""
        import json

        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
            cur.execute(
                "INSERT INTO server_stats (server_id, stats) VALUES (1, %s)",
                (json.dumps({"pkt4-received": 42, "pkt4-ack-sent": 40, "v4-lease-reuses": 3}),),
            )
        db.commit()
        r = client.get("/metrics")
        text = r.data.decode()
        assert "# TYPE jen_server_pkt4_received_total counter" in text
        assert 'jen_server_pkt4_received_total{server="Test Kea"} 42' in text
        assert 'jen_server_pkt4_ack_sent_total{server="Test Kea"} 40' in text
        assert "v4_lease_reuses" not in text

    def test_no_server_stats_rows_produces_no_pkt4_metrics(self, client, mock_kea, metrics_open, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
        db.commit()
        r = client.get("/metrics")
        text = r.data.decode()
        assert "jen_server_pkt4_" not in text

    def test_pkt4_samples_for_one_metric_are_grouped_across_servers(
        self, client, mock_kea, metrics_open, db, monkeypatch
    ):
        """The Prometheus exposition format requires every sample of one
        metric family to be contiguous — with two servers both reporting
        pkt4-received, both samples must sit together, not be split up
        by an unrelated family in between."""
        import json

        from jen import extensions

        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [{"id": 1, "name": "kea-a"}, {"id": 2, "name": "kea-b"}],
        )
        with db.cursor() as cur:
            cur.execute("DELETE FROM server_stats")
            cur.execute(
                "INSERT INTO server_stats (server_id, stats) VALUES (1, %s), (2, %s)",
                (json.dumps({"pkt4-received": 10}), json.dumps({"pkt4-received": 20})),
            )
        db.commit()
        r = client.get("/metrics")
        text = r.data.decode()
        lines = [ln for ln in text.splitlines() if ln.startswith("jen_server_pkt4_received_total{")]
        assert len(lines) == 2
        first_idx = text.index(lines[0])
        second_idx = text.index(lines[1])
        between = text[first_idx + len(lines[0]) : second_idx]
        assert "jen_server_pkt4_" not in between


class TestGrafanaDashboard:
    """v5.43.0 (Q44) — contrib/grafana/jen-kea.json. Not served by Jen
    itself in this step (that's the Settings → System download route);
    just: it's valid JSON, and everything it queries is something
    /metrics actually emits, so a stale panel can't ship silently."""

    def _dashboard_path(self):
        import pathlib

        return pathlib.Path(__file__).resolve().parent.parent / "contrib" / "grafana" / "jen-kea.json"

    def test_json_parses_and_has_panels(self):
        import json

        data = json.loads(self._dashboard_path().read_text(encoding="utf-8"))
        assert data["panels"]
        assert data["templating"]["list"][0]["name"] == "DS_PROMETHEUS"

    def test_every_expr_references_a_metric_metrics_actually_emits(self, client, mock_kea, metrics_open, db):
        import json
        import re

        # Seed everything conditionally-emitted (pool_size/utilization_ratio
        # need a lease_history row; the pkt4-* families need a server_stats
        # row) so an absent-because-no-data metric doesn't look like a
        # dashboard referencing something /metrics can never produce.
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history")
            cur.execute("INSERT INTO lease_history (subnet_id, active_leases, pool_size) VALUES (1, 5, 100)")
            cur.execute("DELETE FROM server_stats")
            cur.execute(
                "INSERT INTO server_stats (server_id, stats) VALUES (1, %s)",
                (
                    json.dumps(
                        {
                            "pkt4-received": 1,
                            "pkt4-ack-sent": 1,
                            "pkt4-nak-sent": 1,
                            "pkt4-receive-drop": 1,
                            "pkt4-parse-failed": 1,
                        }
                    ),
                ),
            )
        db.commit()

        dash = json.loads(self._dashboard_path().read_text(encoding="utf-8"))
        referenced = set()
        for panel in dash["panels"]:
            for target in panel.get("targets", []):
                referenced.update(re.findall(r"jen_[a-z0-9_]*", target["expr"]))
        assert referenced, "no metric names found in any panel expr — regex or fixture is wrong"

        text = client.get("/metrics").data.decode()
        emitted = set(re.findall(r"^(jen_[a-z0-9_]*)[\s{]", text, re.MULTILINE))
        missing = referenced - emitted
        assert not missing, f"dashboard panel(s) reference metric(s) /metrics never emits: {missing}"
