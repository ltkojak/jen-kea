"""
tests/test_ha_maintenance.py
────────────────────────────
v5.38.0 (Q37) — the planned-maintenance flow: the pure stepper and
partner resolution in jen/services/ha_maintenance.py, and the
/servers/ha/maintenance* routes with kea_command faked. The one thing
that matters most is pinned first: ha-maintenance-start goes to the
PARTNER (the server that keeps serving), never to the one being taken
down.
"""

import copy
from datetime import datetime, timedelta, timezone

from jen import extensions
from jen.services import ha_maintenance as hm
from tests.conftest import restricted_client as _restricted_client
from tests.test_ha_console import HA_DHCP4_CFG, SERVERS, _status_get_response

NOW = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)


def _st(state):
    return {"local": {"role": "primary", "scopes": ["server1"], "state": state}, "remote": {}}


def _state(step="handover", **over):
    base = {
        "step": step,
        "step_at": NOW.isoformat(),
        "down_name": "Primary",
        "up_name": "Standby",
        "leases_shared": False,
    }
    base.update(over)
    return base


# ── pure ─────────────────────────────────────────────────────────────────────


class TestNextStep:
    def test_handover_advances_when_both_moved(self):
        v = hm.next_step(_state(), _st("in-maintenance"), _st("partner-in-maintenance"), NOW + timedelta(seconds=5))
        assert v["advance"] == "work" and v["tone"] == "ok" and v["can_cancel"] is True

    def test_handover_waits_then_times_out_naming_the_side(self):
        v = hm.next_step(_state(), _st("hot-standby"), _st("partner-in-maintenance"), NOW + timedelta(seconds=20))
        assert v["advance"] is None and v["timed_out"] is False and "Waiting" in v["message"]
        v = hm.next_step(_state(), _st("hot-standby"), _st("partner-in-maintenance"), NOW + timedelta(seconds=61))
        assert v["timed_out"] is True and v["tone"] == "fail"
        assert (
            "Primary is hot-standby, not in-maintenance" in v["message"]
            and "Standby" not in v["message"].split(":")[1].split(";")[0]
        )
        assert v["can_cancel"] is True and "cancel" in v["message"]
        v = hm.next_step(_state(), None, _st("hot-standby"), NOW + timedelta(seconds=61))
        assert "Standby is hot-standby, not partner-in-maintenance" in v["message"] and v["can_cancel"] is False

    def test_work_offers_cancel_only_while_partner_in_maintenance(self):
        v = hm.next_step(_state("work"), _st("in-maintenance"), _st("partner-in-maintenance"), NOW)
        assert v["can_cancel"] is True and "cancel" in v["message"]
        v = hm.next_step(_state("work"), None, _st("partner-down"), NOW)
        assert v["can_cancel"] is False and "no longer applies" in v["message"] and v["tone"] == "ok"

    def test_back_waits_for_both_normal_and_mentions_shared_leases(self):
        v = hm.next_step(_state("back"), None, _st("partner-down"), NOW)
        assert v["advance"] is None and "Waiting for Primary" in v["message"]
        v = hm.next_step(_state("back"), _st("syncing"), _st("partner-down"), NOW)
        assert "Kea syncs leases on its own" in v["message"]
        v = hm.next_step(_state("back", leases_shared=True), _st("waiting"), _st("partner-down"), NOW)
        assert "nothing to sync" in v["message"]
        v = hm.next_step(_state("back"), _st("hot-standby"), _st("hot-standby"), NOW)
        assert v["advance"] == "done" and v["tone"] == "ok"

    def test_preflight_and_done_messages(self):
        v = hm.next_step(_state("preflight"), _st("hot-standby"), _st("hot-standby"), NOW)
        assert v["tone"] == "ok" and "Standby take every scope" in v["message"]
        v = hm.next_step(_state("done"), _st("hot-standby"), _st("hot-standby"), NOW)
        assert "Repeat for Standby" in v["message"]


class TestResolvePartner:
    def _cfgs(self):
        from jen.services import kea_ha

        a = kea_ha.ha_config(HA_DHCP4_CFG)
        b_raw = copy.deepcopy(HA_DHCP4_CFG)
        b_raw["hooks-libraries"][0]["parameters"]["high-availability"][0]["this-server-name"] = "server2"
        b = kea_ha.ha_config(b_raw)
        return a, b

    def test_finds_the_partner_by_this_server_name(self):
        a, b = self._cfgs()
        up, reason = hm.resolve_partner(SERVERS[0], SERVERS, {1: a, 2: b})
        assert up is SERVERS[1] and reason == ""
        up, reason = hm.resolve_partner(SERVERS[1], SERVERS, {1: a, 2: b})
        assert up is SERVERS[0]

    def test_partner_not_in_jen(self):
        a, _b = self._cfgs()
        up, reason = hm.resolve_partner(SERVERS[0], SERVERS, {1: a, 2: None})
        assert up is None and "only knows one side" in reason and "'server2'" in reason

    def test_no_ha_hook_on_the_chosen_server(self):
        up, reason = hm.resolve_partner(SERVERS[0], SERVERS, {1: None, 2: None})
        assert up is None and "no HA hook" in reason

    def test_leases_shared_flag(self):
        from jen.services import kea_ha

        assert hm.leases_shared(kea_ha.ha_config(HA_DHCP4_CFG)) is False
        raw = copy.deepcopy(HA_DHCP4_CFG)
        raw["hooks-libraries"][0]["parameters"]["high-availability"][0]["send-lease-updates"] = False
        cfg = kea_ha.ha_config(raw)
        assert cfg["send_lease_updates"] is False and hm.leases_shared(cfg) is True


# ── routes ───────────────────────────────────────────────────────────────────


class _Kea:
    """A fake kea_command: HA configs per server, mutable HA states,
    and a record of every HA command sent and to whom."""

    def __init__(self, states=None):
        self.states = states or {"Primary": "hot-standby", "Standby": "hot-standby"}
        self.sent = []
        self.refuse = set()

    def __call__(self, command, service="dhcp4", arguments=None, server=None, timeout=10):
        name = (server or {}).get("name", "Primary")
        if command == "config-get":
            cfg = copy.deepcopy(HA_DHCP4_CFG)
            cfg["hooks-libraries"][0]["parameters"]["high-availability"][0]["this-server-name"] = (
                "server1" if name == "Primary" else "server2"
            )
            return {"result": 0, "arguments": {"Dhcp4": cfg}}
        if command == "status-get":
            st = self.states.get(name)
            if st is None:
                return {"result": 1, "text": "unreachable"}
            return _status_get_response(st)
        if command in ("ha-maintenance-start", "ha-maintenance-cancel"):
            self.sent.append((command, name))
            if command in self.refuse:
                return {"result": 1, "text": "partner is unreachable"}
            return {"result": 0, "text": "ok"}
        if command == "version-get":
            return {"result": 0, "arguments": {"extended": "3.0.1"}}
        return {"result": 0, "arguments": {}}


def _wire(monkeypatch, kea):
    from jen.services import health
    from jen.services import kea as kea_svc

    monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(s) for s in SERVERS])
    monkeypatch.setattr(kea_svc, "kea_command", kea)
    monkeypatch.setattr(
        extensions.cfg, "get", lambda s, k, fallback=None: "hot-standby" if (s, k) == ("kea", "ha_mode") else fallback
    )
    # the preflight runs the real Health engine; pin its answers so the
    # route test doesn't depend on a live Kea
    monkeypatch.setattr(
        health,
        "run_checks",
        lambda ctx=None: [
            health.Check("kea_reachable", "Kea servers reachable", "kea", "ok", "2/2 reachable"),
            health.Check("kea_ha_state", "HA state healthy", "kea", "ok", "hot-standby"),
            health.Check("kea_time_sync", "Kea clock in sync", "kea", "skip", ""),
            health.Check("kea_config_drift", "Subnet map matches Kea", "kea", "ok", ""),
            health.Check("lease_snapshot_fresh", "Lease snapshots current", "capacity", "warn", "stale"),
            health.Check("db_jen", "Jen database", "jen", "ok", ""),
        ],
    )


class TestMaintenanceRoutes:
    def test_gates(self, client, db, monkeypatch):
        _wire(monkeypatch, _Kea())
        r = client.get("/servers/ha/maintenance", follow_redirects=False)
        assert r.status_code in (301, 302, 308)
        c, _ = _restricted_client(client, db, allowed_subnets=None, role="admin", username="maint_admin1")
        r = c.get("/servers/ha/maintenance", follow_redirects=True)
        assert b"SuperAdmin access required." in r.data

    def test_recent_auth_required(self, logged_in_client, monkeypatch):
        _wire(monkeypatch, _Kea())
        with logged_in_client.session_transaction() as sess:
            sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        r = logged_in_client.get("/servers/ha/maintenance", follow_redirects=False)
        assert r.status_code == 302 and "reauth" in r.headers["Location"]

    def test_chooser_lists_servers_and_preselects(self, logged_in_client, monkeypatch):
        _wire(monkeypatch, _Kea())
        body = logged_in_client.get("/servers/ha/maintenance?down=2").data.decode()
        assert "Which server are you taking down?" in body and 'value="2" selected' in body
        assert "Planned maintenance" in logged_in_client.get("/servers").data.decode()

    def test_partner_not_in_jen_stops(self, logged_in_client, monkeypatch):
        kea = _Kea()
        _wire(monkeypatch, kea)
        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(SERVERS[0])])
        r = logged_in_client.post("/servers/ha/maintenance/begin", data={"down": "1"}, follow_redirects=True)
        assert b"only knows one side of this pair" in r.data and kea.sent == []

    def test_begin_resolves_partner_and_shows_preflight(self, logged_in_client, monkeypatch):
        _wire(monkeypatch, _Kea())
        r = logged_in_client.post("/servers/ha/maintenance/begin", data={"down": "1"}, follow_redirects=True)
        body = r.data.decode()
        assert "Taking down <strong>Primary</strong>; <strong>Standby</strong> keeps serving" in body
        assert "Kea servers reachable" in body and "Lease snapshots current" in body and "Start handover" in body
        with logged_in_client.session_transaction() as sess:
            st = sess["ha_maint"]
        assert st["down"] == 1 and st["up"] == 2 and st["step"] == "preflight" and st["preflight_ok"] is True

    def test_handover_sends_maintenance_start_to_the_partner(self, logged_in_client, monkeypatch, db):
        kea = _Kea()
        _wire(monkeypatch, kea)
        logged_in_client.post("/servers/ha/maintenance/begin", data={"down": "1"})
        r = logged_in_client.post("/servers/ha/maintenance/handover", follow_redirects=True)
        assert r.status_code == 200
        # THE direction: the command goes to Standby (keeps serving), never to Primary (going down)
        assert kea.sent == [("ha-maintenance-start", "Standby")]
        with logged_in_client.session_transaction() as sess:
            assert sess["ha_maint"]["step"] == "handover"
        with db.cursor() as cur:
            cur.execute(
                "SELECT action, entity FROM audit_log WHERE action='ha_maintenance_handover' ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
        assert row and row["entity"] == "Primary / Standby"

    def test_handover_refused_by_kea_is_a_flash(self, logged_in_client, monkeypatch):
        kea = _Kea()
        kea.refuse.add("ha-maintenance-start")
        _wire(monkeypatch, kea)
        logged_in_client.post("/servers/ha/maintenance/begin", data={"down": "1"})
        r = logged_in_client.post("/servers/ha/maintenance/handover", follow_redirects=True)
        assert b"partner is unreachable" in r.data
        with logged_in_client.session_transaction() as sess:
            assert sess["ha_maint"]["step"] == "preflight"

    def test_failed_preflight_blocks_handover(self, logged_in_client, monkeypatch):
        from jen.services import health

        kea = _Kea()
        _wire(monkeypatch, kea)
        monkeypatch.setattr(
            health,
            "run_checks",
            lambda ctx=None: [
                health.Check("kea_reachable", "Kea servers reachable", "kea", "fail", "Standby not reachable")
            ],
        )
        logged_in_client.post("/servers/ha/maintenance/begin", data={"down": "1"})
        r = logged_in_client.post("/servers/ha/maintenance/handover", follow_redirects=True)
        assert b"preflight check failed" in r.data and kea.sent == []

    def test_status_partial_advances_to_work_then_cancel_goes_to_partner(self, logged_in_client, monkeypatch):
        kea = _Kea()
        _wire(monkeypatch, kea)
        logged_in_client.post("/servers/ha/maintenance/begin", data={"down": "1"})
        logged_in_client.post("/servers/ha/maintenance/handover")
        body = logged_in_client.get("/servers/ha/maintenance/status?partial=1").data.decode()
        assert "Waiting for Kea" in body
        kea.states = {"Primary": "in-maintenance", "Standby": "partner-in-maintenance"}
        body = logged_in_client.get("/servers/ha/maintenance/status?partial=1").data.decode()
        assert "in-maintenance and can be shut down" in body and "Cancel handover" in body
        js = logged_in_client.get("/servers/ha/maintenance/status").get_json()
        assert js["step"] == "work" and js["can_cancel"] is True and js["up"]["state"] == "partner-in-maintenance"
        r = logged_in_client.post("/servers/ha/maintenance/cancel", follow_redirects=True)
        assert r.status_code == 200 and kea.sent[-1] == ("ha-maintenance-cancel", "Standby")
        assert logged_in_client.get("/servers/ha/maintenance/status").get_json() == {"active": False}

    def test_partner_down_hides_cancel_and_back_completes(self, logged_in_client, monkeypatch):
        kea = _Kea()
        _wire(monkeypatch, kea)
        logged_in_client.post("/servers/ha/maintenance/begin", data={"down": "1"})
        logged_in_client.post("/servers/ha/maintenance/handover")
        kea.states = {"Primary": "in-maintenance", "Standby": "partner-in-maintenance"}
        logged_in_client.get("/servers/ha/maintenance/status?partial=1")  # → work
        kea.states = {"Primary": None, "Standby": "partner-down"}
        body = logged_in_client.get("/servers/ha/maintenance/status?partial=1").data.decode()
        assert "no longer applies" in body and "Cancel handover" not in body and "is back" in body
        logged_in_client.post("/servers/ha/maintenance/back")
        body = logged_in_client.get("/servers/ha/maintenance/status?partial=1").data.decode()
        assert "Waiting for Primary" in body
        kea.states = {"Primary": "hot-standby", "Standby": "hot-standby"}
        body = logged_in_client.get("/servers/ha/maintenance/status?partial=1").data.decode()
        assert "Both back to normal" in body and "Repeat for Standby" in body and "down=2" in body
        r = logged_in_client.post("/servers/ha/maintenance/finish", follow_redirects=True)
        assert r.status_code == 200
        with logged_in_client.session_transaction() as sess:
            assert "ha_maint" not in sess

    def test_timeout_names_the_stuck_side(self, logged_in_client, monkeypatch):
        kea = _Kea()
        _wire(monkeypatch, kea)
        logged_in_client.post("/servers/ha/maintenance/begin", data={"down": "1"})
        logged_in_client.post("/servers/ha/maintenance/handover")
        with logged_in_client.session_transaction() as sess:
            sess["ha_maint"]["step_at"] = (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
        body = logged_in_client.get("/servers/ha/maintenance/status?partial=1").data.decode()
        assert "No handover after 60s" in body and "Standby is hot-standby, not partner-in-maintenance" in body

    def test_status_json_per_server(self, logged_in_client, monkeypatch):
        kea = _Kea({"Primary": "hot-standby", "Standby": None})
        _wire(monkeypatch, kea)
        js = logged_in_client.get("/servers/ha/1/status.json").get_json()
        assert js["reachable"] is True and js["local"]["state"] == "hot-standby"
        js = logged_in_client.get("/servers/ha/2/status.json").get_json()
        assert js == {"reachable": False, "id": 2, "name": "Standby"}
        assert logged_in_client.get("/servers/ha/9/status.json").status_code == 404
