"""
tests/test_kea_changeset.py
────────────────────────────
v5.28.0 (Q24, C5) — jen/services/kea_changeset.py: the shared
multi-server change-set orchestration (plan → preflight → commit →
revert-on-failure → restart) that replaces the identical
read/mutate/apply/restart loop duplicated across subnets.py and
ddns.py. Driven entirely against tests/_kea_host_fakes.py::FakeHelper,
same convention as the route-level tests that already use it — no SSH,
no real Kea host.
"""

import copy

import pytest

from jen.services import kea_changeset as cs
from jen.services import kea_host
from tests._kea_host_fakes import FakeHelper

SERVER_A = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1"}
SERVER_B = {"id": 2, "name": "kea-b", "ssh_host": "10.0.0.2"}


@pytest.fixture
def fake(monkeypatch):
    f = FakeHelper()
    f.configs[(1, "dhcp4")] = {"Dhcp4": {"subnet4": [{"id": 1}]}}
    f.configs[(2, "dhcp4")] = {"Dhcp4": {"subnet4": [{"id": 1}]}}
    f.shas[(1, "dhcp4")] = "sha-a"
    f.shas[(2, "dhcp4")] = "sha-b"
    monkeypatch.setattr(kea_host, "helper_call", f.helper_call)
    monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "helper_status", dict)
    # No settings-table or history writes by default (matches
    # test_kea_host.py's own quiet_status convention) — a test that
    # wants to inspect config_revisions.record()'s calls re-patches it
    # itself, which simply overrides this one for that test.
    monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a, **k: None)
    monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
    return f


def _mutate_add_pool(cfg):
    c = copy.deepcopy(cfg)
    c["Dhcp4"]["subnet4"][0].setdefault("pools", []).append({"pool": "10.0.0.10 - 10.0.0.20"})
    return c, "ok"


class TestApplyChangePreflight:
    def test_one_server_failing_preflight_aborts_with_zero_applies(self, fake):
        fake.responses["test-config"] = lambda server, op, payload: (
            {"ok": True} if server["id"] == 1 else {"ok": False, "error": "testerror", "detail": "bad config"}
        )
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])
        assert result.status == "aborted"
        assert "apply-config" not in fake.ops()
        assert any("nothing was changed on any server" in text for _t, text in result.lines)


class TestApplyChangeRevert:
    def test_conflict_on_second_server_reverts_the_first(self, fake, monkeypatch):
        recorded = []
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: recorded.append((a, k)))
        fake.responses["test-config"] = {"ok": True}

        def apply_resp(server, op, payload):
            if server["id"] == 1:
                return {"ok": True, "sha256": "new-a", "helper_version": 2}
            return {"ok": False, "error": "conflict", "sha256": "live-b", "helper_version": 2}

        fake.responses["apply-config"] = apply_resp
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}

        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "aborted"
        apply_calls = [p for (_sid, op, p) in fake.calls if op == "apply-config"]
        assert len(apply_calls) == 3  # A's real apply, B's failed apply, A's revert
        assert apply_calls[2]["config"] == fake.configs[(1, "dhcp4")], "revert must restore A's before_cfg"
        rollback_records = [k for (_a, k) in recorded if k.get("source") == "rollback"]
        assert len(rollback_records) == 1
        assert any("reverted 1 server" in text for _t, text in result.lines)

    def test_revert_that_also_fails_is_rollback_failed(self, fake):
        fake.responses["test-config"] = {"ok": True}
        seen = {"n": 0}

        def apply_resp(server, op, payload):
            seen["n"] += 1
            if server["id"] == 1 and seen["n"] == 1:
                return {"ok": True, "sha256": "new-a", "helper_version": 2}
            return {"ok": False, "error": "conflict", "helper_version": 2}

        fake.responses["apply-config"] = apply_resp

        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "rollback_failed"
        assert any("ROLLBACK FAILED" in text for _t, text in result.lines)


class TestApplyChangeSuccess:
    def test_all_servers_ok_restarts_both(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "new", "helper_version": 2}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}

        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "ok"
        assert fake.ops().count("service") == 2
        assert result.restart_failures == []

    def test_one_restart_failure_still_reports_ok(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "new", "helper_version": 2}

        def service_resp(server, op, payload):
            if server["id"] == 1:
                return {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
            return {"ok": False, "error": "systemctl failed"}

        fake.responses["service"] = service_resp

        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "ok"
        assert result.restart_failures == ["kea-b"]


class TestApplyChangeSkipAndNoServers:
    def test_every_target_skipped_is_status_nothing(self, fake):
        def mutate_skip(cfg):
            return cfg, "notfound"

        result = cs.apply_change(
            "dhcp4",
            mutate_skip,
            "test change",
            servers=[SERVER_A, SERVER_B],
            code_messages={"notfound": "was not found"},
        )
        assert result.status == "nothing"
        assert "apply-config" not in fake.ops()
        assert all(t == "success" for t, _ in result.lines)
        assert all("was not found" in text for _t, text in result.lines)

    def test_no_ssh_configured_servers_is_noservers(self):
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[{"id": 9, "name": "no-ssh"}])
        assert result.status == "noservers"

    def test_a_non_ok_non_skip_code_aborts_before_any_read_config_of_later_servers_is_used(self, fake):
        """A code outside skip_codes (e.g. "exists") must abort the
        WHOLE change set rather than let one server proceed while
        another is silently excluded — the exact partial-failure shape
        this module exists to prevent."""

        def mutate_conflicting_id(cfg):
            return cfg, "exists"

        result = cs.apply_change(
            "dhcp4",
            mutate_conflicting_id,
            "test change",
            servers=[SERVER_A, SERVER_B],
            code_messages={"exists": 'a shared network named "x" already exists'},
        )
        assert result.status == "aborted"
        assert result.last_code == "exists"
        assert "apply-config" not in fake.ops()
        assert any('a shared network named "x" already exists' in text for _t, text in result.lines)


class TestApplyChangeExpectedShaOverride:
    def test_expected_sha_for_overrides_the_freshly_read_sha(self, fake):
        """edit_subnet_post's form carries a sha from when the form was
        OPENED, not the sha read moments ago inside this call."""
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "new", "helper_version": 2}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}

        cs.apply_change(
            "dhcp4",
            _mutate_add_pool,
            "test change",
            servers=[SERVER_A],
            expected_sha_for=lambda server: f"form-sha-{server['id']}",
        )
        apply_payload = fake.payload_for("apply-config")
        assert apply_payload["expect_sha256"] == "form-sha-1"


class TestApplyChangeExceptionHandling:
    def test_a_read_exception_aborts_with_the_exception_text_as_the_line(self, monkeypatch, fake):
        def boom(server, service):
            raise RuntimeError("connection refused")

        monkeypatch.setattr(kea_host, "read_config_versioned", boom)
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A])
        assert result.status == "aborted"
        assert any("connection refused" in text for _t, text in result.lines)
