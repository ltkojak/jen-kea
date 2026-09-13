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
        # v5.28.1 (Q26, A1) — the message must name all three groups
        # CORRECTLY: kea-a's own REVERT failed, so it still has the NEW
        # config (not "the old one", which the pre-A1 wording said);
        # nothing was successfully rolled back ("(none)"); kea-b's own
        # apply failed first, so it was never touched at all. Getting
        # this backwards is exactly the bug an operator would follow
        # into restoring the wrong servers.
        (rollback_line,) = [text for _t, text in result.lines if "ROLLBACK FAILED" in text]
        assert "kea-a still have the NEW config" in rollback_line
        assert "(none) were rolled back" in rollback_line
        assert "kea-b was never changed" in rollback_line

    def test_revert_that_succeeds_but_whose_restart_fails_is_a_warning_line(self, fake):
        """v5.28.1 (Q26, A1) — a revert's own service_action(restart)
        result used to be silently ignored."""
        fake.responses["test-config"] = {"ok": True}

        def apply_resp(server, op, payload):
            if server["id"] == 1:
                return {"ok": True, "sha256": "new-a", "helper_version": 2}
            return {"ok": False, "error": "conflict", "helper_version": 2}

        fake.responses["apply-config"] = apply_resp
        fake.responses["service"] = {"ok": False, "error": "systemctl failed", "detail": "unit not found"}

        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "aborted"  # the revert itself succeeded — no ROLLBACK FAILED
        warning_lines = [text for t, text in result.lines if t == "warning"]
        assert len(warning_lines) == 1
        assert warning_lines[0].startswith("⚠️ kea-a: rolled back, but Kea did not restart")


class TestApplyChangeV1SentinelRevert:
    def test_v1_hosts_revert_call_is_sentinel_guarded(self, fake):
        """v5.28.1 (Q26, A3) — a v1/legacy host's COMMIT apply now
        returns a canonical sentinel instead of no sha at all, so when
        a LATER server forces a revert, that revert's own apply_config
        call has something real to guard against ("is what I'm about
        to overwrite still what I just wrote") instead of an
        unguarded write. Uses an identity mutate (before_cfg ==
        after_cfg) so FakeHelper's static `configs` — which never
        actually changes when "apply-config" is called — still matches
        the sentinel on every reread, letting the guard genuinely pass
        and the revert's real apply-config call happen (this test's
        whole point)."""
        fake.helper_version = 1
        fake.shas.clear()  # no raw sha at all — read_config_versioned falls back to the sentinel
        fake.responses["test-config"] = {"ok": True}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}

        def mutate_noop(cfg):
            return cfg, "ok"

        def apply_resp(server, op, payload):
            if server["id"] == 1:
                return {"ok": True, "helper_version": 1}  # v1 — no raw sha in the reply
            return {"ok": False, "error": "conflict", "helper_version": 1}

        fake.responses["apply-config"] = apply_resp

        result = cs.apply_change("dhcp4", mutate_noop, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "aborted"  # A's revert succeeded — not rollback_failed
        read_calls_a = [p for (sid, op, p) in fake.calls if sid == 1 and op == "read-config"]
        apply_calls_a = [p for (sid, op, p) in fake.calls if sid == 1 and op == "apply-config"]
        # Plan's own read, the commit's pre-write sentinel guard, and
        # the revert's pre-write sentinel guard — three reads for one
        # server, each one the sentinel mechanism actually running.
        assert len(read_calls_a) == 3
        assert len(apply_calls_a) == 2  # the real commit, then the revert
        assert "expect_sha256" not in apply_calls_a[1], "a sentinel must never reach the real helper payload"


class TestApplyChangeSuccess:
    def test_all_servers_ok_restarts_both(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "new", "helper_version": 2}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}

        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "ok"
        assert fake.ops().count("service") == 2
        assert result.restart_failures == []

    def test_one_restart_failure_is_its_own_status_and_a_warning_line(self, fake):
        """v5.28.1 (Q26, A4) — a restart failure is a real operational
        problem, not a ✅ "success" line that reads as "done". The
        config DID apply cleanly (last_code stays "ok"), so callers
        still write Jen's own metadata — only the status distinguishes
        it from a fully clean run."""
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "new", "helper_version": 2}

        def service_resp(server, op, payload):
            if server["id"] == 1:
                return {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
            return {"ok": False, "error": "systemctl failed", "detail": "unit not found"}

        fake.responses["service"] = service_resp

        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "restart_failed"
        assert result.last_code == "ok"
        assert result.restart_failures == ["kea-b"]
        warning_lines = [text for t, text in result.lines if t == "warning"]
        assert len(warning_lines) == 1
        assert warning_lines[0].startswith("⚠️ kea-b:")
        assert "✅" not in warning_lines[0]
        assert not any(t == "success" and "kea-b" in text for t, text in result.lines)


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
