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
import json

import pytest

from jen.services import kea_changeset as cs
from jen.services import kea_host
from jen.services.kea_changeset import ChangeSetResult
from tests._kea_host_fakes import FakeHelper


@pytest.fixture(autouse=True)
def _no_investigation_guard(monkeypatch):
    """`apply_config` asks `investigation_logging.file_write_refusal` before it sends anything (v5.68.0-beta.28, Q164), which reads Jen's settings. This file is about
    the change set's own plan / preflight / commit / revert, not that question - it has its own tests (tests/test_identity_guard.py, through the REAL change set and
    `apply_config`) - so it answers "no refusal" here and the tests need no database."""
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")


_REAL_RECORD_OUTCOME = cs.record_outcome
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
    # v5.65.1: the outcome note for the Servers page is a settings-table write; only the
    # tests that are about it (TestOutcomeReachesTheServersPage) turn it back on.
    monkeypatch.setattr(cs, "record_outcome", lambda *a, **k: None)
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

    def test_revert_that_succeeds_but_whose_restart_fails_is_rollback_failed(self, fake):
        """v5.28.1 (Q26, A1) made the revert's own restart result visible as a warning line; v5.65.6
        (Q95) makes it what it is: the server was put back on its old config and then would not
        start, so Kea is DOWN there. It used to be `aborted` + a warning, which record_outcome never
        persists, so the Servers banner never showed it."""
        fake.responses["test-config"] = {"ok": True}

        def apply_resp(server, op, payload):
            if server["id"] == 1:
                return {"ok": True, "sha256": "new-a", "helper_version": 2}
            return {"ok": False, "error": "conflict", "helper_version": 2}

        fake.responses["apply-config"] = apply_resp
        fake.responses["service"] = {"ok": False, "error": "systemctl failed", "detail": "unit not found"}

        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "rollback_failed"
        assert result.needs_hands == ["kea-a"]
        assert not [text for t, text in result.lines if t == "warning"], "no longer a warning line"
        error_text = " | ".join(text for t, text in result.lines if t == "error")
        assert "kea-a: previous config restored but Kea did not restart on it" in error_text
        assert "ROLLBACK FAILED" in error_text

    def test_mixed_one_revert_fails_another_restores_but_will_not_restart(self, fake):
        """Three servers: A and B commit, C fails. B's revert works but its restart fails; A's revert
        itself fails. Both are in needs_hands, and each is named for what actually happened to it."""
        server_c = {**SERVER_B, "id": 3, "name": "kea-c"}
        fake.configs[(3, "dhcp4")] = {"Dhcp4": {"subnet4": [{"id": 1}]}}
        fake.shas[(3, "dhcp4")] = "sha-c"
        fake.responses["test-config"] = {"ok": True}
        calls = {"a_applies": 0}

        def apply_resp(server, op, payload):
            if server["id"] == 3:
                return {"ok": False, "error": "conflict", "helper_version": 2}
            if server["id"] == 1:
                calls["a_applies"] += 1
                if calls["a_applies"] >= 2:  # A's revert
                    return {"ok": False, "error": "nope", "detail": "disk full", "helper_version": 2}
            return {"ok": True, "sha256": f"new-{server['id']}", "helper_version": 2}

        fake.responses["apply-config"] = apply_resp
        fake.responses["service"] = lambda server, op, payload: (
            {"ok": False, "error": "systemctl failed", "detail": "unit not found"}
            if server["id"] == 2
            else {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        )
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B, server_c])
        assert result.status == "rollback_failed"
        assert sorted(result.needs_hands) == ["kea-a", "kea-b"]
        text = " | ".join(t for _k, t in result.lines)
        assert "kea-a still have the NEW config" in text
        assert "kea-b: previous config restored but Kea did not restart on it" in text


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


class TestApplyChangeTlsPaths:
    """v5.29.0 (Q29) — `tls_paths` reaches both the preflight and the
    commit, so a missing https file on the host is a `tlsmissing`
    preflight abort (nothing written, nothing restarted), never a daemon
    restarted into a config it can't load."""

    TLS = [("/etc/kea/tls/dhcp4/ca.crt", "file"), ("/etc/kea/tls/dhcp4/server.crt", "file")]

    def test_paths_are_sent_with_test_and_apply(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "n", "helper_version": 4}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        result = cs.apply_change("dhcp4", _mutate_add_pool, "https socket", servers=[SERVER_A], tls_paths=self.TLS)
        assert result.status == "ok"
        expected = [list(p) for p in self.TLS]
        assert fake.payload_for("test-config")["tls_paths"] == expected
        assert fake.payload_for("apply-config")["tls_paths"] == expected

    def test_default_is_no_paths(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "n", "helper_version": 4}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        cs.apply_change("dhcp4", _mutate_add_pool, "plain", servers=[SERVER_A])
        assert fake.payload_for("test-config")["tls_paths"] == []

    def test_tlsmissing_at_preflight_aborts_before_any_write(self, fake):
        fake.responses["test-config"] = {"ok": False, "error": "tlsmissing", "path": "/etc/kea/tls/dhcp4/server.key"}
        result = cs.apply_change("dhcp4", _mutate_add_pool, "https socket", servers=[SERVER_A], tls_paths=self.TLS)
        assert result.status == "aborted"
        assert "apply-config" not in fake.ops() and "service" not in fake.ops()
        assert any("/etc/kea/tls/dhcp4/server.key" in text for _t, text in result.lines)


class TestTransportErrorsAreRecordedNotRaised:
    """v5.65.1 (Q90) - the system-boundary suite found `apply_change` raising
    NoValidConnectionsError when server B's SSH was refused AFTER preflight,
    leaving server A on the new config: kea_host.apply_config catches only the
    helper's own errors, so a paramiko/OS error escaped Phase 3 and skipped
    the revert. A transport error is now a recorded failure like any other."""

    def _ok(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}

    def test_second_server_refusing_the_connection_reverts_the_first(self, fake):
        self._ok(fake)

        def apply_resp(server, op, payload):
            if server["id"] == 2:
                raise OSError("Unable to connect to port 22 on 10.0.0.2")
            return {"ok": True, "sha256": "new-a", "helper_version": 2}

        fake.responses["apply-config"] = apply_resp
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "aborted"  # raised nothing, and A was put back
        applies = [(sid, p) for (sid, op, p) in fake.calls if op == "apply-config"]
        assert [sid for sid, _p in applies] == [1, 2, 1]
        assert applies[2][1]["config"] == fake.configs[(1, "dhcp4")], "A's revert restores its before_cfg"
        assert any("kea-b" in text and "Unable to connect" in text for _t, text in result.lines)
        assert any("reverted 1 server" in text for _t, text in result.lines)

    def test_a_revert_that_cannot_connect_is_rollback_failed_naming_the_server(self, fake):
        self._ok(fake)
        seen = {"n": 0}

        def apply_resp(server, op, payload):
            seen["n"] += 1
            if seen["n"] == 1:
                return {"ok": True, "sha256": "new-a", "helper_version": 2}
            raise OSError("connection reset")  # B's commit AND A's revert both raise

        fake.responses["apply-config"] = apply_resp
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "rollback_failed"
        assert result.needs_hands == ["kea-a"]
        (line,) = [text for _t, text in result.lines if "ROLLBACK FAILED" in text]
        assert "kea-a still have the NEW config" in line

    def test_a_preflight_that_raises_aborts_before_any_write(self, fake):
        def test_resp(server, op, payload):
            raise OSError("no route to host")

        fake.responses["test-config"] = test_resp
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])
        assert result.status == "aborted"
        assert "apply-config" not in fake.ops()

    def test_a_restart_that_raises_is_a_failed_restart(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "n", "helper_version": 2}

        def service_resp(server, op, payload):
            raise OSError("ssh gone")

        fake.responses["service"] = service_resp
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A])
        assert result.status == "rollback_failed"  # nothing restarts, so the second restart cannot either


class TestFailedRestartRollsBack:
    """v5.65.1 (Q90) - a restart that fails after the config was written used to
    leave the NEW config on disk and the daemon DOWN ("restart_failed": the config
    is still live, restart it by hand). Now every target is put back on its previous
    config and restarted again: `rolled_back`, or `rollback_failed` when that fails too."""

    def _base(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "new", "helper_version": 2}

    def _service(self, fake, failures):
        """`failures`: how many restarts of server 2 fail before it works (99 = never)."""
        n = {"b": 0}

        def resp(server, op, payload):
            if server["id"] == 2:
                n["b"] += 1
                if n["b"] <= failures:
                    return {"ok": False, "error": "systemctl failed", "detail": "Job for kea-dhcp4-server failed"}
            return {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}

        fake.responses["service"] = resp

    def test_one_failed_restart_puts_every_server_back_and_restarts_them(self, fake):
        self._base(fake)
        self._service(fake, failures=1)
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])

        assert result.status == "rolled_back"
        assert result.last_code == "restart-failed"  # code-gated callers must not treat it as done
        assert result.restart_failures == ["kea-b"] and result.needs_hands == []
        applies = [(sid, p) for (sid, op, p) in fake.calls if op == "apply-config"]
        assert [sid for sid, _p in applies] == [1, 2, 2, 1]  # commit A, commit B, revert B, revert A
        for sid, payload in applies[2:]:
            assert payload["config"] == fake.configs[(sid, "dhcp4")], "each revert restores its before_cfg"
        assert fake.ops().count("service") == 4  # 2 restarts on the new config, 2 on the old
        text = " | ".join(t for _k, t in result.lines)
        assert "Job for kea-dhcp4-server failed" in text and "NOT applied" in text
        assert not any(k == "success" for k, _t in result.lines)  # no "restarted" tick for a change that did not stand

    def test_a_second_failed_restart_is_rollback_failed_and_names_the_server(self, fake):
        self._base(fake)
        self._service(fake, failures=99)
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])
        assert result.status == "rollback_failed"
        assert result.needs_hands == ["kea-b"]
        assert any("ROLLBACK FAILED" in t and "kea-b" in t and "by hand" in t for _k, t in result.lines)

    def test_a_revert_that_cannot_be_written_is_rollback_failed(self, fake):
        fake.responses["test-config"] = {"ok": True}
        seen = {"n": 0}

        def apply_resp(server, op, payload):
            seen["n"] += 1
            if seen["n"] <= 2:  # both commits succeed
                return {"ok": True, "sha256": "new", "helper_version": 2}
            return {"ok": False, "error": "conflict", "helper_version": 2}  # the reverts do not

        fake.responses["apply-config"] = apply_resp
        self._service(fake, failures=1)
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])
        assert result.status == "rollback_failed"
        assert sorted(result.needs_hands) == ["kea-a", "kea-b"]

    def test_all_restarts_ok_is_unchanged(self, fake):
        self._base(fake)
        self._service(fake, failures=0)
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])
        assert result.status == "ok" and result.last_code == "ok"
        assert fake.ops().count("apply-config") == 2  # no revert traffic on the happy path

    def test_no_restart_requested_never_rolls_back(self, fake):
        self._base(fake)
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A], restart=False)
        assert result.status == "ok" and "service" not in fake.ops()

    def test_config_applied_event_only_when_the_change_stands(self, fake, monkeypatch):
        events = []
        monkeypatch.setattr(cs._events, "emit", lambda *a, **k: events.append((a, k)))
        self._base(fake)
        self._service(fake, failures=1)
        cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])
        assert events == []  # rolled back: nothing "applied"
        self._service(fake, failures=0)
        cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[SERVER_A, SERVER_B])
        assert len(events) == 2

    def test_not_applied_statuses_are_the_ones_callers_must_not_write_metadata_for(self):
        assert set(cs.NOT_APPLIED) == {"aborted", "rolled_back", "rollback_failed"}


class TestTwoServersWithOneNameAreTwoTargets:
    """v5.69.0-beta.3 (Q172, item 6): the restart, revert and needs-hands bookkeeping is keyed by server id, never by the free-text name. `restarts` was a dict
    keyed by `t.name`, so two servers called the same thing shared one entry and the second server's clean restart overwrote the first's failure: the change
    was reported ok with a daemon down."""

    A = {"id": 1, "name": "kea", "ssh_host": "10.0.0.1"}
    B = {"id": 2, "name": "kea", "ssh_host": "10.0.0.2"}

    def _failing_first(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "new", "helper_version": 2}

        def service(server, op, payload):
            if server["id"] == 1:
                return {"ok": False, "error": "systemctl failed", "detail": "Job failed"}
            return {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}

        fake.responses["service"] = service

    def test_a_failed_restart_on_the_first_of_two_same_named_servers_is_not_masked(self, fake):
        self._failing_first(fake)
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[self.A, self.B])
        assert result.status in ("rolled_back", "rollback_failed"), (
            "a failed restart was masked by the other server's name"
        )
        assert result.last_code == "restart-failed"
        assert not any(k == "success" for k, _t in result.lines)

    def test_the_server_that_needs_hands_is_named_and_identified_by_id(self, fake):
        self._failing_first(fake)  # its second restart (after the rollback) fails as well
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[self.A, self.B])
        assert result.status == "rollback_failed"
        assert result.needs_hands == ["kea"] and result.needs_hands_ids == [1]  # server 2 restarted fine both times

    def test_a_clean_run_on_the_second_same_named_server_does_not_resolve_the_first_ones_incident(self, monkeypatch):
        data = {}
        from jen.models import user as user_mod

        monkeypatch.setattr(user_mod, "get_global_setting", lambda k, d="": data.get(k, d))
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: data.__setitem__(k, v))
        monkeypatch.setattr(user_mod, "audit", lambda *a, **k: None)
        _REAL_RECORD_OUTCOME(
            cs.ChangeSetResult("rollback_failed", "x", [("error", "boom")], needs_hands=["kea"], needs_hands_ids=[1]),
            "dhcp4",
            "edit",
        )
        # server 2, also called "kea", changed and restarted cleanly: by NAME that would look like server 1 being covered
        _REAL_RECORD_OUTCOME(
            cs.ChangeSetResult("ok", "ok", [], covered=["kea"], covered_ids=[2]), "dhcp4", "edit again"
        )
        assert [i["needs_hands_ids"] for i in cs.attention()["incidents"]] == [[1]]
        _REAL_RECORD_OUTCOME(cs.ChangeSetResult("ok", "ok", [], covered=["kea"], covered_ids=[1]), "dhcp4", "fix")
        assert cs.attention() is None

    def test_the_not_found_line_names_the_configured_file_not_a_default(self, fake):
        """v5.69.0-beta.3 (Q172): the file Jen looks for on a server is the one configured for it; the line that says it is missing names that one."""
        server = {"id": 3, "name": "kea-c", "ssh_host": "10.0.0.3", "kea_conf": "/etc/kea/kea-dhcp4-prod.conf"}
        result = cs.apply_change(
            "dhcp4", _mutate_add_pool, "test change", servers=[server]
        )  # the fake has no config for server 3
        assert result.status == "aborted" and result.last_code == "notfound-conf"
        assert any("kea-dhcp4-prod.conf not found on this server" in text for _k, text in result.lines)
        assert fake.payload_for("read-config")["path"] == "/etc/kea/kea-dhcp4-prod.conf"

    def test_an_ok_run_reports_the_ids_it_covered(self, fake):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "new", "helper_version": 2}
        fake.responses["service"] = {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        result = cs.apply_change("dhcp4", _mutate_add_pool, "test change", servers=[self.A, self.B])
        assert result.status == "ok" and result.covered == ["kea", "kea"] and result.covered_ids == [1, 2]


class TestOutcomeReachesTheServersPage:
    """The Servers page keeps a rolled-back / failed-rollback outcome in front of the operator."""

    @pytest.fixture
    def store(self, monkeypatch):
        data = {}
        from jen.models import user as user_mod

        monkeypatch.setattr(user_mod, "get_global_setting", lambda k, d="": data.get(k, d))
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: data.__setitem__(k, v))
        monkeypatch.setattr(cs, "record_outcome", _REAL_RECORD_OUTCOME)
        return data

    def test_a_failed_rollback_is_recorded_and_a_later_ok_clears_it(self, fake, store):
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "n", "helper_version": 2}
        fake.responses["service"] = {"ok": False, "error": "x", "detail": "boom"}
        cs.apply_change("dhcp4", _mutate_add_pool, "add a pool", servers=[SERVER_A])
        note = cs.attention()["incidents"][0]
        assert note["status"] == "rollback_failed" and note["summary"] == "add a pool"
        assert note["needs_hands"] == ["kea-a"]

        fake.responses["service"] = {"ok": True, "unit": "u", "state": "active"}
        cs.apply_change("dhcp4", _mutate_add_pool, "add a pool", servers=[SERVER_A])
        assert cs.attention() is None

    def test_dismiss_clears_it(self, store):
        store[cs.ATTENTION_KEY] = (
            '{"status": "rolled_back", "service": "dhcp4", "at": "2026-01-01T00:00:00+00:00"}'  # the pre-5.65.10 single-note shape reads as a list of one
        )
        assert cs.attention() == {
            "incidents": [{"status": "rolled_back", "service": "dhcp4", "at": "2026-01-01T00:00:00+00:00"}],
            "unrecognised": 0,
        }
        cs.clear_attention()
        assert cs.attention() is None

    def test_recording_never_raises(self, monkeypatch):
        from jen.models import user as user_mod

        def boom(*a, **k):
            raise RuntimeError("db down")

        monkeypatch.setattr(user_mod, "set_global_setting", boom)
        monkeypatch.setattr(user_mod, "get_global_setting", boom)
        cs.record_outcome(cs.ChangeSetResult("rollback_failed", "x"), "dhcp4", "s")  # no raise
        assert cs.attention() is None


class TestARollbackFailedBannerIsClearedOnlyByARunThatCoveredTheServer:
    """v5.65.8 (Q97 d): the banner is the only persistent sign that a daemon may be stopped, and it used
    to be cleared by ANY later ok run - a DDNS save, or an edit of a server that was never in trouble."""

    @pytest.fixture
    def store(self, monkeypatch):
        data = {}
        from jen.models import user as user_mod

        monkeypatch.setattr(user_mod, "get_global_setting", lambda k, d="": data.get(k, d))
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: data.__setitem__(k, v))
        monkeypatch.setattr(cs, "record_outcome", _REAL_RECORD_OUTCOME)
        return data

    def _fail_a(self, fake):
        """kea-a's rollback fails, so `needs_hands == ['kea-a']` is recorded."""
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "n", "helper_version": 2}
        fake.responses["service"] = {"ok": False, "error": "x", "detail": "boom"}
        cs.apply_change("dhcp4", _mutate_add_pool, "add a pool", servers=[SERVER_A])
        assert cs.attention()["incidents"][-1]["needs_hands"] == ["kea-a"]
        fake.responses["service"] = {"ok": True, "unit": "u", "state": "active"}

    def test_an_ok_run_that_never_touched_the_server_leaves_it(self, fake, store):
        self._fail_a(fake)
        cs.apply_change("dhcp4", _mutate_add_pool, "edit b", servers=[SERVER_B])
        assert cs.attention() is not None and cs.attention()["incidents"][0]["status"] == "rollback_failed"

    def test_an_ok_run_of_another_service_leaves_it(self, fake, store):
        self._fail_a(fake)
        fake.configs[(1, "dhcp6")] = {"Dhcp6": {"subnet6": [{"id": 1}]}}
        fake.shas[(1, "dhcp6")] = "sha-a6"

        def mutate6(cfg):
            import copy as _copy

            c = _copy.deepcopy(cfg)
            c["Dhcp6"]["valid-lifetime"] = 7200
            return c, "ok"

        result = cs.apply_change("dhcp6", mutate6, "edit v6", servers=[SERVER_A])
        assert result.status == "ok" and cs.attention() is not None

    def test_an_ok_run_that_covered_the_server_clears_it(self, fake, store):
        self._fail_a(fake)
        result = cs.apply_change("dhcp4", _mutate_add_pool, "fix a", servers=[SERVER_A, SERVER_B])
        assert result.status == "ok" and result.covered == ["kea-a", "kea-b"]
        assert cs.attention() is None

    def test_a_rolled_back_note_is_still_cleared_by_any_clean_run(self, fake, store):
        store[cs.ATTENTION_KEY] = '{"status": "rolled_back", "service": "dhcp4", "at": "2026-01-01T00:00:00+00:00"}'
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "n", "helper_version": 2}
        fake.responses["service"] = {"ok": True, "unit": "u", "state": "active"}
        cs.apply_change("dhcp4", _mutate_add_pool, "edit b", servers=[SERVER_B])
        assert cs.attention() is None


class TestRollbacksAreAudited:
    """v5.65.8 (Q97 e): only DISMISSING the notice used to leave a mark in the audit log."""

    def test_the_outcome_writes_an_audit_entry(self, fake, monkeypatch):
        from jen.models import user as user_mod

        seen = []
        monkeypatch.setattr(user_mod, "get_global_setting", lambda k, d="": d)
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: None)
        monkeypatch.setattr(
            user_mod, "audit", lambda action, entity, details="": seen.append((action, entity, details))
        )
        monkeypatch.setattr(cs, "record_outcome", _REAL_RECORD_OUTCOME)
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "n", "helper_version": 2}
        fake.responses["service"] = {"ok": False, "error": "x", "detail": "boom"}
        cs.apply_change("dhcp4", _mutate_add_pool, "add a pool", servers=[SERVER_A])
        assert seen and seen[0][0] == "CONFIG_ROLLBACK_FAILED" and seen[0][1] == "dhcp4"
        assert "kea-a" in seen[0][2] and "add a pool" in seen[0][2]


class TestIncidentsAreAListNotASlot:
    """v5.65.10 (Q99 a): the note kept ONE outcome, so a later rolled_back overwrote an unresolved
    rollback_failed (its needs_hands emptied, the next clean run cleared the banner while a daemon was
    stopped), and a second rollback_failed replaced the first one's servers."""

    @pytest.fixture
    def store(self, monkeypatch):
        data = {}
        from jen.models import user as user_mod

        monkeypatch.setattr(user_mod, "get_global_setting", lambda k, d="": data.get(k, d))
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: data.__setitem__(k, v))
        monkeypatch.setattr(user_mod, "audit", lambda *a, **k: None)
        return data

    @staticmethod
    def _failed(*servers):
        return cs.ChangeSetResult("rollback_failed", "x", [("error", "boom")], needs_hands=list(servers))

    @staticmethod
    def _back(*servers):
        return cs.ChangeSetResult("rolled_back", "restart-failed", [("error", "nope")], list(servers))

    @staticmethod
    def _ok(*servers):
        return cs.ChangeSetResult("ok", "ok", [], covered=list(servers))

    def _statuses(self):
        note = cs.attention()
        return [(i["status"], tuple(i["needs_hands"])) for i in note["incidents"]] if note else []

    def test_a_later_rolled_back_never_replaces_a_failed_rollback(self, store):
        _REAL_RECORD_OUTCOME(self._failed("kea-a"), "dhcp4", "edit a")
        _REAL_RECORD_OUTCOME(self._back("kea-b"), "dhcp4", "edit b")
        assert self._statuses() == [("rollback_failed", ("kea-a",)), ("rolled_back", ())]

    def test_the_next_clean_run_clears_the_rolled_back_incident_but_not_the_failed_one(self, store):
        _REAL_RECORD_OUTCOME(self._failed("kea-a"), "dhcp4", "edit a")
        _REAL_RECORD_OUTCOME(self._back("kea-b"), "dhcp4", "edit b")
        _REAL_RECORD_OUTCOME(self._ok("kea-b"), "dhcp4", "edit b again")
        assert self._statuses() == [("rollback_failed", ("kea-a",))]

    def test_two_failed_rollbacks_are_both_shown(self, store):
        _REAL_RECORD_OUTCOME(self._failed("kea-a"), "dhcp4", "edit a")
        _REAL_RECORD_OUTCOME(self._failed("kea-b"), "dhcp4", "edit b")
        assert self._statuses() == [("rollback_failed", ("kea-a",)), ("rollback_failed", ("kea-b",))]

    def test_a_clean_run_covering_only_one_leaves_the_other(self, store):
        _REAL_RECORD_OUTCOME(self._failed("kea-a"), "dhcp4", "edit a")
        _REAL_RECORD_OUTCOME(self._failed("kea-b"), "dhcp4", "edit b")
        _REAL_RECORD_OUTCOME(self._ok("kea-b"), "dhcp4", "fix b")
        assert self._statuses() == [("rollback_failed", ("kea-a",))]

    def test_a_clean_run_covering_both_clears_the_banner(self, store):
        _REAL_RECORD_OUTCOME(self._failed("kea-a"), "dhcp4", "edit a")
        _REAL_RECORD_OUTCOME(self._failed("kea-b"), "dhcp4", "edit b")
        _REAL_RECORD_OUTCOME(self._ok("kea-a", "kea-b"), "dhcp4", "fix both")
        assert cs.attention() is None and store[cs.ATTENTION_KEY] == ""

    def test_a_run_of_another_service_resolves_nothing_that_failed(self, store):
        _REAL_RECORD_OUTCOME(self._failed("kea-a"), "dhcp4", "edit a")
        _REAL_RECORD_OUTCOME(self._ok("kea-a"), "dhcp6", "edit v6")
        assert self._statuses() == [("rollback_failed", ("kea-a",))]

    def test_the_same_trouble_again_refreshes_its_incident_instead_of_piling_up(self, store):
        for _ in range(5):
            _REAL_RECORD_OUTCOME(self._failed("kea-a"), "dhcp4", "edit a")
        assert self._statuses() == [("rollback_failed", ("kea-a",))]

    def test_the_list_is_bounded_and_keeps_failed_rollbacks_over_clean_ones(self, store):
        _REAL_RECORD_OUTCOME(self._failed("kea-a"), "dhcp4", "edit a")
        for i in range(cs._MAX_INCIDENTS + 5):
            _REAL_RECORD_OUTCOME(self._back(f"kea-{i}"), f"svc{i}", f"edit {i}")
        statuses = self._statuses()
        assert len(statuses) == cs._MAX_INCIDENTS and ("rollback_failed", ("kea-a",)) in statuses

    def test_21_unresolved_failed_rollbacks_are_all_kept_past_the_soft_cap(self, store):
        """v5.66.0-beta.3 (Q105 a) — the invariant made literal: an unresolved rollback_failed is
        NEVER evicted just to stay under _MAX_INCIDENTS (20 here), even when every entry on the
        list is one — the list is allowed to exceed the soft cap instead."""
        for i in range(cs._MAX_INCIDENTS + 1):
            _REAL_RECORD_OUTCOME(self._failed(f"kea-{i}"), f"svc{i}", f"edit {i}")
        statuses = self._statuses()
        assert len(statuses) == cs._MAX_INCIDENTS + 1
        assert all(status == "rollback_failed" for status, _ in statuses)

    def test_a_mix_over_the_cap_only_ever_evicts_rolled_back_entries(self, store):
        """21 unresolved failed rollbacks (already over the soft cap on their own), then 5 clean
        rollbacks recorded afterward — each clean one is evicted immediately (there's always a
        non-rollback_failed entry to drop), so all 21 failed incidents survive and none of the 5
        clean ones do."""
        for i in range(cs._MAX_INCIDENTS + 1):
            _REAL_RECORD_OUTCOME(self._failed(f"kea-{i}"), f"svc{i}", f"edit {i}")
        for i in range(5):
            _REAL_RECORD_OUTCOME(self._back(f"clean-{i}"), f"cleansvc{i}", f"clean edit {i}")
        statuses = self._statuses()
        assert len([s for s in statuses if s[0] == "rollback_failed"]) == cs._MAX_INCIDENTS + 1
        assert len([s for s in statuses if s[0] == "rolled_back"]) == 0

    def test_the_hard_ceiling_drops_the_oldest_once_it_is_exceeded(self, store, monkeypatch):
        """The hard ceiling is the ONE real bound — past it, the oldest unresolved incidents are
        dropped after all, oldest first, so the stored note itself never grows forever."""
        monkeypatch.setattr(cs, "_INCIDENTS_HARD_CEILING", 3)
        for i in range(5):
            _REAL_RECORD_OUTCOME(self._failed(f"kea-{i}"), f"svc{i}", f"edit {i}")
        statuses = self._statuses()
        assert statuses == [
            ("rollback_failed", ("kea-2",)),
            ("rollback_failed", ("kea-3",)),
            ("rollback_failed", ("kea-4",)),
        ]

    def test_the_hard_ceiling_logs_an_error(self, store, monkeypatch, caplog):
        monkeypatch.setattr(cs, "_INCIDENTS_HARD_CEILING", 3)
        with caplog.at_level("ERROR"):
            for i in range(5):
                _REAL_RECORD_OUTCOME(self._failed(f"kea-{i}"), f"svc{i}", f"edit {i}")
        assert "hard ceiling" in caplog.text

    def test_under_the_hard_ceiling_no_error_is_logged(self, store, monkeypatch, caplog):
        monkeypatch.setattr(cs, "_INCIDENTS_HARD_CEILING", 3)
        with caplog.at_level("ERROR"):
            for i in range(3):
                _REAL_RECORD_OUTCOME(self._failed(f"kea-{i}"), f"svc{i}", f"edit {i}")
        assert "hard ceiling" not in caplog.text

    def test_a_note_recorded_before_the_upgrade_is_read_and_then_extended(self, store):
        store[cs.ATTENTION_KEY] = (
            '{"status": "rollback_failed", "service": "dhcp4", "at": "2026-01-01T00:00:00+00:00", "needs_hands": ["kea-a"], "summary": "old"}'
        )
        _REAL_RECORD_OUTCOME(self._back("kea-b"), "dhcp4", "edit b")
        assert self._statuses() == [("rollback_failed", ("kea-a",)), ("rolled_back", ())]

    def test_end_to_end_a_failed_rollback_on_a_then_a_rolled_back_change_on_b(self, fake, store, monkeypatch):
        monkeypatch.setattr(cs, "record_outcome", _REAL_RECORD_OUTCOME)
        fake.responses["test-config"] = {"ok": True}
        fake.responses["apply-config"] = {"ok": True, "sha256": "n", "helper_version": 2}
        fake.responses["service"] = {"ok": False, "error": "x", "detail": "boom"}
        cs.apply_change("dhcp4", _mutate_add_pool, "add a pool", servers=[SERVER_A])
        n = {"b": 0}

        def resp(server, op, payload):
            if server["id"] == 2:
                n["b"] += 1
                if n["b"] == 1:
                    return {"ok": False, "error": "systemctl failed", "detail": "Job failed"}
            return {"ok": True, "unit": "u", "state": "active"}

        fake.responses["service"] = resp
        result = cs.apply_change("dhcp4", _mutate_add_pool, "edit b", servers=[SERVER_B])
        assert result.status == "rolled_back"
        assert self._statuses() == [("rollback_failed", ("kea-a",)), ("rolled_back", ())]


@pytest.fixture(autouse=True)
def _the_locked_update_runs_over_each_tests_own_settings_stub(monkeypatch):
    """Q188 (AD5): the incident note is now written through `user.update_global_setting` (one locked transaction). These pure tests stub `get_global_setting` / `set_global_setting` per test; the
    transaction is replaced by the same read-mutate-write over whatever the test installed, so a stub that answers False or raises still fails the write. The REAL transaction is exercised by the
    database tests (`tests/test_incident_store_locking.py`)."""
    from jen.models import user as user_mod

    def update(key, mutate):
        current = user_mod.get_global_setting(key, "")
        try:
            new = mutate(current or "")
        except (
            Exception
        ):  # the real transaction rolls back and answers False (Q189: a note that is not a note is refused)
            return False
        return not (new is not None and new != current and user_mod.set_global_setting(key, new) is False)

    monkeypatch.setattr(user_mod, "update_global_setting", update)


class TestAnUnprovedRecoveryIsAPersistentIncident:
    """v5.69.0-beta.18 (Q187, AC3): a direct-socket recovery Jen could not PROVE is kept in front of the operator in a category - on Servers and in Health - until a verified recovery of THAT
    server and service clears it or a superadmin acknowledges it. An unrelated change never clears it; it is a settings row, so it survives a restart; it carries no socket entry."""

    @pytest.fixture
    def store(self, monkeypatch):
        data = {}
        from jen.models import user as user_mod

        monkeypatch.setattr(user_mod, "get_global_setting", lambda k, d="", strict=False: data.get(k, d))
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: data.__setitem__(k, v))
        monkeypatch.setattr(user_mod, "audit", lambda *a, **k: None)
        monkeypatch.setattr(cs, "record_outcome", _REAL_RECORD_OUTCOME)
        return data

    def test_the_eight_categories_are_the_ones_the_q_names(self):
        assert set(cs.ATTENTION_CATEGORIES) == {
            "remote-unknown",
            "restored-restart-unverified",
            "restart-failed",
            "tls-not-restored",
            "tls-local-stale",
            "restored-endpoint-unreachable",
            "probe-pending",
            "aborted",
        }

    @pytest.mark.parametrize("category", sorted(cs.ATTENTION_CATEGORIES))
    def test_every_category_is_recorded_with_its_server_service_and_a_fixed_sentence(self, store, category):
        assert cs.record_attention(
            1, "dhcp4", "setup of the https 10.0.0.5:8014 control socket", category, server_name="kea-a"
        )
        (incident,) = cs.attention()["incidents"]
        assert incident["kind"] == "attention" and incident["category"] == category and incident["status"] == category
        assert (incident["server_id"], incident["service"], incident["server_name"]) == (1, "dhcp4", "kea-a")
        assert incident["detail"] == cs.ATTENTION_CATEGORIES[category]
        assert "password" not in json.dumps(incident).lower() and "authentication" not in json.dumps(incident)

    def test_an_unknown_category_is_a_programming_error(self, store):
        with pytest.raises(ValueError):
            cs.record_attention(1, "dhcp4", "x", "made-up")

    def test_the_same_trouble_again_refreshes_it_and_a_different_one_is_added(self, store):
        cs.record_attention(1, "dhcp4", "first", "aborted")
        cs.record_attention(1, "dhcp4", "second", "aborted")
        cs.record_attention(1, "dhcp4", "third", "probe-pending")
        cs.record_attention(2, "dhcp4", "other server", "aborted")
        got = [(i["server_id"], i["category"], i["summary"]) for i in cs.attention()["incidents"]]
        assert got == [(1, "aborted", "second"), (1, "probe-pending", "third"), (2, "aborted", "other server")]

    def test_an_unrelated_successful_change_never_clears_it(self, store):
        cs.record_attention(1, "dhcp4", "x", "remote-unknown")
        ok = cs.ChangeSetResult("ok", "ok", covered=["kea-a"], covered_ids=[1])
        cs.record_outcome(ok, "dhcp4", "a pool edit on the same server and service")
        cs.record_outcome(ok, "dhcp6", "anything")
        assert [i["category"] for i in cs.attention()["incidents"]] == ["remote-unknown"]

    def test_a_verified_recovery_of_that_server_and_service_clears_only_its_own(self, store):
        cs.record_attention(1, "dhcp4", "x", "probe-pending")
        cs.record_attention(1, "dhcp6", "y", "probe-pending")
        cs.record_attention(2, "dhcp4", "z", "probe-pending")
        store[cs.ATTENTION_KEY] = json.dumps(
            {
                "incidents": cs.attention()["incidents"]
                + [
                    {
                        "status": "rollback_failed",
                        "service": "dhcp4",
                        "at": "2026-01-01T00:00:00+00:00",
                        "needs_hands": ["kea-a"],
                    }
                ]
            }
        )
        assert cs.resolve_attention(1, "dhcp4") == 1
        left = [(i.get("server_id"), i.get("service"), i["status"]) for i in cs.attention()["incidents"]]
        assert left == [
            (1, "dhcp6", "probe-pending"),
            (2, "dhcp4", "probe-pending"),
            (None, "dhcp4", "rollback_failed"),
        ]

    def test_it_survives_a_restart_because_it_is_a_settings_row(self, store):
        cs.record_attention(1, "dhcp4", "x", "tls-not-restored", server_name="kea-a")
        again = json.loads(store[cs.ATTENTION_KEY])  # what a new process reads from the table
        assert again["incidents"][0]["category"] == "tls-not-restored"

    def test_a_superadmins_acknowledgement_clears_matching_incidents_only(self, store):
        cs.record_attention(1, "dhcp4", "x", "aborted")
        cs.record_attention(1, "dhcp4", "y", "probe-pending")
        cs.record_attention(2, "dhcp4", "z", "aborted")
        assert cs.acknowledge_recovery(1, "dhcp4", "aborted") == 1
        assert cs.acknowledge_recovery(2) == 1
        assert [(i["server_id"], i["category"]) for i in cs.attention()["incidents"]] == [(1, "probe-pending")]

    def test_the_old_dismiss_leaves_the_recovery_incidents_and_clear_attention_still_clears_all(self, store):
        cs.record_attention(1, "dhcp4", "x", "aborted")
        store[cs.ATTENTION_KEY] = json.dumps(
            {
                "incidents": cs.attention()["incidents"]
                + [{"status": "rolled_back", "service": "dhcp4", "at": "2026-01-01T00:00:00+00:00"}]
            }
        )
        cs.dismiss_rollback_notes()
        assert [i["status"] for i in cs.attention()["incidents"]] == ["aborted"]
        cs.clear_attention()
        assert cs.attention() is None

    def test_recording_never_raises_and_says_whether_it_stored(self, monkeypatch):
        from jen.models import user as user_mod

        def boom(*a, **k):
            raise RuntimeError("db down")

        monkeypatch.setattr(user_mod, "set_global_setting", boom)
        monkeypatch.setattr(user_mod, "get_global_setting", boom)
        assert cs.record_attention(1, "dhcp4", "x", "aborted") is False
        assert cs.resolve_attention(1, "dhcp4") == 0 and cs.acknowledge_recovery() is None

    def test_a_write_that_did_not_happen_is_not_reported_as_one_that_did(self, store, monkeypatch):
        """Second pass (finding 5): the REAL `set_global_setting` never raises - it logs and answers False. The three writers believed it."""
        from jen.models import user as user_mod

        cs.record_attention(1, "dhcp4", "x", "aborted")
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: False)
        assert cs.record_attention(1, "dhcp4", "y", "probe-pending") is False
        assert cs.resolve_attention(1, "dhcp4") == 0
        assert cs.acknowledge_recovery(1) is None
        assert [i["category"] for i in cs.attention()["incidents"]] == ["aborted"], "still stored, still shown"

    def test_an_unresolved_recovery_incident_is_never_evicted_by_the_soft_cap(self, store):
        """Second pass (finding 6): the cap protected only `rollback_failed`; a recovery incident means the daemon may be stopped."""
        cs.record_attention(1, "dhcp4", "x", "restart-failed")
        for n in range(25):
            cs.record_outcome(cs.ChangeSetResult("rolled_back", "x", [], [f"kea-{n}"]), "dhcp4", f"s{n}")
        assert "restart-failed" in [i.get("category") for i in cs.attention()["incidents"]]

    def test_an_unreadable_note_is_not_an_empty_one(self, store, monkeypatch):
        """Second pass (finding 9)."""
        from jen.services import health

        store[cs.ATTENTION_KEY] = "{not json"
        with pytest.raises(ValueError):
            cs.recovery_incidents(strict=True)
        assert health._direct_socket_recovery({}).status == "skip"
        store[cs.ATTENTION_KEY] = ""
        assert cs.recovery_incidents(strict=True) == [] and health._direct_socket_recovery({}).status == "ok"
        cs.record_attention(1, "dhcp4", "x", "aborted", server_name="kea-a")
        assert health._direct_socket_recovery({}).status == "fail", (
            "aborted: the daemon may still carry the failed change"
        )

    def test_health_shows_it_failing_for_an_unknown_or_stopped_daemon_and_warning_for_a_pending_probe(self, store):
        from jen.services import health

        assert health._direct_socket_recovery({}).status == "ok"
        cs.record_attention(1, "dhcp4", "x", "probe-pending", server_name="kea-a")
        assert health._direct_socket_recovery({}).status == "warn"
        cs.record_attention(1, "dhcp4", "y", "remote-unknown", server_name="kea-a")
        check = health._direct_socket_recovery({})
        assert check.status == "fail" and "kea-a (dhcp4)" in check.detail and check.fix_url == "/servers"


class TestTheIncidentNoteQ188:
    """v5.69.0-beta.19 (Q188, AD3 / AD5 / AD9): the eight categories, ids compared as strings, a strict read that raises when the table cannot be read, Health's certificate row while a
    `tls-local-stale` incident stands. (The locked transaction itself is `tests/test_incident_store_locking.py`, against the real table.)"""

    @pytest.fixture
    def store(self, monkeypatch):
        data = {}
        from jen.models import user as user_mod

        monkeypatch.setattr(user_mod, "get_global_setting", lambda k, d="", strict=False: data.get(k, d))
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: data.__setitem__(k, v) or True)
        monkeypatch.setattr(user_mod, "audit", lambda *a, **k: None)
        return data

    def test_ids_are_compared_as_strings_by_every_clearing_path(self, store):
        cs.record_attention(1, "dhcp4", "x", "aborted")
        cs.record_attention(2, "dhcp4", "y", "aborted")
        assert cs.resolve_attention("1", "dhcp4") == 1, "a stored 1 and a posted '1' are one server"
        assert cs.acknowledge_recovery("2") == 1
        assert cs.attention() is None

    def test_the_soft_cap_never_evicts_a_recovery_incident_and_the_hard_ceiling_keeps_the_newest(
        self, store, monkeypatch
    ):
        def churn(start, count):
            for n in range(start, start + count):
                cs.record_outcome(
                    cs.ChangeSetResult("rolled_back", "x", [], needs_hands=[f"kea-{n}"], needs_hands_ids=[n]),
                    "dhcp4",
                    f"s{n}",
                )

        cs.record_attention(1, "dhcp4", "x", "restart-failed")
        churn(0, 25)
        kept = cs.attention()["incidents"]
        assert len(kept) == 20 and kept[0].get("category") == "restart-failed", (
            "the soft cap trims old rolled-back notes, never an unproved recovery"
        )
        monkeypatch.setattr(cs, "_INCIDENTS_HARD_CEILING", 5)
        churn(25, 3)
        kept = cs.attention()["incidents"]
        assert len(kept) == 5 and [i["summary"] for i in kept][-3:] == ["s25", "s26", "s27"], (
            "the hard ceiling keeps the NEWEST"
        )

    def test_a_strict_read_raises_when_the_table_cannot_be_read(self, monkeypatch):
        """The REAL `get_global_setting(strict=True)` reads the key itself; with the database down it raises (it never answers the cold-start default), so Health says 'unknown'."""
        from jen.models import db as db_mod
        from jen.services import health

        def down():
            raise RuntimeError("connection refused")

        monkeypatch.setattr(db_mod, "jen_db", down)
        with pytest.raises(ValueError):
            cs.recovery_incidents(strict=True)
        assert health._direct_socket_recovery({}).status == "skip"

    def test_the_certificate_row_says_the_copy_may_not_match_while_the_incident_stands(
        self, store, tmp_path, monkeypatch
    ):
        from jen.services import health, kea_tls

        monkeypatch.setattr(kea_tls, "SSL_DIR", str(tmp_path))
        kea_tls.ensure_ca()
        kea_tls.issue_client_cert()
        kea_tls.issue_server_cert({"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}, "dhcp4", "10.0.0.5")
        assert health._kea_tls_expiry({}).status == "ok"
        cs.record_attention(1, "dhcp4", "x", "tls-local-stale", server_name="kea-a")
        row = health._kea_tls_expiry({})
        assert (
            row.status == "warn"
            and "may not match the certificate on the host" in row.detail
            and "kea-a kea-dhcp4" in row.detail
        )
        cs.resolve_attention(1, "dhcp4")
        assert health._kea_tls_expiry({}).status == "ok"


class TestMalformedNote:
    """Q189 (AE3): the stored recovery note is text Jen may not be able to read as a note (a hand edit, a failed write, a bad restore). A writer that read it as "no incidents" wrote its new
    incident OVER the text; the next recording then silently made it a valid, one-incident note. Now every writer refuses it, byte for byte unchanged, and a superadmin sets it aside."""

    GOOD_LEGACY = json.dumps(
        {
            "status": "rolled_back",
            "service": "dhcp4",
            "summary": "an old change",
            "at": "2026-01-01T00:00:00+00:00",
            "needs_hands": [],
        }
    )
    BAD = [
        "{broken json!!!",
        "[]",
        '{"incidents": "x"}',
        '{"incidents": [1, 2]}',
        "{}",
        '{"foo": 1}',
        '"just a string"',
        "42",
    ]

    @pytest.fixture
    def store(self, monkeypatch):
        data = {}
        from jen.models import user as user_mod

        monkeypatch.setattr(user_mod, "get_global_setting", lambda k, d="", strict=False: data.get(k, d))
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: data.__setitem__(k, v))
        monkeypatch.setattr(user_mod, "audit", lambda *a, **k: None)
        monkeypatch.setattr(cs, "record_outcome", _REAL_RECORD_OUTCOME)
        return data

    def _record(self):
        return cs.record_attention(1, "dhcp4", "setup of a socket", "tls-not-restored", server_name="Primary")

    @pytest.mark.parametrize(
        "stored", [None, "", '{"incidents": []}'], ids=["missing row", "empty string", "valid empty"]
    )
    def test_nothing_recorded_yet_is_recorded(self, store, stored):
        if stored is not None:
            store[cs.ATTENTION_KEY] = stored
        assert self._record() is True
        assert [i["category"] for i in cs.recovery_incidents(strict=True)] == ["tls-not-restored"]

    def test_a_valid_note_is_appended_to(self, store):
        assert self._record() is True
        assert cs.record_attention(2, "dhcp4", "another", "restart-failed", server_name="Standby") is True
        assert sorted(i["server_id"] for i in cs.recovery_incidents(strict=True)) == [1, 2]

    def test_the_legacy_single_note_is_read_as_one_and_appended_to(self, store):
        store[cs.ATTENTION_KEY] = self.GOOD_LEGACY
        assert self._record() is True
        notes = cs._incidents_of(store[cs.ATTENTION_KEY], strict=True)
        assert [i.get("status") for i in notes] == ["rolled_back", "tls-not-restored"]

    @pytest.mark.parametrize("bad", BAD)
    def test_every_writer_refuses_it_and_the_stored_value_is_byte_equal_afterwards(self, store, bad):
        store[cs.ATTENTION_KEY] = bad
        result = ChangeSetResult("rolled_back", "x", [("error", "boom")], needs_hands=["kea-a"], needs_hands_ids=[1])
        assert self._record() is False
        assert cs.resolve_attention(1, "dhcp4") == 0
        assert cs.acknowledge_recovery(1, "dhcp4", "tls-not-restored") is None
        assert cs.record_outcome(result, "dhcp4", "a pool edit") is False
        assert cs.record_outcome(ChangeSetResult("ok", "ok", []), "dhcp4", "a pool edit") is False
        assert cs.dismiss_rollback_notes() is False
        assert cs.clear_attention() is False
        assert store[cs.ATTENTION_KEY] == bad, "NOT ONE writer touched it"

    @pytest.mark.parametrize("bad", BAD)
    def test_a_strict_read_raises_the_malformed_error_and_the_display_stays_empty(self, store, bad):
        store[cs.ATTENTION_KEY] = bad
        with pytest.raises(cs.MalformedNote):
            cs.recovery_incidents(strict=True)
        assert cs.note_state() == "malformed"
        shown = cs.attention()
        # (second pass of Q190, adjusted: a LISTED entry that is not an incident is on record and the banner says so; a note that does not parse at all has nothing to list)
        listed = cs._listed_count(bad)
        assert shown is None if listed == 0 else shown == {"incidents": [], "unrecognised": listed}

    def test_health_says_unknown_before_the_set_aside_and_ok_after(self, store):
        from jen.services import health

        store[cs.ATTENTION_KEY] = "{broken json!!!"
        before = health._direct_socket_recovery(None)
        assert before.status == "skip" and "could not be read" in before.detail
        status, key, length = cs.set_aside_unreadable_note()
        assert (
            status == "done" and key.startswith(cs.ATTENTION_KEY + "_set_aside_") and length == len("{broken json!!!")
        )
        assert health._direct_socket_recovery(None).status == "ok"

    def test_the_set_aside_moves_the_text_and_clears_the_note(self, store):
        store[cs.ATTENTION_KEY] = "{broken json!!!"
        status, key, length = cs.set_aside_unreadable_note()
        assert status == "done" and store[key] == "{broken json!!!" and store[cs.ATTENTION_KEY] == ""
        assert cs.note_state() == "ok" and self._record() is True

    def test_a_note_that_reads_fine_is_not_set_aside(self, store):
        self._record()
        before = store[cs.ATTENTION_KEY]
        assert cs.set_aside_unreadable_note() == ("not-needed", "", 0)
        assert store[cs.ATTENTION_KEY] == before and not [k for k in store if "set_aside" in k]

    def test_an_unavailable_store_is_not_malformed(self, monkeypatch):
        from jen.models import user as user_mod

        def down(key, default=None, strict=False):
            raise RuntimeError("the database is down")

        monkeypatch.setattr(user_mod, "get_global_setting", down)
        assert cs.note_state() == "unavailable"
        assert cs.set_aside_unreadable_note() == ("failed", "", 0)


class TestTheSetAsideClearsOnlyWhatItCopied:
    """Q189 second pass, finding 6: the clear is conditional on the stored value still being the one that was copied (one locked transaction), so a second superadmin's set-aside, or a real
    incident recorded in between, is never wiped."""

    def test_a_note_that_changed_in_between_is_not_cleared(self, monkeypatch):
        import json

        from jen.models import user as user_mod

        store = {cs.ATTENTION_KEY: "{broken json!!!"}
        reads = []

        def get(key, default="", strict=False):
            value = store.get(key, default)
            if key == cs.ATTENTION_KEY and not reads:
                reads.append(1)
                # a rotation records a REAL incident right after the first read
                store[key] = json.dumps(
                    {
                        "incidents": [
                            {"kind": "attention", "category": "tls-not-restored", "service": "dhcp4", "server_id": 1}
                        ]
                    }
                )
            return value

        monkeypatch.setattr(user_mod, "get_global_setting", get)
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: store.__setitem__(k, v))
        status, key, length = cs.set_aside_unreadable_note()
        assert status == "changed" and length == len("{broken json!!!")
        assert "tls-not-restored" in store[cs.ATTENTION_KEY], "the incident recorded in between survived"
        assert store[key] == "{broken json!!!", "the earlier text is kept as a spare"


def _attention(**over):
    entry = {
        "kind": "attention",
        "status": "tls-not-restored",
        "category": "tls-not-restored",
        "service": "dhcp4",
        "server_id": 1,
        "server_name": "kea-a",
        "summary": "setup of a socket",
        "detail": "x",
        "at": "2026-01-01T00:00:00+00:00",
        "needs_hands": [],
        "needs_hands_ids": [],
        "lines": [],
    }
    entry.update(over)
    return entry


def _outcome(**over):
    entry = {"status": "rolled_back", "service": "dhcp4", "summary": "a pool edit", "at": "2026-01-01T00:00:00+00:00"}
    entry.update(over)
    return entry


class TestEveryEntryOfTheNoteHasAShape:
    """Q190 (AF3): `{"incidents": [{}]}` was accepted ("a list of dicts"), and `_incident_cleared` returned True for any entry whose status was not `rollback_failed` - an empty dict included - so a clean
    run DELETED a record nobody could read. A recognised incident has a shape; one that is not recognised is KEPT until a superadmin sets the note aside."""

    @pytest.fixture
    def store(self, monkeypatch):
        data = {}
        from jen.models import user as user_mod

        monkeypatch.setattr(user_mod, "get_global_setting", lambda k, d="", strict=False: data.get(k, d))
        monkeypatch.setattr(user_mod, "set_global_setting", lambda k, v: data.__setitem__(k, v))
        monkeypatch.setattr(user_mod, "audit", lambda *a, **k: None)
        monkeypatch.setattr(cs, "record_outcome", _REAL_RECORD_OUTCOME)
        return data

    GOOD = {
        "an empty list": {"incidents": []},
        "a current attention incident": {"incidents": [_attention()]},
        "a historical rolled_back without ids": {"incidents": [_outcome()]},
        "a rollback_failed without ids": {"incidents": [_outcome(status="rollback_failed", needs_hands=["kea-a"])]},
        "a rollback_failed with ids": {
            "incidents": [_outcome(status="rollback_failed", needs_hands=["a"], needs_hands_ids=[1], lines=["x"])]
        },
        "the 5.65.x single note": _outcome(),
        "attention for dhcp6 and d2": {
            "incidents": [_attention(service="dhcp6"), _attention(service="d2", server_id="2")]
        },
    }
    BAD = {
        "an empty dict entry": {"incidents": [{}]},
        "no status": {"incidents": [_outcome(status=None)]},
        "no service": {"incidents": [{k: v for k, v in _outcome().items() if k != "service"}]},
        "an unknown status": {"incidents": [_outcome(status="all-fine")]},
        "an unknown category": {"incidents": [_attention(category="made-up")]},
        "an attention incident for no server": {"incidents": [_attention(server_id=None)]},
        "an attention incident for an unknown service": {"incidents": [_attention(service="dhcp9")]},
        "no time": {"incidents": [{k: v for k, v in _outcome().items() if k != "at"}]},
        "needs_hands that is not a list": {"incidents": [_outcome(needs_hands="kea-a")]},
        "a string among incidents": {"incidents": [_outcome(), "x"]},
        "valid and invalid mixed": {"incidents": [_attention(), {}, _outcome()]},
        "the single note without a service": {"status": "rolled_back"},
        "a list at the top": [_outcome()],
        # (second pass of Q190: a type is not a shape)
        "a boolean for the server id": {"incidents": [_attention(server_id=False)]},
        "a list for the server id": {"incidents": [_attention(server_id=[])]},
        "a blank server id": {"incidents": [_attention(server_id="  ")]},
        "a time that is not a time": {"incidents": [_outcome(at="yesterday-ish")]},
        "a time that is a number": {"incidents": [_outcome(at=12)]},
        "an attention incident whose time is not a time": {"incidents": [_attention(at="soon")]},
    }

    @pytest.mark.parametrize("name", sorted(GOOD))
    def test_every_recognised_shape_reads(self, store, name):
        raw = json.dumps(self.GOOD[name])
        notes = cs._incidents_of(raw, strict=True)
        assert all(cs.recognised_incident(n) for n in notes)

    @pytest.mark.parametrize("name", sorted(BAD))
    def test_every_unrecognised_shape_raises_naming_the_index_never_the_text(self, name):
        raw = json.dumps(self.BAD[name])
        with pytest.raises(cs.MalformedNote) as e:
            cs._incidents_of(raw, strict=True)
        assert "s3cret" not in str(e.value) and raw not in str(e.value)

    def test_the_message_names_the_index(self):
        with pytest.raises(cs.MalformedNote, match="entry 1 "):
            cs._incidents_of(json.dumps({"incidents": [_attention(), {}]}), strict=True)

    @pytest.mark.parametrize("name", sorted(BAD))
    def test_every_writer_refuses_the_whole_note_and_it_is_byte_equal_afterwards(self, store, name):
        raw = json.dumps(self.BAD[name])
        store[cs.ATTENTION_KEY] = raw
        clean = ChangeSetResult("ok", "ok", [])
        assert cs.record_attention(1, "dhcp4", "x", "aborted") is False
        assert cs.resolve_attention(1, "dhcp4") == 0
        assert cs.acknowledge_recovery(1, "dhcp4", "tls-not-restored") is None
        assert cs.record_outcome(clean, "dhcp4", "a clean change") is False
        assert cs.record_outcome(ChangeSetResult("rolled_back", "x", [], needs_hands=["a"]), "dhcp4", "x") is False
        assert store[cs.ATTENTION_KEY] == raw, "a clean change deleted nothing, a failed one wrote nothing"

    def test_a_clean_run_never_clears_what_it_cannot_read(self):
        clean = ChangeSetResult("ok", "ok", [])
        assert cs._incident_cleared({}, clean, "dhcp4") is False
        assert cs._incident_cleared({"status": "rolled_back"}, clean, "dhcp4") is False
        assert cs._incident_cleared(_attention(), clean, "dhcp4") is False
        assert cs._incident_cleared(_outcome(), clean, "dhcp4") is True, (
            "a RECOGNISED rolled_back note is still cleared by any clean run"
        )

    def test_the_banner_counts_what_it_cannot_read_and_keeps_it(self, store):
        store[cs.ATTENTION_KEY] = json.dumps({"incidents": [_attention(), {}, {"kind": "attention"}]})
        note = cs.attention()
        assert len(note["incidents"]) == 1 and note["unrecognised"] == 2
        store[cs.ATTENTION_KEY] = json.dumps({"incidents": [{}]})
        only = cs.attention()
        assert only == {"incidents": [], "unrecognised": 1}

    def test_the_banner_counts_an_entry_that_is_not_even_a_dict(self, store):
        store[cs.ATTENTION_KEY] = json.dumps({"incidents": ["x", 5, None, _attention()]})
        note = cs.attention()
        assert len(note["incidents"]) == 1 and note["unrecognised"] == 3
        store[cs.ATTENTION_KEY] = json.dumps({"incidents": ["x"]})
        assert cs.attention() == {"incidents": [], "unrecognised": 1}

    def test_an_integer_server_id_and_an_iso_time_still_read(self):
        assert cs.recognised_incident(_attention(server_id=3)) and cs.recognised_incident(_attention(server_id="3"))
        assert cs.recognised_incident(_outcome(at="2026-01-01T00:00:00+00:00"))

    def test_a_note_that_reads_has_no_unrecognised_entries(self, store):
        store[cs.ATTENTION_KEY] = json.dumps({"incidents": [_attention()]})
        assert cs.attention()["unrecognised"] == 0

    def test_recovery_incidents_strict_raises_on_one(self, store):
        store[cs.ATTENTION_KEY] = json.dumps({"incidents": [_attention(), {}]})
        with pytest.raises(cs.MalformedNote):
            cs.recovery_incidents(strict=True)
        assert cs.note_state() == "malformed"

    def test_the_set_aside_moves_it_and_clears_it(self, store):
        raw = json.dumps({"incidents": [_attention(), {}]})
        store[cs.ATTENTION_KEY] = raw
        status, key, length = cs.set_aside_unreadable_note()
        assert status == "done" and store[key] == raw and store[cs.ATTENTION_KEY] == "" and length == len(raw)
        assert cs.record_attention(1, "dhcp4", "x", "aborted") is True
