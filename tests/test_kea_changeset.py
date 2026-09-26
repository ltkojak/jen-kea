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
        note = cs.attention()
        assert note["status"] == "rollback_failed" and note["summary"] == "add a pool"
        assert note["needs_hands"] == ["kea-a"]

        fake.responses["service"] = {"ok": True, "unit": "u", "state": "active"}
        cs.apply_change("dhcp4", _mutate_add_pool, "add a pool", servers=[SERVER_A])
        assert cs.attention() is None

    def test_dismiss_clears_it(self, store):
        store[cs.ATTENTION_KEY] = '{"status": "rolled_back"}'
        assert cs.attention() == {"status": "rolled_back"}
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
        assert cs.attention()["needs_hands"] == ["kea-a"]
        fake.responses["service"] = {"ok": True, "unit": "u", "state": "active"}

    def test_an_ok_run_that_never_touched_the_server_leaves_it(self, fake, store):
        self._fail_a(fake)
        cs.apply_change("dhcp4", _mutate_add_pool, "edit b", servers=[SERVER_B])
        assert cs.attention() is not None and cs.attention()["status"] == "rollback_failed"

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
        store[cs.ATTENTION_KEY] = '{"status": "rolled_back", "service": "dhcp4"}'
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
