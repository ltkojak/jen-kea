"""
tests/test_capabilities.py
───────────────────────────
v5.64.0 (Q83) — jen.services.capabilities: the derivation table (Kea 2.6 /
3.0 / 3.2, with and without the helper, Control Agent vs direct), every
`why()` sentence, the gathering/caching layer, the Health Center row, and
a scanner proving the old inline availability checks are gone from
jen/routes/.

Everything here is pure or monkeypatched — no database, no Kea — so the
whole file runs with `py -m pytest --noconftest tests/test_capabilities.py`.
"""

import pathlib
import re

import pytest

from jen import extensions
from jen.services import capabilities as caps
from jen.services import kea_host

V26, V30, V32 = (2, 6, 0), (3, 0, 3), (3, 2, 0)
# the primary is reached the way every page always has: `server=None`
PRIMARY_CALL = ("version-get", None)


def _derive(version, *, direct=False, helper=5, ssh=True, hooks=None, ddns=None, known=None):
    return caps.derive(
        kea_version=version,
        direct=direct,
        helper_version=helper,
        helper_known=(helper is not None) if known is None else known,
        ssh=ssh,
        hooks=hooks,
        ddns_enabled=ddns,
    )


class TestTransport:
    @pytest.mark.parametrize(
        "version,direct,control_agent,deprecated,removed",
        [
            (V26, False, True, False, False),
            (V30, False, True, True, False),
            (V32, False, False, False, True),
            (V26, True, False, False, False),
            (V30, True, False, False, False),
            (V32, True, False, False, False),
            (None, False, True, False, False),  # unknown version: assume it still ships one
        ],
    )
    def test_control_agent_table(self, version, direct, control_agent, deprecated, removed):
        c = _derive(version, direct=direct)
        assert (c.control_agent, c.ca_deprecated, c.ca_removed, c.direct_control) == (
            control_agent,
            deprecated,
            removed,
            direct,
        )

    @pytest.mark.parametrize("version,ok", [(V26, False), (V30, True), (V32, True), (None, True), ((2, 7, 1), False)])
    def test_direct_socket_needs_2_7_2(self, version, ok):
        assert _derive(version).direct_socket is ok

    def test_the_predicates_are_the_same_thresholds(self):
        assert caps.supports_direct_socket((2, 7, 2)) and not caps.supports_direct_socket((2, 7, 1))
        assert caps.ships_control_agent((3, 1, 9)) and not caps.ships_control_agent((3, 2, 0))
        assert caps.supports_direct_socket(None) and caps.ships_control_agent(None)


class TestHelper:
    @pytest.mark.parametrize(
        "helper,ssh,helper_on,tls,trace",
        [
            (None, True, False, False, False),
            (1, True, True, False, False),
            (3, True, True, False, False),
            (4, True, True, True, False),
            (5, True, True, True, True),
            (5, False, True, True, False),  # Trace needs SSH as well
            (9, True, True, True, True),
        ],
    )
    def test_helper_table(self, helper, ssh, helper_on, tls, trace):
        c = _derive(V30, helper=helper, ssh=ssh)
        assert (c.helper, c.tls, c.trace) == (helper_on, tls, trace)
        assert c.helper_version == helper

    def test_thresholds_are_the_kea_host_constants(self):
        assert kea_host.TLS_HELPER_MIN_VERSION == 4
        assert kea_host.TRACE_HELPER_MIN_VERSION == 5
        assert caps.helper_caps(kea_host.TRACE_HELPER_MIN_VERSION)["trace"] is True
        assert caps.helper_caps(kea_host.TRACE_HELPER_MIN_VERSION - 1)["trace"] is False

    def test_a_non_integer_helper_version_is_not_a_helper(self):
        for junk in (None, "5", True, 5.0):
            assert caps.helper_caps(junk) == {"helper": False, "tls": False, "trace": False}

    def test_never_recorded_is_not_the_same_as_recorded_missing(self):
        never = _derive(V30, helper=None, known=False)
        missing = _derive(V30, helper=None, known=True)
        assert never.helper_known is False and missing.helper_known is True
        assert never.helper is False and missing.helper is False


class TestDaemon:
    def test_packet_stats_and_config_test_need_an_answering_server(self):
        up = caps.derive(kea_version=V30)
        down = caps.derive()
        assert up.packet_stats and up.config_test and up.reachable
        assert not (down.packet_stats or down.config_test or down.reachable)

    def test_reachable_can_be_true_without_a_parseable_version(self):
        c = caps.derive(reachable=True)
        assert c.reachable and c.packet_stats and c.kea_version is None

    @pytest.mark.parametrize("version,ok", [(V26, False), (V30, False), (V32, True), ((3, 3, 1), True), (None, False)])
    def test_drop_reason_counters_arrive_with_3_2(self, version, ok):
        assert _derive(version).packet_drop_reasons is ok

    def test_hook_derived_capabilities(self):
        hooks = {"libdhcp_host_cmds.so", "libdhcp_lease_cmds.so"}
        c = _derive(V30, hooks=hooks, ddns=True)
        assert (c.host_cmds, c.lease_cmds, c.ha_commands, c.ddns, c.hooks_known) == (True, True, False, True, True)
        c = _derive(V30, hooks={"libdhcp_ha.so"}, ddns=False)
        assert (c.host_cmds, c.lease_cmds, c.ha_commands, c.ddns) == (False, False, True, False)

    def test_unknown_hooks_are_off_and_say_so(self):
        c = _derive(V30, hooks=None)
        assert not c.hooks_known and not (c.host_cmds or c.lease_cmds or c.ha_commands or c.ddns)
        assert "no config for this server" in c.why("host_cmds")
        assert "no config for this server" in c.why("ddns")

    @pytest.mark.parametrize(
        "direct,helper,ssh,ready",
        [
            (True, 5, True, True),
            (True, 4, True, False),  # SSH configured and the helper behind
            (True, None, True, False),
            (True, None, False, True),  # no SSH → nothing for a helper to be behind on
            (False, 5, True, False),  # Control Agent mode is never 3.2-ready
        ],
    )
    def test_kea32_ready(self, direct, helper, ssh, ready):
        assert _derive(V30, direct=direct, helper=helper, ssh=ssh).kea32_ready is ready


class TestWhy:
    def test_every_capability_has_a_sentence_on_and_off(self):
        on = _derive(
            V32,
            direct=True,
            helper=5,
            ssh=True,
            hooks={caps.HOOK_HA, caps.HOOK_HOST_CMDS, caps.HOOK_LEASE_CMDS},
            ddns=True,
        )
        off = caps.derive()
        for name in caps.CAPABILITY_NAMES:
            assert on.why(name).strip(), name
            assert off.why(name).strip(), name

    def test_on_and_off_sentences_differ(self):
        on = _derive(V32, direct=True)
        off = caps.derive()
        for name in caps.CAPABILITY_NAMES:
            if getattr(on, name) and not getattr(off, name):
                assert on.why(name) != off.why(name), name

    def test_trace_names_the_fix(self):
        assert _derive(V30, helper=None, known=True).why("trace") == (
            "Trace needs the Kea host helper v5 — Settings → Kea → SSH → Install helper."
        )
        assert "v4" in _derive(V30, helper=4).why("trace")
        assert "SSH" in _derive(V30, helper=5, ssh=False).why("trace")

    def test_unknown_name_is_an_error_not_a_blank(self):
        with pytest.raises(ValueError):
            caps.derive().why("nonsense")

    def test_as_rows_covers_every_name_once_in_order(self):
        rows = _derive(V30).as_rows()
        assert [n for n, _l, _o in rows] == list(caps.CAPABILITY_NAMES)
        assert all(label for _n, label, _o in rows)

    def test_every_capability_name_is_a_field(self):
        assert set(caps.CAPABILITY_NAMES) <= set(caps.field_names())


class TestMode:
    def test_is_direct_reads_the_configured_mode_fresh(self, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        assert caps.is_direct() and not caps.is_ca()
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        assert caps.is_ca() and not caps.is_direct()


# ── gathering ───────────────────────────────────────────────────────────────


@pytest.fixture
def gathered(monkeypatch):
    """A fake Kea + helper status; returns the call log."""
    from jen.services import kea as kea_svc
    from jen.services import subnet_context

    caps.invalidate()
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(
        extensions,
        "KEA_SERVERS",
        [
            {"id": 1, "name": "primary", "ssh_host": "10.0.0.5"},
            {"id": 2, "name": "standby", "ssh_host": ""},
        ],
    )
    log = []

    def fake_kea_command(command, service="dhcp4", arguments=None, server=None, timeout=10):
        log.append((command, (server or {}).get("id")))
        return {"result": 0, "text": "3.0.3", "arguments": {"extended": "3.0.3\ntarball"}}

    monkeypatch.setattr(kea_svc, "kea_command", fake_kea_command)
    monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: extensions.KEA_SERVERS[0])
    monkeypatch.setattr(
        subnet_context,
        "dhcp4_config",
        lambda force=False: {
            "hooks-libraries": [{"library": "/usr/lib/kea/hooks/libdhcp_host_cmds.so"}],
            "dhcp-ddns": {"enable-updates": True},
        },
    )
    monkeypatch.setattr(kea_host, "helper_status", lambda: {"1": {"version": 5}, "2": {"version": None}})
    yield log
    caps.invalidate()


class TestForServer:
    def test_primary_reads_version_helper_hooks_and_ddns(self, gathered):
        c = caps.for_server(1)
        assert c.kea_version == (3, 0, 3) and c.kea_version_text == "3.0.3" and c.reachable
        assert c.direct_control and c.helper and c.trace and c.tls and c.ssh
        assert c.host_cmds and not c.lease_cmds and c.ddns and c.hooks_known

    def test_a_standby_has_no_hooks_read_and_a_recorded_missing_helper(self, gathered):
        c = caps.for_server(2)
        assert c.kea_version == (3, 0, 3)
        assert not c.hooks_known and not c.host_cmds
        assert c.helper_known and not c.helper and not c.trace and not c.ssh

    def test_an_unknown_server_id_is_all_off_but_still_derived(self, gathered):
        c = caps.for_server(99)
        assert not c.helper_known and not c.ssh and not c.trace

    def test_the_version_is_fetched_once_per_minute_per_server(self, gathered):
        caps.for_server(1)
        caps.for_server(1, with_config=False)
        caps.for_server(2)
        assert gathered.count(PRIMARY_CALL) == 1
        assert gathered.count(("version-get", 2)) == 1

    def test_invalidate_forces_a_fresh_read(self, gathered):
        caps.for_server(1)
        caps.invalidate(1)
        caps.for_server(1)
        assert gathered.count(PRIMARY_CALL) == 2
        caps.invalidate()
        caps.for_server(2)
        caps.for_server(2)
        assert gathered.count(("version-get", 2)) == 1

    def test_the_cache_expires(self, gathered, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr(caps.time, "monotonic", lambda: clock[0])
        caps.for_server(1)
        clock[0] += caps._CACHE_TTL_S + 1
        caps.for_server(1)
        assert gathered.count(PRIMARY_CALL) == 2

    def test_probe_kea_false_makes_no_kea_call(self, gathered):
        c = caps.for_server(1, probe_kea=False)
        assert gathered == []
        assert c.helper and c.trace and c.kea_version is None and not c.reachable

    def test_with_config_false_skips_the_hooks(self, gathered):
        c = caps.for_server(1, with_config=False)
        assert not c.hooks_known and not c.host_cmds

    def test_a_kea_that_does_not_answer_is_unreachable_not_an_error(self, gathered, monkeypatch):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **k: {"result": 1, "text": "down"})
        caps.invalidate()
        c = caps.for_server(1)
        assert not c.reachable and c.kea_version is None and not c.packet_stats

    def test_a_kea_that_raises_is_unreachable_not_an_error(self, gathered, monkeypatch):
        from jen.services import kea as kea_svc

        def boom(*a, **k):
            raise RuntimeError("connection refused")

        monkeypatch.setattr(kea_svc, "kea_command", boom)
        caps.invalidate()
        assert not caps.for_server(1).reachable

    def test_for_primary_is_server_one(self, gathered):
        assert caps.for_primary().server_id == 1

    def test_memoised_within_a_request(self, gathered):
        import flask

        app = flask.Flask("capabilities-memo-test")
        with app.test_request_context():
            a = caps.for_server(1)
            caps.invalidate()  # the version cache is gone, the request's memo is not
            b = caps.for_server(1)
            assert a is b
        assert gathered.count(PRIMARY_CALL) == 1

    def test_the_memo_does_not_cross_requests(self, gathered):
        import flask

        app = flask.Flask("capabilities-memo-test-2")
        with app.test_request_context():
            a = caps.for_server(1)
        caps.invalidate()
        with app.test_request_context():
            b = caps.for_server(1)
        assert a is not b


class TestFromStatus:
    def test_health_status_rows_need_no_kea_call(self, gathered):
        row = {"server": {"id": 1, "ssh_host": "h"}, "up": True, "version": "3.2.0"}
        c = caps.from_status(row, dhcp4_cfg={"hooks-libraries": [{"library": "libdhcp_ha.so"}]})
        assert gathered == []
        assert c.kea_version == (3, 2, 0) and c.packet_drop_reasons and c.ha_commands and c.helper

    def test_a_down_server(self, gathered):
        c = caps.from_status({"server": {"id": 2}, "up": False, "version": ""})
        assert not c.reachable and not c.packet_stats and not c.helper


# ── the Health Center row ───────────────────────────────────────────────────


class TestHealthRow:
    def test_registered_in_the_kea_group_with_a_stable_id(self):
        from jen.services import health

        assert "capabilities" in health.CHECK_IDS
        assert health._CHECK_META["capabilities"][1] == "kea"

    def test_lists_on_and_off_per_server(self, gathered):
        from jen.services import health

        ctx = {
            "server_status": [
                {"server": {"id": 1, "name": "primary", "ssh_host": "h"}, "up": True, "version": "3.0.3"},
                {"server": {"id": 2, "name": "standby"}, "up": False, "version": ""},
            ],
            "active_server": {"id": 1},
            "dhcp4_config": {"hooks-libraries": [{"library": "libdhcp_host_cmds.so"}]},
        }
        c = health._capabilities(ctx)
        assert c.status == "ok" and c.id == "capabilities" and c.group == "kea"
        assert "primary — on:" in c.detail and "standby — on:" in c.detail
        assert "Reservation commands" in c.detail.split("standby")[0].split("off:")[0]
        assert gathered == []  # no Kea call of its own

    def test_skips_when_no_server_status(self):
        from jen.services import health

        assert health._capabilities({"server_status": []}).status == "skip"

    def test_a_refresh_drops_the_cached_capabilities(self, gathered):
        from jen.services import health

        caps.for_server(1)
        health._capabilities({"server_status": [{"server": {"id": 1}, "up": True, "version": "3.0.3"}]})
        caps.for_server(1)
        assert gathered.count(PRIMARY_CALL) == 2


# ── nothing in jen/routes/ decides availability for itself any more ─────────

ROUTES = pathlib.Path(__file__).resolve().parent.parent / "jen" / "routes"

# Each pattern is one of the old inline shapes Q83 replaced.
OLD_PATTERNS = {
    "the raw connection mode": re.compile(r"KEA_CONNECTION_MODE"),
    "a Kea version tuple comparison": re.compile(r"[<>]=?\s*\(\d+,\s*\d+,\s*\d+\)"),
    "a helper feature threshold": re.compile(r"(TLS|D2|TRACE)_HELPER_MIN_VERSION|\b(tls|d2)_supported\("),
    "a recorded helper version read as a gate": re.compile(r"helper_status\(\)\.get\("),
}


def _route_files():
    return sorted(ROUTES.rglob("*.py"))


class TestNoOldInlineChecksRemain:
    def test_the_scanner_actually_finds_the_old_shapes(self):
        samples = {
            "the raw connection mode": 'if extensions.KEA_CONNECTION_MODE == "direct":',
            "a Kea version tuple comparison": "if v < (2, 7, 2):",
            "a helper feature threshold": "and st.get('version') >= kea_host.TLS_HELPER_MIN_VERSION",
            "a recorded helper version read as a gate": "recorded = __host.helper_status().get(str(sid))",
        }
        for label, line in samples.items():
            assert OLD_PATTERNS[label].search(line), label

    def test_no_route_matches_any_old_pattern(self):
        offenders = []
        for path in _route_files():
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                for label, pattern in OLD_PATTERNS.items():
                    if pattern.search(code):
                        offenders.append(f"{path.relative_to(ROUTES.parent.parent)}:{lineno} ({label}): {line.strip()}")
        assert not offenders, "decide availability through jen.services.capabilities instead:\n" + "\n".join(offenders)
