"""
tests/test_kea_log_transactions.py
───────────────────────────────────
v5.68.0-beta.10 (Q145) — Explain's log evidence is ONE exchange, read from the server that handled the client.

* `kea_log_inputs.latest_transaction`: the client id, the class list and the packet dump used to be taken as the newest OF EACH KIND,
  so one "observation" could be stitched from three different transactions. They now come from the newest COMPLETE exchange
  (a class list or a packet dump) alone, and `tid` is what groups the lines (a tid is a client's xid and repeats over time).
* `explain_context.read_log`: evidence used to come from `KEA_SERVERS[0]` - a standby, an unreachable box or one without the helper in
  HA, while the log that saw the client was on the peer. The HA-active server is read first, then the others, until one has an exchange
  for the MAC; the view names the server and the transaction.

Pure (`pytest --noconftest tests/test_kea_log_transactions.py`): real logs from three Kea versions plus constructed ones.
"""

import pathlib
from datetime import datetime

import pytest

from jen import extensions
from jen.services import explain_context as ctx
from jen.services import explain_inputs as inputs
from jen.services import kea_log_inputs as li

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
REAL_MAC = "02:50:00:00:01:06"
MAC = "aa:bb:cc:dd:ee:01"
OTHER = "aa:bb:cc:dd:ee:02"


def _head(ts, level, msg_id, mac, cid, tid):
    return f"2026-10-04 {ts} {level:<5} [kea-dhcp4.test/1.1] {msg_id} [hwtype=1 {mac}], cid=[{cid}], tid={tid}"


def _classes(ts, mac, cid, tid, names):
    return (
        _head(ts, "DEBUG", "DHCP4_CLASSES_ASSIGNED", mac, cid, tid)
        + f": client packet has been assigned on DHCPREQUEST message to the following classes: {', '.join(names)}"
    )


def _dump(ts, mac, cid, tid, hostname):
    return [
        _head(ts, "DEBUG", "DHCP4_QUERY_DATA", mac, cid, tid) + ", packet details: local_address=10.1.0.218:67,",
        "msg_type=DHCPREQUEST (3), trans_id=0x1,",
        "options:",
        f'  type=012, len={len(hostname):03d}: "{hostname}" (string)',
        '  type=060, len=005: "acme1" (string)',
    ]


def _packet(ts, mac, cid, tid):
    return (
        _head(ts, "INFO", "DHCP4_PACKET_RECEIVED", mac, cid, tid)
        + ": DHCPREQUEST (type 3) received from 0.0.0.0 to 255.255.255.255"
    )


class TestRealLogsFromThreeKeaVersions:
    @pytest.mark.parametrize("version", ["3.0.3", "3.2.0", "3.3.1"])
    def test_two_exchanges_and_the_newest_complete_one_is_used_alone(self, version):
        lines = (FIX / f"kea-{version}-debug55.log").read_text(encoding="utf-8").split("\n")
        seen = li.transactions(lines, REAL_MAC)
        assert [t["tid"] for t in seen] == ["0x10006", "0x20006"] and all(t["complete"] for t in seen)
        chosen = li.latest_transaction(lines, REAL_MAC)
        assert chosen["tid"] == "0x20006"
        assert chosen["cid"]["client_id"] == "01:02:50:00:00:01:06"
        assert (
            chosen["query"]["hostname"] == "probe-host"
            and "VENDOR_CLASS_jen-probe-vendor" in chosen["classes"]["classes"]
        )
        assert (
            chosen["first"] <= chosen["classes"]["at"] <= chosen["last"]
            and chosen["first"] <= chosen["query"]["at"] <= chosen["last"]
        )

    def test_a_client_the_log_never_names_has_no_exchange(self):
        lines = (FIX / "kea-3.0.3-debug55.log").read_text(encoding="utf-8").split("\n")
        assert (
            li.transactions(lines, "02:50:00:00:01:99") == []
            and li.latest_transaction(lines, "02:50:00:00:01:99") is None
        )


class TestTheEvidenceNeverCrossesExchanges:
    def _three(self):
        """T1 (tid 0x1): cid A, classes [A1], a dump with hostname h1.  T2 (0x2): cid B, classes [B1], NO dump.  T3 (0x3), the newest of
        all: cid C and only an INFO packet line - nothing that lists classes or options."""
        return [
            _packet("10:00:00.100", MAC, "01:aa", "0x1"),
            _classes("10:00:00.110", MAC, "01:aa", "0x1", ["ALL", "A1"]),
            *_dump("10:00:00.120", MAC, "01:aa", "0x1", "h1"),
            _packet("10:05:00.100", MAC, "01:bb", "0x2"),
            _classes("10:05:00.110", MAC, "01:bb", "0x2", ["ALL", "B1"]),
            _packet("10:09:00.100", MAC, "01:cc", "0x3"),
        ]

    def test_it_is_the_newest_complete_exchange_and_nothing_is_borrowed_from_the_others(self):
        chosen = li.latest_transaction(self._three(), MAC)
        assert chosen["tid"] == "0x2" and chosen["complete"] is True
        assert chosen["cid"]["client_id"] == "01:bb", "not C's: the newest exchange of all has nothing to evidence"
        assert chosen["classes"]["classes"] == ["ALL", "B1"]
        assert chosen["query"] is None, "T1's packet dump is NOT carried over to T2"

    def test_what_the_old_independent_newest_of_each_kind_would_have_said(self):
        lines = self._three()
        stitched = (li.client_id_from_log(lines, MAC), li.latest_classes(lines, MAC), li.latest_query_data(lines, MAC))
        assert (
            stitched[0]["client_id"] == "01:cc"
            and stitched[1]["classes"] == ["ALL", "B1"]
            and stitched[2]["hostname"] == "h1"
        )

    def test_a_tid_that_comes_back_after_a_minute_is_a_new_exchange(self):
        lines = [
            _classes("10:00:00.100", MAC, "01:aa", "0x7", ["ALL", "OLD"]),
            *_dump("10:00:00.120", MAC, "01:aa", "0x7", "old-host"),
            _classes("10:30:00.100", MAC, "01:aa", "0x7", ["ALL", "NEW"]),
        ]
        seen = li.transactions(lines, MAC)
        assert [t["classes"]["classes"][-1] for t in seen] == ["OLD", "NEW"] and seen[1]["query"] is None
        assert li.latest_transaction(lines, MAC)["classes"]["classes"] == ["ALL", "NEW"]

    def test_the_same_tid_from_two_clients_is_two_exchanges(self):
        lines = [
            _classes("10:00:00.100", MAC, "01:aa", "0x5", ["ALL", "MINE"]),
            _classes("10:00:00.105", OTHER, "01:dd", "0x5", ["ALL", "THEIRS"]),
        ]
        assert li.latest_transaction(lines, MAC)["classes"]["classes"] == ["ALL", "MINE"]
        assert li.latest_transaction(lines, OTHER)["cid"]["client_id"] == "01:dd"

    def test_a_log_with_no_class_list_or_dump_still_gives_the_client_id_of_the_newest_exchange(self):
        lines = [_packet("10:00:00.100", MAC, "01:aa", "0x1"), _packet("10:05:00.100", MAC, "01:bb", "0x2")]
        chosen = li.latest_transaction(lines, MAC)
        assert chosen["tid"] == "0x2" and chosen["complete"] is False and chosen["cid"]["client_id"] == "01:bb"
        assert chosen["classes"] is None and chosen["query"] is None


# ── the server the evidence comes from ────────────────────────────────────────────────────────────────────────────────────

S1 = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1"}
S2 = {"id": 2, "name": "kea-b", "ssh_host": "10.0.0.2"}
OWN_LOG = [
    _classes("10:00:00.110", MAC, "01:aa:bb:cc:dd:ee:01", "0x9", ["ALL", "VENDOR_CLASS_Acme", "vip"]),
    *_dump("10:00:00.120", MAC, "01:aa:bb:cc:dd:ee:01", "0x9", "packet-host"),
]
ELSEWHERE_LOG = [_classes("10:00:00.110", OTHER, "01:dd", "0x4", ["ALL", "someone-else"])]


@pytest.fixture
def servers(monkeypatch):
    """Two SSH servers, a recorded tail_log answering per server id, and a configurable HA status."""
    ctx.clear_log_cache()
    monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(S1), dict(S2)])
    world = {
        "tails": {1: {"ok": True, "code": "ok", "lines": []}, 2: {"ok": True, "code": "ok", "lines": []}},
        "asked": [],
        "ha": {},
    }

    def tail(server, path, lines, timeout=None, helper_only=False):
        world["asked"].append(server["id"])
        return world["tails"][server["id"]]

    def ha_status(server):
        return world["ha"].get(server["id"])

    monkeypatch.setattr("jen.services.kea_host.tail_log", tail)
    monkeypatch.setattr("jen.services.kea_ha.ha_status", ha_status)
    monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: None)
    yield world
    ctx.clear_log_cache()


def _ha(scopes, state="hot-standby"):
    return {"local": {"role": "primary", "scopes": scopes, "state": state}, "remote": {}}


class TestTheServerThatHandledTheClient:
    def test_server_0_unreachable_the_peer_supplies_it_and_is_named(self, servers):
        servers["tails"][1] = {"ok": False, "code": "error", "detail": "ssh refused"}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        view = ctx.read_log(MAC, allowed=True)
        assert view["state"] == "ok" and view["server"] == {"id": 2, "name": "kea-b"}
        assert view["query"]["hostname"] == "packet-host" and servers["asked"] == [1, 2]

    def test_server_0_standby_server_1_active_the_active_one_is_read_first_and_only_it(self, servers):
        servers["ha"] = {1: _ha([]), 2: _ha(["server1"])}
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": []}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        view = ctx.read_log(MAC, allowed=True)
        assert servers["asked"] == [2, 1], "every reachable server is read now (Q157), the HA-active one first"
        assert view["server"]["name"] == "kea-b"

    def test_the_helper_only_on_server_1(self, servers, monkeypatch):
        servers["tails"][1] = {"ok": False, "code": "no-helper", "detail": "not installed"}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        assert ctx.read_log(MAC, allowed=True)["server"]["name"] == "kea-b"
        ctx.clear_log_cache()
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{**S1, "ssh_host": ""}, dict(S2)])
        servers["asked"].clear()
        assert ctx.read_log(MAC, allowed=True)["server"]["name"] == "kea-b" and servers["asked"] == [2]

    def test_the_exchange_only_on_server_1_is_found_there(self, servers):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": ELSEWHERE_LOG}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-b" and view["transaction"]["tid"] == "0x9" and servers["asked"] == [1, 2]

    def test_when_no_server_names_the_client_the_view_is_empty_and_says_which_log_was_read(self, servers):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": ELSEWHERE_LOG}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": ELSEWHERE_LOG}
        view = ctx.read_log(MAC, allowed=True)
        assert view["state"] == "ok" and view["classes"] is None and view["transaction"] is None
        assert view["server"]["name"] == "kea-a"

    def test_when_no_server_can_be_read_the_first_reason_stands(self, servers):
        servers["tails"][1] = {"ok": False, "code": "no-helper"}
        servers["tails"][2] = {"ok": False, "code": "error", "detail": "boom"}
        assert ctx.read_log(MAC, allowed=True)["state"] == "no-helper"

    def test_a_complete_exchange_on_a_later_server_beats_an_incomplete_one_on_an_earlier(self, servers):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": [_packet("10:00:00.100", MAC, "01:aa", "0x1")]}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        assert ctx.read_log(MAC, allowed=True)["server"]["name"] == "kea-b"

    def test_the_view_names_the_exchange(self, servers):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        view = ctx.read_log(MAC, allowed=True)
        assert view["transaction"]["tid"] == "0x9" and view["transaction"]["complete"] is True
        assert view["transaction"]["before_config_change"] is False


class TestAClassListFromBeforeTheConfigChanged:
    def _revision(self, monkeypatch, created):
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda server_id, service: {"created_at": created})

    def test_it_is_labelled_when_the_newest_revision_is_newer_than_the_exchange(self, servers, monkeypatch):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        self._revision(monkeypatch, datetime(2026, 10, 4, 11, 0, 0))  # after 10:00:00 of the logged exchange
        view = ctx.read_log(MAC, allowed=True)
        assert view["transaction"]["before_config_change"] is True and view["classes"]["before_config_change"] is True
        built = inputs.build(MAC, log=view)
        assert built["assigned"]["before_config_change"] is True, "the engine is told, and words it on the class row"
        fresh = dict(view, classes=dict(view["classes"], before_config_change=False))
        assert "before_config_change" not in inputs.build(MAC, log=fresh)["assigned"]

    def test_it_is_not_labelled_when_the_config_is_older_than_the_exchange(self, servers, monkeypatch):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        self._revision(monkeypatch, datetime(2026, 10, 4, 9, 0, 0))
        assert ctx.read_log(MAC, allowed=True)["transaction"]["before_config_change"] is False

    def test_with_the_hosts_clock_unknown_it_is_never_guessed(self, servers, monkeypatch):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        self._revision(monkeypatch, datetime(2026, 10, 4, 23, 0, 0))
        assert ctx.read_log(MAC, allowed=True)["transaction"]["before_config_change"] is False

    def test_the_hosts_offset_is_applied(self, servers, monkeypatch):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: -18000.0)  # the log says 10:00 local = 15:00 UTC
        self._revision(monkeypatch, datetime(2026, 10, 4, 12, 0, 0))  # 12:00 UTC: BEFORE the exchange
        assert ctx.read_log(MAC, allowed=True)["transaction"]["before_config_change"] is False
        ctx.clear_log_cache()
        self._revision(monkeypatch, datetime(2026, 10, 4, 16, 0, 0))  # 16:00 UTC: after it
        assert ctx.read_log(MAC, allowed=True)["transaction"]["before_config_change"] is True


class TestTheHaQuestionIsAskedRarely:
    """v5.68.0-beta.21 (Q156, item 3): `read_log` computed the order of the servers - one HA `status-get` each, a 10 s timeout for a Control Agent that
    is down - BEFORE it looked at its own cache or at `fetch=False`, so the Overview's "never a fresh round trip" read paid for it on every `/client`
    render, and again for each of Explain, Config and Changes. LOG_TTL_S bounded the log read, not the probe."""

    @pytest.fixture
    def counted(self, servers, monkeypatch):
        calls = []

        def ha_status(server):
            calls.append(server["id"])
            return servers["ha"].get(server["id"])

        monkeypatch.setattr("jen.services.kea_ha.ha_status", ha_status)
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        return calls

    def test_an_overview_render_with_two_servers_makes_zero_ha_calls_and_zero_reads(self, servers, counted):
        view = ctx.read_log(MAC, allowed=True, fetch=False)
        assert view["state"] == "not-fetched"
        assert counted == [] and servers["asked"] == []

    def test_a_caller_who_may_not_read_the_log_asks_nothing(self, servers, counted):
        assert ctx.read_log(MAC, allowed=False)["state"] == "not-allowed"
        assert counted == []

    def test_no_server_and_no_helper_are_answered_from_the_configuration_alone(self, servers, counted, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [])
        assert ctx.read_log(MAC, allowed=True)["state"] == "no-server"
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{**S1, "ssh_host": ""}, {**S2, "ssh_host": ""}])
        assert ctx.read_log(MAC, allowed=True)["state"] == "no-helper"
        assert counted == []

    def test_a_cached_read_makes_zero_calls(self, servers, counted):
        ctx.read_log(MAC, allowed=True)
        assert sorted(counted) == [1, 2], "the first read asks each server once"
        counted.clear()
        servers["asked"].clear()
        ctx.read_log(MAC, allowed=True)
        ctx.read_log(MAC, allowed=True, fetch=False)
        assert counted == [] and servers["asked"] == []

    def test_two_reads_inside_the_ttl_for_different_macs_share_one_probe_per_server(self, servers, counted):
        ctx.read_log(MAC, allowed=True)
        assert sorted(counted) == [1, 2]
        ctx.read_log(OTHER, allowed=True)  # a different client: its own log read, the same HA answer
        assert sorted(counted) == [1, 2], "a second client's read re-asked the HA question"

    def test_a_whole_client_page_worth_of_readers_is_one_probe_per_server(self, servers, counted):
        """Overview (fetch=False), then Explain, Config and Changes each reading the log: one status-get per server, not four."""
        ctx.read_log(MAC, allowed=True, fetch=False)
        for _tab in ("explain", "config", "changes"):
            ctx.read_log(MAC, allowed=True)
        assert sorted(counted) == [1, 2]

    def test_the_ttl_expiring_asks_each_server_again_once(self, servers, counted, monkeypatch):
        clock = {"now": 1000.0}
        monkeypatch.setattr(ctx.time, "monotonic", lambda: clock["now"])
        ctx.read_log(MAC, allowed=True)
        assert sorted(counted) == [1, 2]
        clock["now"] += ctx.LOG_TTL_S - 1
        ctx.read_log(OTHER, allowed=True)
        assert sorted(counted) == [1, 2]
        clock["now"] += 2
        ctx.read_log(MAC, allowed=True)
        assert sorted(counted) == [1, 1, 2, 2], "one more per server after the window"

    def test_a_changed_server_list_is_seen_at_once(self, servers, counted, monkeypatch):
        ctx.read_log(MAC, allowed=True)
        counted.clear()
        monkeypatch.setattr(
            extensions, "KEA_SERVERS", [dict(S1), dict(S2), {"id": 3, "name": "kea-c", "ssh_host": "10.0.0.3"}]
        )
        servers["tails"][3] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        ctx.read_log(OTHER, allowed=True)
        assert sorted(counted) == [1, 2, 3]

    def test_the_order_is_still_ha_active_first(self, servers, counted):
        servers["ha"] = {1: _ha([]), 2: _ha(["server1"])}
        view = ctx.read_log(MAC, allowed=True)
        assert servers["asked"] == [2, 1] and view["server"]["name"] == "kea-b"
        probes = len(counted)
        assert [s["id"] for s in ctx._evidence_servers()] == [2, 1], "the memoised order is the HA-active-first one"
        assert len(counted) == probes

    def test_a_single_server_never_asks_the_ha_question(self, servers, counted, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(S1)])
        ctx.read_log(MAC, allowed=True)
        assert counted == []


def _exchange(at, cid, tid, host):
    return [
        _classes(at, MAC, cid, tid, ["ALL", f"CLASS_{host}"]),
        *_dump(at.replace(":00.110", ":00.120"), MAC, cid, tid, host),
    ]


class TestTheNewestCompleteExchangeAcrossServersWins:
    """v5.68.0-beta.22 (Q157, item 7): `read_log` broke at the FIRST server in order whose exchange was complete and never compared times across
    servers, so after a failover the old active's older exchange beat the standby's newer one. It now collects the complete exchange of every
    reachable server and chooses the newest - ordered only when both log-clock offsets are known, else (or within 5 s) the first in order."""

    def test_a_older_b_newer_the_newer_one_wins_when_the_offsets_are_known(self, servers, monkeypatch):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        servers["tails"][1] = {
            "ok": True,
            "code": "ok",
            "lines": _exchange("10:00:00.110", "01:aa", "0xa", "old-active"),
        }
        servers["tails"][2] = {
            "ok": True,
            "code": "ok",
            "lines": _exchange("10:05:00.110", "01:bb", "0xb", "new-active"),
        }
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-b" and view["transaction"]["tid"] == "0xb"
        assert view["query"]["hostname"] == "new-active" and "other_complete" not in view

    def test_a_newer_b_older_the_newer_one_wins_whatever_the_order(self, servers, monkeypatch):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": _exchange("10:09:00.110", "01:aa", "0xa", "newer")}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": _exchange("10:01:00.110", "01:bb", "0xb", "older")}
        assert ctx.read_log(MAC, allowed=True)["server"]["name"] == "kea-a"

    def test_known_offsets_reorder_what_the_raw_times_say(self, servers, monkeypatch):
        """B's clock runs two hours ahead of UTC: its 12:00 is 10:00 UTC, older than A's 10:30 (offset 0)."""
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 7200.0 if server["id"] == 2 else 0.0)
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": _exchange("10:30:00.110", "01:aa", "0xa", "a-host")}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": _exchange("12:00:00.110", "01:bb", "0xb", "b-host")}
        assert ctx.read_log(MAC, allowed=True)["server"]["name"] == "kea-a"

    def test_unknown_offsets_fall_back_to_the_server_order_not_the_raw_times(self, servers):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": _exchange("10:00:00.110", "01:aa", "0xa", "first")}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": _exchange("11:00:00.110", "01:bb", "0xb", "second")}
        assert ctx.read_log(MAC, allowed=True)["server"]["name"] == "kea-a", (
            "an offset-less comparison is a guess; the HA order decides"
        )

    def test_within_five_seconds_the_first_in_order_wins_and_the_other_is_named(self, servers, monkeypatch):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": _exchange("10:00:00.110", "01:aa", "0xa", "a-host")}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": _exchange("10:00:03.110", "01:bb", "0xb", "b-host")}
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-a" and view["other_complete"] == [{"server": "kea-b", "comparable": True}]
        assert view["query"]["hostname"] == "a-host", "fields are never mixed across transactions"

    def test_ha_active_first_decides_a_tie(self, servers, monkeypatch):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        servers["ha"] = {1: _ha([]), 2: _ha(["server1"])}
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": _exchange("10:00:00.110", "01:aa", "0xa", "standby")}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": _exchange("10:00:01.110", "01:bb", "0xb", "active")}
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-b" and view["other_complete"] == [{"server": "kea-a", "comparable": True}]

    def test_an_incomplete_exchange_is_only_the_fallback_when_no_server_has_a_complete_one(self, servers, monkeypatch):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": [_packet("10:09:00.100", MAC, "01:aa", "0x1")]}
        servers["tails"][2] = {
            "ok": True,
            "code": "ok",
            "lines": _exchange("10:01:00.110", "01:bb", "0xb", "complete-but-older"),
        }
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-b" and view["transaction"]["complete"] is True
        ctx.clear_log_cache()
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": [_packet("10:02:00.100", MAC, "01:bb", "0x2")]}
        assert ctx.read_log(MAC, allowed=True)["transaction"]["complete"] is False

    def test_one_unreachable_server_leaves_the_other_s_exchange(self, servers, monkeypatch):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        servers["tails"][1] = {"ok": False, "code": "error", "detail": "ssh refused"}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": _exchange("10:00:00.110", "01:bb", "0xb", "only")}
        view = ctx.read_log(MAC, allowed=True)
        assert view["state"] == "ok" and view["server"]["name"] == "kea-b" and "other_complete" not in view

    def test_the_explain_tab_says_so(self):
        import pathlib

        html = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "_explain_result.html").read_text(
            encoding="utf-8"
        )
        assert "other_complete" in html and "logged this client at about the same time" in html
        assert "the two clocks cannot be compared" in html


class TestTheOtherExchangeIsNamedWhateverTheClocks:
    """v5.68.0-beta.23 (Q158, item 5): beta.22 named the other server only when BOTH log-clock offsets were known and the times were within 5 s - with an
    offset unknown the second complete exchange was silently not mentioned, although the docstring said it was. `other_complete` is
    [{"server", "comparable"}]: comparable = both offsets known (and within the tie window, or it is not "also" at all)."""

    @staticmethod
    def _logs(servers, a="10:00:00.110", b="10:00:03.110"):
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": _exchange(a, "01:aa", "0xa", "a-host")}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": _exchange(b, "01:bb", "0xb", "b-host")}

    def test_both_clocks_known_within_five_seconds_is_comparable(self, servers, monkeypatch):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        self._logs(servers)
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-a" and view["other_complete"] == [{"server": "kea-b", "comparable": True}]

    def test_both_clocks_known_more_than_five_seconds_apart_the_newer_wins_and_nothing_is_also(
        self, servers, monkeypatch
    ):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        self._logs(servers, "10:00:00.110", "10:00:30.110")
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-b" and "other_complete" not in view

    def test_the_first_servers_clock_unknown_names_the_second_as_not_comparable(self, servers, monkeypatch):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: None if server["id"] == 1 else 0.0)
        self._logs(servers, "10:00:00.110", "11:00:00.110")
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-a", "first in order: the comparison is a guess"
        assert view["other_complete"] == [{"server": "kea-b", "comparable": False}]

    def test_the_second_servers_clock_unknown_names_it_as_not_comparable(self, servers, monkeypatch):
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: None if server["id"] == 2 else 0.0)
        self._logs(servers, "10:00:00.110", "09:00:00.110")
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-a" and view["other_complete"] == [
            {"server": "kea-b", "comparable": False}
        ]

    def test_neither_clock_known_names_the_other_as_not_comparable(self, servers):
        self._logs(servers)
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-a" and view["other_complete"] == [
            {"server": "kea-b", "comparable": False}
        ]
        assert view["query"]["hostname"] == "a-host", "fields are never mixed across transactions"

    def test_the_two_sentences_the_tab_prints(self):
        import pathlib
        import re

        import jinja2

        html = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "_explain_result.html").read_text(
            encoding="utf-8"
        )
        paragraph = re.search(r'(<p class="u-865c33" id="explain-exchange">What was read.*?</p>)', html, re.S).group(1)
        env = jinja2.Environment(autoescape=True, undefined=jinja2.StrictUndefined)
        template = env.from_string(paragraph)
        exchange = {"at": "10:00:00.110", "tid": "0xa", "server": "kea-a", "before_config_change": False}
        same = template.render(exchange=exchange, other_complete=[{"server": "kea-b", "comparable": True}])
        assert (
            "Another server also logged this client at about the same time (kea-b)" in same
            and "cannot be compared" not in same
        )
        unknown = template.render(exchange=exchange, other_complete=[{"server": "kea-b", "comparable": False}])
        assert (
            "Another server also logged a complete exchange (kea-b), but the two clocks cannot be compared, so this one was chosen because it is first in order."
            in unknown
        )
        assert "at about the same time" not in unknown
        alone = template.render(exchange=exchange, other_complete=[])
        assert "Another server" not in alone
