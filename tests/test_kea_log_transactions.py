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
import time
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
        assert view["query"]["hostname"] == "packet-host" and sorted(servers["asked"]) == [1, 2]

    def test_server_0_standby_server_1_active_the_active_one_is_read_first_and_only_it(self, servers):
        servers["ha"] = {1: _ha([]), 2: _ha(["server1"])}
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": []}
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        view = ctx.read_log(MAC, allowed=True)
        assert sorted(servers["asked"]) == [1, 2], "every reachable server is read now (Q157), the HA-active one first"
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
        assert (
            view["server"]["name"] == "kea-b"
            and view["transaction"]["tid"] == "0x9"
            and sorted(servers["asked"]) == [1, 2]
        )

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
        assert sorted(servers["asked"]) == [1, 2] and view["server"]["name"] == "kea-b"
        probes = len(counted)
        assert [s["id"] for s in ctx._evidence_servers()] == [2, 1], "the memoised order is the HA-active-first one"
        assert len(counted) == probes

    def test_a_single_server_never_asks_the_ha_question(self, servers, counted, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(S1)])
        ctx.read_log(MAC, allowed=True)
        assert counted == []


class _InFlight:
    """Counts the fake reads/probes that have started and not finished. A pool worker thread outlives its task (the executor keeps it for the next
    one), so a teardown cannot `join` it - it waits for the count to reach zero instead, THEN clears the caches the released reads wrote to."""

    def __init__(self):
        import threading

        self._lock = threading.Lock()
        self.n = 0

    def __enter__(self):
        with self._lock:
            self.n += 1

    def __exit__(self, *exc):
        with self._lock:
            self.n -= 1

    def drain(self, timeout=5.0):
        deadline = time.monotonic() + timeout
        while self.n > 0 and time.monotonic() < deadline:
            time.sleep(0.01)


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


class TestTheLogsAreReadConcurrentlyInsideOneBudget:
    """v5.68.0-beta.23 (Q158, item 4): beta.22 read every server's log in turn, each with its own 15 s timeout - one good server and three unreachable
    ones was ~45 s on top of the HA probes. The servers are read at once on a four-worker executor against ONE deadline (`EVIDENCE_BUDGET_S`, 20 s in
    production; 1.0 s here), the newest complete exchange among the answers that arrived in time is chosen, and a server that did not answer is
    named in `view["not_checked"]`."""

    BUDGET = 1.0

    @pytest.fixture
    def pool(self, monkeypatch):
        import threading

        ctx.clear_log_cache()
        monkeypatch.setattr(ctx, "EVIDENCE_BUDGET_S", self.BUDGET)
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        monkeypatch.setattr(
            "jen.services.config_revisions.latest", lambda server_id, service: None
        )  # no database in a timing test
        gate = threading.Event()  # released at teardown: a "hung" read never outlives the test
        inflight = _InFlight()
        world = {"answers": {}, "delay": {}, "hang": set(), "asked": [], "gate": gate}

        def tail(server, path, lines, timeout=None, helper_only=False):
            world["asked"].append(server["id"])
            with inflight:
                if server["id"] in world["hang"]:
                    gate.wait(30)
                elif world["delay"].get(server["id"]):
                    time.sleep(world["delay"][server["id"]])
                return world["answers"].get(server["id"]) or {"ok": False, "code": "error", "detail": "released"}

        monkeypatch.setattr("jen.services.kea_host.tail_log", tail)
        monkeypatch.setattr("jen.services.kea_ha.ha_status", lambda server: None)
        names = {1: "kea-a", 2: "kea-b", 3: "kea-c", 4: "kea-d"}
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [{"id": i, "name": n, "ssh_host": f"10.0.0.{i}"} for i, n in names.items()],
        )
        yield world
        gate.set()
        # fixup 4 (F9): the released reads WRITE to the shared tail cache as they finish; wait for them first, then clear, or a late write survives into
        # the next test
        inflight.drain()
        ctx.clear_log_cache()
        from jen.services import log_tail

        log_tail.clear()

    @staticmethod
    def _ok(at, tid, host):
        return {"ok": True, "code": "ok", "lines": _exchange(at, f"01:{tid}", tid, host)}

    @staticmethod
    def _timed(fn):
        started = time.monotonic()
        value = fn()
        return value, time.monotonic() - started

    def test_one_fast_server_and_three_that_never_answer_costs_the_budget_not_three_timeouts(self, pool):
        pool["answers"] = {3: self._ok("10:00:00.110", "0xc", "c-host")}
        pool["hang"] = {1, 2, 4}
        view, elapsed = self._timed(lambda: ctx.read_log(MAC, allowed=True))
        assert view["server"]["name"] == "kea-c" and view["transaction"]["tid"] == "0xc"
        assert view["query"]["hostname"] == "c-host"
        assert view["not_checked"] == ["kea-a", "kea-b", "kea-d"]
        assert self.BUDGET - 0.1 <= elapsed < self.BUDGET + 1.0, (
            f"{elapsed:.2f} s: one shared deadline, not one wait per server"
        )
        print(f"BUDGET one fast + three silent: {elapsed:.2f} s (budget {self.BUDGET} s)")

    def test_two_fast_servers_with_different_times_the_newer_wins_and_nothing_waits(self, pool):
        pool["answers"] = {
            1: self._ok("10:00:00.110", "0xa", "old"),
            2: self._ok("10:09:00.110", "0xb", "new"),
            3: {"ok": True, "code": "ok", "lines": []},
            4: {"ok": True, "code": "ok", "lines": []},
        }
        view, elapsed = self._timed(lambda: ctx.read_log(MAC, allowed=True))
        assert view["server"]["name"] == "kea-b" and view["query"]["hostname"] == "new" and "not_checked" not in view
        assert elapsed < 0.6, elapsed
        print(f"BUDGET two fast: {elapsed:.2f} s")

    def test_a_slow_server_inside_the_budget_is_used(self, pool):
        pool["answers"] = {
            1: self._ok("10:00:00.110", "0xa", "fast-old"),
            2: self._ok("10:07:00.110", "0xb", "slow-new"),
            3: {"ok": False, "code": "error", "detail": "ssh refused"},
            4: {"ok": True, "code": "ok", "lines": []},
        }
        pool["delay"] = {2: 0.4}
        view, elapsed = self._timed(lambda: ctx.read_log(MAC, allowed=True))
        assert (
            view["server"]["name"] == "kea-b" and view["query"]["hostname"] == "slow-new" and "not_checked" not in view
        )
        assert 0.35 <= elapsed < self.BUDGET, elapsed
        print(f"BUDGET one fast + one slow inside the budget: {elapsed:.2f} s")

    def test_every_server_unavailable_is_an_error_not_a_hang(self, pool):
        pool["answers"] = {i: {"ok": False, "code": "error", "detail": "ssh refused"} for i in (1, 2, 3, 4)}
        view, elapsed = self._timed(lambda: ctx.read_log(MAC, allowed=True))
        assert view["state"] == "error" and "not_checked" not in view and elapsed < 0.6
        ctx.clear_log_cache()
        pool["hang"] = {1, 2, 3, 4}
        view, elapsed = self._timed(lambda: ctx.read_log(MAC, allowed=True))
        assert view["state"] == "error" and view["not_checked"] == ["kea-a", "kea-b", "kea-c", "kea-d"]
        assert "4 server(s) could not be checked in time" in view["message"]
        assert elapsed < self.BUDGET + 1.0
        print(f"BUDGET all unavailable: {elapsed:.2f} s")

    def test_the_budget_expiring_drops_the_late_answer_and_a_late_answer_never_changes_the_cached_view(self, pool):
        pool["answers"] = {
            1: self._ok("10:00:00.110", "0xa", "in-time"),
            2: self._ok("10:09:00.110", "0xb", "too-late-and-newer"),
            3: {"ok": True, "code": "ok", "lines": []},
            4: {"ok": True, "code": "ok", "lines": []},
        }
        pool["delay"] = {2: self.BUDGET + 1.5}
        view, elapsed = self._timed(lambda: ctx.read_log(MAC, allowed=True))
        assert view["server"]["name"] == "kea-a" and view["query"]["hostname"] == "in-time"
        assert view["not_checked"] == ["kea-b"], "named, not silently dropped"
        assert self.BUDGET - 0.1 <= elapsed < self.BUDGET + 1.0, elapsed
        time.sleep(1.6)  # the late read finishes; the cached view is untouched
        again = ctx.read_log(MAC, allowed=True)
        assert again["query"]["hostname"] == "in-time" and again["not_checked"] == ["kea-b"]
        print(f"BUDGET expiring: {elapsed:.2f} s (the late answer would have taken {self.BUDGET + 1.5:.1f} s)")

    def test_fields_are_never_mixed_across_the_servers_that_answered(self, pool):
        pool["answers"] = {
            1: self._ok("10:00:00.110", "0xa", "a-host"),
            2: self._ok("10:00:02.110", "0xb", "b-host"),
            3: {"ok": True, "code": "ok", "lines": []},
            4: {"ok": True, "code": "ok", "lines": []},
        }
        view = ctx.read_log(MAC, allowed=True)
        assert view["query"]["hostname"] == "a-host" and view["transaction"]["tid"] == "0xa"
        assert view["other_complete"] == [{"server": "kea-b", "comparable": True}]

    def test_the_pool_is_four_workers_and_created_on_first_use(self):
        import inspect

        assert ctx.EVIDENCE_WORKERS == 4 and ctx.EVIDENCE_BUDGET_S == 20
        source = inspect.getsource(ctx)
        assert source.count("ThreadPoolExecutor(") == 1
        assert "_evidence_pool: concurrent.futures.ThreadPoolExecutor | None = None" in source

    def test_the_tab_says_how_many_could_not_be_checked(self):
        import pathlib
        import re

        import jinja2

        root = pathlib.Path(__file__).resolve().parent.parent
        html = (root / "templates" / "_explain_result.html").read_text(encoding="utf-8")
        paragraph = re.search(r'(<p class="u-865c33" id="explain-not-checked">.*?</p>)', html, re.S).group(1)
        env = jinja2.Environment(autoescape=True, undefined=jinja2.StrictUndefined)
        text = env.from_string(paragraph).render(
            not_checked=["kea-a", "kea-d"], exchange={"at": "x"}, log_server="kea-b"
        )
        assert "2 server(s) could not be checked in time (kea-a, kea-d)" in text
        assert "What is shown is what the rest said." in text
        assert '"not_checked"' in (root / "jen" / "routes" / "explain.py").read_text(encoding="utf-8")


class TestAFailedReadIsKeptForTheShortWindow:
    """Fixup 4, F7: (a) a view built from a failure or from servers that did not answer in time is cached for `log_tail.TTL_S`, not 30 s; (b) the evidence pool
    is sized to the servers; (c) `kea_host.tail_log` turns an SSH timeout into a failed read, which `log_tail` then keeps for its window."""

    def test_an_error_view_is_kept_three_seconds_a_good_one_thirty(self, servers, monkeypatch):
        from jen.services import log_tail

        clock = {"now": 5000.0}
        monkeypatch.setattr(ctx.time, "monotonic", lambda: clock["now"])
        monkeypatch.setattr(log_tail.time, "monotonic", lambda: clock["now"])
        servers["tails"][1] = {"ok": False, "code": "error", "detail": "ssh refused"}
        servers["tails"][2] = {"ok": False, "code": "error", "detail": "ssh refused"}
        assert ctx.read_log(MAC, allowed=True)["state"] == "error"
        asked = len(servers["asked"])
        clock["now"] += log_tail.TTL_S - 0.5
        ctx.read_log(MAC, allowed=True)
        assert len(servers["asked"]) == asked, "inside the short window: served from the cache"
        clock["now"] += 1.0
        servers["tails"][2] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        view = ctx.read_log(MAC, allowed=True)
        assert view["state"] == "ok" and view["server"]["name"] == "kea-b", (
            "a late recovery is used 3 s later, not 30 s"
        )
        # a view with a failed server is still the SHORT window (v5.68.0-beta.24: the failure is disclosed and may recover) ...
        assert view["read_failures"] == [{"server": "kea-a", "reason": "the read failed"}]
        # ... and a view with nothing wrong is kept for the long one
        servers["tails"][1] = {"ok": True, "code": "ok", "lines": OWN_LOG}
        clock["now"] += log_tail.TTL_S + 1
        assert "read_failures" not in ctx.read_log(MAC, allowed=True)
        asked = len(servers["asked"])
        clock["now"] += 20
        ctx.read_log(MAC, allowed=True)
        assert len(servers["asked"]) == asked

    def test_a_view_with_servers_that_did_not_answer_in_time_is_kept_the_short_window_too(self, monkeypatch):
        import threading

        from jen.services import log_tail

        ctx.clear_log_cache()
        gate = threading.Event()
        monkeypatch.setattr(ctx, "EVIDENCE_BUDGET_S", 0.3)
        monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda server_id, service: None)
        monkeypatch.setattr("jen.services.kea_ha.ha_status", lambda server: None)
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1"}, {"id": 2, "name": "kea-b", "ssh_host": "10.0.0.2"}],
        )

        def tail(server, path, lines, timeout=None, helper_only=False):
            if server["id"] == 2:
                gate.wait(10)
            return {"ok": True, "code": "ok", "lines": OWN_LOG}

        monkeypatch.setattr("jen.services.kea_host.tail_log", tail)
        try:
            view = ctx.read_log(MAC, allowed=True)
            assert view["not_checked"] == ["kea-b"]
            key = ("log", MAC.lower())
            assert ctx._log_cache[key][2] == log_tail.TTL_S
        finally:
            gate.set()
            ctx.clear_log_cache()

    def test_the_pool_is_sized_to_the_servers_at_first_use(self, monkeypatch):
        monkeypatch.setattr(ctx, "_evidence_pool", None)
        assert ctx._pool(1)._max_workers == 4, "never below EVIDENCE_WORKERS"
        monkeypatch.setattr(ctx, "_evidence_pool", None)
        assert ctx._pool(6)._max_workers == 12, "two workers per SSH server"

    def test_an_ssh_timeout_is_a_failed_read_not_an_exception(self, monkeypatch):

        from jen.services import kea_host

        monkeypatch.setattr(kea_host, "helper_call", lambda *a, **k: (_ for _ in ()).throw(TimeoutError("timed out")))
        res = kea_host.tail_log(
            {"id": 9, "name": "kea-x", "ssh_host": "10.0.0.9"}, "/var/log/kea.log", 1000, timeout=15, helper_only=True
        )
        assert res["ok"] is False and res["code"] == "error" and "timeout" in res["detail"].lower()

    def test_log_tail_keeps_that_failed_read_for_its_window_so_the_hang_runs_once(self, monkeypatch):

        from jen.services import kea_host, log_tail

        log_tail.clear()
        attempts = []

        def hang(*a, **k):
            attempts.append(1)
            raise TimeoutError("timed out")

        monkeypatch.setattr(kea_host, "helper_call", hang)
        server = {"id": 9, "name": "kea-x", "ssh_host": "10.0.0.9"}
        first = log_tail.tail(server, "/var/log/kea.log", 1000, timeout=15)
        second = log_tail.tail(server, "/var/log/kea.log", 1000, timeout=15)
        assert first["ok"] is False and second == first and len(attempts) == 1, "one attempt per TTL"
        log_tail.clear()


class TestTheApiAndSshHostsAreCompared:
    """Fixup 4, F3: Jen reads a Kea through the API and edits its file over SSH. If the two hosts are not the same Kea, what Jen reads back describes a
    different daemon from the one whose file it changed. The Kea settings save WARNS (never refuses) when they resolve to different addresses."""

    @staticmethod
    def _resolver(monkeypatch, table):
        from jen.services import host_match as auth

        monkeypatch.setattr(auth, "_addresses_of", lambda host, timeout=2.0: table.get(host))
        return auth

    def test_different_addresses_warn_and_name_both_hosts(self, monkeypatch):
        auth = self._resolver(monkeypatch, {"kea-api": {"10.0.0.1"}, "kea-ssh": {"10.0.0.2"}})
        text = auth.api_ssh_mismatch("http://kea-api:8000", "kea-ssh")
        assert "kea-api" in text and "kea-ssh" in text and "different addresses" in text and "Saved anyway" in text

    def test_the_same_address_or_a_shared_one_is_silent(self, monkeypatch):
        auth = self._resolver(
            monkeypatch, {"kea-api": {"10.0.0.1", "10.0.0.2"}, "kea-ssh": {"10.0.0.2"}, "same": {"10.0.0.1"}}
        )
        assert auth.api_ssh_mismatch("http://kea-api:8000", "kea-ssh") == ""
        assert auth.api_ssh_mismatch("https://same", "same") == ""

    def test_what_does_not_resolve_is_not_warned_about(self, monkeypatch):
        auth = self._resolver(monkeypatch, {"kea-api": {"10.0.0.1"}})
        assert auth.api_ssh_mismatch("http://kea-api:8000", "unresolvable") == ""
        assert auth.api_ssh_mismatch("http://unresolvable:8000", "kea-api") == ""
        assert auth.api_ssh_mismatch("", "kea-api") == "" and auth.api_ssh_mismatch("http://kea-api", "") == ""
        assert auth.api_ssh_mismatch("not a url", "kea-api") == ""

    def test_ip_literals_need_no_lookup(self):
        from jen.services import host_match as auth

        assert auth._addresses_of("10.1.2.3") == {"10.1.2.3"} and auth._addresses_of("[::1]") == {"::1"}
        assert "different addresses" in auth.api_ssh_mismatch("http://10.0.0.1:8000", "10.0.0.2")
        assert auth.api_ssh_mismatch("http://10.0.0.1:8000", "10.0.0.1") == ""

    def test_the_three_save_routes_call_it_and_only_warn(self):
        import pathlib

        source = (
            pathlib.Path(__file__).resolve().parent.parent / "jen" / "routes" / "settings" / "infrastructure.py"
        ).read_text(encoding="utf-8")
        assert source.count("__host_match.api_ssh_mismatch(") == 3
        assert source.count('flash(mismatch, "warning")') == 3


# ── v5.68.0-beta.24 (Q159): failed reads disclosed, the pool follows the servers, the HA probes inside the budget ───────────────────────


@pytest.fixture
def evidence(monkeypatch):
    """Four SSH servers whose log reads and HA probes can each be fast, slow or hung (released at teardown, threads joined BEFORE the caches are cleared),
    with the budget scaled to a fraction of a second so the elapsed time of a whole read is something a test can assert."""
    import threading

    from jen.services import log_tail

    ctx.clear_log_cache()
    monkeypatch.setattr(ctx, "EVIDENCE_BUDGET_S", 2.0)
    monkeypatch.setattr(ctx, "HA_PROBE_BUDGET_S", 0.5)
    monkeypatch.setattr(ctx, "_clock_offset_s", lambda server: 0.0)
    monkeypatch.setattr("jen.services.config_revisions.latest", lambda server_id, service: None)
    monkeypatch.setattr(ctx, "_evidence_pool", None)
    gate = threading.Event()
    world = {
        "logs": {},  # server id -> tail result
        "log_delay": {},
        "log_hang": set(),
        "ha": {},  # server id -> ha_status answer
        "ha_delay": {},
        "ha_hang": set(),
        "ha_calls": [],
        "gate": gate,
    }
    inflight = _InFlight()

    def tail(server, path, lines, timeout=None, helper_only=False):
        with inflight:
            if server["id"] in world["log_hang"]:
                gate.wait(30)
            elif world["log_delay"].get(server["id"]):
                time.sleep(world["log_delay"][server["id"]])
            return world["logs"].get(server["id"]) or {"ok": True, "code": "ok", "lines": []}

    def ha_status(server):
        world["ha_calls"].append(server["id"])
        with inflight:
            if server["id"] in world["ha_hang"]:
                gate.wait(30)
            elif world["ha_delay"].get(server["id"]):
                time.sleep(world["ha_delay"][server["id"]])
            return world["ha"].get(server["id"])

    monkeypatch.setattr("jen.services.kea_host.tail_log", tail)
    monkeypatch.setattr("jen.services.kea_ha.ha_status", ha_status)
    monkeypatch.setattr(
        extensions,
        "KEA_SERVERS",
        [{"id": i, "name": f"kea-{n}", "ssh_host": f"10.0.0.{i}"} for i, n in ((1, "a"), (2, "b"), (3, "c"), (4, "d"))],
    )
    world["tail"] = tail
    yield world
    gate.set()
    inflight.drain()
    ctx.clear_log_cache()
    log_tail.clear()


def _timed(fn):
    started = time.monotonic()
    value = fn()
    return value, time.monotonic() - started


def _good(at, tid, host):
    return {"ok": True, "code": "ok", "lines": _exchange(at, f"01:{tid}", tid, host)}


class TestAServerThatFailedIsDisclosedWhateverTheOthersShow:
    """Item 2: `read_log` kept `problem` only when no complete exchange was found; with one, a server whose SSH failed, whose helper was missing or whose
    log was gone was dropped without a word - the tab showed A's exchange and said nothing of B, which may hold a newer one. `not_checked` covered the
    deadline only. `read_failures` carries a FIXED phrase per code, never the exception text."""

    def _a_complete(self, evidence):
        evidence["logs"][1] = _good("10:00:00.110", "0xa", "a-host")
        return ctx.read_log(MAC, allowed=True)

    def test_b_ssh_failed_names_b_and_says_a_newer_exchange_may_exist(self, evidence):
        evidence["logs"][2] = {
            "ok": False,
            "code": "error",
            "detail": "Connection refused by 10.0.0.2 as root",
            "transport": True,
        }
        view = self._a_complete(evidence)
        assert view["server"]["name"] == "kea-a" and view["read_failures"] == [
            {"server": "kea-b", "reason": "SSH failed"}
        ]
        assert "10.0.0.2" not in str(view["read_failures"]) and "root" not in str(view["read_failures"]), (
            "never the exception text"
        )

    def test_b_helper_missing(self, evidence):
        evidence["logs"][2] = {"ok": False, "code": "no-helper", "detail": "not installed"}
        assert self._a_complete(evidence)["read_failures"] == [{"server": "kea-b", "reason": "the helper is missing"}]

    def test_b_log_missing(self, evidence):
        evidence["logs"][2] = {"ok": False, "code": "missing", "detail": "log file not found"}
        assert self._a_complete(evidence)["read_failures"] == [{"server": "kea-b", "reason": "the log is missing"}]

    def test_b_read_failed_for_another_reason(self, evidence):
        evidence["logs"][2] = {"ok": False, "code": "error", "detail": "tail exited 2"}
        assert self._a_complete(evidence)["read_failures"] == [{"server": "kea-b", "reason": "the read failed"}]

    def test_b_timeout_is_not_checked_not_a_read_failure(self, evidence):
        evidence["log_hang"] = {2}
        view = self._a_complete(evidence)
        assert view["not_checked"] == ["kea-b"] and "read_failures" not in view

    def test_b_answered_but_never_named_the_client_is_not_a_failure(self, evidence):
        evidence["logs"][2] = {"ok": True, "code": "ok", "lines": ELSEWHERE_LOG}
        view = self._a_complete(evidence)
        assert view["server"]["name"] == "kea-a" and "read_failures" not in view and "not_checked" not in view

    def test_both_complete_has_no_failure_to_disclose(self, evidence):
        evidence["logs"][2] = _good("10:00:02.110", "0xb", "b-host")
        view = self._a_complete(evidence)
        assert "read_failures" not in view and view["other_complete"] == [{"server": "kea-b", "comparable": True}]

    def test_several_failures_are_all_named_and_the_view_is_kept_the_short_window(self, evidence):
        from jen.services import log_tail

        evidence["logs"][2] = {"ok": False, "code": "no-helper"}
        evidence["logs"][3] = {"ok": False, "code": "missing"}
        view = self._a_complete(evidence)
        assert [f["server"] for f in view["read_failures"]] == ["kea-b", "kea-c"]
        assert ctx._log_cache[("log", MAC.lower())][2] == log_tail.TTL_S, (
            "a recovery is picked up within the short window"
        )

    def test_the_tab_prints_the_sentence(self):
        import pathlib
        import re

        import jinja2

        html = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "_explain_result.html").read_text(
            encoding="utf-8"
        )
        paragraph = re.search(r'(<p class="u-865c33" id="explain-read-failures">.*?</p>)', html, re.S).group(1)
        env = jinja2.Environment(autoescape=True, undefined=jinja2.StrictUndefined)
        one = env.from_string(paragraph).render(
            exchange={"server": "kea-a"}, read_failures=[{"server": "kea-b", "reason": "SSH failed"}]
        )
        assert (
            one
            == '<p class="u-865c33" id="explain-read-failures">The exchange shown came from kea-a. kea-b could not be checked (SSH failed), so a newer exchange may exist there.</p>'
        )
        two = env.from_string(paragraph).render(
            exchange={"server": "kea-a"},
            read_failures=[
                {"server": "kea-b", "reason": "SSH failed"},
                {"server": "kea-c", "reason": "the log is missing"},
            ],
        )
        assert (
            "kea-b could not be checked (SSH failed); kea-c could not be checked (the log is missing), so a newer exchange may exist on one of them."
            in two
        )
        none = env.from_string(paragraph).render(
            exchange=None, read_failures=[{"server": "kea-b", "reason": "SSH failed"}]
        )
        assert "The exchange shown" not in none and "kea-b could not be checked (SSH failed)." in none

    def test_the_next_page_load_is_the_cached_view_and_a_recovery_clears_it(self, evidence, monkeypatch):
        """The trace for the new field: the next load inside the window is the same view; after the window, a recovered server leaves nothing behind."""
        from jen.services import log_tail

        clock = {"now": 9000.0}
        monkeypatch.setattr(ctx.time, "monotonic", lambda: clock["now"])
        monkeypatch.setattr(log_tail.time, "monotonic", lambda: clock["now"])
        evidence["logs"][2] = {"ok": False, "code": "no-helper"}
        first = self._a_complete(evidence)
        assert ctx.read_log(MAC, allowed=True) is first
        evidence["logs"][2] = _good("10:00:04.110", "0xb", "b-host")
        clock["now"] += log_tail.TTL_S + 0.5
        again = ctx.read_log(MAC, allowed=True)
        assert "read_failures" not in again and again["other_complete"] == [{"server": "kea-b", "comparable": True}]


class TestThePoolFollowsTheServerCount:
    """Item 4: `_pool` was sized once, at first use: one server at start and eight configured later was still four workers, and the later servers queued
    past the budget."""

    def test_one_server_then_eight_the_pool_follows_and_the_old_one_is_shut_down(self, monkeypatch):
        monkeypatch.setattr(ctx, "_evidence_pool", None)
        first = ctx._pool(1)
        assert first._max_workers == 4
        second = ctx._pool(8)
        assert second is not first and second._max_workers == 16 and first._shutdown, (
            "replaced, the old one shut down without waiting"
        )
        assert ctx._pool(8) is second, "the same size again is the same pool"

    def test_removing_servers_never_shrinks_it_and_it_is_bounded(self, monkeypatch):
        monkeypatch.setattr(ctx, "_evidence_pool", None)
        big = ctx._pool(6)
        assert big._max_workers == 12
        assert ctx._pool(1) is big and ctx._pool(0) is big, "never shrinks"
        assert ctx._pool(100)._max_workers == ctx.EVIDENCE_WORKERS_MAX == 16
        assert ctx._pool(1000)._max_workers == 16, "bounded by the cap"

    def test_reads_holding_the_old_pools_workers_do_not_block_the_new_one(self, monkeypatch):
        import threading

        monkeypatch.setattr(ctx, "_evidence_pool", None)
        gate = threading.Event()
        old = ctx._pool(1)
        stuck = [old.submit(gate.wait, 30) for _ in range(4)]  # all four workers are busy with slow reads
        new = ctx._pool(8)
        started = time.monotonic()
        assert new.submit(lambda: "answered").result(timeout=5) == "answered"
        assert time.monotonic() - started < 1.0, "the new pool did not queue behind the old pool's hung reads"
        gate.set()
        for f in stuck:
            f.result(timeout=5)

    def test_eight_servers_added_after_a_one_server_start_are_all_read_inside_the_budget(self, evidence, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1"}])
        evidence["logs"][1] = _good("10:00:00.110", "0xa", "a-host")
        ctx.read_log(MAC, allowed=True)
        assert ctx._evidence_pool._max_workers == 4
        ctx.clear_log_cache()
        eight = [{"id": i, "name": f"kea-{i}", "ssh_host": f"10.0.0.{i}"} for i in range(1, 9)]
        monkeypatch.setattr(extensions, "KEA_SERVERS", eight)
        for i in range(2, 9):
            evidence["logs"][i] = _good(f"10:00:{i:02d}.110", f"0x{i}", f"host-{i}")
            evidence["log_delay"][i] = (
                0.5  # every server needs 0.5 s: four workers would need two rounds (~1.0 s), sixteen need one
            )
        view, elapsed = _timed(lambda: ctx.read_log(MAC, allowed=True))
        assert ctx._evidence_pool._max_workers == 16 and "not_checked" not in view
        assert elapsed < 0.85, f"{elapsed:.2f} s: the later servers queued behind four workers"
        print(f"POOL eight slow servers on a resized pool: {elapsed:.2f} s")


class TestTheHaProbesSitInsideTheBudget:
    """Item 5: the HA probes ran sequentially BEFORE the log budget started - N unreachable Control Agents cost 10 s each on top of the 20 s. They run on the
    same pool now, concurrently with the log reads, against the same deadline and capped at HA_PROBE_BUDGET_S. The total elapsed time is the assertion."""

    BUDGET, SLICE, MARGIN = 2.0, 0.5, 0.6

    @staticmethod
    def _active():
        return {"local": {"role": "primary", "scopes": ["server1"], "state": "hot-standby"}, "remote": {}}

    def test_two_unreachable_apis_and_a_reachable_ssh_log(self, evidence):
        evidence["ha_hang"] = {1, 2}
        evidence["ha"][3] = self._active()
        for i in (1, 2, 3):
            evidence["logs"][i] = _good(f"10:00:0{i}.110", f"0x{i}", f"host-{i}")
        view, elapsed = _timed(lambda: ctx.read_log(MAC, allowed=True))
        assert view["ha_order"] == "partial" and "not_checked" not in view
        assert view["server"]["name"] == "kea-c", "the server whose probe answered (and is active) is first in order"
        assert self.SLICE - 0.1 <= elapsed < self.BUDGET + self.MARGIN, elapsed
        print(
            f"HA two unreachable APIs + reachable logs: {elapsed:.2f} s (probe slice {self.SLICE} s, budget {self.BUDGET} s)"
        )

    def test_four_unreachable_apis_total_under_the_budget(self, evidence):
        evidence["ha_hang"] = {1, 2, 3, 4}
        evidence["logs"][1] = _good("10:00:01.110", "0x1", "host-1")
        view, elapsed = _timed(lambda: ctx.read_log(MAC, allowed=True))
        assert view["ha_order"] == "unknown" and view["server"]["name"] == "kea-a", "configured order"
        assert elapsed < self.BUDGET, f"{elapsed:.2f} s: four hung Control Agents must not cost four timeouts"
        print(f"HA four unreachable APIs: {elapsed:.2f} s")

    def test_a_warm_memo_asks_nothing(self, evidence):
        evidence["ha"][2] = self._active()
        evidence["logs"][2] = _good("10:00:02.110", "0x2", "host-2")
        ctx.read_log(MAC, allowed=True)
        calls = len(evidence["ha_calls"])
        assert calls == 4
        view, elapsed = _timed(lambda: ctx.read_log(OTHER, allowed=True))  # a second client inside the memo window
        assert len(evidence["ha_calls"]) == calls and elapsed < 0.4, (len(evidence["ha_calls"]), elapsed)
        assert "ha_order" not in view
        print(f"HA warm memo: {elapsed:.2f} s")

    def test_a_cold_memo_probes_once_and_a_complete_answer_leaves_no_note(self, evidence):
        evidence["ha"][3] = self._active()
        evidence["logs"][3] = _good("10:00:03.110", "0x3", "host-3")
        view, elapsed = _timed(lambda: ctx.read_log(MAC, allowed=True))
        assert (
            sorted(evidence["ha_calls"]) == [1, 2, 3, 4]
            and "ha_order" not in view
            and view["server"]["name"] == "kea-c"
        )
        assert elapsed < 0.5, elapsed
        print(f"HA cold memo, every probe answers: {elapsed:.2f} s")

    def test_a_slow_api_with_a_fast_ssh_log_is_waited_for_inside_the_slice(self, evidence):
        evidence["ha_delay"] = {1: 0.3}
        evidence["ha"][1] = self._active()
        evidence["logs"][1] = _good("10:00:01.110", "0x1", "host-1")
        view, elapsed = _timed(lambda: ctx.read_log(MAC, allowed=True))
        assert "ha_order" not in view and view["server"]["name"] == "kea-a"
        assert 0.25 <= elapsed < self.SLICE + 0.4, elapsed
        print(f"HA slow API (0.3 s), fast SSH: {elapsed:.2f} s")

    def test_every_read_succeeds_after_the_fallback_ordering(self, evidence):
        evidence["ha_hang"] = {1, 2, 3, 4}
        for i in (1, 2, 3, 4):
            evidence["logs"][i] = _good(f"10:0{i}:00.110", f"0x{i}", f"host-{i}")
        view, elapsed = _timed(lambda: ctx.read_log(MAC, allowed=True))
        assert view["ha_order"] == "unknown" and "not_checked" not in view and "read_failures" not in view
        assert view["server"]["name"] == "kea-d" and view["query"]["hostname"] == "host-4", (
            "the newest, whatever the order"
        )
        assert elapsed < self.BUDGET, elapsed
        print(f"HA all probes hung, all reads succeed: {elapsed:.2f} s")

    def test_the_memo_keeps_whatever_was_learned_and_the_tab_notes_the_order(self, evidence):
        import pathlib
        import re

        import jinja2

        evidence["ha_hang"] = {1, 2}
        evidence["ha"][3] = self._active()
        ctx.read_log(MAC, allowed=True)
        assert ctx._evidence_memo[3] == "partial" and ctx._evidence_memo[2][0] == "3"
        before = len(evidence["ha_calls"])
        ctx.read_log(OTHER, allowed=True)
        assert len(evidence["ha_calls"]) == before, "the partial answer is memoised, not re-probed per page"
        html = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "_explain_result.html").read_text(
            encoding="utf-8"
        )
        paragraph = re.search(r'(<p class="u-865c33" id="explain-ha-order">.*?</p>)', html, re.S).group(1)
        text = (
            jinja2.Environment(autoescape=True, undefined=jinja2.StrictUndefined)
            .from_string(paragraph)
            .render(ha_order="partial")
        )
        assert "HA order not determined; servers read in configured order." in text


# ── v5.68.0-beta.25 (Q160): Explain keys its servers by id, not by object ──────────────────────────────────────────────────────────


class TestExplainKeysItsServersByIdNotByObject:
    """Item 3: `read_log` keyed its futures by `id(server)` over the CURRENT `KEA_SERVERS`, while `_evidence_plan` returned the memo's list - the dict objects of
    up to 30 s ago, keyed by server ids only. After any config reload that rebuilt the server dicts with the same ids, `pending[id(server)]` raised KeyError.
    The HA probes had the same keying. The memo now holds KEYS plus a signature of (id, api_url, ssh_host), and the list is rebuilt from the servers as
    configured now."""

    @staticmethod
    def _rebuilt(**overrides):
        """The same four servers as fresh dict objects (what a config reload does), optionally with a changed field on one id."""
        servers = [
            {"id": i, "name": f"kea-{n}", "ssh_host": f"10.0.0.{i}"}
            for i, n in ((1, "a"), (2, "b"), (3, "c"), (4, "d"))
        ]
        for sid, fields in overrides.items():
            servers[int(sid) - 1].update(fields)
        return servers

    @staticmethod
    def _forget_views():
        """Forget the per-client views and the 3 s shared tail cache, but NOT the 30 s order memo - what the tests are about."""
        from jen.services import log_tail

        ctx._log_cache.clear()
        log_tail.clear()

    @staticmethod
    def _spy(evidence, monkeypatch):
        """Record which server OBJECTS and hosts the tails were asked of."""
        seen = []
        real = evidence["tail"]

        def tail(server, path, lines, timeout=None, helper_only=False):
            seen.append((id(server), server["ssh_host"]))
            return real(server, path, lines, timeout, helper_only)

        monkeypatch.setattr("jen.services.kea_host.tail_log", tail)
        return seen

    def test_the_dicts_replaced_with_the_same_ids_after_the_memo_is_warm_raise_nothing_and_the_current_objects_are_read(
        self, evidence, monkeypatch
    ):
        evidence["ha"][2] = {"local": {"role": "primary", "scopes": ["server1"], "state": "hot-standby"}, "remote": {}}
        evidence["logs"][2] = _good("10:00:02.110", "0x2", "host-2")
        first = ctx.read_log(MAC, allowed=True)
        assert first["server"]["name"] == "kea-b" and ctx._evidence_memo is not None
        new_objects = self._rebuilt()
        monkeypatch.setattr(extensions, "KEA_SERVERS", new_objects)
        self._forget_views()  # only the per-client view and the 3 s tail cache; the 30 s order memo stays warm
        seen = self._spy(evidence, monkeypatch)
        calls = len(evidence["ha_calls"])
        view = ctx.read_log(OTHER, allowed=True)  # a different client: no exception
        assert view["state"] == "ok" and view["server"]["name"] == "kea-b"
        assert {oid for oid, _host in seen} == {id(s) for s in new_objects}, (
            "the tails were asked of the CURRENT objects, not the memo's"
        )
        assert len(evidence["ha_calls"]) == calls, (
            "the signature is unchanged, so the order memo was kept (and rebuilt from the new objects)"
        )
        assert [s["id"] for s in ctx._evidence_servers()] == [2, 1, 3, 4], (
            "the HA-active server first, then configured order"
        )

    def test_an_ssh_host_changed_under_the_same_id_invalidates_the_memo_and_the_new_host_is_tailed(
        self, evidence, monkeypatch
    ):
        evidence["logs"][1] = _good("10:00:01.110", "0x1", "host-1")
        ctx.read_log(MAC, allowed=True)
        probes = len(evidence["ha_calls"])
        monkeypatch.setattr(extensions, "KEA_SERVERS", self._rebuilt(**{"1": {"ssh_host": "10.9.9.9"}}))
        self._forget_views()
        seen = self._spy(evidence, monkeypatch)
        ctx.read_log(OTHER, allowed=True)
        assert len(evidence["ha_calls"]) == probes + 4, "the signature changed: every server was probed again"
        assert "10.9.9.9" in {host for _oid, host in seen} and "10.0.0.1" not in {host for _oid, host in seen}

    def test_a_server_added_or_removed_changes_the_order_and_the_pool_follows(self, evidence, monkeypatch):
        ctx.read_log(MAC, allowed=True)
        assert [s["id"] for s in ctx._evidence_servers()] == [1, 2, 3, 4]
        grown = self._rebuilt() + [{"id": i, "name": f"kea-{i}", "ssh_host": f"10.0.0.{i}"} for i in range(5, 11)]
        monkeypatch.setattr(extensions, "KEA_SERVERS", grown)
        self._forget_views()
        ctx.read_log(OTHER, allowed=True)
        assert [s["id"] for s in ctx._evidence_servers()] == list(
            range(1, 11)
        ) and ctx._evidence_pool._max_workers == 16
        monkeypatch.setattr(extensions, "KEA_SERVERS", [s for s in grown if s["id"] not in (2, 5)])
        self._forget_views()
        ctx.read_log(MAC, allowed=True)
        assert [s["id"] for s in ctx._evidence_servers()] == [1, 3, 4, 6, 7, 8, 9, 10], (
            "removed servers are gone from the order"
        )
        assert ctx._evidence_pool._max_workers == 16, "and the pool never shrinks"

    def test_two_overlapping_reads_during_a_config_change_both_complete(self, evidence, monkeypatch):
        import threading

        evidence["logs"][1] = _good("10:00:01.110", "0x1", "host-1")
        evidence["log_delay"] = {1: 0.4, 2: 0.4, 3: 0.4, 4: 0.4}
        results, errors = {}, []

        def read(key, mac):
            try:
                results[key] = ctx.read_log(mac, allowed=True)
            except Exception as e:  # pragma: no cover
                errors.append(e)

        first = threading.Thread(target=read, args=("first", MAC))
        first.start()
        time.sleep(0.15)  # the first read is in flight against the old objects
        monkeypatch.setattr(extensions, "KEA_SERVERS", self._rebuilt())  # a config reload rebuilds the server dicts
        second = threading.Thread(target=read, args=("second", OTHER))
        second.start()
        first.join(10)
        second.join(10)
        assert errors == [] and set(results) == {"first", "second"}
        assert results["first"]["server"]["name"] == "kea-a" and results["second"]["state"] == "ok"

    def test_a_server_that_is_unreachable_after_the_replacement_is_still_disclosed(self, evidence, monkeypatch):
        evidence["logs"][1] = _good("10:00:01.110", "0x1", "host-1")
        ctx.read_log(MAC, allowed=True)
        monkeypatch.setattr(extensions, "KEA_SERVERS", self._rebuilt())
        self._forget_views()
        evidence["logs"][2] = {"ok": False, "code": "error", "detail": "refused", "transport": True}
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-a" and view["read_failures"] == [
            {"server": "kea-b", "reason": "SSH failed"}
        ]

    def test_a_server_in_the_plan_that_was_never_submitted_is_not_checked_not_an_exception(self, evidence, monkeypatch):
        ghost = {"id": 99, "name": "kea-ghost", "ssh_host": "10.0.0.99"}
        real = ctx._evidence_plan
        monkeypatch.setattr(ctx, "_evidence_plan", lambda deadline: (real(deadline)[0] + [ghost], None))
        evidence["logs"][1] = _good("10:00:01.110", "0x1", "host-1")
        view = ctx.read_log(MAC, allowed=True)
        assert view["server"]["name"] == "kea-a" and view["not_checked"] == ["kea-ghost"]

    def test_no_explain_code_keys_anything_by_object_identity(self):
        """Self-check (b), as a test."""
        import inspect

        source = inspect.getsource(ctx)
        assert "id(server" not in source and "id(s)" not in source, (
            "a server is identified by `_server_key`, never by id(obj)"
        )
        assert "def _server_key" in source and "def _signature" in source

    def test_the_memo_holds_keys_and_the_signature_not_the_old_objects(self, evidence):
        ctx.read_log(MAC, allowed=True)
        stamp, signature, keys, ha_order = ctx._evidence_memo
        assert all(isinstance(k, str) for k in keys) and keys == ["1", "2", "3", "4"]
        assert signature == (
            ("1", None, "10.0.0.1"),
            ("2", None, "10.0.0.2"),
            ("3", None, "10.0.0.3"),
            ("4", None, "10.0.0.4"),
        )
