"""
tests/test_explain_inputs.py
────────────────────────────
v5.68.0-beta.2 (Q135) — the client Explain evaluates, built from the MAC, the lease row, Kea's own log and what was typed,
each input labelled by where it came from (jen/services/explain_inputs.py); plus the pure parts of the lookups' glue
(jen/services/explain_context.py) and the Changes tab's element filter. Pure: `pytest --noconftest tests/test_explain_inputs.py`.
"""

import pytest

from jen.services import explain_context as ctx
from jen.services import explain_inputs as ei
from jen.services.client_changes import element_matches

MAC = "aa:bb:cc:dd:ee:01"
LEASE = {
    "ip": "10.0.0.5",
    "subnet_id": 1,
    "hostname": "lease-host",
    "client_id": "01AABBCCDDEE01",
    "user_context": '{ "ISC": { "relay-agent-info": { "remote-id": "0A0B0C0D0E0F", "sub-options": "0x010441424344" } } }',
}
CLASSES = {"classes": ["ALL", "VENDOR_CLASS_MSFT 5.0", "windows"], "at": "2026-10-04 15:10:39.670"}
QUERY = {
    "at": "2026-10-04 15:10:41.905",
    "hostname": "packet-host",
    "vendor_class": "MSFT 5.0",
    "client_id": "01:aa:bb:cc:dd:ee:01",
    "user_class": "iPXE",
    "circuit_id": "eth0/1/7",
    "remote_id": "0a0b0c0d0e0f",
}
CID = {"client_id": "01:aa:bb:cc:dd:ee:01", "at": "2026-10-04 15:10:41.700"}


class TestBuild:
    def test_the_mac_alone(self):
        built = ei.build(MAC.upper())
        assert built["client"]["mac"] == MAC and built["sources"] == {"mac": "mac"}
        assert not built["assigned"] and all(not built["client"][f] for f in ei.FIELDS if f != "mac")

    def test_the_lease_gives_client_id_hostname_and_the_relays_ids(self):
        built = ei.build(MAC, lease=LEASE)
        assert built["client"]["client_id"] == "01:aa:bb:cc:dd:ee:01" and built["sources"]["client_id"] == "lease"
        assert built["client"]["hostname"] == "lease-host" and built["sources"]["hostname"] == "lease"
        assert built["client"]["circuit_id"] == "ABCD" and built["sources"]["circuit_id"] == "lease-relay"
        assert built["client"]["remote_id"] == "0a0b0c0d0e0f" and built["sources"]["remote_id"] == "lease-relay"

    def test_the_assigned_classes_give_the_vendor_class_and_the_class_list(self):
        built = ei.build(MAC, log={"classes": CLASSES})
        assert built["client"]["vendor_class"] == "MSFT 5.0" and built["sources"]["vendor_class"] == "log-classes"
        assert built["when"]["vendor_class"] == "at 2026-10-04 15:10:39.670"
        assert built["assigned"] == {"classes": CLASSES["classes"], "at": CLASSES["at"]}

    def test_the_packet_dump_outranks_the_lease_and_the_classes(self):
        built = ei.build(MAC, lease=LEASE, log={"classes": CLASSES, "query": QUERY, "cid": CID})
        c, s = built["client"], built["sources"]
        assert c["hostname"] == "packet-host" and s["hostname"] == "log-packet"
        assert c["vendor_class"] == "MSFT 5.0" and s["vendor_class"] == "log-packet"
        assert c["user_class"] == "iPXE" and c["circuit_id"] == "eth0/1/7" and s["circuit_id"] == "log-packet"

    def test_the_label_outranks_the_lease_for_the_client_id(self):
        built = ei.build(MAC, lease=LEASE, log={"cid": CID})
        assert built["sources"]["client_id"] == "log-label" and built["when"]["client_id"].startswith("at ")

    def test_what_was_typed_outranks_everything(self):
        built = ei.build(
            MAC,
            lease=LEASE,
            log={"query": QUERY, "classes": CLASSES},
            typed={"hostname": "typed-host", "giaddr": "10.0.0.1"},
        )
        assert built["client"]["hostname"] == "typed-host" and built["sources"]["hostname"] == "typed"
        assert built["client"]["giaddr"] == "10.0.0.1" and built["sources"]["giaddr"] == "typed"
        assert "hostname" not in built["when"], "a typed value carries no log timestamp"

    def test_blanks_do_not_blank_what_was_inferred_and_the_mac_cannot_be_typed_over(self):
        built = ei.build(
            MAC, lease=LEASE, typed={"hostname": "   ", "client_id": "", "mac": "de:ad:be:ef:00:00", "bogus": "x"}
        )
        assert built["client"]["hostname"] == "lease-host" and built["client"]["mac"] == MAC
        assert "bogus" not in built["client"]

    def test_auto_off_is_the_old_behaviour(self):
        built = ei.build(
            MAC, lease=LEASE, log={"query": QUERY, "classes": CLASSES}, typed={"hostname": "typed-host"}, auto=False
        )
        assert (
            built["client"]["hostname"] == "typed-host"
            and not built["client"]["client_id"]
            and not built["client"]["vendor_class"]
        )
        assert built["assigned"] is None

    def test_a_lease_with_nothing_to_give(self):
        built = ei.build(MAC, lease={"ip": "10.0.0.5", "hostname": "", "client_id": None, "user_context": None})
        assert built["sources"] == {"mac": "mac"}

    def test_provenance_lists_what_has_a_value_in_field_order(self):
        built = ei.build(MAC, lease=LEASE, typed={"vendor_class": "x"})
        rows = ei.provenance(built)
        assert [r["field"] for r in rows] == [
            "mac",
            "client_id",
            "vendor_class",
            "hostname",
            "circuit_id",
            "circuit_id_hex",
            "remote_id",
        ]
        by = {r["field"]: r for r in rows}
        assert by["client_id"]["label"] == "the current lease" and by["vendor_class"]["label"] == "typed"
        assert by["mac"]["label"] == "the MAC you asked about"


class TestHint:
    def test_not_allowed_says_who_may(self):
        text = ctx.hint_for({"missing_inputs": ["vendor_class"]}, {"state": "not-allowed"})
        assert "admin with access to every subnet" in text

    def test_an_unreadable_log_says_why_and_to_type_it(self):
        text = ctx.hint_for(
            {"missing_inputs": ["hostname"]},
            {"state": "no-helper", "message": "Reading Kea's log needs the Kea host helper."},
        )
        assert text.startswith("Reading Kea's log needs the Kea host helper.") and "Type what is missing" in text

    def test_a_readable_log_names_the_level_that_unlocks_the_rest(self):
        text = ctx.hint_for({"missing_inputs": ["vendor_class", "circuit_id"]}, {"state": "ok"})
        assert "debuglevel 55" in text and "debuglevel 45" in text and "store-extended-info" in text

    def test_nothing_missing_nothing_said(self):
        assert ctx.hint_for({"missing_inputs": []}, {"state": "ok"}) == "" and ctx.hint_for(None, None) == ""


class TestReadLogGates:
    def test_a_caller_who_may_not_read_the_log_gets_no_log_and_no_server_call(self, monkeypatch):
        called = []
        monkeypatch.setattr("jen.services.kea_host.tail_log", lambda *a, **k: called.append(a) or {})
        view = ctx.read_log(MAC, allowed=False)
        assert view["state"] == "not-allowed" and not view["classes"] and called == []

    def test_a_host_with_no_ssh_is_not_asked(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "k", "ssh_host": ""}])
        called = []
        monkeypatch.setattr("jen.services.kea_host.tail_log", lambda *a, **k: called.append(a) or {})
        assert ctx.read_log(MAC, allowed=True)["state"] == "no-helper" and called == []

    def test_no_server_at_all(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [])
        assert ctx.read_log(MAC, allowed=True)["state"] == "no-server"

    def test_a_read_is_parsed_cached_and_not_repeated(self, monkeypatch):
        from jen import extensions

        ctx.clear_log_cache()
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "k", "ssh_host": "10.0.0.9"}])
        line = (
            "2026-10-04 15:10:39.670 DEBUG [kea-dhcp4.dhcp4/1.1] DHCP4_CLASSES_ASSIGNED [hwtype=1 aa:bb:cc:dd:ee:01], "
            "cid=[01:aa:bb:cc:dd:ee:01], tid=0x1: client packet has been assigned on DHCPDISCOVER message to the "
            "following classes: ALL, VENDOR_CLASS_Acme, vip"
        )
        calls = []

        def tail(server, path, lines, timeout=None, helper_only=False):
            calls.append((path, lines, helper_only))
            return {"ok": True, "code": "ok", "lines": [line]}

        monkeypatch.setattr("jen.services.kea_host.tail_log", tail)
        first = ctx.read_log(MAC, allowed=True)
        again = ctx.read_log(MAC, allowed=True)
        assert first["state"] == "ok" and first["classes"]["classes"] == ["ALL", "VENDOR_CLASS_Acme", "vip"]
        assert first["cid"]["client_id"] == "01:aa:bb:cc:dd:ee:01" and first["query"] is None
        assert again is first and len(calls) == 1 and calls[0][1:] == (1000, True), "one helper-only tail, cached after"
        ctx.clear_log_cache()

    @pytest.mark.parametrize(
        "reply,state",
        [
            ({"ok": False, "code": "no-helper"}, "no-helper"),
            ({"ok": False, "code": "missing"}, "missing"),
            ({"ok": False, "code": "error", "detail": "boom"}, "error"),
        ],
    )
    def test_each_failure_is_its_own_state(self, monkeypatch, reply, state):
        from jen import extensions

        ctx.clear_log_cache()
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "k", "ssh_host": "10.0.0.9"}])
        monkeypatch.setattr("jen.services.kea_host.tail_log", lambda *a, **k: reply)
        assert ctx.read_log(MAC, allowed=True)["state"] == state
        ctx.clear_log_cache()

    def test_the_overview_does_not_pay_for_a_round_trip(self, monkeypatch):
        from jen import extensions

        ctx.clear_log_cache()
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "k", "ssh_host": "10.0.0.9"}])
        called = []
        monkeypatch.setattr("jen.services.kea_host.tail_log", lambda *a, **k: called.append(a) or {})
        assert ctx.read_log(MAC, allowed=True, fetch=False)["state"] == "not-fetched" and called == []


class TestElementFilter:
    @pytest.mark.parametrize(
        "label,element,expected",
        [
            ("pool 10.0.0.100 - 10.0.0.200", "pool 10.0.0.100 - 10.0.0.200", True),
            ("pool 10.0.0.100 - 10.0.0.200", "POOL 10.0.0.100 - 10.0.0.200", True),
            ("pool 10.0.0.100 - 10.0.0.200", "pool", True),
            ("pool 10.0.0.100 - 10.0.0.200", "pool 10.0.0.201 - 10.0.0.250", False),
            ("subnet 1 (10.0.0.0/24)", "subnet 1 (10.0.0.0/24)", True),
            ("subnet 1 (10.0.0.0/24)", "subnet", True),
            ("subnet 1 (10.0.0.0/24)", "subnet 2 (10.0.1.0/24)", False),
            ("reservation aa:bb:cc:dd:ee:ff", "reservation", True),
            ("global reservation aa:bb:cc:dd:ee:ff", "reservation", True),
            ("class voip", "class voip", True),
            ("class voip", "class", True),
            ("class voip2", "class voip", False),
            ("shared network campus", "shared network", True),
            ("pool x", "", True),
            ("pool x", None, True),
        ],
    )
    def test_the_filter(self, label, element, expected):
        assert element_matches(label, element) is expected
