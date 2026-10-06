"""
tests/test_client_dns.py
─────────────────────────
v5.68.0-beta.11 (Q146) — the Investigation page's DNS tab checks EVERY record the caller may see for the client, not the first
reservation and the newest lease. The first groups are pure (`pytest --noconftest tests/test_client_dns.py -k "not Route"`): the
rows a subject yields (v4 and v6, deduplicated by name and address, capped with the total reported) and `_dns_tab` over a fake
resolver. The Route group drives the real tab against seeded reservations: two records, the first fine, the second wrong - the
second mismatch shows.
"""

import pytest

from jen.services import client_dns as cd
from jen.services.client_subject import ClientSubject

MAC = "aa:bb:cc:dd:ef:20"
MAC_HEX = "AABBCCDDEF20"


def _view(**kw):
    base = {"kind": "mac", "identifier": MAC, "mac": MAC, "ip": "10.45.0.5"}
    base.update(kw)
    return ClientSubject(**base)


class TestTheRows:
    def test_every_v4_reservation_and_lease_is_a_row_not_just_the_first(self):
        view = _view(
            reservations=[
                {"ip": "10.45.0.10", "hostname": "first", "subnet_id": 1},
                {"ip": "10.45.1.10", "hostname": "second", "subnet_id": 2},
            ],
            leases4=[
                {"ip": "10.45.0.5", "hostname": "leased", "subnet_id": 1},
                {"ip": "10.45.1.5", "hostname": "older-lease", "subnet_id": 2},
            ],
        )
        rows, total = cd.records_for(view)
        assert [(r["name"], r["ip"], r["source"]) for r in rows] == [
            ("first", "10.45.0.10", "reservation"),
            ("second", "10.45.1.10", "reservation"),
            ("leased", "10.45.0.5", "lease"),
            ("older-lease", "10.45.1.5", "lease"),
        ]
        assert total == 4

    def test_the_same_name_and_address_from_a_reservation_and_a_lease_is_one_row_naming_both(self):
        view = _view(
            reservations=[{"ip": "10.45.0.10", "hostname": "Host", "subnet_id": 1}],
            leases4=[{"ip": "10.45.0.10", "hostname": "host", "subnet_id": 1}],
        )
        rows, total = cd.records_for(view)
        assert len(rows) == 1 and total == 1 and rows[0]["source"] == "reservation, lease"

    def test_the_same_name_at_a_different_address_is_a_different_record(self):
        view = _view(
            reservations=[{"ip": "10.45.0.10", "hostname": "host", "subnet_id": 1}],
            leases4=[{"ip": "10.45.0.77", "hostname": "host", "subnet_id": 1}],
        )
        assert [r["ip"] for r in cd.records_for(view)[0]] == ["10.45.0.10", "10.45.0.77"]

    def test_a_record_with_no_name_or_no_address_is_not_a_row(self):
        view = _view(
            reservations=[{"ip": "10.45.0.10", "hostname": ""}, {"ip": "", "hostname": "x"}],
            leases4=[{"ip": "garbage", "hostname": "y"}, {"ip": "10.45.0.5", "hostname": None}],
        )
        assert cd.records_for(view) == ([], 0)

    def test_v6_reservation_addresses_and_v6_leases_are_rows_but_delegated_prefixes_are_not(self):
        view = _view(
            kind="duid",
            mac="",
            reservations6=[
                {
                    "hostname": "v6host",
                    "subnet_id": 7,
                    "reservations": [
                        {"address": "2001:db8::10", "type_name": "IA_NA"},
                        {"address": "2001:db8:1000::", "type_name": "IA_PD", "prefix_len": 56},
                    ],
                }
            ],
            leases6=[
                {"address": "2001:DB8::0020", "type_name": "IA_NA", "hostname": "v6host"},
                {"address": "2001:db8:2000::", "type_name": "IA_PD", "hostname": "v6host"},
                {"address": "2001:db8::30", "type_name": "IA_TA", "hostname": "temp"},
            ],
        )
        rows, _total = cd.records_for(view)
        assert [(r["name"], r["ip"], r["source"]) for r in rows] == [
            ("v6host", "2001:db8::10", "reservation"),
            ("v6host", "2001:db8::20", "lease"),
        ], "addresses are written in their one canonical form so the same address from two places is one record"

    def test_a_dual_stack_client_has_one_row_per_address(self):
        view = _view(
            reservations=[{"ip": "10.45.0.10", "hostname": "dual"}],
            reservations6=[{"hostname": "dual", "reservations": [{"address": "2001:db8::10", "type_name": "IA_NA"}]}],
        )
        assert [r["ip"] for r in cd.records_for(view)[0]] == ["10.45.0.10", "2001:db8::10"]

    def test_the_cap_reports_how_many_there_were(self):
        view = _view(leases4=[{"ip": f"10.45.0.{i}", "hostname": f"h{i}"} for i in range(1, 31)])
        rows, total = cd.records_for(view, limit=5)
        assert len(rows) == 5 and total == 30
        assert cd.DEFAULT_LIMIT == 20 and len(cd.records_for(view)[0]) == 20


@pytest.fixture
def resolver(monkeypatch):
    """The Jen host's resolver, replaced: `answers[name]` is what _run_verify would return for that fully qualified name."""
    from jen.routes import ddns

    answers = {}
    monkeypatch.setattr(ddns, "_reconcile_suffix", lambda: "")
    monkeypatch.setattr(ddns, "_run_verify", lambda name, ip: answers.get(name, {"forward_error": "no such host"}))
    return answers


class TestTheTabOverAFakeResolver:
    def test_two_records_the_first_fine_and_the_second_wrong_the_second_mismatch_shows(self, resolver):
        from jen.routes.client import _dns_tab

        resolver["good"] = {"forward_ips": ["10.45.0.10"], "reverse_name": "good"}
        resolver["bad"] = {"forward_ips": ["10.45.9.9"], "reverse_name": "bad"}  # the record points somewhere else
        view = _view(
            reservations=[
                {"ip": "10.45.0.10", "hostname": "good", "subnet_id": 1},
                {"ip": "10.45.1.10", "hostname": "bad", "subnet_id": 2},
            ]
        )
        results, error, note = _dns_tab(view)
        assert error == "" and note == ""
        assert {r["name"]: r["verdict"] for r in results} == {"good": "ok", "bad": "wrong-forward"}

    def test_a_v6_address_is_checked_as_an_aaaa_record(self, resolver):
        from jen.routes.client import _dns_tab

        resolver["dual"] = {"forward_ips": ["10.45.0.10", "2001:db8::99"], "reverse_name": "dual"}
        view = _view(
            reservations=[{"ip": "10.45.0.10", "hostname": "dual"}],
            reservations6=[{"hostname": "dual", "reservations": [{"address": "2001:db8::10", "type_name": "IA_NA"}]}],
        )
        results, _error, _note = _dns_tab(view)
        assert [(r["rtype"], r["verdict"]) for r in results] == [("A", "ok"), ("AAAA", "wrong-forward")]

    def test_more_records_than_a_page_checks_says_so(self, resolver):
        from jen.routes.client import _dns_tab

        view = _view(leases4=[{"ip": f"10.45.0.{i}", "hostname": f"h{i}"} for i in range(1, 26)])
        results, _error, note = _dns_tab(view)
        assert len(results) == cd.DEFAULT_LIMIT and note == "Checked the first 20 of 25 records."

    def test_no_named_record_is_no_work(self, resolver):
        from jen.routes.client import _dns_tab

        assert _dns_tab(_view()) == ([], "", "")


# ── Route tests (need the unit suite's database) ────────────────────────────────


@pytest.fixture
def two_reservations(db):
    def clean():
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (MAC_HEX,))
            cur.execute("DELETE FROM devices WHERE mac=%s", (MAC,))
        db.commit()

    clean()
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) VALUES "
            "(UNHEX(%s), 0, 1, INET_ATON('10.45.0.10'), 'first-good'), "
            "(UNHEX(%s), 0, 2, INET_ATON('10.45.1.10'), 'second-bad')",
            (MAC_HEX, MAC_HEX),
        )
        cur.execute("INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES (%s, '10.45.0.10', 1)", (MAC,))
    db.commit()
    yield
    clean()


class TestRouteTheDnsTab:
    def test_a_wrong_second_record_shows_on_the_tab(self, logged_in_client, two_reservations, resolver):
        resolver["first-good"] = {"forward_ips": ["10.45.0.10"], "reverse_name": "first-good"}
        resolver["second-bad"] = {"forward_ips": ["10.45.9.9"], "reverse_name": "second-bad"}
        body = logged_in_client.get(f"/client?q={MAC}&tab=dns").data.decode()
        assert "first-good" in body and "second-bad" in body
        assert "wrong-forward" in body, "the second record's mismatch must show; the tab used to check only the first"
