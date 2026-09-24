"""
tests/test_client_subject.py
──────────────────────────────
v5.63.0 (Q82) — jen.services.client_subject: identifier-kind detection and
`authorize()`'s three subnet policies are pure (no DB); `resolve()` and the
holder/previous-holder rules are DB-backed, against real lease4/hosts/
devices/events rows the same way tests/test_timeline.py already does.
"""

import pytest

from jen.services.client_subject import (
    ClientNotAuthorized,
    ClientSubject,
    authorize,
    detect_kind,
    hex_to_mac,
    mac_hex,
)


class TestDetectKind:
    """(kind, normalized) for a raw, user-typed identifier."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("aa:bb:cc:dd:ee:ff", ("mac", "aa:bb:cc:dd:ee:ff")),
            ("AA:BB:CC:DD:EE:FF", ("mac", "aa:bb:cc:dd:ee:ff")),
            ("aa-bb-cc-dd-ee-ff", ("mac", "aa:bb:cc:dd:ee:ff")),
            ("aabb.ccdd.eeff", ("mac", "aa:bb:cc:dd:ee:ff")),  # Cisco-style
            ("aabbccddeeff", ("mac", "aa:bb:cc:dd:ee:ff")),  # bare hex
            ("10.0.0.5", ("ipv4", "10.0.0.5")),
            ("255.255.255.255", ("ipv4", "255.255.255.255")),
            ("fe80::1", ("ipv6", "fe80::1")),
            ("2001:db8::aa:bb", ("ipv6", "2001:db8::aa:bb")),
            ("duid:0001000AAA112233445566", ("duid", "0001000aaa112233445566")),
            ("0001000aaa112233445566", ("duid", "0001000aaa112233445566")),  # bare, > 12 hex digits
            ("printer-1", ("hostname", "printer-1")),
            ("printer-1.lan.example.com", ("hostname", "printer-1.lan.example.com")),
            ("Printer-1", ("hostname", "printer-1")),  # lowercased
            ("", ("unknown", "")),
            ("   ", ("unknown", "")),
            ("!!!not-a-thing!!!", ("unknown", "!!!not-a-thing!!!")),
            ("duid:", ("unknown", "duid:")),  # empty duid body
        ],
    )
    def test_table(self, raw, expected):
        assert detect_kind(raw) == expected

    def test_a_hostname_with_hex_looking_characters_is_not_mistaken_for_a_mac(self):
        # "deadbeef" is 8 hex characters — not 12 (a MAC) or >12 (a DUID) —
        # so it must fall through to hostname detection, not be treated as
        # a malformed MAC/DUID.
        assert detect_kind("deadbeef") == ("hostname", "deadbeef")

    def test_mac_hex_and_hex_to_mac_round_trip(self):
        assert mac_hex("aa:bb:cc:dd:ee:ff") == "AABBCCDDEEFF"
        assert hex_to_mac("AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff"
        assert hex_to_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"

    def test_hex_to_mac_refuses_the_wrong_length(self):
        # A DUID is hex too, but is never exactly 12 digits' worth — this
        # must not silently produce a truncated/garbage MAC from it.
        assert hex_to_mac("0001000aaa112233445566") == ""
        assert hex_to_mac("") == ""


class TestAuthorize:
    """The three subnet policies docs/ARCHITECTURE.md §2 names."""

    def test_per_object_unrestricted_caller_passes_through_unchanged(self):
        subject = ClientSubject(kind="mac", leases4=[{"subnet_id": 1}], reservations=[{"subnet_id": 2}])
        assert authorize(subject, rule="per_object", accessible_ids=None) is subject

    def test_per_object_drops_inaccessible_leases_and_reservations(self):
        subject = ClientSubject(
            kind="mac",
            leases4=[{"subnet_id": 1}, {"subnet_id": 2}],
            reservations=[{"subnet_id": 2}],
        )
        out = authorize(subject, rule="per_object", accessible_ids={1})
        assert out.leases4 == [{"subnet_id": 1}]
        assert out.reservations == []

    def test_per_object_blanks_an_inaccessible_devices_placement_fields_only(self):
        device = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "first_seen": "2026-01-01",
            "last_seen": "2026-01-02",
            "last_ip": "10.0.0.5",
            "last_hostname": "host",
            "last_subnet_id": 2,
            "device_name": "secret",
            "owner": "someone",
            "notes": "private",
        }
        subject = ClientSubject(kind="mac", device=device)
        out = authorize(subject, rule="per_object", accessible_ids={1})
        assert out.device is not None
        assert out.device["mac"] == "aa:bb:cc:dd:ee:ff"  # bookends survive
        assert out.device["first_seen"] == "2026-01-01"
        assert out.device["last_ip"] is None
        assert out.device["last_subnet_id"] is None
        assert out.device["owner"] is None
        assert out.device["notes"] is None

    def test_per_object_keeps_an_accessible_device_untouched(self):
        device = {"last_subnet_id": 1, "owner": "someone"}
        subject = ClientSubject(kind="mac", device=device)
        out = authorize(subject, rule="per_object", accessible_ids={1})
        assert out.device == device

    def test_all_known_passes_an_unrestricted_caller(self):
        subject = ClientSubject(kind="mac", subnet_ids=frozenset({1, 2}))
        assert authorize(subject, rule="all_known", all_subnets=True) is subject

    def test_all_known_passes_when_every_subnet_is_accessible(self):
        subject = ClientSubject(kind="mac", subnet_ids=frozenset({1, 2}))
        out = authorize(subject, rule="all_known", accessible_ids={1, 2}, all_subnets=False)
        assert out is subject

    def test_all_known_refuses_when_one_subnet_is_missing(self):
        subject = ClientSubject(kind="mac", subnet_ids=frozenset({1, 2}))
        with pytest.raises(ClientNotAuthorized):
            authorize(subject, rule="all_known", accessible_ids={1}, all_subnets=False)

    def test_all_known_refuses_a_subject_with_no_known_subnet_for_a_restricted_caller(self):
        subject = ClientSubject(kind="mac", subnet_ids=frozenset())
        with pytest.raises(ClientNotAuthorized):
            authorize(subject, rule="all_known", accessible_ids={1}, all_subnets=False)

    def test_unrestricted_passes_an_all_subnets_caller(self):
        subject = ClientSubject(kind="mac")
        assert authorize(subject, rule="unrestricted", all_subnets=True) is subject

    def test_unrestricted_refuses_a_restricted_caller(self):
        subject = ClientSubject(kind="mac")
        with pytest.raises(ClientNotAuthorized):
            authorize(subject, rule="unrestricted", all_subnets=False)

    def test_unknown_rule_raises_valueerror(self):
        with pytest.raises(ValueError):
            authorize(ClientSubject(kind="mac"), rule="nonsense")


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM events")
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN ('AABBCCDDEF01', 'AABBCCDDEF02')")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier) IN ('AABBCCDDEF01', 'AABBCCDDEF02')")
        cur.execute("DELETE FROM devices WHERE mac IN ('aa:bb:cc:dd:ef:01', 'aa:bb:cc:dd:ef:02')")
    db.commit()


class TestResolve:
    """DB-backed — real lease4/hosts/devices/events rows, the same tables
    and shapes timeline.py/explain.py always used."""

    MAC = "aa:bb:cc:dd:ef:01"
    MAC_HEX = "AABBCCDDEF01"
    IP = "10.44.0.5"

    def test_mac_subject_finds_device_lease_and_reservation(self, db):
        from jen.services.client_subject import resolve

        _clean(db)
        with db.cursor() as cur:
            cur.execute("INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES (%s, %s, 1)", (self.MAC, self.IP))
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
                "(inet_aton(%s), UNHEX(%s), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)",
                (self.IP, self.MAC_HEX),
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address) VALUES "
                "(UNHEX(%s), 0, 1, inet_aton(%s))",
                (self.MAC_HEX, self.IP),
            )
        db.commit()
        try:
            subject = resolve(self.MAC)
            assert subject.kind == "mac"
            assert subject.mac == self.MAC
            assert subject.ip == self.IP
            assert subject.device["last_ip"] == self.IP
            assert subject.lease["ip"] == self.IP
            assert subject.reservation["ip"] == self.IP
            assert subject.subnet_ids == frozenset({1})
            assert subject.found is True
            assert set(subject.fetched_at) == {"device", "leases", "reservations"}
        finally:
            _clean(db)

    def test_a_mac_with_no_record_anywhere_is_not_found(self, db):
        from jen.services.client_subject import resolve

        _clean(db)
        subject = resolve("aa:bb:cc:dd:ef:99")
        assert subject.kind == "mac"
        assert subject.found is False
        assert subject.device is None
        assert subject.lease is None
        assert subject.reservation is None

    def test_ip_subject_resolves_the_current_holder(self, db):
        from jen.services.client_subject import resolve

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
                "(inet_aton(%s), UNHEX(%s), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)",
                (self.IP, self.MAC_HEX),
            )
        db.commit()
        try:
            subject = resolve(self.IP)
            assert subject.kind == "ipv4"
            assert subject.mac == self.MAC
            assert subject.holder_mac == self.MAC
            assert subject.lease["ip"] == self.IP
        finally:
            _clean(db)

    def test_ip_subject_lists_previous_holders_excluding_the_current_one(self, db):
        from jen.services.client_subject import resolve

        _clean(db)
        old_mac_hex = "AABBCCDDEF02"
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
                "(inet_aton(%s), UNHEX(%s), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)",
                (self.IP, self.MAC_HEX),
            )
            cur.execute(
                "INSERT INTO events (kind, mac, ip, subnet_id, detail) VALUES ('lease.new', %s, %s, 1, 'old-holder')",
                ("aa:bb:cc:dd:ef:02", self.IP),
            )
            cur.execute(
                "INSERT INTO events (kind, mac, ip, subnet_id, detail) VALUES ('lease.new', %s, %s, 1, 'new-holder')",
                (self.MAC, self.IP),
            )
        db.commit()
        try:
            subject = resolve(self.IP)
            assert subject.previous_holders == ["aa:bb:cc:dd:ef:02"]
        finally:
            _clean(db)
            with db.cursor() as cur:
                cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (old_mac_hex,))
            db.commit()

    def test_hostname_subject_with_one_match_resolves_as_that_mac(self, db):
        from jen.services.client_subject import resolve

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, last_hostname, last_subnet_id) VALUES (%s, 'lonely-host', 1)",
                (self.MAC,),
            )
        db.commit()
        try:
            subject = resolve("lonely-host")
            assert subject.kind == "mac"
            assert subject.mac == self.MAC
            assert subject.candidates == []
        finally:
            _clean(db)

    def test_hostname_subject_with_two_macs_is_ambiguous(self, db):
        from jen.services.client_subject import resolve

        _clean(db)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, last_hostname, last_subnet_id) VALUES (%s, 'shared-host', 1)",
                (self.MAC,),
            )
            cur.execute(
                "INSERT INTO devices (mac, last_hostname, last_subnet_id) VALUES (%s, 'shared-host', 1)",
                ("aa:bb:cc:dd:ef:02",),
            )
        db.commit()
        try:
            subject = resolve("shared-host")
            assert subject.kind == "hostname"
            assert subject.mac == ""
            assert {c["mac"] for c in subject.candidates} == {self.MAC, "aa:bb:cc:dd:ef:02"}
        finally:
            _clean(db)

    def test_hostname_subject_with_no_match_is_not_found(self, db):
        from jen.services.client_subject import resolve

        _clean(db)
        subject = resolve("nobody-has-this-hostname")
        assert subject.kind == "hostname"
        assert subject.found is False
        assert subject.candidates == []

    def test_ipv6_and_duid_subjects_are_honestly_empty(self):
        from jen.services.client_subject import resolve

        s6 = resolve("fe80::1")
        assert s6.kind == "ipv6" and s6.ip == "fe80::1" and s6.found is False

        sd = resolve("duid:0001000aaa112233445566")
        assert sd.kind == "duid" and sd.duid == "0001000aaa112233445566" and sd.found is False
