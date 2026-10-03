"""
tests/test_kea_identifier_corroboration.py
─────────────────────────────────────────
v5.67.0-beta.15 (Q129, items a and b) — the identifier repair can no longer rewrite a legitimate client-id, and
fixed-width option values stored as hex text are listed for review.

A client-id (option 61) is opaque: embedded clients that send their MAC as ASCII text exist, so a client-id row
that is made only of hex digits is "damaged" (offered, ticked) ONLY when a `lease4` row corroborates it, is
"ambiguous" (listed, unticked) with no evidence, and is never touched when a lease shows the client sends exactly
that text. DUIDs are also validated by their decoded type word. Against the real MariaDB.
"""

import re

import pytest

from jen.services import dbexport, kea_identifiers

DECODED = bytes.fromhex("01001122334455")  # a client-id: hardware type 1 + a MAC
TEXT = DECODED.hex().encode()  # the 14 ASCII characters "01001122334455"
MAC = bytes.fromhex("001122334455")


class TestPureRules:
    def test_a_duid_must_decode_to_a_type_word_of_one_to_four(self):
        f = kea_identifiers.looks_like_hex_of_itself
        for word in ("0001", "0002", "0003", "0004"):
            assert f((word + "00010203040506").encode(), 1), word
        for word in ("0000", "0005", "0009", "ffff", "8000"):
            assert not f((word + "00010203040506").encode(), 1), word

    def test_a_hw_address_and_client_id_rules_are_unchanged_as_candidates(self):
        f = kea_identifiers.looks_like_hex_of_itself
        assert f(b"001122334455", 0) and not f(b"00112233445566", 0)
        assert f(TEXT, 3) and not f(b"0011223", 3)

    @pytest.mark.parametrize(
        "matches,verdict",
        [
            ([], "ambiguous"),
            ([{"matches": set()}], "ambiguous"),
            ([{"matches": {"decoded"}}], "damaged"),
            ([{"matches": {"hwaddr"}}], "damaged"),
            ([{"matches": {"text"}}], "legitimate"),
            ([{"matches": {"decoded"}}, {"matches": {"text"}}], "ambiguous"),
            ([{"matches": {"text", "decoded"}}], "ambiguous"),
        ],
    )
    def test_classification_from_lease_evidence(self, matches, verdict):
        assert kea_identifiers.classify_client_id(TEXT, matches) == verdict

    def test_text_typed_option_codes_are_never_candidates(self):
        text_or_opaque = {12, 14, 15, 17, 18, 40, 47, 56, 60, 61, 66, 67, 77, 82, 119, 252}
        assert not text_or_opaque & set(kea_identifiers._FIXED_OPTIONS)

    @pytest.mark.parametrize(
        "kind,raw,shown",
        [
            ("ipv4", bytes([10, 0, 0, 1]), "10.0.0.1"),
            ("ipv4", bytes([10, 0, 0, 1, 10, 0, 0, 2]), "10.0.0.1, 10.0.0.2"),
            ("ipv4", bytes(4), None),
            ("ipv4", b"\xff\xff\xff\xff", None),
            ("mask", bytes([255, 255, 255, 0]), "255.255.255.0"),
            ("mask", bytes([255, 0, 255, 0]), None),
            ("mtu", (1500).to_bytes(2, "big"), "1500"),
            ("mtu", (10).to_bytes(2, "big"), None),
            ("lease", (3600).to_bytes(4, "big"), "3600 seconds"),
            ("lease", bytes(4), None),
            ("lease", b"\xff\xff\xff\xff", None),
            ("int32", (-18000 % (1 << 32)).to_bytes(4, "big"), "-18000 seconds"),
        ],
    )
    def test_plausibility_per_kind(self, kind, raw, shown):
        assert kea_identifiers._plausible_option(kind, raw) == shown


@pytest.fixture
def kea(db):
    tables = ["ipv6_reservations", "dhcp6_options", "dhcp4_options", "hosts", "lease4"]

    def wipe():
        db.commit()
        with db.cursor() as cur:
            for t in tables:
                cur.execute(f"DELETE FROM `{t}`")
        db.commit()

    wipe()
    yield db
    wipe()


def _host(db, host_id, ident, typ, name="h"):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO hosts (host_id, dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, "
            "hostname) VALUES (%s, %s, %s, 1, %s, %s)",
            (host_id, ident, typ, 167772160 + host_id, name),
        )
    db.commit()


def _lease(db, address, hwaddr=None, client_id=None):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, client_id, valid_lifetime, subnet_id, hostname) "
            "VALUES (%s, %s, %s, 3600, 1, 'x')",
            (address, hwaddr, client_id),
        )
    db.commit()


def _found(by_id=True):
    conn = dbexport._direct_kea_conn()
    try:
        found = kea_identifiers.find_damaged(conn)
    finally:
        conn.close()
    return {d["host_id"]: d for d in found} if by_id else found


def _ident(db, host_id):
    db.commit()
    with db.cursor() as cur:
        cur.execute("SELECT HEX(dhcp_identifier) AS h FROM hosts WHERE host_id = %s", (host_id,))
        return cur.fetchone()["h"]


def _checkbox(page, name, value):
    """The checkbox's whole tag, or None."""
    m = re.search(rf'<input type="checkbox" name="{name}" value="{value}"[^>]*>', page)
    return m.group(0) if m else None


class TestClientIdCorroboration:
    def test_a_legitimate_ascii_hex_client_id_with_no_lease_is_never_offered_ticked(self, db, kea, logged_in_client):
        _host(kea, 1, TEXT, 3, "embedded-client")
        d = _found()[1]
        assert d["confidence"] == "ambiguous" and d["evidence"] == []
        page = logged_in_client.get("/database/kea-identifiers").data.decode()
        box = _checkbox(page, "host_id", 1)
        assert box and " checked" not in box, "an ambiguous client-id must never be ticked by default"
        assert "ambiguous, review by hand" in page and "No lease matches either form" in page
        # the default repair (everything "damaged") leaves it alone
        conn = dbexport._direct_kea_conn()
        try:
            assert kea_identifiers.repair(conn) == []
        finally:
            conn.close()
        assert _ident(kea, 1) == TEXT.hex().upper()

    def test_the_operator_can_still_repair_an_ambiguous_one_by_naming_it(self, db, kea):
        _host(kea, 1, TEXT, 3)
        conn = dbexport._direct_kea_conn()
        try:
            results = kea_identifiers.repair(conn, host_ids=[1])
        finally:
            conn.close()
        assert results[0]["status"] == "repaired" and _ident(kea, 1) == DECODED.hex().upper()

    def test_a_lease_with_the_decoded_client_id_corroborates_the_damage(self, db, kea, logged_in_client):
        _host(kea, 1, TEXT, 3, "damaged-client")
        _lease(kea, 167772300, hwaddr=MAC, client_id=DECODED)
        d = _found()[1]
        assert d["confidence"] == "damaged" and d["evidence"][0]["matches"] == {"decoded"}
        page = logged_in_client.get("/database/kea-identifiers").data.decode()
        assert " checked" in _checkbox(page, "host_id", 1)
        assert "the client-id is the repaired bytes" in page
        conn = dbexport._direct_kea_conn()
        try:
            assert [r["status"] for r in kea_identifiers.repair(conn)] == ["repaired"]
        finally:
            conn.close()
        assert _ident(kea, 1) == DECODED.hex().upper()

    def test_a_twelve_character_text_is_corroborated_by_a_hardware_address(self, db, kea):
        _host(kea, 1, MAC.hex().encode(), 3)
        _lease(kea, 167772300, hwaddr=MAC, client_id=None)
        d = _found()[1]
        assert d["confidence"] == "damaged" and d["evidence"][0]["matches"] == {"hwaddr"}

    def test_a_longer_text_is_not_corroborated_by_a_hardware_address(self, db, kea):
        _host(kea, 1, TEXT, 3)  # 14 characters: seven bytes, which no hardware address is
        _lease(kea, 167772300, hwaddr=MAC, client_id=b"\x99")
        assert _found()[1]["confidence"] == "ambiguous"

    def test_a_lease_that_shows_the_text_makes_it_legitimate_and_it_is_never_repaired(self, db, kea, logged_in_client):
        _host(kea, 1, TEXT, 3, "ascii-client")
        _lease(kea, 167772300, hwaddr=MAC, client_id=TEXT)
        d = _found()[1]
        assert d["confidence"] == "legitimate" and d["evidence"][0]["matches"] == {"text"}
        page = logged_in_client.get("/database/kea-identifiers").data.decode()
        assert _checkbox(page, "host_id", 1) is None and "left alone" in page and TEXT.decode() in page
        conn = dbexport._direct_kea_conn()
        try:
            assert kea_identifiers.repair(conn) == []
            named = kea_identifiers.repair(conn, host_ids=[1])  # even when named
        finally:
            conn.close()
        assert named[0]["status"] == "skipped" and "sends exactly this text" in named[0]["detail"]
        assert _ident(kea, 1) == TEXT.hex().upper()

    def test_evidence_that_points_both_ways_is_ambiguous(self, db, kea, logged_in_client):
        _host(kea, 1, TEXT, 3)
        _lease(kea, 167772300, client_id=DECODED)
        _lease(kea, 167772301, client_id=TEXT)
        assert _found()[1]["confidence"] == "ambiguous"
        page = logged_in_client.get("/database/kea-identifiers").data.decode()
        assert "the client sends the bytes" in page and "the client sends the text" in page

    def test_hw_address_and_duid_need_no_lease(self, db, kea):
        _host(kea, 1, b"001122334455", 0)
        _host(kea, 2, b"0003000100112233445566", 1)
        found = _found()
        assert found[1]["confidence"] == "damaged" and found[2]["confidence"] == "damaged"

    def test_text_that_decodes_to_no_duid_type_is_not_flagged(self, db, kea):
        _host(kea, 1, b"ffff00010203040506", 1)
        _host(kea, 2, b"000900010203040506", 1)
        assert _found() == {}

    def test_circuit_id_and_flex_id_are_never_flagged(self, db, kea):
        _host(kea, 1, TEXT, 2)
        _host(kea, 2, TEXT, 4)
        assert _found() == {}

    def test_the_health_check_fails_only_on_a_row_certain_enough_to_tick(self, db, kea):
        from jen.services import health

        _host(kea, 1, TEXT, 3)
        c = health._kea_identifiers({"unrestricted": True})
        assert c.status == "ok" and "1 client-id(s) are hex text with no lease" in c.detail
        _lease(kea, 167772300, client_id=DECODED)
        assert health._kea_identifiers({"unrestricted": True}).status == "fail"


class TestOptionValueCandidates:
    def _option(self, db, option_id, host_id, code, value, scope=3):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO dhcp4_options (option_id, code, value, formatted_value, space, host_id, scope_id, "
                "client_classes) VALUES (%s, %s, %s, NULL, 'dhcp4', %s, %s, '')",
                (option_id, code, value, host_id, scope),
            )
        db.commit()

    def _seed(self, db):
        _host(db, 1, bytes.fromhex("001122334455"), 0, "printer")
        for oid, code, value in [
            (1, 3, b"0a000001"),  # routers as text: 10.0.0.1
            (2, 51, b"00000e10"),  # lease time as text: 3600 s
            (3, 6, b"0a0000010a000002"),  # two DNS servers
            (4, 1, b"ffffff00"),  # a mask
            (5, 15, b"deadbeef"),  # domain-name: TEXT, never listed
            (6, 3, bytes.fromhex("0a000001")),  # the real thing: four binary bytes
            (7, 3, b"00000000"),  # decodes to 0.0.0.0: implausible
            (8, 51, b"00000e1"),  # odd length
            (9, 3, b"0a00000g"),  # not hex
            (10, 26, b"0010"),  # mtu of 16: implausible
        ]:
            self._option(db, oid, 1, code, value)
        # a global option (no host, scope 0) that happens to look the same is not a reservation's
        self._option(db, 11, None, 3, b"0a000001", scope=0)

    def test_only_fixed_width_host_scoped_hex_text_with_a_plausible_value_is_listed(self, db, kea):
        self._seed(kea)
        conn = dbexport._direct_kea_conn()
        try:
            found = kea_identifiers.find_option_candidates(conn)
        finally:
            conn.close()
        assert [(c["option_id"], c["code"], c["repaired"]) for c in found] == [
            (1, 3, "10.0.0.1"),
            (2, 51, "3600 seconds"),
            (3, 6, "10.0.0.1, 10.0.0.2"),
            (4, 1, "255.255.255.0"),
        ]
        assert found[0]["hostname"] == "printer" and found[0]["name"] == "routers"

    def test_the_page_lists_them_unticked_and_says_why_text_options_are_absent(self, db, kea, logged_in_client):
        self._seed(kea)
        page = logged_in_client.get("/database/kea-identifiers").data.decode()
        assert "4 option value(s) to review" in page
        for oid in (1, 2, 3, 4):
            box = _checkbox(page, "option_id", oid)
            assert box and " checked" not in box
        assert _checkbox(page, "option_id", 5) is None
        assert "text options are never listed" in page

    def test_nothing_changes_until_a_row_is_ticked_and_only_that_row_changes(self, db, kea, logged_in_client):
        self._seed(kea)
        before = _all_option_values(kea)
        assert logged_in_client.get("/database/kea-identifiers").status_code == 200
        assert _all_option_values(kea) == before, "viewing the page must change nothing"
        r = logged_in_client.post("/database/kea-identifiers/repair", data={"option_id": ["2"]})
        assert r.status_code == 200 and b"option 2" in r.data
        after = _all_option_values(kea)
        assert after[2] == bytes.fromhex("00000e10")
        assert {k: v for k, v in after.items() if k != 2} == {k: v for k, v in before.items() if k != 2}

    def test_an_option_edited_after_the_review_is_left_alone(self, db, kea, monkeypatch):
        self._seed(kea)
        conn = dbexport._direct_kea_conn()
        try:
            real = kea_identifiers.find_option_candidates

            def stale(c):
                found = real(c)
                with c.cursor() as cur:
                    cur.execute("UPDATE dhcp4_options SET value = %s WHERE option_id = 1", (bytes.fromhex("0a000009"),))
                return found

            monkeypatch.setattr(kea_identifiers, "find_option_candidates", stale)
            results = kea_identifiers.repair_options(conn, [1])
        finally:
            conn.close()
        assert results[0]["status"] == "skipped" and "changed since" in results[0]["detail"]

    def test_an_id_that_is_not_a_candidate_cannot_be_repaired(self, db, kea):
        self._seed(kea)
        conn = dbexport._direct_kea_conn()
        try:
            assert kea_identifiers.repair_options(conn, [5, 6, 11, 99]) == []
        finally:
            conn.close()
        assert _all_option_values(kea)[5] == b"deadbeef"

    def test_a_clean_database_has_no_candidates(self, db, kea, logged_in_client):
        _host(kea, 1, bytes.fromhex("001122334455"), 0)
        self._option(kea, 1, 1, 3, bytes.fromhex("0a000001"))
        assert b"Nothing to repair" in logged_in_client.get("/database/kea-identifiers").data


def _all_option_values(db):
    db.commit()
    with db.cursor() as cur:
        cur.execute("SELECT option_id, value FROM dhcp4_options ORDER BY option_id")
        return {r["option_id"]: bytes(r["value"]) for r in cur.fetchall()}
