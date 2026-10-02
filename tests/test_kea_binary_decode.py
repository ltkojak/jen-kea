"""
tests/test_kea_binary_decode.py
────────────────────────────────
v5.67.0-beta.11 (Q123) — the pure rules behind the binary-column fix, with no database: how a value is
written (`_clean_row`) and how it is decoded on the way back in (`_decode_import_rows`). The DB-backed
round trip that proves the STORED bytes match is tests/test_kea_binary_roundtrip.py; this file is what
runs under `py -m pytest --noconftest` on a machine with no MariaDB, and it pins the one decision the
whole fix rests on — a typed tag, never a guess.
"""

import datetime

import pytest

from jen.services import dbexport, kea_identifiers

MAC = bytes.fromhex("341343e60e2a")
NOT_UTF8 = b"\xff\xfe\x00\x80\xc3\x28"
CLIENT_ID = b"" + MAC
TEXTISH_HEX = b"abcdef123456"  # a circuit-id typed as hex text - not damage


class TestCleanRow:
    def test_bytes_become_a_tagged_object_not_a_bare_hex_string(self):
        out = dbexport._clean_row({"id": 1, "mac": MAC, "blob": NOT_UTF8, "name": "deadbeef"})
        assert out["mac"] == {"$bin": "341343e60e2a"}
        assert out["blob"] == {"$bin": NOT_UTF8.hex()}
        assert out["name"] == "deadbeef", "a plain string that looks like hex is never converted"
        assert out["id"] == 1

    def test_bytearray_and_datetime(self):
        out = dbexport._clean_row({"b": bytearray(MAC), "d": datetime.datetime(2026, 10, 2, 12, 0, 0)})
        assert out["b"] == {"$bin": MAC.hex()}
        assert out["d"] == "2026-10-02T12:00:00"

    def test_none_stays_none(self):
        assert dbexport._clean_row({"b": None}) == {"b": None}


class TestDecode:
    def rows(self, **kw):
        return [{"id": 1, **kw}]

    def test_a_tag_is_decoded_in_any_column(self):
        out = dbexport._decode_import_rows("t", self.rows(c={"$bin": MAC.hex()}), ["id", "c"], set(), 3)
        assert out == [[1, MAC]]

    def test_an_older_files_bare_hex_in_a_binary_column_is_decoded(self):
        for fmt in (1, 2):
            out = dbexport._decode_import_rows("t", self.rows(c=MAC.hex()), ["c"], {"c"}, fmt)
            assert out == [[MAC]]

    def test_upper_case_hex_is_decoded(self):
        assert dbexport._decode_import_rows("t", self.rows(c=MAC.hex().upper()), ["c"], {"c"}, 2) == [[MAC]]

    def test_a_bare_string_for_a_text_column_is_never_touched(self):
        out = dbexport._decode_import_rows("t", self.rows(name="deadbeef"), ["name"], {"c"}, 2)
        assert out == [["deadbeef"]]

    @pytest.mark.parametrize("bad", ["zz11", "abc", "34 13", "0x3413", "341343e60e2g"])
    def test_text_that_is_not_hex_is_refused_by_column_and_row(self, bad):
        with pytest.raises(dbexport.BinaryValueError) as e:
            dbexport._decode_import_rows(
                "hosts", self.rows(dhcp_identifier=bad), ["dhcp_identifier"], {"dhcp_identifier"}, 2
            )
        assert "hosts.dhcp_identifier" in str(e.value) and "row 1" in str(e.value)

    def test_the_second_rows_bad_value_is_named_as_row_2(self):
        rows = [{"c": MAC.hex()}, {"c": "nope"}]
        with pytest.raises(dbexport.BinaryValueError, match="row 2"):
            dbexport._decode_import_rows("t", rows, ["c"], {"c"}, 2)

    def test_a_format3_file_never_has_a_bare_string_in_a_binary_column(self):
        with pytest.raises(dbexport.BinaryValueError, match="tags every binary value"):
            dbexport._decode_import_rows("t", self.rows(c=MAC.hex()), ["c"], {"c"}, 3)

    @pytest.mark.parametrize("bad", ["xyz", 5, None, "abc"])
    def test_a_malformed_tag_is_refused(self, bad):
        with pytest.raises(dbexport.BinaryValueError):
            dbexport._decode_import_rows("t", self.rows(c={"$bin": bad}), ["c"], {"c"}, 3)

    def test_null_in_a_binary_column_stays_null(self):
        assert dbexport._decode_import_rows("t", self.rows(c=None), ["c"], {"c"}, 2) == [[None]]

    def test_an_object_that_merely_has_a_bin_key_among_others_is_not_a_tag(self):
        v = {"$bin": "00", "extra": 1}
        assert dbexport._decode_import_rows("t", self.rows(c=v), ["c"], set(), 3) == [[v]]

    def test_only_the_requested_columns_are_returned_in_order(self):
        rows = [{"a": 1, "b": {"$bin": "ff"}, "z": "skip me"}]
        assert dbexport._decode_import_rows("t", rows, ["b", "a"], set(), 3) == [[b"\xff", 1]]


class TestRecognisingDamage:
    def test_pure_rules(self):
        f = kea_identifiers.looks_like_hex_of_itself
        assert f(b"341343e60e2a", 0)  # 6-byte MAC written as text
        assert f(b"34134300e60e2a1b", 0)  # 8 bytes
        assert f((b"ab" * 20), 0)  # 20-byte InfiniBand
        assert not f(b"341343e60e2", 0)  # odd
        assert not f(b"341343e60e2ag1", 0)  # not hex
        assert not f(b"3413434", 0)
        assert not f(b"abcdef12345678", 0)  # 14 characters: not a plausible hardware-address length
        assert f(b"0003000134134300e60e2a", 1)  # a duid of any plausible length
        assert f(b"01341343e60e2a", 3)  # a client-id
        assert not f(MAC, 0)  # a genuine six-byte MAC is binary, never ASCII hex
        assert not f(CLIENT_ID, 3)
        assert not f(TEXTISH_HEX, 2)  # circuit-id: never flagged — ASCII hex is legitimate text there
        assert not f(TEXTISH_HEX, 4)  # flex-id: same
        assert not f(None, 0)
