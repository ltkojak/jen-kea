"""
tests/test_option_bytes.py
───────────────────────────
v5.68.0-beta.10 (Q145) — option 77 and the relay circuit id are compared by Kea as BYTES, and Explain used to compare something else.

* The rule builder wrote `option[77].hex == '<text>'` (the string's bytes), Explain evaluated `option[77].hex` against the typed TEXT, and
  the kea-compat config that real Kea matched uses the RFC 3004 wire form with the length byte (`0x08…`) - three meanings for one
  accessor. A client sends its user class either as the bare string (dhclient's `send user-class`) or length-prefixed (Windows); there
  is no one right literal, only the bytes Kea received.
* A binary circuit id (`DE AD BE EF`) was compared as the ASCII of its hex.

So: Kea's packet dump supplies the BYTES (`user_class_bytes`, `circuit_id_hex`) beside the display text; the engine compares bytes; with
only the text known it judges a test under both client forms and calls it decided only when they agree; and the builder offers both forms.
Pure (`pytest --noconftest tests/test_option_bytes.py`).
"""

import pathlib

import pytest

from jen.services import dhcp_explain as de
from jen.services import explain_inputs as ei
from jen.services import kea_classes as kc
from jen.services import kea_log_inputs as li

FIX = pathlib.Path(__file__).resolve().parent / "fixtures"
REAL_MAC = "02:50:00:00:01:06"
LP = "086a656e2d75736572"  # 08 'jen-user'
RAW = "6a656e2d75736572"  # 'jen-user'


def _judge(expression, client):
    """(verdict, missing) of one class test for a client."""
    missing: set = set()
    return de.evaluate(de.parse_expression(expression), client, {}, missing), missing


class TestWhatTheDumpGives:
    @pytest.mark.parametrize("version", ["3.0.3", "3.2.0", "3.3.1"])
    def test_real_kea_dumps_give_the_bytes_and_the_display_text(self, version):
        lines = (FIX / f"kea-{version}-debug55.log").read_text(encoding="utf-8").split("\n")
        query = li.latest_query_data(lines, REAL_MAC)
        assert query["user_class"] == "jen-user" and query["user_class_bytes"] == LP
        assert query["circuit_id"] == "eth0/1/7" and query["circuit_id_hex"] == "657468302f312f37"

    def _dump(self, rows):
        head = "2026-10-05 10:00:00.100 DEBUG [kea-dhcp4.packets/1.1] DHCP4_QUERY_DATA [hwtype=1 02:50:00:00:01:06], cid=[], tid=0x1, packet details:"
        return [head, "options:", *rows]

    def test_a_raw_client_is_the_bare_string_exactly_as_real_kea_prints_it(self):
        # kea-dhcp4 3.0.3, 3.2.0 and 3.3.1 (kea-compat, Q145): a raw client's row has the printable text after the hex, a length-prefixed
        # client's (above) does not
        row = "  type=077, len=008: 6a:65:6e:2d:75:73:65:72 'jen-user'"
        query = li.latest_query_data(self._dump([row]), REAL_MAC)
        assert query["user_class_bytes"] == RAW and query["user_class"] == "jen-user"

    def test_the_same_row_without_the_trailing_text_is_the_same_bytes(self):
        query = li.latest_query_data(self._dump(["  type=077, len=008: 6a:65:6e:2d:75:73:65:72"]), REAL_MAC)
        assert query["user_class_bytes"] == RAW and query["user_class"] == "jen-user"

    def test_a_binary_circuit_id_keeps_its_bytes_and_shows_as_hex(self):
        rows = ["  type=082, len=006:,", "options:", "    type=001, len=004: de:ad:be:ef"]
        query = li.latest_query_data(self._dump(rows), REAL_MAC)
        assert query["circuit_id"] == "deadbeef" and query["circuit_id_hex"] == "deadbeef"

    def test_the_leases_extended_info_gives_the_circuit_bytes_too(self):
        info = {"ISC": {"relay-agent-info": {"sub-options": "0x0104deadbeef"}}}
        got = li.relay_info_from_user_context(info)
        assert got["circuit_id_hex"] == "deadbeef" and got["circuit_id"] == "deadbeef"


class TestTheEngineComparesBytes:
    def test_a_length_prefixed_client_matches_the_length_prefixed_literal_only(self):
        client = {"mac": "aa:bb:cc:dd:ee:01", "user_class": "jen-user", "user_class_bytes": LP}
        assert _judge(f"option[77].hex == 0x{LP}", client)[0] is True
        assert _judge("option[77].hex == 'jen-user'", client)[0] is False, "Kea compares the 9 bytes, not the text"
        assert _judge("substring(option[77].hex,1,8) == 'jen-user'", client)[0] is True
        assert _judge("substring(option[77].hex,0,8) == 'jen-user'", client)[0] is False

    def test_a_raw_client_matches_the_plain_literal_only(self):
        client = {"mac": "aa:bb:cc:dd:ee:01", "user_class": "jen-user", "user_class_bytes": RAW}
        assert _judge("option[77].hex == 'jen-user'", client)[0] is True
        assert _judge(f"option[77].hex == 0x{LP}", client)[0] is False
        assert _judge("substring(option[77].hex,0,8) == 'jen-user'", client)[0] is True
        assert _judge("substring(option[77].hex,1,8) == 'jen-user'", client)[0] is False

    def test_with_only_the_text_a_test_that_depends_on_the_form_is_undecided_and_says_what_would_settle_it(self):
        client = {"mac": "aa:bb:cc:dd:ee:01", "user_class": "jen-user"}
        verdict, missing = _judge("option[77].hex == 'jen-user'", client)
        assert verdict is None and missing == {"user_class_bytes"}
        assert _judge(f"option[77].hex == 0x{LP}", client)[0] is None

    def test_with_only_the_text_a_test_both_forms_agree_on_is_decided(self):
        client = {"mac": "aa:bb:cc:dd:ee:01", "user_class": "jen-user"}
        assert _judge("option[77].hex == 'someone-else'", client) == (False, set())
        assert _judge("not (option[77].hex == 'someone-else')", client) == (True, set())

    def test_no_user_class_at_all_is_still_missing_user_class(self):
        verdict, missing = _judge("option[77].hex == 'x'", {"mac": "aa:bb:cc:dd:ee:01"})
        assert verdict is None and missing == {"user_class"}

    def test_bytes_that_are_not_hex_are_unknown_not_a_crash(self):
        verdict, missing = _judge("option[77].hex == 'x'", {"mac": "aa", "user_class_bytes": "zz"})
        assert verdict is None and missing == {"user_class_bytes"}

    def test_a_binary_circuit_id_is_compared_as_bytes(self):
        client = {"mac": "aa:bb:cc:dd:ee:01", "circuit_id": "deadbeef", "circuit_id_hex": "deadbeef"}
        assert _judge("relay4[1].hex == 0xdeadbeef", client)[0] is True, (
            "DE AD BE EF satisfies relay4[1].hex == 0xdeadbeef"
        )
        assert _judge("relay4[1].hex == 'deadbeef'", client)[0] is False, "and is NOT the ASCII of its hex"

    def test_a_text_circuit_id_matches_both_spellings(self):
        client = {"mac": "aa:bb:cc:dd:ee:01", "circuit_id": "eth0/1/7", "circuit_id_hex": "657468302f312f37"}
        assert _judge("relay4[1].hex == 'eth0/1/7'", client)[0] is True
        assert _judge("relay4[1].hex == 0x657468302f312f37", client)[0] is True

    def test_a_typed_text_circuit_id_with_no_bytes_is_its_ascii(self):
        client = {"mac": "aa:bb:cc:dd:ee:01", "circuit_id": "eth0/1/7"}
        assert _judge("relay4[1].hex == 'eth0/1/7'", client)[0] is True
        assert _judge("relay4[1].hex == 0x657468302f312f37", client)[0] is True

    def test_the_old_vocabulary_is_unchanged(self):
        client = {"mac": "aa:bb:cc:dd:ee:01", "vendor_class": "MSFT 5.0", "hostname": "pc1"}
        assert _judge("substring(option[60].hex,0,4) == 'MSFT'", client)[0] is True
        assert _judge("option[12].text == 'pc1'", client)[0] is True

    def test_a_non_zero_start_is_now_in_the_grammar_a_negative_one_is_not(self):
        assert de.parse_expression("substring(option[77].hex,1,8) == 'jen-user'")
        with pytest.raises(de.ExprError):
            de.parse_expression("substring(option[77].hex,-1,8) == 'jen-user'")


class TestTheInputsCarryBoth:
    QUERY = {
        "at": "2026-10-05 10:00:00.100",
        "hostname": "",
        "vendor_class": "",
        "client_id": "",
        "user_class": "jen-user",
        "user_class_bytes": LP,
        "circuit_id": "eth0/1/7",
        "circuit_id_hex": "657468302f312f37",
        "remote_id": "",
    }

    def test_the_dump_supplies_the_text_and_the_bytes(self):
        built = ei.build("aa:bb:cc:dd:ee:01", log={"query": self.QUERY})
        assert built["client"]["user_class"] == "jen-user" and built["client"]["user_class_bytes"] == LP
        assert (
            built["sources"]["user_class_bytes"] == "log-packet"
            and built["client"]["circuit_id_hex"] == "657468302f312f37"
        )
        fields = [p["field"] for p in ei.provenance(built)]
        assert fields.index("user_class") < fields.index("user_class_bytes") < fields.index("circuit_id_hex")

    def test_typed_bytes_are_normalised_and_win(self):
        built = ei.build(
            "aa:bb:cc:dd:ee:01",
            log={"query": self.QUERY},
            typed={"user_class_bytes": "6A 65 6E", "circuit_id_hex": "DE:AD"},
        )
        assert built["client"]["user_class_bytes"] == "6a:65:6e" and built["sources"]["user_class_bytes"] == "typed"
        assert built["client"]["circuit_id_hex"] == "de:ad"

    def test_the_labels_are_there_for_the_form(self):
        assert "user_class_bytes" in de.INPUT_LABELS and "circuit_id_hex" in de.INPUT_LABELS


class TestTheRuleBuilderOffersBothForms:
    def _expr(self, field, op, value):
        return kc.build_expression([{"field": field, "op": op, "value": value}])

    def test_plain_text_is_what_it_always_wrote(self):
        assert self._expr("user_class", "equals", "jen-user") == "option[77].hex == 'jen-user'"
        assert self._expr("user_class", "starts_with", "jen") == "substring(option[77].hex,0,3) == 'jen'"

    def test_length_prefixed_writes_the_bytes_with_the_length_byte(self):
        assert self._expr("user_class_lp", "equals", "jen-user") == f"option[77].hex == 0x{LP}"

    def test_length_prefixed_starts_with_skips_the_length_byte(self):
        assert self._expr("user_class_lp", "starts_with", "jen") == "substring(option[77].hex,1,3) == 'jen'"

    def test_a_length_prefixed_value_is_still_validated(self):
        with pytest.raises(ValueError):
            self._expr("user_class_lp", "equals", "it's")
        with pytest.raises(ValueError):
            self._expr("user_class_lp", "equals", "")
        with pytest.raises(ValueError):
            self._expr("user_class_lp", "equals", "x" * 256)

    def test_the_two_forms_are_two_labelled_fields(self):
        assert (
            "plain text" in kc.FIELDS["user_class"]["ui_label"]
            and "length-prefixed" in kc.FIELDS["user_class_lp"]["ui_label"]
        )
        assert kc.FIELDS["user_class_lp"]["kea"] == "option[77].hex"

    @pytest.mark.parametrize(
        "field,op",
        [
            ("user_class", "equals"),
            ("user_class", "starts_with"),
            ("user_class_lp", "equals"),
            ("user_class_lp", "starts_with"),
        ],
    )
    def test_everything_the_builder_writes_for_option_77_is_something_explain_can_evaluate(self, field, op):
        expr = self._expr(field, op, "jen-user")
        de.parse_expression(expr)  # no ExprError: Explain never says "not evaluable" about the builder's own output

    def test_builder_and_explain_agree_for_each_client_form(self):
        """The same expression the builder writes, judged for a client that sent each form: a length-prefixed client matches the
        length-prefixed rules and not the plain ones, a raw client the reverse (what real Kea does is pinned in kea-compat)."""
        lp_client = {"mac": "aa", "user_class_bytes": LP}
        raw_client = {"mac": "aa", "user_class_bytes": RAW}
        for field, op, value, expects_lp, expects_raw in (
            ("user_class", "equals", "jen-user", False, True),
            ("user_class", "starts_with", "jen", False, True),
            ("user_class_lp", "equals", "jen-user", True, False),
            ("user_class_lp", "starts_with", "jen", True, False),
        ):
            expr = self._expr(field, op, value)
            assert _judge(expr, lp_client)[0] is expects_lp, (expr, "length-prefixed client")
            assert _judge(expr, raw_client)[0] is expects_raw, (expr, "raw client")
