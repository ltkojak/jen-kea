"""
tests/test_plugin_helpers.py
──────────────────────────────
v5.65.10 (Q99 d, l) — the helpers the seven bundled plugins each copied by hand, once, behind
`jen.plugin_api` (jen/services/plugin_helpers.py), and the JSON-body helpers in api_auth.
The pure ones run without a database; the request-context ones use the `app` fixture.
"""

import json
import re
from pathlib import Path

import pytest

from jen import plugin_api
from jen.services import api_auth, plugin_helpers


class TestNormalizeMac:
    @pytest.mark.parametrize(
        "raw",
        [
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "aabb.ccdd.eeff",
            "AABBCCDDEEFF",
            " aabbccddeeff ",
        ],
    )
    def test_every_usual_spelling_becomes_lowercase_colons(self, raw):
        assert plugin_helpers.normalize_mac(raw) == "aa:bb:cc:dd:ee:ff"

    @pytest.mark.parametrize(
        "raw", ["", "  ", None, 5, ["aa"], {"mac": 1}, "aa:bb", "zz:zz:zz:zz:zz:zz", "aa:bb:cc:dd:ee:ff:00"]
    )
    def test_anything_else_is_none_never_an_exception(self, raw):
        assert plugin_helpers.normalize_mac(raw) is None

    def test_it_is_the_one_object_a_plugin_sees(self):
        assert plugin_api.normalize_mac is plugin_helpers.normalize_mac


class TestLikePattern:
    def test_percent_underscore_and_backslash_are_literal(self):
        assert plugin_helpers.like_pattern("10.0_1") == "%10.0\\_1%"
        assert plugin_helpers.like_pattern("50%") == "%50\\%%"
        assert plugin_helpers.like_pattern("a\\b") == "%a\\\\b%"

    def test_plain_text_is_just_wrapped(self):
        assert plugin_helpers.like_pattern("printer") == "%printer%"

    def test_a_lone_percent_no_longer_matches_everything(self):
        assert plugin_helpers.like_pattern("%") == "%\\%%"


class TestInPlaceholders:
    def test_one_per_value(self):
        assert plugin_helpers.in_placeholders([1, 2, 3]) == "%s,%s,%s"
        assert plugin_helpers.in_placeholders({7}) == "%s"

    def test_an_empty_list_is_valid_sql_that_matches_nothing(self):
        assert plugin_helpers.in_placeholders([]) == "NULL"

    def test_a_generator_is_counted_once(self):
        assert plugin_helpers.in_placeholders(x for x in (1, 2)) == "%s,%s"


class TestSearchScope:
    def test_an_unrestricted_caller_gets_everything(self):
        assert plugin_helpers.search_scope(set(), True, "r.subnet_id") == ("1=1", [])

    def test_a_restricted_caller_gets_an_in_clause_over_their_ids(self):
        clause, params = plugin_helpers.search_scope({3, 1}, False, "r.subnet_id")
        assert clause == "r.subnet_id IN (%s,%s)" and params == [1, 3]

    def test_a_caller_who_may_see_nothing_gets_none(self):
        assert plugin_helpers.search_scope(set(), False, "subnet_id") is None
        assert plugin_helpers.search_scope(None, False, "subnet_id") is None

    @pytest.mark.parametrize("bad", ["", "a b", "x; DROP TABLE t", "a.b.c", "1col", "col)--", None])
    def test_a_column_that_is_not_a_column_name_is_refused(self, bad):
        with pytest.raises(ValueError):
            plugin_helpers.search_scope({1}, False, bad)

    def test_the_limit_then_filter_bug_it_exists_to_prevent(self):
        """A provider that LIMITs before it filters can spend its 20 rows on other subnets' rows and give a
        restricted caller nothing; with the clause in the query the limit applies to what they may see."""
        rows = [{"id": i, "subnet_id": 2} for i in range(25)] + [{"id": 100 + i, "subnet_id": 1} for i in range(5)]
        clause, params = plugin_helpers.search_scope({1}, False, "subnet_id")
        assert clause == "subnet_id IN (%s)"
        visible = [r for r in rows if r["subnet_id"] in params][:20]  # what the SQL does: filter, then LIMIT
        assert len(visible) == 5
        assert len([r for r in rows[:20] if r["subnet_id"] in params]) == 0  # what limit-then-filter returned


class TestSubnetForIp:
    @pytest.fixture(autouse=True)
    def _map(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(
            extensions,
            "SUBNET_MAP",
            {
                1: {"name": "a", "cidr": "10.98.1.0/24"},
                2: {"name": "b", "cidr": "10.77.0.0/24"},
                3: {"name": "bad", "cidr": "nope"},
            },
        )

    def test_the_subnet_that_holds_the_address(self):
        assert plugin_helpers.subnet_for_ip("10.98.1.5") == 1
        assert plugin_helpers.subnet_for_ip(" 10.77.0.200 ") == 2

    @pytest.mark.parametrize("ip", ["192.0.2.1", "not an ip", "", None, "10.98.1.999"])
    def test_an_address_in_no_subnet_or_not_an_address_is_none(self, ip):
        assert plugin_helpers.subnet_for_ip(ip) is None


class TestStrField:
    def test_a_string_is_stripped_and_cut(self):
        assert api_auth.str_field({"a": "  hello  "}, "a") == "hello"
        assert api_auth.str_field({"a": "abcdef"}, "a", 3) == "abc"

    @pytest.mark.parametrize("value", [None, 5, 1.5, True, ["x"], {"x": 1}])
    def test_a_non_string_is_absent_not_an_exception(self, value):
        assert api_auth.str_field({"a": value}, "a") == ""

    def test_a_missing_key_or_a_non_dict_body_is_empty(self):
        assert (
            api_auth.str_field({}, "a") == ""
            and api_auth.str_field([1], "a") == ""
            and api_auth.str_field(None, "a") == ""
        )

    def test_it_is_the_one_object_a_plugin_sees(self):
        assert plugin_api.str_field is api_auth.str_field and plugin_api.json_object_body is api_auth.json_object_body


class TestJsonObjectBody:
    def test_an_object_passes(self, app):
        with app.test_request_context("/x", method="POST", json={"a": 1}):
            body, err = api_auth.json_object_body()
        assert body == {"a": 1} and err is None

    @pytest.mark.parametrize("payload", [[1, 2], "text", 5, [{"a": 1}], True])
    def test_anything_but_an_object_is_a_400(self, app, payload):
        with app.test_request_context("/x", method="POST", json=payload):
            body, err = api_auth.json_object_body()
            assert body is None and err[1] == 400
            assert err[0].get_json() == {"error": "expected a JSON object"}

    def test_bytes_that_are_not_json_are_a_400(self, app):
        with app.test_request_context("/x", method="POST", data="{not json", content_type="application/json"):
            body, err = api_auth.json_object_body()
        assert body is None and err[1] == 400

    def test_no_body_at_all_is_an_empty_object(self, app):
        with app.test_request_context("/x", method="POST"):
            body, err = api_auth.json_object_body()
        assert body == {} and err is None


class TestCoreAndMfaRoutesRefuseANonObjectBody:
    def test_a_core_write_answers_400_not_a_misleading_field_error(self, client, db, mock_kea):
        from tests.test_api_writes import RAW_RW, _h, _key_row

        _key_row(db, "q99-body", RAW_RW, 1)
        r = client.post("/api/v1/reservations", data=json.dumps([1, 2]), headers=_h(RAW_RW))
        assert r.status_code == 400 and r.get_json()["error"] == "expected a JSON object"

    def test_the_passkey_reauth_finish_route_is_a_400_not_a_500(self, logged_in_client):
        r = logged_in_client.post("/mfa/passkey/reauth/finish", json=[1, 2])
        assert r.status_code == 400 and r.get_json()["error"] == "expected a JSON object"

    def test_no_mfa_route_reads_a_body_with_or_empty_dict_any_more(self):
        src = Path("jen/routes/mfa_routes.py").read_text(encoding="utf-8")
        assert not re.search(r"get_json\(silent=True\)\s*or\s*\{\}", src)


class TestAssertSubnetAccessCanBeQuiet:
    def test_notify_false_queues_no_flash(self, app):
        from flask import session

        from jen.services import access

        class _Nope:
            is_authenticated = True

            def can_access_subnet(self, sid):
                return False

        with app.test_request_context("/x"):
            session.clear()
            orig = access.current_user
            access.current_user = _Nope()
            try:
                assert access.assert_subnet_access(1, notify=False) is False
                assert not session.get("_flashes"), "notify=False must queue no flash"
                assert access.assert_subnet_access(1) is False
                assert [m for _c, m in session["_flashes"]] == ["You do not have access to that subnet."]
            finally:
                access.current_user = orig


class _FakeUser:
    is_authenticated = True

    def __init__(self, role, subnets):
        self.role, self._subnets = role, set(subnets)

    def can_access_subnet(self, sid):
        return sid in self._subnets


@pytest.fixture
def as_user(monkeypatch):
    """Act as a given fake session user inside `jen.services.access` (what both helpers consult)."""
    from jen.services import access

    def _set(role, subnets=()):
        monkeypatch.setattr(access, "current_user", _FakeUser(role, subnets))

    return _set


class TestSubnetOr404AndRequireWrite:
    def test_subnet_or_404_gives_one_answer_for_unknown_and_not_yours(self, app, as_user, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(
            extensions,
            "SUBNET_MAP",
            {1: {"name": "a", "cidr": "10.98.1.0/24"}, 2: {"name": "b", "cidr": "10.77.0.0/24"}},
        )
        as_user("admin", [1])
        with app.test_request_context("/x"):
            ok, err_ok = plugin_helpers.subnet_or_404(1)
            hidden, err_hidden = plugin_helpers.subnet_or_404(2)
            missing, err_missing = plugin_helpers.subnet_or_404(99)
            from flask import get_flashed_messages

            assert get_flashed_messages() == [], "a JSON route must not queue a flash"
        assert ok == {"name": "a", "cidr": "10.98.1.0/24"} and err_ok is None
        assert hidden is None and missing is None
        assert err_hidden[1] == 404 and err_missing[1] == 404
        assert err_hidden[0].get_json() == err_missing[0].get_json() == {"error": "not found"}

    def test_require_write_refuses_a_viewer_with_a_json_403(self, app, as_user):
        @plugin_helpers.require_write(message="nope")
        def route():
            return "ran", 200

        as_user("viewer")
        with app.test_request_context("/api/v1/x", method="POST", json={}):
            resp, code = route()
        assert code == 403 and resp.get_json() == {"error": "nope"}

    def test_require_write_flashes_and_redirects_a_page_request(self, app, as_user):
        @plugin_helpers.require_write(message="Read only.", redirect_endpoint="dashboard.dashboard")
        def route():
            return "ran"

        as_user("viewer")
        with app.test_request_context("/network/x", method="POST"):
            from flask import get_flashed_messages

            resp = route()
            assert resp.status_code == 302 and get_flashed_messages() == ["Read only."]

    @pytest.mark.parametrize("role", ["admin", "superadmin"])
    def test_require_write_lets_an_admin_through_untouched(self, app, as_user, role):
        @plugin_helpers.require_write()
        def route(x, y=2):
            return ("ran", x, y)

        as_user(role)
        with app.test_request_context("/x", method="POST"):
            assert route(1, y=3) == ("ran", 1, 3)
