"""
tests/test_investigation_providers.py
──────────────────────────────────────
v5.68.0-beta.4 (Q139) — register_investigation_provider(): the registry, the one-card-per-plugin run, the card validation that
refuses to trust the plugin, the read-only subject, and the export from jen.plugin_api. No database: the providers here are fakes.
`pytest --noconftest tests/test_investigation_providers.py`. The page those cards land on is tests/test_investigation_providers_routes.py.
"""

import logging
import threading

import pytest

from jen import plugin_api
from jen.services import client_subject as cs
from jen.services import investigation_providers as ip


@pytest.fixture(autouse=True)
def clean_registry():
    before = dict(ip._PROVIDERS)
    ip._PROVIDERS.clear()
    yield
    ip._PROVIDERS.clear()
    ip._PROVIDERS.update(before)


def _subject(**kw):
    base = {"kind": "mac", "identifier": "aa:bb:cc:dd:ee:01", "mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.5"}
    base.update(kw)
    return cs.ClientSubject(**base)


class TestRegistration:
    def test_it_is_exported_from_plugin_api_as_the_same_function(self):
        assert plugin_api.register_investigation_provider is ip.register_investigation_provider
        assert "register_investigation_provider" in plugin_api.__all__

    def test_a_provider_that_is_not_callable_is_refused(self):
        with pytest.raises(TypeError):
            ip.register_investigation_provider("p", title="P", fn="nope")

    def test_registering_twice_replaces(self):
        ip.register_investigation_provider("p", title="P", fn=lambda s, a, al: {"summary": "one"})
        ip.register_investigation_provider("p", title="P", fn=lambda s, a, al: {"summary": "two"})
        assert len(ip.registered_investigation_providers()) == 1
        assert ip.run_investigation_providers(_subject(), {1}, True)[0]["card"]["summary"] == "two"


class TestRunning:
    def test_a_card_comes_back_with_its_plugins_title_in_registration_order(self):
        ip.register_investigation_provider("b", title="Beta", fn=lambda s, a, al: {"summary": "b says"})
        ip.register_investigation_provider("a", title="Alpha", fn=lambda s, a, al: {"summary": "a says"})
        out = ip.run_investigation_providers(_subject(), {1}, True)
        assert [r["plugin_id"] for r in out] == ["b", "a"]
        assert out[0]["title"] == "Beta" and out[0]["card"]["summary"] == "b says" and not out[0]["unavailable"]

    def test_none_means_nothing_to_say_and_renders_nothing(self):
        ip.register_investigation_provider("quiet", title="Quiet", fn=lambda s, a, al: None)
        assert ip.run_investigation_providers(_subject(), {1}, True) == []

    def test_a_card_with_neither_summary_nor_rows_is_nothing_to_say(self):
        ip.register_investigation_provider("empty", title="Empty", fn=lambda s, a, al: {"summary": "  ", "rows": []})
        assert ip.run_investigation_providers(_subject(), {1}, True) == []

    def test_a_raising_provider_is_unavailable_and_the_next_one_still_runs(self, caplog):
        def boom(s, a, al):
            raise RuntimeError("paramiko exploded at 10.0.0.5")

        ip.register_investigation_provider("bad", title="Bad", fn=boom)
        ip.register_investigation_provider("good", title="Good", fn=lambda s, a, al: {"summary": "fine"})
        with caplog.at_level(logging.ERROR):
            out = ip.run_investigation_providers(_subject(), {1}, True)
        assert out[0]["plugin_id"] == "bad" and out[0]["unavailable"] and out[0]["card"] is None
        assert out[1]["card"]["summary"] == "fine"
        assert "bad" in caplog.text

    def test_an_answer_that_is_not_a_card_is_unavailable_not_a_crash(self):
        ip.register_investigation_provider("odd", title="Odd", fn=lambda s, a, al: ["a", "list"])
        out = ip.run_investigation_providers(_subject(), {1}, True)
        assert out[0]["unavailable"] is True

    def test_a_provider_over_its_budget_is_unavailable_and_the_card_it_would_have_returned_never_shows(
        self, monkeypatch, caplog
    ):
        monkeypatch.setattr(ip, "BUDGET_SECONDS", 0.05)
        release = threading.Event()

        def slow(s, a, al):
            release.wait(5)
            return {"summary": "late"}

        ip.register_investigation_provider("slow", title="Slow", fn=slow)
        try:
            with caplog.at_level(logging.WARNING):
                out = ip.run_investigation_providers(_subject(), {1}, True)
        finally:
            release.set()
        assert out[0]["unavailable"] is True and out[0]["card"] is None and out[0]["reason"] == "over 0.05 s"
        assert "still running" in caplog.text

    def test_the_provider_is_handed_the_subject_and_the_callers_own_scope(self):
        seen = {}

        def fn(subject, accessible, all_subnets):
            seen.update(mac=subject.mac, ip=subject.ip, accessible=set(accessible), all_subnets=all_subnets)
            return None

        ip.register_investigation_provider("p", title="P", fn=fn)
        ip.run_investigation_providers(_subject(), {1, 2}, False)
        assert seen == {"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.5", "accessible": {1, 2}, "all_subnets": False}

    def test_a_restricted_caller_with_no_subnets_gets_no_providers_run_at_all(self):
        called = []
        ip.register_investigation_provider("p", title="P", fn=lambda s, a, al: called.append(1))
        assert ip.run_investigation_providers(_subject(), set(), False) == [] and called == []

    def test_the_subject_is_a_copy_a_provider_cannot_edit_what_the_page_sees(self):
        def vandal(subject, accessible, all_subnets):
            subject.leases4.append({"ip": "6.6.6.6"})
            subject.reservations.clear()
            return {"summary": "done"}

        ip.register_investigation_provider("vandal", title="V", fn=vandal)
        original = _subject(leases4=[{"ip": "10.0.0.5"}], reservations=[{"ip": "10.0.0.5"}])
        ip.run_investigation_providers(original, {1}, True)
        assert original.leases4 == [{"ip": "10.0.0.5"}] and original.reservations == [{"ip": "10.0.0.5"}]


class TestTheCardIsNotTrusted:
    def _card(self, **kw):
        return ip._card({"summary": "s", **kw})

    def test_the_shape_is_normalised(self):
        card = ip._card(
            {
                "summary": "On port 3",
                "status": "warn",
                "href": "/plugin/switchport/mac/aa",
                "rows": [
                    {"label": "Switch", "value": "sw1", "href": "/plugin/switchport/s/1"},
                    {"label": "VLAN", "value": 20},
                ],
            }
        )
        assert card == {
            "summary": "On port 3",
            "status": "warn",
            "href": "/plugin/switchport/mac/aa",
            "rows": [
                {"label": "Switch", "value": "sw1", "href": "/plugin/switchport/s/1"},
                {"label": "VLAN", "value": "20"},
            ],
        }

    def test_an_unknown_status_is_ok(self):
        assert self._card(status="catastrophe")["status"] == "ok"
        assert self._card()["status"] == "ok"
        assert self._card(status="none")["status"] == "none"

    @pytest.mark.parametrize(
        "href",
        [
            "https://evil.example/x",
            "//evil.example/x",
            "javascript:alert(1)",
            "relative/path",
            "/a\\b",
            "/a\nb",
            "/a\x00b",
            5,
            None,
        ],
    )
    def test_a_link_that_is_not_a_path_inside_jen_is_dropped_whatever_the_field(self, href):
        card = self._card(href=href, rows=[{"label": "L", "value": "v", "href": href}])
        assert card["href"] == "" and "href" not in card["rows"][0]

    def test_rows_are_capped_and_junk_rows_skipped(self):
        rows = [{"label": f"r{i}", "value": "v"} for i in range(50)] + ["junk", None, {"label": "", "value": ""}]
        card = ip._card({"summary": "s", "rows": rows})
        assert len(card["rows"]) == ip.MAX_ROWS

    def test_long_text_is_cut(self):
        card = ip._card({"summary": "x" * 5000, "rows": [{"label": "y" * 5000, "value": "z" * 5000}]})
        assert len(card["summary"]) == ip.MAX_SUMMARY
        assert len(card["rows"][0]["label"]) == ip.MAX_TEXT and len(card["rows"][0]["value"]) == ip.MAX_TEXT


class TestTheOneLineAnswer:
    def test_only_warn_cards_with_a_summary_are_listed(self):
        results = [
            {
                "plugin_id": "a",
                "title": "A",
                "card": {"summary": "down for 3 checks", "status": "warn"},
                "unavailable": False,
            },
            {"plugin_id": "b", "title": "B", "card": {"summary": "fine", "status": "ok"}, "unavailable": False},
            {"plugin_id": "c", "title": "C", "card": None, "unavailable": True},
            {"plugin_id": "d", "title": "D", "card": {"summary": "", "status": "warn"}, "unavailable": False},
        ]
        assert ip.warnings_line(results) == [{"title": "A", "summary": "down for 3 checks"}]
