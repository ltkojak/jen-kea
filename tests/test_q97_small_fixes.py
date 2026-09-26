"""
tests/test_q97_small_fixes.py
──────────────────────────────
v5.65.8 (Q97) - the small items of the second audit of the release candidate: search providers filter
before they truncate and guard each row, discover_plugins() sanitises nav icons for every reader, a JSON
array body no longer 500s the dashboard prefs, reset-template validates its alert type, the palette
comment is true, the DNS tab is spelt DNS, api_key_can_access_subnet fails closed on a missing key,
event kinds and alert type ids cannot exceed their columns, and register_alert_type checks its icon.
"""

import json
import logging
import pathlib

import pytest

from jen.services import search_providers as sp


@pytest.fixture
def providers():
    saved = dict(sp._PROVIDERS)
    sp._PROVIDERS.clear()
    yield
    sp._PROVIDERS.clear()
    sp._PROVIDERS.update(saved)


class TestSearchProvidersFilterThenTruncate:
    def test_a_restricted_caller_whose_rows_come_after_the_cap_still_sees_them(self, providers):
        rows = [{"title": f"b{i}", "subnet_id": 2} for i in range(25)] + [
            {"title": f"a{i}", "subnet_id": 1} for i in range(5)
        ]
        sp.register_search_provider("demo", title="Demo", fn=lambda q, ids, all_: rows)
        card = sp.run_search_providers("x", {1}, False)[0]
        assert [r["title"] for r in card["rows"]] == [f"a{i}" for i in range(5)]

    def test_the_cap_still_applies_to_what_the_caller_may_see(self, providers):
        rows = [{"title": f"a{i}", "subnet_id": 1} for i in range(50)]
        sp.register_search_provider("demo", title="Demo", fn=lambda q, ids, all_: rows)
        assert len(sp.run_search_providers("x", {1}, False)[0]["rows"]) == sp.MAX_ROWS

    def test_a_non_dict_row_is_skipped_and_the_page_is_not_blanked(self, providers, caplog):
        sp.register_search_provider("bad", title="Bad", fn=lambda q, ids, all_: ["oops", None, 5, {"title": "ok"}])
        sp.register_search_provider("good", title="Good", fn=lambda q, ids, all_: [{"title": "fine", "subnet_id": 1}])
        with caplog.at_level(logging.WARNING):
            cards = sp.run_search_providers("x", {1}, True)
        assert [c["plugin_id"] for c in cards] == ["bad", "good"]
        assert [r["title"] for r in cards[0]["rows"]] == ["ok"]
        assert cards[1]["rows"]
        assert "non-dict row" in caplog.text

    def test_a_provider_returning_a_non_list_is_treated_as_no_rows(self, providers):
        sp.register_search_provider("odd", title="Odd", fn=lambda q, ids, all_: {"not": "a list"})
        assert sp.run_search_providers("x", {1}, True)[0]["rows"] == []


class TestDiscoverPluginsSanitisesIcons:
    def test_a_manifest_naming_a_missing_icon_reads_puzzle_for_every_reader(self, tmp_path, monkeypatch):
        from jen import extensions
        from jen.services import plugins as plugins_svc

        d = tmp_path / "iconless"
        d.mkdir()
        manifest = {
            "id": "iconless",
            "name": "x",
            "version": "1.0.0",
            "nav": [{"label": "X", "icon": "no-such-icon"}],
        }
        (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(tmp_path / "none-a"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "none-b"))
        found = [m for m in plugins_svc.discover_plugins() if m["id"] == "iconless"]
        assert found
        assert found[0]["nav"][0]["icon"] == "puzzle"

    def test_it_warns_once_not_on_every_call(self, caplog):
        from jen.services import icons

        icons._nav_warned.discard(("plugin q97", "still-missing"))
        with caplog.at_level(logging.WARNING, logger="jen.services.icons"):
            icons.checked_nav_icon("still-missing", "plugin q97")
            icons.checked_nav_icon("still-missing", "plugin q97")
        assert caplog.text.count("still-missing") == 1


class TestApiKeyCanAccessSubnetFailsClosedOnAMissingKey:
    @pytest.mark.parametrize("key", [None, {}])
    @pytest.mark.parametrize("subnet", [None, 1, "1"])
    @pytest.mark.parametrize("allow", [False, True])
    def test_a_missing_key_is_false_for_everything(self, key, subnet, allow):
        from jen.plugin_api import api_key_can_access_subnet

        assert api_key_can_access_subnet(key, subnet, allow_unattributed=allow) is False

    def test_a_real_unrestricted_key_still_grants(self):
        from jen.plugin_api import api_key_can_access_subnet

        assert api_key_can_access_subnet({"id": 1, "subnet_access": None}, 5) is True

    def test_a_scoped_key_is_unchanged(self):
        from jen.plugin_api import api_key_can_access_subnet

        key = {"id": 1, "subnet_access": "[1]"}
        assert api_key_can_access_subnet(key, 1)
        assert not api_key_can_access_subnet(key, 2)


class TestColumnLengthGuards:
    def test_emit_refuses_a_kind_longer_than_the_column(self, caplog):
        from jen.services import events

        kind = "plugin.demo." + "a" * 40
        assert len(kind) > events.KIND_MAX_LENGTH
        assert events._PLUGIN_KIND_RE.match(kind)
        with caplog.at_level(logging.ERROR):
            assert events.emit(kind) is None
        assert "column holds 40" in caplog.text

    def test_register_alert_type_raises_on_an_over_long_id(self):
        from jen.services import alerts

        long_id = "demo_" + "x" * alerts.ALERT_TYPE_MAX_LENGTH
        with pytest.raises(ValueError, match="limited to 50"):
            alerts.register_alert_type("demo", long_id, label="x", icon="bell", default_template="x")
        assert long_id not in alerts.ALERT_TYPE_LABELS

    def test_an_id_at_the_limit_registers_and_a_bad_icon_becomes_bell(self, caplog):
        from jen.services import alerts

        ok_id = "demo_" + "y" * (alerts.ALERT_TYPE_MAX_LENGTH - 5)
        assert len(ok_id) == alerts.ALERT_TYPE_MAX_LENGTH
        try:
            with caplog.at_level(logging.WARNING):
                alerts.register_alert_type("demo", ok_id, label="x", icon="no-such-icon", default_template="x")
            assert alerts.ALERT_TYPE_ICONS[ok_id] == "bell"
            assert "not in the sprite" in caplog.text
        finally:
            alerts.ALERT_TYPE_LABELS.pop(ok_id, None)
            alerts.ALERT_TYPE_ICONS.pop(ok_id, None)
            alerts.DEFAULT_TEMPLATES.pop(ok_id, None)
            alerts.PLUGIN_ALERT_TYPES.pop(ok_id, None)


class TestTemplatesAndComments:
    def test_the_client_tab_chip_reads_dns_in_capitals(self):
        text = pathlib.Path("templates/client.html").read_text(encoding="utf-8")
        assert "'DNS' if t == 'dns'" in text

    def test_the_palette_comment_no_longer_says_it_is_never_revalidated(self):
        text = pathlib.Path("jen/__init__.py").read_text(encoding="utf-8")
        assert "never re-validated here" not in text


class TestDashboardPrefsAndResetTemplate:
    @pytest.mark.parametrize("body", [[1, 2], "text", 5, [{"id": "x"}]])
    def test_a_non_object_body_is_a_400_not_a_500(self, logged_in_client, body):
        r = logged_in_client.post("/api/dashboard/save-prefs", json=body)
        assert r.status_code == 400

    def test_an_object_body_still_saves(self, logged_in_client):
        r = logged_in_client.post("/api/dashboard/save-prefs", json={"widgets": []})
        assert r.status_code == 200

    def test_reset_template_refuses_an_unknown_type_and_touches_no_row(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("REPLACE INTO alert_templates (alert_type, template_text) VALUES ('q97-not-real', 'x')")
        db.commit()
        try:
            r = logged_in_client.post("/settings/alerts/reset-template", data={"alert_type": "q97-not-real"})
            assert r.status_code == 302
            with db.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS n FROM alert_templates WHERE alert_type='q97-not-real'")
                assert cur.fetchone()["n"] == 1
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_templates WHERE alert_type='q97-not-real'")
            db.commit()

    def test_reset_template_still_resets_a_real_type(self, logged_in_client, db):
        from jen.services.alerts import DEFAULT_TEMPLATES

        real = next(iter(DEFAULT_TEMPLATES))
        with db.cursor() as cur:
            cur.execute("REPLACE INTO alert_templates (alert_type, template_text) VALUES (%s, 'custom')", (real,))
        db.commit()
        r = logged_in_client.post("/settings/alerts/reset-template", data={"alert_type": real})
        assert r.status_code == 302
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM alert_templates WHERE alert_type=%s", (real,))
            assert cur.fetchone()["n"] == 0
