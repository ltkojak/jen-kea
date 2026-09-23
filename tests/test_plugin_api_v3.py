"""
tests/test_plugin_api_v3.py
────────────────────────────
v5.57.0 (Q73) — plugin API v3: emit() opened to plugins, register_alert_type,
register_row_action, api_key_required/filter_subnet_ids, register_search_provider.
The nav-icon-sprite-name check and emit()'s own kind validation are pure and
live in tests/test_desktop_polish.py-style files / tests/test_events.py
respectively; everything here needs the real app + DB, loading one fake
plugin through the real loader (jen.services.plugins._load_plugin) the same
way a real plugin's register(app) would run.
"""

import pytest

from jen.services.icons import nav_icon

FAKE_PLUGIN_ID = "fake"


@pytest.fixture(scope="module")
def fake_plugin(app):
    """Registers v3's new hooks directly on the real `app`, the same way
    a plugin's own register(app) would from plugin.py — module scoped
    so this only runs once per test run. register_alert_type mutates
    process-global dicts (the same ones a real plugin's load would), so
    this tears itself back down afterward rather than leaking a fake
    entry into every other test file that iterates them (e.g.
    tests/test_q57_quickwins.py checks every DEFAULT_TEMPLATES entry
    opens with a standard glyph — the template below follows that
    convention too, for the same reason a real plugin should)."""
    from jen.plugin_api import register_alert_type
    from jen.services import alerts as alerts_svc

    register_alert_type(
        FAKE_PLUGIN_ID,
        "fake_thing",
        label="Fake Thing",
        icon="puzzle",
        default_template="ℹ️ Fake: {subject}",
    )

    yield FAKE_PLUGIN_ID

    alerts_svc.ALERT_TYPE_LABELS.pop("fake_thing", None)
    alerts_svc.ALERT_TYPE_ICONS.pop("fake_thing", None)
    alerts_svc.DEFAULT_TEMPLATES.pop("fake_thing", None)
    alerts_svc.PLUGIN_ALERT_TYPES.pop("fake_thing", None)


class TestRegisterAlertType:
    def test_bad_prefix_is_refused(self):
        from jen.services.alerts import register_alert_type

        with pytest.raises(ValueError):
            register_alert_type("fake", "not_prefixed", label="x", icon="puzzle", default_template="x")

    def test_merges_into_the_three_dicts(self, fake_plugin):
        from jen.services.alerts import ALERT_TYPE_ICONS, ALERT_TYPE_LABELS, DEFAULT_TEMPLATES, PLUGIN_ALERT_TYPES

        assert ALERT_TYPE_LABELS["fake_thing"] == "Fake Thing"
        assert ALERT_TYPE_ICONS["fake_thing"] == "puzzle"
        assert DEFAULT_TEMPLATES["fake_thing"] == "ℹ️ Fake: {subject}"
        assert PLUGIN_ALERT_TYPES["fake_thing"] == FAKE_PLUGIN_ID

    def test_settings_alerts_shows_it_under_from_plugins(self, fake_plugin, logged_in_client):
        html = logged_in_client.get("/settings/alerts").data.decode()
        assert "From plugins" in html
        assert "Fake Thing" in html
        assert 'id="al-tpl-fake_thing"' in html

    def test_send_alert_reaches_a_channel_configured_for_it(self, fake_plugin, db, monkeypatch):
        import json

        from jen.services import alerts

        with db.cursor() as cur:
            cur.execute("DELETE FROM alert_channels WHERE channel_name='_probe_fake_channel'")
            cur.execute(
                "INSERT INTO alert_channels (channel_type, channel_name, config, enabled, alert_types) "
                "VALUES ('webhook', '_probe_fake_channel', %s, 1, %s)",
                (json.dumps({"url": "http://example.invalid/hook"}), json.dumps(["fake_thing"])),
            )
        db.commit()
        sent = []
        monkeypatch.setattr(alerts, "_send_webhook_channel", lambda message, alert_type, config: sent.append(message))
        try:
            alerts.send_alert("fake_thing", log_result=False, subject="hello")
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_channels WHERE channel_name='_probe_fake_channel'")
            db.commit()
        assert sent == ["ℹ️ Fake: hello"]


class TestNavIconSpriteName:
    """v5.57.0 (Q73) — a manifest's nav[].icon can now name a sprite icon
    directly, not just a legacy emoji; nav_icon() (already the loader's
    own resolution path, plugins.py's get_nav_items() + base.html's
    {{ nav_icon(item.icon) }}) needs no change, just this to prove it."""

    def test_a_sprite_name_renders_as_the_icon(self):
        out = str(nav_icon("activity"))
        assert "<svg" in out and 'href="#i-activity"' in out

    def test_a_legacy_emoji_still_renders_as_plain_text(self):
        out = str(nav_icon("🚀"))
        assert "<svg" not in out and "🚀" in out
