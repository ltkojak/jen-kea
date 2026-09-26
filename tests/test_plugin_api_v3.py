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

import hashlib
import json

import pytest

from jen.services.icons import nav_icon
from tests.test_api_key_authorization import _insert_api_key

FAKE_PLUGIN_ID = "fake"


def _fake_search_provider(query, accessible_subnet_ids, all_subnets):
    return [
        {"title": "Fake result", "subtitle": "in scope", "href": "/fake/x", "subnet_id": 1},
        {"title": "Denied result", "subtitle": "out of scope", "href": "/fake/y", "subnet_id": 999},
    ]


def _raising_search_provider(query, accessible_subnet_ids, all_subnets):
    raise RuntimeError("fake provider boom")


@pytest.fixture(scope="module")
def fake_plugin():
    """Registers register_alert_type/register_row_action/register_search_provider
    the same way a plugin's own register(app) would from plugin.py. These
    mutate process-global dicts (the same ones a real plugin's load
    would), so this tears itself back down afterward rather than leaking
    a fake entry into every other test file that iterates them (e.g.
    tests/test_q57_quickwins.py checks every DEFAULT_TEMPLATES entry
    opens with a standard glyph — the template below follows that
    convention too, for the same reason a real plugin should).

    api_key_required's own routes are NOT registered here: the shared
    session-scoped `app` fixture may already have served a request by
    the time this module's tests run, and Flask refuses new @app.route()
    registration after that ("the setup method 'route' can no longer be
    called"). TestApiKeyRequired hosts its two probe routes on a
    throwaway Flask app of its own instead (see its api_client fixture)."""
    from jen.plugin_api import register_alert_type, register_row_action, register_search_provider
    from jen.services import alerts as alerts_svc
    from jen.services import row_actions as row_actions_svc
    from jen.services import search_providers as search_providers_svc

    register_alert_type(
        FAKE_PLUGIN_ID,
        "fake_thing",
        label="Fake Thing",
        icon="puzzle",
        default_template="ℹ️ Fake: {subject}",
    )
    register_row_action(
        FAKE_PLUGIN_ID,
        "lease",
        label="Fake Action",
        icon="puzzle",
        href="/fake/action?mac={mac}",
        confirm="Do the fake thing to {mac}?",
    )
    register_search_provider(FAKE_PLUGIN_ID, title="Fake Plugin", fn=_fake_search_provider)
    register_search_provider("fake-raiser", title="Fake Raiser", fn=_raising_search_provider)

    yield FAKE_PLUGIN_ID

    alerts_svc.ALERT_TYPE_LABELS.pop("fake_thing", None)
    alerts_svc.ALERT_TYPE_ICONS.pop("fake_thing", None)
    alerts_svc.DEFAULT_TEMPLATES.pop("fake_thing", None)
    alerts_svc.PLUGIN_ALERT_TYPES.pop("fake_thing", None)
    row_actions_svc._ACTIONS[:] = [a for a in row_actions_svc._ACTIONS if a["plugin_id"] != FAKE_PLUGIN_ID]
    search_providers_svc._PROVIDERS.pop(FAKE_PLUGIN_ID, None)
    search_providers_svc._PROVIDERS.pop("fake-raiser", None)


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


class TestRegisterRowAction:
    MAC = "aa:bb:cc:fa:ce:99"  # valid hex (UNHEX needs it) despite spelling "face"

    @pytest.fixture
    def one_lease(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (self.MAC.replace(":", ""),))
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, state, expire, valid_lifetime, hostname) "
                "VALUES (INET_ATON('10.99.0.50'), UNHEX(%s), 1, 0, NOW() + INTERVAL 1 HOUR, 3600, 'fakehost')",
                (self.MAC.replace(":", ""),),
            )
        db.commit()
        yield
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (self.MAC.replace(":", ""),))
        db.commit()

    def test_renders_for_an_admin_with_mac_url_encoded(self, fake_plugin, one_lease, logged_in_client):
        html = logged_in_client.get("/leases").data.decode()
        assert "Fake Action" in html
        # The leases list renders MAC uppercase (MySQL/MariaDB HEX()), same
        # as every other MAC shown on that page — the row action's href
        # inherits that case rather than normalizing it.
        assert f"/fake/action?mac={self.MAC.upper().replace(':', '%3A')}" in html

    def test_confirm_text_substitutes_the_raw_mac_not_url_encoded(self, fake_plugin, one_lease, logged_in_client):
        """v5.61.0 (Q78) — confirm is a sentence a person reads, so its
        {mac} substitutes the raw MAC ('aa:bb:...'), never the
        %-encoded form href's {mac} gets. The exact-string match below
        (real colons, no %3A) is itself the proof."""
        html = logged_in_client.get("/leases").data.decode()
        assert f'data-confirm="Do the fake thing to {self.MAC.upper()}?"' in html

    def test_does_not_render_for_a_viewer(self, fake_plugin, one_lease, client, db):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_probe_viewer_q73")
        html = client.get("/leases").data.decode()
        assert "Fake Action" not in html


class TestApiKeyRequired:
    """api_key_required is plain Flask (g/request/jsonify) with no
    dependency on Jen's own app instance, so these tests host the two
    probe routes on a throwaway Flask app rather than the shared
    session-scoped `app` fixture — see fake_plugin's docstring for why."""

    RAW_RW = "jen_q73_rw_probe"
    RAW_RO = "jen_q73_ro_probe"
    RAW_SCOPED = "jen_q73_scoped_probe"

    @pytest.fixture(scope="class")
    def api_client(self):
        from flask import Flask, g, jsonify

        from jen.plugin_api import api_key_required

        mini = Flask(__name__)

        @mini.route("/api/v1/plugins/fake/echo", methods=["GET"])
        @api_key_required(write=False)
        def fake_echo():
            return jsonify({"key_id": g.api_key["id"]})

        @mini.route("/api/v1/plugins/fake/write", methods=["POST"])
        @api_key_required(write=True)
        def fake_write():
            return jsonify({"ok": True})

        return mini.test_client()

    @pytest.fixture
    def keys(self, db):
        def _key(name, raw, can_write, subnet_access=None):
            key_id = _insert_api_key(db, name, created_by=1, subnet_access=subnet_access)
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE api_keys SET key_hash=%s, can_write=%s WHERE id=%s",
                    (hashlib.sha256(raw.encode()).hexdigest(), can_write, key_id),
                )
            db.commit()
            return key_id

        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name LIKE '_q73_probe_%%'")
        db.commit()
        ids = {
            "rw": _key("_q73_probe_rw", self.RAW_RW, 1),
            "ro": _key("_q73_probe_ro", self.RAW_RO, 0),
            "scoped": _key("_q73_probe_scoped", self.RAW_SCOPED, 1, subnet_access=[1]),
        }
        yield ids
        with db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name LIKE '_q73_probe_%%'")
        db.commit()

    def test_no_key_is_401(self, api_client):
        r = api_client.get("/api/v1/plugins/fake/echo")
        assert r.status_code == 401

    def test_bad_key_is_401(self, api_client):
        r = api_client.get("/api/v1/plugins/fake/echo", headers={"Authorization": "Bearer not-a-real-key"})
        assert r.status_code == 401

    def test_valid_key_is_200_and_sets_g_api_key(self, api_client, keys):
        r = api_client.get("/api/v1/plugins/fake/echo", headers={"Authorization": f"Bearer {self.RAW_RW}"})
        assert r.status_code == 200
        assert r.get_json() == {"key_id": keys["rw"]}

    def test_read_only_key_on_a_write_route_is_403(self, api_client, keys):
        r = api_client.post("/api/v1/plugins/fake/write", headers={"Authorization": f"Bearer {self.RAW_RO}"})
        assert r.status_code == 403

    def test_write_capable_key_on_a_write_route_is_200(self, api_client, keys):
        r = api_client.post("/api/v1/plugins/fake/write", headers={"Authorization": f"Bearer {self.RAW_RW}"})
        assert r.status_code == 200


class TestFilterSubnetIds:
    def test_unrestricted_key_gets_the_whole_list_back(self):
        from jen.services.api_auth import filter_subnet_ids

        assert filter_subnet_ids({"subnet_access": None}, [1, 2, 3]) == [1, 2, 3]

    def test_scoped_key_is_intersected(self):
        from jen.services.api_auth import filter_subnet_ids

        assert filter_subnet_ids({"subnet_access": json.dumps([1, 3])}, [1, 2, 3]) == [1, 3]

    def test_malformed_scope_denies_everything(self):
        from jen.services.api_auth import filter_subnet_ids

        assert filter_subnet_ids({"subnet_access": "not json"}, [1, 2, 3]) == []


class TestRegisterSearchProvider:
    def test_rows_appear_for_an_unrestricted_admin(self, fake_plugin):
        from jen.services.search_providers import run_search_providers

        results = run_search_providers("q", [1, 999], True)
        fake = next(r for r in results if r["plugin_id"] == FAKE_PLUGIN_ID)
        assert [row["title"] for row in fake["rows"]] == ["Fake result", "Denied result"]

    def test_a_denied_subnet_id_is_dropped_for_a_scoped_caller(self, fake_plugin):
        from jen.services.search_providers import run_search_providers

        results = run_search_providers("q", [1], False)
        fake = next(r for r in results if r["plugin_id"] == FAKE_PLUGIN_ID)
        assert [row["title"] for row in fake["rows"]] == ["Fake result"]

    def test_a_raising_provider_shows_unavailable(self, fake_plugin):
        from jen.services.search_providers import run_search_providers

        results = run_search_providers("q", [1], True)
        raiser = next(r for r in results if r["plugin_id"] == "fake-raiser")
        assert raiser["unavailable"] is True
        assert raiser["rows"] == []

    def test_search_route_renders_a_card_per_provider(self, fake_plugin, logged_in_client):
        html = logged_in_client.get("/search?q=fakequery").data.decode()
        assert "Fake Plugin" in html
        assert "Fake result" in html
        assert "Fake Raiser" in html
        assert "unavailable" in html


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


# ── v5.65.2 (Q91 i): one helper for "no attributable subnet" ─────────────────────


class _User:
    def __init__(self, allowed=None, authenticated=True):
        self.is_authenticated = authenticated
        self._allowed = allowed

    @property
    def all_subnets(self):
        return self._allowed is None

    def can_access_subnet(self, subnet_id):
        return self.all_subnets or int(subnet_id) in self._allowed


class TestCanAccessSubnet:
    def _as(self, monkeypatch, user):
        from jen import plugin_api

        monkeypatch.setattr(plugin_api, "_current_user", user)
        return plugin_api.can_access_subnet

    def test_a_scoped_user_is_judged_on_the_subnet(self, monkeypatch):
        can = self._as(monkeypatch, _User(allowed=[1]))
        assert can(1) is True and can("1") is True
        assert can(2) is False and can("nonsense") is False

    def test_none_fails_closed_for_a_scoped_user(self, monkeypatch):
        """Core's rule (docs/ARCHITECTURE.md section 2): no attributable subnet is for unrestricted callers only."""
        can = self._as(monkeypatch, _User(allowed=[1]))
        assert can(None) is False
        assert can(None, allow_unattributed=True) is True  # the explicit, commented opt-out

    def test_an_unrestricted_user_may_see_anything_including_none(self, monkeypatch):
        can = self._as(monkeypatch, _User(allowed=None))
        assert can(1) is True and can(99) is True and can(None) is True

    def test_an_anonymous_caller_may_see_nothing(self, monkeypatch):
        can = self._as(monkeypatch, _User(allowed=None, authenticated=False))
        assert can(1) is False and can(None) is False and can(None, allow_unattributed=True) is False


class TestApiKeyCanAccessSubnet:
    def test_scoped_key(self):
        from jen.plugin_api import api_key_can_access_subnet as can

        key = {"subnet_access": "[1, 3]"}
        assert can(key, 1) is True and can(key, "3") is True
        assert can(key, 2) is False and can(key, "x") is False

    def test_none_fails_closed_for_a_scoped_key(self):
        from jen.plugin_api import api_key_can_access_subnet as can

        key = {"subnet_access": [1]}
        assert can(key, None) is False
        assert can(key, None, allow_unattributed=True) is True

    def test_an_unrestricted_key_sees_everything(self):
        from jen.plugin_api import api_key_can_access_subnet as can

        key = {"subnet_access": None}
        assert can(key, 5) is True and can(key, None) is True

    def test_a_missing_key_is_not_an_unrestricted_one(self):
        # v5.65.8 (Q97 a): an empty row used to read as "no scope" and so as "everything"
        from jen.plugin_api import api_key_can_access_subnet as can

        assert can({}, 5) is False and can({}, None) is False and can(None, 5) is False

    def test_a_malformed_scope_fails_closed(self):
        from jen.plugin_api import api_key_can_access_subnet as can

        key = {"subnet_access": "not json"}
        assert can(key, 1) is False and can(key, None) is False

    def test_the_helpers_are_published(self):
        from jen import plugin_api

        assert "can_access_subnet" in plugin_api.__all__ and "api_key_can_access_subnet" in plugin_api.__all__
