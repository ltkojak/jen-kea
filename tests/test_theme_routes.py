"""
tests/test_theme_routes.py
─────────────────────────────
v5.55.0 (Q63) — the three Settings -> Appearance -> Theme routes
(jen/routes/settings/theme.py) and how they show up on the page. Needs
the CI database (jen.services.theme's own pure logic is tested directly
in tests/test_theme.py, which runs without one).
"""

import json

import pytest

from tests.conftest import restricted_client


def _get_setting(db, key):
    with db.cursor() as cur:
        cur.execute("SELECT setting_value FROM settings WHERE setting_key=%s", (key,))
        row = cur.fetchone()
        return row["setting_value"] if row else None


def _audit_count(db, action):
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) c FROM audit_log WHERE action=%s", (action,))
        return cur.fetchone()["c"]


VALID_CUSTOM = {
    "bg": "#101010",
    "surface": "#151515",
    "surface2": "#1a1a1a",
    "surface3": "#202020",
    "border": "#2f2f2f",
    "text": "#eeeeee",
    "text_muted": "#888888",
    "primary": "#4fc3f7",
    "success": "#66bb6a",
    "warning": "#ffca28",
    "danger": "#ef5350",
    "radius": "8",
    "mono_ui": "on",
}


class TestCardVisibility:
    def test_superadmin_sees_the_card(self, logged_in_client):
        resp = logged_in_client.get("/settings/appearance")
        assert b'id="app-theme"' in resp.data
        assert b'action="/settings/theme/default"' in resp.data
        assert b'action="/settings/theme/custom"' in resp.data

    def test_admin_does_not_see_the_card(self, client, db):
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        resp = c.get("/settings/appearance")
        assert b'id="app-theme"' not in resp.data


class TestNonSuperadminRejected:
    @pytest.mark.parametrize(
        "path,data",
        [
            ("/settings/theme/default", {"theme_default": "light"}),
            ("/settings/theme/custom", VALID_CUSTOM),
            ("/settings/theme/custom/remove", {}),
        ],
    )
    def test_admin_post_is_redirected_away_and_changes_nothing(self, client, db, path, data):
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        before = _get_setting(db, "theme_default")
        # REPEATABLE READ (MySQL/MariaDB's default): `before`'s SELECT opened
        # a transaction on this connection, and it would otherwise still be
        # looking at that same snapshot below — a real write slipping past
        # the decorator would go unnoticed. Close it out before the POST.
        db.commit()
        resp = c.post(path, data=data, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"] != path  # sent to the access-denied redirect, not back to itself
        assert _get_setting(db, "theme_default") == before


class TestSaveThemeDefault:
    def test_valid_preset_id_is_saved_and_audited(self, logged_in_client, db):
        resp = logged_in_client.post(
            "/settings/theme/default", data={"theme_default": "phosphor"}, follow_redirects=True
        )
        assert resp.status_code == 200
        assert _get_setting(db, "theme_default") == "phosphor"
        assert _audit_count(db, "SAVE_THEME_DEFAULT") == 1

    def test_unknown_id_is_rejected(self, logged_in_client, db):
        resp = logged_in_client.post(
            "/settings/theme/default", data={"theme_default": "not-a-real-preset"}, follow_redirects=True
        )
        assert resp.status_code == 200
        assert b"Unknown theme" in resp.data
        assert _get_setting(db, "theme_default") is None

    def test_custom_is_only_accepted_once_a_custom_palette_exists(self, logged_in_client, db):
        resp = logged_in_client.post("/settings/theme/default", data={"theme_default": "custom"}, follow_redirects=True)
        assert b"Unknown theme" in resp.data
        logged_in_client.post("/settings/theme/custom", data=VALID_CUSTOM)
        resp = logged_in_client.post("/settings/theme/default", data={"theme_default": "custom"}, follow_redirects=True)
        assert resp.status_code == 200
        assert _get_setting(db, "theme_default") == "custom"


class TestSaveThemeCustom:
    def test_valid_palette_is_saved_audited_and_renders_as_a_root_block(self, logged_in_client, db):
        resp = logged_in_client.post("/settings/theme/custom", data=VALID_CUSTOM, follow_redirects=True)
        assert resp.status_code == 200
        assert _audit_count(db, "SAVE_THEME_CUSTOM") == 1
        stored = json.loads(_get_setting(db, "theme_custom"))
        assert stored["tokens"]["primary"] == "#4fc3f7"
        assert stored["radius"] == 8
        assert stored["mono_ui"] is True

        page = logged_in_client.get("/settings/appearance")
        assert b':root[data-theme="custom"]' in page.data
        assert b"--primary:#4fc3f7" in page.data
        assert b"--radius:8px" in page.data

    def test_3_digit_hex_is_normalized_to_6(self, logged_in_client, db):
        data = dict(VALID_CUSTOM)
        data["text_muted"] = "#888"
        logged_in_client.post("/settings/theme/custom", data=data)
        stored = json.loads(_get_setting(db, "theme_custom"))
        assert stored["tokens"]["text_muted"] == "#888888"

    @pytest.mark.parametrize(
        "bad_bg",
        ["url(javascript:alert(1))", "red", "#12345678", "#fff;}body{background:red", "expression(alert(1))"],
    )
    def test_invalid_hex_is_rejected_and_nothing_is_saved(self, logged_in_client, db, bad_bg):
        data = dict(VALID_CUSTOM)
        data["bg"] = bad_bg
        resp = logged_in_client.post("/settings/theme/custom", data=data, follow_redirects=True)
        assert resp.status_code == 200
        assert _get_setting(db, "theme_custom") is None
        assert _audit_count(db, "SAVE_THEME_CUSTOM") == 0

    def test_low_contrast_palette_saves_with_a_warning_not_an_error(self, logged_in_client, db):
        data = dict(VALID_CUSTOM)
        data["text"] = "#101010"  # nearly identical to bg -> below 4.5:1
        resp = logged_in_client.post("/settings/theme/custom", data=data, follow_redirects=True)
        assert resp.status_code == 200
        assert _get_setting(db, "theme_custom") is not None  # still saved
        assert b"WCAG AA" in resp.data  # the warning flash made it through


class TestRemoveThemeCustom:
    def test_removes_the_palette_and_falls_default_back_to_dark(self, logged_in_client, db):
        logged_in_client.post("/settings/theme/custom", data=VALID_CUSTOM)
        logged_in_client.post("/settings/theme/default", data={"theme_default": "custom"})
        assert _get_setting(db, "theme_default") == "custom"
        # Same REPEATABLE READ gotcha as TestNonSuperadminRejected above —
        # that assert's SELECT opened a transaction here; without closing it,
        # every read below would still see this pre-remove snapshot.
        db.commit()

        resp = logged_in_client.post("/settings/theme/custom/remove", follow_redirects=True)
        assert resp.status_code == 200
        assert _get_setting(db, "theme_custom") == ""
        assert _get_setting(db, "theme_default") == "dark"
        assert _audit_count(db, "REMOVE_THEME_CUSTOM") == 1

        page = logged_in_client.get("/settings/appearance")
        assert b'data-theme="custom"' not in page.data

    def test_removing_when_default_was_a_built_in_preset_leaves_it_alone(self, logged_in_client, db):
        logged_in_client.post("/settings/theme/custom", data=VALID_CUSTOM)
        logged_in_client.post("/settings/theme/default", data={"theme_default": "light"})
        logged_in_client.post("/settings/theme/custom/remove")
        assert _get_setting(db, "theme_default") == "light"


class TestThemeDefaultDrivesThePage:
    def test_page_head_reflects_the_saved_default(self, logged_in_client):
        logged_in_client.post("/settings/theme/default", data={"theme_default": "contrast"})
        page = logged_in_client.get("/settings/appearance")
        # The base <html data-theme="dark"> attribute is a static fallback for
        # the instant before the FOUC-avoiding IIFE runs — THEME_DEFAULT is
        # what that IIFE actually reads.
        assert b'THEME_DEFAULT = "contrast"' in page.data
        assert b'content="' in page.data.split(b'name="theme-color"')[1][:20]  # meta tag present and non-empty

    @pytest.mark.parametrize(
        "preset_id,name",
        [("dark", "Dark"), ("light", "Light"), ("contrast", "High contrast"), ("phosphor", "Phosphor")],
    )
    def test_the_picker_names_the_saved_default(self, logged_in_client, preset_id, name):
        # v5.55.3 (Q66) — the picker's own "Install default (<name>)"
        # entry, once per page (nav dropdown) plus once for the phone
        # sheet — both server-rendered from theme_default_name, not |tojson'd.
        logged_in_client.post("/settings/theme/default", data={"theme_default": preset_id})
        page = logged_in_client.get("/settings/appearance")
        expected = f"Install default ({name})".encode()
        assert page.data.count(expected) == 2, (
            f"expected 2 occurrences (nav + sheet), found {page.data.count(expected)}"
        )


class TestSettingsEndpointsRegistered:
    def test_the_three_endpoints_exist(self, app):
        names = {r.endpoint for r in app.url_map.iter_rules()}
        assert "settings.save_theme_default" in names
        assert "settings.save_theme_custom" in names
        assert "settings.remove_theme_custom" in names
