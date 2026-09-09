"""
tests/test_settings_ia.py
─────────────────────────
v5.9.0 — the Settings information-architecture rework. Settings became
seven task-shaped groups (Kea · Databases · Access & Security · Alerts &
Integrations · Appearance · System · Logs), Database left the top nav,
/settings became a landing grid, and the navigation is defined once in
jen/routes/settings/nav.py instead of three hand-maintained endpoint
lists in base.html.

The build rules that made this safe are pinned here:
  - every POST endpoint URL is unchanged — checked by resolving every
    literal `action="/…"` in the settings templates against the url_map;
  - every old GET URL 301s to its new home (bookmarks, the update overlay
    redirect, docs);
  - the nav model (pure function) puts each endpoint in the right section
    and hides only what a role genuinely can't open.
"""

import os
import re
from pathlib import Path

import pytest

from jen.routes.settings import nav as navmod

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"


class TestNavModel:
    def test_top_nav_has_no_database_item(self):
        ids = [i["id"] for i in navmod.TOP_NAV]
        assert ids == ["dashboard", "management", "network", "settings", "about"]

    def test_settings_hidden_for_viewer_visible_for_admin(self):
        assert "settings" not in [i["id"] for i in navmod.nav_context("dashboard.dashboard", "viewer")["top"]]
        assert "settings" in [i["id"] for i in navmod.nav_context("dashboard.dashboard", "admin")["top"]]

    def test_management_section_active_by_prefix(self):
        ctx = navmod.nav_context("reservations.edit_reservation", "admin")
        assert [i for i in ctx["top"] if i["active"]][0]["id"] == "management"
        assert [t["label"] for t in ctx["strip"] if t["active"]] == ["Reservations"]

    def test_network_strip_appends_plugin_items_and_activates_them(self):
        plugins = [{"section": "network", "label": "IPAM", "icon": "🗺️", "endpoint": "ipam.index"}]
        ctx = navmod.nav_context("ipam.index", "admin", plugins)
        assert [i for i in ctx["top"] if i["active"]][0]["id"] == "network"
        assert ctx["strip"][-1]["label"] == "IPAM" and ctx["strip"][-1]["active"]

    @pytest.mark.parametrize(
        "endpoint,group",
        [
            ("settings.settings_kea", "kea"),
            ("settings.author_kea_config", "kea"),
            ("database.database", "databases"),
            ("database.migrate_page", "databases"),
            ("settings.settings_security", "security"),
            ("users.users", "security"),
            ("api.api_keys", "security"),
            ("api.api_docs", "security"),
            ("settings.settings_alerts", "alerts"),
            ("settings.settings_appearance", "appearance"),
            ("settings.settings_system", "system"),
            ("plugins.plugins_page", "system"),
            ("users.audit_log", "logs"),
        ],
    )
    def test_every_settings_endpoint_lands_in_its_group(self, endpoint, group):
        ctx = navmod.nav_context(endpoint, "superadmin")
        assert ctx["in_settings"] and ctx["group"]["id"] == group
        assert [g["id"] for g in ctx["strip"] if g["active"]] == [group]
        assert [i for i in ctx["top"] if i["active"]][0]["id"] == "settings"

    def test_landing_is_in_settings_with_no_active_group(self):
        ctx = navmod.nav_context("settings.settings", "admin")
        assert ctx["in_settings"] and ctx["group"] is None
        assert [g["id"] for g in ctx["strip"]] == [g["id"] for g in navmod.SETTINGS_GROUPS]

    def test_superadmin_only_subtabs_hidden_for_admin(self):
        admin = navmod.nav_context("settings.settings_security", "admin")["subtabs"]
        sup = navmod.nav_context("settings.settings_security", "superadmin")["subtabs"]
        assert "users" not in [t["id"] for t in admin["security"]]
        assert "users" in [t["id"] for t in sup["security"]]
        assert [t["id"] for t in admin["databases"]] == ["connections"]

    def test_every_group_match_target_is_a_real_endpoint(self, app):
        endpoints = {r.endpoint for r in app.url_map.iter_rules()}
        for g in navmod.SETTINGS_GROUPS:
            for m in g["match"]:
                if m.endswith("."):
                    assert any(e.startswith(m) for e in endpoints), m
                else:
                    assert m in endpoints, m


class TestOldUrlsRedirect:
    @pytest.mark.parametrize(
        "old,new",
        [
            ("/settings/infrastructure", "/settings/kea"),
            ("/settings/icons", "/settings/appearance#app-icons"),
            ("/database", "/settings/databases"),
            ("/database?tab=backups", "/settings/databases?tab=backups"),
            ("/database/migrate", "/settings/databases/migrate"),
            ("/users", "/settings/users"),
            ("/audit", "/settings/logs"),
            ("/audit?page=2", "/settings/logs?page=2"),
        ],
    )
    def test_301_to_new_home(self, logged_in_client, old, new):
        r = logged_in_client.get(old, follow_redirects=False)
        assert r.status_code == 301, (old, r.status_code)
        loc = r.headers["Location"]
        assert loc.endswith(new) or loc.split("://", 1)[-1].split("/", 1)[-1] == new.lstrip("/"), (old, loc)


class TestGroupPagesRender:
    def test_landing_lists_every_group(self, logged_in_client, mock_kea):
        r = logged_in_client.get("/settings")
        assert r.status_code == 200
        for g in navmod.SETTINGS_GROUPS:
            assert g["url"].encode() in r.data, g["id"]

    @pytest.mark.parametrize(
        "path",
        [
            "/settings/kea",
            "/settings/security",
            "/settings/appearance",
            "/settings/system",
            "/settings/alerts",
            "/settings/logs",
            "/settings/logs?tab=alerts",
            "/settings/databases",
            "/settings/databases?tab=backups",
            "/settings/users",
            "/settings/api-keys",
        ],
    )
    def test_page_renders_with_its_group_active(self, logged_in_client, mock_kea, path):
        from jen import extensions

        os.makedirs(extensions.ICONS_CUSTOM_DIR, exist_ok=True)
        r = logged_in_client.get(path)
        assert r.status_code == 200, path
        body = r.data.decode()
        assert 'class="section-tab active"' in body, path
        assert 'href="/settings" class="settings-back"' in body

    def test_top_nav_no_longer_links_database(self, logged_in_client):
        body = logged_in_client.get("/").data.decode()
        assert 'href="/database"' not in body
        assert 'href="/settings"' in body

    def test_databases_connections_tab_is_admin_visible_tools_are_not(self, client, db):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=None, role="admin", username="ia_plain_admin")
        r = c.get("/settings/databases?tab=backups")
        assert r.status_code == 200
        body = r.data.decode()
        assert "Save Jen DB" in body  # connections tab forced
        assert "Run Backup Now" not in body
        assert "superadmin access required" not in body.lower()

    def test_duplicate_cards_are_gone(self, logged_in_client, mock_kea):
        """Server Ports lived on two tabs; SSH was split across two. One
        home each now."""
        system = logged_in_client.get("/settings/system").data.decode()
        security = logged_in_client.get("/settings/security").data.decode()
        kea = logged_in_client.get("/settings/kea").data.decode()
        assert 'action="/settings/save-ports"' in system
        assert 'action="/settings/save-ports"' not in security
        assert 'action="/settings/generate-ssh-key"' in kea
        assert 'action="/settings/generate-ssh-key"' not in security
        assert 'action="/settings/generate-ssh-key"' not in system


class TestEveryFormActionStillResolves:
    """Moving cards between templates must not orphan a form. Every literal
    action="/…" in the settings-area templates has to resolve to a route
    that accepts POST (or GET, for the search forms)."""

    SETTINGS_TEMPLATES = [
        "settings_home.html",
        "settings_kea.html",
        "settings_security.html",
        "settings_appearance.html",
        "settings_system.html",
        "settings_alerts.html",
        "database.html",
        "database_import_confirm.html",
        "logs.html",
        "users.html",
        "api_keys.html",
        "plugins.html",
    ]

    def test_actions_resolve(self, app):
        adapter = app.url_map.bind("localhost")
        seen = 0
        for name in self.SETTINGS_TEMPLATES:
            src = (TEMPLATES / name).read_text(encoding="utf-8")
            for m in re.finditer(r'<form[^>]*\baction="([^"]*)"[^>]*>', src):
                action = m.group(1)
                if not action.startswith("/"):
                    continue  # url_for(...) or JS-set
                path = re.sub(r"\{\{[^}]*\}\}", "1", action).split("?", 1)[0]
                method = "GET" if 'method="GET"' in m.group(0) else "POST"
                adapter.match(path, method=method)  # raises NotFound / MethodNotAllowed
                seen += 1
        assert seen > 30, f"only {seen} literal form actions found — template scan broke?"
