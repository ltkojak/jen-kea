"""
tests/test_settings_blueprint.py
────────────────────────────────
v5.6.1 — jen/routes/settings.py (2,060 lines) was split into a package
(jen/routes/settings/{alerts,infrastructure,authoring,branding,security,
updates}.py). All modules register on the one `bp`, so every endpoint
stays `settings.<fn>` and every `url_for("settings.…")` keeps resolving.

This is the guard: the full set of registered endpoints, frozen. A
dropped, renamed, or double-registered route fails here.
"""

EXPECTED_ENDPOINTS = {
    "settings.settings",
    "settings.settings_system",
    "settings.save_audit_retention",
    "settings.save_mfa_mode",
    "settings.settings_alerts",
    "settings.save_alert_channel",
    "settings.delete_alert_channel",
    "settings.test_alert_channel",
    "settings.save_alert_template",
    "settings.reset_alert_template",
    "settings.save_alert_global",
    "settings.settings_infrastructure",
    "settings.save_infra_kea",
    "settings.save_infra_kea_db",
    "settings.save_infra_kea6",
    "settings.toggle_ipv6",
    "settings.author_kea_config",
    "settings.author_kea_config_preview",
    "settings.author_kea_config_post",
    "settings.check_kea_binaries",
    "settings.check_config_drift_route",
    "settings.install_kea_binary",
    "settings.save_infra_jen_db",
    "settings.save_infra_ssh",
    "settings.save_extra_servers",
    "settings.save_infra_ddns",
    "settings.save_ha_settings",
    "settings.restart_jen",
    "settings.save_ports",
    "settings.save_metrics_settings",
    "settings.generate_ssh_key",
    "settings.save_telegram",
    "settings.test_telegram",
    "settings.save_session_settings",
    "settings.save_rate_limit",
    "settings.clear_lockouts",
    "settings.upload_cert",
    "settings.remove_cert",
    "settings.upload_favicon",
    "settings.remove_favicon",
    "settings.settings_icons",
    "settings.upload_custom_icon",
    "settings.delete_custom_icon",
    "settings.upload_nav_logo",
    "settings.remove_nav_logo",
    "settings.save_nav_color",
    "settings.check_update",
    "settings.update_status",
    "settings.self_update",
}


def _settings_endpoints(app):
    return {r.endpoint for r in app.url_map.iter_rules() if r.endpoint.startswith("settings.")}


class TestSettingsBlueprintSplit:
    def test_every_expected_endpoint_is_registered(self, app):
        got = _settings_endpoints(app)
        assert EXPECTED_ENDPOINTS - got == set(), f"missing after split: {EXPECTED_ENDPOINTS - got}"

    def test_no_unexpected_settings_endpoint(self, app):
        got = _settings_endpoints(app)
        assert got - EXPECTED_ENDPOINTS == set(), f"unexpected endpoint(s): {got - EXPECTED_ENDPOINTS}"

    def test_helpers_still_importable_by_old_path(self):
        # test_kea6 (and its post-split successors) import these from the
        # package root; the __init__ re-exports them from .authoring.
        from jen.routes.settings import _parse_subnet_lines, _subnets_to_lines

        assert callable(_parse_subnet_lines)
        assert callable(_subnets_to_lines)

    def test_landing_route_still_redirects_to_system(self, logged_in_client):
        r = logged_in_client.get("/settings")
        assert r.status_code in (301, 302)
        assert "/settings/system" in r.headers["Location"]

    def test_a_route_from_each_split_module_responds(self, logged_in_client, mock_kea):
        # one GET route per module, smoke-level. settings_icons (the
        # branding module's only GET) lists the custom-icon dir, which a
        # bare checkout / CI workspace doesn't have — create it so this
        # exercises the route, not the environment.
        import os

        from jen import extensions

        os.makedirs(extensions.ICONS_CUSTOM_DIR, exist_ok=True)
        for path in ("/settings/system", "/settings/alerts", "/settings/infrastructure", "/settings/icons"):
            assert logged_in_client.get(path).status_code == 200
