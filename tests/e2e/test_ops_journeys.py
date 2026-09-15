"""
tests/e2e/test_ops_journeys.py
─────────────────────────────────
v5.39.0 (Q40) step 2/2 — HA planned maintenance, API key creation
("shown exactly once"), the support bundle download, and the Health
Center's manual refresh button.
"""

import pytest

pytestmark = pytest.mark.e2e


def _fake_kea_command(command, service="dhcp4", arguments=None, server=None, timeout=10):
    """A two-server HA pair, distinguished by `server["id"]` — the real
    fake_kea fixture answers every server identically (one shared HTTP
    double), which can't tell two Jen-configured servers apart the way
    resolve_partner() needs, so this journey fakes kea_command directly
    instead."""
    sid = (server or {}).get("id")
    this_name = "kea-a" if sid == 1 else "kea-b"
    peer_name = "kea-b" if sid == 1 else "kea-a"
    role = "primary" if sid == 1 else "standby"
    peer_role = "standby" if sid == 1 else "primary"

    if command == "config-get":
        return {
            "result": 0,
            "arguments": {
                "Dhcp4": {
                    "hooks-libraries": [
                        {
                            "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
                            "parameters": {
                                "high-availability": [
                                    {
                                        "this-server-name": this_name,
                                        "mode": "hot-standby",
                                        "peers": [
                                            {"name": this_name, "role": role},
                                            {"name": peer_name, "role": peer_role},
                                        ],
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
        }
    if command == "status-get":
        return {
            "result": 0,
            "arguments": {
                "high-availability": [
                    {
                        "ha-servers": {
                            "local": {"role": role, "state": "hot-standby", "scopes": []},
                            "remote": {"role": peer_role, "last-state": "hot-standby", "last-scopes": []},
                        }
                    }
                ]
            },
        }
    if command == "version-get":
        return {"result": 0, "text": "2.6.1", "arguments": {"extended": "2.6.1"}}
    return {"result": 0, "arguments": {}}


class TestHaPlannedMaintenance:
    def test_chooser_begin_and_stepper_polls(self, logged_in_page, base_url, monkeypatch):
        from jen import extensions
        from jen.config import app_config
        from jen.services import kea as kea_svc

        # ha_mode first (write_value's default reload=True re-derives
        # KEA_SERVERS from the on-disk config too, so it has to happen
        # BEFORE the two-server override below, not after).
        app_config.write_value("kea", "ha_mode", "hot-standby")
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [
                {**extensions.KEA_SERVERS[0], "id": 1, "name": "kea-a"},
                {**extensions.KEA_SERVERS[0], "id": 2, "name": "kea-b"},
            ],
        )
        monkeypatch.setattr(kea_svc, "kea_command", _fake_kea_command)

        page = logged_in_page
        page.goto(f"{base_url}/servers/ha/maintenance")
        page.wait_for_selector('select[name="down"]', timeout=10000)
        page.get_by_role("button", name="Run preflight").click()
        page.wait_for_selector("#maint-status", timeout=10000)

        # The stepper polls #maint-status every 5s on its own
        # (hx-trigger="every 5s") — no click needed, just wait for one
        # such request to actually happen. expect_response() is the
        # real Playwright API (there is no bare wait_for_response()); it
        # still needs something happening inside the block, so that's a
        # plain timed wait rather than a click.
        with page.expect_response("**/servers/ha/maintenance/status?partial=1", timeout=10000):
            page.wait_for_timeout(6000)


class TestApiKeyCreation:
    def test_key_shown_once_then_gone_on_reload(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/settings/api-keys")
        page.fill('input[name="name"]', "e2e-test-key")
        page.get_by_role("button", name="Generate Key").click()
        page.wait_for_url("**/settings/api-keys", timeout=10000)

        key_text = page.locator("#newKeyVal").text_content().strip()
        assert key_text.startswith("jen_")

        page.reload()
        assert page.locator("#newKeyVal").count() == 0


class TestSupportBundleDownload:
    def test_download_returns_a_zip(self, logged_in_page, base_url):
        resp = logged_in_page.request.get(f"{base_url}/settings/system/support-bundle")
        assert resp.status == 200
        assert resp.headers.get("content-type", "").startswith("application/zip")
        assert "attachment" in resp.headers.get("content-disposition", "")


class TestHealthCenterRefresh:
    def test_refresh_button_polls_the_partial(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/health-center")
        with page.expect_response("**/health-center/data?partial=1", timeout=10000):
            page.get_by_role("button", name="Refresh").click()
