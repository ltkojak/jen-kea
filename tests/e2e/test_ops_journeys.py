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
        # (Q223, AH15) the download is a POST from the page's own form (CSRF token and all): a GET answers 405 and builds nothing
        page = logged_in_page
        assert page.request.get(f"{base_url}/settings/system/support-bundle").status == 405
        page.goto(f"{base_url}/settings/system")
        button = page.locator('form[action="/settings/system/support-bundle"] button[type=submit]')
        with page.expect_download(timeout=30000) as download_info:
            button.click()
        assert download_info.value.suggested_filename.startswith("jen-support-")
        assert download_info.value.suggested_filename.endswith(".zip")


class TestHealthCenterRefresh:
    def test_refresh_button_polls_the_partial(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/health-center")
        with page.expect_response("**/health-center/data?partial=1&refresh=1", timeout=10000):
            page.get_by_role("button", name="Refresh").click()


class TestTheBulkCountIsHonest:
    """Q205 (AU4): a lease with a reservation shows a disabled box; select-all and the count cover the boxes that can be ticked."""

    def test_select_all_counts_the_releasable_rows_only(self, logged_in_page, base_url):
        import pymysql
        import pymysql.cursors
        from playwright.sync_api import expect

        from tests.conftest import TEST_DB

        conn = pymysql.connect(**TEST_DB, cursorclass=pymysql.cursors.DictCursor)
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN ('AABBCCDDEE71','AABBCCDDEE72')")
                cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCCDDEE71'")
                for ip, mac, host in (
                    ("10.99.0.71", "AABBCCDDEE71", "e2e-reserved"),
                    ("10.99.0.72", "AABBCCDDEE72", "e2e-plain"),
                ):
                    cur.execute(
                        "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) "
                        "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, %s, 0)",
                        (ip, mac, host),
                    )
                cur.execute(
                    "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                    "VALUES (UNHEX('AABBCCDDEE71'), 0, 1, INET_ATON('10.99.0.71'), 'e2e-reserved')"
                )
            conn.commit()
        finally:
            conn.close()
        page = logged_in_page
        page.goto(f"{base_url}/leases")
        page.wait_for_selector("text=e2e-plain")
        reserved_row = page.locator("tr", has_text="e2e-reserved").first
        expect(reserved_row.locator(".row-checkbox")).to_be_disabled()
        enabled = page.locator(".row-checkbox:not([disabled])").count()
        assert enabled >= 1
        page.check("#selectAll")
        expect(page.locator("#selectedCount")).to_have_text(f"{enabled} selected")
        assert page.locator(".row-checkbox:checked").count() == enabled, "the disabled box is never ticked"


class TestTheAuthoredFormSurvivesTheStepUp:
    """Q205 (AU11 b; Opus's M20): the Author page keeps its form as a draft in the tab, so a confirmation that aged out does not cost the operator the form."""

    def test_the_form_comes_back_filled_after_the_password_confirmation(self, logged_in_page, base_url, monkeypatch):
        from playwright.sync_api import expect

        from jen import extensions
        from jen.routes.settings import authoring
        from jen.services import access
        from tests.e2e.conftest import ADMIN_PASSWORD

        server = {**extensions.KEA_SERVERS[0], "id": 1, "name": "kea-a", "ssh_host": "127.0.0.1"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        detected = {
            "found": False,
            "interfaces": [],
            "lease_db_type": "",
            "lease_db_host": "",
            "lease_db_name": "",
            "hooks": [],
        }
        monkeypatch.setattr(authoring, "_author_kea_detect", lambda service: (server, detected, ["eth0"], None, []))
        state = {"stale": False}
        real = access.auth_is_recent
        monkeypatch.setattr(access, "auth_is_recent", lambda minutes=10: False if state["stale"] else real(minutes))

        page = logged_in_page
        page.goto(f"{base_url}/settings/infrastructure/author-kea/dhcp4")
        page.fill("#f-interfaces", "eth7")
        # the confirmation ages out; the apply is refused for it and the person is sent to confirm
        state["stale"] = True
        page.evaluate("() => submitForm()")
        page.wait_for_url("**/auth/reauth**", timeout=10000)
        state["stale"] = False
        page.fill("#f-password", ADMIN_PASSWORD)
        page.click('form[action$="/auth/reauth"] button[type=submit]')
        page.wait_for_url("**/settings/infrastructure/author-kea/dhcp4", timeout=10000)
        expect(page.locator("#f-interfaces")).to_have_value("eth7")
        expect(
            page.locator("[data-author-draft-note]")
        ).to_be_visible()  # Q210: the note carries no id (a .form-hint with an id must be named by a control; this one describes none)
        # the explicit discard drops the draft
        page.click("#discard-draft")
        page.wait_for_load_state("networkidle")
        assert page.input_value("#f-interfaces") != "eth7"
