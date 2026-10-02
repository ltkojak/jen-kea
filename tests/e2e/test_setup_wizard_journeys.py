"""
tests/e2e/test_setup_wizard_journeys.py
─────────────────────────────────────────
v5.67.0 (Q115 step 3) — the six-step guided first-hour wizard, walked
through a real browser against the real live_server + fake Kea Control
Agent this whole e2e suite already shares (tests/e2e/conftest.py). Every
/setup/<step> route is independently reachable regardless of which step
is "current", so this journey drives them directly rather than depending
on the one-time entry redirect (already unit-tested in
tests/test_setup_wizard.py::TestEntryRedirectOnDashboard — live_server
connects Kea at session setup, so that redirect's trigger condition
never arises naturally in this shared session).

The Kea host helper step uses the same FakeHelper double
test_import_wizard_journeys.py uses, set to report the real shipped
helper's own version (jen-kea-helper's HELPER_VERSION) so
install_helper()'s own "already up to date" short-circuit returns
success without ever opening a real SSH connection. "Test SSH" itself
dials a real host and is left to the unit suite
(tests/test_setup_wizard.py::TestTestSsh) rather than exercised here.
"""

import pathlib

import pytest

from tests._kea_host_fakes import FakeHelper
from tests.conftest import TEST_DB

pytestmark = pytest.mark.e2e


class TestSetupWizardJourney:
    def test_all_six_steps(self, logged_in_page, base_url, monkeypatch):
        from jen import extensions
        from jen.config import app_config
        from jen.services import kea_host

        # v5.67.0 (Q115 step 3 fixup 2) — every step here writes something
        # real and persistent (connect, subnets, the SSH target) through
        # the exact same app_config choke point a real operator's save
        # would use — this is session-scoped live_server, shared with
        # every other e2e journey, so a real write here outlives this
        # test. CI caught it: saving an SSH target made a LATER, unrelated
        # journey's "with no SSH configured" assumption false. A snapshot
        # of the whole config file, restored byte-for-byte afterward, is
        # simpler and more certainly complete than re-deriving every field
        # this wizard (or a future step added to it) might touch.
        config_backup = pathlib.Path(extensions.CONFIG_FILE).read_text()

        fake = FakeHelper()
        fake.helper_version = 7  # jen-kea-helper's own HELPER_VERSION
        fake.configs[(1, "dhcp4")] = {"Dhcp4": {"subnet4": []}}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)

        page = logged_in_page

        try:
            # Step 1: connect — the same Kea API and jen_test (standing in
            # for Kea's own DB, same as every other test in this suite)
            # live_server already proved reachable at session setup.
            page.goto(f"{base_url}/setup/connect")
            page.fill('input[name="api_url"]', extensions.KEA_API_URL)
            page.fill('input[name="kea_db_host"]', TEST_DB["host"])
            page.fill('input[name="kea_db_user"]', TEST_DB["user"])
            page.fill('input[name="kea_db_pass"]', TEST_DB["password"])
            page.fill('input[name="kea_db_name"]', TEST_DB["database"])
            page.get_by_role("button", name="Test & Connect").click()
            page.wait_for_url("**/setup/found", timeout=10000)

            # Step 2: what Jen found — the fake Kea's default config-get
            # response (tests/e2e/_fake_kea_server.py's TWO_SUBNET_DHCP4)
            # reports real subnets, so this is the "Use these subnets"
            # branch.
            page.get_by_role("button", name="Use these subnets").click()
            page.wait_for_url("**/setup/helper", timeout=10000)

            # Step 3: the Kea host helper. The target never needs to be a
            # real, reachable host — helper_call is mocked above, so
            # nothing here actually opens a socket.
            page.fill('input[name="ssh_host"]', "10.0.0.5")
            page.fill('input[name="ssh_user"]', "jen")
            page.get_by_role("button", name="Save target").click()
            page.wait_for_url("**/setup/helper", timeout=10000)
            page.get_by_role("button", name="Install the helper").click()
            page.wait_for_url("**/setup/baseline", timeout=10000)

            # Step 4: baseline — kea_host.read_config() reads through the
            # same mocked helper_call, from fake.configs set up above.
            page.get_by_role("button", name="Capture baseline").click()
            page.wait_for_url("**/setup/recovery", timeout=10000)

            # Step 5: recovery point — v5.67.0-beta.8 (Q120, item i): the bundle is downloaded for REAL.
            # It used to be skipped here ("I will do this later"), which is how the page's real defect
            # went unseen: a bundle download is a form POST whose response is a FILE, so the page never
            # reloaded and "Continue" (rendered only for a fresh bundle) never appeared. The page now
            # polls /setup/recovery/status after the download starts and swaps Continue in.
            assert page.get_by_role("button", name="I will do this later").is_visible()
            assert not page.get_by_role("button", name="Continue").is_visible()
            passphrase = "correct horse battery staple"
            page.fill('input[name="passphrase"]', passphrase)
            page.fill('input[name="passphrase_confirm"]', passphrase)
            with page.expect_download(timeout=30000) as download_info:
                page.get_by_role("button", name="Download recovery bundle").click()
            assert download_info.value.suggested_filename.startswith("jen-recovery-")
            page.get_by_role("button", name="Continue").wait_for(state="visible", timeout=20000)
            assert not page.get_by_role("button", name="I will do this later").is_visible()
            page.get_by_role("button", name="Continue").click()
            page.wait_for_url("**/setup/investigate", timeout=10000)

            # Step 6: investigate — whichever branch this session's shared
            # lease state puts us in, the primary action marks the step
            # done.
            if page.get_by_role("button", name="Finish setup").count():
                page.get_by_role("button", name="Finish setup").click()
                page.wait_for_url("**/setup/investigate", timeout=10000)
                assert "First hour complete" in page.content()
            else:
                # v5.67.0-beta.5 (Q117 item k) — this now opens the full
                # six-tab Investigation page, not the narrow Explain tab.
                page.get_by_role("button", name="Investigate").first.click()
                page.wait_for_url("**/client**", timeout=10000)
        finally:
            pathlib.Path(extensions.CONFIG_FILE).write_text(config_backup)
            app_config.reload()
            # The wizard's own step state lives in the settings key/value
            # table, not jen.config — clear it too, and the 30-second
            # settings cache (jen/models/user.py) that would otherwise
            # keep serving a later test a stale "every step resolved"
            # answer for up to 30 more seconds.
            from jen.models import user as jen_user
            from jen.models.db import jen_db

            with jen_db() as db, db.cursor() as cur:
                cur.execute(
                    "DELETE FROM settings WHERE setting_key IN "
                    "('setup_wizard_state', 'setup_wizard_redirect_shown', 'setup_wizard_started_at', "
                    "'setup_wizard_completed_at', 'last_recovery_bundle_at', 'last_recovery_bundle_size', "
                    "'last_recovery_bundle_excluded_audit')"
                )
            jen_user._settings_cache_ts = 0
