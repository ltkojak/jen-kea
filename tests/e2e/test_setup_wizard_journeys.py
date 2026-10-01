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

import pytest

from tests._kea_host_fakes import FakeHelper
from tests.conftest import TEST_DB

pytestmark = pytest.mark.e2e


class TestSetupWizardJourney:
    def test_all_six_steps(self, logged_in_page, base_url, monkeypatch):
        from jen import extensions
        from jen.services import kea_host

        fake = FakeHelper()
        fake.helper_version = 7  # jen-kea-helper's own HELPER_VERSION
        fake.configs[(1, "dhcp4")] = {"Dhcp4": {"subnet4": []}}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)

        page = logged_in_page

        # Step 1: connect — the same Kea API and jen_test (standing in for
        # Kea's own DB, same as every other test in this suite) live_server
        # already proved reachable at session setup.
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
        # reports real subnets, so this is the "Use these subnets" branch.
        page.get_by_role("button", name="Use these subnets").click()
        page.wait_for_url("**/setup/helper", timeout=10000)

        # Step 3: the Kea host helper. The target never needs to be a real,
        # reachable host — helper_call is mocked above, so nothing here
        # actually opens a socket.
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

        # Step 5: recovery point — confirm without actually downloading a
        # bundle (that form posts to the existing, already-tested
        # /settings/databases/recovery-bundle route unchanged).
        page.get_by_role("button", name="I've saved it — continue").click()
        page.wait_for_url("**/setup/investigate", timeout=10000)

        # Step 6: investigate — whichever branch this session's shared
        # lease state puts us in, the primary action marks the step done.
        if page.get_by_role("button", name="Finish setup").count():
            page.get_by_role("button", name="Finish setup").click()
            page.wait_for_url("**/setup/investigate", timeout=10000)
            assert "First hour complete" in page.content()
        else:
            page.get_by_role("button", name="Explain").first.click()
            page.wait_for_url("**/tools/explain**", timeout=10000)
