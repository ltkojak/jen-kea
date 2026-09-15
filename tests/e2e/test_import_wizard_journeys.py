"""
tests/e2e/test_import_wizard_journeys.py
──────────────────────────────────────────
v5.39.0 (Q40) step 2/2 — the Windows DHCP and ISC dhcpd.conf import
wizards. Windows goes all the way to preview, which (unlike subnet
edit / class builder) *requires* an SSH-configured server rather than
skipping validation — jen/routes/subnets.py's import_windows_preview
redirects back to review with a flash otherwise — so this journey
fakes one server's SSH helper the same way
tests/test_win_dhcp_import_wizard.py does for its own route-level
tests, reusing the same tests/_kea_host_fakes.py double.
"""

from pathlib import Path

import pytest

from tests._kea_host_fakes import FakeHelper

pytestmark = pytest.mark.e2e

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


class TestWindowsImportWizard:
    def test_upload_review_and_preview(self, logged_in_page, base_url, monkeypatch):
        from jen import extensions
        from jen.services import kea_host

        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [{**extensions.KEA_SERVERS[0], "ssh_host": "10.0.0.5", "ssh_user": "jen", "ssh_key": "/tmp/e2e-fake-key"}],
        )
        fake = FakeHelper()
        fake.configs[(1, "dhcp4")] = {"Dhcp4": {"subnet4": []}}
        fake.responses["test-config"] = {"ok": True, "detail": "configuration seems sane"}
        monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)

        page = logged_in_page
        page.goto(f"{base_url}/subnets/import-windows")
        page.set_input_files('input[name="xml_file"]', str(FIXTURES_DIR / "windows-dhcp-export.xml"))
        page.get_by_role("button", name="Upload & Review").click()
        page.wait_for_url("**/subnets/import-windows/review", timeout=10000)

        page.get_by_role("button", name="Preview Changes").click()
        page.wait_for_url("**/subnets/import-windows/preview", timeout=10000)
        assert page.locator("pre").count() > 0


class TestIscImportWizard:
    def test_upload_and_review(self, logged_in_page, base_url):
        page = logged_in_page
        page.goto(f"{base_url}/subnets/import-isc")
        page.set_input_files('input[name="conf_file"]', str(FIXTURES_DIR / "dhcpd.conf"))
        page.get_by_role("button", name="Upload & Review").click()
        page.wait_for_url("**/subnets/import-isc/review", timeout=10000)
        assert "10.0.1.0" in page.content()
