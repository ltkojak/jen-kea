"""
tests/e2e/test_q249_a.py
────────────────────────
Q249 - the Kea logging card, driven in a real browser: a superadmin opens Settings → Kea, reads where the running daemon writes its log, changes it to a file Jen can read,
confirms, and the card and the message say what Kea now does; then back to the system journal.

The daemon is a STATEFUL fake Kea (`config-set` / a restart really move what `config-get` answers, with Kea's defaults written out); the Kea host behind SSH is
`tests/_q249_a_world.py::KeaHost`, standing in for `kea_host.helper_call` in this same process (the Flask app and the browser's server are one process): it holds the daemon's
file, restarts the daemon from it, and its log file grows only when the running logger names it - so the proof the card waits for is observed, not assumed.
"""

import pytest

from tests._q249_a_world import KeaHost, dhcp4, kea_writes_defaults, packaged_logger
from tests.e2e._fake_kea_server import StatefulKeaServer

pytestmark = pytest.mark.e2e

LOG = "/var/log/kea/kea-dhcp4.log"


@pytest.fixture
def logging_primary(monkeypatch, live_server):
    """The primary server (id 1) on File over SSH, its daemon a stateful fake that logs to stdout as the package ships it, and its host answering the helper's ops."""
    from jen.config import app_config
    from jen.models.db import jen_db
    from jen.services import kea_host

    daemon = StatefulKeaServer(dhcp4([packaged_logger()]))
    daemon.expand = kea_writes_defaults
    daemon.running = kea_writes_defaults(daemon.running)
    daemon.start()
    host = KeaHost(daemon)
    parser = app_config._read_parser()
    before = {
        ("kea", "api_url"): parser.get("kea", "api_url", fallback=""),
        ("kea", "config_transport"): parser.get("kea", "config_transport", fallback=""),
        ("kea_ssh", "host"): parser.get("kea_ssh", "host", fallback=""),
        ("kea_ssh", "user"): parser.get("kea_ssh", "user", fallback=""),
    }
    with jen_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(id), 0) AS top FROM kea_config_revisions")
        row = cur.fetchone()
        top = row["top"] if isinstance(row, dict) else row[0]
    app_config.write_values(
        [
            ("kea", "api_url", daemon.url),
            ("kea", "config_transport", "file"),
            ("kea_ssh", "host", "10.9.9.9"),
            ("kea_ssh", "user", "jen"),
        ],
        typed={"kea", "kea_ssh"},
    )
    monkeypatch.setattr(kea_host, "helper_call", host.helper_call)
    yield daemon, host
    app_config.write_values([(s, k, v) for (s, k), v in before.items()], typed={"kea", "kea_ssh"})
    with jen_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM kea_config_revisions WHERE id > %s AND server_id = 1", (top,))
    daemon.stop()


def _save(page, card, choice):
    card.locator(f'input[name="output"][value="{choice}"]').check()
    card.get_by_role("button", name="Save Kea Logging").click()
    with page.expect_navigation():
        page.get_by_role("button", name="Change Logging").click()
    return page.locator("#kea-logging-1")


def test_a_superadmin_moves_keas_log_to_a_file_and_back_to_the_journal(logged_in_page, base_url, logging_primary):
    daemon, host = logging_primary
    page = logged_in_page
    page.goto(f"{base_url}/settings/kea")
    assert page.locator('.page-jump a[href="#kea-logging"]').inner_text() == "Kea logging"
    card = page.locator("#kea-logging-1")
    name = card.locator(".wm-head strong").inner_text()

    # what the running daemon says: the journal, and Jen reads the Kea Log Path setting's file (which Kea does not write)
    assert card.locator("[data-kl-writes]").inner_text() == "the system journal (stdout)"
    assert "from the Kea Log Path setting" in card.locator("[data-kl-reads]").inner_text()
    assert card.locator("[data-kl-severity]").inner_text() == "INFO"
    assert card.locator('input[name="output"]:checked').get_attribute("value") == "journal"
    assert card.locator('input[name="log_file"]').input_value() == LOG

    # a file Jen can read: the dialog asks, Kea is changed, the file is seen to grow, and the card reads the daemon again
    card.locator('input[name="output"][value="file"]').check()
    card.get_by_role("button", name="Save Kea Logging").click()
    assert (
        page.locator("#jen-confirm-message").inner_text()
        == f"Change where {name} writes its log? Kea is restarted to apply it."
    )
    with page.expect_navigation():
        page.get_by_role("button", name="Change Logging").click()
    card = page.locator("#kea-logging-1")
    assert f"Kea is writing to {LOG} on {name}." in page.locator("body").inner_text()
    assert card.locator("[data-kl-writes]").inner_text() == f"the file {LOG}"
    reads = card.locator("[data-kl-reads]").inner_text()
    assert LOG in reads and "from Kea's logger" in reads
    assert card.locator('input[name="output"]:checked').get_attribute("value") == "file"
    assert [o["output"] for o in daemon.running["loggers"][0]["output-options"]] == [LOG]
    assert "tail-log" in host.ops() and "apply-config" in host.ops()

    # the same choice again changes nothing
    card = _save(page, card, "file")
    assert "Nothing to change." in page.locator("body").inner_text()

    # back to Kea's default
    card = _save(page, card, "journal")
    assert card.locator("[data-kl-writes]").inner_text() == "the system journal (stdout)"
    assert card.locator('input[name="output"]:checked').get_attribute("value") == "journal"
    assert daemon.file["loggers"][0]["output-options"] == [{"output": "stdout", "pattern": "%-5p %m\n"}]


def test_a_file_kea_does_not_write_is_put_back_and_the_card_says_so(logged_in_page, base_url, logging_primary):
    daemon, host = logging_primary
    host.writes_log = False  # Kea accepts the logger and writes nothing (a file its account may not write)
    page = logged_in_page
    page.goto(f"{base_url}/settings/kea")
    card = page.locator("#kea-logging-1")
    name = card.locator(".wm-head strong").inner_text()
    card = _save(page, card, "both")
    said = page.locator("body").inner_text()
    assert (
        f"Kea accepted the change on {name} but Jen could not prove that it writes to {LOG}, so the previous logging was put back."
        in said
    )
    assert card.locator("[data-kl-writes]").inner_text() == "the system journal (stdout)"
    assert card.locator('input[name="output"]:checked').get_attribute("value") == "journal"
