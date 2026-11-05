"""
tests/e2e/test_write_mode_journeys.py
─────────────────────────────────────
Q217 (BG5 e) - the Write mode card, driven in a real browser: a superadmin opens Settings → Kea on a File over SSH server, selects Live API, reads the helper row, runs the readiness check,
accepts the file rewrite, switches with a recent confirmation, and the chip, the Servers page badge and the card read "Live API"; then back to File over SSH. The daemon is a STATEFUL fake Kea
(`expand` set, as the real one writes its defaults out); the host's helper facts are stood in the way the unit suite stands them in (`config_write_check`, `read_config_versioned`, and the helper's
recorded build), in this same process - the Flask app and the browser's server are one process.
"""

import copy

import pytest

from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer

pytestmark = pytest.mark.e2e


def _expands(section):
    out = copy.deepcopy(section)
    for subnet in out.get("subnet4", []):
        subnet.setdefault("t1-percent", 0.5)
        subnet.setdefault("reservations", [])
    out.setdefault("echo-client-id", True)
    return out


@pytest.fixture
def file_mode_primary(monkeypatch, live_server):
    """The primary server (id 1) on File over SSH, its daemon a stateful fake and its host's helper at build 20."""
    from jen.config import app_config
    from jen.services import kea_host

    daemon = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
    daemon.expand = _expands
    daemon.start()
    parser = app_config._read_parser()
    before = {
        ("kea", "api_url"): parser.get("kea", "api_url", fallback=""),
        ("kea", "config_transport"): parser.get("kea", "config_transport", fallback=""),
        ("kea_ssh", "host"): parser.get("kea_ssh", "host", fallback=""),
        ("kea_ssh", "user"): parser.get("kea_ssh", "user", fallback=""),
    }
    app_config.write_values(
        [
            ("kea", "api_url", daemon.url),
            ("kea", "config_transport", "file"),
            ("kea_ssh", "host", "10.9.9.9"),
            ("kea_ssh", "user", "jen"),
        ],
        typed={"kea", "kea_ssh"},
    )
    monkeypatch.setattr(
        kea_host,
        "config_write_check",
        lambda server, service: {
            "ok": True,
            "may_write": True,
            "includes": [],
            "mode": "0660",
            "account": {"name": "_kea"},
        },
    )
    monkeypatch.setattr(
        kea_host, "read_config_versioned", lambda *a, **k: ({"Dhcp4": copy.deepcopy(daemon.running)}, "r" * 64)
    )
    kea_host.record_helper_status(1, 7, build=20)
    yield daemon
    app_config.write_values([(s, k, v) for (s, k), v in before.items()], typed={"kea", "kea_ssh"})
    daemon.stop()


def test_a_superadmin_moves_a_server_from_the_file_to_live_api_and_back(logged_in_page, base_url, file_mode_primary):
    page = logged_in_page
    page.goto(f"{base_url}/settings/kea")
    card = page.locator("#config-card-1")
    assert "Current: File over SSH" in card.locator("[data-wm-chip]").inner_text()
    assert card.locator('input[name="transport"]:checked').get_attribute("value") == "file"

    # Live API: step 1 is green (the helper is at build 20), step 2 has not run
    card.locator('input[name="transport"][value="api"]').check()
    assert (
        card.locator('[data-mode-panel="api"]').is_visible()
        and not card.locator('[data-mode-panel="file"]').is_visible()
    )
    assert card.locator('[data-wm-row="1"]').get_attribute("data-state") == "ok"
    assert card.locator('[data-wm-row="2"]').get_attribute("data-state") == "idle"
    switch = card.locator('[data-wm-switch="1"][data-wm-target="api"]')
    assert switch.is_disabled() and "Waiting on step 2" in card.locator('[data-wm-holding="1"]').inner_text()

    # Run check: the page reloads with the facts; the check passes
    card.locator('[data-wm-check="1"]').click()
    page.wait_for_load_state("load")
    card = page.locator("#config-card-1")
    card.locator('input[name="transport"][value="api"]').check()
    assert card.locator('[data-wm-row="2"]').get_attribute("data-state") == "ok"

    # step 3: nothing is accepted yet, so the button waits; ticking the one box the facts call for enables it
    assert switch.is_disabled() and "Waiting on step 3" in card.locator('[data-wm-holding="1"]').inner_text()
    card.locator('input[name="consent_rendering"]').check()
    assert switch.is_enabled()
    switch.click()
    page.get_by_role("button", name="Confirm").click()
    page.wait_for_load_state("load")

    # the chip, the card and the Servers page agree
    assert "Current: Live API" in page.locator("#config-card-1 [data-wm-chip]").inner_text()
    page.goto(f"{base_url}/servers")
    assert "Live API" in page.locator('[data-transport="api"]').first.inner_text()

    # and back: File over SSH needs no facts
    page.goto(f"{base_url}/settings/kea")
    card = page.locator("#config-card-1")
    card.locator('input[name="transport"][value="file"]').check()
    card.locator('[data-wm-switch="1"][data-wm-target="file"]').click()
    page.get_by_role("button", name="Confirm").click()
    page.wait_for_load_state("load")
    assert "Current: File over SSH" in page.locator("#config-card-1 [data-wm-chip]").inner_text()


def test_a_box_in_the_hidden_panel_is_not_a_consent(logged_in_page, base_url, file_mode_primary):
    """Q218 BH3 b (AC4): the three panels share one form, and a box in a hidden panel is still a box that submits. Tick the File panel's discard box, change the mind to Live API, switch: the box is disabled
    with its panel, the request does not carry it, and the audit row shows only the consent the facts called for."""
    from jen.config import app_config
    from jen.models.db import jen_db

    app_config.write_values(
        [("kea", "config_transport", "off")], typed={"kea"}
    )  # Read-only: the File panel offers the discard box
    page = logged_in_page
    page.goto(f"{base_url}/settings/kea")
    card = page.locator("#config-card-1")
    card.locator('input[name="transport"][value="api"]').check()
    card.locator('[data-wm-check="1"]').click()
    page.wait_for_load_state("load")
    card = page.locator("#config-card-1")

    card.locator('input[name="transport"][value="file"]').check()
    box = card.locator('[data-mode-panel="file"] input[name="discard_file_edit"]')
    box.check()
    assert box.is_enabled()
    card.locator('input[name="transport"][value="api"]').check()
    assert box.is_disabled(), "the box went with its panel"

    card.locator('input[name="consent_rendering"]').check()
    card.locator('[data-wm-switch="1"][data-wm-target="api"]').click()
    page.get_by_role("button", name="Confirm").click()
    page.wait_for_load_state("load")
    assert "Current: Live API" in page.locator("#config-card-1 [data-wm-chip]").inner_text()
    with jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT details FROM audit_log WHERE action='KEA_TRANSPORT_SWITCHED' ORDER BY id DESC LIMIT 1")
        details = cur.fetchone()["details"]
    assert "consents: consent_rendering" in details and "discard_file_edit" not in details, details
