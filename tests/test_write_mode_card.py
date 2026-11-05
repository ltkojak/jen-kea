"""
tests/test_write_mode_card.py
─────────────────────────────
Q217 (BG1, BG2, BG3, BG5 c) - the Write mode card: ONE choice (three radios, the current one checked), the steps its choice needs under it, the switch button that says what holds it, and the words
(Live API, File over SSH, Read-only) the same everywhere a mode is named. The card is rendered by the REAL builder (`infrastructure._config_cards`) through a plain Jinja environment with
`StrictUndefined` (tests/_write_mode_render.py). Pure: runs under `--noconftest`.
"""

import copy
import pathlib
import re

import pytest

from jen.services import capabilities as caps
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import write_mode as words
from tests import _write_mode_render as wm
from tests.test_kea_consent import GOOD, STATES

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The old strings (BG1): they appear nowhere under templates/, jen/, docs/ or tests/ afterward.
OLD_STRINGS = (
    "How changes reach",
    "Use the API",
    "Use the file over SSH",
    "Stop writing to it",
    "Check API configuration",
    "not a write target",
    "changes replace the file over SSH",
    "The daemon accepts its own configuration",
)


def _facts(delta=None, **extra):
    out = copy.deepcopy(GOOD)
    out.update({"at": wm.NOW, "consented_at": wm.NOW, "consents": [], "bound": "x", "tls": False})
    out.update(delta or {})
    out.update(extra)
    return out


class TestTheWordsAreTheOperators:
    @pytest.mark.parametrize("ssh", [True, False], ids=["with ssh", "no ssh"])
    @pytest.mark.parametrize("declared", ["api", "file", "off"])
    def test_one_word_on_the_radio_the_chip_the_badge_and_the_sentence(self, monkeypatch, declared, ssh):
        server = {"id": 1, "name": "kea-x", "api_url": "http://x", "config_transport": declared}
        if ssh:
            server["ssh_host"] = "10.0.0.1"
        effective = cs._transport(server, "dhcp4")  # `file` without SSH reads as off, everywhere
        cards, html = wm.render(monkeypatch, [server], {1: _facts({"agree": True})})
        word = words.MODE_WORDS[effective]
        assert wm.checked_modes(html) == [effective]
        assert f"Current: {word}" in html and f"<strong>{word} (current)</strong>" in html
        c = caps.derive(ssh=ssh, config_transport=effective, config_declared=declared, config_probe=_facts())
        assert c.config_transport == effective
        assert words.mode_word(c.config_transport) == word == cards[0]["mode_word"]
        if effective == "off" and declared == "file":
            assert "needs an SSH host" in c.transport_why()
        else:
            assert c.transport_why() == words.MODE_SENTENCES[effective]

    def test_the_three_sentences_are_the_maintainers(self):
        assert words.MODE_WORDS == {"api": "Live API", "file": "File over SSH", "off": "Read-only"}
        assert words.MODE_ORDER == ("api", "file", "off")
        assert (
            words.MODE_SENTENCES["api"]
            == "Jen sends changes to the running daemon. Live at once, no restart, no SSH needed."
        )
        assert words.MODE_SENTENCES["file"].endswith("The 5.x way.")
        assert words.MODE_SENTENCES["off"] == "Jen monitors this server and never changes its configuration."

    def test_no_old_string_survives_anywhere_in_the_tree(self):
        here = pathlib.Path(__file__).resolve()
        found = []
        for base in ("templates", "jen", "docs", "tests"):
            for path in sorted((ROOT / base).rglob("*")):
                if (
                    not path.is_file()
                    or path.suffix not in (".py", ".html", ".md", ".js", ".json", ".txt")
                    or "__pycache__" in path.parts
                    or "release-history" in path.parts
                    or path.resolve() == here
                ):
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                found += [f"{path.relative_to(ROOT).as_posix()}: {old!r}" for old in OLD_STRINGS if old in text]
        assert not found, found

    def test_the_spelling_of_the_consents_is_the_operators(self):
        assert (
            words.CONSENT_TEXTS["consent_rendering"]
            == "Kea will rewrite its config file in its own format; comments and key order are lost"
        )
        assert set(words.CONSENT_TEXTS) == set(api.CONSENTS)


class TestTheCardIsOneChoice:
    @pytest.mark.parametrize(("name", "delta", "ssh", "given", "allowed", "needs"), STATES, ids=[s[0] for s in STATES])
    def test_each_consent_table_state_through_the_real_builder(
        self, monkeypatch, name, delta, ssh, given, allowed, needs
    ):
        server = dict(wm.S_API if ssh else wm.S_API_NOSSH)
        probe = _facts(delta)
        cards, html = wm.render(monkeypatch, [server], {server["id"]: probe})
        (c,) = cards
        # exactly one checked radio, and it is the mode
        assert wm.checked_modes(html) == ["api"] and html.count('type="radio"') == 3
        # row 3 offers exactly the consents the FACTS call for, in the gate's order, and the list is the gate's own table
        shown = wm.api_consent_names(html)
        assert shown == api.consents_called_for(probe, has_ssh=ssh)
        assert shown.count("consent_rendering") == 1
        discovered, have = [], []
        for _ in (
            api.CONSENTS
        ):  # walk consent_gap one refusal at a time: the consent each refusal names is the next one the card must offer
            sentence, wants = api.consent_gap("kea", probe, have, has_ssh=ssh, strict=False)
            if not sentence or wants not in api.CONSENTS:
                break
            discovered.append(wants)
            have.append(wants)
        assert [n for n in shown if n in discovered] == discovered
        # the holding sentence is the gate's first refusal, verbatim
        gap = api.consent_gap(server["name"], probe, api.CONSENTS, has_ssh=ssh, strict=False)[0]
        if gap:
            assert c["holding"] == f"Waiting on step 2: {gap}" and c["row2"]["text"] == gap
        else:
            assert c["row2"]["state"] == "ok" and not c["holding"]

    def test_the_switch_button_says_what_holds_it(self, monkeypatch):
        cards, html = wm.render(monkeypatch, [wm.S_FILE], {}, helper={"1": {"build": 17, "version": 7}})
        (c,) = cards
        assert (
            c["row1"]["state"] == "bad"
            and "this host has build 17" in c["row1"]["text"]
            and c["row1"]["button"] == "Update helper"
        )
        assert c["holding"].startswith("Waiting on step 1:")
        assert re.search(r'data-wm-target="api"[^>]*disabled', html)
        assert "/settings/infrastructure/install-kea-helper/1" in html

    def test_no_check_yet_holds_on_step_two(self, monkeypatch):
        cards, html = wm.render(monkeypatch, [wm.S_FILE], {})
        assert (
            cards[0]["holding"] == "Waiting on step 2: Run the readiness check"
            and cards[0]["row2"]["button"] == "Run check"
        )
        assert wm.consent_names(html) == []  # the facts call for nothing until they exist

    def test_a_ready_server_holds_only_on_the_consents_the_page_script_checks(self, monkeypatch):
        cards, html = wm.render(monkeypatch, [wm.S_FILE], {1: _facts()})
        assert cards[0]["holding"] == "" and wm.consent_names(html) == ["consent_rendering"]
        assert 'name="probe_at" value="2026-11-04T10:00:00+00:00"' in html

    def test_the_current_mode_cannot_be_switched_to(self, monkeypatch):
        cards, html = wm.render(monkeypatch, [wm.S_API], {2: _facts()})
        assert re.search(r'data-wm-target="api"[^>]*disabled', html) and "This is the current mode." in html

    def test_a_server_already_in_live_api_whose_gate_is_closed_can_record_a_consent(self, monkeypatch):
        """Q217, second pass row 2: the current mode's button is "Record consent" and enabled while the gate is blocked on a fact the operator can accept."""
        cards, html = wm.render(
            monkeypatch, [wm.S_API], {2: _facts(auth="none")}, gate="this endpoint has no authentication"
        )
        button = re.search(r'<button[^>]*data-wm-target="api"[^>]*>[^<]*</button>', html).group(0)
        assert "disabled" not in button and "data-current" not in button and "Record consent" in button
        _cards, quiet = wm.render(monkeypatch, [wm.S_API], {2: _facts()})
        assert "Record consent" in quiet and re.search(r'data-wm-target="api"[^>]*disabled', quiet)

    def test_the_file_panel_offers_the_discard_box_to_a_server_that_is_not_in_file_mode(self, monkeypatch):
        """Q217, second pass row 3: `_to_file` demands `discard_file_edit` when the file differs; the box is on the panel for any server with SSH that is not already File over SSH."""
        _cards, html = wm.render(monkeypatch, [wm.S_API], {2: _facts()})
        assert 'name="discard_file_edit"' in html
        _cards, html = wm.render(monkeypatch, [wm.S_FILE], {1: _facts()})
        assert 'name="discard_file_edit"' not in html

    def test_one_switch_form_per_server_and_the_row_buttons_do_not_nest_in_it(self, monkeypatch):
        cards, html = wm.render(monkeypatch, [wm.S_FILE, wm.S_API], {1: _facts(), 2: _facts()})
        assert html.count('id="wm-form-') == 2
        for form in re.findall(r'<form id="wm-form-\d+".*?</form>', html, re.S):
            assert "<button" not in form and "<form" not in form[1:]

    def test_the_grant_buttons_are_on_the_check_row_only_when_the_write_fact_says_so(self, monkeypatch):
        denied = _facts({"write": {"may_write": False, "account": "_kea", "mode": "0640", "daemon_is_root": False}})
        _c, html = wm.render(monkeypatch, [wm.S_API], {2: denied})
        assert "allow-config-write/2" in html and "deny-config-write/2" not in html
        _c, html = wm.render(monkeypatch, [wm.S_API], {2: _facts()})
        assert "deny-config-write/2" in html and "allow-config-write/2" not in html
        _c, html = wm.render(monkeypatch, [wm.S_API], {2: denied}, helper={"2": {"build": 17, "version": 7}})
        assert "allow-config-write/2" not in html  # an old helper cannot do it: row 1 says so


class TestAnAdminAndAViewerSeeTheHeader:
    NEEDLES = (
        "unauthenticated",
        "_kea",
        "0660",
        "10.0.0.2",
        "secret-site-extra.json",
        "wm-form-",
        "data-wm-consent",
        "readiness",
        "What the check found",
    )

    def test_disabled_radios_and_no_panel_facts_consents_or_buttons(self, monkeypatch):
        probe = _facts({"auth": "none", "include": ["/etc/kea/secret-site-extra.json"]})
        cards, html = wm.render(monkeypatch, [wm.S_API], {2: probe}, superadmin=False)
        assert wm.checked_modes(html) == ["api"]
        assert html.count("disabled") >= 3 and "A superadmin changes the write mode" in html
        for needle in self.NEEDLES:
            assert needle not in html, needle
        assert "<form" not in html and "<button" not in html and "data-mode-panel" not in html
        assert set(cards[0]) <= {
            "id",
            "name",
            "transport",
            "declared",
            "mode_word",
            "blocked",
            "why",
            "ssh",
            "full",
            "modes",
        }


class TestWhatTheFactsSayAboutTheirCause:
    """Q217 BG3 a: an old helper is not "no SSH"."""

    def test_an_old_helper_is_named_not_ssh(self, monkeypatch):
        detail = "the Kea host helper on this host is older than build 19 - press Update helper"
        probe = _facts({"include": None, "agree": None, "write": {"unavailable": detail}}, include_unavailable=detail)
        cards, html = wm.render(monkeypatch, [wm.S_API], {2: probe}, helper={"2": {"build": 17, "version": 7}})
        assert f"not known — {detail}" in html and "cannot be known without SSH" not in html

    def test_no_ssh_is_named_no_ssh(self, monkeypatch):
        probe = _facts({"include": None, "agree": None, "write": "unknown until the first change"})
        cards, html = wm.render(monkeypatch, [wm.S_API_NOSSH], {3: probe}, helper={})
        assert (
            "cannot be known without SSH" in html
            and "not known —" not in html.split("Config file uses include")[1].split("</tr>")[0]
        )

    def test_where_the_file_and_the_daemon_differ_is_printed(self, monkeypatch):
        probe = _facts({"agree": False}, agree_at="at Dhcp4.valid-lifetime: the file says 1, the daemon 2")
        _c, html = wm.render(monkeypatch, [wm.S_API], {2: probe})
        assert "no — at Dhcp4.valid-lifetime: the file says 1, the daemon 2" in html
