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


def _fleet(first, size):
    """A fleet of `size` servers whose first is `first` and whose others are Read-only (Q218 BH4 b, AC21: a page block is tested at the fleet size the product is for - one AND three)."""
    return [first] + [
        {"id": 10 + i, "name": f"kea-fleet-{i}", "api_url": f"http://fleet{i}/", "config_transport": "off"}
        for i in range(size - 1)
    ]


class TestTheWordsAreTheOperators:
    @pytest.mark.parametrize("fleet", [1, 3], ids=["one server", "three servers"])
    @pytest.mark.parametrize("ssh", [True, False], ids=["with ssh", "no ssh"])
    @pytest.mark.parametrize("declared", ["api", "file", "off"])
    def test_one_word_on_the_radio_the_chip_the_badge_and_the_sentence(self, monkeypatch, declared, ssh, fleet):
        server = {"id": 1, "name": "kea-x", "api_url": "http://x", "config_transport": declared}
        if ssh:
            server["ssh_host"] = "10.0.0.1"
        effective = cs._transport(server, "dhcp4")  # `file` without SSH reads as off, everywhere
        cards, html = wm.render(monkeypatch, _fleet(server, fleet), {1: _facts({"agree": True})})
        word = words.MODE_WORDS[effective]
        assert wm.checked_modes(html) == [effective] + ["off"] * (fleet - 1)
        assert f"Current: {word}" in html and f"<strong>{word} (current)</strong>" in html
        assert len(cards) == fleet and html.count("Current: ") == fleet  # every server's card names its mode
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

    def test_the_pending_alert_prints_what_the_settlement_waits_on(self, monkeypatch):
        """Q218 BH1 e: the alert names what *Settle it now* would stop on, above the button, and the confirm text says the file is compared too."""
        note = "a change of 2026-11-05 07:00:00 is live and its file write waits: the file on kea-b carries an edit the daemon has not loaded (at Dhcp4.user-context) - restart Kea there first, or discard it from the server's Write mode card"
        _cards, html = wm.render(monkeypatch, [wm.S_API], {2: _facts()}, pending=True, pending_note=note)
        alert = html[html.index("data-transport-pending>") : html.index("Settle it now</button>")]
        assert "its file write waits" in alert and "Dhcp4.user-context" in alert and "Settle it now" not in alert[:-5]
        assert "with the file on the host" in alert and "a file edit the daemon never loaded stops it" in alert
        _cards, quiet = wm.render(monkeypatch, [wm.S_API], {2: _facts()})
        assert "data-transport-pending>" not in quiet
        _cards, down = wm.render(
            monkeypatch, [wm.S_API], {2: _facts()}, pending=True, pending_note=OSError("no answer")
        )
        assert (
            "data-transport-pending>" in down and "data-transport-pending-note" not in down
        )  # the alert stands without the note

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

    # the nine states the gate can refuse in (Opus's V2: pass/lineage/verify217/V2_roles.py), each with the consents on record that leave THAT one uncovered
    GATE_STATES = [
        (
            "the daemon did not answer",
            {"config_api": False, "read_error": "connection refused to 10.0.0.2:8000"},
            api.CONSENTS,
        ),
        (
            "config-test refused the running config",
            {"test_ok": False, "test_detail": "bad subnet 10.0.0.0/24"},
            api.CONSENTS,
        ),
        ("the file carries an include", {"include": ["/etc/kea/extra.conf"]}, api.CONSENTS),
        (
            "the host's facts could not be read",
            {"agree": None, "include": None, "write": {"unavailable": "helper-too-old"}},
            api.CONSENTS,
        ),
        (
            "the file and the daemon differ",
            {"agree": False, "agree_at": "at Dhcp4.subnet4[0].valid-lifetime: the file says 3600, the daemon 7200"},
            ["consent_rendering"],
        ),
        (
            "the daemon may not write its file",
            {"write": {"may_write": False, "mode": "0640", "account": "_kea", "daemon_is_root": False}},
            ["consent_rendering", "discard_file_edit"],
        ),
        ("the file rewrite is not accepted yet", {}, []),
        ("the endpoint has no authentication", {"auth": "none"}, ["consent_rendering"]),
        ("nothing stands in the way", {}, api.CONSENTS),
    ]
    HOST_FACTS = (
        "_kea",
        "0640",
        "0660",
        "no authentication",
        "unauthenticated",
        "10.0.0.2",
        "/etc/kea/extra.conf",
        "Dhcp4.subnet4[0]",
        "helper-too-old",
        "bad subnet",
        "build 20",
    )

    @pytest.mark.parametrize("fleet", [1, 3], ids=["one server", "three servers"])
    def test_no_gate_fact_reaches_an_admin_in_any_state(self, monkeypatch, fleet):
        """Q218 BH4 a (AC7): `card["why"]` is set before the early return for a non-superadmin and the template prints it outside `{% if c.full %}`, so the gate's own sentence - the daemon's account, the
        file's mode, an include's path, "no authentication" - reached an admin. The nine states, the REAL gate (not a stub), the needle list scoped to the card's block."""
        for label, over, consents in self.GATE_STATES:
            facts = _facts(dict(over), consents=list(consents))
            monkeypatch.setattr(api, "stored_probe", lambda sid, f=facts: copy.deepcopy(f))
            monkeypatch.setattr(api, "_bound", lambda s: "x")  # the facts' own `bound`
            real = api.probe_gate(wm.S_API)
            _cards, admin = wm.render(monkeypatch, _fleet(wm.S_API, fleet), {2: facts}, superadmin=False, gate=real)
            for needle in self.HOST_FACTS:
                assert needle not in admin, (label, needle, real)
            cards, _html = wm.render(monkeypatch, _fleet(wm.S_API, fleet), {2: facts}, superadmin=False, gate=real)
            if real:
                assert cards[0]["blocked"] is True and cards[0]["why"].endswith(
                    "will stop until a superadmin has read its Write mode card."
                ), (label, cards[0]["why"])
                assert real not in cards[0]["why"]
                super_cards, super_html = wm.render(monkeypatch, [wm.S_API], {2: facts}, superadmin=True, gate=real)
                assert real in super_cards[0]["why"], (label, "a superadmin reads the gate's own words")
            else:
                assert cards[0]["why"] == words.MODE_SENTENCES["api"], label

    def test_the_chip_keeps_its_blocked_state_for_an_admin(self, monkeypatch):
        facts = _facts({"auth": "none"}, consents=["consent_rendering"])
        _cards, html = wm.render(
            monkeypatch, [wm.S_API], {2: facts}, superadmin=False, gate="this endpoint has no authentication"
        )
        assert "Current: Live API, blocked" in html and "no authentication" not in html

    def test_no_holding_sentence_is_empty(self, monkeypatch):
        """Q218 BH4 c (AC25): the sentence beside a switch button is never empty - a current mode whose gate is closed prints the gate's sentence, not `holding`."""
        for gate in ("", "this endpoint has no authentication"):
            _cards, html = wm.render(monkeypatch, [wm.S_API], {2: _facts(auth="none")}, gate=gate)
            for sentence in re.findall(r'<span class="form-hint" data-wm-holding="\d+">(.*?)</span>', html, re.S):
                assert sentence.strip(), (gate, "an empty sentence beside the button")
        _cards, html = wm.render(
            monkeypatch, [wm.S_API], {2: _facts(auth="none")}, gate="this endpoint has no authentication"
        )
        sentence = re.search(r'data-wm-holding="2">(.*?)</span>', html, re.S).group(1)
        assert "no authentication" in sentence


class TestOneEnabledInputPerConsentNamePerForm:
    """Q218 BH3 b (AC4): the three mode panels share one form, and a hidden box still submits. Only the selected mode's boxes are enabled on the server render, and the script toggles them with the radio."""

    @pytest.mark.parametrize("fleet", [1, 3], ids=["one server", "three servers"])
    @pytest.mark.parametrize("transport", ["api", "file", "off"])
    @pytest.mark.parametrize("ssh", [True, False], ids=["with ssh", "no ssh"])
    def test_one_enabled_input_per_consent_name_per_form(self, monkeypatch, transport, ssh, fleet):
        server = {"id": 1, "name": "kea-x", "api_url": "http://x", "config_transport": transport}
        if ssh:
            server["ssh_host"] = "10.0.0.1"
        _cards, html = wm.render(monkeypatch, _fleet(server, fleet), {1: _facts({"agree": False}, auth="none")})
        names = {}
        for form_id, card in re.findall(r'id="config-card-(\d+)"(.*?)(?=id="config-card-|\Z)', html, re.S):
            per_form = {}
            for tag in re.findall(r'<input type="checkbox"[^>]*>', card):
                name = re.search(r'name="(\w+)"', tag).group(1)
                per_form[name] = per_form.get(name, 0) + (1 if " disabled" not in tag else 0)
            assert all(count <= 1 for count in per_form.values()), (transport, ssh, form_id, per_form)
            names.update(per_form)
        assert names, (transport, ssh)
        # and only the selected mode's panel has any enabled box
        enabled_in = {
            panel
            for panel in ("api", "file")
            for tag in re.findall(r'<input type="checkbox"[^>]*>', _panel(html, panel))
            if " disabled" not in tag
        }
        assert enabled_in <= {transport}, (transport, ssh, enabled_in)

    def test_the_script_toggles_the_boxes_with_the_radio(self):
        template = (ROOT / "templates" / "settings_kea.html").read_text(encoding="utf-8")
        assert "box.disabled = hidden" in template and "[data-mode-panel]" in template
        assert (
            "box.disabled = hidden || !!box.closest('[data-wm-accepted]');" in template
        )  # (Q228, F3) a box shown ticked and locked stays locked

    def test_the_card_comes_back_on_the_panel_an_action_was_pressed_in(self):
        """Q228, F2 (the maintainer on a real server, 2026-11-11): the page is rendered with the CURRENT mode's radio checked, so Run check - pressed under Live API on a server that
        is on File over SSH - reloaded with its own result hidden. The card keeps a ONE-SHOT note of the panel and opens it again; it selects a radio and submits nothing."""
        template = (ROOT / "templates" / "settings_kea.html").read_text(encoding="utf-8")
        start = template.index("var REOPEN = 'jen-wm-reopen';")
        script = template[
            start : template.index("document.addEventListener('change'", start)
        ]  # the note's own code: remember, reopen and the capture listener
        # written when the action is sent: the check's own success, and every form inside a mode's panel (capture phase - base.html's confirm sends the form itself afterward)
        assert "remember(btn.closest('[data-wm-card]'));" in template
        assert template.index("remember(btn.closest('[data-wm-card]'));") < template.index("window.location.reload();")
        assert "ev.target.closest('[data-mode-panel]')" in script and "}, true);" in script
        # one shot: read and removed in the same breath, and only a note of this card's own shape is believed
        assert "window.sessionStorage.getItem(REOPEN); window.sessionStorage.removeItem(REOPEN);" in script
        assert "/^\\d+:(api|file|off)$/.test(kept)" in script
        # it only selects: no submit, no click, and a radio the account may not use stays as rendered
        assert "radio.checked = true;" in script and "if (!radio || radio.disabled) return;" in script
        assert ".submit(" not in script and ".click(" not in script
        # the panels are shown from the radio AFTER the note is read
        assert template.index("reopen();\n    refreshAll();") > template.index("function reopen()")

    def test_every_form_inside_a_panel_is_covered_by_the_one_listener(self):
        # the actions a panel carries: each is a form inside [data-mode-panel], so the capture listener sees it; the switch form is the card's own and is not
        template = (ROOT / "templates" / "settings_kea.html").read_text(encoding="utf-8")
        card = template[template.index('data-wm-card="{{ c.id }}"') : template.index('data-wm-target="off"')]
        panels = card[card.index("data-mode-panel=") :]
        for action in ("install-kea-helper", "allow-config-write", "deny-config-write"):
            assert f"/settings/infrastructure/{action}/" in panels, action
        assert 'action="/settings/infrastructure/kea-transport/' not in panels


def _panel(html, mode):
    start = html.find(f'data-mode-panel="{mode}"')
    if start == -1:
        return ""
    end = html.find('data-mode-panel="', start + 10)
    return html[start : end if end != -1 else len(html)]


class TestTheServersPageNamesEveryServersMode:
    """Q218 BH4 b (AC21): the Write mode row is ONE macro, called by the single-server table and by every multi-server card, so a fleet of two or three is told how changes reach each server."""

    def test_both_views_call_the_one_macro(self):
        servers = (ROOT / "templates" / "servers.html").read_text(encoding="utf-8")
        macro = (ROOT / "templates" / "_write_mode_badge.html").read_text(encoding="utf-8")
        assert servers.count("write_mode_badge(s") == 2, (
            "one call in the single-server view and one in the multi-server card"
        )
        assert "{% macro write_mode_badge(" in macro and macro.count('data-transport="') == 1
        assert (
            'data-transport="' not in servers and "data-transport-blocked" not in servers
        )  # nothing of the row is written twice
        single = servers.split("<!-- Single server view -->")[1].split("<!-- Multi-server / HA view -->")[0]
        multi = servers.split("<!-- Multi-server / HA view -->")[1]
        assert "write_mode_badge(s)" in single and "write_mode_badge(s, 'stat-label')" in multi

    def test_the_macro_keeps_the_role_split(self):
        macro = (ROOT / "templates" / "_write_mode_badge.html").read_text(encoding="utf-8")
        assert "{% if current_user.is_admin_or_above %}href=" in macro
        assert "s.transport_unauthenticated" in macro and "s.transport_refused" in macro


class TestTheServersRouteReadsNothingForAnAdminThatIsAHostFact:
    def test_the_route_asks_for_the_reader_s_sentence(self):
        source = (ROOT / "jen" / "routes" / "servers.py").read_text(encoding="utf-8")
        assert "caps.transport_why_for(" in source and "caps.transport_why()" not in source


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


def _macro_html(*, transport, refused, superadmin=False, admin=True):
    """The Write mode row of the Servers page, rendered through the one macro (`templates/_write_mode_badge.html`) with the role's `current_user`."""
    import types

    from jinja2 import DictLoader, Environment

    source = (ROOT / "templates" / "_write_mode_badge.html").read_text(encoding="utf-8")
    env = Environment(loader=DictLoader({"m": source + "{{ write_mode_badge(s) }}"}), autoescape=True)
    s = {
        "server": {"id": 7},
        "transport": transport,
        "transport_word": words.mode_word(transport),
        "transport_why": "why",
        "transport_blocked": False,
        "transport_unauthenticated": False,
        "transport_refused": refused,
    }
    user = types.SimpleNamespace(is_admin_or_above=admin, is_superadmin=superadmin)
    return env.get_template("m").render(s=types.SimpleNamespace(**s), current_user=user)


class TestTheRefusedNoteIsLiveApisOnly:
    """Q219 BI3 b (AD3): a remembered refusal of `config-write` belongs to Live API. The macro prints it only for a server that is on Live API (like its two siblings, the blocked note and the
    ", unauthenticated" suffix), over 3 transports x 3 roles x refused/not = 18 cells; and the route derives it for `api` only."""

    @pytest.mark.parametrize("refused", ["Permission denied", ""], ids=["refused", "not refused"])
    @pytest.mark.parametrize("role", ["superadmin", "admin", "viewer"])
    @pytest.mark.parametrize("transport", ["api", "file", "off"])
    def test_the_refused_note_prints_for_live_api_and_for_nothing_else(self, transport, role, refused):
        html = _macro_html(
            transport=transport, refused=refused, superadmin=role == "superadmin", admin=role in ("superadmin", "admin")
        )
        assert ("data-transport-refused" in html) == (transport == "api" and bool(refused)), (transport, role, html)
        if transport == "api" and refused:
            assert "Permission denied" in html

    def test_the_route_derives_the_note_for_live_api_only(self):
        source = (ROOT / "jen" / "routes" / "servers.py").read_text(encoding="utf-8")
        assert (
            'if current_user.is_admin_or_above and caps.config_transport == "api" else ""'
            in source.replace("\n            ", " ")
            or 'caps.config_transport == "api"' in source.split('s["transport_refused"]')[1][:400]
        )


class TestNoConsentBoxWithoutAStoredResult:
    """Q219 BI3 c (AD7): a box with no stored result has nothing to bind to - the File panel offers the discard box only when a readiness result is on record - and the route's sentence names the check."""

    def _file_panel(self, monkeypatch, probes):
        server = {"id": 2, "name": "kea-b", "api_url": "http://y", "ssh_host": "10.0.0.2", "config_transport": "off"}
        _cards, html = wm.render(monkeypatch, [server], probes)
        return _panel(html, "file"), _panel(html, "off")

    def test_no_stored_result_no_box_in_the_file_or_the_read_only_panel(self, monkeypatch):
        file_panel, off_panel = self._file_panel(monkeypatch, {})
        assert "checkbox" not in file_panel and "checkbox" not in off_panel

    def test_a_stored_result_offers_the_discard_box_in_the_file_panel_only(self, monkeypatch):
        file_panel, off_panel = self._file_panel(monkeypatch, {2: _facts({"agree": False})})
        assert 'name="discard_file_edit"' in file_panel and "checkbox" not in off_panel


class TestTheConsentValueIsOneConstant:
    """Q219 BI3 d (AD15): the template and the route read the same constant, `write_mode.CONSENT_VALUE` - a test renders the card in every shape and checks every consent input carries it."""

    SERVERS = [
        {"id": 2, "name": "kea-b", "api_url": "http://y", "ssh_host": "10.0.0.2", "config_transport": "off"},
        {"id": 3, "name": "kea-c", "api_url": "http://z", "config_transport": "api"},
        {"id": 1, "name": "kea-a", "api_url": "http://x", "ssh_host": "10.0.0.1", "config_transport": "file"},
    ]

    def test_every_consent_input_carries_the_constant(self, monkeypatch):
        probes = {s["id"]: _facts({"agree": False}, auth="none") for s in self.SERVERS}
        _cards, html = wm.render(monkeypatch, self.SERVERS, probes)
        tags = re.findall(r'<input type="checkbox"[^>]*>', html)
        assert len(tags) >= 6, len(tags)
        for tag in tags:
            assert f'value="{words.CONSENT_VALUE}"' in tag, tag

    def test_the_route_reads_the_constant_not_a_literal(self):
        source = (ROOT / "jen" / "routes" / "settings" / "kea_transport.py").read_text(encoding="utf-8")
        assert "request.form.get(name) == __write_mode.CONSENT_VALUE" in source and '== "1"' not in source
        template = (ROOT / "templates" / "settings_kea.html").read_text(encoding="utf-8")
        assert 'type="checkbox" name="{{ n.name }}" value="{{ c.consent_value }}"' in template
        assert 'value="1" form=' not in template.split("<!-- Write mode (Q217)")[1].split("<!-- SSH")[0]


class TestTheProofSentencesAreOneTable:
    """Q219 BI1 f: the words the card, the bundle and Health use for what the readiness check proved are `write_mode.PROOF_SENTENCES`."""

    def test_the_four_readings_and_the_two_non_verdicts(self):
        assert set(words.PROOF_SENTENCES) >= {
            "loaded",
            "rendering",
            "none",
            "no-clock",
            "unreadable",
            "no-file",
            "planned",
        }
        assert words.proof_sentence("loaded", "2026-11-05 14:02:00 UTC", "2026-11-05 14:05:00 UTC") == (
            "one the daemon has loaded (written 2026-11-05 14:02:00 UTC, loaded 2026-11-05 14:05:00 UTC)"
        )
        assert words.proof_sentence("none", "14:07", "14:05") == (
            "written at 14:07, after the daemon's last load at 14:05 - the daemon has not loaded that edit"
        )
        assert "helper build 22" in words.proof_sentence("none", "", "")
        assert words.proof_sentence("none", "14:00", "14:05", after=False) == (
            "written at 14:00, before the daemon's last load at 14:05, but the daemon does not run it"
        )
        assert "could not be read" in words.proof_sentence("none", "14:07", "")
        assert words.proof_sentence(None) == "" and words.proof_sentence("") == ""

    @pytest.mark.parametrize(
        ("probe", "needle"),
        [
            (
                {"agree": True, "proof": "loaded", "file_written_at": 1_800_000_000, "daemon_loaded_at": 1_800_000_100},
                "one the daemon has loaded (written 2027-01-15",
            ),
            ({"agree": True, "proof": "rendering"}, "own rendering of what the daemon runs"),
            (
                {"agree": False, "proof": "none", "file_written_at": 1_800_000_200, "daemon_loaded_at": 1_800_000_100},
                "the daemon has not loaded that edit",
            ),
            ({"agree": False, "proof": "none", "file_written_at": None, "daemon_loaded_at": None}, "helper build 22"),
        ],
    )
    def test_the_card_row_prints_the_proofs_words(self, monkeypatch, probe, needle):
        _cards, html = wm.render(monkeypatch, [wm.S_API], {2: _facts(probe)})
        row = html.split("Config file matches running config")[1].split("</tr>")[0]
        assert needle in row, row


class TestStepThreeSaysWhatWasAccepted:
    """Q228, F3 (the maintainer, minutes after switching a real server to Live API): step 3 was drawn the same way before and after the switch - a gray circle, the box unticked, a
    blue Record consent button that does nothing - so a consent that had just been given read as not given. On the current mode with its gate open, a consent on record that covers
    every box the facts call for is SHOWN: the step green with when it was given, the boxes ticked and locked, the button hidden."""

    def _api_panel(self, monkeypatch, facts, **kw):
        cards, html = wm.render(monkeypatch, [wm.S_API], {2: facts}, **kw)
        return cards[0], _panel(html, "api")

    def test_a_consent_on_record_is_shown(self, monkeypatch):
        card, panel = self._api_panel(monkeypatch, _facts(consents=["discard_file_edit", "consent_rendering"]))
        assert card["accepted_at"] == wm.NOW and card["accepted_all"] is True
        assert 'data-state="ok" data-wm-row="3" data-wm-accepted="2"' in panel
        # (Q230, AP11) the stored ISO text is printed as a time: the UTC wording inside a `<time>` element
        assert (
            '<strong>3.</strong> Accepted <time datetime="2026-11-04T10:00:00Z" data-jen-time="fmt" data-jen-fmt="%Y-%m-%d %H:%M">2026-11-04 10:00 UTC</time></span>'
            in panel
        )
        assert wm.NOW not in panel and "Accept what changes" not in panel
        boxes = re.findall(r'<input type="checkbox"[^>]*>', panel)
        assert boxes and all(" checked disabled" in b for b in boxes), boxes
        assert wm.consent_names(panel) == ["consent_rendering"], "the boxes are the ones the facts call for NOW"
        button = re.search(r'<button[^>]*data-wm-target="api"[^>]*>[^<]*</button>', panel).group(0)
        assert "wm-hidden" in button and " disabled" in button and 'data-current="1"' in button
        assert "This is the current mode." in panel

    def test_a_consent_recorded_before_the_boxes_were_kept_covers_the_rendering(self, monkeypatch):
        facts = _facts()
        del facts["consents"]  # 7.0.0-beta.1 and beta.2 recorded when, not which: it counts as the file rewrite only
        card, panel = self._api_panel(monkeypatch, facts)
        assert card["accepted_all"] is True and 'data-wm-accepted="2"' in panel

    def test_a_box_the_record_does_not_cover_is_still_asked(self, monkeypatch):
        # the control: the facts call for a box that is NOT on record (`_facts` records an empty list) - step 3 is not done, the box is unticked and can be ticked
        card, panel = self._api_panel(monkeypatch, _facts())
        assert card["accepted_all"] is False
        assert (
            'data-state="idle" data-wm-row="3"' in panel
            and "data-wm-accepted" not in panel
            and "Accept what changes" in panel
        )
        assert not any(" checked" in b for b in re.findall(r'<input type="checkbox"[^>]*>', panel))

    def test_a_blocked_gate_keeps_the_boxes_and_the_button(self, monkeypatch):
        # the control: the gate is closed on a fact the operator can accept. Whatever is on record, the step is asked and Record consent is offered
        card, panel = self._api_panel(
            monkeypatch,
            _facts(auth="none", consents=["consent_rendering"]),
            gate="this endpoint has no authentication",
        )
        assert "data-wm-accepted" not in panel and 'data-state="idle" data-wm-row="3"' in panel
        button = re.search(r'<button[^>]*data-wm-target="api"[^>]*>[^<]*</button>', panel).group(0)
        assert "wm-hidden" not in button and "disabled" not in button and "Record consent" in button
        assert not any(" checked" in b for b in re.findall(r'<input type="checkbox"[^>]*>', panel))

    def test_a_server_on_another_mode_is_asked_as_before(self, monkeypatch):
        # the control: File over SSH with a consent on record from an earlier switch is still asked for the switch it has not made
        cards, html = wm.render(monkeypatch, [wm.S_FILE], {1: _facts(consents=["consent_rendering"])})
        panel = _panel(html, "api")
        assert cards[0]["accepted_all"] is True, "the record covers it; the MODE is what is not current"
        assert "data-wm-accepted" not in panel and "Accept what changes" in panel
        assert not any(" checked" in b for b in re.findall(r'<input type="checkbox"[^>]*>', panel))
        assert "wm-hidden" not in re.search(r'<button[^>]*data-wm-target="api"[^>]*>', panel).group(0)

    def test_no_stored_result_accepts_nothing(self, monkeypatch):
        cards, _html = wm.render(monkeypatch, [wm.S_API], {})
        assert cards[0]["accepted_all"] is False and cards[0]["accepted_at"] == ""

    def test_the_hidden_button_has_a_rule(self):
        css = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
        assert ".wm-switch .btn.wm-hidden { display: none; }" in css


class TestConfigHistorySaysWhichHash:
    """Q228, F4 (the same walk): Config history's column was headed SHA and carried two kinds of value with nothing to tell them apart - a file's sha256 in lower case and, for a
    change over the API, Kea's own digest in upper case. They are never compared with each other, so the page says which one a row shows."""

    def test_the_words(self):
        from jen.services import config_revisions as rev

        assert rev.HASH_KIND_WORDS == {"raw": "file", "kea": "Kea digest", "canonical": "content", "legacy": ""}

    def test_the_list_carries_the_kind_and_the_route_hands_the_words_over(self):
        service = (ROOT / "jen" / "services" / "config_revisions.py").read_text(encoding="utf-8")
        assert '"SELECT id, server_id, service, sha256, hash_kind, summary, username, source, created_at "' in service
        route = (ROOT / "jen" / "routes" / "servers.py").read_text(encoding="utf-8")
        assert "hash_words=__rev.HASH_KIND_WORDS," in route

    @pytest.mark.parametrize(
        "row, want",
        [
            ({"sha256": "bc997c57cf3d0000", "hash_kind": "raw"}, 'bc997c57cf3d <span class="muted">file</span>'),
            ({"sha256": "A3158AAD578E0000", "hash_kind": "kea"}, 'A3158AAD578E <span class="muted">Kea digest</span>'),
            (
                {"sha256": "0123456789ab0000", "hash_kind": "canonical"},
                '0123456789ab <span class="muted">content</span>',
            ),
            ({"sha256": "0123456789ab0000", "hash_kind": "legacy"}, "0123456789ab"),
            ({"sha256": "0123456789ab0000", "hash_kind": "something-new"}, "0123456789ab"),
            ({"sha256": "", "hash_kind": "kea"}, "\u2014"),
            ({"sha256": None, "hash_kind": "raw"}, "\u2014"),
        ],
    )
    def test_the_cell(self, row, want):
        import jinja2

        from jen.services import config_revisions as rev

        page = (ROOT / "templates" / "config_history.html").read_text(encoding="utf-8")
        assert '<th class="u-e2c960">Hash</th>' in page and ">SHA</th>" not in page
        cell = re.search(r'<td data-m="hide"  class="mono u-e2c960">(.*?)</td>', page, re.S).group(1)
        env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=True)
        assert env.from_string(cell).render(r=row, hash_words=rev.HASH_KIND_WORDS) == want

    def test_every_page_that_prints_a_revisions_hash_says_its_kind(self):
        # the whole templates directory: a revision's hash is printed in two places, and each carries the word. A third page that prints one without it fails here
        import jinja2

        from jen.services import config_revisions as rev

        printing = sorted(
            p.name
            for p in (ROOT / "templates").glob("*.html")
            if re.search(r"\b(r|rev)\.sha256\[", p.read_text(encoding="utf-8"))
        )
        assert printing == ["config_history.html", "config_history_detail.html"]
        for name in printing:
            assert "hash_words.get(" in (ROOT / "templates" / name).read_text(encoding="utf-8"), name
        route = (ROOT / "jen" / "routes" / "servers.py").read_text(encoding="utf-8")
        assert route.count("hash_words=__rev.HASH_KIND_WORDS,") == 2
        detail = (ROOT / "templates" / "config_history_detail.html").read_text(encoding="utf-8")
        line = re.search(r'· (<span class="mono">\{\{ rev\.sha256.*?)</p>', detail, re.S).group(1)
        render = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=True).from_string(line).render
        assert render(rev={"sha256": "A3158AAD578E0123ffff", "hash_kind": "kea"}, hash_words=rev.HASH_KIND_WORDS) == (
            '<span class="mono">A3158AAD578E0123</span> <span class="muted">Kea digest</span>'
        )
        assert render(
            rev={"sha256": "0123456789abcdef0000", "hash_kind": "legacy"}, hash_words=rev.HASH_KIND_WORDS
        ) == ('<span class="mono">0123456789abcdef</span>')
