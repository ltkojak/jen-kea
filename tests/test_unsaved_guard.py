"""
tests/test_unsaved_guard.py
───────────────────────────
v5.70.0-beta.4 (Q208, AX3): a half-edited long form warns before it is left. The forms carry `data-guard-unsaved`; ONE script in base.html takes the snapshot, arms `beforeunload` and stands
down for a form that is being submitted. Pure source tests (`py -m pytest --noconftest tests/test_unsaved_guard.py`); the browser journey is tests/e2e/test_unsaved_guard.py.
"""

import pathlib
import re

import pytest

TEMPLATES = pathlib.Path("templates")
BASE = (TEMPLATES / "base.html").read_text(encoding="utf-8")

# template -> (an `action=`/`id=` fragment that names the guarded form(s), how many carry the attribute)
GUARDED = {
    "settings_kea.html": [
        "/settings/infrastructure/save-kea",
        "/settings/infrastructure/save-ssh",
        "/settings/infrastructure/save-ha",
        "/settings/infrastructure/save-extra-servers",
        "/settings/infrastructure/save-d2",
        "/settings/infrastructure/save-ddns",
        "/settings/infrastructure/save-kea6",
    ],
    "settings_alerts.html": [
        "/settings/alerts/save-global",
        "/settings/alerts/save-template",
        "save_metrics_settings",
    ],
    "ddns.html": ["/ddns/naming/save"],
    "database.html": [
        "/settings/infrastructure/save-jen-db",
        "/settings/infrastructure/save-kea-db",
        "/database/schedule",
    ],
    "settings_security.html": ["/settings/save-oidc", "/settings/save-session", "/settings/save-rate-limit"],
    "dhcp_class_edit.html": ['id="class-form"'],
    "settings_appearance.html": ['id="theme-custom-form"'],
    "add_subnet.html": ['id="add-subnet-form"'],
    "edit_subnet.html": ['id="edit-subnet-form"'],
    "add_reservation.html": ["<form data-guard-unsaved method="],
    "author_kea_config.html": ['id="author-kea-form"'],
}
# named in the entry and NOT guarded, with the reason (a deviation, reported)
NOT_GUARDED_BY_DEVIATION = {
    "settings_alerts.html (save-channel)": "the channel form is filled by the page's own script when a channel is edited (second pass, SP-8): the snapshot taken at load is not the form the person is looking at",
    "servers.html": "no editable form: its 21 `input` tags are CSRF fields and one checkbox group of a one-click HA action; there is nothing to half-edit",
}
# the forms that must never carry it
LIST_FILTERS = ["leases.html", "devices.html", "reservations.html"]


def _forms(text):
    return re.findall(r"<form\b[^>]*>", text)


class TestTheListedFormsAreGuarded:
    @pytest.mark.parametrize("name", sorted(GUARDED))
    def test_each_named_form_carries_the_attribute(self, name):
        forms = _forms((TEMPLATES / name).read_text(encoding="utf-8"))
        for fragment in GUARDED[name]:
            hit = [f for f in forms if fragment in f]
            assert hit, (name, fragment, "no such form")
            assert all("data-guard-unsaved" in f for f in hit), (name, fragment)

    @pytest.mark.parametrize("name", LIST_FILTERS)
    def test_a_list_filter_form_that_swaps_on_change_is_not_guarded(self, name):
        assert "data-guard-unsaved" not in (TEMPLATES / name).read_text(encoding="utf-8")

    def test_a_logout_form_is_not_guarded(self):
        logouts = [f for f in _forms(BASE) if 'action="/logout"' in f]
        assert len(logouts) == 2, "the nav menu's and the phone sheet's"
        assert not any("data-guard-unsaved" in f for f in logouts)

    def test_no_guarded_form_is_itself_the_target_of_an_htmx_swap(self):
        """A form htmx swaps on change would lose its own state to the swap. (dhcp_class_edit's class form has hx-post for its live PREVIEW, which swaps a different element: it is guarded.)"""
        for path in TEMPLATES.glob("*.html"):
            for f in _forms(path.read_text(encoding="utf-8")):
                if "data-guard-unsaved" in f and "hx-target" in f:
                    fid = re.search(r'\bid="([^"]+)"', f)
                    target = re.search(r'hx-target="([^"]+)"', f).group(1)
                    assert not fid or target != "#" + fid.group(1), (path.name, f)

    def test_the_deviation_is_real(self):
        text = (TEMPLATES / "servers.html").read_text(encoding="utf-8")
        assert not re.search(r"<(textarea|select)\b|<input\b(?![^>]*type=\"(hidden|checkbox)\")", text)
        assert "servers.html" in NOT_GUARDED_BY_DEVIATION


class TestOneScript:
    def test_the_beforeunload_listener_appears_once_in_the_tree_inside_a_nonced_script(self):
        hits = []
        for path in list(TEMPLATES.glob("*.html")) + list(pathlib.Path("static/js").glob("*.js")):
            if path.name == "htmx.min.js":
                continue
            hits += [
                path.name
                for _ in re.finditer(r"""addEventListener\(\s*['"]beforeunload['"]""", path.read_text(encoding="utf-8"))
            ]
        assert hits == ["base.html"]
        for script in re.finditer(r"<script\b([^>]*)>(.*?)</script>", BASE, re.S):
            if "'beforeunload'" in script.group(2):
                assert 'nonce="{{ csp_nonce }}"' in script.group(1)

    def test_the_snapshot_is_the_forms_own_data(self):
        assert "new URLSearchParams(new FormData(f)).toString()" in BASE

    def test_a_submitted_form_is_not_blocked_by_the_event_or_by_form_submit(self):
        # the document-level submit listener covers the submit event; the prototype wrapper covers form.submit() (data-confirm, data-submit and a page script's own call)
        assert "f.setAttribute('data-submitting', '1')" in BASE
        assert "e.defaultPrevented" in BASE
        assert "HTMLFormElement.prototype.submit = function" in BASE
        assert re.search(r"hasAttribute\('data-submitting'\)", BASE)

    def test_the_idle_redirect_the_session_dialog_and_a_discarded_draft_are_not_blocked(self):
        assert BASE.count("window.jenLeaving = true") == 2, "the idle redirect and the dialog's own sign-out"
        assert "if (window.jenLeaving) return;" in BASE
        assert "window.jenLeaving = true" in (TEMPLATES / "author_kea_config.html").read_text(encoding="utf-8")

    def test_the_page_returns_no_custom_text(self):
        assert "e.returnValue = ''" in BASE

    def test_the_listener_is_armed_only_on_a_page_that_has_a_guarded_form(self):
        assert "guardArmed" in BASE

    def test_every_programmatic_submit_of_a_guarded_form_in_the_tree_is_covered(self):
        """A page script that submits a guarded form with `.submit()` is the shape the guard must not block: the wrapper sets the flag, so the sweep only has to know such scripts exist."""
        callers = []
        for name in GUARDED:
            text = (TEMPLATES / name).read_text(encoding="utf-8")
            callers += [name for _ in re.finditer(r"\.submit\(\)", text)]
        assert set(callers) <= {"add_subnet.html", "edit_subnet.html", "author_kea_config.html"}
