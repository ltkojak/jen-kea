"""
tests/test_dialogs.py
─────────────────────
v5.70.0-beta.2 (Q206, AV1 and AV2): the browser's own alert(), prompt() and confirm() are retired for Jen's toast, prompt and confirm dialogs, and a flashed message can be dismissed.

Pure source and render tests - no database (`py -m pytest --noconftest tests/test_dialogs.py`). The behaviour in a real browser (a name typed through the dialog, the toast, the new option
with no navigation, a success flash that fades and an error that stays) is tests/e2e/test_ui_polish.py.
"""

import pathlib
import re

import pytest

from tests.test_csp import TEMPLATE_HTML_FILES
from tests.test_desktop_polish import _render

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")

# a CALL of the browser's dialog: the bare name or window.name, not jenConfirm(, not x.confirm( on some other object, not data-confirm= / hx-confirm= (no parenthesis)
CALL = re.compile(r"(?<![\w$.])(?:window\s*\.\s*)?(?:alert|prompt|confirm)\s*\(")
# every reviewed exception, with the reason it is not a call to the browser's dialog. EMPTY on purpose: a site that needs one is a site that moves to jenToast / jenPrompt / jenConfirm.
REVIEWED: dict = {}

_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_STRING = re.compile(r"""'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\\n])*`""")


def calls_in(text):
    """The (line number, line) of every call of alert/prompt/confirm in `text`, after the same blanking the CSP tests do (a `//` line is prose) plus comments and one-line strings."""
    for pattern in (_JINJA_COMMENT, _HTML_COMMENT, _BLOCK_COMMENT):
        text = pattern.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("//"):
            continue
        if CALL.search(_STRING.sub('""', line)):
            found.append((n, line.strip()))
    return found


class TestNoBrowserDialogs:
    def test_no_template_or_plugin_calls_a_browser_dialog(self):
        assert REVIEWED == {}, "the reviewed list is empty on purpose - move the site instead"
        offenders = {}
        for path in TEMPLATE_HTML_FILES:
            hits = calls_in(path.read_text(encoding="utf-8"))
            if hits:
                offenders[path.as_posix()] = hits
        assert not offenders, f"a browser dialog is called: {offenders}"

    def test_the_sweep_sees_what_it_is_for(self):
        assert calls_in("x.then(() => alert('Codes copied'));")
        assert calls_in("var name = prompt('Name this filter:');")
        assert calls_in("if (window.confirm('Sure?')) go();")
        assert calls_in("if (!ports) { e.preventDefault(); alert ('Enter a port.'); }")
        assert calls_in("<script>\nalert(1)\n</script>")

    def test_the_sweep_ignores_what_is_not_a_call(self):
        for ok in (
            "jenConfirm('Release?', go);",
            "jenPrompt('Name:', save);",
            "jenToast('Saved', 'success');",
            "var s = 'press alert( to ...';",
            "// alert('x') was the old way",
            "/* prompt('x') */",
            "{# confirm('x') #}",
            "<!-- alert('x') -->",
            '<form data-confirm="Delete it?" hx-confirm="Sure?">',
            "toast.alert('x');",
            "const el = form.querySelector('[data-confirm]');",
        ):
            assert not calls_in(ok), ok


# (template, what the site is now) - the classification of the seventeen sites in templates/ and the one in the watchdog plugin
SITES = [
    (
        "templates/leases.html",
        [
            "jenPrompt('Name this filter:'",
            "jenToast('Filter saved: '",
            "jenToast('Error: '",
            "jenToast('No leases selected.', 'info')",
        ],
    ),
    (
        "templates/reservations.html",
        [
            "jenPrompt('Name this filter:'",
            "jenToast('Filter saved: '",
            "jenToast('Error: '",
            "jenToast('No reservations selected.', 'info')",
        ],
    ),
    (
        "templates/devices.html",
        ["jenToast('Error saving: ' + data.error, 'error')", "jenToast('No devices selected.', 'info')"],
    ),
    ("templates/subnets.html", ["jenToast('Could not save the colour: '", "jenToast('Error saving note: '"]),
    ("templates/settings_alerts.html", ["jenToast('Channel not found', 'error')"]),
    ("templates/mfa_backup_codes.html", ["jenToast('Codes copied to clipboard', 'success')"]),
    ("templates/user_profile.html", ['id="avatar-note"', 'getElementById("avatar-note")']),
    (
        "templates/database_migrate.html",
        ['id="step1-note"', "getElementById('step1-note')", "'Fill in host, user, and database name.'"],
    ),
    ("plugins/watchdog/templates/watchdog/index.html", ['id="wd-port-note"', "getElementById('wd-port-note')"]),
]


class TestEverySiteMovedToTheClassTheEntryGivesIt:
    @pytest.mark.parametrize("path,needles", SITES)
    def test_the_site_uses_its_replacement(self, path, needles):
        text = (ROOT / path).read_text(encoding="utf-8")
        for needle in needles:
            assert needle in text, (path, needle)

    @pytest.mark.parametrize("path", ["templates/leases.html", "templates/reservations.html"])
    def test_a_saved_filter_is_added_to_the_list_not_reloaded_into_it(self, path):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert "location.reload" not in text
        assert "sel.insertBefore(opt" in text and "opt.selected = true" in text

    @pytest.mark.parametrize("path", ["templates/user_profile.html", "templates/database_migrate.html"])
    def test_a_validation_note_is_a_sentence_beside_its_field_never_a_toast(self, path):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert 'class="field-note"' in text
        assert "jenToast" not in text

    def test_the_two_template_sites_that_copy_use_the_shared_copier(self):
        for path in ("templates/mfa_backup_codes.html", "templates/api_keys.html"):
            text = (ROOT / path).read_text(encoding="utf-8")
            assert "jenCopyText(" in text and "navigator.clipboard" not in text, path


class TestToastRegion:
    def test_the_regions_are_in_base_and_announce_the_right_way(self):
        status = re.search(r'<div id="jen-toasts"[^>]*>', BASE).group(0)
        assert 'role="status"' in status and 'aria-live="polite"' in status
        urgent = re.search(r'<div id="jen-toasts-alert"[^>]*>', BASE).group(0)
        assert 'role="alert"' in urgent

    def test_four_kinds_two_regions(self):
        body = BASE[BASE.index("window.jenToast = function") : BASE.index("window.jenPrompt = function")]
        assert "success: true, error: true, info: true, warning: true" in BASE
        assert "kind === 'error' || kind === 'warning'" in body
        assert "'jen-toasts-alert' : 'jen-toasts'" in body

    def test_success_and_info_leave_by_themselves_in_five_seconds_error_and_warning_stay(self):
        body = BASE[BASE.index("window.jenToast = function") : BASE.index("window.jenPrompt = function")]
        assert "if (!urgent) autoLeave(el, 5000)" in body
        assert body.count("autoLeave(") == 1

    def test_the_timer_waits_while_the_pointer_is_over_the_toast(self):
        fn = BASE[BASE.index("function autoLeave(") : BASE.index("var TOAST_KINDS")]
        assert "addEventListener('mouseenter', pause)" in fn and "addEventListener('mouseleave'" in fn
        assert "clearTimeout(timer)" in fn

    def test_the_cap_never_drops_an_error_or_a_warning(self):
        # SP-H1: the polite region keeps at most four; a toast that is an error or a warning is never removed by the cap, only by being closed
        body = BASE[BASE.index("window.jenToast = function") : BASE.index("window.jenPrompt = function")]
        assert "if (!urgent) { while (region.children.length > 4) region.firstChild.remove(); }" in body

    def test_the_regions_announce_one_toast_at_a_time(self):
        for rid in ("jen-toasts", "jen-toasts-alert"):
            assert 'aria-atomic="false"' in re.search(rf'<div id="{rid}"[^>]*>', BASE).group(0)

    def test_every_toast_has_a_close_button(self):
        body = BASE[BASE.index("window.jenToast = function") : BASE.index("window.jenPrompt = function")]
        assert "close.className = 'alert-close'" in body and "setAttribute('aria-label', 'Dismiss')" in body

    def test_reduced_motion_gets_no_slide(self):
        css_block = BASE[BASE.index("@media (prefers-reduced-motion: no-preference) {\n            .alert-flash") :]
        css_block = css_block[: css_block.index(".alert.leaving")]
        assert "animation: toast-in" in css_block and "transition: opacity" in css_block
        assert "function reducedMotion()" in BASE and "if (reducedMotion()) { el.remove(); return; }" in BASE

    def test_the_stack_sits_above_the_tab_bar_on_a_phone(self):
        assert re.search(r"\.toast-stack \{[^}]*bottom: calc\(var\(--tabbar-h\) \+ env\(safe-area-inset-bottom\)", BASE)

    def test_a_toast_is_built_with_textcontent_never_html(self):
        body = BASE[BASE.index("window.jenToast = function") : BASE.index("window.jenPrompt = function")]
        assert "text.textContent = String(message)" in body and "innerHTML" not in body


class TestPromptDialog:
    def test_it_is_a_dialog_with_a_labelled_field(self):
        tag = re.search(r'<div id="jen-prompt-overlay"[^>]*>', BASE).group(0)
        assert 'role="dialog"' in tag and 'aria-modal="true"' in tag and "hidden" in tag
        assert '<label id="jen-prompt-label" for="jen-prompt-input">' in BASE
        field = re.search(r'<input[^>]*id="jen-prompt-input"[^>]*>', BASE).group(0)
        assert 'maxlength="100"' in field and 'type="text"' in field

    def test_the_hidden_attribute_really_hides_it(self):
        # the lesson of Q205: an inline display beside `hidden` beats it. The overlay is a class with a [hidden] rule and carries no style attribute.
        assert ".jen-dialog-overlay[hidden] { display: none; }" in BASE
        tag = re.search(r'<div id="jen-prompt-overlay"[^>]*>', BASE).group(0)
        assert "style=" not in tag

    def test_it_follows_the_confirm_dialogs_rules(self):
        body = BASE[BASE.index("window.jenPrompt = function") : BASE.index("// v5.70.0-beta.2 (Q206, AV2)")]
        assert "field.focus()" in body  # focus goes to the field
        assert "e.key === 'Enter'" in body and "submit()" in body  # Enter confirms
        assert "e.key === 'Escape'" in body  # Escape cancels
        assert "if (value) onValue(value)" in body  # an empty value cancels
        assert "opener.focus()" in body  # focus returns
        assert "order = [field, cancelBtn, okBtn]" in body  # Tab cycles
        assert "removeEventListener('keydown', onKey, true)" in body

    def test_the_value_is_trimmed_before_it_is_handed_over(self):
        body = BASE[BASE.index("window.jenPrompt = function") : BASE.index("// v5.70.0-beta.2 (Q206, AV2)")]
        assert "field.value.trim()" in body

    def test_the_cap_is_the_saved_search_routes_own(self):
        route = (ROOT / "jen" / "routes" / "search.py").read_text(encoding="utf-8")
        assert 'request.form.get("name", "").strip()[:100]' in route


class TestFlashes:
    @pytest.mark.parametrize("category", ["success", "info"])
    def test_a_success_or_an_info_has_a_close_button_and_fades_after_six_seconds(self, category):
        html = _render(flashes=[(category, "All good.")])
        tag = re.search(rf'<div class="alert alert-{category} alert-flash"[^>]*>', html).group(0)
        assert 'role="status"' in tag and 'aria-live="polite"' in tag and 'data-autofade="6000"' in tag
        assert '<button type="button" class="alert-close" aria-label="Dismiss">' in html

    @pytest.mark.parametrize("category", ["error", "danger"])
    def test_an_error_or_a_danger_is_an_alert_with_a_close_button_and_no_timer(self, category):
        html = _render(flashes=[(category, "It broke.")])
        tag = re.search(rf'<div class="alert alert-{category} alert-flash"[^>]*>', html).group(0)
        assert 'role="alert"' in tag and "data-autofade" not in tag
        assert '<button type="button" class="alert-close" aria-label="Dismiss">' in html

    def test_a_warning_stays_until_it_is_closed(self):
        html = _render(flashes=[("warning", "Careful.")])
        tag = re.search(r'<div class="alert alert-warning alert-flash"[^>]*>', html).group(0)
        assert 'role="status"' in tag and "data-autofade" not in tag
        assert 'class="alert-close"' in html

    def test_one_delegated_listener_closes_them_and_the_toasts(self):
        assert BASE.count("closest('.alert-close')") == 1
        assert re.search(r"document\.querySelectorAll\('\.alert-flash\[data-autofade\]'\)", BASE)

    def test_a_flash_and_a_toast_share_one_pause_and_one_reduced_motion_rule(self):
        assert BASE.count("function autoLeave(") == 1 and BASE.count("function leave(") == 1
        assert "autoLeave(el, parseInt(el.getAttribute('data-autofade'), 10) || 6000)" in BASE
