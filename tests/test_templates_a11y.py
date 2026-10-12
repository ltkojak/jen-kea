"""
tests/test_templates_a11y.py
────────────────────────────
v5.69.0-beta.4 (Q173, items 3, 4, 6 and 7): the bounded accessibility fixes, the end-user prose with no release markers, the rule the style extractor once got wrong, and the dates
the v6 tables print through the same filter as the v4 ones. Pure source and render tests - no database.
"""

import json
import pathlib
import re

import pytest

from tests.test_csp import TEMPLATE_HTML_FILES

IMG_RE = re.compile(r"<img\b[^>]*>", re.S)


class TestBoundedAccessibility:
    def test_every_target_blank_has_noopener(self):
        for path in TEMPLATE_HTML_FILES:
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if 'target="_blank"' in line:
                    assert "noopener" in line, (path.as_posix(), n)

    def test_every_img_has_alt(self):
        for path in TEMPLATE_HTML_FILES:
            for tag in IMG_RE.findall(path.read_text(encoding="utf-8")):
                assert re.search(r"\balt=", tag), (path.as_posix(), tag)

    def test_the_confirm_overlay_and_the_shortcuts_modal_are_dialogs(self):
        text = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
        for id_ in ("kb-modal", "jen-confirm-overlay"):
            tag = re.search(rf'<div[^>]*id="{id_}"[^>]*>', text).group(0)
            assert 'role="dialog"' in tag and 'aria-modal="true"' in tag, id_

    def test_the_confirm_dialog_moves_focus_in_and_gives_it_back(self):
        text = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
        body = text[
            text.index("window.jenConfirm = function") : text.index("v5.56.4 (Q72b) — full-page form submissions")
        ]
        assert (
            "cancelBtn.focus()" in body and "opener.focus()" in body and "removeEventListener('keydown', onKey)" in body
        )

    def test_the_ipmap_cells_say_their_state_in_words(self):
        text = pathlib.Path("templates/ipmap.html").read_text(encoding="utf-8")
        assert (
            text.count('role="img" aria-label=') == 2
            and text.count('aria-hidden="true" style="display:inline-block;width:12px') == 3
        )

    @pytest.mark.parametrize("name", ["settings_kea", "settings_alerts", "settings_security", "ddns", "database"])
    def test_a_label_that_is_bound_names_a_control_that_exists(self, name):
        text = pathlib.Path(f"templates/{name}.html").read_text(encoding="utf-8")
        ids = re.findall(r'\bid="([^"{]+)"', text)
        for target in re.findall(r'<label[^>]*\bfor="(f-[^"]+)"', text):
            assert ids.count(target) == 1, (name, target)


class TestNoReleaseMarkerInEndUserProse:
    """item 4: the page text says what a thing is, never which beta added it. Comments (Jinja, HTML, CSS, JS) may narrate their history; the allowlist is the updates card."""

    COMMENT = re.compile(r"\{#.*?#\}|<!--.*?-->|/\*.*?\*/", re.S)
    MARKER = re.compile(r"beta|\bv?5\.\d{1,3}(?:\.\d+)?\b|\(Q\d+", re.I)
    # file -> why a match is not a release marker
    REVIEWED = {
        "settings_system.html": "the Updates card names the beta CHANNEL and what it offers",
        "_icon_sprite.html": "SVG path coordinates",
        "explain.html": "a placeholder naming a DHCP vendor-class string (MSFT 5.0)",
        "settings_alerts.html": "Pi-hole v5 and v6 are that product's versions",
    }

    def _prose(self, path):
        text = self.COMMENT.sub("", path.read_text(encoding="utf-8"))
        return [line for line in text.splitlines() if not line.strip().startswith("//")]

    def test_no_template_prints_a_version_or_a_beta_to_the_reader(self):
        found = []
        for path in pathlib.Path("templates").glob("*.html"):
            if path.name in self.REVIEWED:
                continue
            for n, line in enumerate(self._prose(path), 1):
                if self.MARKER.search(re.sub(r"\{\{.*?\}\}|\{%.*?%\}", "", line)):
                    found.append((path.name, n, line.strip()[:120]))
        assert found == [], found


class TestTheStyleExtractorsBadRuleIsGone:
    """item 3: `.u-999e54{color:' + color + '}` was a JS fragment the extractor took for a style; its two call sites now colour their lines from script."""

    def test_the_map_and_the_stylesheet_carry_no_javascript_fragment(self):
        root = pathlib.Path(".")
        mapping = json.loads((root / "tools" / "inline_style_map.json").read_text(encoding="utf-8"))
        css = (root / "static" / "css" / "ui-classes.css").read_text(encoding="utf-8")
        assert not [k for k in mapping if "'" in k or "+" in k], (
            "a declaration with a quote or a plus sign is script text, not CSS"
        )
        assert "' + color + '" not in css

    def test_the_setup_progress_pills_use_tokens_every_theme_defines(self):
        text = pathlib.Path("templates/_setup_progress.html").read_text(encoding="utf-8")
        for token in re.findall(r"var\((--[a-z0-9-]+)\)", text):
            assert token in {"--primary", "--surface2", "--success", "--border", "--text-muted"}, token

    def test_the_options_grid_collapses_on_a_phone(self):
        base = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
        assert ".dhcp-opt-grid { grid-template-columns: minmax(0, 1fr); }" in base
        assert 'class="dhcp-opt-grid"' in pathlib.Path("templates/dhcp_options.html").read_text(encoding="utf-8")


class TestTheV6TablesFormatTheirDates:
    @pytest.mark.parametrize(
        "template,field",
        [
            ("_leases6_results.html", "l.expire"),
            ("_devices6_results.html", "d.last_expire"),
            ("config_history.html", "r.created_at"),
            ("config_history_detail.html", "rev.created_at"),
        ],
    )
    def test_the_date_goes_through_the_same_filter_as_the_v4_tables(self, template, field):
        text = pathlib.Path("templates", template).read_text(encoding="utf-8")
        assert "{{ " + field + "|utcfmt }}" in text and "{{ " + field + " }}" not in text

    def test_the_filter_renders_a_datetime_not_its_repr(self):
        from datetime import datetime

        from jinja2 import Environment

        env = Environment()

        def utcfmt(value, fmt="%Y-%m-%d %H:%M"):
            return value.strftime(fmt) + " UTC" if value else "—"

        env.filters["utcfmt"] = utcfmt
        out = env.from_string("{{ d|utcfmt }}").render(d=datetime(2026, 10, 11, 9, 5))
        assert out == "2026-10-11 09:05 UTC" and "datetime.datetime(" not in out


class TestTheColspansMatchTheirHeaders:
    def test_the_reservations_empty_row_spans_the_columns_the_role_sees(self):
        text = pathlib.Path("templates/_reservations_results.html").read_text(encoding="utf-8")
        assert """colspan="{{ 9 if current_user.role in ('superadmin','admin') else 8 }}\"""" in text

    def test_the_devices_empty_row_spans_the_columns_the_role_sees(self):
        text = pathlib.Path("templates/_device_rows.html").read_text(encoding="utf-8")
        assert "(12 if current_user.role in ('superadmin','admin') else 11)" in text


class TestNoReleaseMarkerInTheApiDescription:
    """The OpenAPI document is end-user text too (the API docs page and every client generator read it): its strings carry no release number and no Q reference."""

    def test_no_string_in_the_spec_names_a_release_or_a_q(self):
        import ast

        tree = ast.parse(pathlib.Path("jen/routes/api_spec.py").read_text(encoding="utf-8"))
        module_doc = ast.get_docstring(tree, clean=False)
        marker = re.compile(r"\(v?5\.\d+|\(Q\d+|, Q\d+\)|\bbeta\.\d+")
        found = [
            (node.lineno, node.value[:80])
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value != module_doc
            and marker.search(node.value)
        ]
        assert found == [], found
