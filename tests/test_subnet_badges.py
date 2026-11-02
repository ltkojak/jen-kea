"""
tests/test_subnet_badges.py
───────────────────────────
Q205 (v5.70.0-beta.1, AU1/AU8): a subnet's badge tone is chosen per subnet, from seven, and nothing is derived from its name.

The first four classes are pure (`py -m pytest --noconftest tests/test_subnet_badges.py -k "not Route"`): the source sweep over `templates/` and `plugins/`, the two pinned declarations, the seven
tones in every preset and the macro's output. `TestTheRoute` needs the database like every route test.
"""

import pathlib
import re

import jinja2
import pytest

from jen.services import subnet_tones, theme

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")

#: the exact text of the name rules the maintainer's own subnets used (templates/base.html, v5.69.4): `.badge-production` (primary) and `.badge-iot` (success). blue and green are these
#: declarations byte for byte, so the maintainer's blue and green never drift.
OLD_PRODUCTION = "background: color-mix(in srgb, var(--primary) 18%, transparent); color: var(--primary);"
OLD_IOT = "background: color-mix(in srgb, var(--success) 18%, transparent); color: var(--success);"


def _rule(selector):
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", BASE)
    assert m, f"{selector} has no rule in base.html"
    return " ".join(m.group(1).split())


def _templates():
    return sorted(list((ROOT / "templates").glob("*.html")) + list((ROOT / "plugins").rglob("*.html")))


class TestNothingIsDerivedFromAName:
    def test_no_template_builds_a_badge_class_from_a_value(self):
        offenders = []
        for path in _templates():
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"badge-\{\{", line):
                    offenders.append(f"{path.name}:{n}")
        assert not offenders, offenders

    def test_the_only_class_built_from_an_expression_is_a_tone_from_the_tone_map_or_the_seven(self):
        allowed = {"tone", "t", "subnet_tone(s.id)"}
        for path in _templates():
            for m in re.finditer(r"badge-tone-\{\{\s*([^}]+?)\s*\}\}", path.read_text(encoding="utf-8")):
                assert m.group(1) in allowed, (path.name, m.group(0))

    def test_no_script_builds_a_subnet_badge(self):
        for path in _templates():
            text = path.read_text(encoding="utf-8")
            assert not re.search(r"""['"]badge badge-['"]\s*\+""", text), path.name

    def test_the_three_name_rules_are_gone(self):
        for old in (".badge-production", ".badge-iot", ".badge-vlan70"):
            assert old not in BASE
            for path in _templates():
                assert old[1:] not in path.read_text(encoding="utf-8"), (old, path.name)

    def test_every_template_that_prints_a_subnet_in_a_badge_imports_the_macro(self):
        for name in (
            "_device_rows.html",
            "_lease_rows.html",
            "_recent_leases.html",
            "_recent_leases_rows.html",
            "_reservation_row.html",
            "dashboard.html",
            "search_results.html",
            "subnets.html",
        ):
            text = (ROOT / "templates" / name).read_text(encoding="utf-8")
            assert "{% from '_subnet_badge.html' import subnet_badge %}" in text, name
            assert "subnet_badge(" in text, name

    def test_the_ipv6_pill_is_blue_not_a_name_rule(self):
        text = (ROOT / "templates" / "subnets.html").read_text(encoding="utf-8")
        assert text.count('class="badge badge-tone-blue"') >= 2 and "badge-production" not in text


class TestThePinnedDeclarationsAndTheSevenTones:
    def test_blue_is_todays_production_rule_and_green_is_todays_iot_rule_byte_for_byte(self):
        assert _rule(".badge-tone-blue") == OLD_PRODUCTION
        assert _rule(".badge-tone-green") == OLD_IOT

    def test_there_are_exactly_seven_tones_and_each_has_a_rule(self):
        assert subnet_tones.TONES == ("blue", "green", "red", "orange", "yellow", "purple", "mono")
        for tone in subnet_tones.TONES:
            rule = _rule(f".badge-tone-{tone}")
            assert "color-mix(in srgb," in rule and "18%, transparent" in rule, (tone, rule)
        assert len(set(re.findall(r"\.badge-tone-(\w+)\s*\{", BASE))) == 7

    def test_red_orange_and_mono_use_the_themes_own_tokens(self):
        assert "var(--danger)" in _rule(".badge-tone-red") and "var(--warning)" in _rule(".badge-tone-orange")
        mono = _rule(".badge-tone-mono")
        assert "color: var(--text);" in mono and "color-mix(in srgb, var(--text) 18%, transparent)" in mono

    def test_the_default_is_blue_and_only_a_known_tone_is_valid(self):
        assert subnet_tones.DEFAULT_TONE == "blue"
        assert all(subnet_tones.valid_tone(t) for t in subnet_tones.TONES)
        for bad in ("", "Blue", "pink", None, 7, "blue ", "badge-production"):
            assert not subnet_tones.valid_tone(bad)

    @staticmethod
    def _mix(a, b, pa):
        """sRGB mix of two #rrggbb colors, `pa` percent of a."""
        pa = pa / 100.0
        ca, cb = [int(a[i : i + 2], 16) for i in (1, 3, 5)], [int(b[i : i + 2], 16) for i in (1, 3, 5)]
        return "#" + "".join(f"{round(x * pa + y * (1 - pa)):02x}" for x, y in zip(ca, cb, strict=True))

    @staticmethod
    def _full(h):
        h = h.strip()
        return "#" + "".join(c * 2 for c in h[1:]) if len(h) == 4 else h

    @pytest.mark.parametrize("preset", sorted(theme.PRESETS))
    @pytest.mark.parametrize(("hue", "tone"), [("#e6b400", "yellow"), ("#a371f7", "purple")])
    def test_the_fixed_hues_read_in_every_preset(self, preset, hue, tone):
        """yellow and purple are fixed hues mixed 50% toward the preset's own text color, on an 18% tint of the hue over the preset's surface: the label keeps a legible ratio on a light and on a dark preset."""
        tokens = theme.PRESETS[preset]["tokens"]
        text, surface = self._full(tokens["text"]), self._full(tokens["surface"])
        label = self._mix(hue, text, 50)
        chip = self._mix(hue, surface, 18)
        assert theme.contrast_ratio(label, chip) >= 3.0, (preset, tone, label, chip, theme.contrast_ratio(label, chip))

    @pytest.mark.parametrize("preset", sorted(theme.PRESETS))
    def test_mono_is_the_texts_own_color_on_a_tint_of_itself(self, preset):
        tokens = theme.PRESETS[preset]["tokens"]
        text, surface = self._full(tokens["text"]), self._full(tokens["surface"])
        assert theme.contrast_ratio(text, self._mix(text, surface, 18)) >= 3.0


def _env():
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(ROOT / "templates")), autoescape=True, undefined=jinja2.StrictUndefined
    )
    env.globals["subnet_tone"] = lambda sid: {3: "green", 5: "purple"}.get(sid, "blue")
    env.globals["subnet_filter_href"] = lambda sid: None if sid is None else f"/leases?subnet={sid}"
    return env


class TestTheMacro:
    def _render(self, call):
        return _env().from_string("{% from '_subnet_badge.html' import subnet_badge %}" + call).render().strip()

    def test_a_tone_comes_from_the_id_not_the_name(self):
        assert self._render("{{ subnet_badge(3, 'iot') }}") == '<span class="badge badge-tone-green">iot</span>'
        assert self._render("{{ subnet_badge(4, 'iot') }}") == '<span class="badge badge-tone-blue">iot</span>', (
            "the name `iot` carries no color of its own"
        )
        assert self._render("{{ subnet_badge(5, 'admin') }}") == '<span class="badge badge-tone-purple">admin</span>', (
            "a subnet NAMED admin is not the red role badge"
        )

    def test_a_filter_badge_is_a_link_to_the_id(self):
        out = self._render("{{ subnet_badge(3, 'Office', link=True) }}")
        assert out == '<a class="badge badge-tone-green" href="/leases?subnet=3" title="Show only Office">Office</a>'

    def test_a_subnet_with_no_id_is_blue_and_never_a_link(self):
        out = self._render("{{ subnet_badge(None, 'v6 net', link=True) }}")
        assert out == '<span class="badge badge-tone-blue">v6 net</span>'

    def test_the_name_is_escaped(self):
        out = self._render("{{ subnet_badge(3, name, link=True) }}".replace("name", "'<img src=x onerror=alert(1)>'"))
        assert "<img" not in out and "&lt;img" in out

    def test_every_tone_renders_its_class(self):
        for tone in subnet_tones.TONES:
            env = _env()
            env.globals["subnet_tone"] = lambda sid, t=tone: t
            out = env.from_string(
                "{% from '_subnet_badge.html' import subnet_badge %}{{ subnet_badge(1, 'x') }}"
            ).render()
            assert f"badge-tone-{tone}" in out


class TestTheToneMap:
    def test_tone_for_reads_the_map_and_defaults_to_blue(self, monkeypatch):
        monkeypatch.setattr(subnet_tones, "tones", lambda: {2: "red"})
        assert subnet_tones.tone_for(2) == "red"
        assert subnet_tones.tone_for(9) == "blue"
        assert subnet_tones.tone_for("2") == "red"
        assert subnet_tones.tone_for(None) == "blue" and subnet_tones.tone_for("abc") == "blue"

    def test_an_unreadable_table_is_blue_everywhere_not_a_failed_page(self, monkeypatch):
        import jen.models.db as db

        def boom():
            raise RuntimeError("down")

        monkeypatch.setattr(db, "jen_db", boom)
        assert subnet_tones._load() == {}


class TestTheRoute:
    """POST /subnets/save-badge-color (AU1 d). The note route's rule: an id Jen does not list and one the caller may not see are the ONE 404; a value that is not one of the seven is a 400."""

    URL = "/subnets/save-badge-color"

    @pytest.fixture(autouse=True)
    def _no_tone_left_over(self, db):
        def clear():
            with db.cursor() as cur:
                cur.execute("UPDATE subnet_notes SET badge_color=NULL")
            db.commit()

        clear()
        yield
        clear()

    @staticmethod
    def _stored(db, sid=1):
        with db.cursor() as cur:
            cur.execute("SELECT badge_color FROM subnet_notes WHERE subnet_id=%s", (sid,))
            row = cur.fetchone()
        db.commit()
        return row["badge_color"] if row else None

    @pytest.mark.parametrize("tone", subnet_tones.TONES)
    def test_each_of_the_seven_is_stored_and_rendered(self, logged_in_client, db, mock_kea, tone):
        r = logged_in_client.post(self.URL, data={"subnet_id": "1", "tone": tone})
        assert r.status_code == 200 and r.get_json() == {"ok": True, "tone": tone}
        assert self._stored(db) == tone
        page = logged_in_client.get("/subnets").data.decode()
        assert f"badge badge-tone-{tone} tone-btn" in page
        assert page.count('aria-pressed="true"') >= 1

    def test_an_eighth_value_is_refused_and_nothing_changes(self, logged_in_client, db, mock_kea):
        logged_in_client.post(self.URL, data={"subnet_id": "1", "tone": "green"})
        for bad in ("pink", "", "Green", "badge-production", "green; x"):
            r = logged_in_client.post(self.URL, data={"subnet_id": "1", "tone": bad})
            assert r.status_code == 400 and r.get_json()["ok"] is False
        assert self._stored(db) == "green"

    def test_an_id_that_is_not_there_and_a_non_number(self, logged_in_client, db):
        assert logged_in_client.post(self.URL, data={"subnet_id": "999", "tone": "red"}).status_code == 404
        assert logged_in_client.post(self.URL, data={"subnet_id": "x", "tone": "red"}).status_code == 400

    def test_a_hidden_subnet_is_the_same_answer_as_one_that_is_not_there(self, client, db):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[999], role="admin", username="badge_scoped")
        hidden = client.post(self.URL, data={"subnet_id": "1", "tone": "red"})
        missing = client.post(self.URL, data={"subnet_id": "424242", "tone": "red"})
        assert hidden.status_code == missing.status_code == 404
        assert hidden.get_data() == missing.get_data(), "RBAC-002: a hidden subnet is not an oracle"
        assert self._stored(db) is None

    def test_a_viewer_cannot_write_and_nothing_is_stored(self, client, db):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="viewer", username="badge_viewer")
        r = client.post(self.URL, data={"subnet_id": "1", "tone": "red"})
        assert r.status_code in (302, 403)
        assert self._stored(db) is None

    def test_a_viewer_sees_the_badge_and_no_picker(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="viewer", username="badge_viewer2")
        page = client.get("/subnets").data.decode()
        assert "badge-tone-" in page and '<span class="tone-picker">' not in page and 'class="tone-menu"' not in page
        assert 'tone-choice" data-subnet-id' not in page

    def test_the_picker_offers_the_subnets_own_name_in_each_of_the_seven(self, logged_in_client, mock_kea):
        page = logged_in_client.get("/subnets").data.decode()
        assert page.count("tone-choice") >= 7
        for tone in subnet_tones.TONES:
            assert f"badge badge-tone-{tone} tone-choice" in page
        assert "Test Network · red" in page

    def test_a_note_and_a_tone_do_not_clobber_each_other(self, logged_in_client, db):
        logged_in_client.post("/subnets/save-note", data={"subnet_id": "1", "notes": "keep me"})
        logged_in_client.post(self.URL, data={"subnet_id": "1", "tone": "purple"})
        logged_in_client.post("/subnets/save-note", data={"subnet_id": "1", "notes": "keep me too"})
        with db.cursor() as cur:
            cur.execute("SELECT notes, badge_color FROM subnet_notes WHERE subnet_id=1")
            row = cur.fetchone()
        db.commit()
        assert row == {"notes": "keep me too", "badge_color": "purple"}

    def test_the_choice_is_audited(self, logged_in_client, db):
        logged_in_client.post(self.URL, data={"subnet_id": "1", "tone": "orange"})
        with db.cursor() as cur:
            cur.execute("SELECT details FROM audit_log WHERE action='SAVE_SUBNET_BADGE_COLOR' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        db.commit()
        assert row and "orange" in row["details"]

    def test_a_pages_badge_follows_the_stored_tone_by_id(self, logged_in_client, db, mock_kea):
        """The Leases page's badge for the subnet carries the tone picked on the card (the journey in tests/e2e does the same through a browser)."""
        logged_in_client.post(self.URL, data={"subnet_id": "1", "tone": "green"})
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE address=INET_ATON('10.99.0.77')")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                "VALUES (INET_ATON('10.99.0.77'), UNHEX('AABBCCDDEE77'), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 1, 0, 'badge-host')"
            )
        db.commit()
        try:
            page = logged_in_client.get("/leases").data.decode()
            assert 'class="badge badge-tone-green"' in page and 'href="/leases?subnet=1"' in page
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE address=INET_ATON('10.99.0.77')")
            db.commit()


class TestTheHint:
    """Q208 (AX10): the first-time hint that the badge is the picker. Administrators only, only when a card renders, hidden until the page's script finds this browser has not dismissed it."""

    def test_the_admin_page_has_the_hint_hidden_with_its_close_button(self, logged_in_client, mock_kea):
        page = logged_in_client.get("/subnets").data.decode()
        m = re.search(
            r'<div class="alert alert-info alert-flash" id="tone-hint" role="note" hidden>(.*?)</div>', page, re.S
        )
        assert m, "the hint is on the administrator's page"
        assert "Click a subnet's name on its card to choose its badge color - the badge is the picker." in m.group(
            1
        ) or "Click a subnet&#39;s name" in m.group(1)
        assert 'class="alert-close" aria-label="Dismiss"' in m.group(1)
        assert "data-autofade" not in m.group(0), "a hint waits to be read"

    def test_the_script_un_hides_it_unless_this_browser_dismissed_it(self, logged_in_client, mock_kea):
        page = logged_in_client.get("/subnets").data.decode()
        assert "localStorage.getItem('jen-tone-hint') === 'seen'" in page
        assert "localStorage.setItem('jen-tone-hint', 'seen')" in page
        assert page.count("try { seen = localStorage") == 1 and "private mode" in page

    def test_a_viewer_has_no_hint(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=None, role="viewer", username="hint_viewer")
        page = client.get("/subnets").data.decode()
        assert 'id="tone-hint"' not in page

    def test_a_page_with_no_subnet_has_none(self, logged_in_client, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {})
        page = logged_in_client.get("/subnets").data.decode()
        assert 'id="tone-hint"' not in page

    def test_the_template_names_the_store_and_puts_the_hint_in_the_admin_branch_only(self):
        text = pathlib.Path("templates/subnets.html").read_text(encoding="utf-8")
        assert (
            "localStorage.getItem('jen-tone-hint')" in text and "localStorage.setItem('jen-tone-hint', 'seen')" in text
        )
        assert "{% if subnets and current_user.role in ('superadmin','admin') %}" in text
