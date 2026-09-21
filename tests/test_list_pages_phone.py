"""
tests/test_list_pages_phone.py
──────────────────────────────
v5.52.0 (Q59) — Leases, Reservations and Devices on the phone, using the Q58
vocabulary: `data-m` on every cell, a label on every filter select, the
reservation actions in an action bar, the type chips as a chip row.

The row and macro tests are pure (`py -m pytest --noconftest tests/test_list_pages_phone.py -k "not TestPages"`);
TestPages renders the real pages and needs the CI database.
"""

import pathlib
import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser

from jinja2 import Environment, FileSystemLoader

from jen.services.icons import icon
from jen.services.reltime import relative_time

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _src(name):
    return (ROOT / "templates" / name).read_text(encoding="utf-8")


class User:
    def __init__(self, role="admin"):
        self.role = role
        self.all_subnets = True
        self.is_authenticated = True


def _env():
    env = Environment(loader=FileSystemLoader(str(ROOT / "templates")))
    env.globals.update(
        icon=icon,
        csrf_token=lambda: "tok",
        get_manufacturer_icon_url=lambda m: None,
        device_type_display={"phone": ("Phone", "#00b4d8")},
        device_info={},
    )
    env.filters.update(
        hostname=lambda v: v,
        utcfmt=lambda v: "2026-09-21 10:00 UTC" if v else "—",
        utcdate=lambda v: "2026-09-21" if v else "—",
        relfmt=relative_time,
    )
    return env


class Cells(HTMLParser):
    """Collect each row's cells as (data-m, text)."""

    def __init__(self):
        super().__init__()
        self.rows, self._cell, self._depth = [], None, 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "tr":
            self.rows.append([])
        elif tag == "td" and self.rows:
            self._cell = [a.get("data-m"), ""]
            self.rows[-1].append(self._cell)

    def handle_endtag(self, tag):
        if tag == "td":
            self._cell = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell[1] += data


def _cells(html):
    p = Cells()
    p.feed(html)
    return [[(m, " ".join(t.split())) for m, t in row] for row in p.rows]


NOW = datetime.utcnow()


def _lease(**kw):
    d = {
        "ip": "10.0.0.5",
        "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": "living-tv",
        "subnet_name": "Prod",
        "subnet_id": 1,
        "has_reservation": False,
        "obtained": NOW - timedelta(hours=1),
        "expire": NOW + timedelta(days=3, hours=1),
    }
    d.update(kw)
    return d


def _render(name, **ctx):
    base = {"current_user": User(), "show_expired": False, "ipv6_enabled": False, "subnet6_map": {}}
    base.update(ctx)
    return _env().get_template(name).render(**base)


class TestLeaseRow:
    def test_cells_carry_the_vocabulary(self):
        cells = _cells(_render("_lease_rows.html", leases=[_lease()]))[0]
        assert [m for m, _ in cells] == [
            None,
            "secondary",
            "primary",
            "hide",
            "secondary",
            "hide",
            "secondary",
            "trailing",
        ]

    def test_primary_is_the_hostname_and_secondary_the_ip_subnet_expiry(self):
        cells = _cells(_render("_lease_rows.html", leases=[_lease()]))[0]
        assert "living-tv" in cells[2][1]
        assert cells[1][1] == "10.0.0.5" and cells[4][1] == "Prod"
        assert "in 3 d" in cells[6][1]  # the phone rendering of the expiry sits beside the full timestamp

    def test_expiry_has_both_renderings_and_the_mac_moves_into_the_menu(self):
        html = _render("_lease_rows.html", leases=[_lease()])
        assert '<span class="desk-only">2026-09-21 10:00 UTC</span><span class="phone-only">in 3 d</span>' in html
        assert 'action-menu-item disabled mono">aa:bb:cc:dd:ee:ff<' in html

    def test_a_viewer_gets_no_checkbox_or_kebab(self):
        cells = _cells(_render("_lease_rows.html", leases=[_lease()], current_user=User("viewer")))[0]
        assert [m for m, _ in cells] == ["secondary", "primary", "hide", "secondary", "hide", "secondary"]

    def test_the_empty_state_row_spans_the_line(self):
        cells = _cells(_render("_lease_rows.html", leases=[]))[0]
        assert cells[0][0] == "full"


def _res(**kw):
    d = {
        "host_id": 7,
        "ip": "10.0.0.9",
        "mac": "aa:bb:cc:00:00:01",
        "hostname": "printer",
        "subnet_name": "Prod",
        "subnet_id": 1,
        "is_conflict": False,
        "is_active": True,
        "dns_override": "",
        "notes": "",
    }
    d.update(kw)
    return d


class TestReservationRow:
    def _cells(self, **kw):
        return _cells(_render("_reservation_row.html", h=_res(**kw)))[0]

    def test_vocabulary(self):
        assert [m for m, _ in self._cells()] == [
            None,
            "secondary",
            "primary",
            "hide",
            "secondary",
            "secondary",
            "hide",
            "hide",
            "trailing",
        ]

    def test_dns_override_and_notes_show_only_when_set(self):
        cells = self._cells(dns_override="a.example", notes="front desk")
        assert cells[6][0] == "secondary" and cells[7][0] == "secondary"

    def test_status_is_secondary_and_conflict_still_reads(self):
        cells = self._cells(is_conflict=True)
        assert cells[5][0] == "secondary" and "Conflict" in cells[5][1]


def _dev(**kw):
    d = {
        "id": 3,
        "mac": "aa:bb:cc:00:00:02",
        "device_name": "Matt's iPhone",
        "owner": "",
        "last_ip": "10.0.0.7",
        "last_hostname": "matts-iphone",
        "subnet_name": "Prod",
        "manufacturer": "Apple",
        "device_type": "phone",
        "device_icon": "",
        "first_seen": NOW - timedelta(days=30),
        "last_seen": NOW - timedelta(hours=2),
        "is_stale": False,
        "has_reservation": False,
        "v6_addresses": [],
        "notes": "",
        "type_override_key": "",
        "icon_override_key": "",
    }
    d.update(kw)
    return d


class TestDeviceRow:
    def _cells(self, **kw):
        return _cells(
            _render(
                "_device_rows.html", devices=[_dev(**kw)], v6_duid_only=[], stale_days=30, show_stale=False, search=""
            )
        )[0]

    def test_a_named_device_shows_its_name_and_hides_the_hostname(self):
        cells = self._cells()
        assert [m for m, _ in cells] == [
            None,
            "hide",
            "primary",
            "hide",
            "secondary",
            "hide",
            "hide",
            "badge",
            "hide",
            "secondary",
            "hide",
            "trailing",
        ]

    def test_an_unnamed_device_promotes_its_hostname(self):
        cells = self._cells(device_name="")
        assert cells[5][0] == "primary" and "matts-iphone" in cells[5][1]

    def test_owner_shows_only_when_set(self):
        assert self._cells()[3][0] == "hide"
        assert self._cells(owner="Matt")[3][0] == "secondary"

    def test_last_seen_is_relative_on_a_phone_and_warns_when_stale(self):
        html = _render(
            "_device_rows.html",
            devices=[_dev(is_stale=True)],
            v6_duid_only=[],
            stale_days=30,
            show_stale=False,
            search="",
        )
        assert '<span class="phone-only">2 h ago</span>' in html
        assert 'class="mono hide-tablet warn"' in html

    def test_a_duid_only_row_keeps_its_hostname_and_badge(self):
        duid = {"duid_hex": "00ff", "hostname": "v6-only", "subnet_name": "Prod", "addresses": [], "last_expire": NOW}
        html = _render("_device_rows.html", devices=[], v6_duid_only=[duid], stale_days=30, show_stale=False, search="")
        modes = [m for m, _ in _cells(html)[0]]
        assert "primary" in modes and "badge" in modes


class TestSourceShape:
    def test_the_three_results_tables_are_rowlists_not_mobile_cards(self):
        for f in ("_leases_results.html", "_reservations_results.html", "_devices_results.html"):
            src = _src(f)
            assert 'class="sortable rowlist"' in src and "mobile-cards" not in src, f

    def test_no_data_label_left_in_the_converted_rows(self):
        for f in ("_lease_rows.html", "_reservation_row.html", "_device_rows.html"):
            assert "data-label" not in _src(f), f

    def test_inline_styles_gone_from_the_converted_partials(self):
        for f in (
            "_lease_rows.html",
            "_reservation_row.html",
            "_leases_results.html",
            "_reservations_results.html",
            "_devices_results.html",
            "leases.html",
            "reservations.html",
        ):
            assert 'style="' not in _src(f), f

    def test_every_filter_select_has_a_label(self):
        for f in ("leases.html", "reservations.html", "devices.html"):
            for m in re.finditer(r"<select\b[^>]*>", _src(f)):
                tag = m.group(0)
                if 'id="edit' in tag:  # the Edit Device modal's own form field, labelled by its <label>
                    continue
                assert "aria-label=" in tag, (f, tag)

    def test_the_search_input_is_tagged_primary(self):
        for f in ("leases.html", "reservations.html", "devices.html"):
            for m in re.finditer(r'<input type="text" name="search"[^>]*>', _src(f)):
                assert 'data-m="primary"' in m.group(0), (f, m.group(0))

    def test_sort_controls_are_in_each_v4_filter_form(self):
        for f in ("leases.html", "reservations.html", "devices.html"):
            assert "sort_controls(" in _src(f), f
        macro = _src("_sort_controls.html")
        assert 'aria-label="Sort"' in macro and 'aria-label="Order"' in macro and "data-nocount" in macro

    def test_reservations_primary_action_lives_in_an_action_bar(self):
        src = _src("reservations.html")
        bar = re.search(r'<div class="action-bar">(.*?)\n</div>', src, re.S).group(1)
        assert "btn-primary" in bar and "Export CSV" in bar and "Dry-run Import" in bar

    def test_type_chips_are_a_chip_row(self):
        assert 'id="type-filter-bar" class="chip-row' in _src("devices.html")

    def test_stale_days_moved_into_the_filter_bar_with_a_label(self):
        src = _src("devices.html")
        assert 'aria-label="Stale after (days)"' in src
        assert "page-header-flex" not in src and 'class="page-header" style' not in src

    def test_row_tap_opens_the_menu_or_ticks_the_box(self):
        base = _src("base.html")
        assert "menu.checked = !menu.checked" in base and "box.checked = !box.checked" in base


class TestRelativeTime:
    def test_future_and_past(self):
        now = datetime.utcnow()  # the clock is passed in, so a slow suite cannot skew the result
        at = lambda **kw: relative_time(now + timedelta(**kw), now=now.replace(tzinfo=timezone.utc))  # noqa: E731
        assert at(days=3, hours=2) == "in 3 d"
        assert at(hours=-5, minutes=-1) == "5 h ago"
        assert at(minutes=-7, seconds=-5) == "7 min ago"
        assert at(seconds=10) == "now"

    def test_empty_and_junk(self):
        assert relative_time(None) == "—"
        assert relative_time("not a date") == "not a date"


class TestPages:
    def test_leases_page(self, logged_in_client):
        html = logged_in_client.get("/leases").data.decode()
        assert 'class="sortable rowlist"' in html
        for label in ("Subnet", "Time", "Rows per page", "Sort", "Order", "Saved filters"):
            assert f'aria-label="{label}"' in html, label

    def test_reservations_page(self, logged_in_client):
        html = logged_in_client.get("/reservations").data.decode()
        assert 'class="sortable rowlist"' in html
        assert re.search(r'<div class="action-bar">\s*<a href="/reservations/add" class="btn btn-primary">', html)
        for label in ("Subnet", "Status", "Rows per page", "Sort", "Order"):
            assert f'aria-label="{label}"' in html, label

    def test_devices_page(self, logged_in_client):
        html = logged_in_client.get("/devices").data.decode()
        assert 'class="sortable rowlist"' in html and 'class="chip-row' in html
        assert 'name="stale_days"' in html and 'aria-label="Stale after (days)"' in html

    def test_a_filter_change_keeps_the_sort(self, logged_in_client):
        html = logged_in_client.get("/devices?sort=owner&dir=asc").data.decode()
        assert re.search(r'<option value="owner" selected>', html)
        assert re.search(r'<option value="asc" selected>', html)

    def test_relfmt_filter_is_registered(self, app):
        assert "relfmt" in app.jinja_env.filters
