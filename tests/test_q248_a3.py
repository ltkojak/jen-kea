"""
tests/test_q248_a3.py
─────────────────────
Q248, stage a3 - the lists (Leases, Reservations, Devices, Logs), wide monitors and the way back on detail pages: what a rendered page and the routes can hold. The
layout itself (no sideways scroll, a clipped cell, the columns at 1024 px, the phone card, the bars at 2560 px) is measured in a browser, tests/e2e/test_q248_a3.py;
the navigation model of the detail pages is in tests/test_settings_ia.py.

* V12  a value a client or an operator chose is written in a `.clip` with its whole text as the title, on the four lists.
* V13  a date, a time and a status badge never wrap; a list never drops the column it is sorted by.
* V48  the list search boxes: a placeholder of two words, what it listed in the field's title and accessible name.
* V51  the MAC cell is the phone card's third line on the three lists; a device card keeps its subnet and its status.
* V54  a table page asks for the wide column; forms, settings and About do not; the top row and the strip get the same column.
* addition 4  Trace and Saved searches keep their parent's strip and start with one back link.
* addition 5  a lease row carries "Reserved" and "Expires soon"; the summary's two counts are filters (`?reserved=1`, `?expiring=1`), each one more condition of
              the list's own query inside the caller's subnet restriction, kept by every sort and page link; the expiry is a relative time with the exact one as its title.
"""

import pathlib
import re

import pytest

from tests.conftest import restricted_client

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = (ROOT / "templates" / "base.html").read_text(encoding="utf-8")
HX = {"HX-Request": "true"}
LONG = "conference-room-display-with-a-very-long-descriptive-hostname-b2.lab.example.internal"
LONG_NAME = "Wall display, north side, by the door, behind the plant, above the radiator"


def _src(name):
    return (ROOT / "templates" / name).read_text(encoding="utf-8")


def _body(c, path, **kw):
    r = c.get(path, **kw)
    assert r.status_code == 200, (path, r.status_code)
    return r.get_data(as_text=True)


def _summary_html(body):
    at = body.index('<p class="results-summary"')
    return body[at : body.index("</p>", at)]


def _summary(body):
    m = re.search(r'<p class="results-summary"[^>]*>(.*?)</p>', body, re.S)
    return " ".join(re.sub(r"<[^>]+>", "", m.group(1)).split()) if m else None


def _table(body):
    """The list's own table (base.html's stylesheet and script name table elements in their comments, so nothing here searches the whole page for one)."""
    at = re.search(r'<table class="[^"]*rowlist[^"]*">', body).start()
    return body[at : body.index("</table>", at)]


def _head(body):
    table = _table(body)
    return table[table.index("<thead>") : table.index("</thead>")]


def _tbody(body):
    table = _table(body)
    return table[table.index("<tbody") : table.index("</tbody>")]


def _rows(body):
    """The table body's rows, each as its HTML."""
    return re.findall(r"<tr[ >].*?</tr>", _tbody(body), re.S)


def _row(body, needle):
    hits = [r for r in _rows(body) if needle in r]
    assert len(hits) == 1, (needle, len(hits))
    return hits[0]


def _hosts(body):
    """The hostnames the lease list shows, in order (each is the title of its clip)."""
    return re.findall(r'<span class="clip" title="([^"]+)">', _tbody(body))


SEED_MACS = ("AABBCC248301", "AABBCC248302", "AABBCC248303", "AABBCC248304", "AABBCC248305", "AABBCC248306")


def _wipe(cur):
    marks = ",".join(["%s"] * len(SEED_MACS))
    cur.execute(f"DELETE FROM lease4 WHERE HEX(hwaddr) IN ({marks})", SEED_MACS)  # nosec B608 - test seed
    cur.execute(f"DELETE FROM hosts WHERE HEX(dhcp_identifier) IN ({marks})", SEED_MACS)  # nosec B608 - test seed


@pytest.fixture
def leases(db):
    """Subnet 1: `soon-a` expires in 30 minutes; `resv-b` in 3 hours and has a reservation in subnet 1; `both-c` expires in 20 minutes and has a reservation in
    subnet 1; `moved-d` in 5 hours, and its only reservation is in subnet 2 (the client that moved); `gone-e` expired an hour ago. Subnet 2 (which the test
    configuration does not list, so no restricted account may see it): `hidden-f` expires in 10 minutes and has a reservation in subnet 2."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4")
        _wipe(cur)
        for ip, mac, host, expire, subnet in (
            ("10.99.0.71", SEED_MACS[0], "soon-a", "DATE_ADD(NOW(), INTERVAL 30 MINUTE)", 1),
            ("10.99.0.72", SEED_MACS[1], "resv-b", "DATE_ADD(NOW(), INTERVAL 3 HOUR)", 1),
            ("10.99.0.73", SEED_MACS[2], "both-c", "DATE_ADD(NOW(), INTERVAL 20 MINUTE)", 1),
            ("10.99.0.74", SEED_MACS[3], "moved-d", "DATE_ADD(NOW(), INTERVAL 5 HOUR)", 1),
            ("10.99.0.75", SEED_MACS[4], "gone-e", "DATE_SUB(NOW(), INTERVAL 1 HOUR)", 1),
            ("10.98.0.76", SEED_MACS[5], "hidden-f", "DATE_ADD(NOW(), INTERVAL 10 MINUTE)", 2),
        ):
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                f"VALUES (INET_ATON(%s), UNHEX(%s), 3600, {expire}, %s, 0, %s)",  # nosec B608 - test seed
                (ip, mac, subnet, host),
            )
        for mac, subnet, ip in (
            (SEED_MACS[1], 1, "10.99.0.72"),
            (SEED_MACS[2], 1, "10.99.0.73"),
            (SEED_MACS[3], 2, "10.98.0.74"),
            (SEED_MACS[5], 2, "10.98.0.76"),
        ):
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), 'q248a3')",
                (mac, subnet, ip),
            )
    db.commit()
    yield
    with db.cursor() as cur:
        _wipe(cur)
    db.commit()


# ───────────────────────────── addition 5 (a): the marks ─────────────────────────────


class TestLeaseRowsShowWhatTheSummaryCounts:
    def test_a_reserved_lease_says_reserved_and_one_that_is_not_does_not(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases")
        assert '<span class="badge badge-reserved row-mark">Reserved</span>' in _row(body, "resv-b")
        assert ">Reserved<" not in _row(body, "soon-a")
        # the row says it ONCE as words a person reads (its tick box's tooltip is not on the page's face)
        assert len(re.findall(r">Reserved<", _row(body, "resv-b"))) == 1

    def test_a_lease_inside_its_last_hour_says_expires_soon(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases")
        assert '<span class="badge badge-stale row-mark">Expires soon</span>' in _row(body, "soon-a")
        assert "Expires soon" in _row(body, "both-c") and ">Reserved<" in _row(body, "both-c")
        assert "Expires soon" not in _row(body, "resv-b") and "Expires soon" not in _row(body, "moved-d")

    def test_the_marks_are_the_live_lists(self, logged_in_client, leases):
        """The history has no count of either, and an expired row is not "about to expire"."""
        body = _body(logged_in_client, "/leases?expired=1")
        assert "gone-e" in _tbody(body) and "row-mark" not in _tbody(body)

    def test_the_number_of_marks_is_the_number_the_summary_says(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases")
        text = _summary(body)
        # resv-b, both-c, moved-d and hidden-f are reserved (an unrestricted account counts every reservation); soon-a, both-c and hidden-f expire within the hour
        assert text == "5 active leases · 3 expire within the hour · 4 reserved", text
        assert body.count(">Reserved</span>") == 4 and body.count(">Expires soon</span>") == 3

    def test_a_reservation_in_a_subnet_the_caller_cannot_see_is_not_marked(self, client, db, leases):
        """`moved-d` is in subnet 1 and its only reservation is in subnet 2: an account scoped to subnet 1 reads no mark on it, as it reads no count of it."""
        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="q248a3_mark_viewer")
        body = _body(client, "/leases")
        assert ">Reserved<" in _row(body, "resv-b")
        assert ">Reserved<" not in _row(body, "moved-d")
        assert _summary(body) == "4 active leases · 2 expire within the hour · 2 reserved"

    def test_the_expiry_is_a_relative_time_with_the_exact_one_as_its_title(self, logged_in_client, leases):
        row = _row(_body(logged_in_client, "/leases"), "resv-b")
        m = re.search(
            r'<span title="(20\d\d-\d\d-\d\d \d\d:\d\d UTC)"><time datetime="[0-9T:-]+Z" data-jen-time="rel">in (2|3) h</time></span>',
            row,
        )
        assert m, row
        assert "desk-only" not in row and "phone-only" not in row, "one rendering at every width"

    def test_the_rewriter_gives_a_relative_time_its_exact_moment(self):
        """`title` in the reader's zone or in UTC (format() follows the Display menu's pick), `data-jen-utc` for a tap on a touch screen."""
        at = BASE.index("if (kind === 'rel') {")
        block = BASE[at : at + 900]
        assert "el.setAttribute('title', format(el.getAttribute('datetime'), 'fmt'));" in block
        assert "el.setAttribute('data-jen-utc'," in block
        assert "if (kind === 'rel') return;" not in BASE


# ───────────────────────────── addition 5 (b): the two filters ─────────────────────────────


class TestTheSummarysCountsAreFilters:
    def test_reserved_lists_only_the_reserved_leases(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases?reserved=1&sort=ip&dir=asc")
        assert _hosts(body) == ["hidden-f", "resv-b", "both-c", "moved-d"]
        assert _summary(body).startswith("4 active leases")

    def test_expiring_lists_only_the_leases_inside_their_last_hour(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases?expiring=1&sort=hostname&dir=asc")
        assert _hosts(body) == ["both-c", "hidden-f", "soon-a"]
        assert _summary(body).startswith("3 active leases")

    def test_both_are_both(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases?reserved=1&expiring=1&sort=ip&dir=asc")
        assert _hosts(body) == ["hidden-f", "both-c"]

    def test_any_value_but_1_is_no_filter(self, logged_in_client, leases):
        for query in ("reserved=0", "reserved=yes", "expiring=", "reserved=1%27%20OR%201=1"):
            assert len(_hosts(_body(logged_in_client, "/leases?" + query))) == 5, query

    def test_each_filter_is_one_more_condition_of_the_other_filters(self, logged_in_client, leases):
        assert _hosts(_body(logged_in_client, "/leases?reserved=1&search=resv")) == ["resv-b"]
        assert _hosts(_body(logged_in_client, "/leases?expiring=1&subnet=1&sort=ip&dir=asc")) == ["soon-a", "both-c"]

    def test_the_counts_are_links_that_keep_the_filters_and_the_sort_in_force(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases?search=10.99&subnet=1&sort=ip&dir=asc&per_page=50")
        line = body[body.index('id="leases-summary"') : body.index("</p>", body.index('id="leases-summary"'))]
        keep = "?sort=ip&amp;dir=asc&amp;subnet=1&amp;minutes=&amp;search=10.99&amp;expired=0&amp;per_page=50"
        assert (
            f'<a class="summary-filter" href="{keep}&amp;expiring=1" title="Show only these leases">2 expire within the hour</a>'
            in line
        )
        assert (
            f'<a class="summary-filter" href="{keep}&amp;reserved=1" title="Show only these leases">3 reserved</a>'
            in line
        )

    def test_a_filter_in_force_is_a_chip_that_takes_it_away_and_keeps_the_other(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases?reserved=1&expiring=1&per_page=50")
        line = body[body.index('id="leases-summary"') : body.index("</p>", body.index('id="leases-summary"'))]
        keep = "?sort=expires&amp;dir=desc&amp;subnet=all&amp;minutes=&amp;search=&amp;expired=0&amp;per_page=50"
        assert (
            f'<a class="filter-chip" href="{keep}&amp;reserved=1" title="Remove this filter">Expiring soon only' in line
        )
        assert f'<a class="filter-chip" href="{keep}&amp;expiring=1" title="Remove this filter">Reserved only' in line
        assert _summary(body) == "2 active leases · Expiring soon only · Reserved only"

    def test_every_sort_link_and_every_page_link_keeps_them(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases?expiring=1&reserved=1&per_page=1")
        links = re.findall(r'(?:href|hx-get)="(\?sort=[^"]+)"', _head(body))
        assert len(links) == 12 and all(link.endswith("&amp;reserved=1&amp;expiring=1") for link in links), links
        paged = _body(logged_in_client, "/leases?expiring=1&per_page=1")
        pages = re.findall(r'(?:href|hx-get)="(\?page=[^"]+)"', paged)
        assert pages and all(p.endswith("&amp;expiring=1") for p in pages), pages
        # and a list with neither filter has neither in any sort or page link
        plain = _body(logged_in_client, "/leases?per_page=1")
        links = re.findall(
            r'(?:href|hx-get)="(\?(?:sort|page)=[^"]+)"', plain[plain.index('<table class="sortable rowlist">') :]
        )
        assert len(links) > 12 and not [link for link in links if "expiring" in link or "reserved" in link]

    def test_the_htmx_refresh_keeps_them(self, logged_in_client, leases):
        """The filter form's refresh sends the form's fields; the two filters are fields of it."""
        partial = _body(
            logged_in_client,
            "/leases?subnet=all&minutes=&search=&reserved=1&per_page=all&sort=ip&dir=asc&expired=0",
            headers=HX,
        )
        assert "<html" not in partial and _hosts(partial) == ["hidden-f", "resv-b", "both-c", "moved-d"]
        page = _body(logged_in_client, "/leases?reserved=1")
        form = page[
            page.index('<form method="GET" class="contents"') : page.index("</form>", page.index('hx-get="/leases"'))
        ]
        assert re.search(r'<input type="checkbox" name="reserved" value="1" checked>\s*Reserved only</label>', form)
        assert re.search(r'<input type="checkbox" name="expiring" value="1" >\s*Expiring soon only</label>', form)

    def test_the_history_has_neither_filter(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases?expired=1&reserved=1&expiring=1")
        assert len(_hosts(body)) == 6, "the history lists every lease row"
        assert 'name="reserved"' not in body and 'name="expiring"' not in body
        assert "filter-chip" not in _summary_html(body) and "row-mark" not in _tbody(body)
        # no sort link of the history carries a filter the history does not have
        assert not [
            link
            for link in re.findall(r'(?:href|hx-get)="(\?sort=[^"]+)"', _head(body))
            if "reserved" in link or "expiring" in link
        ]

    def test_a_filter_that_matches_nothing_says_so_and_clear_filters_clears_it(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases?reserved=1&expiring=1&search=soon-a&per_page=100")
        assert "No active leases with a reservation expiring within the hour match “soon-a”" in body
        assert body.count("Clear filters") == 1
        assert 'href="/leases?per_page=100&amp;sort=expires&amp;dir=desc"' in body

    def test_the_clear_button_names_neither(self, logged_in_client, leases):
        body = _body(logged_in_client, "/leases?reserved=1")
        assert '<a href="/leases" class="btn btn-secondary">Clear</a>' in body


class TestTheFiltersStayInsideTheCallersSubnets:
    def test_a_restricted_account_sees_only_its_own_subnets_rows_under_each_filter(self, client, db, leases):
        restricted_client(client, db, allowed_subnets=[1], role="admin", username="q248a3_filter_admin")
        # `hidden-f` (subnet 2) expires in ten minutes and is reserved: it is in neither list
        assert _hosts(_body(client, "/leases?expiring=1&sort=ip&dir=asc")) == ["soon-a", "both-c"]
        # `moved-d` is the caller's own lease, but its only reservation is in subnet 2: "reserved" is what the caller's own count counts
        assert _hosts(_body(client, "/leases?reserved=1&sort=ip&dir=asc")) == ["resv-b", "both-c"]
        assert _hosts(_body(client, "/leases?reserved=1&expiring=1")) == ["both-c"]
        both = _body(client, "/leases?reserved=1")
        assert "hidden-f" not in both and "10.98.0.76" not in both
        assert _summary(both) == "2 active leases · 1 expires within the hour · Reserved only"

    def test_the_restricted_filter_and_the_restricted_count_agree(self, client, db, leases):
        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="q248a3_filter_viewer")
        count = int(re.search(r"(\d+) reserved", _summary(_body(client, "/leases"))).group(1))
        assert len(_hosts(_body(client, "/leases?reserved=1"))) == count == 2

    def test_an_account_with_no_subnet_sees_nothing_under_either(self, client, db, leases):
        restricted_client(client, db, allowed_subnets=[], role="viewer", username="q248a3_filter_none")
        for query in ("reserved=1", "expiring=1", "reserved=1&expiring=1"):
            body = _body(client, "/leases?" + query)
            assert _hosts(body) == [] and "10.99.0.7" not in body and "10.98.0.7" not in body, query

    def test_a_subnet_filter_the_caller_may_not_use_does_not_widen_it(self, client, db, leases):
        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="q248a3_filter_edge")
        assert _hosts(_body(client, "/leases?subnet=2&reserved=1&sort=ip&dir=asc")) == ["resv-b", "both-c"]

    def test_the_unrestricted_account_reads_every_reservation(self, logged_in_client, leases):
        assert "moved-d" in _hosts(_body(logged_in_client, "/leases?reserved=1"))
        assert "hidden-f" in _hosts(_body(logged_in_client, "/leases?reserved=1&expiring=1&sort=ip&dir=asc"))

    def test_the_conditions_are_fixed_text_with_one_parameter(self):
        from jen.routes import leases as mod

        assert mod.EXPIRING_SOON == "l.expire <= NOW() + INTERVAL 1 HOUR"
        assert mod.RESERVED_ANY.count("%s") == 0 and mod.RESERVED_VISIBLE.count("%s") == 1
        assert (
            "h.dhcp_identifier = l.hwaddr" in mod.RESERVED_ANY
            and "h.dhcp_identifier = l.hwaddr" in mod.RESERVED_VISIBLE
        )
        src = (ROOT / "jen" / "routes" / "leases.py").read_text(encoding="utf-8")
        # one definition of "expires within the hour": the count, the mark and the filter read the constant
        assert src.count("INTERVAL 1 HOUR") == 1


# ───────────────────────────── V12: a long value ─────────────────────────────


@pytest.fixture
def long_values(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)='AABBCC2483A1'")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCC2483A2'")
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
            "VALUES (INET_ATON('10.99.0.81'), UNHEX('AABBCC2483A1'), 3600, DATE_ADD(NOW(), INTERVAL 2 HOUR), 1, 0, %s)",
            (LONG,),
        )
        cur.execute(
            "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
            "VALUES (UNHEX('AABBCC2483A2'), 0, 1, INET_ATON('10.99.0.82'), %s)",
            (LONG,),
        )
        cur.execute(
            "INSERT INTO devices (mac, device_name, owner, last_ip, last_hostname, last_subnet_id, manufacturer, device_type, first_seen, last_seen) "
            "VALUES ('aa:bb:cc:24:83:a3', %s, %s, '10.99.0.83', %s, 1, %s, 'tv', NOW(), NOW())",
            (
                LONG_NAME,
                "Facilities and audio visual",
                LONG,
                "Shenzhen Extremely Long Manufacturer Name Technology Co., Ltd.",
            ),
        )
        cur.execute(
            "INSERT INTO audit_log (user_id, username, action, entity, details, ip_address) VALUES (1, 'admin', 'EDIT_SUBNET', 'subnets', %s, '10.0.0.9')",
            ("Changed the pool of subnet 1 and its lease time; " * 6,),
        )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)='AABBCC2483A1'")
        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCC2483A2'")
    db.commit()


class TestALongValueIsClipped:
    def test_the_length_this_file_uses_is_the_look_overs(self):
        assert len(LONG) == 85

    def test_a_printout_shows_the_whole_value(self):
        """Paper has no hover: the print sheet takes the one-line cut away."""
        sheet = (ROOT / "static" / "css" / "print.css").read_text(encoding="utf-8")
        rule = re.search(r"\n\s*\.clip \{([^}]*)\}", sheet).group(1)
        assert "-webkit-line-clamp: unset" in rule and "overflow: visible" in rule and "max-width: none" in rule

    def test_the_rule_cuts_one_line_and_lets_the_value_break_anywhere(self):
        rule = re.search(r"\n\s*\.clip \{([^}]*)\}", BASE).group(1)
        for part in (
            "-webkit-line-clamp: 1",
            "overflow: hidden",
            "word-break: break-all",
            "white-space: normal",
            "min-width: 0",
        ):
            assert part in rule, part
        assert re.search(r"\.clip-row > \* \{ flex: none; \}", BASE) and re.search(
            r"\.clip-row > \.clip \{ flex: 0 1 auto; \}", BASE
        )

    @pytest.mark.parametrize("path", ["/leases", "/reservations"])
    def test_a_hostname_is_a_clip_with_its_whole_text_as_the_title(self, logged_in_client, long_values, path):
        row = _row(_body(logged_in_client, path), LONG)
        assert f'<span class="clip" title="{LONG}">{LONG}</span>' in row
        # the name and what follows it are one row: the vendor badge and the Investigate button keep their size
        assert re.search(r'<div class="clip-row">\s*<span class="clip"', row)

    def test_a_device_name_an_owner_and_a_hostname_are_clips(self, logged_in_client, long_values):
        row = _row(_body(logged_in_client, "/devices"), "aa:bb:cc:24:83:a3")
        name = LONG_NAME
        assert re.search(r'<span id="dname-\d+" class="clip" title="' + re.escape(name) + '">', row)
        assert re.search(r'<span id="downer-\d+" class="clip" title="Facilities and audio visual">', row)
        assert f'<span class="clip" title="{LONG}">{LONG}</span>' in row
        # the vendor's badge is capped and its name cut; the whole name is the badge's title
        assert (
            '<span class="mfr-badge mfr-badge-lg vendor-badge" title="Shenzhen Extremely Long Manufacturer Name Technology Co., Ltd."'
            in row
        )
        assert '<span class="vendor-name">Shenzhen Extremely Long Manufacturer Name Technology Co., Ltd.</span>' in row

    def test_a_device_with_no_name_has_no_empty_title(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) VALUES ('aa:bb:cc:24:83:a4', '10.99.0.84', 'plain', 1, NOW(), NOW())"
            )
        db.commit()
        row = _row(_body(logged_in_client, "/devices"), "aa:bb:cc:24:83:a4")
        assert re.search(r'<span id="dname-\d+" class="clip">—</span>', row)

    def test_an_audit_events_details_are_a_clip_that_opens_where_it_is(self, logged_in_client, long_values):
        body = _body(logged_in_client, "/settings/logs")
        details = "Changed the pool of subnet 1 and its lease time; " * 6
        assert f'<span class="clip" data-clip-toggle title="{details}">{details}</span>' in body
        assert "e.target.closest('.clip[data-clip-toggle]')" in BASE and "classList.toggle('clip-open')" in BASE
        assert re.search(r"\.clip\.clip-open \{[^}]*-webkit-line-clamp: unset", BASE)


# ───────────────────────────── V13: what never wraps, what is never dropped ─────────────────────────────


class TestTheListsAtNarrowWidths:
    def test_a_date_and_a_badge_never_wrap(self):
        assert "table.rowlist time, table.rowlist .badge { white-space: nowrap; }" in BASE

    def test_a_subnets_badge_on_one_line_is_capped(self):
        """A subnet's name is the operator's own words: a badge that no longer wraps must not be able to widen its column without limit."""
        rule = re.search(r'table\.rowlist \.badge\[class\*="badge-tone-"\] \{([^}]*)\}', BASE).group(1)
        assert "max-width: 28ch" in rule and "overflow: hidden" in rule and "text-overflow: ellipsis" in rule

    def test_the_hide_classes_are_screen_rules_between_the_phone_and_their_width(self):
        assert re.search(
            r"@media screen and \(max-width: 1439px\) and \(min-width: 769px\) \{\s*\.hide-below-1440 \{ display: none !important; \}",
            BASE,
        )
        assert re.search(
            r"@media screen and \(max-width: 1279px\) and \(min-width: 769px\) \{\s*\.hide-below-1280 \{ display: none !important; \}",
            BASE,
        )

    @staticmethod
    def _th(src, label):
        """The opening <th ...> of the header whose text starts with `label`."""
        hits = [
            m.group(1)
            for m in re.finditer(r"(<th\b[^>]*>)(?:<a\b[^>]*>)?([^<{]*)", src)
            if m.group(2).strip().startswith(label)
        ]
        assert len(hits) == 1, (label, hits)
        return hits[0]

    def test_devices_keeps_last_seen_and_drops_first_seen_first(self):
        src = _src("_devices_results.html")
        assert "hide-" not in self._th(src, "Last Seen"), "the column the list is sorted by is never dropped"
        assert "hide-below-1440" in self._th(src, "First Seen") and "hide-below-1440" in self._th(src, "Owner")
        assert "hide-below-1280" in self._th(src, "Type")
        # (a header's hide-mobile says nothing: a phone shows no header row at all)
        assert "hide-below" not in self._th(src, "Status") and "hide-tablet" not in self._th(src, "Status")
        assert src.count("<th></th>") == 1, "the row menu's column carries no class that hides it"

    def test_devices_sorts_by_last_seen_by_default(self, logged_in_client):
        body = _body(logged_in_client, "/devices")
        assert re.search(r'<th aria-sort="(?:ascending|descending)"><a href="\?sort=last_seen', body)

    def test_leases_keeps_expires_and_drops_obtained(self):
        src = _src("_leases_results.html")
        assert re.search(r"<th\{% if sort=='expires' %\}", src), "Expires carries no class at all"
        assert re.search(r"<th class=\"hide-mobile hide-below-1280\"\{% if sort=='obtained' %\}", src)
        rows = _src("_lease_rows.html")
        assert '<td class="mono muted hide-mobile hide-below-1280" data-m="hide">{{ l.obtained|utcfmt }}</td>' in rows
        assert "hide-tablet" not in src and "hide-tablet" not in rows

    def test_the_cells_of_a_dropped_column_carry_the_headers_class(self, logged_in_client, db):
        """A header hidden without its cells (or the other way) shifts every column after it."""
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, device_name, owner, last_ip, last_hostname, last_subnet_id, manufacturer, device_type, first_seen, last_seen) "
                "VALUES ('aa:bb:cc:24:83:a5', 'Named', 'Someone', '10.99.0.85', 'named-host', 1, 'Acme', 'tv', NOW(), NOW())"
            )
        db.commit()
        body = _body(logged_in_client, "/devices")
        head = re.findall(r"<th\b([^>]*)>", _head(body))
        cells = re.findall(r"<td\b([^>]*)>", _row(body, "aa:bb:cc:24:83:a5").split('<div class="action-menu">')[0])
        assert len(head) == len(cells)
        for th, td in zip(head, cells, strict=True):
            for cls in ("hide-below-1440", "hide-below-1280", "hide-tablet"):
                assert (cls in th) == (cls in td), (cls, th, td)

    def test_a_reservations_status_never_breaks(self):
        assert '<td class="nowrap" data-m="secondary">' in _src("_reservation_row.html")


# ───────────────────────────── V48: the list search boxes ─────────────────────────────


class TestTheListSearchBoxes:
    @pytest.mark.parametrize(
        "path,placeholder,title",
        [
            ("/leases", "Search leases", "Search by IP address, hostname or MAC address"),
            ("/reservations", "Search", "Search by IP address, hostname or MAC address"),
            ("/devices", "Search devices", "Search by MAC address, name, owner or IP address"),
        ],
    )
    def test_the_placeholder_is_one_or_two_words_and_the_field_says_the_rest(
        self, logged_in_client, path, placeholder, title
    ):
        body = _body(logged_in_client, path)
        tag = re.search(r'<input type="text" name="search"[^>]*>', body).group(0)
        assert f'placeholder="{placeholder}"' in tag
        assert f'title="{title}"' in tag and f'aria-label="{title}"' in tag
        assert 'data-m="primary"' in tag

    def test_no_list_template_keeps_a_placeholder_that_lists_its_fields(self):
        for name in ("leases.html", "reservations.html", "devices.html"):
            for tag in re.findall(r'<input type="text" name="search"[^>]*>', _src(name)):
                placeholder = re.search(r'placeholder="([^"]*)"', tag).group(1)
                assert len(placeholder.split()) <= 2 and "," not in placeholder and "..." not in placeholder, (
                    name,
                    placeholder,
                )
                assert "title=" in tag and "aria-label=" in tag, (name, tag)

    def test_the_phones_select_button_keeps_its_own_width(self):
        assert ".fs-ready .select-toggle { flex: none; }" in BASE


# ───────────────────────────── V51: the phone card ─────────────────────────────


class TestThePhoneCardShowsTheMac:
    def test_the_third_line_is_a_rule_of_the_phone_block(self):
        at = BASE.index('table.rowlist tbody tr:has(> td[data-m="third"])::before')
        assert BASE.rindex("@media screen and (max-width: 768px)", 0, at) > BASE.rindex(
            "@media screen and (min-width: 769px)", 0, at
        )
        assert 'table.rowlist tbody td[data-m="third"] { order: 6;' in BASE

    def test_a_lease_card(self, logged_in_client, leases):
        row = _row(_body(logged_in_client, "/leases"), "resv-b")
        # the cell the desktop row prints the MAC in: the code font, and the copy control
        assert re.search(
            r'(?i)<td class="mono" data-m="third"><button type="button" class="copy mono" data-copy="aa:bb:cc:24:83:02"',
            row,
        )

    def test_a_reservation_card(self, logged_in_client, leases):
        row = _row(_body(logged_in_client, "/reservations"), "10.99.0.72")
        assert re.search(
            r'(?i)<td class="mono" data-m="third"><button type="button" class="copy mono" data-copy="aa:bb:cc:24:83:02"',
            row,
        )

    def test_a_device_card_keeps_its_subnet_and_its_status(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, device_name, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) "
                "VALUES ('aa:bb:cc:24:83:a6', 'Card', '10.99.0.86', 'card-host', 1, NOW(), NOW())"
            )
        db.commit()
        row = _row(_body(logged_in_client, "/devices"), "aa:bb:cc:24:83:a6")
        thirds = re.findall(r'<td(?: class="[^"]*")? data-m="third">(.*?)</td>', row, re.S)
        assert len(thirds) == 3
        assert 'class="copy mono" data-copy="aa:bb:cc:24:83:a6"' in thirds[0]
        assert "Test Network" in thirds[1] and "badge-tone-" in thirds[1]
        assert "badge-dynamic" in thirds[2] and "Dynamic" in thirds[2]
        assert "hide-mobile" not in "".join(re.findall(r'<td[^>]*data-m="third"', row))

    def test_no_third_line_cell_is_hidden_from_a_phone(self):
        for name, cells in (("_lease_rows.html", 1), ("_reservation_row.html", 1), ("_device_rows.html", 3)):
            tags = re.findall(r'<td[^>]*data-m="third"[^>]*>', _src(name))
            assert len(tags) == cells, (name, tags)
            for tag in tags:
                assert "hide-mobile" not in tag, (name, tag)


# ───────────────────────────── V54: the wide column ─────────────────────────────


class TestTheWideColumn:
    def test_the_rule_comes_after_the_rules_it_widens(self):
        wide = BASE.index(".content--wide { max-width: 1800px; }")
        assert BASE.index(".container { max-width: 1400px;") < wide
        assert (
            BASE.index(".nav-inner { display: flex;") < wide
            and "max-width: 1400px" in BASE[BASE.index(".nav-inner { display: flex;") : wide]
        )

    @pytest.mark.parametrize(
        "path", ["/leases", "/reservations", "/devices", "/settings/logs", "/settings/logs?tab=alerts"]
    )
    def test_a_table_page_asks_for_it_and_the_bars_follow(self, logged_in_client, path):
        body = _body(logged_in_client, path)
        assert '<div class="container content--wide">' in body
        assert '<div class="nav-inner content--wide">' in body
        assert re.search(r'<div class="section-tabs-wrap section-tabs-wrap--wide">\s*<div class="section-tabs', body)

    @pytest.mark.parametrize("path", ["/about", "/settings/kea", "/reservations/add", "/saved-searches", "/reports"])
    def test_a_form_a_settings_page_and_about_stay_as_they_were(self, logged_in_client, mock_kea, path):
        body = _body(logged_in_client, path)
        assert '<div class="container">' in body and '<div class="nav-inner">' in body
        assert 'class="section-tabs-wrap section-tabs-wrap--wide"' not in body
        assert 'class="container content--wide"' not in body

    def test_the_bars_backgrounds_run_edge_to_edge_and_their_contents_do_not(self):
        nav = re.search(r"\n\s*\.nav \{([^}]*)\}", BASE).group(1)
        assert "background: var(--surface)" in nav and "max-width" not in nav
        wrap = re.search(r"\.section-tabs-wrap \{ --page-w: 1400px;([^}]*)\}", BASE).group(1)
        assert "background: var(--surface)" in wrap and "border-bottom: 1px solid var(--border)" in wrap
        assert ".section-tabs-wrap--wide { --page-w: 1800px; }" in BASE
        assert re.search(r"\.section-tabs-wrap > \.section-tabs \{ max-width: var\(--page-w\); margin: 0 auto;", BASE)

    def test_abouts_release_notes_are_capped_near_80_characters(self):
        assert ".changelog-body { max-width: 80ch; }" in BASE
        assert 'class="changelog-body ' in _src("about.html"), (
            "the class About's notes are keyed to is still on the page"
        )

    def test_the_top_rows_fit_is_measured_on_the_inner_wrapper(self):
        assert "fitRow.scrollWidth > fitRow.clientWidth + 1" in BASE


# ───────────────────────────── addition 4: the way back ─────────────────────────────


def _active_tabs(body):
    return [
        re.sub(r"<[^>]+>", "", t).strip()
        for t in re.findall(r'<a href="[^"]*" class="section-tab active">(.*?)</a>', body, re.S)
    ]


def _first_of_content(body):
    """What follows the content column's own leading lines (the print stamp): the first element a page's content block wrote."""
    at = body.index('<p class="print-only">')
    return body[body.index("</p>", at) + 4 :].lstrip()


class TestDetailPagesHaveOneWayBack:
    def test_the_rule(self):
        assert ".back-link { display: inline-block; margin-bottom: 8px; font-size: 13px; }" in BASE

    @pytest.mark.parametrize("who", ["admin", "viewer", "restricted"])
    def test_saved_searches_is_under_leases_with_a_link_back_to_it(self, client, logged_in_client, db, who):
        c = logged_in_client
        if who == "viewer":
            c, _ = restricted_client(client, db, allowed_subnets=None, role="viewer", username="q248a3_back_viewer")
        elif who == "restricted":
            c, _ = restricted_client(client, db, allowed_subnets=[1], role="admin", username="q248a3_back_admin")
        body = _body(c, "/saved-searches")
        assert _active_tabs(body) == ["Leases"]
        assert re.search(r'<a href="/leases" class="nav-link\s+active">', body), "Management is lit"
        assert _first_of_content(body).startswith('<a class="back-link" href="/leases">&larr; Leases</a>')
        assert body.count('class="back-link"') == 1

    def test_trace_is_under_investigate_with_a_link_back_to_it(self, logged_in_client, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])
        body = _body(logged_in_client, "/tools/trace")
        assert _active_tabs(body) == ["Investigate"]
        assert re.search(r'<a href="/subnets" class="nav-link\s+active">', body), "Network is lit"
        assert _first_of_content(body).startswith('<a class="back-link" href="/client">&larr; Investigate a client</a>')
        assert body.count('class="back-link"') == 1

    def test_a_trace_of_one_client_goes_back_to_that_client(self, logged_in_client, monkeypatch):
        """What was typed into the MAC field is what the Investigate page is asked about (it is not a MAC here, so the log is never read)."""
        from jen import extensions

        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}])
        body = _body(logged_in_client, "/tools/trace?mac=front%20desk")
        assert '<a class="back-link" href="/client?q=front%20desk">&larr; Investigate a client</a>' in body

    def test_neither_page_has_a_second_way_back(self):
        for name in ("trace.html", "saved_searches.html", "_trace_results.html"):
            src = _src(name)
            assert src.count("back-link") == (0 if name.startswith("_") else 1), name
            assert not re.search(r">\s*(?:&larr;|←|‹)?\s*Back\b", src), name

    def test_profile_stays_an_account_page(self, logged_in_client):
        body = _body(logged_in_client, "/profile")
        assert _active_tabs(body) == [] and 'class="back-link"' not in body
