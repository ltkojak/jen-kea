"""Q233 (v7.1.0-beta.1): Settings -> Databases -> Export, the Kea card picks TABLES - an All box and one tick box
per table, the Jen card's shape - so every Kea table can go in one file. The groups stay for a backup, a migration
and a request that names one.

Nothing here needs a database: the selection is a pure function, the writer is driven through stand-ins for its
connection (named below), and the card is rendered from the template's own text. The route against a real Kea
schema is `tests/test_kea_binary_roundtrip.py::TestTheKeaExportPicksTables`."""

import gzip
import json
import pathlib
import re

import jinja2
import pytest

from jen.services import dbexport

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = (ROOT / "templates" / "database.html").read_text(encoding="utf-8")
ROUTE = (ROOT / "jen" / "routes" / "database.py").read_text(encoding="utf-8")


class TestTheSelection:
    def test_the_picker_lists_every_exportable_table_in_restore_order(self):
        assert list(dbexport.KEA_EXPORT_TABLES) == dbexport.KEA_RESTORE_ORDER
        assert set(dbexport.KEA_EXPORT_TABLES) == dbexport.KEA_ALL_TABLES
        assert set(dbexport.KEA_EXPORT_TABLES) == set(dbexport.KEA_EXPORT_SQL)

    def test_what_is_ticked_when_the_page_opens_is_what_a_backup_saves(self):
        assert (
            list(dbexport.KEA_EXPORT_DEFAULT_TABLES) == dbexport.KEA_EXPORT_GROUPS[dbexport.KEA_BACKUP_GROUP]["tables"]
        )
        assert "lease4" not in dbexport.KEA_EXPORT_DEFAULT_TABLES

    @pytest.mark.parametrize("group_id", sorted(dbexport.KEA_EXPORT_GROUPS))
    def test_a_selection_that_is_a_group_is_named_for_it(self, group_id):
        tables = dbexport.KEA_EXPORT_GROUPS[group_id]["tables"]
        assert dbexport.kea_export_selection(reversed(tables)) == (tables, group_id)

    def test_every_table_in_one_file_is_a_custom_selection_in_restore_order(self):
        picked = ["lease4", "ipv6_reservations", "hosts", "dhcp6_options", "dhcp4_options", "hosts"]
        assert dbexport.kea_export_selection(picked) == (dbexport.KEA_RESTORE_ORDER, dbexport.KEA_CUSTOM_GROUP)

    def test_reservations_beside_a_lease_snapshot_is_one_selection(self):
        assert dbexport.kea_export_selection(["lease4", "hosts"]) == (["hosts", "lease4"], "custom")

    def test_the_custom_name_is_no_group(self):
        assert dbexport.KEA_CUSTOM_GROUP not in dbexport.KEA_EXPORT_GROUPS

    @pytest.mark.parametrize("tables", [None, [], ()])
    def test_an_empty_selection_is_refused(self, tables):
        with pytest.raises(ValueError):
            dbexport.kea_export_selection(tables)

    @pytest.mark.parametrize("name", ["users", "lease6", "hosts; DROP TABLE hosts", "", "HOSTS"])
    def test_a_name_that_is_not_an_exportable_kea_table_is_refused_and_not_echoed(self, name):
        with pytest.raises(ValueError) as refused:
            dbexport.kea_export_selection(["hosts", name])
        assert name == "" or name not in str(refused.value)


class _Conn:
    """A stand-in for the direct Kea connection: `write_kea_export` only closes it; every read goes through the
    three functions replaced beside it."""

    closed = False

    def close(self):
        self.closed = True


@pytest.fixture
def written(monkeypatch, tmp_path):
    """`write_kea_export` against stand-ins: every table exists but `dhcp6_options`, each has one row. Returns
    a function that writes and hands back (returned meta, the file's document, the tables streamed in order)."""
    streamed = []

    def _stream(conn, tbl, f, sql=None):
        assert sql == dbexport.KEA_EXPORT_SQL[tbl], "each table goes out through its own fixed query"
        streamed.append(tbl)
        f.write(json.dumps({"t": tbl}))
        return 1

    conn = _Conn()
    monkeypatch.setattr(dbexport, "_direct_kea_conn", lambda: conn)
    monkeypatch.setattr(dbexport, "_table_exists", lambda c, t: t != "dhcp6_options")
    monkeypatch.setattr(dbexport, "_stream_table_rows", _stream)
    monkeypatch.setattr(dbexport, "_binary_columns", lambda c, tables: {t: [] for t in tables})

    def write(*args, **kwargs):
        streamed.clear()
        path = tmp_path / "kea.json.gz"
        meta = dbexport.write_kea_export(str(path), *args, **kwargs)
        assert conn.closed
        return meta, json.loads(gzip.decompress(path.read_bytes())), list(streamed)

    return write


class TestTheWriter:
    def test_a_selection_is_written_in_restore_order_whatever_order_it_was_ticked_in(self, written):
        meta, doc, streamed = written(tables=["lease4", "hosts", "dhcp4_options"])
        assert streamed == ["hosts", "dhcp4_options", "lease4"]
        assert list(doc["data"]) == ["hosts", "dhcp4_options", "lease4"]
        assert doc["_meta"]["tables"] == ["hosts", "dhcp4_options", "lease4"]
        assert doc["_meta"]["group"] == "custom" and meta["group"] == "custom"
        assert doc["_meta"]["row_counts"] == {"hosts": 1, "dhcp4_options": 1, "lease4": 1}
        assert doc["_meta"]["database"] == "kea" and doc["_meta"]["format"] == dbexport.EXPORT_FORMAT

    def test_every_table_goes_in_one_file_and_a_table_this_kea_lacks_is_left_out(self, written):
        _meta, doc, streamed = written(tables=dbexport.KEA_RESTORE_ORDER)
        assert streamed == ["hosts", "dhcp4_options", "ipv6_reservations", "lease4"]
        assert "dhcp6_options" not in doc["data"] and "dhcp6_options" not in doc["_meta"]["tables"]

    def test_the_four_reservation_tables_ticked_by_hand_are_a_reservations_all_file(self, written):
        _meta, doc, _streamed = written(tables=list(dbexport.KEA_EXPORT_DEFAULT_TABLES))
        assert doc["_meta"]["group"] == dbexport.KEA_BACKUP_GROUP

    def test_tables_wins_over_group(self, written):
        _meta, doc, streamed = written("reservations_all", tables=["lease4"])
        assert streamed == ["lease4"] and doc["_meta"]["group"] == "leases"

    def test_a_group_is_written_as_it_always_was(self, written):
        _meta, doc, streamed = written("reservations")
        assert streamed == ["hosts", "dhcp4_options"] and doc["_meta"]["group"] == "reservations"
        _meta, doc, streamed = written()
        assert streamed == ["hosts", "dhcp4_options", "ipv6_reservations"]
        assert doc["_meta"]["group"] == "reservations_all"

    def test_an_unknown_group_or_table_or_an_empty_selection_writes_nothing(self, monkeypatch, tmp_path):
        def no_connection():
            raise AssertionError("refused before a connection is opened")

        monkeypatch.setattr(dbexport, "_direct_kea_conn", no_connection)
        path = tmp_path / "x.json.gz"
        for args, kwargs in ((("nope",), {}), ((), {"tables": []}), ((), {"tables": ["users"]})):
            with pytest.raises(ValueError):
                dbexport.write_kea_export(str(path), *args, **kwargs)
        assert not path.exists()


class TestTheRoute:
    """The route's own text: what it reads, what it refuses, what it records. Its behavior against a database is
    in tests/test_kea_binary_roundtrip.py."""

    BODY = ROUTE[ROUTE.index("def export_kea():") : ROUTE.index('@bp.route("/database/backup/download')]

    def test_a_request_that_names_a_group_is_answered_as_before_and_one_that_does_not_reads_the_ticked_tables(self):
        assert 'if "group" in request.form:' in self.BODY
        assert 'request.form.getlist("tables")' in self.BODY
        assert "dbexport.kea_export_selection(picked)" in self.BODY
        assert "dbexport.write_kea_export(tmp_path, group, tables)" in self.BODY

    def test_nothing_ticked_is_an_error_and_never_the_default_export(self):
        assert 'flash("Tick at least one Kea table to export.", "error")' in self.BODY
        assert "KEA_BACKUP_GROUP" not in self.BODY, "an empty form must not fall back to a group"

    def test_a_refused_name_is_answered_with_fixed_words(self):
        assert 'flash("Invalid export table.", "error")' in self.BODY
        assert "flash(str(" not in self.BODY and 'flash(f"' not in self.BODY

    def test_the_audit_line_names_the_tables(self):
        assert "f\"Exported tables: {', '.join(tables)}\"" in self.BODY

    def test_the_page_is_handed_the_tables_and_which_are_ticked(self):
        assert "kea_tables=dbexport.KEA_EXPORT_TABLES," in ROUTE
        assert "kea_default_tables=dbexport.KEA_EXPORT_DEFAULT_TABLES," in ROUTE


def _card():
    start = PAGE.index("<!-- Kea Export -->")
    return PAGE[start : PAGE.index("{% endif %}", PAGE.index("Download Kea Export"))]


@pytest.fixture(scope="module")
def card():
    env = jinja2.Environment(autoescape=True, undefined=jinja2.StrictUndefined)
    return env.from_string(_card()).render(
        kea_db_host="db.example",
        kea_db_name="kea",
        csrf_token=lambda: "token",
        kea_tables=dbexport.KEA_EXPORT_TABLES,
        kea_default_tables=dbexport.KEA_EXPORT_DEFAULT_TABLES,
    )


class TestTheCard:
    def test_one_tick_box_per_table_in_restore_order(self, card):
        assert (
            re.findall(r'<input type="checkbox" name="tables" value="([a-z0-9_]+)"', card) == dbexport.KEA_RESTORE_ORDER
        )

    def test_the_reservation_tables_are_ticked_and_lease4_is_not(self, card):
        ticked = re.findall(r'name="tables" value="([a-z0-9_]+)" checked', card)
        assert ticked == list(dbexport.KEA_EXPORT_DEFAULT_TABLES)
        assert 'name="tables" value="lease4" class=' in card

    def test_the_all_box_drives_the_kea_tables_and_opens_unticked(self, card):
        assert (
            '<input type="checkbox" class="toggle-all-cb" data-toggle-group="kea-tables"> <strong>All</strong>' in card
        )
        assert '<div id="kea-tables"' in card

    def test_every_table_says_what_it_is(self, card):
        for desc in dbexport.KEA_EXPORT_TABLES.values():
            assert jinja2.filters.do_forceescape(desc) in card

    def test_the_card_has_no_radio_and_posts_no_group(self, card):
        assert 'type="radio"' not in card and 'name="group"' not in card
        assert "kea_groups" not in PAGE and "kea-group-card" not in PAGE and "highlightKea" not in PAGE

    def test_the_picker_is_the_jen_cards_markup(self):
        jen = PAGE[PAGE.index("<!-- Jen Export -->") : PAGE.index("<!-- Kea Export -->")]
        start = jen.rindex("<label", 0, jen.index(">Select Tables</label>"))
        heading = jen[start : jen.index('<label class="u-dbfa94">')]
        assert heading in _card(), "the Select Tables heading and its row are the Jen card's, character for character"
        assert "style=" not in heading, "by class: tools/extract_inline_styles.py turned the shared styles into classes"
        form = _card()[_card().index("<form") :]
        assert form.count("style=") == 2, "the two it had: the warning and the button"

    def test_an_all_box_follows_its_boxes(self):
        script = PAGE[PAGE.rindex("<script") :]
        assert "cb.checked = !group.querySelector('input[type=checkbox]:not(:checked)');" in script
        assert "group.addEventListener('change'" in script

    def test_the_download_form_and_its_warning_stand(self, card):
        assert '<form method="POST" action="/database/export/kea" data-download>' in card
        assert "Store securely." in card and "Download Kea Export" in card
