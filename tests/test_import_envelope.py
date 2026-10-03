"""
tests/test_import_envelope.py
─────────────────────────────
v5.67.0-beta.14 (Q128, item d) — the export envelope is checked before anything uses it. `parse_import_file`
wrapped only decompress + json.loads, so a `[]` root, a `_meta` that is a string, a table that is not a list or
a row that is not an object raised uncaught from the confirmation page (500), and `format` was unbounded (9 was
"at least 3"). The upload route also refused a plain-JSON export as "not a valid gzip export" though the parser
has always accepted both. Both fixed; the fuzz cases go through the real HTTP upload route.
"""

import gzip
import io
import json
import zlib

import pytest

from jen.services import dbexport

GOOD = {"data": {"settings": [{"setting_key": "k", "setting_value": "v"}]}, "_meta": {"database": "jen"}}


def _gz(obj) -> bytes:
    return gzip.compress(json.dumps(obj).encode("utf-8"))


def _plain(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")


def _meta(**kw):
    return {"data": {"settings": []}, "_meta": {"database": "jen", **kw}}


# every shape the old parser let through to a crash further down, as (id, payload)
BAD_SHAPES = [
    ("list-root", []),
    ("string-root", "hello"),
    ("number-root", 7),
    ("null-root", None),
    ("meta-is-a-string", {"data": {}, "_meta": "jen"}),
    ("meta-is-a-list", {"data": {}, "_meta": ["database"]}),
    ("meta-empty", {"data": {}, "_meta": {}}),
    ("no-meta", {"data": {}}),
    ("no-data", {"_meta": {"database": "jen"}}),
    ("data-is-a-list", {"data": [], "_meta": {"database": "jen"}}),
    ("data-is-a-string", {"data": "x", "_meta": {"database": "jen"}}),
    ("database-not-text", {"data": {}, "_meta": {"database": 5}}),
    ("table-not-a-list", {"data": {"settings": {"a": 1}}, "_meta": {"database": "jen"}}),
    ("table-is-null", {"data": {"settings": None}, "_meta": {"database": "jen"}}),
    ("row-not-an-object", {"data": {"settings": [1, 2]}, "_meta": {"database": "jen"}}),
    ("row-is-a-list", {"data": {"settings": [[1]]}, "_meta": {"database": "jen"}}),
    ("version-text", _meta(jen_export_version="1")),
    ("version-bool", _meta(jen_export_version=True)),
    ("version-negative", _meta(jen_export_version=-1)),
    ("format-text", _meta(format="3")),
    ("format-bool", _meta(format=True)),
    ("format-float", _meta(format=2.5)),
    ("format-negative", _meta(format=-3)),
    ("exported-at-number", _meta(exported_at=12345)),
    ("app-version-list", _meta(jen_app_version=["5"])),
    ("tables-not-a-list", _meta(tables="settings")),
    ("tables-with-a-number", _meta(tables=["settings", 4])),
    ("row-counts-a-list", _meta(row_counts=[1])),
    ("row-counts-text-value", _meta(row_counts={"settings": "many"})),
    ("binary-columns-a-list", _meta(binary_columns=["a"])),
    ("binary-columns-bad-value", _meta(binary_columns={"hosts": "dhcp_identifier"})),
    ("plugin-tables-a-list", _meta(plugin_tables=["wol"])),
    ("plugin-tables-path-as-id", _meta(plugin_tables={"../../etc": {"tables": []}})),
    ("plugin-tables-empty-id", _meta(plugin_tables={"": {"tables": []}})),
    ("plugin-tables-value-a-string", _meta(plugin_tables={"wol": "wol_hosts"})),
    ("plugin-tables-tables-a-string", _meta(plugin_tables={"wol": {"tables": "wol_hosts"}})),
]


class TestParseImportFile:
    @pytest.mark.parametrize("name,payload", BAD_SHAPES, ids=[n for n, _ in BAD_SHAPES])
    def test_a_malformed_envelope_is_a_clean_refusal_gzip_or_plain(self, name, payload):
        for blob in (_gz(payload), _plain(payload)):
            meta, data, err = dbexport.parse_import_file(blob)
            assert err and err.startswith("not a Jen export: "), (name, err)
            assert meta is None and data is None

    def test_the_refusal_names_the_reason(self):
        assert "top level is not an object" in dbexport.parse_import_file(_plain([]))[2]
        shapes = dict(BAD_SHAPES)
        assert "data.settings is not a list" in dbexport.parse_import_file(_plain(shapes["table-not-a-list"]))[2]
        assert (
            "data.settings row 1 is not an object" in dbexport.parse_import_file(_plain(shapes["row-not-an-object"]))[2]
        )
        assert "_meta.format is not a whole number" in dbexport.parse_import_file(_plain(_meta(format="3")))[2]

    @pytest.mark.parametrize(
        "blob",
        [b"", b"not json at all", b"\xff\xfe\x00bad utf8", b"[1, 2", b'{"data": ' * 5],
        ids=["empty", "text", "not-utf8", "truncated-json", "repeated"],
    )
    def test_garbage_is_a_refusal_that_carries_no_part_of_the_file(self, blob):
        meta, data, err = dbexport.parse_import_file(blob)
        assert meta is None and data is None
        assert err == "not a Jen export: the file is not valid gzip-compressed or plain JSON."

    def test_a_corrupt_gzip_is_refused_not_read_as_text(self):
        good = _gz(GOOD)
        for blob in (good[:-10], good[:20], good[:3] + b"\x00" * 30, good[:10] + bytes(len(good) - 10)):
            assert blob[:2] == dbexport.GZIP_MAGIC
            assert dbexport.parse_import_file(blob)[2] == (
                "not a Jen export: the file is not valid gzip-compressed or plain JSON."
            )

    def test_gzip_and_plain_json_both_parse(self):
        for blob in (_gz(GOOD), _plain(GOOD)):
            meta, data, err = dbexport.parse_import_file(blob)
            assert err is None and meta["database"] == "jen" and data["settings"][0]["setting_key"] == "k"

    def test_optional_fields_may_be_absent_but_a_complete_modern_envelope_is_accepted(self):
        full = _meta(
            jen_export_version=1,
            format=3,
            exported_at="2026-10-03T00:00:00Z",
            jen_app_version="5.67.0",
            tables=["settings"],
            row_counts={"settings": 0},
            binary_columns={"hosts": ["dhcp_identifier"]},
            plugin_tables={"wol": {"version": "1.0.4", "tables": ["wol_hosts"]}},
        )
        assert dbexport.parse_import_file(_plain(full))[2] is None
        assert (
            dbexport.parse_import_file(_plain({"data": {}, "_meta": {"database": "kea", "group": "reservations_all"}}))[
                2
            ]
            is None
        )

    def test_format_is_bounded_by_what_this_jen_understands(self):
        assert dbexport.parse_import_file(_plain(_meta(format=dbexport.EXPORT_FORMAT)))[2] is None
        meta, data, err = dbexport.parse_import_file(_plain(_meta(format=dbexport.EXPORT_FORMAT + 1)))
        assert "reads up to format 3" in err and "Upgrade Jen" in err
        assert meta is not None  # the same shape as the newer-schema-version refusal: the caller may still show it
        assert "format 9" in dbexport.parse_import_file(_plain(_meta(format=9)))[2]

    def test_a_newer_schema_version_is_still_refused_as_before(self):
        err = dbexport.parse_import_file(_plain(_meta(jen_export_version=dbexport.SCHEMA_VERSION + 1)))[2]
        assert "newer than this Jen supports" in err


class TestUploadRoute:
    """POST /database/import/inspect with each malformed file: a message and a redirect, never a 500."""

    def _post(self, client, blob, name="x.json.gz"):
        return client.post(
            "/database/import/inspect",
            data={"file": (io.BytesIO(blob), name)},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    @pytest.mark.parametrize("name,payload", BAD_SHAPES, ids=[n for n, _ in BAD_SHAPES])
    def test_no_malformed_envelope_is_a_server_error(self, logged_in_client, name, payload):
        for blob, fname in ((_gz(payload), "x.json.gz"), (_plain(payload), "x.json")):
            r = self._post(logged_in_client, blob, fname)
            assert r.status_code == 200, (name, fname, r.status_code)
            assert b"not a Jen export" in r.data, (name, fname)
            assert b"Confirm Import" not in r.data

    def test_a_plain_json_export_reaches_the_confirmation_page(self, logged_in_client):
        r = self._post(logged_in_client, _plain(GOOD), "export.json")
        assert r.status_code == 200
        assert b"Confirm Import" in r.data
        assert b"not a valid gzip" not in r.data

    def test_a_gzip_export_still_does(self, logged_in_client):
        r = self._post(logged_in_client, _gz(GOOD))
        assert r.status_code == 200 and b"Confirm Import" in r.data

    @pytest.mark.parametrize(
        "make",
        [
            lambda: _gz(GOOD)[:-12],
            lambda: _gz(GOOD)[:25],
            lambda: _gz(GOOD)[:12] + zlib.compress(b"junk")[:8] * 4,
        ],
        ids=["truncated-trailer", "truncated-header", "corrupt-body"],
    )
    def test_a_corrupt_gzip_is_refused_not_a_server_error(self, logged_in_client, make):
        r = self._post(logged_in_client, make())
        assert r.status_code == 200
        assert b"not a valid gzip export" in r.data or b"not a Jen export" in r.data
        assert b"Confirm Import" not in r.data

    def test_a_plain_file_over_the_cap_is_refused_before_it_is_parsed(self, logged_in_client, monkeypatch):
        import configparser

        from jen import extensions

        cfg = configparser.ConfigParser()
        cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        cfg.read_dict({"backups": {"max_import_mb": "1"}})
        monkeypatch.setattr(extensions, "cfg", cfg)

        def boom(_b):
            raise AssertionError("parsed a file that was over the cap")

        monkeypatch.setattr(dbexport, "parse_import_file", boom)
        r = self._post(logged_in_client, b"[" + b"0," * (1024 * 1024) + b"0]", "big.json")
        assert r.status_code == 200 and b"cap" in r.data.lower()

    def test_a_plain_file_goes_through_the_same_admission_check(self, logged_in_client, monkeypatch):
        monkeypatch.setattr("jen.tools.restore._mem_available_bytes", lambda: 1)

        def boom(_b):
            raise AssertionError("parsed a file the admission check refused")

        monkeypatch.setattr(dbexport, "parse_import_file", boom)
        r = self._post(logged_in_client, _plain(GOOD), "export.json")
        assert r.status_code == 200 and b"Cannot import" in r.data

    def test_a_tampered_file_between_inspect_and_confirm_is_a_message_not_a_500(self, logged_in_client):
        import base64
        import os

        from jen import extensions

        os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
        path = os.path.join(extensions.CONTENT_TMP_DIR, "jen_import_q128tamper.json.gz")
        with open(path, "wb") as f:
            f.write(b"[]")
        r = logged_in_client.post(
            "/database/import/confirm",
            data={"tmp_path": base64.b64encode(path.encode()).decode()},
            follow_redirects=True,
        )
        assert r.status_code == 200 and b"expired" in r.data.lower()
        assert not os.path.exists(path)
