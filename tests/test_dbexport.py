"""Tests for jen/services/dbexport.py's table/column whitelist validation.

Regression coverage for the v4.3.9 fix: table names (from form data or an
uploaded export file) and column names (from an uploaded export file) were
interpolated unescaped into f-string SQL identifiers with no validation
against the known-table/known-column whitelists defined in the same module.
These tests exercise the pure validation logic directly — no DB connection
needed, since _validate_tables() takes plain lists/sets.
"""


class TestValidateTables:
    def test_drops_unknown_table_names(self):
        from jen.services.dbexport import _validate_tables

        known = {"users", "devices", "settings"}
        result = _validate_tables(["users", "devices", "x`; DROP TABLE users;--"], known)
        assert result == ["users", "devices"]

    def test_keeps_all_known_tables(self):
        from jen.services.dbexport import _validate_tables

        known = {"users", "devices"}
        result = _validate_tables(["users", "devices"], known)
        assert result == ["users", "devices"]

    def test_none_passes_through_as_none(self):
        from jen.services.dbexport import _validate_tables

        assert _validate_tables(None, {"users"}) is None

    def test_empty_list_returns_empty_list(self):
        from jen.services.dbexport import _validate_tables

        assert _validate_tables([], {"users"}) == []

    def test_all_invalid_returns_empty_list_not_the_originals(self):
        from jen.services.dbexport import _validate_tables

        result = _validate_tables(["`x` UNION SELECT * FROM users--"], {"users", "devices"})
        assert result == []

    def test_union_injection_payload_as_table_name_is_dropped(self):
        """The exact shape of attack this fix closes: a crafted table name
        designed to break out of backticks in `SELECT * FROM `{table}``."""
        from jen.services.dbexport import _validate_tables

        known = {"users", "devices", "settings"}
        payload = "x` UNION SELECT username,password_hash,3,4 FROM users-- "
        result = _validate_tables([payload], known)
        assert result == []
        assert payload not in result


class TestKeaAllTables:
    def test_kea_all_tables_flattens_every_group(self):
        from jen.services.dbexport import KEA_ALL_TABLES, KEA_EXPORT_GROUPS

        expected = {t for grp in KEA_EXPORT_GROUPS.values() for t in grp["tables"]}
        assert expected == KEA_ALL_TABLES
        # sanity: the known real tables are present
        assert "hosts" in KEA_ALL_TABLES
        assert "lease4" in KEA_ALL_TABLES

    def test_injected_table_name_not_in_kea_all_tables(self):
        from jen.services.dbexport import KEA_ALL_TABLES

        assert "hosts`; DROP TABLE hosts;--" not in KEA_ALL_TABLES


class TestColumnFiltering:
    """Mirrors the filtering logic used in import_jen/import_kea against
    _get_table_columns() — exercised here without a live DB connection."""

    def test_unknown_columns_filtered_out(self):
        real_cols = {"id", "mac", "hostname", "owner"}
        untrusted_row_keys = ["id", "mac", "hostname`) VALUES (('x'); DROP TABLE devices;--"]
        cols = [c for c in untrusted_row_keys if c in real_cols]
        assert cols == ["id", "mac"]

    def test_all_columns_valid_keeps_all(self):
        real_cols = {"id", "mac", "hostname", "owner"}
        row_keys = ["id", "mac", "hostname", "owner"]
        cols = [c for c in row_keys if c in real_cols]
        assert cols == row_keys

    def test_no_valid_columns_yields_empty_list(self):
        real_cols = {"id", "mac"}
        row_keys = ["totally_made_up_column"]
        cols = [c for c in row_keys if c in real_cols]
        assert cols == []


class TestBackupCount:
    """v5.13.0 — the Settings landing page needs only the NUMBER of
    backups, not their contents. backup_count() is a directory listing;
    list_backups() decompresses and JSON-parses every file for its
    `_meta` header, which is far too heavy for a status hint."""

    def test_counts_only_json_gz_files(self, tmp_path, monkeypatch):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        (tmp_path / "a.json.gz").write_bytes(b"x")
        (tmp_path / "b.json.gz").write_bytes(b"x")
        (tmp_path / "notes.txt").write_text("ignore me")
        (tmp_path / "c.json").write_text("{}")
        assert dbexport.backup_count() == 2

    def test_zero_when_dir_missing(self, tmp_path, monkeypatch):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path / "nope"))
        assert dbexport.backup_count() == 0

    def test_zero_when_dir_empty(self, tmp_path, monkeypatch):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        assert dbexport.backup_count() == 0

    def test_does_not_open_any_file(self, tmp_path, monkeypatch):
        """The whole point: a corrupt / unreadable backup file must not
        break the count the way list_backups() would."""
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        (tmp_path / "corrupt.json.gz").write_bytes(b"not gzip at all")
        assert dbexport.backup_count() == 1
