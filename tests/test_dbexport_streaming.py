"""
tests/test_dbexport_streaming.py
──────────────────────────────────
v5.66.0-beta.4 (Q106) — dbexport.write_jen_export() writes the same JSON document export_jen()
always has, straight to a gzip file, one row at a time from a server-side cursor — never
holding a whole table in memory. `audit_log` ("can be large", dbexport.py) is the table this
was written for. DB-backed (needs a real connection to insert/export/import against), so it
doesn't run under --noconftest locally; CI is the arbiter.
"""

import gzip
import json
import tracemalloc

from jen.services import dbexport


def _seed_audit_log(db, n, detail_size=200):
    with db.cursor() as cur:
        cur.execute("DELETE FROM audit_log")
        cur.executemany(
            "INSERT INTO audit_log (action, entity, details, username) VALUES (%s, %s, %s, %s)",
            [("NOTE", f"entity-{i}", "x" * detail_size, "admin") for i in range(n)],
        )
    db.commit()


class TestWriteJenExportRoundTrip:
    def test_matches_export_jen_byte_for_value(self, db, tmp_path):
        """The streaming writer and the old build-it-all-in-memory writer must produce the
        SAME document — same tables, same rows, same row_counts — even though the streaming
        writer puts `data` before `_meta` (key order is free in JSON)."""
        _seed_audit_log(db, 5)
        with db.cursor() as cur:
            cur.execute("DELETE FROM settings WHERE setting_key='_q106_streaming_probe'")
            cur.execute("INSERT INTO settings (setting_key, setting_value) VALUES ('_q106_streaming_probe', 'yes')")
        db.commit()

        tables = ["audit_log", "settings", "schema_migrations"]
        old_content, _fname = dbexport.export_jen(tables)
        old_payload = json.loads(old_content.decode("utf-8"))

        path = tmp_path / "stream-export.json.gz"
        meta = dbexport.write_jen_export(str(path), tables=tables)
        with gzip.open(path, "rt", encoding="utf-8") as f:
            new_payload = json.loads(f.read())

        assert new_payload["data"] == old_payload["data"]
        assert new_payload["_meta"]["row_counts"] == old_payload["_meta"]["row_counts"]
        assert new_payload["_meta"]["database"] == "jen"
        assert meta["row_counts"] == old_payload["_meta"]["row_counts"]

    def test_returned_meta_carries_size_and_row_count(self, db, tmp_path):
        _seed_audit_log(db, 3)
        path = tmp_path / "sized-export.json.gz"
        meta = dbexport.write_jen_export(str(path), tables=["audit_log"])
        assert meta["jen_db_rows"] == 3
        assert meta["jen_db_uncompressed_bytes"] > 0
        # the file's own uncompressed size (what a real restore would gzip.decompress) matches
        with gzip.open(path, "rt", encoding="utf-8") as f:
            assert len(f.read()) == meta["jen_db_uncompressed_bytes"]

    def test_written_file_is_0600(self, db, tmp_path):
        import os
        import stat

        if os.name == "nt":
            import pytest

            pytest.skip("POSIX permission bits — not meaningful on Windows")
        path = tmp_path / "perm-export.json.gz"
        dbexport.write_jen_export(str(path), tables=["schema_migrations"])
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_empty_table_is_an_empty_list_not_missing(self, db, tmp_path):
        with db.cursor() as cur:
            cur.execute("DELETE FROM audit_log")
        db.commit()
        path = tmp_path / "empty-export.json.gz"
        meta = dbexport.write_jen_export(str(path), tables=["audit_log"])
        assert meta["row_counts"]["audit_log"] == 0
        with gzip.open(path, "rt", encoding="utf-8") as f:
            payload = json.loads(f.read())
        assert payload["data"]["audit_log"] == []


class TestScheduledAndManualBackupWriteStraightToDisk:
    """v5.66.0-beta.4 (Q106) — run_scheduled_backup()'s 'jen' branch moved onto
    write_jen_export() directly, the same as backup_now() (tests/test_database.py)."""

    def test_run_scheduled_backup_writes_a_readable_jen_backup(self, db, monkeypatch, tmp_path):
        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        with db.cursor() as cur:
            cur.execute(
                "REPLACE INTO backup_schedule "
                "(id, enabled, frequency, hour, keep_count, include_jen, include_kea) "
                "VALUES (1, 1, 'daily', 3, 7, 1, 0)"
            )
        db.commit()

        dbexport.run_scheduled_backup()

        files = list(tmp_path.glob("jen-scheduled-*.json.gz"))
        assert len(files) == 1
        with gzip.open(files[0], "rt", encoding="utf-8") as f:
            payload = json.loads(f.read())
        assert payload["_meta"]["database"] == "jen"

        with db.cursor() as cur:
            cur.execute("SELECT last_status FROM backup_schedule WHERE id=1")
            assert "Jen:" in cur.fetchone()["last_status"]


class TestExportMemoryStaysBounded:
    def test_a_200k_row_audit_log_export_peaks_under_a_small_fixed_bound(self, db, tmp_path):
        """The property under test: peak memory while EXPORTING does not grow with the row
        count. 200,000 rows of ~200 bytes of `details` each is ~40+ MB of raw table data —
        held as one Python list-of-dicts (the old shape) that would be several times that in
        object overhead; streamed row by row through a bounded fetchmany(), it should not be
        within an order of magnitude of that."""
        _seed_audit_log(db, 200_000)
        path = tmp_path / "big-export.json.gz"

        tracemalloc.start()
        try:
            dbexport.write_jen_export(str(path), tables=["audit_log"])
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        print(f"MEASURED export peak for 200,000 audit_log rows: {peak} bytes ({peak / (1024 * 1024):.1f} MB)")
        assert peak < 30 * 1024 * 1024, f"export of 200,000 rows peaked at {peak} bytes — no longer bounded"


class TestRestoreMemoryFactor:
    """MEASURES (never estimates) jen.tools.restore's actual bottleneck: dbexport.parse_import_file
    (gzip.decompress + json.loads of the WHOLE file) followed by import_jen()'s insert path -
    the streaming export above does not change this side; a streaming IMPORTER is explicitly
    out of scope for this Q. Three synthetic sizes, each printed as
    'MEASURED restore-memory-factor n=<rows> uncompressed=<bytes> peak=<bytes> k=<ratio>' -
    these are the numbers jen.tools.restore.RESTORE_MEMORY_FACTOR and docs/runbooks.md's
    "Before you start: size" step are set from."""

    def _measure(self, db, tmp_path, n):
        _seed_audit_log(db, n)
        path = tmp_path / f"restore-factor-{n}.json.gz"
        meta = dbexport.write_jen_export(str(path), tables=["audit_log"])
        uncompressed = meta["jen_db_uncompressed_bytes"]
        gz_bytes = path.read_bytes()

        tracemalloc.start()
        try:
            dbexport.import_jen(gz_bytes, tables_to_restore=["audit_log"])
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        k = peak / uncompressed if uncompressed else 0.0
        print(f"MEASURED restore-memory-factor n={n} uncompressed={uncompressed} peak={peak} k={k:.2f}")
        return uncompressed, peak, k

    def test_2000_rows(self, db, tmp_path):
        self._measure(db, tmp_path, 2_000)

    def test_20000_rows(self, db, tmp_path):
        self._measure(db, tmp_path, 20_000)

    def test_100000_rows(self, db, tmp_path):
        uncompressed, peak, k = self._measure(db, tmp_path, 100_000)
        # a loose sanity ceiling, not the calibrated guard itself (RESTORE_MEMORY_FACTOR in
        # jen/tools/restore.py, updated by hand from what this test prints) - this just catches
        # the import path becoming wildly less memory-efficient than any reasonable factor.
        assert k < 15, (uncompressed, peak, k)
