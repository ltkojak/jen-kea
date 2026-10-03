"""Tests for jen/services/dbexport.py's table/column whitelist validation.

Regression coverage for the v4.3.9 fix: table names (from form data or an
uploaded export file) and column names (from an uploaded export file) were
interpolated unescaped into f-string SQL identifiers with no validation
against the known-table/known-column whitelists defined in the same module.
These tests exercise the pure validation logic directly — no DB connection
needed, since _validate_tables() takes plain lists/sets.
"""

import pytest

from jen.services import dbexport


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
    list_backups() reads each backup's own .meta.json sidecar (v5.66.0-beta.6,
    Q108) rather than opening the backup file itself."""

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


class TestPublishBackup:
    """v5.66.0-beta.6 (Q108) — a backup is published atomically or not at all: write_fn(f)
    into a 0600 temp file in the SAME directory as the final path, fsync'd, then a rename
    onto the final name. Any exception during the write removes the temp file and leaves
    the final name never created — no truncated file can ever list as a good backup."""

    def test_a_clean_write_lands_at_the_final_path(self, tmp_path):
        from jen.services import dbexport

        final = tmp_path / "jen-scheduled-x.json.gz"
        dbexport.publish_backup(str(final), lambda f: f.write(b"hello"))
        assert final.read_bytes() == b"hello"

    def test_write_fns_return_value_passes_through(self, tmp_path):
        from jen.services import dbexport

        final = tmp_path / "x.json.gz"

        def write_fn(f):
            f.write(b"x")
            return {"answer": 42}

        assert dbexport.publish_backup(str(final), write_fn) == {"answer": 42}

    def test_no_temp_file_left_behind_on_success(self, tmp_path):
        from jen.services import dbexport

        final = tmp_path / "x.json.gz"
        dbexport.publish_backup(str(final), lambda f: f.write(b"x"))
        assert [p.name for p in tmp_path.iterdir()] == [final.name]

    def test_a_writer_raising_halfway_leaves_no_final_file_and_no_temp(self, tmp_path):
        import pytest

        from jen.services import dbexport

        final = tmp_path / "jen-scheduled-x.json.gz"

        def bad_write(f):
            f.write(b"partial")
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            dbexport.publish_backup(str(final), bad_write)
        assert not final.exists()
        assert list(tmp_path.iterdir()) == []

    def test_enospc_from_the_writer_leaves_no_final_file(self, tmp_path):
        import errno

        import pytest

        from jen.services import dbexport

        final = tmp_path / "jen-scheduled-x.json.gz"

        def enospc_write(f):
            raise OSError(errno.ENOSPC, "No space left on device")

        with pytest.raises(OSError):
            dbexport.publish_backup(str(final), enospc_write)
        assert not final.exists()
        assert list(tmp_path.iterdir()) == []

    def test_final_file_is_0600(self, tmp_path):
        import os
        import stat

        from jen.services import dbexport

        if os.name == "nt":
            import pytest

            pytest.skip("POSIX permission bits — not meaningful on Windows")
        final = tmp_path / "x.json.gz"
        dbexport.publish_backup(str(final), lambda f: f.write(b"x"))
        assert stat.S_IMODE(os.stat(final).st_mode) == 0o600


class TestWriteMetaSidecarAndLegacyDetails:
    """v5.66.0-beta.6 (Q108) — list_backups() reads only the sidecar; a pre-Q108 backup
    (no sidecar) gets one read via read_legacy_backup_details()."""

    def test_sidecar_written_alongside_the_backup(self, tmp_path):
        import json
        import os

        from jen.services import dbexport

        final = tmp_path / "jen-scheduled-x.json.gz"
        final.write_bytes(b"x")
        dbexport._write_meta_sidecar(
            str(final),
            {"database": "jen", "tables": ["settings"], "exported_at": "2026-01-01T00:00:00Z", "row_counts": {}},
        )
        sidecar = dbexport._sidecar_path(str(final))
        assert os.path.isfile(sidecar)
        with open(sidecar, encoding="utf-8") as f:
            payload = json.load(f)
        assert payload["database"] == "jen"
        assert payload["compressed_bytes"] == final.stat().st_size

    def test_list_backups_never_opens_the_backup_file_when_a_sidecar_exists(self, tmp_path, monkeypatch):
        """The whole point of the sidecar: list_backups() must not need gzip.open on the
        backup itself at all once a sidecar exists."""
        import json

        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        final = tmp_path / "jen-scheduled-x.json.gz"
        final.write_bytes(b"not actually gzip")
        sidecar_payload = {"database": "jen", "tables": ["settings"], "exported_at": "2026-01-01T00:00:00Z"}
        with open(dbexport._sidecar_path(str(final)), "w", encoding="utf-8") as f:
            json.dump(sidecar_payload, f)

        def boom(*a, **k):
            raise AssertionError("list_backups() opened the backup file itself")

        monkeypatch.setattr(dbexport.gzip, "open", boom)
        rows = dbexport.list_backups()
        assert len(rows) == 1
        assert rows[0]["has_sidecar"] is True
        assert rows[0]["db"] == "JEN"

    def test_a_legacy_backup_with_no_sidecar_lists_with_has_sidecar_false(self, tmp_path, monkeypatch):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        (tmp_path / "jen-manual-old.json.gz").write_bytes(b"x")
        rows = dbexport.list_backups()
        assert rows[0]["has_sidecar"] is False
        assert rows[0]["db"] == "?"

    def test_read_legacy_backup_details_parses_once_and_writes_the_sidecar(self, tmp_path, monkeypatch):
        import gzip
        import json
        import os

        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        payload = {"data": {}, "_meta": {"database": "jen", "tables": [], "exported_at": "2026-01-01T00:00:00Z"}}
        path = tmp_path / "jen-manual-old.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as f:
            json.dump(payload, f)

        result = dbexport.read_legacy_backup_details("jen-manual-old.json.gz")
        assert result["database"] == "jen"
        assert os.path.isfile(dbexport._sidecar_path(str(path)))
        # the second read must be from the sidecar alone
        rows = dbexport.list_backups()
        assert rows[0]["has_sidecar"] is True

    def test_read_legacy_backup_details_missing_file_returns_none(self, tmp_path, monkeypatch):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        assert dbexport.read_legacy_backup_details("nope.json.gz") is None


class TestWriteBackupIsAtomicAndSidecars:
    """v5.66.0-beta.6 (Q108) — _write_backup() (the Kea side) goes through publish_backup()
    now, same guarantee as the Jen side, and writes its own sidecar. Needs no DB connection —
    payload_dict is a plain dict, not a live export."""

    def test_writes_the_file_and_a_sidecar(self, tmp_path, monkeypatch):
        import gzip
        import json
        import os

        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        payload = {"_meta": {"database": "kea", "tables": ["hosts"], "exported_at": "2026-01-01T00:00:00Z"}, "data": {}}
        path = dbexport._write_backup(payload, "kea-scheduled-x.json.gz")
        assert os.path.isfile(path)
        with gzip.open(path, "rt", encoding="utf-8") as f:
            assert json.load(f) == payload
        with open(dbexport._sidecar_path(path), encoding="utf-8") as f:
            sidecar = json.load(f)
        assert sidecar["database"] == "kea"
        assert sidecar["uncompressed_bytes"] > 0

    def test_still_returns_a_bare_path_string(self, tmp_path, monkeypatch):
        """The return type must not change — routes/settings/updates.py's pre-update
        backup flashes this value directly as a path, not a tuple."""
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        result = dbexport._write_backup({"_meta": {}}, "jen-pre-update.json.gz")
        assert isinstance(result, str)


class TestPruneBackupsPerKind:
    """v5.66.0-beta.6 (Q108) — retention is per kind (jen-/kea-), scheduled files only: a
    manual or pre-update backup is never a pruning candidate, and pruning one kind never
    touches the other."""

    def _touch(self, path, age_s=0):
        import os

        path.write_bytes(b"x")
        if age_s:
            t = path.stat().st_mtime - age_s
            os.utime(path, (t, t))

    def test_only_the_named_kinds_scheduled_prefix_is_pruned(self, tmp_path, monkeypatch):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        for i in range(3):
            self._touch(tmp_path / f"jen-scheduled-{i}.json.gz", age_s=(3 - i) * 10)
        self._touch(tmp_path / "jen-manual-99.json.gz")
        self._touch(tmp_path / "kea-scheduled-0.json.gz")

        dbexport._prune_backups(1, "jen")

        remaining = {p.name for p in tmp_path.iterdir()}
        assert "jen-manual-99.json.gz" in remaining  # never a candidate
        assert "kea-scheduled-0.json.gz" in remaining  # different kind
        assert sum(1 for n in remaining if n.startswith("jen-scheduled-")) == 1
        assert "jen-scheduled-2.json.gz" in remaining  # the newest of the three survives

    def test_sidecar_removed_alongside_a_pruned_backup(self, tmp_path, monkeypatch):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        old = tmp_path / "jen-scheduled-old.json.gz"
        new = tmp_path / "jen-scheduled-new.json.gz"
        self._touch(old, age_s=100)
        self._touch(new, age_s=0)
        (tmp_path / "jen-scheduled-old.meta.json").write_text("{}", encoding="utf-8")

        dbexport._prune_backups(1, "jen")

        assert not old.exists()
        assert not (tmp_path / "jen-scheduled-old.meta.json").exists()
        assert new.exists()

    def test_fewer_than_keep_count_prunes_nothing(self, tmp_path, monkeypatch):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        self._touch(tmp_path / "jen-scheduled-a.json.gz")
        dbexport._prune_backups(7, "jen")
        assert (tmp_path / "jen-scheduled-a.json.gz").exists()


class TestSweepStalePartFiles:
    """v5.66.0-beta.6 (Q108) — a `.part-*.tmp` left behind by a killed publish_backup() is
    swept once it's genuinely old; a young one (a publish that may still be in progress) is
    left alone."""

    def test_old_part_file_removed(self, tmp_path, monkeypatch):
        import os

        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        p = tmp_path / ".part-abc123.tmp"
        p.write_bytes(b"x")
        old = p.stat().st_mtime - (dbexport._STALE_PART_AGE_S + 60)
        os.utime(p, (old, old))
        dbexport._sweep_stale_part_files()
        assert not p.exists()

    def test_young_part_file_is_left_alone(self, tmp_path, monkeypatch):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        p = tmp_path / ".part-abc123.tmp"
        p.write_bytes(b"x")
        dbexport._sweep_stale_part_files()
        assert p.exists()

    def test_non_part_files_are_never_touched(self, tmp_path, monkeypatch):
        import os

        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        p = tmp_path / "jen-scheduled-x.json.gz"
        p.write_bytes(b"x")
        old = p.stat().st_mtime - (dbexport._STALE_PART_AGE_S + 60)
        os.utime(p, (old, old))
        dbexport._sweep_stale_part_files()
        assert p.exists()


class TestJenTablesCoverage:
    """v5.44.0 (Q45) — JEN_TABLES had silently drifted behind every table
    a migration actually creates (webauthn_credentials, plugins,
    kea_config_revisions, … — found while building the recovery bundle,
    which needs export_jen() to cover everything). This pins it so the
    next new table added by a migration fails CI instead of silently
    being left out of both the recovery bundle and the regular "export
    everything" Backups feature."""

    # v5.49.0-beta.3: nothing is deliberately excluded any more —
    # schema_migrations is exported so a restore doesn't re-run every
    # migration.
    DELIBERATELY_EXCLUDED: set[str] = set()

    def _migration_created_tables(self) -> set[str]:
        import pathlib
        import re

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "models" / "migrations.py").read_text(
            encoding="utf-8"
        )
        return set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", src))

    def test_every_migration_table_is_exportable_or_deliberately_excluded(self):
        from jen.services.dbexport import JEN_TABLES

        created = self._migration_created_tables()
        assert created, "regex found no tables — migrations.py's CREATE TABLE shape changed?"
        missing = created - set(JEN_TABLES) - self.DELIBERATELY_EXCLUDED
        assert not missing, f"migration-created table(s) missing from JEN_TABLES: {missing}"

    def test_no_stale_entries_for_tables_that_no_longer_exist(self):
        """The reverse check — JEN_TABLES listing something no migration
        (or the Kea-side tables, which never belong here) creates would
        mean export_jen() tries to read a table that was never there."""
        from jen.services.dbexport import JEN_TABLES

        created = self._migration_created_tables()
        stale = set(JEN_TABLES) - created
        assert not stale, f"JEN_TABLES has entrie(s) no migration creates: {stale}"


class TestValidateSchedule:
    """v5.67.0-beta.5 (Q117, item j) — routes/database.py::save_schedule
    and routes/setup.py's own Recovery-step "schedule" action both used
    to do a bare int(form.get("hour")) with no try/except: a malformed
    value was an unhandled 500. validate_schedule() is the one shared,
    pure validator both routes now call."""

    def test_a_full_valid_form_round_trips(self):
        from jen.services.dbexport import validate_schedule

        form = {
            "enabled": "1",
            "frequency": "weekly",
            "hour": "3",
            "keep_count": "14",
            "include_jen": "1",
            "include_kea": "",
        }
        values, errors = validate_schedule(form)
        assert errors == []
        assert values == {
            "enabled": 1,
            "include_jen": 1,
            "include_kea": 0,
            "frequency": "weekly",
            "hour": 3,
            "keep_count": 14,
        }

    def test_defaults_when_fields_are_absent(self):
        from jen.services.dbexport import validate_schedule

        values, errors = validate_schedule({})
        assert errors == []
        assert values["frequency"] == "daily"
        assert values["hour"] == 2
        assert values["keep_count"] == 7
        assert values["enabled"] == 0

    def test_non_numeric_hour_is_an_error_not_a_crash(self):
        from jen.services.dbexport import validate_schedule

        values, errors = validate_schedule({"hour": "not-a-number"})
        assert "hour" not in values
        assert any("Hour" in e for e in errors)

    def test_empty_hour_falls_back_to_the_default_not_a_crash(self):
        # routes/database.py's old `int(form.get("hour", 2))` only fell
        # back to the default for a MISSING key — a present-but-empty
        # value (a cleared <input>) still reached a bare int("") and
        # crashed. validate_schedule treats empty the same as missing
        # (the more forgiving reading of a cleared form field) rather
        # than refusing it outright — either way, it never crashes.
        from jen.services.dbexport import validate_schedule

        values, errors = validate_schedule({"hour": ""})
        assert errors == []
        assert values["hour"] == 2

    def test_out_of_range_hour_is_refused(self):
        from jen.services.dbexport import validate_schedule

        for bad in ("-1", "24", "100"):
            values, errors = validate_schedule({"hour": bad})
            assert "hour" not in values, bad
            assert any("Hour" in e for e in errors), bad

    def test_boundary_hours_are_accepted(self):
        from jen.services.dbexport import validate_schedule

        for ok in ("0", "23"):
            values, errors = validate_schedule({"hour": ok})
            assert errors == [], ok
            assert values["hour"] == int(ok)

    def test_out_of_range_keep_count_is_refused(self):
        from jen.services.dbexport import validate_schedule

        for bad in ("0", "31", "-5"):
            values, errors = validate_schedule({"keep_count": bad})
            assert "keep_count" not in values, bad
            assert any("Keep" in e for e in errors), bad

    def test_an_unrecognized_frequency_is_refused(self):
        from jen.services.dbexport import validate_schedule

        values, errors = validate_schedule({"frequency": "monthly"})
        assert "frequency" not in values
        assert any("Frequency" in e for e in errors)

    def test_every_valid_frequency_round_trips(self):
        from jen.services.dbexport import VALID_SCHEDULE_FREQUENCIES, validate_schedule

        for freq in VALID_SCHEDULE_FREQUENCIES:
            values, errors = validate_schedule({"frequency": freq})
            assert errors == []
            assert values["frequency"] == freq

    def test_multiple_bad_fields_report_multiple_errors(self):
        from jen.services.dbexport import validate_schedule

        values, errors = validate_schedule({"frequency": "monthly", "hour": "99", "keep_count": "0"})
        assert len(errors) == 3
        assert values == {"enabled": 0, "include_jen": 0, "include_kea": 0}


class TestAScheduleMustBackUpSomething:
    """v5.67.0-beta.15 (Q129, item e) — an enabled schedule with neither half ticked was saved, "ran" every night
    and backed up nothing, and onboarding counted it as protection."""

    def test_enabled_with_neither_target_is_refused(self):
        from jen.services.dbexport import validate_schedule

        values, errors = validate_schedule({"enabled": "1", "include_jen": "", "include_kea": ""})
        assert errors == [
            "An enabled schedule must back up at least one thing — tick the Jen database, the Kea reservations, "
            "or both (or untick Enable)."
        ]

    @pytest.mark.parametrize(
        "form", [{"include_jen": "1"}, {"include_kea": "1"}, {"include_jen": "1", "include_kea": "1"}]
    )
    def test_enabled_with_any_target_is_fine(self, form):
        from jen.services.dbexport import validate_schedule

        assert validate_schedule({"enabled": "1", **form})[1] == []

    def test_disabled_with_neither_target_is_fine(self):
        from jen.services.dbexport import validate_schedule

        assert validate_schedule({"include_jen": "", "include_kea": ""})[1] == []

    def test_the_schedule_page_refuses_it_and_saves_nothing(self, logged_in_client, monkeypatch):
        saved = []
        monkeypatch.setattr("jen.services.dbexport.save_schedule", lambda *a: saved.append(a))
        r = logged_in_client.post("/database/schedule", data={"enabled": "1", "frequency": "daily", "hour": "2"})
        assert r.status_code == 400 and b"must back up at least one thing" in r.data
        assert saved == []

    def test_the_setup_recovery_step_refuses_it_too(self, logged_in_client, monkeypatch):
        saved = []
        monkeypatch.setattr("jen.services.dbexport.save_schedule", lambda *a: saved.append(a))
        r = logged_in_client.post("/setup/recovery", data={"action": "schedule", "enabled": "1"})
        assert b"must back up at least one thing" in r.data
        assert saved == []

    def test_a_legacy_row_with_no_target_says_so_instead_of_recording_an_empty_run(self, db, monkeypatch, tmp_path):
        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        with db.cursor() as cur:
            cur.execute(
                "REPLACE INTO backup_schedule (id, enabled, frequency, hour, keep_count, include_jen, include_kea) "
                "VALUES (1, 1, 'daily', 3, 7, 0, 0)"
            )
        db.commit()
        dbexport.run_scheduled_backup()
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT last_status FROM backup_schedule WHERE id=1")
            assert "Nothing was backed up" in cur.fetchone()["last_status"]
        assert list(tmp_path.glob("*.json.gz")) == []

    @pytest.mark.parametrize(
        "enabled,jen,kea,counts",
        [(1, 0, 0, False), (0, 1, 1, False), (1, 1, 0, True), (1, 0, 1, True), (1, 1, 1, True)],
    )
    def test_onboarding_counts_only_an_enabled_schedule_that_targets_something(
        self, monkeypatch, enabled, jen, kea, counts
    ):
        from types import SimpleNamespace

        from jen.services import dbexport as _dbexport
        from jen.services import health, onboarding

        monkeypatch.setattr(health, "run_checks", lambda ctx: [])
        monkeypatch.setattr(_dbexport, "backup_count", lambda: 0)
        monkeypatch.setattr(
            _dbexport, "get_schedule", lambda: {"enabled": enabled, "include_jen": jen, "include_kea": kea}
        )
        user = SimpleNamespace(id=1, can_access_subnet=lambda s: True)
        ctx = onboarding.build_ctx(user, True)
        assert ctx["backup_schedule_enabled"] is counts
        row = next(r for r in onboarding.checklist(ctx)["rows"] if "backup" in r["title"].lower())
        assert row["done"] is counts

    def test_no_schedule_row_at_all_is_not_protection(self, monkeypatch):
        from types import SimpleNamespace

        from jen.services import dbexport as _dbexport
        from jen.services import health, onboarding

        monkeypatch.setattr(health, "run_checks", lambda ctx: [])
        monkeypatch.setattr(_dbexport, "backup_count", lambda: 0)
        monkeypatch.setattr(_dbexport, "get_schedule", dict)
        ctx = onboarding.build_ctx(SimpleNamespace(id=1, can_access_subnet=lambda s: True), True)
        assert ctx["backup_schedule_enabled"] is False
