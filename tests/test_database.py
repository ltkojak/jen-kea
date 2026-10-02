"""
tests/test_database.py
───────────────────────
database.py had zero test coverage of any kind before v4.4.5 — not even
incidental coverage from another test file. It's the highest blast-radius
route file in the app (full DB export/import/restore/migrate, gated
superadmin-only since v4.4.2), and there was nothing that would catch a
regression like "someone accidentally weakens @_superadmin_required on
/database/import/confirm" — which is exactly the class of bug
/mfa/admin-reset turned out to be elsewhere in the app.

This file is deliberately focused on the authorization boundary (every
route, not a sample) plus the two path-handling checks that matter for a
file-download/file-import surface, rather than re-testing export/import
correctness already covered at the service layer by test_dbexport.py.
"""

import base64

import pytest

from tests.conftest import restricted_client as _restricted_client

# Every route in jen/routes/database.py, with its method and a form/body
# that gets it as far as the auth check (not necessarily further — we're
# testing the gate, not full functional behavior).
_DATABASE_ROUTES = [
    # ("GET", "/database") — v5.9.0: the page itself (Settings → Databases) is admin-visible for the
    # Connections tab; every tool below stays superadmin-only and is what this list guards.
    ("POST", "/database/export/jen", {}),
    ("POST", "/database/export/kea", {}),
    ("GET", "/database/backup/download/somefile.json.gz", {}),
    ("POST", "/database/backup/delete/somefile.json.gz", {}),
    ("POST", "/database/backup/details/somefile.json.gz", {}),  # v5.66.0-beta.6 (Q108)
    ("POST", "/database/backup/now", {}),
    ("POST", "/database/import/inspect", {}),
    ("POST", "/database/import/confirm", {}),
    ("POST", "/database/schedule", {}),
    ("GET", "/settings/databases/migrate", {}),
    ("POST", "/database/migrate/test", {}),
    ("POST", "/settings/databases/recovery-bundle", {}),  # v5.44.0 (Q45)
    ("GET", "/database/kea-identifiers", {}),  # v5.67.0-beta.11 (Q123)
    ("POST", "/database/kea-identifiers/repair", {}),
    # /database/migrate/run deliberately excluded — it spawns a background
    # thread and streams SSE; the auth decorator runs before any of that,
    # so it's covered adequately by the same pattern, but exercising it
    # here would leave a dangling thread per test run.
]


class TestDatabaseRoutesRejectAnonymous:
    """Every route must require login. Flask-Login's default unauthorized
    handler redirects to the login page (302) rather than a form-postable
    endpoint returning 401/403 directly."""

    @pytest.mark.parametrize("method,path,data", _DATABASE_ROUTES)
    def test_anonymous_is_redirected(self, client, method, path, data):
        if method == "GET":
            r = client.get(path, follow_redirects=False)
        else:
            r = client.post(path, data=data, follow_redirects=False)
        assert r.status_code in (301, 302, 308, 401)
        if r.status_code in (301, 302, 308):
            assert "login" in r.headers.get("Location", "").lower()


class TestDatabaseRoutesRejectPlainAdmin:
    """A plain admin (not superadmin) must be rejected on every route here.
    This is the actual regression class this file exists to catch — see
    module docstring."""

    @pytest.mark.parametrize("method,path,data", _DATABASE_ROUTES)
    def test_plain_admin_forbidden(self, client, db, method, path, data):
        _restricted_client(
            client, db, allowed_subnets=None, role="admin", username=f"dbtest_admin_{abs(hash(path + method)) % 100000}"
        )
        if method == "GET":
            r = client.get(path, follow_redirects=True)
        else:
            r = client.post(path, data=data, follow_redirects=True)
        assert r.status_code == 200
        assert b"superadmin access required" in r.data.lower()


class TestDatabaseMainPageLoadsForSuperadmin:
    def test_database_page_loads(self, logged_in_client):
        r = logged_in_client.get("/settings/databases")
        assert r.status_code == 200

    def test_migrate_page_loads(self, logged_in_client):
        r = logged_in_client.get("/settings/databases/migrate")
        assert r.status_code == 200


class TestBackupPathTraversalProtection:
    """download_backup/delete_backup both run filename through
    os.path.basename() before joining onto BACKUP_DIR. Confirm a
    traversal-shaped filename can't escape BACKUP_DIR — it should just
    resolve to a (nonexistent) file with the traversal characters
    stripped, not touch anything outside BACKUP_DIR."""

    def test_download_traversal_resolves_within_backup_dir(self, logged_in_client, monkeypatch, tmp_path):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        r = logged_in_client.get("/database/backup/download/..%2f..%2f..%2fetc%2fpasswd", follow_redirects=True)
        # Either 404 (Werkzeug's <path:filename> still can't smuggle a
        # literal escape) or Jen's own "not found" flash — either way,
        # nothing outside tmp_path was ever touched.
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            assert b"not found" in r.data.lower() or b"backup file not found" in r.data.lower()

    def test_delete_traversal_does_not_remove_arbitrary_file(self, logged_in_client, monkeypatch, tmp_path):
        from jen.services import dbexport

        outside_target = tmp_path.parent / "should_not_be_deleted.txt"
        outside_target.write_text("do not delete me")
        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        logged_in_client.post(f"/database/backup/delete/..%2f{outside_target.name}", follow_redirects=True)
        assert outside_target.exists()
        outside_target.unlink()


class TestBackupNowWritesStraightToDisk:
    """v5.66.0-beta.4 (Q106) — backup_now()'s 'jen' branch moved onto
    dbexport.write_jen_export() directly (no more export_jen() bytes +
    json.loads() + _write_backup() round trip)."""

    def test_jen_backup_is_written_and_readable(self, logged_in_client, db, mock_kea, monkeypatch, tmp_path):
        import gzip
        import json

        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        r = logged_in_client.post("/database/backup/now", data={"include": ["jen"]}, follow_redirects=True)
        assert r.status_code == 200
        assert b"backup saved" in r.data.lower()

        files = list(tmp_path.glob("jen-manual-*.json.gz"))
        assert len(files) == 1
        with gzip.open(files[0], "rt", encoding="utf-8") as f:
            payload = json.loads(f.read())
        assert payload["_meta"]["database"] == "jen"
        assert "settings" in payload["data"]


class TestImportConfirmTmpPathValidation:
    """import_confirm() decodes a client-submitted base64 tmp_path and requires it to both
    resolve inside Jen's own CONTENT_TMP_DIR scratch directory AND already exist as a file —
    the two checks together mean a tampered tmp_path can't be used to read or import an
    arbitrary file on the server. v5.66.0-beta.6 (Q108) moved the real directory off /tmp
    (import_inspect() now spools there too, alongside every other Jen scratch file) —
    validation follows the same directory, not a hardcoded /tmp prefix."""

    def test_rejects_path_outside_the_scratch_directory(self, logged_in_client):
        tampered = base64.b64encode(b"/etc/passwd").decode()
        r = logged_in_client.post("/database/import/confirm", data={"tmp_path": tampered}, follow_redirects=True)
        assert r.status_code == 200
        assert b"expired" in r.data.lower() or b"re-upload" in r.data.lower()

    def test_rejects_correct_prefix_but_nonexistent_file(self, logged_in_client):
        import os

        from jen import extensions

        fake_path = os.path.join(extensions.CONTENT_TMP_DIR, "jen_import_doesnotexist123.json.gz")
        fake = base64.b64encode(fake_path.encode()).decode()
        r = logged_in_client.post("/database/import/confirm", data={"tmp_path": fake}, follow_redirects=True)
        assert r.status_code == 200
        assert b"expired" in r.data.lower() or b"re-upload" in r.data.lower()

    def test_accepts_and_consumes_a_real_tmp_import_file(self, logged_in_client, monkeypatch):
        import os
        import tempfile

        from jen import extensions
        from jen.services import dbexport

        # A minimal, syntactically valid export payload so parse_import_file
        # doesn't error out before we even reach the path-validation logic
        # this test is actually targeting.
        monkeypatch.setattr(
            dbexport, "parse_import_file", lambda file_bytes: ({"database": "unknown-for-test"}, {}, None)
        )
        os.makedirs(extensions.CONTENT_TMP_DIR, exist_ok=True)
        # kept past the block on purpose — the route reads it back by path
        real_tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
            delete=False, suffix=".json.gz", dir=extensions.CONTENT_TMP_DIR, prefix="jen_import_"
        )
        real_tmp.write(b"placeholder")
        real_tmp.close()
        encoded = base64.b64encode(real_tmp.name.encode()).decode()

        r = logged_in_client.post("/database/import/confirm", data={"tmp_path": encoded}, follow_redirects=True)
        assert r.status_code == 200
        # The temp file must be consumed (unlinked) either way, valid path
        # or not — it should never survive a confirm attempt.
        assert not os.path.exists(real_tmp.name)


class TestImportInspectCapAndAdmission:
    """v5.66.0-beta.6 (Q108) — import_inspect() spools the upload (never f.read()), refuses
    above [backups] max_import_mb, then runs the same admission check a restore does before
    ever calling parse_import_file()."""

    def _with_max_import_mb(self, monkeypatch, mb):
        import configparser

        from jen import extensions

        test_cfg = configparser.ConfigParser()
        test_cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        test_cfg.read_dict({"backups": {"max_import_mb": str(mb)}})
        monkeypatch.setattr(extensions, "cfg", test_cfg)

    def test_upload_over_the_cap_is_refused_before_anything_is_parsed(self, logged_in_client, monkeypatch):
        import io

        from jen.services import dbexport

        self._with_max_import_mb(monkeypatch, 1)  # 1 MB cap

        def boom(file_bytes):
            raise AssertionError("parse_import_file() ran on an upload that was over the cap")

        monkeypatch.setattr(dbexport, "parse_import_file", boom)

        oversized = b"x" * (2 * 1024 * 1024)  # 2 MB, over the 1 MB cap
        r = logged_in_client.post(
            "/database/import/inspect",
            data={"file": (io.BytesIO(oversized), "big.json.gz")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"cap" in r.data.lower() or b"512" in r.data or b"1 mb" in r.data.lower()

    def test_admission_check_refuses_before_parsing(self, logged_in_client, monkeypatch):
        """A tiny available-memory answer must refuse a real (small but nonzero) gzip
        upload before parse_import_file() ever runs — mirroring restore.check_memory()'s
        own 'refuses before anything is touched' property."""
        import gzip
        import io

        from jen.services import dbexport

        content = gzip.compress(b'{"data": {}, "_meta": {"database": "jen"}}' * 1000)

        def boom(file_bytes):
            raise AssertionError("parse_import_file() ran despite the admission check refusing")

        monkeypatch.setattr(dbexport, "parse_import_file", boom)
        monkeypatch.setattr("jen.tools.restore._mem_available_bytes", lambda: 1)  # ~0 available

        r = logged_in_client.post(
            "/database/import/inspect",
            data={"file": (io.BytesIO(content), "small.json.gz")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200

    def test_a_small_valid_export_reaches_the_confirm_page(self, logged_in_client):
        import gzip
        import io
        import json

        payload = {"data": {"settings": []}, "_meta": {"database": "jen", "tables": ["settings"]}}
        content = gzip.compress(json.dumps(payload).encode())
        r = logged_in_client.post(
            "/database/import/inspect",
            data={"file": (io.BytesIO(content), "small.json.gz")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"confirm" in r.data.lower() or b"import" in r.data.lower()


class TestRecoveryBundleRoute:
    """v5.44.0 (Q45) — POST /settings/databases/recovery-bundle. The
    generic superadmin/anonymous gating is already covered by
    _DATABASE_ROUTES above; this is the route's own behavior."""

    PASSPHRASE = "correct horse battery staple"

    def test_passphrase_too_short_is_rejected(self, logged_in_client):
        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": "short", "passphrase_confirm": "short"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"at least" in r.data.lower()

    def test_mismatched_confirmation_is_rejected(self, logged_in_client):
        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": "a different phrase entirely"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"did not match" in r.data.lower()

    def test_successful_build_streams_a_decryptable_bundle(self, logged_in_client, db, mock_kea):
        from jen.services.recovery import open_bundle

        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )
        assert r.status_code == 200
        assert r.headers["Content-Disposition"].startswith("attachment;")
        assert r.data.startswith(b"JENREC2")  # v5.65.0: the streaming format
        assert int(r.headers["Content-Length"]) == len(r.data)
        tf = open_bundle(r.data, self.PASSPHRASE)
        names = tf.getnames()
        assert "manifest.json" in names
        assert "jen_db.json.gz" in names

    def test_an_over_the_cap_bundle_is_refused_with_no_file_left(
        self, logged_in_client, db, mock_kea, monkeypatch, tmp_path
    ):
        """v5.65.0 (Q85) - the cap now bites on file SIZES before anything is written."""
        from jen import extensions
        from jen.services import recovery

        content = tmp_path / "content"
        content.mkdir()
        (content / "big.bin").write_bytes(b"0" * 5000)
        tmp = tmp_path / "tmp"
        monkeypatch.setattr(extensions, "CONTENT_DIR", str(content))
        monkeypatch.setattr(extensions, "CONTENT_TMP_DIR", str(tmp))
        monkeypatch.setattr(recovery, "SIZE_CAP_BYTES", 4000)
        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
            follow_redirects=True,
        )
        assert r.status_code == 200 and b"size cap" in r.data
        assert not tmp.exists() or list(tmp.iterdir()) == []

    def test_wrong_passphrase_cannot_open_it(self, logged_in_client, db, mock_kea):
        from jen.services.recovery import BadPassphrase, open_bundle

        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )
        with pytest.raises(BadPassphrase):
            open_bundle(r.data, "not the right passphrase")

    def test_audit_logged(self, logged_in_client, db, mock_kea):
        with db.cursor() as cur:
            cur.execute("DELETE FROM audit_log WHERE action='RECOVERY_BUNDLE_EXPORT'")
        db.commit()
        logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM audit_log WHERE action='RECOVERY_BUNDLE_EXPORT'")
            assert cur.fetchone()["cnt"] == 1

    def test_manifest_carries_jen_version_and_channel(self, logged_in_client, db, mock_kea):
        import json

        from jen import JEN_VERSION
        from jen.services.recovery import open_bundle

        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )
        tf = open_bundle(r.data, self.PASSPHRASE)
        manifest = json.loads(tf.extractfile("manifest.json").read())
        assert manifest["jen_version"] == JEN_VERSION
        assert "channel" in manifest and "schema_version" in manifest

    def test_manifest_carries_the_db_export_size_and_audit_history_included_by_default(
        self, logged_in_client, db, mock_kea
    ):
        """v5.66.0-beta.4 (Q106) — jen.tools.restore's pre-restore memory guard reads
        jen_db_uncompressed_bytes/jen_db_rows straight from this manifest."""
        import json

        from jen.services.recovery import open_bundle

        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )
        tf = open_bundle(r.data, self.PASSPHRASE)
        manifest = json.loads(tf.extractfile("manifest.json").read())
        assert isinstance(manifest["jen_db_uncompressed_bytes"], int) and manifest["jen_db_uncompressed_bytes"] > 0
        assert isinstance(manifest["jen_db_rows"], int)
        assert manifest["jen_db_audit_history_included"] is True

    def test_without_audit_history_excludes_the_table_and_says_so_in_the_manifest(self, logged_in_client, db, mock_kea):
        import gzip
        import json

        from jen.services.recovery import open_bundle

        with db.cursor() as cur:
            cur.execute("DELETE FROM audit_log")
            cur.execute("INSERT INTO audit_log (action, entity, details, username) VALUES ('NOTE', 'x', 'y', 'admin')")
        db.commit()

        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={
                "passphrase": self.PASSPHRASE,
                "passphrase_confirm": self.PASSPHRASE,
                "without_audit_history": "1",
            },
        )
        tf = open_bundle(r.data, self.PASSPHRASE)
        manifest = json.loads(tf.extractfile("manifest.json").read())
        assert manifest["jen_db_audit_history_included"] is False
        db_export = json.loads(gzip.decompress(tf.extractfile("jen_db.json.gz").read()))
        assert "audit_log" not in db_export["data"]
        assert "settings" in db_export["data"]  # every OTHER table is still there

    def test_no_temp_files_left_behind_after_a_successful_build(
        self, logged_in_client, db, mock_kea, monkeypatch, tmp_path
    ):
        """The DB export is written to a 0600 temp file beside the bundle's own — both must be
        gone once the response has been fully consumed, not just the bundle's own tempfile."""
        from jen import extensions

        content_tmp = tmp_path / "content-tmp"
        content_tmp.mkdir()
        monkeypatch.setattr(extensions, "CONTENT_TMP_DIR", str(content_tmp))
        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )
        assert r.status_code == 200
        _ = r.data  # force the streamed body through fully (the test client already buffers it)
        assert list(content_tmp.iterdir()) == []

    def test_last_recovery_bundle_settings_are_recorded_once_the_stream_finishes(self, logged_in_client, db, mock_kea):
        """v5.67.0-beta.5 (Q117, item i) — /setup's Recovery step relies on
        these three settings to tell a real download from a clicked
        button; this is the one route that writes them."""
        from jen.models.user import get_global_setting

        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )
        assert r.status_code == 200
        body = r.data  # force the streamed body through fully — the setting is written in _stream()'s finally
        assert get_global_setting("last_recovery_bundle_at", "") != ""
        assert get_global_setting("last_recovery_bundle_size", "") == str(len(body))
        assert get_global_setting("last_recovery_bundle_excluded_audit", "") == "false"

    def test_recovery_bundle_status_is_fresh_through_the_real_writers_not_a_typeerror(
        self, logged_in_client, db, mock_kea
    ):
        """v5.67.0-beta.7 (Q119, item f) — setup_wizard_started_at
        (mark_started(), timezone-AWARE) and last_recovery_bundle_at
        (this route's own _stream(), used to be NAIVE) compared with a
        bare datetime.fromisoformat() raised TypeError — not the
        ValueError recovery_bundle_status()'s own try/except actually
        catches, so it propagated as a 500. Exercised here through both
        REAL writers, never a hand-built naive string, which is exactly
        what let the bug through the test suite the first time: 500s on
        GET /setup/recovery, its "done" POST, and /getting-started, for
        every admin, from the moment a bundle had actually been
        downloaded."""
        from jen.services import setup_wizard

        setup_wizard.mark_started()
        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )
        assert r.status_code == 200
        _ = r.data  # force the streamed body through fully

        status = setup_wizard.recovery_bundle_status()  # must not raise
        assert status["exists"] is True
        assert status["fresh"] is True


class TestRecoveryBundleKeys:
    """v5.49.0-beta.2 (audit B) - the fallback secret/MFA keys ride as
    explicit members (restored 0600), never as ordinary content/ files."""

    PASSPHRASE = "correct horse battery staple"

    def test_fallback_keys_are_explicit_members_exactly_once(
        self, logged_in_client, db, mock_kea, monkeypatch, tmp_path
    ):
        from jen import extensions
        from jen.services.recovery import open_bundle

        content = tmp_path / "content"
        (content / "keys").mkdir(parents=True)
        (content / "keys" / ".secret_key").write_text("s" * 64)
        (content / "keys" / ".mfa_key").write_text("m" * 44)
        (content / "logo.png").write_bytes(b"png")
        monkeypatch.setattr(extensions, "CONTENT_DIR", str(content))
        monkeypatch.setattr(extensions, "CONTENT_KEYS_DIR", str(content / "keys"))
        monkeypatch.setattr(extensions, "MFA_KEY_PATH", str(tmp_path / "nowhere" / "mfa_key"))

        r = logged_in_client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )
        names = open_bundle(r.data, self.PASSPHRASE).getnames()
        assert names.count("mfa_key") == 1 and names.count("secret_key") == 1
        assert not any(n.startswith("content/keys") for n in names)
        assert "content/logo.png" in names


class TestBundleDownloadsAreNoStore:
    """v5.49.0-beta.5 (Q55-M) - the recovery bundle and the database exports
    are secrets/PII: never cached; a failure before streaming leaves no file."""

    PASSPHRASE = "correct horse battery staple"

    def _post_recovery(self, client):
        return client.post(
            "/settings/databases/recovery-bundle",
            data={"passphrase": self.PASSPHRASE, "passphrase_confirm": self.PASSPHRASE},
        )

    def test_recovery_bundle_is_no_store(self, logged_in_client, db, mock_kea):
        r = self._post_recovery(logged_in_client)
        assert r.status_code == 200
        assert r.headers["Cache-Control"] == "no-store"

    def test_jen_export_is_no_store(self, logged_in_client, db):
        r = logged_in_client.post("/database/export/jen", data={"tables": ["settings"]})
        assert r.status_code == 200
        assert r.headers["Cache-Control"] == "no-store"

    def test_kea_export_is_no_store(self, logged_in_client, db):
        r = logged_in_client.post("/database/export/kea", data={"group": "reservations"})
        assert r.status_code == 200
        assert r.headers["Cache-Control"] == "no-store"

    def test_a_failing_build_leaves_no_file_in_the_tmp_dir(self, logged_in_client, db, mock_kea, monkeypatch, tmp_path):
        from jen import extensions
        from jen.services import recovery

        monkeypatch.setattr(extensions, "CONTENT_TMP_DIR", str(tmp_path))

        def boom(*a, **k):
            raise RuntimeError("build failed")

        monkeypatch.setattr(recovery, "build_stream", boom)
        r = self._post_recovery(logged_in_client)
        assert r.status_code in (200, 302)
        assert list(tmp_path.iterdir()) == []

    def test_a_failure_after_the_file_is_written_removes_it(
        self, logged_in_client, db, mock_kea, monkeypatch, tmp_path
    ):
        from jen import extensions
        from jen.models import user as user_module

        monkeypatch.setattr(extensions, "CONTENT_TMP_DIR", str(tmp_path))
        real_audit = user_module.audit

        def failing_audit(action, *a, **k):
            if action == "RECOVERY_BUNDLE_EXPORT":
                raise RuntimeError("audit down")
            return real_audit(action, *a, **k)

        monkeypatch.setattr(user_module, "audit", failing_audit)
        r = self._post_recovery(logged_in_client)
        assert r.status_code in (200, 302)  # a flash and a redirect, not a 500
        assert list(tmp_path.iterdir()) == []  # the half-made secrets file is gone

    def test_recovery_card_is_visibly_different_from_the_support_bundle(self, logged_in_client, db):
        recovery_page = logged_in_client.get("/settings/databases?tab=recovery").data.decode()
        assert "Recovery bundle — contains secrets" in recovery_page
        assert "NOT redacted" in recovery_page and "support bundle" in recovery_page
        system_page = logged_in_client.get("/settings/system").data.decode()
        assert "redacted</strong> one" in system_page

    def test_no_plugin_backup_notice_with_no_plugins_installed(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM settings WHERE setting_key='plugin_backup_notice_seen'")
            cur.execute("DELETE FROM plugins")
        db.commit()
        page = logged_in_client.get("/settings/databases?tab=recovery").data.decode()
        assert "Plugin data is now part of every recovery bundle" not in page

    def test_plugin_backup_notice_shown_until_a_real_export_carries_a_plugin_table(
        self, logged_in_client, db, monkeypatch
    ):
        """v5.66.0-beta.5 (Q107) — a superadmin with a plugin installed sees the one-time notice
        until write_jen_export() actually carries that plugin's tables (jen/services/dbexport.py),
        which is exactly what proves a fresh, Q107-aware bundle has been taken since. The route
        checks table EXISTENCE (dbexport.export_table_groups()), not a `plugins` DB row — that
        row is write-only bookkeeping the registry-install flow populates, never plain
        enable_plugin() (the only way a bundled plugin like this one actually gets enabled) — so
        the table has to be real, via a real migration run, not just a fake row."""
        import json
        import os
        import pathlib

        from jen import extensions
        from jen.services.plugins import run_plugin_migrations

        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", os.path.join(extensions.JEN_ROOT, "plugins"))
        manifest_path = pathlib.Path(extensions.JEN_ROOT) / "plugins" / "wol" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        with db.cursor() as cur:
            cur.execute("DELETE FROM settings WHERE setting_key='plugin_backup_notice_seen'")
            cur.execute("DROP TABLE IF EXISTS wol_hosts")
            cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id='wol'")
        db.commit()
        ok, msg, _count = run_plugin_migrations(manifest)
        assert ok, msg

        page = logged_in_client.get("/settings/databases?tab=recovery").data.decode()
        assert "Plugin data is now part of every recovery bundle" in page

        from jen.models.user import set_global_setting

        set_global_setting("plugin_backup_notice_seen", "1")
        page = logged_in_client.get("/settings/databases?tab=recovery").data.decode()
        assert "Plugin data is now part of every recovery bundle" not in page

        # tidy: this is a real commit against the shared session-scoped test database, not a
        # rolled-back transaction — leave no trace of the real table for a later test.
        with db.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS wol_hosts")
            cur.execute("DELETE FROM plugin_schema_migrations WHERE plugin_id='wol'")
            cur.execute("DELETE FROM settings WHERE setting_key='plugin_backup_notice_seen'")
        db.commit()


class TestBackupDownloadIsNoStore:
    """v5.49.0-beta.6 (Q56-7) - the scheduled-backup download is a database dump."""

    def test_no_store_header(self, logged_in_client, db, monkeypatch, tmp_path):
        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        (tmp_path / "jen-manual-test.json.gz").write_bytes(b"gz")
        r = logged_in_client.get("/database/backup/download/jen-manual-test.json.gz")
        assert r.status_code == 200
        assert r.headers["Cache-Control"] == "no-store"

    def test_50mb_backup_download_stays_memory_bounded(self, logged_in_client, db, monkeypatch, tmp_path):
        """v5.66.0-beta.6 (Q108) — send_file() streams straight from disk; the old
        `f.read()` + `Response(data, ...)` held the whole file in the worker's memory for
        the length of the request."""
        import tracemalloc

        from jen.services import dbexport

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        path = tmp_path / "jen-manual-big.json.gz"
        with open(path, "wb") as f:
            f.seek(50 * 1024 * 1024 - 1)
            f.write(b"\0")  # a real 50 MB sparse file on disk — never held whole to create it

        tracemalloc.start()
        try:
            r = logged_in_client.get("/database/backup/download/jen-manual-big.json.gz")
            # count bytes WITHOUT retaining them — b"".join(r.response) would itself hold a
            # second full copy of the body, swamping the very peak this test is measuring
            total = 0
            for chunk in r.response:
                total += len(chunk)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert total == 50 * 1024 * 1024
        print(f"MEASURED backup-download peak for a 50 MB file: {peak} bytes ({peak / (1024 * 1024):.1f} MB)")
        assert peak < 20 * 1024 * 1024, f"download of a 50 MB backup peaked at {peak} bytes — no longer streamed"
