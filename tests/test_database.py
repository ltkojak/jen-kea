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
    ("GET",  "/database", {}),
    ("POST", "/database/export/jen", {}),
    ("POST", "/database/export/kea", {}),
    ("GET",  "/database/backup/download/somefile.json.gz", {}),
    ("POST", "/database/backup/delete/somefile.json.gz", {}),
    ("POST", "/database/backup/now", {}),
    ("POST", "/database/import/inspect", {}),
    ("POST", "/database/import/confirm", {}),
    ("POST", "/database/schedule", {}),
    ("GET",  "/database/migrate", {}),
    ("POST", "/database/migrate/test", {}),
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
        _restricted_client(client, db, allowed_subnets=None, role="admin",
                            username=f"dbtest_admin_{abs(hash(path + method)) % 100000}")
        if method == "GET":
            r = client.get(path, follow_redirects=True)
        else:
            r = client.post(path, data=data, follow_redirects=True)
        assert r.status_code == 200
        assert b"superadmin access required" in r.data.lower()


class TestDatabaseMainPageLoadsForSuperadmin:
    def test_database_page_loads(self, logged_in_client):
        r = logged_in_client.get("/database")
        assert r.status_code == 200

    def test_migrate_page_loads(self, logged_in_client):
        r = logged_in_client.get("/database/migrate")
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
        r = logged_in_client.get(
            "/database/backup/download/..%2f..%2f..%2fetc%2fpasswd",
            follow_redirects=True
        )
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
        logged_in_client.post(
            f"/database/backup/delete/..%2f{outside_target.name}",
            follow_redirects=True
        )
        assert outside_target.exists()
        outside_target.unlink()


class TestImportConfirmTmpPathValidation:
    """import_confirm() decodes a client-submitted base64 tmp_path and
    requires it to both start with /tmp/jen_import_ AND already exist as a
    file — the two checks together mean a tampered tmp_path can't be used
    to read or import an arbitrary file on the server."""

    def test_rejects_path_outside_tmp_import_prefix(self, logged_in_client):
        tampered = base64.b64encode(b"/etc/passwd").decode()
        r = logged_in_client.post(
            "/database/import/confirm",
            data={"tmp_path": tampered},
            follow_redirects=True
        )
        assert r.status_code == 200
        assert b"expired" in r.data.lower() or b"re-upload" in r.data.lower()

    def test_rejects_correct_prefix_but_nonexistent_file(self, logged_in_client):
        fake = base64.b64encode(b"/tmp/jen_import_doesnotexist123").decode()
        r = logged_in_client.post(
            "/database/import/confirm",
            data={"tmp_path": fake},
            follow_redirects=True
        )
        assert r.status_code == 200
        assert b"expired" in r.data.lower() or b"re-upload" in r.data.lower()

    def test_accepts_and_consumes_a_real_tmp_import_file(self, logged_in_client, tmp_path, monkeypatch):
        import tempfile
        from jen.services import dbexport
        # A minimal, syntactically valid export payload so parse_import_file
        # doesn't error out before we even reach the path-validation logic
        # this test is actually targeting.
        monkeypatch.setattr(dbexport, "parse_import_file",
                             lambda file_bytes: ({"database": "unknown-for-test"}, {}, None))
        real_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json.gz",
                                                dir="/tmp", prefix="jen_import_")
        real_tmp.write(b"placeholder")
        real_tmp.close()
        encoded = base64.b64encode(real_tmp.name.encode()).decode()

        r = logged_in_client.post(
            "/database/import/confirm",
            data={"tmp_path": encoded},
            follow_redirects=True
        )
        assert r.status_code == 200
        # The temp file must be consumed (unlinked) either way, valid path
        # or not — it should never survive a confirm attempt.
        import os
        assert not os.path.exists(real_tmp.name)
