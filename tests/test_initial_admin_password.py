"""
tests/test_initial_admin_password.py
────────────────────────────────────
v5.17.0 (Q6 6G) — with no JEN_INITIAL_ADMIN_PASSWORD the seed generates a
random token (not the literal "admin"), forces a change, and writes the
credential to <CONTENT_DIR>/initial-admin-password (0600).
force_password_change() deletes that file on success.
"""

import os
import stat

import pytest

from jen import extensions
from jen.models.db import _write_initial_admin_password, init_jen_db
from jen.models.user import hash_password, verify_password


@pytest.fixture
def content_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(extensions, "CONTENT_DIR", str(tmp_path))
    return tmp_path


class TestFileHelpers:
    def test_write_creates_a_0600_file_with_username_and_password(self, content_dir):
        _write_initial_admin_password("s3cr3t-token")
        p = content_dir / "initial-admin-password"
        assert p.read_text() == "admin\ns3cr3t-token\n"
        if os.name == "posix":
            assert stat.S_IMODE(p.stat().st_mode) == 0o600

    def test_write_is_best_effort_on_an_unwritable_dir(self, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_DIR", "/proc/nonexistent/nope")
        _write_initial_admin_password("x")  # must not raise

    def test_force_change_deletes_the_file(self, content_dir, logged_in_client, db):
        (content_dir / "initial-admin-password").write_text("admin\nwhatever\n")
        # flag the admin so the route runs its success path
        with db.cursor() as cur:
            cur.execute("UPDATE users SET must_change_password=1 WHERE id=1")
        db.commit()
        try:
            with logged_in_client.session_transaction() as sess:
                sess.pop("_user_cache", None)  # re-load so the flag is seen
            logged_in_client.post(
                "/force-password-change",
                data={"new_password": "brand-new-pass-99", "confirm_password": "brand-new-pass-99"},
                follow_redirects=True,
            )
            assert not (content_dir / "initial-admin-password").exists()
        finally:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE users SET password=%s, must_change_password=0 WHERE id=1",
                    (hash_password("admin"),),
                )
            db.commit()


class TestSeedSource:
    def test_seed_generates_a_token_not_the_literal_admin(self):
        import inspect

        import jen.models.db as db_module

        src = inspect.getsource(db_module.init_jen_db)
        assert "secrets.token_urlsafe" in src
        assert 'hash_password("admin")' not in src and "hash_password('admin')" not in src
        assert "initial-admin-password" in src


@pytest.fixture
def emptied_users(db):
    """Snapshot every users row, empty the table for a real seed run, then
    restore the snapshot exactly (ids included)."""
    with db.cursor() as cur:
        cur.execute("SELECT * FROM users")
        rows = cur.fetchall()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM users")
        for r in rows:
            cols = ", ".join(r.keys())
            marks = ", ".join(["%s"] * len(r))
            cur.execute(f"INSERT INTO users ({cols}) VALUES ({marks})", tuple(r.values()))
    db.commit()


class TestSeedRoundTrip:
    """Exercise the real seed against an emptied users table."""

    def test_generated_password_logs_in_and_admin_is_not_the_literal(
        self, db, tmp_path, monkeypatch, capsys, emptied_users
    ):
        monkeypatch.setattr(extensions, "CONTENT_DIR", str(tmp_path))
        monkeypatch.delenv("JEN_INITIAL_ADMIN_PASSWORD", raising=False)
        with db.cursor() as cur:
            cur.execute("DELETE FROM users")
        db.commit()

        init_jen_db()
        printed = capsys.readouterr().out
        pw_file = tmp_path / "initial-admin-password"
        assert pw_file.exists()
        _, generated = pw_file.read_text().split()
        assert "initial-admin-password" in printed

        with db.cursor() as cur:
            cur.execute("SELECT password, must_change_password FROM users WHERE username='admin'")
            row = cur.fetchone()
        assert row["must_change_password"] == 1
        assert verify_password(row["password"], generated) is True
        assert verify_password(row["password"], "admin") is False

    def test_env_var_path_writes_no_file(self, db, tmp_path, monkeypatch, emptied_users):
        monkeypatch.setattr(extensions, "CONTENT_DIR", str(tmp_path))
        monkeypatch.setenv("JEN_INITIAL_ADMIN_PASSWORD", "operator-chose-this")
        with db.cursor() as cur:
            cur.execute("DELETE FROM users")
        db.commit()

        init_jen_db()
        assert not (tmp_path / "initial-admin-password").exists()
        with db.cursor() as cur:
            cur.execute("SELECT password, must_change_password FROM users WHERE username='admin'")
            row = cur.fetchone()
        assert row["must_change_password"] == 0
        assert verify_password(row["password"], "operator-chose-this") is True
