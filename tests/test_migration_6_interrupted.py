"""
tests/test_migration_6_interrupted.py - v5.68.0-beta.16 (Q151, item 8): migration 6 survives a crash between its ENUM ALTER and its UPDATE.

Migration 6 expands `users.role` to include `superadmin` and promotes the legacy `admin` rows - but ONLY on a genuine pre-3.5 schema, which it detects by the
ENUM lacking 'superadmin'. The ALTER auto-commits. A crash between the ALTER and the UPDATE therefore left an ENUM that already had 'superadmin': the next start
decided "not a pre-3.5 schema" and the legacy admins were never promoted - while an unconditional promotion would escalate every modern mid-tier `admin` on
every start (the v4.2.0 bug this migration was rewritten to fix). The decision is now recorded in `settings` (`legacy_admin_promotion_pending`) BEFORE the ALTER,
and the UPDATE runs whenever the marker is set, whatever the ENUM says; the marker is cleared only after the UPDATE.

Driven against a small in-memory stand-in for the four statements the migration issues, so every crash point is exercised without touching the shared test
database's real `users` table (the real-database interrupt tests for migrations 3, 4, 8, 22 and 24 are in tests/test_migrations.py).
"""

import contextlib
import re

import pytest

from jen.models.migrations import _m006_superadmin_role

MARKER = "legacy_admin_promotion_pending"


class Interrupt(Exception):
    """The process died here."""


class FakeUsersDb:
    """`users.role`'s column type, the legacy/modern rows, `subnet_access` and the `settings` table - and nothing else."""

    def __init__(self, role_type, roles, subnet_access=True):
        self.role_type = role_type
        self.roles = list(roles)
        self.subnet_access = subnet_access
        self.settings = {}
        self.mutations = 0
        self.interrupt_before = None  # the 0-based index of the first MUTATING statement that never runs
        self.rowcount = 0
        self._fetch = None

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def fetchone(self):
        return self._fetch

    def execute(self, sql, params=()):
        text = " ".join(sql.split())
        if re.match(r"SHOW COLUMNS FROM users LIKE", text):
            column = params[0]
            if column == "role":
                self._fetch = {"Field": "role", "Type": self.role_type}
            elif column == "subnet_access":
                self._fetch = {"Field": "subnet_access", "Type": "json"} if self.subnet_access else None
            else:
                self._fetch = None
            return
        if text.startswith("SELECT setting_value FROM settings"):
            self._fetch = {"setting_value": self.settings[MARKER]} if MARKER in self.settings else None
            return
        # everything below changes something: a crash can land before any one of them
        if self.interrupt_before is not None and self.mutations == self.interrupt_before:
            raise Interrupt
        self.mutations += 1
        if text.startswith("INSERT INTO settings"):
            self.settings[MARKER] = "1"
        elif text.startswith("ALTER TABLE users MODIFY COLUMN role"):
            self.role_type = "enum('superadmin','admin','viewer')"
        elif text.startswith("UPDATE users SET role='superadmin' WHERE role='admin'"):
            promoted = [i for i, r in enumerate(self.roles) if r == "admin"]
            for i in promoted:
                self.roles[i] = "superadmin"
            self.rowcount = len(promoted)
        elif text.startswith("DELETE FROM settings"):
            self.settings.pop(MARKER, None)
        elif text.startswith("ALTER TABLE users ADD COLUMN subnet_access"):
            self.subnet_access = True
        else:
            raise AssertionError(f"migration 6 issued a statement this stand-in does not know: {text}")


PRE_35 = "enum('admin','viewer')"
MODERN = "enum('superadmin','admin','viewer')"


def _run(db):
    _m006_superadmin_role(db)


class TestAGenuinePre35Schema:
    def test_the_legacy_admins_are_promoted_once_and_the_marker_is_cleared(self):
        db = FakeUsersDb(PRE_35, ["admin", "admin", "viewer"], subnet_access=False)
        _run(db)
        assert db.roles == ["superadmin", "superadmin", "viewer"]
        assert db.role_type == MODERN and db.subnet_access and MARKER not in db.settings

    def test_the_marker_is_recorded_before_the_alter(self):
        """Interrupt BEFORE the ALTER (the marker is the first mutation): the decision is already on record."""
        db = FakeUsersDb(PRE_35, ["admin"])
        db.interrupt_before = 1
        with pytest.raises(Interrupt):
            _run(db)
        assert db.settings.get(MARKER) == "1" and db.role_type == PRE_35


class TestAModernSchemaIsNeverTouched:
    def test_a_mid_tier_admin_is_not_promoted(self):
        db = FakeUsersDb(MODERN, ["admin", "viewer", "superadmin"])
        _run(db)
        assert db.roles == ["admin", "viewer", "superadmin"] and MARKER not in db.settings and db.mutations == 0

    def test_an_admin_created_after_a_completed_migration_stays_an_admin_on_every_later_start(self):
        db = FakeUsersDb(PRE_35, ["admin"])
        _run(db)
        db.roles.append("admin")  # a deliberate mid-tier account, made after the migration
        for _ in range(3):
            _run(db)
        assert db.roles == ["superadmin", "admin"], "the marker was cleared: nobody is promoted again"


class TestACrashAtEveryPointThenARerun:
    @pytest.mark.parametrize("crash_before", [0, 1, 2, 3, 4])
    def test_the_legacy_admins_end_up_promoted_and_nothing_else_does(self, crash_before):
        db = FakeUsersDb(PRE_35, ["admin", "viewer", "admin"], subnet_access=False)
        db.interrupt_before = crash_before
        with contextlib.suppress(Interrupt):
            _run(db)
        db.interrupt_before = None
        db.mutations = 0
        _run(db)  # the next start
        assert db.roles == ["superadmin", "viewer", "superadmin"], f"crash before mutation {crash_before}"
        assert db.role_type == MODERN and db.subnet_access and MARKER not in db.settings

    def test_a_crash_between_the_alter_and_the_update_is_exactly_the_case_that_used_to_be_lost(self):
        db = FakeUsersDb(PRE_35, ["admin"])
        db.interrupt_before = 2  # marker (0), ALTER (1) done; the UPDATE (2) never runs
        with pytest.raises(Interrupt):
            _run(db)
        assert db.role_type == MODERN, (
            "the ENUM already says superadmin - the old discriminator now reads 'not pre-3.5'"
        )
        assert db.roles == ["admin"] and db.settings.get(MARKER) == "1"
        db.interrupt_before = None
        _run(db)
        assert db.roles == ["superadmin"] and MARKER not in db.settings

    def test_a_crash_after_the_update_before_the_marker_is_cleared_is_harmless(self):
        db = FakeUsersDb(PRE_35, ["admin"])
        db.interrupt_before = 3  # marker, ALTER, UPDATE done; the marker's DELETE never runs
        with pytest.raises(Interrupt):
            _run(db)
        assert db.roles == ["superadmin"] and db.settings.get(MARKER) == "1"
        db.interrupt_before = None
        _run(db)
        assert db.roles == ["superadmin"] and MARKER not in db.settings
