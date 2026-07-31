"""
tests/test_db_context.py
────────────────────────
Connection context manager guarantees (v4.1.0).

jen_db() / kea_db() must: commit on clean exit, rollback on exception,
and always return the connection to the pool — on every path including
early returns and raised exceptions.
"""

import pytest

from jen.models import db as db_module


class FakeConnection:
    def __init__(self):
        self.committed = 0
        self.rolled_back = 0
        self.closed = 0

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1

    def close(self):
        self.closed += 1


@pytest.fixture
def fake_conn(monkeypatch):
    conn = FakeConnection()
    monkeypatch.setattr(db_module, "get_jen_db", lambda: conn)
    monkeypatch.setattr(db_module, "get_kea_db", lambda: conn)
    return conn


class TestContextManagers:

    def test_commit_and_close_on_clean_exit(self, fake_conn):
        with db_module.jen_db() as db:
            assert db is fake_conn
        assert fake_conn.committed == 1
        assert fake_conn.rolled_back == 0
        assert fake_conn.closed == 1

    def test_rollback_and_close_on_exception(self, fake_conn):
        with pytest.raises(RuntimeError):
            with db_module.jen_db():
                raise RuntimeError("boom")
        assert fake_conn.committed == 0
        assert fake_conn.rolled_back == 1
        assert fake_conn.closed == 1

    def test_close_on_early_return(self, fake_conn):
        def fn():
            with db_module.jen_db():
                return "early"
        assert fn() == "early"
        assert fake_conn.committed == 1
        assert fake_conn.closed == 1

    def test_explicit_commit_inside_block_preserved(self, fake_conn):
        with db_module.jen_db() as db:
            db.commit()  # explicit mid-block commit as many routes do
        assert fake_conn.committed == 2  # explicit + CM final
        assert fake_conn.closed == 1

    def test_kea_db_same_guarantees(self, fake_conn):
        with pytest.raises(ValueError):
            with db_module.kea_db():
                raise ValueError("boom")
        assert fake_conn.rolled_back == 1
        assert fake_conn.closed == 1

    def test_exception_propagates_unchanged(self, fake_conn):
        class Custom(Exception):
            pass
        with pytest.raises(Custom):
            with db_module.jen_db():
                raise Custom()
