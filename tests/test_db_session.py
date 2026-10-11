"""Item 3 (Q172): every connection Jen opens runs in UTC - the pooled ones and the direct fallbacks - so NOW() in SQL and datetime.now(utc) in Python are one clock."""

from datetime import datetime, timezone

import pymysql

from jen.models import db as dbmod


def _zone_and_now(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT @@session.time_zone AS tz, NOW() AS now")
        return cur.fetchone()


class TestEveryConnectionIsUtc:
    def test_the_jen_pool(self):
        with dbmod.jen_db() as conn:
            row = _zone_and_now(conn)
        assert row["tz"] == "+00:00"
        assert abs((row["now"].replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).total_seconds()) < 60

    def test_the_kea_pool(self):
        with dbmod.kea_db() as conn:
            assert _zone_and_now(conn)["tz"] == "+00:00"

    def test_the_direct_fallback(self, monkeypatch):
        monkeypatch.setattr(dbmod, "_jen_pool", None)
        monkeypatch.setattr(dbmod, "_pool_failed_at", {})

        def no_pool():
            raise pymysql.err.OperationalError(2003, "pool: can't connect")

        monkeypatch.setattr(dbmod, "_make_jen_pool", no_pool)
        conn = dbmod.get_jen_db()
        try:
            assert _zone_and_now(conn)["tz"] == "+00:00"
        finally:
            conn.close()

    def test_the_export_and_migration_connections_too(self):
        from jen.services import dbexport

        for make in (dbexport._direct_jen_conn, dbexport._direct_kea_conn):
            conn = make()
            try:
                assert _zone_and_now(conn)["tz"] == "+00:00", make.__name__
            finally:
                conn.close()


class TestNoConnectionIsOpenedWithoutIt:
    """The six places that open one (three pools, three direct fallbacks) and the three export helpers all carry the init command - a source test, so a fourth
    connection added later without it fails here and not on a host east of UTC."""

    def test_every_pymysql_connect_and_pool_in_the_db_layer_names_the_zone(self):
        import pathlib
        import re

        for rel in ("jen/models/db.py", "jen/services/dbexport.py"):
            text = pathlib.Path(rel).read_text(encoding="utf-8")
            opens = len(re.findall(r"pymysql\.connect\(|PooledDB\(", text))
            named = text.count("init_command=SESSION_TIME_ZONE_INIT")
            assert opens == named, f"{rel}: {opens} connection(s) opened, {named} carry the UTC init command"
