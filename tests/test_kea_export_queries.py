"""
tests/test_kea_export_queries.py
─────────────────────────────────
v5.67.0-beta.13 (Q127, item e) — the reservation backup carries host-scoped options only. Kea's options tables
also hold the global, subnet, class, shared-network and pool options of its config backend; a reservation backup
that did `SELECT *` over them wrote all of those back by their auto-increment ids on restore. The exporter now
takes one fixed query per table. Pure — no database: `py -m pytest --noconftest tests/test_kea_export_queries.py`;
the behaviour against real rows is in tests/kea_compat/test_db_moves.py and tests/test_kea_binary_roundtrip.py.
"""

import inspect
import re

from jen.services import dbexport

WHOLLY_SCOPED = {"hosts", "ipv6_reservations", "lease4"}  # every row of these IS what its group is about


class TestEveryExportedTableHasAFixedQuery:
    def test_the_dict_covers_exactly_the_exportable_tables(self):
        assert set(dbexport.KEA_EXPORT_SQL) == dbexport.KEA_ALL_TABLES

    def test_the_options_tables_are_never_exported_unfiltered(self):
        for t in ("dhcp4_options", "dhcp6_options"):
            sql = dbexport.KEA_EXPORT_SQL[t]
            assert "host_id IS NOT NULL" in sql, f"{t}: an options row with no host is not a reservation's"
            assert f"scope_id = {dbexport.KEA_HOST_OPTION_SCOPE}" in sql, f"{t}: only the host scope"

    def test_a_select_star_without_a_predicate_is_allowed_only_for_the_wholly_scoped_tables(self):
        for t, sql in dbexport.KEA_EXPORT_SQL.items():
            if " WHERE " not in sql:
                assert t in WHOLLY_SCOPED, (
                    f"{t}: SELECT * with no predicate over a table that holds more than its group"
                )
            assert re.fullmatch(rf"SELECT \* FROM `{t}`( WHERE .+)?", sql), sql

    def test_the_writer_uses_the_dict_and_not_a_bare_select(self):
        assert "KEA_EXPORT_SQL[tbl]" in inspect.getsource(dbexport.write_kea_export)
        assert "sql or " in inspect.getsource(dbexport._stream_table_rows)

    def test_the_jen_export_still_streams_whole_tables(self):
        assert "_stream_table_rows(conn, tbl, f)" in inspect.getsource(dbexport.write_jen_export)

    def test_the_group_says_host_scoped_options(self):
        desc = dbexport.KEA_EXPORT_GROUPS[dbexport.KEA_BACKUP_GROUP]["description"]
        assert "host-scoped options" in desc and "not global, subnet or class options" in desc


class TestTheScopeNumber:
    def test_a_hosts_options_are_scope_three(self):
        """dhcp_option_scope: 0 global, 1 subnet, 2 client-class, 3 host, 4 shared-network, 5 pool, 6 pd-pool — read from
        the real table on Kea 3.0.3, 3.2.0 and 3.3.1, and from the scope_id Kea's own reservation-add writes."""
        assert dbexport.KEA_HOST_OPTION_SCOPE == 3


class TestTheMigrationUsesTheSameQueries:
    """v5.67.0-beta.17 (Q131) — migrate_kea used to `SELECT *` the options tables (it had no `sql` parameter) while
    the export used the fixed per-table queries, so a reservation MOVE carried the config backend's global, subnet,
    pool and class options by their option_ids. One predicate per table, shared by both movers and by the
    verification."""

    def test_the_dict_is_built_from_the_one_where_table(self):
        assert set(dbexport.KEA_TABLE_WHERE) == {"dhcp4_options", "dhcp6_options"}
        for t, where in dbexport.KEA_TABLE_WHERE.items():
            assert dbexport.KEA_EXPORT_SQL[t] == f"SELECT * FROM `{t}` WHERE {where}"
        for t in dbexport.KEA_ALL_TABLES - set(dbexport.KEA_TABLE_WHERE):
            assert dbexport.KEA_EXPORT_SQL[t] == f"SELECT * FROM `{t}`"

    def test_migrate_kea_copies_through_the_dict_and_verifies_with_the_same_predicate(self):
        src = inspect.getsource(dbexport.migrate_kea)
        assert "sql=KEA_EXPORT_SQL[tbl]" in src
        assert "where=KEA_TABLE_WHERE.get(tbl)" in src

    def test_migrate_jen_is_unchanged_it_passes_no_query_and_no_predicate(self):
        src = inspect.getsource(dbexport.migrate_jen)
        assert "sql=" not in src and "KEA_" not in src and "where=" not in src

    def test_the_helpers_take_the_same_arguments_the_export_does(self):
        assert "sql" in inspect.signature(dbexport._copy_table_rows).parameters
        assert "sql" in inspect.signature(dbexport._stream_table_rows).parameters
        for fn in (dbexport._row_count, dbexport._pk_sample, dbexport._verify_copy):
            assert inspect.signature(fn).parameters["where"].default is None, fn.__name__
        assert "sql or " in inspect.getsource(dbexport._copy_table_rows)

    def test_the_wizard_page_says_the_same_thing_the_move_does(self):
        desc = dbexport.KEA_EXPORT_GROUPS[dbexport.KEA_BACKUP_GROUP]["description"]
        assert "host-scoped options" in desc and "not global, subnet or class options" in desc
