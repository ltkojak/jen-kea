"""
tests/test_kea_test_schema.py
──────────────────────────────
v5.67.0-beta.13 (Q127) — the Kea-side tables the tests run against are Kea's real definitions (unique keys,
foreign keys, lookup tables, `schema_version`), copied from `kea-admin db-init` of Kea 3.2.0 — and defined in
TWO places: tests/conftest.py (the unit suite) and tests/system/compose/mariadb-init.sql (the system stack).
This keeps them the same statements, and pins the facts of the real schema the unit suite is there to
expose. Pure: `py -m pytest --noconftest tests/test_kea_test_schema.py`.
"""

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _conftest_statements() -> list[str]:
    src = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8").replace("\r\n", "\n")
    a = src.index("_KEA_SCHEMA_TABLES = [")
    b = src.index("\n]\n", a) + 3
    return ast.literal_eval(src[a + len("_KEA_SCHEMA_TABLES = ") : b])


def _norm(sql: str) -> str:
    return re.sub(r"\s+", " ", sql.strip().rstrip(";")).strip()


def _init_statements() -> list[str]:
    text = (ROOT / "tests" / "system" / "compose" / "mariadb-init.sql").read_text(encoding="utf-8")
    text = text.replace("\r\n", "\n").split("USE kea;", 1)[1]
    text = "\n".join(line for line in text.splitlines() if not line.strip().startswith("--"))
    return [s for s in (p.strip() for p in text.split(";\n")) if s.strip(";").strip()]


def _create(name: str) -> str:
    for s in _conftest_statements():
        if re.match(rf"CREATE TABLE IF NOT EXISTS {name}\b", s.strip()):
            return _norm(s)
    raise AssertionError(f"conftest defines no {name}")


class TestTheTwoDefinitionsAreTheSameStatements:
    def test_the_system_stack_creates_exactly_the_unit_suites_tables_and_rows(self):
        assert [_norm(s) for s in _init_statements()] == [_norm(s) for s in _conftest_statements()]


class TestTheFactsOfTheRealSchemaThisSuiteExistsToExpose:
    def test_hosts_has_the_real_unique_keys(self):
        hosts = _create("hosts")
        assert (
            "UNIQUE KEY key_dhcp4_identifier_subnet_id (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id)"
            in hosts
        )
        assert (
            "UNIQUE KEY key_dhcp6_identifier_subnet_id (dhcp_identifier, dhcp_identifier_type, dhcp6_subnet_id)"
            in hosts
        )
        assert "dhcp_identifier VARBINARY(255)" in hosts  # 255 in every 3.x, not the 128 it used to say here

    def test_children_cascade_from_hosts_and_the_options_also_carry_the_legacy_no_action_constraint(self):
        for table, cascade, legacy in (
            ("dhcp4_options", "fk_dhcp4_options_Host", "fk_options_host1"),
            ("dhcp6_options", "fk_dhcp6_options_Host", "fk_options_host10"),
        ):
            sql = _create(table)
            assert f"CONSTRAINT {cascade} FOREIGN KEY (host_id) REFERENCES hosts (host_id) ON DELETE CASCADE" in sql
            assert f"CONSTRAINT {legacy} FOREIGN KEY (host_id) REFERENCES hosts (host_id) ON DELETE NO ACTION" in sql
        assert "FOREIGN KEY (host_id) REFERENCES hosts (host_id) ON DELETE CASCADE" in _create("ipv6_reservations")

    def test_an_options_row_must_name_its_scope_and_its_client_classes(self):
        for table in ("dhcp4_options", "dhcp6_options"):
            sql = _create(table)
            assert "scope_id TINYINT UNSIGNED NOT NULL," in sql  # no default
            assert "client_classes LONGTEXT NOT NULL," in sql  # no default: omitting it is an error in strict mode

    def test_the_lookup_rows_and_the_schema_version_are_there(self):
        joined = " ".join(_norm(s) for s in _conftest_statements())
        assert (
            "INSERT IGNORE INTO host_identifier_type VALUES (0, 'hw-address'), (1, 'duid'), (2, 'circuit-id')" in joined
        )
        assert "(3, 'host')" in joined, "Kea's scope_id for a host's options is 3 (read from a real reservation-add)"
        assert "INSERT IGNORE INTO schema_version VALUES (35, 0)" in joined

    def test_the_parents_are_created_before_the_tables_that_point_at_them(self):
        names = [
            m.group(1)
            for s in _conftest_statements()
            if (m := re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", s.strip()))
        ]
        for child, parent in (
            ("hosts", "host_identifier_type"),
            ("dhcp4_options", "hosts"),
            ("dhcp4_options", "dhcp_option_scope"),
            ("dhcp6_options", "hosts"),
            ("ipv6_reservations", "hosts"),
        ):
            assert names.index(parent) < names.index(child), (parent, child)


class TestTheIpv6ColumnsAreBinaryLikeTheRealOnes:
    """v5.67.0-beta.16 (Q130) — lease6.address, ipv6_reservations.address and excluded_prefix are BINARY(16) in every
    Kea 3.x (tests/kea_compat/test_db_moves.py::test_the_v6_address_columns_are_binary_sixteen asserts it against
    ISC's own schema on each version in the matrix). This suite's tables were VARCHAR(39), so every test that seeded
    a text address hid the bug Jen's readers had. They are binary here now, and a test that seeds an address seeds
    bytes."""

    def test_lease6(self):
        sql = _create("lease6")
        assert "address BINARY(16) PRIMARY KEY NOT NULL" in sql
        assert "duid VARBINARY(130)" in sql  # 130 in every 3.x, not the 128 it used to say here
        assert "VARCHAR(39)" not in sql

    def test_ipv6_reservations(self):
        sql = _create("ipv6_reservations")
        assert "address BINARY(16) NOT NULL" in sql
        assert "excluded_prefix BINARY(16)" in sql
        assert "VARCHAR(39)" not in sql

    def test_nothing_in_the_unit_suite_still_says_the_address_is_text(self):
        src = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
        assert "VARCHAR(39)" not in src.replace("VARCHAR(39) —", "")  # the explanatory comment names the old type

    def test_no_test_seeds_a_text_literal_into_an_ipv6_address_column(self):
        """`VALUES ('2001:db8::10', ...)` into a BINARY(16) column pads the text with NULs instead of storing an
        address: every seeding statement uses INET6_ATON(...) or a packed bytes parameter."""
        offenders = []
        pattern = re.compile(
            r"INTO (?:lease6|ipv6_reservations)\s*\([^)]*\)\s*VALUES\s*\(\s*(?:\d+\s*,\s*)?'[0-9a-fA-F:]+'"
        )
        for path in sorted((ROOT / "tests").glob("test_*.py")):
            if path.name == "test_kea_test_schema.py":
                continue
            text = path.read_text(encoding="utf-8")
            for m in pattern.finditer(text):
                offenders.append(f"{path.name}: {m.group(0)[-60:]!r}")
        assert not offenders, offenders
