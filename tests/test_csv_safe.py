"""
tests/test_csv_safe.py
──────────────────────
v5.30.0 (Q30, A3) — the CSV formula-injection guard shared by Jen's
reservation export and the plugins' exports.
"""

import csv
import io

import pytest

from jen.services.csv_safe import safe_cell, safe_row


class TestSafeCell:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ('=HYPERLINK("http://evil")', '\'=HYPERLINK("http://evil")'),
            ("+cmd|' /C calc'!A0", "'+cmd|' /C calc'!A0"),
            ("-1+1", "'-1+1"),
            ("@SUM(A1)", "'@SUM(A1)"),
            ("\t=1+1", "'\t=1+1"),
            ("\r=1+1", "'\r=1+1"),
            ("printer-1", "printer-1"),
            ("10.0.0.5", "10.0.0.5"),
            ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
            ("", ""),
            (None, ""),
            (7, "7"),
        ],
    )
    def test_cells(self, raw, expected):
        assert safe_cell(raw) == expected

    def test_row_and_round_trip_through_the_csv_module(self):
        out = io.StringIO()
        csv.writer(out).writerow(safe_row(["10.0.0.5", "=cmd", "host"]))
        assert out.getvalue().strip() == "10.0.0.5,'=cmd,host"


class TestReservationExportIsGuarded:
    def test_export_route_quotes_a_formula_hostname(self, logged_in_client, db, monkeypatch):
        """A hostname of `=1+1` on a reservation must come out as `'=1+1`."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE hostname=%s", ("=1+1",))
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('aabbccddeeff'), 0, 1, INET_ATON('192.168.1.77'), %s)",
                ("=1+1",),
            )
        db.commit()
        try:
            r = logged_in_client.get("/reservations/export")
            assert r.status_code == 200
            assert b"'=1+1" in r.data
            assert b",=1+1," not in r.data
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM hosts WHERE hostname=%s", ("=1+1",))
            db.commit()
