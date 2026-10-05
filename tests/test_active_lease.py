"""
tests/test_active_lease.py
───────────────────────────
v5.68.0-beta.10 (Q145) — ONE definition of "this lease is current": state 0 AND not past its expiry
(`client_subject.ACTIVE_LEASE4`, and its v6 twin `kea6.ACTIVE_LEASE6`). Kea keeps a state-0 row past its `expire` until reclamation
removes it, and five readers asked `state = 0` alone, so an expired row was "the current lease": it decided who holds an address,
which MAC a hostname resolves to, what the Investigation page called the client's lease, what Explain read the client id and hostname
from, and (v6) how many active leases a subnet had. `TestTheSourceHasOneSpelling` is pure (`--noconftest`); the rest seed an
expired state-0 row beside an active one and assert each of those consequences against the real test database.
"""

import pathlib
import re

import pytest

from jen import extensions
from jen.services import client_subject as cs
from jen.services import kea6

ROOT = pathlib.Path(__file__).resolve().parent.parent
GHOST_MAC = "aa:bb:cc:dd:ee:71"
GHOST_HEX = "AABBCCDDEE71"
LIVE_MAC = "aa:bb:cc:dd:ee:72"
LIVE_HEX = "AABBCCDDEE72"
GHOST_IP = "10.71.0.10"
LIVE_IP = "10.71.0.11"


class TestTheSourceHasOneSpelling:
    """The three modules that read "the current lease" never write `state = 0` themselves: it lives in the two constants."""

    FILES = ("jen/services/client_subject.py", "jen/services/kea6.py", "jen/services/explain_context.py")

    def test_the_constants_are_the_documented_predicate(self):
        assert cs.ACTIVE_LEASE4 == "state = 0 AND expire > NOW()"
        assert kea6.ACTIVE_LEASE6 == "state = 0 AND expire > NOW()"

    @pytest.mark.parametrize("path", FILES)
    def test_no_query_spells_state_zero_by_hand(self, path):
        text = (ROOT / path).read_text(encoding="utf-8")
        spelled = [
            line.strip()
            for line in text.splitlines()
            if re.search(r"\bstate\s*=\s*0\b", line) and not line.lstrip().startswith(("ACTIVE_LEASE", "#", '"""', "`"))
        ]
        spelled = [s for s in spelled if "ACTIVE_LEASE" not in s]
        assert not spelled, f"{path} spells the current-lease predicate by hand instead of ACTIVE_LEASE4/6: {spelled}"

    def test_every_current_lease_query_names_the_constant(self):
        text = (ROOT / "jen/services/client_subject.py").read_text(encoding="utf-8")
        assert text.count("{ACTIVE_LEASE4}") >= 5, (
            "client_subnet_for_mac, load_leases4 x2, mac_from_ip, macs_for_hostname"
        )
        assert "{_cs.ACTIVE_LEASE4}" in (ROOT / "jen/services/explain_context.py").read_text(encoding="utf-8")
        assert "where.append(ACTIVE_LEASE6)" in (ROOT / "jen/services/kea6.py").read_text(encoding="utf-8")


@pytest.fixture
def leases(db, monkeypatch):
    """GHOST: a state-0 lease1 hour past its expiry (hostname 'ghost-host', a client id, an address); LIVE: an active one."""
    monkeypatch.setattr(
        extensions, "SUBNET_MAP", {1: {"name": "A", "cidr": "10.71.0.0/24"}, 2: {"name": "B", "cidr": "10.72.0.0/24"}}
    )
    _wipe(db)
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, client_id, subnet_id, valid_lifetime, expire, state, hostname) VALUES "
            "(INET_ATON(%s), UNHEX(%s), UNHEX('01AABBCCDDEE71'), 1, 3600, DATE_SUB(NOW(), INTERVAL 1 HOUR), 0, 'ghost-host'), "
            "(INET_ATON(%s), UNHEX(%s), UNHEX('01AABBCCDDEE72'), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0, 'live-host')",
            (GHOST_IP, GHOST_HEX, LIVE_IP, LIVE_HEX),
        )
    db.commit()
    yield
    _wipe(db)


def _wipe(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM lease4 WHERE address IN (INET_ATON(%s), INET_ATON(%s))", (GHOST_IP, LIVE_IP))
        cur.execute("DELETE FROM lease6 WHERE subnet_id IN (771, 772)")
    db.commit()


class TestAnExpiredStateZeroRowIsNotTheCurrentLease:
    """The six consequences the review listed, one test each (the sixth is v6, below)."""

    def test_1_it_is_not_the_clients_lease_by_mac(self, leases):
        assert cs.load_leases4(GHOST_MAC) == []
        assert [row["ip"] for row in cs.load_leases4(LIVE_MAC)] == [LIVE_IP], "the active lease is still found"

    def test_2_it_is_not_the_lease_at_that_address(self, leases):
        assert cs.load_leases4("", GHOST_IP) == []
        assert [row["hostname"] for row in cs.load_leases4("", LIVE_IP)] == ["live-host"]

    def test_3_it_does_not_hold_the_address(self, leases):
        assert cs.mac_from_ip(GHOST_IP) == ""
        assert cs.mac_from_ip(LIVE_IP) == LIVE_MAC

    def test_4_its_hostname_resolves_to_no_one(self, leases):
        assert GHOST_MAC not in cs.macs_for_hostname("ghost-host")
        assert LIVE_MAC in cs.macs_for_hostname("live-host")

    def test_5_the_client_is_not_placed_by_it(self, leases):
        # no reservation, no device row: the expired lease must not be what places the client in subnet 1
        assert cs.client_subnet_for_mac(GHOST_MAC) is None
        assert cs.client_subnet_for_mac(LIVE_MAC) == 1

    def test_6_explain_reads_nothing_from_it(self, logged_in_client, leases, mock_kea, monkeypatch):
        cfg = {
            "valid-lifetime": 3600,
            "subnet4": [{"id": 1, "subnet": "10.71.0.0/24", "pools": [{"pool": "10.71.0.100 - 10.71.0.200"}]}],
        }
        monkeypatch.setattr("jen.routes.explain.dhcp4_config", lambda force=False: cfg)
        monkeypatch.setattr(
            "jen.services.explain_context.read_log",
            lambda mac, *, allowed, fetch=True: {
                "classes": None,
                "query": None,
                "cid": None,
                "state": "not-allowed",
                "message": "",
            },
        )
        page = logged_in_client.get(f"/tools/explain?mac={GHOST_MAC}&subnet=1").get_data(as_text=True)
        for secret in ("ghost-host", "01:aa:bb:cc:dd:ee:71", "the current lease"):
            assert secret not in page, f"{secret!r}: an expired lease fed Explain's inputs"
        live = logged_in_client.get(f"/tools/explain?mac={LIVE_MAC}&subnet=1").get_data(as_text=True)
        assert "live-host" in live and "the current lease" in live, "an active lease still does"

    def test_the_historical_view_still_has_the_row(self, leases, db):
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM lease4 WHERE address=INET_ATON(%s) AND state=0", (GHOST_IP,))
            assert cur.fetchone()["n"] == 1, "the row is still in the table; only 'current' stopped meaning it"


class TestTheV6Twin:
    @pytest.fixture
    def v6(self, db):
        _wipe(db)
        with db.cursor() as cur:
            for address, subnet, expire, state in (
                ("2001:db8:71::1", 771, "DATE_SUB(NOW(), INTERVAL 1 HOUR)", 0),  # state 0 past its expiry
                ("2001:db8:71::2", 771, "DATE_ADD(NOW(), INTERVAL 1 HOUR)", 0),  # active
                ("2001:db8:71::3", 771, "DATE_ADD(NOW(), INTERVAL 1 HOUR)", 1),  # declined: not state 0
            ):
                cur.execute(
                    "INSERT INTO lease6 (address, duid, valid_lifetime, expire, subnet_id, pref_lifetime, lease_type, iaid, "  # nosec B608 - test seed
                    f"prefix_len, hostname, hwaddr, state) VALUES (INET6_ATON(%s), %s, 3600, {expire}, %s, 1800, 0, 1, 128, "
                    "'h6', NULL, %s)",
                    (address, bytes.fromhex("00030001001a2b3c4d5e"), subnet, state),
                )
        db.commit()
        yield
        _wipe(db)

    def test_the_default_read_is_the_active_rows_only(self, v6):
        got = {r["address"]: r for r in kea6.list_lease6(subnet_id=771)}
        assert set(got) == {"2001:db8:71::2"} and got["2001:db8:71::2"]["expired"] is False

    def test_the_historical_read_keeps_every_row_and_flags_the_expired_ones(self, v6):
        got = {r["address"]: r["expired"] for r in kea6.list_lease6(subnet_id=771, show_expired=True)}
        assert got == {"2001:db8:71::1": True, "2001:db8:71::2": False, "2001:db8:71::3": True}

    def test_the_devices_and_the_counts_built_on_it_follow(self, v6):
        assert [a["address"] for d in kea6.list_lease6_devices(subnet_id=771) for a in d["addresses"]] == [
            "2001:db8:71::2"
        ]
