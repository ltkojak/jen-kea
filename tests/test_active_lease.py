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


# ── v5.68.0-beta.18 (Q153): the guard is the WHOLE tree, not a file list ───────────────────────────────────────────────────────────
# Q145 defined ACTIVE_LEASE4 and pinned it over three files; twenty-five other queries in the repository kept the bare `state=0`. A fix to a
# definition is a fix to every use, so this scans every Python file under jen/ and plugins/ (nothing is exempt but the definition itself) for a
# SQL string that spells the predicate by hand.

SPELLING = re.compile(r"\bstate\s*(?:=|!=|<>)\s*0\b|\bstate\s+IN\s*\(\s*0\b", re.I)

#: The explicitly HISTORICAL queries: (file, the exact text matched) -> why a bare state is right there. Everything else must use
#: ACTIVE_LEASE4/6 (or active_lease4('l') for an aliased table).
HISTORICAL = {
    ("jen/routes/leases.py", "state != 0"): (
        "'Delete expired/stale leases' housekeeping: removes rows Kea has already moved out of state 0 (declined, expired-reclaimed, "
        "released). A state-0 row is Kea's own to reclaim and is deliberately not deleted from under it."
    ),
}


def _sql_strings(tree):
    """Every string constant in `tree` that is not a docstring (the SQL, including the literal parts of f-strings)."""
    import ast

    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            docstrings.add(id(node.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            yield node.lineno, node.value


def spelled_by_hand(source: str, relpath: str = "x.py") -> list[tuple[str, int, str]]:
    """[(path, line, text)] for every SQL string in `source` that spells `state = 0` / `state != 0` itself and is not on HISTORICAL."""
    import ast

    out = []
    for lineno, text in _sql_strings(ast.parse(source)):
        for m in SPELLING.finditer(text):
            if (relpath, m.group(0)) in HISTORICAL:
                continue
            out.append((relpath, lineno, m.group(0)))
    return out


class TestTheWholeTreeHasOneSpelling:
    """No query anywhere in jen/ or plugins/ spells the current-lease predicate by hand: it is `leases_sql.ACTIVE_LEASE4/6` or it is on
    the HISTORICAL allowlist with a reason."""

    TREES = ("jen", "plugins")

    def _files(self):
        for tree in self.TREES:
            for path in sorted((ROOT / tree).rglob("*.py")):
                rel = path.relative_to(ROOT).as_posix()
                if rel == "jen/services/leases_sql.py" or "__pycache__" in rel:
                    continue
                yield rel, path

    def test_nothing_spells_it_by_hand(self):
        found = []
        for rel, path in self._files():
            found += spelled_by_hand(path.read_text(encoding="utf-8"), rel)
        assert not found, (
            "a query spells state = 0 itself instead of using jen.services.leases_sql (ACTIVE_LEASE4/6 or active_lease4('l')); "
            "if it is a deliberately HISTORICAL query add it to HISTORICAL with the reason: "
            + "; ".join(f"{p}:{n} {t!r}" for p, n, t in found)
        )

    def test_the_allowlist_is_exactly_what_the_tree_still_contains(self):
        """An entry that no longer matches anything is dead weight that would hide a future regression."""
        import ast

        present = set()
        for rel, path in self._files():
            for _n, text in _sql_strings(ast.parse(path.read_text(encoding="utf-8"))):
                for m in SPELLING.finditer(text):
                    present.add((rel, m.group(0)))
        assert set(HISTORICAL) <= present, f"stale allowlist entries: {set(HISTORICAL) - present}"

    def test_every_allowlist_entry_says_why(self):
        assert all(len(reason) > 40 for reason in HISTORICAL.values())

    def test_the_guard_has_power(self):
        bad = 'def f(cur):\n    cur.execute("SELECT 1 FROM lease4 WHERE state=0 AND subnet_id=%s", (1,))\n'
        assert spelled_by_hand(bad, "jen/x.py") != []
        good = "def f(cur):\n    cur.execute(f\"SELECT 1 FROM lease4 l WHERE {active_lease4('l')}\")\n"
        assert spelled_by_hand(good, "jen/x.py") == []
        joined = 'def f(cur):\n    cur.execute(f"SELECT 1 FROM lease4 WHERE state = 0 AND x={y}")\n'
        assert spelled_by_hand(joined, "jen/x.py") != [], "the literal part of an f-string is scanned too"
        doc = 'def f():\n    """say state=0 in prose"""\n    return 1\n'
        assert spelled_by_hand(doc, "jen/x.py") == [], "a docstring is prose, not a query"
        for variant in ("state != 0", "state <> 0", "l.state=0", "state IN (0)"):
            assert spelled_by_hand(f'q = "SELECT 1 FROM lease4 l WHERE {variant}"\n', "jen/x.py"), variant

    def test_the_constants_are_the_one_definition(self):
        from jen.services import leases_sql

        assert cs.ACTIVE_LEASE4 is leases_sql.ACTIVE_LEASE4 and kea6.ACTIVE_LEASE6 is leases_sql.ACTIVE_LEASE6
        assert leases_sql.active_lease4("l") == "l.state = 0 AND l.expire > NOW()"
        assert leases_sql.not_active_lease4() == "NOT (state = 0 AND expire > NOW())"

    def test_plugins_get_the_constant_through_plugin_api_only(self):
        from jen import plugin_api

        assert plugin_api.ACTIVE_LEASE4 == cs.ACTIVE_LEASE4 and plugin_api.ACTIVE_LEASE6 == kea6.ACTIVE_LEASE6
        for plugin in sorted((ROOT / "plugins").glob("*/plugin.py")):
            assert "leases_sql" not in plugin.read_text(encoding="utf-8"), (
                f"{plugin}: a plugin imports only jen.plugin_api"
            )


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


@pytest.fixture
def metrics_opened(monkeypatch):
    """/metrics needs a token or an explicit opt-in; this test is about the number it prints (as tests/test_dashboard.py does)."""
    import configparser

    cfg = configparser.ConfigParser()
    cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
    if "server" not in cfg:
        cfg["server"] = {}
    cfg["server"]["metrics_open"] = "true"
    monkeypatch.setattr(extensions, "cfg", cfg)


def _load_plugin(plugin_id):
    """A bundled plugin's real plugin.py, loaded by path (it imports Flask and, lazily, jen.plugin_api - both real here)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        f"q153_{plugin_id.replace('-', '_')}", ROOT / "plugins" / plugin_id / "plugin.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestEveryCurrentLeaseSurface:
    """v5.68.0-beta.18 (Q153) - the thirteen surfaces that used to ask `state = 0` alone, each against ONE expired state-0 row (GHOST) beside
    ONE live row (LIVE) in the same subnet: the expired row is on none of them, the live one is on all of them. The historical views
    (`?expired=1`) still show it."""

    def test_01_the_leases_page_default_view(self, logged_in_client, leases):
        page = logged_in_client.get("/leases?subnet=1").get_data(as_text=True)
        assert LIVE_IP in page and GHOST_IP not in page

    def test_01b_the_historical_view_still_lists_it(self, logged_in_client, leases):
        page = logged_in_client.get("/leases?subnet=1&expired=1").get_data(as_text=True)
        assert LIVE_IP in page and GHOST_IP in page

    def test_02_release_finds_no_active_lease_at_an_expired_address(self, logged_in_client, leases, mock_kea):
        r = logged_in_client.post("/leases/release", data={"ip": GHOST_IP}, follow_redirects=True)
        assert f"No active lease found for {GHOST_IP}" in r.get_data(as_text=True)

    def test_03_the_dashboards_live_counts(self, logged_in_client, leases, mock_kea):
        stats = logged_in_client.get("/api/stats").get_json()["subnets"]["1"]
        assert stats["active"] == 1 and stats["dynamic"] == 1

    def test_04_the_prometheus_gauge(self, client, leases, mock_kea, metrics_opened):
        text = client.get("/metrics").get_data(as_text=True)
        line = next(
            x for x in text.splitlines() if x.startswith("jen_subnet_active_leases{") and 'cidr="10.71.0.0/24"' in x
        )
        assert line.endswith(" 1")

    def test_05_the_snapshot_that_feeds_history_and_the_forecast(self, leases, mock_kea, db):
        from jen.services import alerts

        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history WHERE subnet_id=1")
        db.commit()
        alerts.take_lease_snapshot()
        with db.cursor() as cur:
            cur.execute(
                "SELECT active_leases, dynamic_leases FROM lease_history WHERE subnet_id=1 ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
        assert row["active_leases"] == 1 and row["dynamic_leases"] == 1
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease_history WHERE subnet_id=1")
        db.commit()

    def test_06_the_rest_api_subnet_summary(self, client, leases, mock_kea, db):
        import hashlib

        raw = "q153-api-key-abcdef0123456789"
        with db.cursor() as cur:
            cur.execute("SELECT id FROM users ORDER BY id LIMIT 1")
            owner = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, subnet_access, active) VALUES (%s, %s, %s, %s, NULL, 1)",
                ("q153", hashlib.sha256(raw.encode()).hexdigest(), raw[:8], owner),
            )
        db.commit()
        data = client.get("/api/v1/subnets", headers={"Authorization": f"Bearer {raw}"}).get_json()
        items = data["subnets"] if isinstance(data, dict) else data
        assert next(s for s in items if s["id"] == 1)["active_leases"] == 1

    def test_07_a_logins_client_hostname(self, leases):
        from jen.services import fingerprint

        assert fingerprint.client_hostname(GHOST_IP) != "ghost-host"
        assert fingerprint.client_hostname(LIVE_IP) == "live-host"

    def test_08_dns_syncs_lease_source(self, leases):
        rows = _load_plugin("dns-sync")._leases_for_subnets([1])
        assert [r["hostname"] for r in rows] == ["live-host"]

    def test_09_network_discoverys_in_kea_sets(self, leases):
        lease_ips, lease_macs, _res_ips, _res_macs = _load_plugin("network-discovery")._load_kea(1)
        assert LIVE_IP in lease_ips and GHOST_IP not in lease_ips

    def test_10_presences_current_address_of_a_device(self, leases):
        presence = _load_plugin("presence")
        assert presence._current_ip_hostname(GHOST_MAC) == (None, None)
        assert presence._current_ip_hostname(LIVE_MAC) == (LIVE_IP, "live-host")

    def test_11_presences_other_active_lease_check(self, leases):
        presence = _load_plugin("presence")
        assert presence._has_active_lease(GHOST_MAC) is False
        assert presence._has_active_lease(LIVE_MAC) is True

    def test_12_ipams_address_space(self, leases):
        active, _reservations = _load_plugin("ipam")._load_kea_sets(1, "10.71.0.0/24")
        assert set(active) == {LIVE_IP}

    def test_13_the_v6_snapshots_aggregate(self, db):
        _wipe(db)
        with db.cursor() as cur:
            for address, expire, state in (
                ("2001:db8:71::1", "DATE_SUB(NOW(), INTERVAL 1 HOUR)", 0),
                ("2001:db8:71::2", "DATE_ADD(NOW(), INTERVAL 1 HOUR)", 0),
                ("2001:db8:71::3", "DATE_ADD(NOW(), INTERVAL 1 HOUR)", 1),
            ):
                cur.execute(
                    "INSERT INTO lease6 (address, duid, valid_lifetime, expire, subnet_id, pref_lifetime, lease_type, iaid, "  # nosec B608 - test seed
                    f"prefix_len, hostname, hwaddr, state) VALUES (INET6_ATON(%s), %s, 3600, {expire}, 771, 1800, 0, 1, 128, "
                    "'h6', NULL, %s)",
                    (address, bytes.fromhex("00030001001a2b3c4d5e"), state),
                )
        db.commit()
        try:
            assert kea6.count_lease6_by_subnet([771]) == {771: {"IA_NA": 1, "IA_TA": 0, "IA_PD": 0}}
        finally:
            _wipe(db)
