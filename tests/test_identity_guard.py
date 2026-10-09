"""
tests/test_identity_guard.py
────────────────────────────
v5.68.0-beta.28 (Q164) — the identity invariant ("a Kea server with investigation state outstanding keeps the settings that say WHICH Kea Jen reaches")
enforced where every write to it already passes: `AppConfig._write_parser` for jen.config, and (second half of this file) `kea_host.apply_config` for the Kea
config FILE. beta.27 asked the question on three routes; an enumeration of the tree found six paths that write the same keys, so these tests drive the REAL
`AppConfig` on a temp file and the fake daemon of tests/_investigation_world.py, never a route's own check.

`pytest --noconftest tests/test_identity_guard.py` runs everything except the classes marked CI-only (they need the database and the Flask app).
"""

import ast
import configparser
import pathlib
import threading
import time

import pytest

from jen import config as jconfig
from jen import extensions
from jen.config import AppConfig, ConfigChangeRefused, app_config
from jen.services import investigation_logging as inv

pytest_plugins = ("tests._investigation_world",)

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def cfgfile(tmp_path, monkeypatch, world):
    """A real jen.config on disk that describes the two servers of the `world` fixture; `extensions.CONFIG_FILE` points at it, and a reload re-derives the
    world's server list from it (the globals the real reload assigns are not touched)."""
    ini = configparser.ConfigParser(interpolation=None)
    ini["kea"] = {"name": "kea-a", "api_url": "http://10.0.0.1:8000", "api_user": "u", "api_pass": "p"}
    ini["kea_ssh"] = {"host": "10.0.0.1", "user": "jen", "kea_conf": "/etc/kea/kea-dhcp4.conf"}
    ini["kea_server_2"] = {
        "name": "kea-b",
        "api_url": "http://10.0.0.2:8000",
        "ssh_host": "10.0.0.2",
        "ssh_user": "jen",
        "kea_conf": "/etc/kea/kea-dhcp4.conf",
    }
    ini["jen_db"] = {"host": "h", "user": "u", "password": "p"}
    path = tmp_path / "jen.config"
    with open(path, "w", encoding="utf-8") as f:
        ini.write(f)
    monkeypatch.setattr(extensions, "CONFIG_FILE", str(path))

    def reload():  # what the real reload does for the world: the server list follows the file
        world.servers[:] = AppConfig.derive_kea_servers(app_config._read_parser(), quiet=True)

    monkeypatch.setattr(app_config, "reload", reload)
    reload()
    world.path = path
    return world


def _disk(path):
    p = configparser.ConfigParser(interpolation=None)
    p.read(str(path), encoding="utf-8")
    return p


def _audits(world, action):
    return [a for a in world.store.get("_audit", []) if a[0] == action]


def _server(world, sid):
    return next(s for s in world.servers if s["id"] == sid)


class TestTheConfigWriterRefusesAnIdentityChange:
    """The matrix: what is refused, what is not. Every refusal raises before the first byte (the file is byte-identical), names the server, and is audited."""

    def _refused(self, world, change, *needles):
        before = world.path.read_bytes()
        with pytest.raises(ConfigChangeRefused) as raised:
            if callable(change):
                app_config.mutate(change)
            else:
                app_config.write_values(change)
        assert world.path.read_bytes() == before, "nothing was written"
        for needle in needles:
            assert needle in str(raised.value), (needle, str(raised.value))
        return str(raised.value)

    def test_a_server_with_an_entry_cannot_have_its_ssh_host_changed(self, cfgfile):
        w = cfgfile
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        self._refused(
            w, [("kea_ssh", "host", "10.9.9.9")], "Investigation logging is on for kea-a", "Changing its ssh_host"
        )
        (row,) = _audits(w, "INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED")
        assert row[1] == "kea-a" and "change of ssh_host refused while investigation logging is on" in row[2]

    @pytest.mark.parametrize(
        ("section", "key", "value", "field"),
        [
            ("kea", "api_url", "http://elsewhere:8000", "api_url"),
            ("kea_ssh", "user", "someone-else", "ssh_user"),
            ("kea_ssh", "kea_conf", "/opt/kea/dhcp4.conf", "kea_conf"),
        ],
    )
    def test_each_of_the_four_fields_is_identity(self, cfgfile, section, key, value, field):
        assert inv.turn_on(_server(cfgfile, 1), 5)["ok"]
        self._refused(cfgfile, [(section, key, value)], f"Changing its {field}")

    def test_an_extra_server_with_an_entry_is_protected_the_same_way(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 2), 5)["ok"]
        self._refused(cfgfile, [("kea_server_2", "ssh_host", "10.7.7.7")], "Investigation logging is on for kea-b")

    def test_removing_a_server_that_has_an_entry_is_refused_with_the_removal_sentence(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 2), 5)["ok"]
        text = self._refused(
            cfgfile, lambda p: p.remove_section("kea_server_2"), "Removing the server now would leave its Kea at DEBUG"
        )
        assert "kea-b" in text
        (row,) = _audits(cfgfile, "INVESTIGATION_LOGGING_REMOVAL_REFUSED")
        assert row[1] == "kea-b"

    def test_the_connection_mode_is_refused_even_with_the_same_url(self, cfgfile):
        """Item 2: the mode is global - `ca -> direct` with the url unchanged changes how EVERY Kea is reached."""
        assert inv.turn_on(_server(cfgfile, 1), 5)["ok"]
        text = self._refused(
            cfgfile, [("kea", "connection_mode", "direct")], "connection mode is how Jen reaches EVERY Kea"
        )
        assert "kea-a" in text
        (row,) = _audits(cfgfile, "INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED")
        assert "connection mode (ca -> direct)" in row[2]

    def test_the_mode_changed_from_the_primary_page_is_refused_when_an_EXTRA_server_has_the_entry(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 2), 5)["ok"]
        text = self._refused(
            cfgfile, [("kea", "connection_mode", "direct"), ("kea", "api_url", "http://10.0.0.1:8000")], "kea-b"
        )
        assert "EVERY Kea" in text

    def test_a_mode_that_apply_reads_as_the_default_is_no_change(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 1), 5)["ok"]
        app_config.write_values(
            [("kea", "connection_mode", "CA "), ("kea", "api_user", "u2")]
        )  # `apply()` reads anything but "direct" as "ca"
        assert _audits(cfgfile, "INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED") == []

    def test_an_unreadable_record_refuses_every_identity_change(self, cfgfile):
        cfgfile.store[inv.RECORD_KEY] = "{broken"
        self._refused(
            cfgfile,
            [("kea_ssh", "host", "10.9.9.9")],
            "cannot be read, so it cannot tell whether this server is at investigation DEBUG",
        )
        (row,) = _audits(cfgfile, "INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED")
        assert "while Jen's record of investigation logging is unreadable" in row[2]
        self._refused(cfgfile, [("kea", "connection_mode", "direct")])
        assert cfgfile.store[inv.RECORD_KEY] == "{broken", "the damaged value is not touched by a refusal"

    @pytest.mark.parametrize("raw", ["", '{"servers": {}}'])
    def test_a_valid_empty_record_allows_the_change(self, cfgfile, raw):
        cfgfile.store[inv.RECORD_KEY] = raw
        app_config.write_values([("kea_ssh", "host", "10.9.9.9"), ("kea", "connection_mode", "direct")])
        assert _disk(cfgfile.path).get("kea_ssh", "host") == "10.9.9.9"
        assert _audits(cfgfile, "INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED") == []

    def test_after_turn_off_the_change_is_allowed(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 1), 5)["ok"]
        self._refused(cfgfile, [("kea_ssh", "host", "10.9.9.9")])
        assert inv.turn_off(_server(cfgfile, 1))["ok"]
        app_config.write_values([("kea_ssh", "host", "10.9.9.9")])
        assert _disk(cfgfile.path).get("kea_ssh", "host") == "10.9.9.9"

    def test_a_dhcp6_only_write_and_every_non_identity_key_is_allowed_while_an_entry_exists(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 1), 5)["ok"]
        app_config.write_values(
            [
                ("kea6", "api_url", "http://10.0.0.1:8001"),  # the DHCPv6 daemon's own url is not the v4 identity
                ("d2", "api_url", "http://10.0.0.1:8002"),
                ("kea", "name", "Renamed"),
                ("kea", "api_user", "other"),
                ("kea", "api_pass", "newpass"),
                ("kea_ssh", "key_path", "/k"),
                ("kea_server_2", "name", "Also renamed"),
                ("server", "http_port", "5051"),
            ]
        )
        assert _audits(cfgfile, "INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED") == []

    def test_a_server_with_no_entry_is_free_while_another_has_one_and_a_new_server_may_be_added(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 1), 5)["ok"]
        app_config.write_values([("kea_server_2", "ssh_host", "10.7.7.7")])
        app_config.write_values(
            [("kea_server_3", "api_url", "http://10.0.0.3:8000"), ("kea_server_3", "ssh_host", "10.0.0.3")]
        )
        assert _disk(cfgfile.path).get("kea_server_3", "ssh_host") == "10.0.0.3"

    def test_a_removed_entry_is_not_a_server_to_protect(self, cfgfile):
        """The sweep marked it `removed`: its server is already gone, and a server added again under the id is a new one."""
        assert inv.turn_on(_server(cfgfile, 2), 5)["ok"]
        record = inv._record()
        record["servers"]["2"]["removed"] = True
        assert inv._save(record)
        app_config.mutate(lambda p: p.remove_section("kea_server_2"))
        assert not _disk(cfgfile.path).has_section("kea_server_2")

    def test_a_config_with_no_kea_credentials_yet_is_read_leniently(self, cfgfile):
        """A fresh install's file has no `[kea]` credentials: the view reads blanks, the write is not an error of its own."""
        cfgfile.path.write_text("[jen_db]\nhost = h\nuser = u\npassword = p\n", encoding="utf-8")
        app_config.write_values(
            [("kea", "api_url", "http://10.0.0.1:8000"), ("kea", "api_user", "u"), ("kea", "api_pass", "p")],
            reload=False,
        )
        assert _disk(cfgfile.path).get("kea", "api_url") == "http://10.0.0.1:8000"

    def test_a_guard_that_raises_fails_closed(self, cfgfile, monkeypatch):
        def broken(before, after):
            raise RuntimeError("settings exploded")

        monkeypatch.setattr(jconfig, "_identity_guards", [broken])
        self._refused(
            cfgfile,
            [("kea_ssh", "host", "10.9.9.9")],
            "could not check whether a Kea server has investigation logging outstanding",
        )

    def test_a_write_that_changes_no_identity_never_asks_a_guard(self, cfgfile, monkeypatch):
        asked = []
        monkeypatch.setattr(jconfig, "_identity_guards", [lambda before, after: asked.append(1) or ""])
        app_config.write_values([("server", "http_port", "5052"), ("kea", "api_pass", "x")])
        assert asked == []

    def test_the_comparison_is_by_what_the_config_means_not_how_it_is_spelled(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 1), 5)["ok"]
        app_config.write_values(
            [
                ("kea_ssh", "host", "10.0.0.1  "),
                ("kea_ssh", "kea_conf", ""),
                ("kea", "api_url", " http://10.0.0.1:8000"),
            ]
        )
        assert _audits(cfgfile, "INVESTIGATION_LOGGING_IDENTITY_CHANGE_REFUSED") == []


class TestPreflight:
    """`preflight_identity_change` is the same question without the write: a route whose first act is on the Kea host asks it BEFORE that act."""

    def test_it_refuses_what_the_write_would_refuse_and_writes_nothing(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 1), 5)["ok"]
        before = cfgfile.path.read_bytes()
        with pytest.raises(ConfigChangeRefused, match="connection mode"):
            app_config.preflight_identity_change(
                [("kea", "connection_mode", "direct"), ("kea", "api_url", "http://10.0.0.1:8004")]
            )
        assert cfgfile.path.read_bytes() == before

    def test_a_callable_edits_a_copy_the_way_a_mutate_callback_does(self, cfgfile):
        assert inv.turn_on(_server(cfgfile, 2), 5)["ok"]
        before = cfgfile.path.read_bytes()
        with pytest.raises(ConfigChangeRefused, match="Removing the server"):
            app_config.preflight_identity_change(lambda p: p.remove_section("kea_server_2"))
        assert cfgfile.path.read_bytes() == before

    def test_it_returns_none_when_the_change_is_allowed(self, cfgfile):
        assert app_config.preflight_identity_change([("kea_ssh", "host", "10.9.9.9")]) is None
        assert _disk(cfgfile.path).get("kea_ssh", "host") == "10.0.0.1", "a preflight never writes"


class TestTheSetupWizardIsGuardedWithNoChangeToIt:
    """setup_wizard.py:393 and :743 write the same keys, reachable at any time."""

    def test_connect_and_the_ssh_target_are_refused_while_an_entry_exists(self, cfgfile, monkeypatch):
        from jen.models import db as dbmod
        from jen.services import setup_wizard

        monkeypatch.setattr(dbmod, "reset_kea_pools", lambda: None)
        assert inv.turn_on(_server(cfgfile, 1), 5)["ok"]
        before = cfgfile.path.read_bytes()
        with pytest.raises(ConfigChangeRefused):
            setup_wizard.save_ssh_target("10.9.9.9", "jen")
        with pytest.raises(ConfigChangeRefused):
            setup_wizard.save_connection(
                api_url="http://elsewhere:8000",
                api_user="u",
                api_pass="",
                mode="ca",
                kea_db_host="h",
                kea_db_user="u",
                kea_db_pass="",
                kea_db_name="kea",
            )
        assert cfgfile.path.read_bytes() == before
        assert inv.turn_off(_server(cfgfile, 1))["ok"]
        ok, _err = setup_wizard.save_ssh_target("10.9.9.9", "jen")
        assert ok


class TestTheRaceBetweenASaveAndTurnOn:
    """Item 3: `endpoint_change_refusal` read the record and the route then wrote the config; `turn_on` held only investigation's lock. A save that passed the
    check could commit AFTER `turn_on` recorded an entry against the old identity. The two orderings, with barriers."""

    def test_turn_on_first_the_save_waits_and_is_then_refused(self, cfgfile, monkeypatch):
        w = cfgfile
        inside, release = threading.Event(), threading.Event()
        real_apply = inv._changeset.apply_change

        def slow_apply(*a, **kw):  # turn_on is mid-flight: inside its SSH round trip, entry not yet recorded
            inside.set()
            assert release.wait(10)
            return real_apply(*a, **kw)

        monkeypatch.setattr(inv._changeset, "apply_change", slow_apply)
        out, saved = {}, {}
        t_on = threading.Thread(target=lambda: out.update(inv.turn_on(_server(w, 1), 5)))
        t_on.start()
        assert inside.wait(10)

        def save():
            try:
                app_config.write_values([("kea_ssh", "host", "10.9.9.9")])
                saved["result"] = "written"
            except ConfigChangeRefused as e:
                saved["result"] = f"refused: {e}"

        t_save = threading.Thread(target=save)
        t_save.start()
        t_save.join(0.4)
        assert t_save.is_alive(), "the save is waiting for the running turn-on (identity_lock)"
        assert _disk(w.path).get("kea_ssh", "host") == "10.0.0.1"
        release.set()
        t_on.join(10)
        t_save.join(10)
        assert out["ok"] is True
        assert saved["result"].startswith("refused: Investigation logging is on for kea-a"), saved
        assert _disk(w.path).get("kea_ssh", "host") == "10.0.0.1", (
            "the entry and the identity it was recorded against still agree"
        )

    def test_the_save_first_turn_on_then_refuses_because_what_it_was_given_is_stale(self, cfgfile, monkeypatch):
        w = cfgfile
        stale = dict(_server(w, 1))  # what the Servers page read BEFORE the save
        inside, go = threading.Event(), threading.Event()

        def holding_guard(before, after):  # the save holds identity_lock while it decides
            inside.set()
            assert go.wait(10)
            return ""

        monkeypatch.setattr(jconfig, "_identity_guards", [holding_guard, *jconfig._identity_guards])
        t_save = threading.Thread(target=lambda: app_config.write_values([("kea_ssh", "host", "10.9.9.9")]))
        t_save.start()
        assert inside.wait(10)
        out = {}
        t_on = threading.Thread(target=lambda: out.update(inv.turn_on(stale, 5)))
        t_on.start()
        t_on.join(0.4)
        assert t_on.is_alive(), "turn-on waits for the save that holds identity_lock"
        go.set()
        t_save.join(10)
        t_on.join(10)
        assert _disk(w.path).get("kea_ssh", "host") == "10.9.9.9"
        assert out["ok"] is False and "changed while this was starting" in out["lines"][0]
        assert w.daemons[1].writes == 0 and not any(c.startswith("apply") for c in w.daemons[1].calls), (
            "nothing was written to the Kea it was not meant for"
        )
        assert inv._record()["servers"] == {}

    def test_the_two_do_not_deadlock_when_both_arrive_together(self, cfgfile):
        w = cfgfile
        results = []

        def save():
            try:
                app_config.write_values([("kea_ssh", "host", "10.9.9.9")])
                results.append("saved")
            except ConfigChangeRefused:
                results.append("refused")

        threads = [
            threading.Thread(target=lambda: results.append(inv.turn_on(_server(w, 1), 5)["ok"])),
            threading.Thread(target=save),
        ]
        started = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        assert not any(t.is_alive() for t in threads) and time.monotonic() - started < 15
        # whichever order it was, the stored entry and the file's identity agree
        entry = inv._record()["servers"].get("1")
        assert entry is None or entry["ssh_host"] == _disk(w.path).get("kea_ssh", "host"), (entry, results)


class TestAnUnavailableSettingsReadIsNeverAnEmptyRecord:
    """Item 4: `_record()` read through `get_global_setting(RECORD_KEY, "")`, which answers its DEFAULT on a cold start with the Jen database down - "unavailable"
    read as "empty"."""

    def test_unavailable_is_damaged_with_a_flag_and_every_mutation_refuses(self, cfgfile):
        w = cfgfile
        w.db["unavailable"] = True
        record = inv._record()
        assert record["damaged"] is True and record["unavailable"] is True and record["servers"] == {}
        assert "could not be read" in inv.turn_on(_server(w, 1), 5)["lines"][0]
        assert inv.turn_off(_server(w, 1))["ok"] is False
        assert inv.removal_refusal([2]) != ""
        assert inv.acknowledge_damaged("alice", all_subnets=True) is False
        assert inv.forget(2) is False
        assert inv._save({"servers": {"1": {}}, "damaged": True, "raw": "", "unavailable": True}) is False
        before = w.path.read_bytes()
        with pytest.raises(ConfigChangeRefused, match="settings could not be read"):
            app_config.write_values([("kea_ssh", "host", "10.9.9.9")])
        with pytest.raises(ConfigChangeRefused):
            app_config.write_values([("kea", "connection_mode", "direct")])
        assert w.path.read_bytes() == before
        assert w.daemons[1].writes == 0 and inv.RECORD_KEY not in w.store

    def test_recovery_writes_nothing_and_says_why(self, cfgfile):
        w = cfgfile
        w.db["unavailable"] = True
        out = inv.sweep(now=inv._now(), full=True)
        assert out["errors"] == [inv.SETTINGS_UNAVAILABLE] and out["adopted"] == []
        assert inv.recovery_status()["problems"] == [inv.SETTINGS_UNAVAILABLE]
        assert not any(k in w.store for k in (inv.RECORD_KEY, inv.DAMAGED_KEY))

    def test_health_says_unavailable_and_what_to_fix(self, cfgfile):
        from jen.services import health

        w = cfgfile
        w.db["unavailable"] = True
        check = health._debug_logging_left_on({})
        assert check.status == "fail" and "settings could not be read (its database is unavailable)" in check.detail
        assert "investigation logging and every change to a Kea's connection are refused" in check.detail

    def test_the_database_returning_is_normal_again(self, cfgfile):
        w = cfgfile
        w.db["unavailable"] = True
        assert inv._record()["unavailable"] is True
        w.db["unavailable"] = False
        assert inv._record() == {"servers": {}, "damaged": False, "raw": "", "bad": []}
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        assert inv.turn_off(_server(w, 1))["ok"]
        app_config.write_values([("kea_ssh", "host", "10.9.9.9")])

    def test_the_cold_start_reads_the_table_before_it_asks_whether_it_was_ever_read(self, monkeypatch):
        """`settings_ever_loaded()` is False until the FIRST read: asked first, a cold start with a perfectly good database read as unavailable."""
        from jen.models import db as dbmod
        from jen.models import user as usermod

        rows = [{"setting_key": inv.RECORD_KEY, "setting_value": ""}]

        class Conn:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def cursor(self):
                return self

            def execute(self, sql, params=None):
                pass

            def fetchall(self):
                return rows

        monkeypatch.setattr(usermod, "_settings_cache", {})
        monkeypatch.setattr(usermod, "_settings_cache_ts", 0)
        monkeypatch.setattr(usermod, "_settings_next_try_mono", 0)
        monkeypatch.setattr(usermod, "_settings_ever_loaded", False)
        monkeypatch.setattr(dbmod, "jen_db", lambda: Conn())
        assert inv._record()["damaged"] is False
        assert usermod.settings_ever_loaded() is True

    def test_the_cold_start_with_the_database_down_is_unavailable(self, monkeypatch):
        from jen.models import db as dbmod
        from jen.models import user as usermod

        def down():
            raise OSError("connection refused")

        monkeypatch.setattr(usermod, "_settings_cache", {})
        monkeypatch.setattr(usermod, "_settings_cache_ts", 0)
        monkeypatch.setattr(usermod, "_settings_next_try_mono", 0)
        monkeypatch.setattr(usermod, "_settings_ever_loaded", False)
        monkeypatch.setattr(dbmod, "jen_db", down)
        record = inv._record()
        assert record["damaged"] is True and record.get("unavailable") is True


# ── the source tests (F) ────────────────────────────────────────────────────────────────────────────────────────────────


def _parse(rel):
    return ast.parse((ROOT / rel).read_text(encoding="utf-8"))


def _functions(tree):
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


class TestTheIdentityInvariantHasOneChokePointInTheSource:
    #: Modules that may write jen.config WITHOUT going through `AppConfig._write_parser`, each with why.
    CONFIG_WRITERS_ALLOWED = {
        "jen/tools/restore.py": "a root CLI (`install.sh --restore`) that runs with Jen STOPPED and puts back a backed-up config wholesale; it has no running "
        "process to protect and no settings table to consult",
    }

    def test_01_the_only_writer_of_jen_config_is_the_parsers_write(self):
        offenders, seen_writer = [], []
        write_calls = {
            "write_private_file",
            "_write_file",
            "open",
            "replace",
            "copy",
            "copy2",
            "copyfile",
            "move",
            "write_text",
            "write_bytes",
        }
        for path in sorted((ROOT / "jen").rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in _functions(tree):
                for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
                    name = (
                        call.func.id
                        if isinstance(call.func, ast.Name)
                        else call.func.attr
                        if isinstance(call.func, ast.Attribute)
                        else ""
                    )
                    if name not in write_calls:
                        continue
                    text = ast.unparse(call)
                    if name == "open" and not any(
                        m in text for m in ("'w'", '"w"', "'wb'", '"wb"', "'a'", '"a"', "'r+'", '"r+"', "mode=")
                    ):
                        continue
                    touches = (
                        "CONFIG_FILE" in text
                        or ("jen.config" in text and rel != "jen/config.py")
                        or (rel == "jen/config.py" and "self.path" in text)
                    )
                    if not touches:
                        continue
                    if rel == "jen/config.py" and fn.name == "_write_parser":
                        seen_writer.append(rel)
                    elif rel not in self.CONFIG_WRITERS_ALLOWED:
                        offenders.append(f"{rel}::{fn.name}: {text[:90]}")
        assert seen_writer, "the walk found no write in AppConfig._write_parser: the test has lost its power"
        assert not offenders, f"these write jen.config without going through AppConfig._write_parser: {offenders}"
        stale = [rel for rel in self.CONFIG_WRITERS_ALLOWED if not (ROOT / rel).exists()]
        assert not stale, stale

    def test_01b_write_parser_asks_the_guards_before_it_writes(self):
        fn = next(f for f in _functions(_parse("jen/config.py")) if f.name == "_write_parser")
        lines = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                name = (
                    n.func.attr
                    if isinstance(n.func, ast.Attribute)
                    else n.func.id
                    if isinstance(n.func, ast.Name)
                    else ""
                )
                lines.setdefault(name, n.lineno)
        assert "_check_identity" in lines and "write_private_file" in lines
        assert lines["_check_identity"] < lines["write_private_file"]

    def test_01c_every_config_writer_takes_the_identity_lock_first(self):
        tree = _parse("jen/config.py")
        wrapper = next(f for f in _functions(tree) if f.name == "wrapper")
        with_ = next(n for n in ast.walk(wrapper) if isinstance(n, ast.With))
        order = [ast.unparse(i.context_expr) for i in with_.items]
        assert (
            order[0] == "identity_lock" and order[1] == "AppConfig._write_lock" and order[2].startswith("_file_lock")
        ), order
        serialized = {
            f.name
            for f in _functions(tree)
            for d in f.decorator_list
            if isinstance(d, ast.Name) and d.id == "_serialized"
        }
        assert {"write_value", "write_values", "write_subnets", "write_subnets6", "mutate"} <= serialized, serialized

    def test_02_the_guard_is_registered_at_import_and_create_app_imports_the_module(self):
        assert inv.identity_guard in jconfig._identity_guards
        create_app = next(f for f in _functions(_parse("jen/__init__.py")) if f.name == "create_app")
        imported = [
            n
            for n in ast.walk(create_app)
            if isinstance(n, ast.ImportFrom) and any(a.name == "investigation_logging" for a in n.names)
        ]
        assert imported, (
            "create_app() must import investigation_logging explicitly (a config write before any route module loaded is guarded too)"
        )
        assert "ConfigChangeRefused" in (ROOT / "jen" / "__init__.py").read_text(encoding="utf-8")

    def test_03_the_identity_keys_are_exactly_the_four_settings_that_say_which_kea(self):
        """Behavioural AND structural: changing any of the identity options changes the view; changing any other option of a server does not."""
        identity_options = [
            ("kea", "api_url"),
            ("kea_ssh", "host"),
            ("kea_ssh", "user"),
            ("kea_ssh", "kea_conf"),
            ("kea_server_2", "api_url"),
            ("kea_server_2", "ssh_host"),
            ("kea_server_2", "ssh_user"),
            ("kea_server_2", "kea_conf"),
            ("kea", "connection_mode"),
        ]
        other_options = [
            ("kea", "name"),
            ("kea", "api_user"),
            ("kea", "api_pass"),
            ("kea", "role"),
            ("kea", "api_ca"),
            ("kea", "api_tls_verify"),
            ("kea6", "api_url"),
            ("d2", "api_url"),
            ("kea_ssh", "key_path"),
            ("kea_server_2", "name"),
            ("kea_server_2", "api_user"),
            ("kea_server_2", "api_pass"),
            ("kea_server_2", "api6_url"),
            ("kea_server_2", "api_d2_url"),
            ("kea_server_2", "ssh_key"),
            ("kea_server_2", "role"),
        ]

        def parser(over=None):
            p = configparser.ConfigParser(interpolation=None)
            p.read_dict(
                {
                    "kea": {"api_url": "http://a:1", "api_user": "u", "api_pass": "p", "connection_mode": "ca"},
                    "kea_ssh": {"host": "h", "user": "j", "kea_conf": "/etc/kea/kea-dhcp4.conf"},
                    "kea_server_2": {
                        "api_url": "http://b:1",
                        "ssh_host": "h2",
                        "ssh_user": "j",
                        "kea_conf": "/etc/kea/kea-dhcp4.conf",
                    },
                }
            )
            for (section, key), value in (over or {}).items():
                if not p.has_section(section):
                    p.add_section(section)
                p.set(section, key, value)
            return p

        base = jconfig.identity_view(parser())
        for option in identity_options:
            value = "direct" if option[1] == "connection_mode" else "/changed/" + option[1]
            assert jconfig.identity_view(parser({option: value})) != base, (
                f"{option} is identity and the view does not carry it"
            )
        for option in other_options:
            assert jconfig.identity_view(parser({option: "changed"})) == base, (
                f"{option} is not identity and the view carries it"
            )
        assert (
            set(jconfig.IDENTITY_KEYS) == {"api_url", "ssh_host", "ssh_user", "kea_conf"} and jconfig.MODE_KEY in base
        )
        keys_derived = {
            k.value
            for f in _functions(_parse("jen/config.py"))
            if f.name == "derive_kea_servers"
            for d in ast.walk(f)
            if isinstance(d, ast.Dict)
            for k in d.keys
            if isinstance(k, ast.Constant)
        }
        assert set(jconfig.IDENTITY_KEYS) <= keys_derived, (
            "derive_kea_servers no longer builds one of the identity keys"
        )

    def test_06_no_route_asks_endpoint_change_refusal_any_more(self):
        offenders = []
        for path in sorted((ROOT / "jen" / "routes").rglob("*.py")):
            for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(n, ast.Attribute) and n.attr in ("endpoint_change_refusal", "identity_guard"):
                    offenders.append(f"{path.relative_to(ROOT).as_posix()}:{n.lineno}")
        assert not offenders, (
            f"the guard is automatic (the config writer asks it); a route-level check is a second path: {offenders}"
        )

    def test_07_the_guard_reads_nothing_but_settings_and_takes_no_lock(self):
        """The lock order depends on it: investigation `_lock` -> identity_lock -> the writer's locks, and the guard runs INSIDE the last two."""
        src = ast.unparse(
            next(f for f in _functions(_parse("jen/services/investigation_logging.py")) if f.name == "identity_guard")
        )
        for forbidden in ("_lock", "_host.", "_kea.", "_changeset.", "apply_change", "read_config_versioned"):
            assert forbidden not in src, f"identity_guard must not use {forbidden}"


@pytest.fixture
def ci_config(tmp_path):
    """CI-only: a real jen.config the Flask routes write to, with an SSH target for the primary."""
    original = extensions.CONFIG_FILE
    cfg = configparser.ConfigParser()
    cfg["kea"] = {"api_url": "http://1.2.3.4:8000", "api_user": "u4", "api_pass": "p4"}
    cfg["kea_ssh"] = {"host": "10.0.0.5", "user": "jen"}
    cfg["kea_db"] = {"host": "dbhost", "user": "du", "password": "dp", "database": "kea"}
    cfg["jen_db"] = {"host": "dbhost", "user": "ju", "password": "jp", "database": "jen"}
    cfg["subnets"] = {"1": "LAN, 192.168.1.0/24"}
    path = tmp_path / "jen.config"
    with open(path, "w") as f:
        cfg.write(f)
    extensions.CONFIG_FILE = str(path)
    app_config.reload()
    yield path
    extensions.CONFIG_FILE = original
    from tests.conftest import _patch_extensions

    _patch_extensions()


def _record_for(server_id, name="Primary"):
    import json

    from jen.models import user as _user

    _user.set_global_setting(
        inv.RECORD_KEY,
        json.dumps(
            {
                "servers": {
                    str(server_id): {
                        "name": name,
                        "until": "2099-01-01T00:00:00+00:00",
                        "file": "debug",
                        "daemon": "debug",
                        "pending": None,
                        "ssh_host": "10.0.0.5",
                    }
                }
            }
        ),
    )


def _clear_record():
    from jen.models import user as _user

    _user.set_global_setting(inv.RECORD_KEY, "")


class TestTheErrorHandlerAndTheWholeAppAreWiredCI:
    """CI-only (the Flask app and the database): the refusal reaches a person on whichever route asked."""

    def test_after_create_app_the_guard_is_registered(self, app):
        assert inv.identity_guard in jconfig._identity_guards

    def test_a_refused_save_flashes_and_redirects_and_a_json_caller_gets_409(
        self, logged_in_client, db, mock_kea, ci_config
    ):
        _record_for(1)
        try:
            r = logged_in_client.post(
                "/settings/infrastructure/save-ssh",
                data={"host": "10.9.9.9", "user": "jen", "kea_conf": ""},
                follow_redirects=True,
            )
            assert b"Changing its ssh_host now would point Jen at a different Kea" in r.data
            j = logged_in_client.post(
                "/settings/infrastructure/save-ssh",
                data={"host": "10.9.9.9", "user": "jen", "kea_conf": ""},
                headers={"Accept": "application/json"},
            )
            assert (
                j.status_code == 409
                and "turn it off from Servers first" in j.get_json()["error"]
                and j.get_json()["ok"] is False
            )
            disk = configparser.ConfigParser()
            disk.read(str(ci_config))
            assert disk.get("kea_ssh", "host") == "10.0.0.5", "nothing was written"
        finally:
            _clear_record()

    def test_the_redirect_goes_back_to_the_referring_page_only_when_it_is_this_host(
        self, logged_in_client, db, mock_kea, ci_config
    ):
        _record_for(1)
        try:
            data = {"host": "10.9.9.9", "user": "jen", "kea_conf": ""}
            own = logged_in_client.post(
                "/settings/infrastructure/save-ssh", data=data, headers={"Referer": "http://localhost/servers"}
            )
            elsewhere = logged_in_client.post(
                "/settings/infrastructure/save-ssh", data=data, headers={"Referer": "https://evil.example/x"}
            )
            assert own.headers["Location"].endswith("/servers")
            assert "evil.example" not in elsewhere.headers["Location"]
        finally:
            _clear_record()

    def test_the_kea_page_with_the_same_url_and_a_different_mode_is_refused(
        self, logged_in_client, db, mock_kea, ci_config
    ):
        """Item 2 through the route that review named: `save_infra_kea` passed only {"api_url": ...} to the old check."""
        _record_for(1)
        try:
            r = logged_in_client.post(
                "/settings/infrastructure/save-kea",
                data={"api_url": "http://1.2.3.4:8000", "api_user": "u4", "connection_mode": "direct"},
                follow_redirects=True,
            )
            assert b"The connection mode is how Jen reaches EVERY Kea" in r.data
            disk = configparser.ConfigParser()
            disk.read(str(ci_config))
            assert disk.get("kea", "connection_mode", fallback="ca") == "ca"
        finally:
            _clear_record()

    def test_the_setup_wizard_saves_are_refused_while_an_entry_exists(self, logged_in_client, db, mock_kea, ci_config):
        _record_for(1)
        try:
            r = logged_in_client.post(
                "/setup/helper",
                data={"action": "save_target", "ssh_host": "10.9.9.9", "ssh_user": "jen"},
                follow_redirects=True,
            )
            assert r.status_code == 200 and b"turn it off from Servers first" in r.data
            disk = configparser.ConfigParser()
            disk.read(str(ci_config))
            assert disk.get("kea_ssh", "host") == "10.0.0.5"
        finally:
            _clear_record()


# ── v5.68.0-beta.28 (Q164) part 2: the Kea FILE choke point - `kea_host.apply_config` ─────────────────────────────────────────────────────────

import copy  # noqa: E402

from jen.services import kea_changeset as _changeset_mod  # noqa: E402
from jen.services import kea_config_edit as ed  # noqa: E402
from jen.services import kea_host  # noqa: E402

_REAL_APPLY_CHANGE = (
    _changeset_mod.apply_change
)  # the `world` fixture replaces it with the fake daemon's; these tests want the REAL change set


@pytest.fixture
def host_world(world, monkeypatch):
    """`world` with the REAL `kea_changeset.apply_change` and the REAL `kea_host.apply_config`; only the wire is fake: `helper_call` writes the payload into the
    fake daemon's FILE (as the helper would), `test_config` always passes."""
    monkeypatch.setattr(inv._changeset, "apply_change", _REAL_APPLY_CHANGE)
    monkeypatch.setattr(_changeset_mod._events, "emit", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "test_config", lambda server, service, cfg, **kw: {"ok": True, "code": "ok"})
    monkeypatch.setattr(kea_host, "_record_from_resp", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "_record_revision_after_apply", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "_conf_path", lambda server, service: "/etc/kea/kea-dhcp4.conf")
    sent = []

    def helper_call(server, op, payload=None, timeout=60):
        assert op == "apply-config", op
        sent.append((server["id"], payload["service"]))
        world.daemons[server["id"]].file = copy.deepcopy(payload["config"])
        return {"ok": True, "sha256": "applied"}

    monkeypatch.setattr(kea_host, "helper_call", helper_call)
    world.sent = sent
    return world


def _marker(cfg):
    return ed.investigation_marker(cfg)


def _without_marker(cfg):
    out, _code = ed.clear_investigation_logging(copy.deepcopy(cfg))
    return out


class TestTheKeaFileWriterRefusesToEraseTheMarker:
    """The three writers that were not investigation logging - a config-history restore, the import push, Author Kea Config - wrote a candidate over a file that
    carried the marker. Their call shapes are exercised through the REAL `apply_config`."""

    @pytest.mark.parametrize(
        "kwargs",
        [
            {
                "expect_sha256": "applied",
                "summary": "restore of #7",
                "source": "restore",
            },  # servers.py: config-history restore
            {"expect_sha256": "applied", "summary": "Windows DHCP import"},  # subnets.py: the import push
            {
                "allow_overwrite": False,
                "summary": "authored",
                "helper_only": True,
            },  # authoring.py: Author Kea Config (through the change set)
        ],
        ids=["config-history-restore", "import-push", "author-kea-config"],
    )
    def test_each_writer_is_refused_with_investigation_on_and_nothing_is_sent(self, host_world, kwargs):
        w = host_world
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        sent_before = len(w.sent)
        candidate = _without_marker(w.daemons[1].file)
        res = kea_host.apply_config(_server(w, 1), "dhcp4", candidate, **kwargs)
        assert res["ok"] is False and res["code"] == "investigation-on" and res["via"] == "guard"
        assert "Investigation logging is on for kea-a" in res["detail"] and "would remove the marker" in res["detail"]
        assert len(w.sent) == sent_before, "nothing reached the host"
        assert _marker(w.daemons[1].file) is not None, "the marker is still in the file"
        (row,) = _audits(w, "INVESTIGATION_LOGGING_FILE_WRITE_REFUSED")
        assert row[1] == "kea-a"

    def test_after_turn_off_the_same_write_goes_through(self, host_world):
        w = host_world
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        candidate = _without_marker(w.daemons[1].file)
        assert kea_host.apply_config(_server(w, 1), "dhcp4", candidate)["code"] == "investigation-on"
        assert inv.turn_off(_server(w, 1))["ok"]
        assert kea_host.apply_config(_server(w, 1), "dhcp4", candidate)["ok"] is True

    def test_an_ordinary_edit_that_keeps_the_marker_is_not_touched(self, host_world):
        """A subnet or option edit starts from the config it just read, which carries the marker: nothing is lost, so nothing is refused."""
        w = host_world
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        edited = copy.deepcopy(w.daemons[1].file)
        edited["Dhcp4"]["subnet4"] = [{"id": 5, "subnet": "10.5.0.0/24"}]
        assert kea_host.apply_config(_server(w, 1), "dhcp4", edited)["ok"] is True
        assert _marker(w.daemons[1].file) is not None and w.daemons[1].file["Dhcp4"]["subnet4"]

    def test_investigation_loggings_own_writes_pass_and_the_flag_does_not_leak(self, host_world):
        w = host_world
        assert inv.turn_on(_server(w, 1), 5)["ok"] and _marker(w.daemons[1].file) is not None
        assert inv.turn_off(_server(w, 1))["ok"] and _marker(w.daemons[1].file) is None
        assert getattr(kea_host._investigation_writer, "on", False) is False
        # nested blocks restore what they found
        with kea_host.investigation_writer():
            with kea_host.investigation_writer():
                assert kea_host._investigation_writer.on is True
            assert kea_host._investigation_writer.on is True
        assert kea_host._investigation_writer.on is False

    def test_the_flag_belongs_to_one_thread(self, host_world):
        import threading

        seen = {}
        with kea_host.investigation_writer():
            t = threading.Thread(target=lambda: seen.update(other=getattr(kea_host._investigation_writer, "on", False)))
            t.start()
            t.join(5)
        assert seen == {"other": False}

    def test_other_services_and_other_servers_are_not_in_scope(self, host_world):
        w = host_world
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        sent_before = len(w.sent)
        assert kea_host.apply_config(_server(w, 1), "dhcp6", {"Dhcp6": {}})["ok"] is True, (
            "only kea-dhcp4's file carries the marker"
        )
        assert kea_host.apply_config(_server(w, 2), "dhcp4", _without_marker(w.daemons[2].file))["ok"] is True, (
            "server 2 has no entry"
        )
        assert len(w.sent) == sent_before + 2

    def test_a_restore_that_is_not_finished_has_a_clean_file_so_there_is_nothing_to_protect(self, host_world):
        w = host_world
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        record = inv._record()
        record["servers"]["1"]["file"] = "restored"
        assert inv._save(record)
        assert kea_host.apply_config(_server(w, 1), "dhcp4", _without_marker(w.daemons[1].file))["ok"] is True

    def test_a_damaged_marker_that_the_write_leaves_alone_is_not_removed_by_it(self, host_world):
        w = host_world
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        damaged = copy.deepcopy(w.daemons[1].file)
        logger_entry = next(x for x in damaged["Dhcp4"]["loggers"] if x["name"] == "kea-dhcp4")
        logger_entry["user-context"]["jen-investigation"].pop("restore")
        assert ed.validate_investigation_marker(damaged), "the marker lost its restore object: damaged, but still there"
        assert kea_host.apply_config(_server(w, 1), "dhcp4", damaged)["ok"] is True

    def test_an_unreadable_or_unavailable_record_refuses_every_dhcp4_write(self, host_world):
        w = host_world
        w.store[inv.RECORD_KEY] = "{broken"
        res = kea_host.apply_config(_server(w, 2), "dhcp4", w.daemons[2].file)
        assert (
            res["code"] == "investigation-on"
            and "cannot be read, so it cannot tell whether this Kea is at investigation DEBUG" in res["detail"]
        )
        w.store[inv.RECORD_KEY] = ""
        w.db["unavailable"] = True
        res = kea_host.apply_config(_server(w, 2), "dhcp4", w.daemons[2].file)
        assert res["code"] == "investigation-on" and "settings could not be read" in res["detail"]
        w.db["unavailable"] = False
        assert kea_host.apply_config(_server(w, 2), "dhcp4", w.daemons[2].file)["ok"] is True
        assert _audits(w, "INVESTIGATION_LOGGING_FILE_WRITE_REFUSED") and w.sent[-1] == (2, "dhcp4")


class TestTheChangeSetReportsAndRevertsARefusedTarget:
    def test_a_refused_target_aborts_the_change_set_before_any_write(self, host_world):
        w = host_world
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        sent_before = len(w.sent)
        result = _changeset_mod.apply_change(
            "dhcp4",
            lambda cfg: (_without_marker(cfg), "ok"),
            "config-history restore",
            servers=[_server(w, 1)],
            restart=False,
        )
        assert result.status == "aborted" and result.last_code == "investigation-on"
        text = " ".join(t for _k, t in result.lines)
        assert "Investigation logging is on for kea-a" in text and "(nothing was written to kea-a)" in text
        assert len(w.sent) == sent_before and _marker(w.daemons[1].file) is not None

    def test_a_server_already_committed_is_put_back_when_a_later_target_is_refused(self, host_world):
        w = host_world
        assert inv.turn_on(_server(w, 1), 5)["ok"]
        original_b = copy.deepcopy(w.daemons[2].file)

        def edit(cfg):
            out = _without_marker(cfg)
            out["Dhcp4"]["valid-lifetime"] = 1234
            return out, "ok"

        result = _changeset_mod.apply_change(
            "dhcp4", edit, "authored", servers=[_server(w, 2), _server(w, 1)], restart=False
        )
        assert result.status == "aborted" and result.last_code == "investigation-on"
        assert "reverted 1 server(s) that had already been updated: kea-b" in " ".join(t for _k, t in result.lines)
        assert w.daemons[2].file == original_b, "kea-b is exactly what it was"
        assert _marker(w.daemons[1].file) is not None

    def test_the_change_set_of_investigation_logging_itself_is_never_refused(self, host_world):
        w = host_world
        assert inv.turn_on(_server(w, 1), 15)["ok"]
        assert inv.turn_on(_server(w, 1), 5)["ok"], "moving the deadline rewrites the marker: investigation's own write"
        assert inv.turn_off(_server(w, 1))["ok"]


def _scoped_calls(tree):
    """[(call, name of the innermost enclosing function or "")] for every Call in `tree`."""
    out = []

    def walk(node, scope):
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else scope
            if isinstance(child, ast.Call):
                out.append((child, scope))
            walk(child, inner)

    walk(tree, "")
    return out


def _call_name(call):
    return (
        call.func.id
        if isinstance(call.func, ast.Name)
        else call.func.attr
        if isinstance(call.func, ast.Attribute)
        else ""
    )


class TestTheKeaFileHasOneChokePointInTheSource:
    def test_04_the_helpers_write_op_and_the_legacy_write_script_are_used_only_inside_apply_config(self):
        sites = set()
        for path in sorted((ROOT / "jen").rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            for call, scope in _scoped_calls(ast.parse(path.read_text(encoding="utf-8"))):
                if any(isinstance(a, ast.Constant) and a.value == "apply-config" for a in call.args):
                    sites.add((rel, scope, "apply-config"))
                if _call_name(call) == "render_author_config_script" and any(
                    k.arg == "dry_run" and isinstance(k.value, ast.Constant) and k.value.value is False
                    for k in call.keywords
                ):
                    sites.add((rel, scope, "legacy write script"))
        assert sites == {
            ("jen/services/kea_host.py", "apply_config", "apply-config"),
            ("jen/services/kea_host.py", "apply_config", "legacy write script"),
        }, sites

    def test_04b_apply_config_asks_before_anything_is_sent(self):
        fn = next(f for f in _functions(_parse("jen/services/kea_host.py")) if f.name == "apply_config")
        lines = {}
        for call, _scope in _scoped_calls(fn):
            lines.setdefault(_call_name(call), call.lineno)
        assert lines["file_write_refusal"] < min(
            lines["_jen_side_conflict"], lines["helper_call"], lines["_legacy_python3"]
        )

    def test_04c_every_apply_change_of_investigation_logging_is_inside_investigation_writer(self):
        tree = _parse("jen/services/investigation_logging.py")
        inside = 0
        for with_ in (n for n in ast.walk(tree) if isinstance(n, ast.With)):
            if any(
                isinstance(i.context_expr, ast.Call) and _call_name(i.context_expr) == "investigation_writer"
                for i in with_.items
            ):
                inside += sum(1 for c in ast.walk(with_) if isinstance(c, ast.Call) and _call_name(c) == "apply_change")
        total = sum(1 for c in ast.walk(tree) if isinstance(c, ast.Call) and _call_name(c) == "apply_change")
        assert total >= 2 and inside == total, (
            f"{total - inside} of {total} apply_change calls in investigation_logging.py are outside `with _host.investigation_writer()`"
        )

    def test_05_the_direct_socket_routes_preflight_before_any_remote_write(self):
        tree = _parse("jen/routes/settings/infrastructure.py")
        remote = {
            "apply_change",
            "apply_config",
            "service_action",
            "install_tls",
            "issue_server_cert",
            "ensure_ca",
            "issue_client_cert",
        }
        for name in ("setup_direct_socket", "remove_direct_socket"):
            fn = next(f for f in _functions(tree) if f.name == name)
            calls = [(c.lineno, _call_name(c)) for c, _s in _scoped_calls(fn)]
            preflight = min(line for line, n in calls if n == "preflight_identity_change")
            first_remote = min(line for line, n in calls if n in remote)
            assert preflight < first_remote, (
                f"{name}: preflight_identity_change (line {preflight}) must come before the first remote act (line {first_remote})"
            )


class TestARefusedDirectSocketRouteTouchesNothingCI:
    """CI-only: the whole route with the REAL config writer; the Kea host is a recording stub that fails the test if it is touched."""

    @pytest.fixture
    def hostile(self, monkeypatch):
        touched = []
        for target in (
            "jen.services.kea_changeset.apply_change",
            "jen.services.kea_host.service_action",
            "jen.services.kea_host.install_tls",
        ):
            monkeypatch.setattr(target, lambda *a, _t=target, **k: touched.append(_t) or {"ok": True})
        return touched

    def test_setup_is_refused_before_the_daemon_is_reconfigured_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, ci_config, hostile, monkeypatch
    ):
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [
                {
                    "id": 1,
                    "name": "Primary",
                    "ssh_host": "10.0.0.5",
                    "api_url": "http://1.2.3.4:8000",
                    "api_user": "u4",
                    "api_pass": "p4",
                }
            ],
        )
        _record_for(1)
        try:
            before = ci_config.read_bytes()
            r = logged_in_client.post(
                "/settings/infrastructure/direct-socket/1/dhcp4",
                data={"scheme": "http", "address": "10.0.0.5", "port": "8004", "user": "u", "password": "p"},
                follow_redirects=True,
            )
            assert b"Investigation logging is on for Primary" in r.data and b"connection mode" in r.data
            assert hostile == [], f"the Kea host was touched: {hostile}"
            assert ci_config.read_bytes() == before
        finally:
            _clear_record()

    def test_removal_is_refused_before_the_daemon_is_reconfigured(
        self, logged_in_client, db, mock_kea, ci_config, hostile, monkeypatch
    ):
        app_config.write_values(
            [
                ("kea", "connection_mode", "direct"),
                ("kea", "api_url", "http://1.2.3.4:8004"),
                ("kea", "api_url_prev", "http://1.2.3.4:8000"),
            ]
        )
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [
                {
                    "id": 1,
                    "name": "Primary",
                    "ssh_host": "10.0.0.5",
                    "api_url": "http://1.2.3.4:8004",
                    "api_user": "u4",
                    "api_pass": "p4",
                }
            ],
        )
        _record_for(1)
        try:
            before = ci_config.read_bytes()
            r = logged_in_client.post("/settings/infrastructure/direct-socket/1/dhcp4/remove", follow_redirects=True)
            assert b"Investigation logging is on for Primary" in r.data
            assert hostile == [] and ci_config.read_bytes() == before
        finally:
            _clear_record()

    def test_config_history_restore_is_refused_through_the_real_apply_config(
        self, logged_in_client, db, mock_kea, monkeypatch
    ):
        from jen.services import config_revisions as rev

        server = {"id": 77, "name": "kea-hist", "ssh_host": "10.0.0.5", "ssh_user": "kea"}
        monkeypatch.setattr(extensions, "KEA_SERVERS", [server])
        old = rev.record(77, "dhcp4", {"Dhcp4": {"subnet4": []}}, "sha-old", "rev 1", hash_kind="raw")
        wire = []
        monkeypatch.setattr("jen.services.kea_host.test_config", lambda *a, **k: {"ok": True})
        monkeypatch.setattr("jen.services.kea_host.helper_call", lambda *a, **k: wire.append(a[1]) or {"ok": True})
        monkeypatch.setattr(
            "jen.services.kea_host.service_action", lambda *a, **k: wire.append("restart") or {"ok": True}
        )
        monkeypatch.setattr("jen.services.kea_host.read_config_versioned", lambda *a, **k: ({"Dhcp4": {}}, "live-sha"))
        _record_for(77, name="kea-hist")
        try:
            r = logged_in_client.post(f"/servers/77/config-history/{old}/restore", follow_redirects=True)
            assert b"Restore failed on kea-hist" in r.data and b"would remove the marker" in r.data
            assert wire == [], f"nothing reached the host: {wire}"
        finally:
            _clear_record()
