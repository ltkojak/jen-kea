"""
tests/test_credentials.py
─────────────────────────
v5.69.0-beta.11 (Q180, CRED-004) - `jen/services/credentials.py` is the ONE definition of which secret Jen sends to which endpoint: a secret is used at its own endpoint, or inherited by a
daemon ON THE SAME HOST; an endpoint on a different host with no secret of its own has NONE. Pure: `py -m pytest --noconftest tests/test_credentials.py`.
"""

import configparser

import pytest

from jen import extensions
from jen.config import AppConfig
from jen.services import credentials as cred
from jen.services import kea


def _parser(**sections):
    p = configparser.ConfigParser(interpolation=None)
    for name, values in sections.items():
        p[name] = values
    return p


def _p(text: str):
    p = configparser.ConfigParser(interpolation=None)
    p.read_string(text)
    return p


BASE = """
[kea]
api_url = https://a:8000
api_user = u
api_pass = S
[kea_db]
host = db1
user = k
password = KDB
"""


class TestResolve:
    def test_kea6_on_the_same_host_inherits_the_kea_api_password(self):
        r = cred.resolve(_p(BASE + "[kea6]\napi_url = https://a:8006\n"))
        assert (r["kea6"].password, r["kea6"].source, r["kea6"].withheld) == ("S", "inherited:kea", "")

    def test_kea6_on_a_different_host_has_none_and_says_whose_it_was_refused(self):
        r = cred.resolve(_p(BASE + "[kea6]\napi_url = https://b:8006\n"))
        assert (r["kea6"].password, r["kea6"].source, r["kea6"].withheld) == ("", "none", "kea")

    def test_an_explicit_blank_password_is_none_and_nothing_is_withheld(self):
        r = cred.resolve(_p(BASE + "[kea6]\napi_url = https://b:8006\napi_pass =\n"))
        assert (r["kea6"].password, r["kea6"].source, r["kea6"].withheld) == ("", "none", "")

    def test_d2_follows_the_same_rule(self):
        same = cred.resolve(_p(BASE + "[d2]\napi_url = https://a:53001\n"))["d2"]
        other = cred.resolve(_p(BASE + "[d2]\napi_url = https://b:53001\n"))["d2"]
        blank = cred.resolve(_p(BASE + "[d2]\napi_url = https://b:53001\napi_pass =\n"))["d2"]
        assert (same.password, other.password, blank.password) == ("S", "", "")
        assert (same.source, other.withheld, blank.withheld) == ("inherited:kea", "kea", "")

    def test_in_ca_mode_an_absent_kea6_url_is_the_control_agents_and_so_the_same_host(self):
        r = cred.resolve(_p(BASE))
        assert r["kea6"].url == "https://a:8000" and r["kea6"].password == "S"

    def test_in_direct_mode_an_absent_kea6_url_is_nothing_and_nothing_is_withheld(self):
        r = cred.resolve(_p(BASE.replace("[kea]\n", "[kea]\nconnection_mode = direct\n")))
        assert r["kea6"].url == "" and r["kea6"].password == "" and r["kea6"].withheld == ""

    def test_an_extra_server_on_a_different_host_with_no_key_has_none(self):
        r = cred.resolve(_p(BASE + "[kea_server_2]\napi_url = https://b:8000\n"))
        assert (r["server_2"].password, r["server_2"].source, r["server_2"].withheld) == ("", "none", "kea")

    def test_an_extra_server_on_the_primarys_host_inherits(self):
        r = cred.resolve(_p(BASE + "[kea_server_2]\napi_url = https://a:8001\n"))
        assert (r["server_2"].password, r["server_2"].source) == ("S", "inherited:kea")

    def test_an_extra_server_with_its_own_password_uses_it(self):
        r = cred.resolve(_p(BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n"))
        assert (r["server_2"].password, r["server_2"].source) == ("P", "own")

    def test_an_extra_servers_ipv6_endpoint_is_judged_against_that_servers_password(self):
        cfg = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi6_url = {}\n"
        elsewhere = cred.resolve(_p(cfg.format("https://c:8006")))["server_2_v6"]
        samebox = cred.resolve(_p(cfg.format("https://b:8006")))["server_2_v6"]
        assert (elsewhere.password, elsewhere.withheld) == ("", "server_2")
        assert (samebox.password, samebox.source) == ("P", "inherited:server_2")

    def test_empty_and_absent_ipv6_passwords_are_different_things(self):
        cfg = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi6_url = https://b:8006\n{}"
        absent = cred.resolve(_p(cfg.format("")))["server_2_v6"]
        empty = cred.resolve(_p(cfg.format("api6_pass =\n")))["server_2_v6"]
        elsewhere_empty = cred.resolve(_p(cfg.replace("b:8006", "c:8006").format("api6_pass =\n")))["server_2_v6"]
        assert absent.password == "P" and empty.password == "" and elsewhere_empty.password == ""
        assert elsewhere_empty.withheld == "", "an explicit blank is the operator's answer: nothing was withheld"

    def test_an_extra_servers_d2_endpoint(self):
        r = cred.resolve(
            _p(BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi_d2_url = https://c:53001\n")
        )
        assert r["server_2_d2"].password == "" and r["server_2_d2"].withheld == "server_2"

    def test_the_kea6_database_inherits_only_on_the_kea_database_host(self):
        same = cred.resolve(_p(BASE + "[kea6_db]\nhost = db1\n"))["kea6_db"]
        other = cred.resolve(_p(BASE + "[kea6_db]\nhost = db2\n"))["kea6_db"]
        absent = cred.resolve(_p(BASE))["kea6_db"]
        assert (same.password, same.source) == ("KDB", "inherited:kea_db")
        assert (other.password, other.withheld) == ("", "kea_db")
        assert absent.password == "KDB"

    def test_the_database_host_is_compared_by_host_and_not_by_port(self):
        r = cred.resolve(_p(BASE + "[kea6_db]\nhost = DB1\nport = 3307\n"))["kea6_db"]
        assert r.password == "KDB" and r.url == "DB1:3307"

    def test_a_percent_in_a_password_is_a_percent(self):
        p = configparser.ConfigParser(interpolation=None)
        p.read_dict({"kea": {"api_url": "https://a:8000", "api_pass": "p%w"}, "kea6": {"api_url": "https://a:8006"}})
        r = cred.resolve(p)
        assert r["kea"].password == "p%w" and r["kea6"].password == "p%w"

    def test_a_fresh_install_with_no_sections_is_not_an_error(self):
        r = cred.resolve(configparser.ConfigParser(interpolation=None))
        assert r["kea"].password == "" and r["kea6"].withheld == "" and "server_2" not in r

    def test_every_endpoint_is_named(self):
        r = cred.resolve(
            _p(BASE + "[jen_db]\nhost = h\nuser = j\npassword = JP\n[kea_server_3]\napi_url = https://c:8000\n")
        )
        assert set(r) == {"kea", "kea6", "d2", "kea_db", "kea6_db", "jen_db", "server_3", "server_3_v6", "server_3_d2"}


class TestTheConsumersAreOnTheResolver:
    @pytest.fixture(autouse=True)
    def _put_the_globals_back(self):
        """`apply` assigns every config global; the rest of the suite must not see this file's."""
        snapshot = dict(vars(extensions))
        yield
        for key, value in snapshot.items():
            setattr(extensions, key, value)

    def test_apply_and_derive_agree_with_resolve(self, monkeypatch):
        cfg = _p(
            BASE
            + "[kea6]\napi_url = https://b:8006\n[d2]\napi_url = https://a:53001\n[kea6_db]\nhost = db2\n[kea_server_2]\napi_url = https://c:8000\napi6_url = https://c:8006\napi_pass = P\n"
        )
        servers = AppConfig.derive_kea_servers(cfg, quiet=True)
        primary, second = servers[0], servers[1]
        assert (primary["api_pass"], primary["api6_pass"], primary["api_d2_pass"]) == ("S", "", "S")
        assert primary["api6_withheld"] == "kea" and primary["api_d2_withheld"] == ""
        assert (second["api_pass"], second["api6_pass"], second["api_withheld"]) == ("P", "P", "")
        for attr in ("KEA6_API_PASS", "D2_API_PASS", "KEA6_DB_PASS"):
            monkeypatch.setattr(extensions, attr, "unset")
        AppConfig().apply(_with_required(cfg))
        assert (extensions.KEA6_API_PASS, extensions.D2_API_PASS, extensions.KEA6_DB_PASS) == ("", "S", "")
        assert extensions.KEA6_API_WITHHELD == "kea" and extensions.D2_API_WITHHELD == ""

    def test_there_is_no_fallback_left_in_the_tree(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent / "jen"
        hits = []
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for needle in ("fallback=primary_pass", 'or server.get("api_pass"'):
                if needle in text:
                    hits.append((path.name, needle))
        assert hits == [], hits


def _with_required(cfg):
    for section, values in {"jen_db": {"host": "h", "user": "u", "password": "jp"}, "server": {}}.items():
        if not cfg.has_section(section):
            cfg.add_section(section)
        for k, v in values.items():
            cfg.set(section, k, v)
    return cfg


class TestEndpointForSendsNothingWithoutACredential:
    @pytest.fixture
    def world(self, monkeypatch):
        sent = []

        class _NoPost:
            exceptions = kea.http.exceptions

            @staticmethod
            def post(*a, **k):
                sent.append((a, k))
                raise AssertionError("a request was sent to an endpoint that has no credential")

        monkeypatch.setattr(kea, "http", _NoPost)
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        return sent

    def _servers(self, text):
        return AppConfig.derive_kea_servers(_p(text), quiet=True)

    def test_a_withheld_ipv6_endpoint_answers_with_the_sentence_and_sends_nothing(self, world):
        primary = self._servers(BASE + "[kea6]\napi_url = https://b:8006\n")[0]
        assert primary["api6_withheld"] == "kea"
        answer = kea._endpoint_for(primary, "dhcp6")
        assert isinstance(answer, dict) and answer["result"] == 1
        assert (
            "has no credential" in answer["text"]
            and "https://b:8006" in answer["text"]
            and "Settings → Kea" in answer["text"]
        )
        assert kea.kea_command("config-get", "dhcp6", server=primary)["result"] == 1
        assert world == []

    def test_a_withheld_extra_server_answers_the_same_way_for_its_api_and_its_d2(self, world):
        servers = self._servers(BASE + "[kea_server_2]\nname = peer\napi_url = https://b:8000\n")
        answer = kea.kea_command("version-get", "dhcp4", server=servers[1])
        assert answer["result"] == 1 and "peer" in answer["text"] and "no credential" in answer["text"]
        assert world == []

    def test_an_endpoint_with_no_password_anywhere_is_still_reached_as_before(self, monkeypatch):
        sent = []

        class _Reply:
            def raise_for_status(self):
                pass

            def json(self):
                return [{"result": 0}]

        class _Post:
            exceptions = kea.http.exceptions

            @staticmethod
            def post(url, **k):
                sent.append((url, k["auth"]))
                return _Reply()

        monkeypatch.setattr(kea, "http", _Post)
        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "ca")
        servers = self._servers(
            "[kea]\napi_url = https://a:8000\napi_user = u\n[kea_server_2]\napi_url = https://b:8000\n"
        )
        assert kea.kea_command("version-get", server=servers[1])["result"] == 0
        assert sent == [("https://b:8000", ("u", ""))], (
            "a Kea with no authentication: a blank password is not a refusal"
        )


class _FakeConfig:
    """Just what `credentials.materialise` asks of `app_config`: the parser as it is, and `mutate`."""

    def __init__(self, parser):
        self.parser = parser
        self.writes = 0
        self.typed = []

    def _read_parser(self):
        copy = configparser.ConfigParser(interpolation=None)
        copy.read_dict({s: dict(self.parser.items(s)) for s in self.parser.sections()})
        return copy

    def mutate(self, fn, reload=True, typed=None):
        parser = self._read_parser()
        fn(parser)
        self.parser = parser
        self.writes += 1
        self.typed.append(set(typed or ()))


class TestMaterialise:
    CFG = (
        BASE
        + "[kea_server_2]\napi_url = https://b:8000\n[kea_server_3]\napi_url = https://c:8000\napi_pass = OWN\n[kea_server_4]\nname = no url\n[kea_server_5]\napi_url = https://a:8001\n"
    )

    def test_a_server_on_another_host_with_no_key_gets_a_marked_copy_and_the_others_are_untouched(self):
        fake, rows = _FakeConfig(_p(self.CFG)), []
        done = cred.materialise(fake, audit=lambda *a: rows.append(a))
        assert done == ["server_2"]
        assert (
            fake.parser.get("kea_server_2", "api_pass") == "S"
            and fake.parser.get("kea_server_2", "api_pass_shared") == "1"
        )
        assert fake.parser.get("kea_server_3", "api_pass") == "OWN" and not fake.parser.has_option(
            "kea_server_3", "api_pass_shared"
        )
        assert not fake.parser.has_option("kea_server_4", "api_pass")
        assert not fake.parser.has_option("kea_server_5", "api_pass"), (
            "a server on the PRIMARY's host still inherits: nothing to convert, nothing copied"
        )
        assert rows == [
            (
                "CONFIG_MIGRATION",
                "kea_server_2",
                "kea_server_2: the parent's api_pass materialised; it no longer follows the parent's",
            )
        ]
        assert "server_2" in fake.typed[0]

    def test_kea6_d2_the_kea6_database_and_a_servers_ipv6_and_d2_are_converted_in_order(self):
        """The second pass (P2-3): U2's reasoning - what worked yesterday works today - applies to every endpoint the old inheritance reached."""
        cfg = (
            BASE
            + "[kea6]\napi_url = https://k6:8006\n[d2]\napi_url = https://dd:53001\n[kea6_db]\nhost = db2\n"
            + "[kea_server_2]\napi_url = https://b:8000\napi6_url = https://b6:8006\napi_d2_url = https://bd:53001\n"
        )
        fake = _FakeConfig(_p(cfg))
        done = cred.materialise(fake)
        assert sorted(done) == ["d2", "kea6", "kea6_db", "server_2", "server_2_d2", "server_2_v6"]
        r = cred.resolve(fake.parser)
        assert (r["kea6"].password, r["d2"].password, r["kea6_db"].password) == ("S", "S", "KDB")
        assert (r["server_2"].password, r["server_2_v6"].password, r["server_2_d2"].password) == ("S", "S", "S")
        assert (
            fake.parser.get("kea6_db", "password_shared") == "1"
            and fake.parser.get("kea_server_2", "api6_pass_shared") == "1"
        )
        assert all(e.withheld == "" for e in r.values())

    def test_another_spelling_of_the_same_box_is_converted_too(self):
        fake = _FakeConfig(
            _p(BASE.replace("https://a:8000", "https://kea-a.lan:8000") + "[kea6]\napi_url = https://10.0.0.5:8006\n")
        )
        assert cred.materialise(fake) == ["kea6"] and fake.parser.get("kea6", "api_pass") == "S"

    def test_a_second_call_changes_nothing(self):
        fake, rows = _FakeConfig(_p(self.CFG)), []
        cred.materialise(fake, audit=lambda *a: rows.append(a))
        snapshot = {s: dict(fake.parser.items(s)) for s in fake.parser.sections()}
        assert cred.materialise(fake, audit=lambda *a: rows.append(a)) == []
        assert fake.writes == 1 and len(rows) == 1
        assert {s: dict(fake.parser.items(s)) for s in fake.parser.sections()} == snapshot

    def test_the_resolution_is_what_it_was_before_the_upgrade_for_every_endpoint(self):
        """The point of converting: the peer on another host is reached with the same password after the conversion as it was by the old inheritance."""
        before = cred.resolve(_p(self.CFG))["server_2"].password
        fake = _FakeConfig(_p(self.CFG))
        cred.materialise(fake)
        assert before == "" and cred.resolve(fake.parser)["server_2"].password == "S"

    def test_a_primary_with_no_password_has_nothing_to_copy(self):
        fake = _FakeConfig(_p("[kea]\napi_url = https://a:8000\n[kea_server_2]\napi_url = https://b:8000\n"))
        assert cred.materialise(fake) == [] and fake.writes == 0

    def test_it_never_runs_in_a_request_and_says_it_did_not_run(self):
        from flask import Flask

        fake = _FakeConfig(_p(self.CFG))
        with Flask(__name__).test_request_context("/"):
            assert cred.materialise(fake) is None
        assert fake.writes == 0

    def test_a_failure_is_logged_never_raised_and_says_it_did_not_run(self):
        class Broken(_FakeConfig):
            def mutate(self, *a, **k):
                raise OSError("disk full")

        assert cred.materialise(Broken(_p(self.CFG))) is None

    def test_a_failing_audit_does_not_undo_the_conversion(self):
        fake = _FakeConfig(_p(self.CFG))

        def audit(*a):
            raise RuntimeError("database down")

        assert cred.materialise(fake, audit=audit) == ["server_2"] and fake.parser.has_option(
            "kea_server_2", "api_pass"
        )


class TestItRunsOncePerInstallNotOncePerStart:
    """The second pass's P1: a section a superadmin leaves WITHOUT a key on purpose (the share box unticked) must not be filled in at the next restart."""

    def test_create_app_converts_only_while_the_install_marker_is_unset_and_sets_it(self):
        import ast
        import pathlib

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "__init__.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        create_app = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "create_app")
        text = ast.get_source_segment(src, create_app)
        assert 'credentials_materialised", "") != "1"' in text and "materialise(app_config" in text
        assert text.index('credentials_materialised", "") != "1"') < text.index("materialise(app_config")
        assert '_set_setting("credentials_materialised", "1")' in text
        assert "is not None" in text.split("materialise(app_config")[1].split("\n")[0], (
            "the marker is set only when the conversion RAN (None = it did not)"
        )

    def test_after_the_conversion_a_keyless_server_stays_keyless(self):
        """What the marker guarantees, in terms of the function: the conversion is a function of the file; nothing in it remembers - so the caller must not call it again."""
        fake = _FakeConfig(_p(BASE + "[kea_server_2]\napi_url = https://b:8000\n"))
        assert cred.materialise(fake) == ["server_2"]
        fake.parser.add_section("kea_server_3")
        fake.parser.set("kea_server_3", "api_url", "https://c:8000")  # added later, on purpose, with no key
        assert cred.resolve(fake.parser)["server_3"].withheld == "kea"


class TestAnIpv6LiteralDatabaseHost:
    def test_the_port_does_not_fuse_into_the_host(self):
        r = cred.resolve(_p(BASE.replace("host = db1", "host = ::1") + "[kea6_db]\nport = 3307\n"))
        assert r["kea_db"].url == "[::1]:3306" and r["kea6_db"].url == "[::1]:3307"
        assert r["kea6_db"].password == "KDB" and r["kea6_db"].withheld == ""

    def test_a_port_change_on_an_ipv6_database_host_is_not_a_move(self):
        before = cred.resolve(_p(BASE.replace("host = db1", "host = ::1")))
        after = cred.resolve(
            _p(BASE.replace("host = db1", "host = ::1").replace("password = KDB", "password = KDB\nport = 3307"))
        )
        assert after["kea_db"].url == "[::1]:3307"
        assert cred.move_refusal(before, after) == ""
