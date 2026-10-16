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
        assert sent == [("https://b:8000", kea._NO_AUTH)], (
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
        assert cred.materialise(fake) == [] and fake.writes == 1, (
            "nothing to copy - the marker alone is written, so a server left keyless LATER is never converted"
        )
        assert not fake.parser.has_option("kea_server_2", "api_pass") and cred.has_model_marker(fake.parser)

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


class TestTheMarkerLivesInTheFileItDescribes:
    """Q181, V3: `[jen] credential_model = explicit` is written in the SAME mutate as the copies (one atomic replace); a file that has it is never converted again."""

    LEGACY = BASE + "[kea_server_2]\napi_url = https://b:8000\n"

    def test_a_fresh_config_with_the_key_copies_nothing_and_writes_nothing(self):
        fake = _FakeConfig(_p(self.LEGACY + "[jen]\ncredential_model = explicit\n"))
        assert cred.materialise(fake) == [] and fake.writes == 0
        assert not fake.parser.has_option("kea_server_2", "api_pass"), (
            "a passwordless peer in a file born explicit is the operator's answer"
        )

    def test_a_pre_beta11_config_gets_the_copies_and_the_key_in_one_write(self):
        fake, rows = _FakeConfig(_p(self.LEGACY)), []
        assert cred.materialise(fake, audit=lambda *a: rows.append(a)) == ["server_2"]
        assert fake.writes == 1, "one atomic mutate: marker and copies together or neither"
        assert (
            fake.parser.get("jen", "credential_model") == "explicit"
            and fake.parser.get("kea_server_2", "api_pass") == "S"
        )
        assert len(rows) == 1
        assert cred.materialise(fake, audit=lambda *a: rows.append(a)) == [] and fake.writes == 1 and len(rows) == 1, (
            "a second start: nothing"
        )

    def test_the_conversion_copies_the_parents_user_with_the_password(self):
        """The old inheritance carried the parent's USER with its password; the resolver inherits a user on the same host only, so a copied password without its user would fail Basic auth."""
        fake = _FakeConfig(_p(self.LEGACY + "[kea6]\napi_url = https://k6:8006\n"))
        assert sorted(cred.materialise(fake)) == ["kea6", "server_2"]
        r = cred.resolve(fake.parser)
        assert (r["server_2"].user, r["server_2"].password) == ("u", "S")
        assert (r["kea6"].user, r["kea6"].password) == ("u", "S")
        assert fake.parser.get("kea_server_2", "api_user") == "u"

    def test_a_user_the_section_already_has_is_kept(self):
        fake = _FakeConfig(_p(self.LEGACY + "api_user = mine\n"))
        cred.materialise(fake)
        assert cred.resolve(fake.parser)["server_2"].user == "mine"

    def test_a_config_without_the_key_whose_database_says_it_converted_and_nothing_pending_gets_the_key_and_no_copies(
        self,
    ):
        fake = _FakeConfig(
            _p(BASE + "[kea_server_2]\napi_url = https://a:8001\n")
        )  # a peer on the primary's own host: nothing to convert
        assert cred.materialise(fake, already_converted=True) == []
        assert cred.has_model_marker(fake.parser) and not fake.parser.has_option("kea_server_2", "api_pass")
        assert fake.writes == 1

    def test_a_restored_legacy_file_whose_database_row_says_converted_is_converted_not_merely_marked(self):
        """Q182 (X5a, subagent S9): the settings row describes the DATABASE's old file, not this one. A restored pre-beta.11 file with a passwordless peer on another host keeps it working."""
        fake, rows = _FakeConfig(_p(self.LEGACY)), []
        assert cred.materialise(fake, audit=lambda *a: rows.append(a), already_converted=True) == ["server_2"]
        assert fake.writes == 1 and cred.has_model_marker(fake.parser)
        assert fake.parser.get("kea_server_2", "api_pass") == "S" and len(rows) == 1

    def test_a_restored_older_database_changes_nothing_because_the_marker_is_not_in_it(self):
        """The decision reads the FILE: with the key present the answer is the same whatever the settings table says."""
        fake = _FakeConfig(_p(self.LEGACY + "[jen]\ncredential_model = explicit\n"))
        assert cred.materialise(fake, already_converted=False) == [] and fake.writes == 0

    def test_a_read_only_file_logs_one_error_naming_it_and_raises_nothing(self, caplog):
        class ReadOnly(_FakeConfig):
            path = "/etc/jen/jen.config"

            def mutate(self, *a, **k):
                raise PermissionError(13, "Read-only file system")

        import logging

        with caplog.at_level(logging.ERROR, logger="jen.services.credentials"):
            assert cred.materialise(ReadOnly(_p(self.LEGACY))) is None
        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1 and "/etc/jen/jen.config" in errors[0].getMessage()

    def test_create_app_calls_it_every_start_and_the_database_key_is_only_read(self):
        import ast
        import pathlib

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "__init__.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        create_app = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "create_app")
        text = ast.get_source_segment(src, create_app)
        assert "materialise(" in text and "already_converted=" in text and "beta11_flag()" in text
        assert "credentials_materialised" not in text.replace("beta11_flag", ""), (
            "create_app no longer reads or writes the settings row itself"
        )
        assert "set_global_setting" not in text.split("materialise(")[1].split("Background workers")[0], (
            "the settings-table row is never written again"
        )

    def test_the_fresh_install_paths_write_the_key(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        assert "credential_model = explicit" in (root / "run.py").read_text(encoding="utf-8")
        installer = (root / "install.sh").read_text(encoding="utf-8")
        assert (
            "credential_model = explicit" in installer
            and '[[ -f "$CONFIG_FILE" ]] || credential_model_block=' in installer
        )

    def test_after_the_conversion_a_keyless_server_stays_keyless(self):
        fake = _FakeConfig(_p(BASE + "[kea_server_2]\napi_url = https://b:8000\n"))
        assert cred.materialise(fake) == ["server_2"]
        fake.parser.add_section("kea_server_3")
        fake.parser.set("kea_server_3", "api_url", "https://c:8000")  # added later, on purpose, with no key
        assert cred.resolve(fake.parser)["server_3"].withheld == "kea"
        assert cred.materialise(fake) == [] and not fake.parser.has_option("kea_server_3", "api_pass")


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


class TestTheThreeReadingsForEveryField:
    """Q181, V1: url, user and password under ONE reading - a value is its own, a present-blank key is explicit, an absent key inherits (the url in CA mode only; the user and the
    password on the same host only)."""

    def test_kea6_url_absent_in_ca_mode_is_the_primarys_present_blank_is_none_and_direct_is_none(self):
        assert cred.resolve(_p(BASE))["kea6"].url == "https://a:8000"
        assert cred.resolve(_p(BASE + "[kea6]\napi_url =\n"))["kea6"].url == ""
        direct = BASE.replace("[kea]\n", "[kea]\nconnection_mode = direct\n")
        assert (
            cred.resolve(_p(direct))["kea6"].url == ""
            and cred.resolve(_p(direct + "[kea6]\napi_url =\n"))["kea6"].url == ""
        )
        assert cred.resolve(_p(direct + "[kea6]\napi_url = https://a:8006\n"))["kea6"].url == "https://a:8006"

    def test_the_user_absent_on_the_same_host_is_the_primarys_present_blank_is_none_and_another_host_is_none(self):
        same = cred.resolve(_p(BASE + "[kea6]\napi_url = https://a:8006\n"))["kea6"]
        blank = cred.resolve(_p(BASE + "[kea6]\napi_url = https://a:8006\napi_user =\n"))["kea6"]
        other = cred.resolve(_p(BASE + "[kea6]\napi_url = https://b:8006\n"))["kea6"]
        own = cred.resolve(_p(BASE + "[kea6]\napi_url = https://b:8006\napi_user = mine\n"))["kea6"]
        assert (same.user, blank.user, other.user, own.user) == ("u", "", "", "mine")

    def test_an_extra_servers_ipv6_url_blank_with_a_password_is_no_endpoint_never_the_v4_url(self):
        r = cred.resolve(
            _p(
                BASE
                + "[kea_server_2]\napi_url = https://b:8000\napi_pass = S\napi6_url =\napi6_pass = S\n".replace(
                    "\napi6_pass", "\napi6_pass"
                )
            )
        )
        assert r["server_2_v6"].url == "" and r["server_2_v6"].password == "S"

    def test_a_servers_d2_user_follows_the_servers_on_the_same_host_only(self):
        cfg = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi_user = su\napi_d2_url = {}\n"
        assert cred.resolve(_p(cfg.format("https://b:53001")))["server_2_d2"].user == "su"
        assert cred.resolve(_p(cfg.format("https://c:53001")))["server_2_d2"].user == ""

    def test_the_database_user_follows_the_same_rule(self):
        assert cred.resolve(_p(BASE + "[kea6_db]\nhost = db1\n"))["kea6_db"].user == "k"
        assert cred.resolve(_p(BASE + "[kea6_db]\nhost = db2\n"))["kea6_db"].user == ""


class TestAFirstAddressIsAMove:
    """Q181, V2: a saved password that had NO address and is given one is a move, unless the password was typed in this write."""

    @staticmethod
    def _pair(before_text, after_text):
        return cred.resolve(_p(before_text)), cred.resolve(_p(after_text))

    DIRECT = "[kea]\nconnection_mode = direct\napi_url = https://a:8004\napi_user = u\napi_pass = S\n"

    def test_a_saved_password_given_its_first_address_untyped_is_refused_with_the_sentence(self):
        before, after = self._pair(
            self.DIRECT + "[kea6]\napi_pass = K6\n", self.DIRECT + "[kea6]\napi_pass = K6\napi_url = https://k6:8006\n"
        )
        assert "is being given its first address" in cred.move_refusal(before, after)

    def test_typed_it_passes(self):
        before, after = self._pair(
            self.DIRECT + "[kea6]\napi_pass = K6\n", self.DIRECT + "[kea6]\napi_pass = K6\napi_url = https://k6:8006\n"
        )
        assert cred.move_refusal(before, after, typed={"kea6"}) == ""

    def test_a_new_section_with_its_password_typed_passes(self):
        before, after = self._pair(
            self.DIRECT, self.DIRECT + "[kea_server_2]\napi_url = https://b:8004\napi_pass = P\n"
        )
        assert cred.move_refusal(before, after, typed={"server_2"}) == ""

    def test_no_password_before_then_an_address_is_free(self):
        before, after = self._pair(
            self.DIRECT + "[kea6]\napi_user = x\n", self.DIRECT + "[kea6]\napi_user = x\napi_url = https://k6:8006\n"
        )
        assert cred.move_refusal(before, after) == ""

    def test_the_writer_refuses_it_byte_identical(self, tmp_path, monkeypatch):
        from jen import extensions
        from jen.config import ConfigChangeRefused, app_config

        path = tmp_path / "jen.config"
        path.write_text(self.DIRECT + "[kea6]\napi_pass = K6\n", encoding="utf-8")
        monkeypatch.setattr(extensions, "CONFIG_FILE", str(path))
        monkeypatch.setattr(app_config, "reload", lambda: None)
        monkeypatch.setattr("jen.config._identity_guards", [])
        before = path.read_bytes()
        with pytest.raises(ConfigChangeRefused, match="first address"):
            app_config.write_values([("kea6", "api_url", "https://k6:8006")])
        assert path.read_bytes() == before
        app_config.write_values([("kea6", "api_url", "https://k6:8006")], typed={"kea6"})
        assert "k6:8006" in path.read_text(encoding="utf-8")


class TestNothingDownstreamDecides:
    """Q181, V1: a whole-tree source test - no `or` fallback on a url, user or password key of a server dict anywhere under jen/."""

    PATTERNS = ("or v4_url_fallback", "v4_url_fallback", "fallback=primary_user", "fallback=primary_pass")

    def test_there_is_no_fallback_left_in_the_tree(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parent.parent / "jen"
        hits = []
        key = re.compile(
            r"""or\s+server\.get\(\s*["'](?:api6?_?(?:d2_)?(?:url|user|pass)|api_d2_(?:url|user|pass)|api6_(?:url|user|pass))["']"""
        )
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for needle in self.PATTERNS:
                if needle in text and path.name != "credentials.py":
                    hits.append((path.name, needle))
            if key.search(text):
                hits.append((path.name, "an `or server.get(<url/user/pass>)`"))
        assert hits == [], hits


class TestTheUserFollowsAnOwnPassword:
    """Q181 second pass (P2-1): an absent user on another host is the parent's when the endpoint has a password of its own - the shape Jen's own forms write - and none otherwise."""

    def test_an_own_password_on_another_host_carries_the_parents_user(self):
        r = cred.resolve(
            _p(BASE + "[kea6]\napi_url = https://z:8006\napi_pass = K6\n[kea6_db]\nhost = db2\npassword = D6\n")
        )
        assert (r["kea6"].user, r["kea6"].password) == ("u", "K6")
        assert (r["kea6_db"].user, r["kea6_db"].password) == ("k", "D6")

    def test_no_password_on_another_host_has_no_user(self):
        r = cred.resolve(_p(BASE + "[kea6]\napi_url = https://z:8006\n"))
        assert (r["kea6"].user, r["kea6"].password, r["kea6"].withheld) == ("", "", "kea")

    def test_a_present_blank_user_is_still_no_user_beside_an_own_password(self):
        r = cred.resolve(_p(BASE + "[kea6]\napi_url = https://z:8006\napi_pass = K6\napi_user =\n"))
        assert r["kea6"].user == ""

    def test_a_server_endpoint_beside_its_own_password(self):
        cfg = (
            BASE
            + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi_user = su\napi6_url = https://c:8006\napi6_pass = P6\n"
        )
        assert cred.resolve(_p(cfg))["server_2_v6"].user == "su"


class TestUrlOwn:
    """Q182 (X1): `Endpoint.url_own` is True when the address is the endpoint's own value (its key is present), False when it is derived from the parent's."""

    def test_present_is_own_absent_in_ca_mode_is_derived(self):
        r = cred.resolve(
            _p(
                BASE
                + "[kea6]\napi_url = https://k6:8006\n[d2]\napi_pass = D\n[kea_server_2]\napi_url = https://b:8000\napi6_url =\n"
            )
        )
        assert (r["kea"].url_own, r["kea6"].url_own, r["d2"].url_own) == (True, True, False)
        assert (r["server_2"].url_own, r["server_2_v6"].url_own, r["server_2_d2"].url_own) == (True, True, False)

    def test_the_databases_are_their_own(self):
        r = cred.resolve(_p(BASE + "[kea6_db]\nhost = db2\n"))
        assert r["kea_db"].url_own and r["kea6_db"].url_own and r["jen_db"].url_own

    def test_an_absent_kea6_database_host_is_the_keas(self):
        assert cred.resolve(_p(BASE))["kea6_db"].url_own is False


class TestNoAuthenticationIsNoUser:
    """Q182 (X2): an absent user beside a PRESENT-BLANK own password is no user - the endpoint said "no authentication". A database keeps its user."""

    SAME = BASE + "[kea6]\napi_url = https://a:8006\napi_pass =\n"

    def test_kea6_on_the_same_host_with_a_blank_password_has_no_user(self):
        e = cred.resolve(_p(self.SAME))["kea6"]
        assert (e.user, e.password, e.source, e.withheld) == ("", "", "none", "")

    def test_d2_and_a_servers_endpoints_likewise(self):
        r = cred.resolve(
            _p(
                BASE
                + "[d2]\napi_url = https://a:53001\napi_pass =\n"
                + "[kea_server_2]\napi_url = https://b:8000\napi_user = su\napi_pass = P\napi6_url = https://b:8006\napi6_pass =\n"
            )
        )
        assert r["d2"].user == "" and r["server_2_v6"].user == ""

    def test_the_server_itself_with_a_blank_password_and_no_user(self):
        r = cred.resolve(_p(BASE + "[kea_server_2]\napi_url = https://a:8001\napi_pass =\n"))
        assert (r["server_2"].user, r["server_2"].password) == ("", "")

    def test_an_own_user_beside_a_blank_password_stays(self):
        e = cred.resolve(_p(self.SAME + "api_user = mine\n"))["kea6"]
        assert (e.user, e.password) == ("mine", "")

    def test_an_absent_password_on_the_same_host_still_inherits_both(self):
        e = cred.resolve(_p(BASE + "[kea6]\napi_url = https://a:8006\n"))["kea6"]
        assert (e.user, e.password) == ("u", "S")

    def test_a_database_keeps_its_user_beside_a_blank_password(self):
        e = cred.resolve(_p(BASE + "[kea6_db]\nhost = db1\npassword =\n"))["kea6_db"]
        assert (e.user, e.password) == ("k", "")


class TestTheMarkerIsAValue:
    """Q182 (X3): `model_marker` is "absent", "explicit" or "invalid"; an invalid one converts nothing, logs once, and the Doctor says so."""

    @pytest.mark.parametrize(
        ("value", "state"),
        [
            (None, "absent"),
            ("explicit", "explicit"),
            (" explicit ", "explicit"),
            ("", "invalid"),
            ("garbage", "invalid"),
        ],
    )
    def test_the_states(self, value, state):
        p = _p(BASE)
        if value is not None:
            p.add_section("jen")
            p.set("jen", "credential_model", value)
        assert cred.model_marker(p) == state
        assert cred.has_model_marker(p) is (state == "explicit")

    def test_an_invalid_marker_converts_nothing_writes_nothing_and_logs_one_error(self, caplog):
        import logging

        class Named(_FakeConfig):
            path = "/etc/jen/jen.config"

        fake = Named(_p(BASE + "[kea_server_2]\napi_url = https://b:8000\n[jen]\ncredential_model = explcit\n"))
        with caplog.at_level(logging.ERROR, logger="jen.services.credentials"):
            assert cred.materialise(fake) is None
        errors = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert fake.writes == 0 and not fake.parser.has_option("kea_server_2", "api_pass")
        assert len(errors) == 1 and "credential_model" in errors[0].getMessage() and "explcit" in errors[0].getMessage()


class TestTheBridgeKeepsBeta11sBlankAsAnAnswer:
    """Second pass (Q182) P2-2: beta.11's own forms wrote `api6_pass =` for "no authentication", and its conversion was remembered in the settings table, not in the file. A file with no marker
    whose database says it converted is NOT a 5.68.0 file: its blank is an answer, and the bridge must not fill it in."""

    FILE = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi6_url = https://c:8006\napi6_pass =\n"

    def test_the_bridge_marks_the_file_and_copies_nothing(self):
        fake = _FakeConfig(_p(self.FILE))
        assert cred.materialise(fake, already_converted=True) == []
        assert fake.parser.get("kea_server_2", "api6_pass") == "" and cred.has_model_marker(fake.parser)

    def test_without_the_bridge_it_is_still_a_legacy_blank(self):
        fake = _FakeConfig(_p(self.FILE))
        assert cred.materialise(fake, already_converted=False) == ["server_2_v6"]
        assert fake.parser.get("kea_server_2", "api6_pass") == "P"


class TestALegacyBlankIsInherit:
    """Q182 (X5d): 5.68.0 read a BLANK `api6_pass` / `api_d2_pass` on a server as "inherit", so in a file without the marker it is pending; with the marker a blank is a blank."""

    LEGACY = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi6_url = https://c:8006\napi6_pass =\n"

    def test_a_marker_less_file_lists_it_and_the_conversion_fills_it(self):
        assert cred.pending_conversions(_p(self.LEGACY)) == ["server_2_v6"]
        fake = _FakeConfig(_p(self.LEGACY))
        assert cred.materialise(fake) == ["server_2_v6"]
        assert (
            fake.parser.get("kea_server_2", "api6_pass") == "P"
            and fake.parser.get("kea_server_2", "api6_pass_shared") == "1"
        )
        assert cred.resolve(fake.parser)["server_2_v6"].source == "own"

    def test_a_marked_file_keeps_the_blank_as_no_password(self):
        marked = _p(self.LEGACY + "[jen]\ncredential_model = explicit\n")
        assert cred.pending_conversions(marked) == []
        e = cred.resolve(marked)["server_2_v6"]
        assert (e.password, e.source, e.withheld) == ("", "none", "")
        fake = _FakeConfig(marked)
        assert cred.materialise(fake) == [] and fake.writes == 0


class TestAModeSwitchRepointsTheDaemonsWholesale:
    """Q181 second pass (P2-5): direct -> CA gives every daemon the Control Agent's address; the form that flips the mode cannot type their passwords, so it is not refused for them."""

    DIRECT = (
        "[kea]\nconnection_mode = direct\napi_url = https://a:8004\napi_user = u\napi_pass = S\n[kea6]\napi_pass = K6\n"
    )

    def test_the_move_rule_skips_a_daemon_whose_address_is_derived_from_an_unmoved_control_agent(self):
        before = cred.resolve(_p(self.DIRECT))
        after = cred.resolve(_p(self.DIRECT.replace("direct", "ca")))
        assert after["kea6"].url_own is False and before["kea6"].url_own is False
        assert "first address" in cred.move_refusal(before, after)
        assert cred.move_refusal(before, after, mode_changed=True) == ""

    def test_the_skip_does_not_cover_an_address_of_the_daemons_own(self):
        """Q182 (X1): a mode flip that also gives the daemon an address of its own on another host is judged as any move."""
        before = cred.resolve(_p(self.DIRECT))
        after = cred.resolve(
            _p(self.DIRECT.replace("direct", "ca").replace("[kea6]", "[kea6]\napi_url = https://k6:8006"))
        )
        assert after["kea6"].url_own is True
        assert "first address" in cred.move_refusal(before, after, mode_changed=True)
        assert cred.move_refusal(before, after, typed={"kea6"}, mode_changed=True) == ""

    def test_the_skip_does_not_cover_a_control_agent_on_a_new_host(self):
        before = cred.resolve(_p(self.DIRECT))
        after = cred.resolve(_p(self.DIRECT.replace("direct", "ca").replace("https://a:8004", "https://z:8000")))
        assert after["kea6"].url_own is False and after["kea6"].url == "https://z:8000"
        assert "first address" in cred.move_refusal(before, after, typed={"kea"}, mode_changed=True)
        assert cred.move_refusal(before, after, typed={"kea", "kea6"}, mode_changed=True) == ""

    def test_a_servers_derived_endpoints_follow_the_same_rule(self):
        text = (
            "[kea]\nconnection_mode = direct\napi_url = https://a:8004\napi_pass = S\n"
            "[kea_server_2]\napi_url = https://b:8004\napi_pass = P\napi6_pass = P6\n"
        )
        before = cred.resolve(_p(text))
        same = cred.resolve(_p(text.replace("direct", "ca")))
        assert cred.move_refusal(before, same, mode_changed=True) == ""
        moved = cred.resolve(_p(text.replace("direct", "ca").replace("https://b:8004", "https://y:8000")))
        assert "first address" in cred.move_refusal(before, moved, typed={"server_2"}, mode_changed=True)

    def test_the_writer_passes_a_mode_switch_and_still_refuses_the_same_change_without_it(self, tmp_path, monkeypatch):
        from jen import extensions
        from jen.config import ConfigChangeRefused, app_config

        path = tmp_path / "jen.config"
        path.write_text(self.DIRECT, encoding="utf-8")
        monkeypatch.setattr(extensions, "CONFIG_FILE", str(path))
        monkeypatch.setattr(app_config, "reload", lambda: None)
        monkeypatch.setattr("jen.config._identity_guards", [])
        with pytest.raises(ConfigChangeRefused, match="first address"):
            app_config.write_values([("kea6", "api_url", "https://a:8006")])
        app_config.write_values([("kea", "connection_mode", "ca")])
        assert "connection_mode = ca" in path.read_text(encoding="utf-8")


class TestAnUnreadableSettingsTableIsNotAnAbsentRow:
    """Q181 second pass (P2-4): beta.11 refused to convert with the settings unreadable; beta.12 must not read "unreadable" as "not converted"."""

    def test_the_flag_is_none_when_the_table_cannot_be_read(self, monkeypatch):
        import contextlib

        @contextlib.contextmanager
        def broken():
            raise OSError("database down")
            yield  # pragma: no cover

        monkeypatch.setattr("jen.models.db.jen_db", broken)
        assert cred.beta11_flag() is None

    def test_the_flag_reads_the_row(self, monkeypatch):
        import contextlib

        class _Cur:
            def __init__(self, row):
                self.row = row

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, *a):
                pass

            def fetchone(self):
                return self.row

        class _Db:
            def __init__(self, row):
                self.row = row

            def cursor(self):
                return _Cur(self.row)

        for row, expected in (
            ({"setting_value": "1"}, True),
            ({"setting_value": '"1"'}, True),
            (None, False),
            ({"setting_value": "0"}, False),
        ):

            @contextlib.contextmanager
            def db(row=row):
                yield _Db(row)

            monkeypatch.setattr("jen.models.db.jen_db", db)
            assert cred.beta11_flag() is expected, row

    def test_create_app_does_nothing_when_the_flag_is_unreadable_and_drops_the_row_after_the_bridge(self):
        import ast
        import pathlib

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "__init__.py").read_text(encoding="utf-8")
        create_app = next(
            n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "create_app"
        )
        text = ast.get_source_segment(src, create_app)
        assert "beta11_flag()" in text and "_bridge is not None" in text and "forget_beta11_flag()" in text
        assert text.index("_bridge is not None") < text.index("materialise(")

    def test_a_marker_that_appears_between_the_probe_and_the_write_stops_the_conversion(self):
        class Racing(_FakeConfig):
            def mutate(self, fn, reload=True, typed=None):
                self.parser.add_section("jen")
                self.parser.set("jen", "credential_model", "explicit")  # a second process won the race
                super().mutate(fn, reload, typed)

        fake = Racing(_p(BASE + "[kea_server_2]\napi_url = https://b:8000\n"))
        assert cred.materialise(fake) == [] and not fake.parser.has_option("kea_server_2", "api_pass")


class TestTheKea6DatabaseIsAnEndpoint:
    """Q182 (X5c, subagent S5): `[kea6_db] host =` is "no Kea6 database", not "the machine Jen runs on"; a host different from Kea's own with no password of its own is withheld. Neither opens a
    pool or a connection, and the Doctor / Health say so."""

    @pytest.fixture(autouse=True)
    def _globals_back(self):
        from jen import extensions

        snapshot = dict(vars(extensions))
        yield
        for key, value in snapshot.items():
            setattr(extensions, key, value)

    def _apply(self, kea6_db_section):
        from jen import extensions
        from jen.config import AppConfig

        cfg = _p(BASE + "[jen_db]\nhost = jh\nuser = j\npassword = JP\n[server]\n" + kea6_db_section)
        AppConfig().apply(cfg)
        return extensions

    def test_a_blank_host_is_no_endpoint_and_opens_nothing(self, monkeypatch):
        import pymysql

        from jen.models import db

        ext = self._apply("[kea6_db]\nhost =\n")
        assert ext.KEA6_DB_HOST == "" and cred.resolve(_p(BASE + "[kea6_db]\nhost =\n"))["kea6_db"].url == ""
        monkeypatch.setattr(
            db, "_make_kea6_pool", lambda: pytest.fail("a pool was made for a Kea6 database with no host")
        )
        monkeypatch.setattr(db.pymysql, "connect", lambda **k: pytest.fail("a connection was made"))
        monkeypatch.setattr(db, "_kea6_pool", None)
        with pytest.raises(pymysql.err.OperationalError, match="no Kea6 database"):
            db.get_kea6_db()

    def test_a_host_on_another_server_with_no_password_is_withheld_and_opens_nothing(self, monkeypatch):
        import pymysql

        from jen.models import db

        ext = self._apply("[kea6_db]\nhost = db2\n")
        assert ext.KEA6_DB_WITHHELD == "kea_db" and ext.KEA6_DB_PASS == ""
        monkeypatch.setattr(db, "_make_kea6_pool", lambda: pytest.fail("a pool was made for a withheld credential"))
        monkeypatch.setattr(db.pymysql, "connect", lambda **k: pytest.fail("a connection was made"))
        monkeypatch.setattr(db, "_kea6_pool", None)
        with pytest.raises(pymysql.err.OperationalError, match="no password of its own"):
            db.get_kea6_db()

    def test_an_own_password_opens_the_pool_and_the_same_database_reuses_kea_s(self, monkeypatch):
        from jen.models import db

        ext = self._apply("[kea6_db]\nhost = db2\npassword = D6\n")
        assert ext.KEA6_DB_WITHHELD == "" and ext.KEA6_DB_PASS == "D6"
        made = []

        class _Pool:
            def connection(self):
                return "a connection"

        monkeypatch.setattr(db, "_make_kea6_pool", lambda: made.append(1) or _Pool())
        monkeypatch.setattr(db, "_kea6_pool", None)
        assert db.get_kea6_db() == "a connection" and made == [1]
        db._kea6_pool = None
        self._apply("")  # no [kea6_db] at all: the v4 database, through the v4 pool
        monkeypatch.setattr(db, "get_kea_db", lambda: "the kea pool")
        assert db.get_kea6_db() == "the kea pool"
