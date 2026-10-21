"""
tests/test_url_never_carries_a_password.py
──────────────────────────────────────────
v5.69.0-beta.21 (Q190, AF2; CRED-005, LEAK-001): an address is shown by ONE helper and a URL never carries a password.

  * `auth.valid_api_url` refuses a URL with user-info (the credential rule's fields are the only place a Kea password lives);
  * `auth.shown_url` is scheme, host and port - never user-info, a path or a query - and `auth.scrub_urls` takes the user-info out of text Jen did not write;
  * a URL that already carries user-info in jen.config is legacy input: ONE warning naming the section and key, a Health note, and Jen still dials it as written.

The sweep that refuses a route which formats an address without the helper is `tests/test_invariant_sweeps.py` S14; the Lab's T4 (`tests/test_kea_tls_rotation.py`) looks for the password in everything
a rotation prints, however the dial fails.

Pure (`pytest --noconftest tests/test_url_never_carries_a_password.py`).
"""

import configparser
import logging

import pytest

from jen.services import auth


class TestValidApiUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "https://u:p@h:8004",
            "https://u@h:8004",
            "http://:p@h:8004",
            "http://u:p@[fd00::5]:8004",
            "http://a@b@h:8004",
        ],
    )
    def test_user_info_is_refused(self, url):
        assert auth.valid_api_url(url) is False and auth.valid_api_url(url, require_port=True) is False
        assert auth.userinfo_sentence(url) == auth.USERINFO_SENTENCE

    @pytest.mark.parametrize("url", ["https://h:8004", "http://h", "http://[fd00::5]:8004", "http://kea-a.lan:8000/"])
    def test_a_plain_address_is_accepted(self, url):
        assert auth.valid_api_url(url) is True and auth.userinfo_sentence(url) == ""

    def test_the_sentence_never_echoes_the_address(self):
        assert "s3cret" not in auth.userinfo_sentence("https://u:s3cret@h:8004")


class TestShownUrl:
    def test_scheme_host_and_port_only(self):
        assert auth.shown_url("https://admin:s3cret@10.0.0.5:8004/path?x=1#f") == "https://10.0.0.5:8004"
        assert auth.shown_url("http://[fd00::5]:8004") == "http://[fd00::5]:8004"
        assert auth.shown_url("http://kea-a") == "http://kea-a"

    @pytest.mark.parametrize("value", ["", None, "garbage", "ftp://h:1", "https://", "http://h:notaport"])
    def test_a_value_that_is_not_an_address_is_never_echoed(self, value):
        assert auth.shown_url(value) == "an address Jen cannot read"

    def test_scrub_removes_user_info_from_any_text(self):
        text = "HTTPSConnectionPool: Max retries exceeded with url: https://admin:s3cret@10.0.0.5:8004/ (Caused by x); also http://u@h:1"
        out = auth.scrub_urls(text)
        assert "s3cret" not in out and "admin" not in out and "https://10.0.0.5:8004/" in out and "http://h:1" in out
        assert auth.scrub_urls(out) == out, "idempotent"
        assert auth.scrub_urls("no address here") == "no address here"


class TestLegacyUrls:
    CONFIG = "[kea]\napi_url = https://u:p@h:8004\n[kea_server_2]\napi6_url = https://h:8006\napi_d2_url = http://x@h:1\nname = standby\n"

    def _cfg(self, text=None):
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string(text or self.CONFIG)
        return cfg

    def test_the_sections_and_keys_are_named_never_the_values(self):
        assert auth.urls_with_userinfo(self._cfg()) == [("kea", "api_url"), ("kea_server_2", "api_d2_url")]

    def test_apply_warns_once_per_key_naming_no_value(self, caplog, monkeypatch):
        from jen import config as jconfig

        monkeypatch.setattr(jconfig, "_USERINFO_WARNED", set())
        with caplog.at_level(logging.WARNING, logger="jen.config"):
            jconfig._warn_userinfo_urls(self._cfg())
            jconfig._warn_userinfo_urls(self._cfg())
        lines = [r.getMessage() for r in caplog.records if "carries a user name" in r.getMessage()]
        assert len(lines) == 2, "one per (section, key), once"
        assert "[kea] api_url" in lines[0] and "[kea_server_2] api_d2_url" in lines[1]
        assert not any("u:p" in line or "x@h" in line for line in lines)

    def test_health_says_where_and_what_to_do(self, monkeypatch):
        from jen import extensions
        from jen.services import health

        monkeypatch.setattr(extensions, "cfg", self._cfg())
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a"}, {"id": 2, "name": "standby"}])
        row = health._endpoint_credentials({})
        assert row.status == "warn"
        assert (
            "the API URL for kea-a (kea api_url) carries a user name; move it to the user and password fields"
            in row.detail
        )
        assert "standby (kea_server_2 api_d2_url)" in row.detail and "u:p" not in row.detail

    def test_a_clean_configuration_says_nothing(self, monkeypatch):
        from jen import extensions
        from jen.services import health

        monkeypatch.setattr(extensions, "cfg", self._cfg("[kea]\napi_url = https://h:8004\n"))
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a"}])
        assert health._endpoint_credentials({}).status == "ok"


class TestTheSecondPassOfQ190:
    """The rows of the second pass (findings 5, 12, 2): the scrub reaches the LAST '@', only Kea's address keys are legacy input, and an address on a page is shown by a filter."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("failed: https://admin:p@ss@10.0.0.5:8004/x", "failed: https://10.0.0.5:8004/x"),
            ("failed: https://admin:p@ss:word@10.0.0.5:8004", "failed: https://10.0.0.5:8004"),
            ("https://u:a@b@c@h:1 and more", "https://h:1 and more"),
            ("see https://u:p@h:8004/path and mail me@example.com", "see https://h:8004/path and mail me@example.com"),
            ("(https://u:p@h:8004)", "(https://h:8004)"),
        ],
    )
    def test_the_scrub_removes_user_info_to_the_last_at_sign_and_only_that(self, text, expected):
        assert auth.scrub_urls(text) == expected

    def test_only_the_keys_an_endpoint_has_are_legacy_input(self):
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string(
            "[ddns]\napi_url = https://u:p@dns:1\n[kea]\napi_url = https://h:1\nsome_other_url = https://u:p@x:1\n"
            "[plugins]\nurl = https://u:p@y:1\n[kea_server_2]\ndirect_prev_api_url = http://u:p@h:8000\n"
        )
        # (Q191, AG3 b: the DNS provider's address is covered too, with its own sentence - its user name and token are the provider's own fields)
        assert auth.urls_with_userinfo(cfg) == [("ddns", "api_url"), ("kea_server_2", "direct_prev_api_url")]

    def test_the_page_filters_show_and_prefill_without_the_password(self):
        import jinja2

        env = jinja2.Environment(autoescape=True, undefined=jinja2.StrictUndefined)
        auth.register_url_filters(env)
        legacy = "https://admin:s3cret@10.0.0.5:8004/x"
        shown = env.from_string(
            "{{ u|shown_url }}|{{ u|no_userinfo }}|{{ ''|no_userinfo }}|{{ none|no_userinfo }}"
        ).render(u=legacy)
        assert shown == "https://10.0.0.5:8004|https://10.0.0.5:8004/x||"
        assert "s3cret" not in shown

    def test_every_template_that_prints_a_kea_address_goes_through_a_filter(self):
        """The template half of S14: a `{{ ... api_url ... }}` print on a page names `shown_url` or `no_userinfo` (a condition or a macro argument prints nothing)."""
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parents[1] / "templates"
        printed = re.compile(
            r"\{\{(?P<expr>[^}]*?(?:api6?_url|api_d2_url|kea6?_api_url|d2_api_url|prev_urls|ddns_url)[^}]*)\}\}"
        )
        found = []
        for path in sorted(root.rglob("*.html")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for m in printed.finditer(line):
                    expr = m.group("expr")
                    if "shown_url" in expr or "no_userinfo" in expr or expr.strip().startswith("direct_socket_setup"):
                        continue
                    found.append(f"{path.name}:{n}: {expr.strip()[:60]}")
        assert found == [], f"a page prints a Kea address without `shown_url` / `no_userinfo` (CRED-005): {found}"


class TestTheKeaClientNeverPrintsALegacyPassword:
    """Second pass, finding 2: the Kea client's own sentences (`Cannot connect to Kea API at ...`, the wrong-daemon text, the no-credential text) are shown on the dashboard, Health and the Doctor page
    to every role - a legacy URL with user-info must reach none of them."""

    URL = "https://admin:s3cret@10.0.0.5:8004/x"

    @pytest.fixture
    def kea_world(self, monkeypatch):
        import types

        import requests

        from jen import extensions
        from jen.services import kea

        monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
        monkeypatch.setattr(kea, "_endpoint_for", lambda server, service: (self.URL, "u", "p"))
        monkeypatch.setattr(kea, "_tls_verify", lambda: True)
        monkeypatch.setattr(kea, "_tls_client_cert", lambda: None)
        world = types.SimpleNamespace(post=None, exceptions=requests.exceptions)
        monkeypatch.setattr(kea, "http", world)
        return kea, world

    def test_cannot_connect_names_the_host_not_the_password(self, kea_world):
        import requests

        kea, world = kea_world

        def post(*a, **k):
            raise requests.exceptions.ConnectionError(f"Max retries exceeded with url: {self.URL}")

        world.post = post
        text = kea.kea_command("version-get")["text"]
        assert "10.0.0.5:8004" in text and "s3cret" not in text and "admin" not in text

    def test_the_wrong_daemon_sentence_names_the_host_not_the_password(self, kea_world):
        kea, world = kea_world

        class Reply:
            def raise_for_status(self):
                return None

            def json(self):
                return [{"result": 0, "arguments": {"Control-agent": {}}}]

        world.post = lambda *a, **k: Reply()
        text = kea.kea_command("config-get")["text"]
        assert "the Control Agent" in text and "10.0.0.5:8004" in text and "s3cret" not in text

    def test_the_no_credential_sentence_names_the_host_not_the_password(self):
        import inspect

        from jen.services import kea

        source = inspect.getsource(kea._endpoint_for)
        assert "_shown(url)" in source and "{url}" not in source, "the sentence goes through the helper"


class TestTheDnsProvidersAddressAndTheRestOfQ191:
    """Q191 (AG3): the DNS provider's URL is pre-filled without a legacy password, warned about once with its own sentence, named by Health, and the installer merge says where a user name sits."""

    def test_the_legacy_sentence_for_a_dns_provider_names_its_own_fields(self):
        note = auth.userinfo_legacy_note("ddns", "api_url")
        assert "DNS provider's URL" in note and "user and token fields" in note and "[ddns] api_url" in note
        assert "user and password fields" in auth.userinfo_legacy_note("kea", "api_url")

    def test_apply_warns_once_for_ddns_naming_no_value(self, caplog, monkeypatch):
        from jen import config as jconfig

        monkeypatch.setattr(jconfig, "_USERINFO_WARNED", set())
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string("[ddns]\napi_url = https://admin:s3cret@dns.example:5380\n")
        with caplog.at_level(logging.WARNING, logger="jen.config"):
            jconfig._warn_userinfo_urls(cfg)
            jconfig._warn_userinfo_urls(cfg)
        lines = [r.getMessage() for r in caplog.records if "carries a user name" in r.getMessage()]
        assert len(lines) == 1 and "DNS provider" in lines[0] and "s3cret" not in lines[0]

    def test_health_names_the_dns_provider(self, monkeypatch):
        from jen import extensions
        from jen.services import health

        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string("[kea]\napi_url = https://h:8004\n[ddns]\napi_url = https://u:s3cret@dns:5380\n")
        monkeypatch.setattr(extensions, "cfg", cfg)
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a"}])
        row = health._endpoint_credentials({})
        assert row.status == "warn" and "DNS provider's URL (ddns api_url)" in row.detail
        assert "s3cret" not in row.detail

    def test_the_dns_fields_are_prefilled_without_user_info(self):
        import pathlib

        source = (pathlib.Path(__file__).resolve().parents[1] / "templates" / "settings_kea.html").read_text(
            encoding="utf-8"
        )
        assert source.count("infra.ddns_url|no_userinfo") == 3 and "{{ infra.ddns_url }}" not in source

    def test_the_installer_merge_names_a_url_with_a_user_name_and_never_the_value(self):
        from tools import config_merge

        text = "[kea]\napi_url = https://u:s3cret@h:8004\n[kea_server_2]\napi6_url = https://h:8006\n[ddns]\napi_url = http://a@dns\n[other]\napi_url = http://x:y@z\n"
        assert config_merge.userinfo_warnings(text) == ["[kea] api_url", "[ddns] api_url"]

    def test_the_merge_command_warns_on_stderr_and_still_prints_the_file(self, tmp_path, capsys):
        from tools import config_merge

        live = tmp_path / "live.config"
        live.write_text("[kea]\napi_url = https://u:s3cret@h:8004\n", encoding="utf-8")
        snapshot = tmp_path / "snap.config"
        snapshot.write_text(live.read_text(encoding="utf-8"), encoding="utf-8")
        import io
        import sys

        stdin = sys.stdin
        sys.stdin = io.StringIO("[kea]\napi_url = https://u:s3cret@h:8004\n")
        try:
            code = config_merge.main(["--snapshot", str(snapshot), "--live", str(live)])
        finally:
            sys.stdin = stdin
        out = capsys.readouterr()
        assert code == 0 and "[kea] api_url" in out.err and "s3cret" not in out.err and "api_url" in out.out

    def test_no_server_dict_carries_a_url_key_so_the_dashboards_raw_print_is_unreachable(self):
        """The dashboard prints `s.server.get('url', '?')` only after `name`; no server dict has a `url` key (they have `api_url`), so that print is a fallback nothing reaches. A source test, so the day
        a `url` key is added to a server dict this fails and the print goes through `shown_url`."""
        import ast
        import pathlib

        tree = ast.parse(
            (pathlib.Path(__file__).resolve().parents[1] / "jen" / "config.py").read_text(encoding="utf-8")
        )
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "derive_kea_servers")
        keys = {
            k.value
            for d in ast.walk(fn)
            if isinstance(d, ast.Dict)
            for k in d.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        assert "url" not in keys and "api_url" in keys
        sets = [
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) and n.slice.value == "url"
        ]
        assert sets == []
