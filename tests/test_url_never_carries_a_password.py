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
