"""
tests/test_same_endpoint.py
───────────────────────────
v5.69.0-beta.9 (Q178, CRED-002) - `auth.same_endpoint`: do two URLs (or bare host[:port] strings) name the same place a secret would be sent to. Scheme, host and port - never
the path or the query. A blank on either side is a different place. Pure: `pytest --noconftest tests/test_same_endpoint.py`.
"""

import pytest

from jen.services import auth
from jen.services.auth import same_endpoint


class TestSameEndpoint:
    @pytest.mark.parametrize(
        "a,b,expect",
        [
            (
                "https://a.example/api",
                "https://A.example./api",
                False,
            ),  # (Q184, Z3: the trailing dot is a different name - absolute against search-relative)
            ("https://a.example./api", "https://A.example./api", True),
            ("https://a.example", "https://a.example:443/x?y=1", True),
            ("http://a.example", "http://a.example:80", True),
            ("http://a.example", "https://a.example", False),
            ("https://a.example", "https://b.example", False),
            ("https://a.example:8443", "https://a.example", False),
            (
                "db.local",
                "db.local:3306",
                False,
            ),  # a bare host has no scheme, so no default port: the driver's default is not this function's to assume
            ("db.local", "DB.local", True),
            ("db.local:3306", "DB.local:3306", True),
            ("db.local:3306", "db.local:3307", False),
            ("", "", False),
            ("  ", "", False),
            ("https://a.example", "", False),
            ("", "https://a.example", False),
            ("https://a.example:notaport", "https://a.example:notaport", False),
            (None, "https://a.example", False),
            (
                "10.0.0.5:8000",
                "http://10.0.0.5:8000",
                False,
            ),  # a bare host:port and a URL are different spellings with different schemes: not assumed equal
        ],
    )
    def test_the_rule(self, a, b, expect):
        assert same_endpoint(a, b) is expect

    def test_userinfo_does_not_make_a_different_place(self):
        assert same_endpoint("https://u:p@a.example/x", "https://a.example/y")

    def test_it_is_symmetric(self):
        pairs = [("https://a.example/x", "https://a.example"), ("db.local", "db.local:3306"), ("", "x.example")]
        for a, b in pairs:
            assert same_endpoint(a, b) is same_endpoint(b, a)


class TestABareIpv6HostIsAPlace:
    """Q178's adversarial pass: `urlsplit("//fe80::1")` reads the last group as a port and raises, so a bare IPv6 database host could never equal itself."""

    @pytest.mark.parametrize("host", ["::1", "fe80::1", "[::1]", "[::1]:3306", "2001:db8::5"])
    def test_it_equals_itself(self, host):
        assert same_endpoint(host, host)

    def test_two_different_addresses_are_different(self):
        assert not same_endpoint("::1", "::2")
        assert not same_endpoint("[::1]:3306", "[::1]:3307")


class TestSameHost:
    @pytest.mark.parametrize(
        "a,b,expect",
        [
            ("https://kea-a:8000", "http://kea-a:53001", True),
            (
                "https://KEA-A.:8000/x",
                "https://kea-a",
                False,
            ),  # (Q184, Z3: `a.` is the absolute name, `a` is search-relative - two names)
            ("https://KEA-A.:8000/x", "https://kea-a.", True),
            ("https://kea-a:8000", "https://kea-b:8000", False),
            ("db-a", "DB-A", True),
            ("db-a", "db-b", False),
            ("", "", False),
            ("https://kea-a:8000", "", False),
            ("::1", "[::1]:53", True),
        ],
    )
    def test_the_rule(self, a, b, expect):
        from jen.services.auth import same_host

        assert same_host(a, b) is expect


class TestAUrlTheTwoParsersReadDifferentlyNamesNoPlace:
    """Second pass (Q183) finding 6: `urlsplit` reads `http://127.0.0.1:9\\@a:8000/` as host `a`, `requests` (urllib3) as `127.0.0.1`, so the primary's credential was inherited by (and sent to) a
    host that `same_host` called the primary's. A place the two disagree about is no place."""

    BAD = [
        "http://127.0.0.1:9\\@a:8000/",
        "http://a:8000\\.evil.example/",
        "http://a:8000/ x",
        "http://a:8000/\nx",
        "http://a:8000/\tx",
        "http://a\x00:8000/",
    ]

    @pytest.mark.parametrize("url", BAD)
    def test_it_is_not_a_place_and_not_the_same_host_as_anything(self, url):
        assert auth._endpoint_parts(url) is None
        assert auth.same_host("https://a:8000", url) is False and auth.same_host(url, url) is False

    @pytest.mark.parametrize("url", BAD)
    def test_it_is_not_a_valid_api_url(self, url):
        assert auth.valid_api_url(url) is False and auth.valid_api_url(url, require_port=True) is False

    def test_a_trailing_no_break_space_is_refused_and_ordinary_padding_is_not(self):
        """AA3 (Q185): the odd-character check runs BEFORE any strip, and the strip is ASCII padding only - a trailing NBSP is part of the value, as the page says."""
        assert auth.valid_api_url("http://a:8000\u00a0") is False and auth.valid_api_url("http://a:8000\u200b") is False
        assert auth.valid_api_url("http://a:8000 \n") is True and auth.valid_api_url("\thttp://a:8000") is True
        assert auth._endpoint_parts("https://a:8000\u00a0") is None
        assert auth.same_host(" https://a:8000\n", "https://a:8001") is True

    def test_an_ordinary_url_is_unchanged(self):
        assert auth.same_host("https://a:8000", "http://a:8006/x?y=1") is True
        assert auth.valid_api_url("http://kea-a.lan:8000") is True

    def test_the_resolver_withholds_the_primarys_password_from_it(self):
        import configparser

        from jen.services import credentials as cred

        p = configparser.ConfigParser(interpolation=None)
        p.read_string(
            "[kea]\napi_url = https://a:8000\napi_pass = PS\n[kea6]\napi_url = http://127.0.0.1:9\\@a:8000/\n"
        )
        e = cred.resolve(p)["kea6"]
        assert (e.password, e.withheld) == ("", "kea")
