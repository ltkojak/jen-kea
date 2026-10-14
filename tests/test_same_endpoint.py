"""
tests/test_same_endpoint.py
───────────────────────────
v5.69.0-beta.9 (Q178, CRED-002) - `auth.same_endpoint`: do two URLs (or bare host[:port] strings) name the same place a secret would be sent to. Scheme, host and port - never
the path or the query. A blank on either side is a different place. Pure: `pytest --noconftest tests/test_same_endpoint.py`.
"""

import pytest

from jen.services.auth import same_endpoint


class TestSameEndpoint:
    @pytest.mark.parametrize(
        "a,b,expect",
        [
            ("https://a.example/api", "https://A.example./api", True),
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
            ("https://KEA-A.:8000/x", "https://kea-a", True),
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
