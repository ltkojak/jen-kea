"""
tests/test_credential_transport.py
──────────────────────────────────
v5.69.0-beta.12 (Q181, V5; CRED-004) - what `credentials.resolve` says is what the transport sends.

Beta.11 made `resolve` the definition of the PASSWORD and left `kea._endpoint_for` deriving the url and the username by its own fallbacks, so the resolver and the transport could
disagree about where a password goes. This is the registry's "exact agreement" line: for EVERY endpoint `resolve(cfg)` names, `kea_command` with `requests.post` mocked is seen
posting to exactly `Endpoint.url` with exactly `(Endpoint.user, Endpoint.password)` (no Authorization header when both are blank) - or, for an endpoint that has no address or whose
password was refused (`withheld`), NOT posting at all and answering with a sentence. The matrix is the three readings of every field (a value, a present-blank key, an absent key)
x the primary and an additional server x CA and direct mode x the same host and a different one.

Pure: `py -m pytest --noconftest tests/test_credential_transport.py`.
"""

import configparser
import itertools

import pytest

from jen import extensions
from jen.config import AppConfig
from jen.services import credentials as cred
from jen.services import kea

PRIMARY = "https://a:8000"


@pytest.fixture(autouse=True)
def _put_the_globals_back():
    snapshot = dict(vars(extensions))
    yield
    for key, value in snapshot.items():
        setattr(extensions, key, value)


class _Post:
    """A `requests` stand-in that records every request and answers a plain success."""

    exceptions = kea.http.exceptions

    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs.get("auth")))

        class _Reply:
            def raise_for_status(self):
                pass

            def json(self):
                return [{"result": 0}]

        return _Reply()


def _config(mode, section_lines, server_lines):
    text = (
        f"[kea]\nconnection_mode = {mode}\napi_url = {PRIMARY}\napi_user = pu\napi_pass = PS\n"
        "[kea_db]\nhost = db1\nuser = k\npassword = KDB\n"
        "[jen_db]\nhost = jh\nuser = j\npassword = JP\n[server]\n"
        f"{section_lines}\n[kea_server_2]\napi_url = https://b:8000\napi_user = su\napi_pass = SS\n{server_lines}\n"
    )
    p = configparser.ConfigParser(interpolation=None)
    p.read_string(text)
    return p


# the three readings of one field: (label, the line, or "" for an absent key)
def _readings(key, own_same, own_other):
    return [
        ("absent", ""),
        ("blank", f"{key} ="),
        ("own-same-host", f"{key} = {own_same}"),
        ("own-other-host", f"{key} = {own_other}"),
    ]


def _cases():
    cases = []
    for mode in ("ca", "direct"):
        for (url_label, url_k6), (pw_label, pw_k6), (user_label, user_k6) in itertools.product(
            _readings("api_url", "https://a:8006", "https://z:8006"),
            [("absent", ""), ("blank", "api_pass ="), ("own", "api_pass = OWN")],
            [("absent", ""), ("blank", "api_user ="), ("own", "api_user = ou")],
        ):
            kea6 = "[kea6]\n" + "\n".join(x for x in (url_k6, pw_k6, user_k6) if x)
            # the same readings for the additional server's IPv6 endpoint (its own host is b)
            url_s = {
                "absent": "",
                "blank": "api6_url =",
                "own-same-host": "api6_url = https://b:8006",
                "own-other-host": "api6_url = https://y:8006",
            }[url_label]
            pw_s = {"absent": "", "blank": "api6_pass =", "own": "api6_pass = OWN6"}[pw_label]
            user_s = {"absent": "", "blank": "api6_user =", "own": "api6_user = ou6"}[user_label]
            server = "\n".join(x for x in (url_s, pw_s, user_s) if x)
            cases.append(
                pytest.param(mode, kea6, server, id=f"{mode}-url:{url_label}-pass:{pw_label}-user:{user_label}")
            )
    return cases


def _calls_for(name, servers):
    """(server dict, service) that reaches the endpoint `name`."""
    primary = servers[0]
    if name == "kea":
        return primary, "dhcp4"
    if name == "kea6":
        return primary, "dhcp6"
    if name == "d2":
        return primary, "d2"
    number, _, suffix = name.removeprefix("server_").partition("_")
    server = next(s for s in servers if s["id"] == int(number))
    return server, {"": "dhcp4", "v6": "dhcp6", "d2": "d2"}[suffix]


def _expect(endpoint, service, direct):
    """What the transport must do for this endpoint: (posts?, url, auth)."""
    if service in ("dhcp6", "d2") and not endpoint.url:
        return False, "", None
    if endpoint.withheld:
        return False, "", None
    auth = (endpoint.user, endpoint.password) if (endpoint.user or endpoint.password) else None
    return True, endpoint.url, auth


@pytest.mark.parametrize(("mode", "kea6", "server"), _cases())
def test_the_transport_posts_exactly_what_resolve_says(mode, kea6, server, monkeypatch):
    cfg = _config(mode, kea6 + "\n[d2]\napi_url = https://a:53001", server)
    resolved = cred.resolve(cfg)
    servers = AppConfig.derive_kea_servers(cfg, quiet=True)
    fake = _Post()
    monkeypatch.setattr(kea, "http", fake)
    AppConfig().apply(_with_required(cfg))  # the KEA6_* and D2_* globals, the primary's own sockets
    for name, endpoint in resolved.items():
        if name.endswith("_db") or name == "jen_db" or name in ("kea6_db",):
            continue
        server_dict, service = _calls_for(name, servers)
        posts, url, auth = _expect(endpoint, service, mode == "direct")
        for via in ("dict", "globals"):
            if via == "globals" and name not in ("kea", "kea6", "d2"):
                continue
            fake.calls.clear()
            reply = kea.kea_command("version-get", service, server=server_dict if via == "dict" else None)
            if posts:
                assert fake.calls == [(url, auth)], (
                    f"{mode} {name} via {via}: resolve says {endpoint}, the transport sent {fake.calls}"
                )
            else:
                assert fake.calls == [], (
                    f"{mode} {name} via {via}: nothing may be sent for {endpoint}, the transport sent {fake.calls}"
                )
                assert reply["result"] == 1 and "text" in reply


def _with_required(cfg):
    for section in ("jen_db", "server"):
        if not cfg.has_section(section):
            cfg.add_section(section)
    return cfg


class TestTheRowsTheReviewNamed:
    """The shapes ChatGPT's review of beta.11 named, as direct assertions beside the matrix."""

    def _send(self, text, name, monkeypatch):
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string(text)
        servers = AppConfig.derive_kea_servers(cfg, quiet=True)
        fake = _Post()
        monkeypatch.setattr(kea, "http", fake)
        monkeypatch.setattr(
            extensions, "KEA_CONNECTION_MODE", cred.resolve(cfg)["kea"].url and ("direct" if "direct" in text else "ca")
        )
        server, service = _calls_for(name, servers)
        reply = kea.kea_command("version-get", service, server=server)
        return fake.calls, reply

    def test_a_present_blank_ipv6_url_is_no_endpoint_and_never_the_v4_url(self, monkeypatch):
        calls, reply = self._send(
            f"[kea]\napi_url = {PRIMARY}\napi_pass = PS\n[kea_server_2]\napi_url = https://b:8000\napi_pass = SS\napi6_url =\napi6_pass = SS\n",
            "server_2_v6",
            monkeypatch,
        )
        assert calls == [] and reply["result"] == 1, (
            "the review's P1: the transport used to fall back to the v4 url and send the v6 password there"
        )

    def test_a_blank_username_is_not_replaced_by_the_primarys(self, monkeypatch):
        calls, _reply = self._send(
            f"[kea]\napi_url = {PRIMARY}\napi_user = pu\napi_pass = PS\n[kea6]\napi_url = https://a:8006\napi_user =\n",
            "kea6",
            monkeypatch,
        )
        assert calls == [("https://a:8006", ("", "PS"))], (
            "present-blank user is explicit: no user (the password is still the same host's)"
        )

    def test_an_absent_username_on_another_host_is_none_not_the_primarys(self, monkeypatch):
        calls, _reply = self._send(
            f"[kea]\napi_url = {PRIMARY}\napi_user = pu\napi_pass = PS\n[kea6]\napi_url = https://z:8006\napi_pass = OWN\n",
            "kea6",
            monkeypatch,
        )
        assert calls == [("https://z:8006", ("", "OWN"))]
