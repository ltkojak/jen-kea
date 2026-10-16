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


def _own_user(cfg, name):
    """Does the endpoint's section carry a user of its own, with a value?"""
    section, option = cred.user_key(name)
    return cfg.has_option(section, option) and cfg.get(section, option, raw=True) != ""


def _expect(endpoint, service, direct, cfg):
    """What the transport must do for this endpoint: (posts?, url, auth).

    Q182 (X2): a header is sent iff the resolved password is non-blank OR the resolved user is an OWN value. A user that is only the parent's, beside a blank password, is not a
    credential the endpoint asked to send - "no authentication" is no header."""
    if service in ("dhcp6", "d2") and not endpoint.url:
        return False, "", None
    if endpoint.withheld:
        return False, "", None
    header = bool(endpoint.password) or (bool(endpoint.user) and _own_user(cfg, endpoint.name))
    return True, endpoint.url, ((endpoint.user, endpoint.password) if header else kea._NO_AUTH)


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
        posts, url, auth = _expect(endpoint, service, mode == "direct", cfg)
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


class TestNoAuthenticationOnTheSameHostSendsNoHeader:
    """Q182 (X2, subagent S1): Kea6, D2, a server's IPv6 endpoint and the wizard's same-box "no authentication" all said `api_pass =` and sent `(primary's user, "")` - an empty Basic
    header carrying a name the endpoint never chose."""

    PRIMARY_BLOCK = (
        f"[kea]\napi_url = {PRIMARY}\napi_user = pu\napi_pass = PS\n"
        "[kea_db]\nhost = db1\nuser = k\npassword = KDB\n[jen_db]\nhost = jh\nuser = j\npassword = JP\n[server]\n"
    )

    def _send(self, text, name, monkeypatch):
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_string(text)
        servers = AppConfig.derive_kea_servers(cfg, quiet=True)
        fake = _Post()
        monkeypatch.setattr(kea, "http", fake)
        AppConfig().apply(_with_required(cfg))
        server, service = _calls_for(name, servers)
        kea.kea_command("version-get", service, server=server)
        kea.kea_command("version-get", service, server=None) if name in ("kea6", "d2") else None
        return fake.calls

    @pytest.mark.parametrize(
        ("name", "block"),
        [
            ("kea6", "[kea6]\napi_url = https://a:8006\napi_pass =\n"),
            ("d2", "[d2]\napi_url = https://a:53001\napi_pass =\n"),
            (
                "server_2_v6",
                "[kea_server_2]\napi_url = https://b:8000\napi_user = su\napi_pass = SS\napi6_url = https://b:8006\napi6_pass =\n",
            ),
            # the shape the wizard writes for "this DHCPv6 control socket has no authentication" on the primary's own box (no user key at all)
            ("kea6", "[kea6]\napi_url = http://a:8006\napi_pass =\n"),
        ],
    )
    def test_the_request_carries_no_authorization_header(self, name, block, monkeypatch):
        calls = self._send(self.PRIMARY_BLOCK + block, name, monkeypatch)
        assert calls and all(auth is kea._NO_AUTH for _url, auth in calls), calls

    def test_the_same_with_a_user_of_its_own_still_sends_it(self, monkeypatch):
        calls = self._send(
            self.PRIMARY_BLOCK + "[kea6]\napi_url = https://a:8006\napi_user = six\napi_pass =\n", "kea6", monkeypatch
        )
        assert calls and all(auth == ("six", "") for _url, auth in calls)

    def test_the_wizard_saves_no_user_and_a_blank_password_and_probes_with_no_header(self, monkeypatch):
        """`enable_v6(no_auth=True)` on a file that has a stale `[kea6] api_user`: the saved section has `api_pass =` and NO user key, and what it resolves to sends no header."""
        from jen.services import setup_wizard

        written = {}

        class _Config:
            def mutate(self, fn, typed=None, **_k):
                p = configparser.ConfigParser(interpolation=None)
                p.read_string(
                    TestNoAuthenticationOnTheSameHostSendsNoHeader.PRIMARY_BLOCK + "[kea6]\napi_user = stale\n"
                )
                fn(p)
                written["parser"] = p

        monkeypatch.setattr("jen.config.app_config", _Config())
        monkeypatch.setattr("jen.models.user.set_global_setting", lambda *a, **k: None)
        assert setup_wizard.enable_v6("http://a:8006", {}, no_auth=True) is None
        p = written["parser"]
        assert (
            p.has_option("kea6", "api_pass")
            and p.get("kea6", "api_pass") == ""
            and not p.has_option("kea6", "api_user")
        )
        e = cred.resolve(p)["kea6"]
        assert (e.user, e.password, e.withheld) == ("", "", "")


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

    def test_an_absent_username_beside_an_own_password_on_another_host_is_the_primarys(self, monkeypatch):
        """The second pass (P2-1): Jen's own forms leave the user blank when a password is typed for a daemon on another host; the account name is the primary's unless said otherwise."""
        calls, _reply = self._send(
            f"[kea]\napi_url = {PRIMARY}\napi_user = pu\napi_pass = PS\n[kea6]\napi_url = https://z:8006\napi_pass = OWN\n",
            "kea6",
            monkeypatch,
        )
        assert calls == [("https://z:8006", ("pu", "OWN"))]

    def test_an_absent_username_and_no_password_on_another_host_sends_nothing(self, monkeypatch):
        calls, reply = self._send(
            f"[kea]\napi_url = {PRIMARY}\napi_user = pu\napi_pass = PS\n[kea6]\napi_url = https://z:8006\n",
            "kea6",
            monkeypatch,
        )
        assert calls == [] and reply["result"] == 1

    def test_an_endpoint_with_no_authentication_sends_no_authorization_header_and_never_looks_in_netrc(
        self, monkeypatch
    ):
        """An explicit blank user and password: a no-op auth callable, not `None` (which would let `requests` read ~/.netrc and send what it finds)."""
        calls, _reply = self._send(
            f"[kea]\napi_url = {PRIMARY}\napi_user = pu\napi_pass = PS\n[kea6]\napi_url = https://z:8006\napi_user =\napi_pass =\n",
            "kea6",
            monkeypatch,
        )
        assert calls == [("https://z:8006", kea._NO_AUTH)]
        request = type("R", (), {"headers": {}})()
        assert kea._NO_AUTH(request) is request and request.headers == {}
