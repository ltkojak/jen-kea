"""Q229: the ONE Q of the independent review of v7.0.0-beta.14 (five findings) and of Opus's pass on the same tag (AO1-AO40).

Both reviews found the same thing from two sides: a secret, or a rule about one, that stopped at the line where it was written.

review #1        an alert is posted to the address that was saved: a redirect is not followed, so a webhook's header and the alert's body go nowhere else.
review #2        an SMTP channel's STARTTLS verifies the server's certificate and name before `login` sends the password.
review #3        a webhook's path is compared as written: `/team-a` and `/team-a/` are two paths.
review #4        an SMTP password is the password of its user name: another user name on the same server is asked for its own.
review #5, AO5   "can Jen dial this" is the port and the host's characters too.
AO1, AO2, AO6    the OIDC issuer is asked what every address a form takes is asked.
AO3              an SMTP host is the third address the Alerts page shows.
AO23             the certificate forms are drawn for a superadmin whatever the state of HTTPS, and for nobody else.
AO24             a file write onto a server on Live API asks about a pending change first.
AO25             a password inside a URL value is masked in a Kea config a person reads.
AO26, AO4        a restore that raised is not "still new"; a count that could not be read says so on Getting started.
AO10, AO12, AO13 the Write mode card: a stored `consents` that is not a list, the time's format, the panel the note names.

The redirect and STARTTLS cells run against REAL local servers (CLAUDE.md: probe, redirect and TLS behavior is never tested behind a mocked client).
"""

import ast
import contextlib
import http.server
import pathlib
import re
import socketserver
import ssl
import threading
import types

import jinja2
import pytest

from jen.services import alerts, auth, kea_authoring, onboarding
from jen.services import kea_api_config as api

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _function(rel: str, name: str) -> str:
    src = (ROOT / rel).read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(src, fn)


def _route():
    from jen.routes.settings import alerts as route

    return route


# ── review #1: no redirect is followed ───────────────────────────────────────────────────────────────────────────────────


class _Receiver(http.server.BaseHTTPRequestHandler):
    """Answers every POST with the server's `answer` (a status, and a Location for a redirect) and records what it was sent."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.server.seen.append((self.path, dict(self.headers.items()), self.rfile.read(length)))
        status, location = self.server.answer
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def _receiver(answer=(200, "")):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    server.seen, server.answer = [], answer
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def _url(server, path="/in"):
    return f"http://127.0.0.1:{server.server_address[1]}{path}"


WEBHOOK = {"payload_type": "json", "header_name": "X-Jen-Secret", "header_value": "SYNTHETIC-HEADER-VALUE"}


class TestARedirectIsNotFollowed:
    """`requests` follows a redirect and takes every header along except `Authorization`; on a 307 or a 308 it re-sends the body too. The production sender, two real servers."""

    def test_the_control_a_plain_answer_is_delivered_with_its_header(self):
        with _receiver() as first:
            assert alerts._send_webhook_channel("hello", "kea_down", {**WEBHOOK, "webhook_url": _url(first)}) is True
            ((path, headers, body),) = first.seen
        assert path == "/in" and headers["X-Jen-Secret"] == "SYNTHETIC-HEADER-VALUE" and b"hello" in body

    @pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
    def test_another_server_is_never_sent_the_header_or_the_alert(self, code):
        with _receiver() as second, _receiver((code, "")) as first:
            first.answer = (code, _url(second, "/landing"))
            with pytest.raises(Exception) as caught:
                alerts._send_webhook_channel("hello", "kea_down", {**WEBHOOK, "webhook_url": _url(first)})
            assert len(first.seen) == 1 and second.seen == [], "the redirect's target was contacted"
        assert str(caught.value) == alerts.REDIRECT_REFUSED.format(code=code)

    def test_another_path_of_the_same_server_is_not_followed_either(self):
        with _receiver((307, "/another-receiver")) as first:
            with pytest.raises(Exception, match="redirect"):
                alerts._send_webhook_channel("hello", "kea_down", {**WEBHOOK, "webhook_url": _url(first)})
            assert [path for path, _h, _b in first.seen] == ["/in"]

    @pytest.mark.parametrize("location", ["", "http://[::1", "//", "/in"])
    def test_a_redirect_with_no_usable_location_and_a_loop_are_one_refusal(self, location):
        with _receiver((302, location)) as first:
            # (a Location `requests` cannot read raises its own error before the status is looked at: a failed send either way, and nothing is dialed twice)
            with pytest.raises(Exception, match="redirect|Invalid"):
                alerts._send_webhook_channel("hello", "kea_down", {**WEBHOOK, "webhook_url": _url(first)})
            assert len(first.seen) == 1

    @pytest.mark.parametrize(
        "send, config",
        [
            (lambda c: alerts._send_slack_channel("hello", c), lambda u: {"webhook_url": u}),
            (lambda c: alerts._send_discord_channel("hello", c), lambda u: {"webhook_url": u}),
            (
                lambda c: alerts._send_ntfy_channel("hello", c),
                lambda u: {"url": u, "topic": "jen", "token": "SYNTHETIC-NTFY-TOKEN"},
            ),
        ],
        ids=["slack", "discord", "ntfy"],
    )
    def test_every_sender_that_dials_a_saved_address(self, send, config):
        with _receiver() as second, _receiver() as first:
            first.answer = (307, _url(second, "/landing"))
            with pytest.raises(Exception, match="redirect"):
                send(config(_url(first, "/base")))
            assert len(first.seen) == 1 and second.seen == []

    def test_what_is_stored_and_shown_names_no_address_and_no_secret(self):
        with _receiver() as second, _receiver() as first:
            first.answer = (307, _url(second, "/landing"))
            config = {**WEBHOOK, "webhook_url": _url(first, "/in?token=SYNTHETIC-QUERY-TOKEN")}
            with pytest.raises(Exception) as caught:
                alerts._send_webhook_channel("hello", "kea_down", config)
        text = alerts._transport_error_text(caught.value, config)
        assert text == alerts.REDIRECT_REFUSED.format(code=307)
        assert "127.0.0.1" not in text and "SYNTHETIC" not in text and "landing" not in text

    def test_every_post_of_the_module_goes_through_the_one_function(self):
        # the whole module: a sender added later that calls `requests` itself fails here
        src = (ROOT / "jen/services/alerts.py").read_text(encoding="utf-8")
        calls = re.findall(r"\brequests\.(?:post|get|put|patch|delete|request|Session)\(", src)
        assert calls == ["requests.post("], calls
        assert "resp = requests.post(url, allow_redirects=False, timeout=timeout, **kwargs)" in _function(
            "jen/services/alerts.py", "_post"
        )  # (Q230, AP24) the timeout is named in the one call
        assert src.count("_post(") == 7  # the definition and the six senders


# ── review #2: STARTTLS verifies ─────────────────────────────────────────────────────────────────────────────────────────


class _Smtp(socketserver.BaseRequestHandler):
    """A real SMTP conversation with STARTTLS, over the certificate the server was given. Every verb it is sent is recorded, so a test can say `AUTH` never arrived."""

    def handle(self):
        conn, seen = self.request, self.server.seen
        stream = conn.makefile("rwb", buffering=0)

        def say(line):
            stream.write(line.encode("ascii") + b"\r\n")

        try:
            say("220 localhost ESMTP")
            tls = False
            while True:
                raw = stream.readline()
                if not raw:
                    return
                verb = raw.decode("utf-8", "replace").strip().split(" ")[0].upper()
                seen.append(verb)
                if verb in ("EHLO", "HELO"):
                    say("250-localhost")
                    if not tls:
                        say("250-STARTTLS")
                    say("250 AUTH PLAIN")
                elif verb == "STARTTLS":
                    say("220 ready")
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(self.server.cert, self.server.key)
                    conn = context.wrap_socket(conn, server_side=True)
                    stream, tls = conn.makefile("rwb", buffering=0), True
                elif verb == "AUTH":
                    say("235 ok")
                elif verb == "DATA":
                    say("354 go on")
                    while stream.readline() not in (b".\r\n", b""):
                        pass
                    seen.append("DELIVERED")
                    say("250 queued")
                elif verb == "QUIT":
                    say("221 bye")
                    return
                else:
                    say("250 ok")
        except (OSError, ssl.SSLError):
            seen.append("HANDSHAKE-ENDED")


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A CA and a server pair it issued for the NAME `localhost` (no address in it), as files."""
    from cryptography import x509

    from jen.services import kea_tls
    from tests import _tls_worlds as tls

    root = tmp_path_factory.mktemp("q229-pki")
    ca = tls.other_ca()
    cert, key = tls.issued_pair(ca, client=False, cn="localhost", sans=[x509.DNSName("localhost")])
    (root / "ca.pem").write_bytes(kea_tls._cert_pem(ca[0]))
    (root / "server.pem").write_bytes(cert)
    (root / "server.key").write_bytes(key)
    return root


@pytest.fixture
def smtp(pki):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Smtp)
    server.daemon_threads = True
    server.seen, server.cert, server.key = [], str(pki / "server.pem"), str(pki / "server.key")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(5)


def _email(server, host="localhost", **over):
    return {
        "smtp_host": host,
        "smtp_port": str(server.server_address[1]),
        "smtp_user": "jen@example.test",
        "smtp_pass": "SYNTHETIC-SMTP-PASSWORD",
        "from_addr": "jen@example.test",
        "to_addr": "ops@example.test",
        "use_tls": "true",
        **over,
    }


class TestStartTlsVerifiesBeforeThePasswordIsSent:
    """`smtplib.SMTP.starttls()` with no context verifies nothing, so `login` sent the password to whatever answered. A real server, a real handshake."""

    def test_a_certificate_nothing_vouches_for_is_refused_and_the_password_is_never_sent(self, smtp):
        with pytest.raises(ssl.SSLCertVerificationError):
            alerts._send_email_channel("hello", "kea_down", _email(smtp))
        assert "AUTH" not in smtp.seen and "DELIVERED" not in smtp.seen, smtp.seen
        assert "STARTTLS" in smtp.seen

    def test_a_certificate_the_trust_store_vouches_for_delivers(self, smtp, pki, monkeypatch):
        monkeypatch.setenv("SSL_CERT_FILE", str(pki / "ca.pem"))
        assert alerts._send_email_channel("hello", "kea_down", _email(smtp)) is True
        assert smtp.seen.index("STARTTLS") < smtp.seen.index("AUTH") < smtp.seen.index("DELIVERED")

    def test_a_trusted_certificate_for_another_name_is_refused(self, smtp, pki, monkeypatch):
        # the certificate is for `localhost`; the channel dials the same server by its address
        monkeypatch.setenv("SSL_CERT_FILE", str(pki / "ca.pem"))
        with pytest.raises(ssl.SSLCertVerificationError):
            alerts._send_email_channel("hello", "kea_down", _email(smtp, host="127.0.0.1"))
        assert "AUTH" not in smtp.seen and "DELIVERED" not in smtp.seen, smtp.seen

    def test_the_operators_own_choice_not_to_verify_still_encrypts_and_delivers(self, smtp):
        assert alerts._send_email_channel("hello", "kea_down", _email(smtp, tls_verify="false")) is True
        assert smtp.seen.index("STARTTLS") < smtp.seen.index("AUTH") < smtp.seen.index("DELIVERED")

    def test_what_is_stored_for_the_refusal_is_its_class(self, smtp):
        with pytest.raises(ssl.SSLCertVerificationError) as caught:
            alerts._send_email_channel("hello", "kea_down", _email(smtp))
        assert alerts._transport_error_text(caught.value, _email(smtp)) == "SSLCertVerificationError"

    @pytest.mark.parametrize(
        "config, verifies",
        [({}, True), ({"tls_verify": "true"}, True), ({"tls_verify": "false"}, False), ({"tls_verify": ""}, True)],
    )
    def test_the_context_a_row_gets(self, config, verifies):
        # a row an earlier release stored has no `tls_verify`: it is verified
        context = alerts._smtp_tls_context(config)
        assert context.check_hostname is verifies
        assert (context.verify_mode == ssl.CERT_REQUIRED) is verifies

    def test_the_sender_passes_the_context_and_nothing_else_calls_starttls(self):
        src = (ROOT / "jen/services/alerts.py").read_text(encoding="utf-8")
        assert src.count("server.starttls(") == 1 and "server.starttls(context=_smtp_tls_context(config))" in src

    def test_the_form_carries_the_choice_and_the_page_may_show_it(self):
        route = _route()
        assert "tls_verify" in route.SHOWN_KEYS["email"]
        html = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        assert '<input type="checkbox" name="tls_verify" id="f-tls_verify" checked' in html
        assert "verifyEl.checked = cfg.tls_verify !== 'false'" in html and "verifyEl.checked = true" in html
        assert '"tls_verify": ("true" if request.form.get("tls_verify") else "false")' in _function(
            "jen/routes/settings/alerts.py", "save_alert_channel"
        )


# ── reviews #3 and #4, and the wire: what a kept secret stays with ───────────────────────────────────────────────────────


def _kept(monkeypatch, channel_type, new, old):
    route = _route()
    monkeypatch.setattr("jen.services.alerts.get_channel_config", lambda row: dict(old))
    return route._kept_secrets(4, channel_type, dict(new), {"id": 4, "channel_type": channel_type, "config": "x"})


SMTP_OLD = {
    "smtp_host": "mail.example.test",
    "smtp_port": "587",
    "smtp_user": "user-a@example.test",
    "smtp_pass": "SYNTHETIC-PASSWORD-A",
    "use_tls": "true",
}


class TestAKeptSecretStaysWithWhatItWasTypedFor:
    @pytest.mark.parametrize("typed", ["https://hooks.example.test/team-a/", "https://hooks.example.test/team-a////"])
    def test_a_webhooks_trailing_slash_is_another_path(self, monkeypatch, typed):
        old = {"webhook_url": "https://hooks.example.test/team-a", "header_value": "SYNTHETIC-OLD"}
        assert _kept(monkeypatch, "webhook", {"webhook_url": typed, "header_value": ""}, old) == (
            "header_value",
            _route().DESTINATION_CHANGED,
        )

    def test_the_same_webhook_address_keeps_it_and_a_typed_value_is_taken(self, monkeypatch):
        old = {"webhook_url": "https://hooks.example.test/team-a", "header_value": "SYNTHETIC-OLD"}
        assert _kept(monkeypatch, "webhook", {**old, "header_value": ""}, old)["header_value"] == "SYNTHETIC-OLD"
        moved = {"webhook_url": "https://hooks.example.test/team-a/", "header_value": "SYNTHETIC-NEW"}
        assert _kept(monkeypatch, "webhook", moved, old)["header_value"] == "SYNTHETIC-NEW"

    @pytest.mark.parametrize(
        "a, b, same",
        [
            ("https://h.example.test", "https://h.example.test/", True),  # every HTTP client sends `/` for both
            ("https://h.example.test/a", "https://h.example.test/a/", False),
            ("https://h.example.test/a/", "https://h.example.test/a//", False),
            ("https://h.example.test/a?x=1", "https://h.example.test/a/?x=1", False),
        ],
    )
    def test_a_path_is_compared_as_written(self, a, b, same):
        assert auth.same_destination(a, b) is same and auth.same_destination(b, a) is same

    def test_an_ntfy_address_is_compared_as_its_sender_dials_it(self, monkeypatch):
        # the sender drops the trailing slash before it appends the topic, so the two spellings are one address and the token is kept
        # (Q230, AP2) the dropping is in `alerts.ntfy_target`, the one function the sender and the comparison both ask
        old = {"url": "https://ntfy.example.test/base", "topic": "jen", "token": "SYNTHETIC-TOKEN"}
        new = {"url": "https://ntfy.example.test/base/", "topic": "jen", "token": ""}
        assert _kept(monkeypatch, "ntfy", new, old)["token"] == "SYNTHETIC-TOKEN"
        sender = _function("jen/services/alerts.py", "_send_ntfy_channel")
        assert (
            "target = ntfy_target(config)" in sender and "_post(target," in sender
        )  # (Q234, AQ2) and "" is not posted to
        assert 'parts.path.rstrip("/") + "/" + topic' in _function("jen/services/alerts.py", "ntfy_target")
        other = {"url": "https://ntfy.example.test/second", "topic": "jen", "token": ""}
        assert _kept(monkeypatch, "ntfy", other, old) == ("ntfy_token", _route().DESTINATION_CHANGED)

    def test_an_issuer_is_compared_as_init_oidc_dials_it(self):
        assert auth.same_issuer("https://idp.example.test/realms/jen/", "https://idp.example.test/realms/jen")
        assert not auth.same_issuer("https://idp.example.test/realms/jen", "https://idp.example.test/realms/two")
        assert not auth.same_issuer("https://idp.example.test/realms/jen", "")
        assert not auth.same_issuer("", "") and not auth.same_issuer(None, None)

    def test_another_smtp_user_name_is_asked_for_its_own_password(self, monkeypatch):
        new = {**SMTP_OLD, "smtp_user": "user-b@example.test", "smtp_pass": ""}
        assert _kept(monkeypatch, "email", new, SMTP_OLD) == ("smtp_pass", _route().SMTP_USER_CHANGED)

    def test_the_same_user_name_keeps_it_and_a_typed_password_is_taken(self, monkeypatch):
        assert (
            _kept(monkeypatch, "email", {**SMTP_OLD, "smtp_pass": ""}, SMTP_OLD)["smtp_pass"] == "SYNTHETIC-PASSWORD-A"
        )
        new = {**SMTP_OLD, "smtp_user": "user-b@example.test", "smtp_pass": "SYNTHETIC-PASSWORD-B"}
        kept = _kept(monkeypatch, "email", new, SMTP_OLD)
        assert (kept["smtp_user"], kept["smtp_pass"]) == ("user-b@example.test", "SYNTHETIC-PASSWORD-B")

    def test_a_relay_with_no_password_changes_its_user_name_freely(self, monkeypatch):
        old = {**SMTP_OLD, "smtp_pass": ""}
        new = {**old, "smtp_user": "user-b@example.test"}
        assert _kept(monkeypatch, "email", new, old)["smtp_user"] == "user-b@example.test"

    def test_turning_verification_off_is_a_changed_wire(self, monkeypatch):
        new = {**SMTP_OLD, "smtp_pass": "", "tls_verify": "false"}
        assert _kept(monkeypatch, "email", new, SMTP_OLD) == ("smtp_pass", _route().DESTINATION_CHANGED)
        # a row with no value and a row that says "true" are one wire
        assert _kept(monkeypatch, "email", {**SMTP_OLD, "smtp_pass": "", "tls_verify": "true"}, SMTP_OLD)["smtp_pass"]

    def test_the_three_wires(self):
        route = _route()
        base = {"smtp_host": "h", "smtp_port": "587"}
        assert route._endpoint("email", {**base, "use_tls": "true"}) == "smtps://h:587"
        assert (
            route._endpoint("email", {**base, "use_tls": "true", "tls_verify": "false"}) == "smtps-unverified://h:587"
        )
        assert route._endpoint("email", {**base, "use_tls": "false", "tls_verify": "true"}) == "smtp://h:587"


# ── review #5, AO5, AO9: can Jen dial this ───────────────────────────────────────────────────────────────────────────────


GOOD_ADDRESSES = [
    "https://hooks.example.test/in",
    "http://hooks.example.test:8080/in?x=1",
    "https://10.0.0.5:8443/in",
    "https://[fd00::5]:8443/in",
    "https://xn--bcher-kva.example/in",
    "https://hooks_internal.example.test/in",
]
BAD_ADDRESSES = [
    "https://hooks.example.test:notaport/team",
    "https://ntfy.example.test:99999/base",
    "https://hooks.example.test:0/in",
    "https://hooks.example.test:-1/in",
    "https://[fd00::5/in",
    "https://hooks.example.test\\@127.0.0.1/in",
    "https://ｈooks.example.test/in",  # a fullwidth letter
    "https://hooks。example.test/in",  # an ideographic full stop
    "https://hooks.example.test/in​",  # a zero-width space
    "https://hooks.example.test/ in",  # a no-break space
    "ftp://hooks.example.test/in",
    "hooks.example.test/in",
    "https:///in",
    "",
    None,
]


class TestAnAddressJenCanDial:
    @pytest.mark.parametrize("value", GOOD_ADDRESSES)
    def test_what_is_an_address(self, value):
        assert auth.http_address(value) is True

    @pytest.mark.parametrize("value", BAD_ADDRESSES)
    def test_what_is_not(self, value):
        assert auth.http_address(value) is False
        assert auth.plain_address(value) is False  # so a stored one is not printed either

    @pytest.mark.parametrize("value", [a for a in BAD_ADDRESSES if a])
    @pytest.mark.parametrize(
        "channel_type, key, field", [("webhook", "webhook_url", "webhook_url"), ("ntfy", "url", "ntfy_url")]
    )
    def test_both_channel_forms_refuse_it_and_name_the_field(self, value, channel_type, key, field):
        refused = _route()._address_refusal(channel_type, {key: value})
        assert refused is not None and refused[0] == field

    def test_requests_agrees_about_every_good_one(self):
        # the other parser: an address this function accepts is one `requests` can prepare
        import requests

        for value in GOOD_ADDRESSES:
            assert requests.Request("POST", value).prepare().url

    def test_an_address_always_keeps_its_own_secret(self):
        # AO9: `same_destination(x, x)` was False for an address with a backslash, which could be saved - a channel that could never be edited again without its secret
        for value in GOOD_ADDRESSES:
            assert auth.same_destination(value, value), value
        for value in (a for a in BAD_ADDRESSES if a):
            assert not auth.http_address(value) or auth.same_destination(value, value)


# ── AO1, AO2, AO6: the issuer is an address ──────────────────────────────────────────────────────────────────────────────


class TestTheIssuerIsAskedWhatEveryAddressIs:
    @pytest.mark.parametrize(
        "value",
        [
            "https://idp.example.test/realms/jen",
            "https://idp.example.test/realms/jen/",
            "https://login.example.test:8443/tenant-a/v2.0",
            "http://127.0.0.1:8080/realms/jen",
            "http://localhost/realms/jen",
            "  https://idp.example.test/realms/jen  ",
        ],
    )
    def test_what_an_issuer_is(self, value):
        assert auth.valid_oidc_issuer(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            "http://remote.example.test\\@127.0.0.1/realms/jen",  # AO1: `urlparse` reads 127.0.0.1, `requests` dials the name before the backslash
            "http://remote.example.test\\@localhost/realms/jen",
            "https://someone:SYNTHETIC-PASSWORD@idp.example.test/realms/jen",  # AO2
            "https://someone@idp.example.test/realms/jen",
            "http://someone:SYNTHETIC-PASSWORD@127.0.0.1/realms/jen",
            "https://idp.example.test/realms/jen#x",  # AO6: the fragment swallows the discovery path
            "https://idp.example.test/realms/jen?tenant=a",
            "https://idp.example.test:notaport/realms/jen",
            "https://ｉdp.example.test/realms/jen",
            "http://idp.example.test/realms/jen",
            "http://127.0.0.1.example.test/realms/jen",
            "idp.example.test/realms/jen",
            "",
            None,
        ],
    )
    def test_what_is_not(self, value):
        assert auth.valid_oidc_issuer(value) is False

    def test_the_two_parsers_disagree_about_the_value_this_refuses(self):
        # why: the question is asked of the address `requests` will dial, not of the one `urlparse` reads
        from urllib.parse import urlparse

        import requests

        value = "http://remote.example.test\\@127.0.0.1/realms/jen"
        assert urlparse(value).hostname == "127.0.0.1"
        assert "remote.example.test" in requests.Request("GET", value).prepare().url.split("/")[2]

    def test_the_route_asks_every_issuer_it_saves_and_says_which_refusal(self):
        src = _function("jen/routes/settings/security.py", "save_oidc")
        assert "if (enabled or issuer) and not __auth.valid_oidc_issuer(issuer):" in src
        assert 'flash_field("issuer", __auth.userinfo_sentence(issuer) or OIDC_ISSUER_SHAPE)' in src
        assert src.index("valid_oidc_issuer(issuer)") < src.index("write_values(") < src.index("__user.audit(")
        from jen.routes.settings import security

        assert "no query and no fragment" in security.OIDC_ISSUER_SHAPE

    def test_the_startup_note_and_health_read_the_issuer(self):
        import configparser

        cfg = configparser.ConfigParser()
        cfg.read_dict(
            {
                "oidc": {
                    "issuer": "https://someone:SYNTHETIC-PASSWORD@idp.example.test/realms/jen",
                    "redirect_uri": "https://a:b@jen.example.test/cb",
                },
                "kea": {"api_url": "http://kea.example.test:8000"},
            }
        )
        # (Q230, AP8) and the redirect URI, the second address of the section
        assert auth.urls_with_userinfo(cfg) == [("oidc", "issuer"), ("oidc", "redirect_uri")]
        note = auth.userinfo_legacy_note("oidc", "issuer")
        assert "[oidc] issuer" in note and "SYNTHETIC" not in note and "user and password fields" not in note
        health = (ROOT / "jen/services/health.py").read_text(encoding="utf-8")
        assert 'if section == "oidc":' in health and "save the single sign-on settings again without it" in health
        cfg["oidc"]["issuer"] = "https://idp.example.test/realms/jen"
        assert auth.urls_with_userinfo(cfg) == [("oidc", "redirect_uri")]
        cfg["oidc"]["redirect_uri"] = "https://jen.example.test/cb"
        assert auth.urls_with_userinfo(cfg) == []


# ── AO3: the SMTP host is the third address ──────────────────────────────────────────────────────────────────────────────


BAD_HOSTS = [
    "someone:SYNTHETIC-PASSWORD@mail.example.test",
    "smtp://mail.example.test",
    "mail.example.test/x?token=SYNTHETIC",
    "mail.example.test#x",
    "mail example.test",
    "mail.example.test\\x",
    "ｍail.example.test",
]


class TestTheSmtpHostIsAnAddressToo:
    @pytest.mark.parametrize("value", ["mail.example.test", "MAIL.example.test", "10.0.0.25", "fd00::25", "smtp_relay"])
    def test_a_host_alone_is_saved_and_shown(self, value):
        route = _route()
        assert route._address_refusal("email", {"smtp_host": value}) is None
        assert route._shown("email", {"smtp_host": value, "smtp_pass": "x"}) == {"smtp_host": value}

    @pytest.mark.parametrize("value", BAD_HOSTS)
    def test_anything_else_is_refused_on_the_save_and_withheld_on_the_page(self, value):
        route = _route()
        assert route._address_refusal("email", {"smtp_host": value}) == ("smtp_host", route.SMTP_HOST_SHAPE)
        shown = route._shown("email", {"smtp_host": value, "smtp_port": "587"})
        assert shown == {"smtp_port": "587", "url_withheld": True}

    def test_a_blank_host_on_an_edit_is_the_stored_one(self, monkeypatch):
        old = {**SMTP_OLD, "smtp_host": "someone:SYNTHETIC-PASSWORD@mail.example.test"}
        kept = _kept(monkeypatch, "email", {**old, "smtp_host": "", "smtp_pass": ""}, old)
        assert kept["smtp_host"] == old["smtp_host"] and kept["smtp_pass"] == old["smtp_pass"]

    def test_the_form_says_a_withheld_host_is_kept(self):
        html = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        assert "hostEl.placeholder = cfg.url_withheld ? 'Saved - leave blank to keep' : 'smtp.gmail.com'" in html
        assert "hostEl.placeholder = 'smtp.gmail.com'" in html  # and a new channel's form is reset


# ── AO23: the certificate card ───────────────────────────────────────────────────────────────────────────────────────────


def _ssl_card(role, ssl_configured, cert_info):
    page = (ROOT / "templates/settings_security.html").read_text(encoding="utf-8")
    start = page.index("<!-- SSL Certificate -->")
    card = page[start : page.index("{% endblock %}", start)]
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=True)
    return env.from_string(card).render(
        icon=lambda name: "",
        csrf_token=lambda: "t",
        current_user=types.SimpleNamespace(role=role),
        ssl_configured=ssl_configured,
        cert_info=cert_info,
        https_port=8443,
        http_port=5050,
    )


CERT = {"subject": "CN=jen.example.test", "issuer": "CN=a CA", "expires": "2027-01-01"}
UPLOAD, REMOVE = 'action="/settings/upload-cert"', 'action="/settings/remove-cert"'


class TestTheCertificateCard:
    """The role test was added inside the "HTTPS is on and its certificate reads" block and took that block's endif. No test rendered this card."""

    def test_a_superadmin_on_plain_http_can_turn_https_on(self):
        html = _ssl_card("superadmin", False, None)
        assert UPLOAD in html and "Enable HTTPS" in html and "Upload certificate to enable HTTPS:" in html
        assert REMOVE not in html and "HTTP Only" in html

    def test_a_superadmin_with_https_on_can_replace_and_remove(self):
        html = _ssl_card("superadmin", True, CERT)
        assert UPLOAD in html and REMOVE in html and "Replace Certificate" in html and "CN=jen.example.test" in html

    def test_a_superadmin_whose_certificate_cannot_be_read_can_still_replace_and_remove(self):
        html = _ssl_card("superadmin", True, None)
        assert UPLOAD in html and REMOVE in html and "Replace Certificate" in html

    @pytest.mark.parametrize("role", ["admin", "viewer"])
    @pytest.mark.parametrize("ssl_configured, cert_info", [(False, None), (True, CERT), (True, None)])
    def test_nobody_else_is_offered_a_form(self, role, ssl_configured, cert_info):
        html = _ssl_card(role, ssl_configured, cert_info)
        assert "<form" not in html and "it is a superadmin's" in html
        assert ("CN=jen.example.test" in html) is bool(
            ssl_configured and cert_info
        )  # what the certificate is, is still shown

    def test_the_forms_are_the_routes_the_card_names(self):
        src = (ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8")
        assert '"/settings/upload-cert"' in src and '"/settings/remove-cert"' in src


# ── AO24: a file write asks about a pending change ───────────────────────────────────────────────────────────────────────


class TestAFileWriteAsksAboutAPendingChange:
    """The guard's digest test was behind `not in_flight`, and an `unverified` apply is what leaves the pending row: the state it exists for was the one it did not ask in."""

    SERVER = {"id": 7, "name": "kea-a", "config_transport": "api", "api_url": "http://kea.example.test:8000"}

    def _world(self, monkeypatch, pending_block="", pending=None):
        calls = []
        monkeypatch.setattr(
            api, "pending_block", lambda server, service: calls.append("pending_block") or pending_block
        )
        monkeypatch.setattr(api, "_get", lambda server, service: ({"Dhcp4": {}}, "D" * 64, ""))
        monkeypatch.setattr(api._rev, "latest_of_kind", lambda sid, service, kind: {"sha256": "E" * 64})
        monkeypatch.setattr(api._rev, "pending", lambda sid, service: pending)
        monkeypatch.setattr(api, "file_proof", lambda *a, **k: {"how": "rendering", "why": "", "sha256": "f" * 64})
        return calls

    def test_a_pending_change_refuses_the_write_with_its_own_sentence(self, monkeypatch):
        sentence = "an earlier change on kea-a is unresolved; resolve it from Config history"
        calls = self._world(monkeypatch, pending_block=sentence, pending={"id": 1})
        assert api.api_daemon_differs(self.SERVER, "dhcp4") == sentence and calls == ["pending_block"]

    def test_a_record_that_cannot_be_read_refuses_it_too(self, monkeypatch):
        self._world(monkeypatch)
        monkeypatch.undo()
        monkeypatch.setattr(api, "_get", lambda server, service: ({"Dhcp4": {}}, "D" * 64, ""))

        def unreadable(sid, service):
            raise api._rev.RevisionStoreUnreadable("the revision store could not be read")

        monkeypatch.setattr(api._rev, "pending", unreadable)
        assert api.api_daemon_differs(self.SERVER, "dhcp4") == api.unreadable_sentence(self.SERVER)

    def test_once_nothing_is_pending_the_digest_is_asked_whatever_was_pending_before(self, monkeypatch):
        # the row settled inside `pending_block` (it answered ""): the daemon's digest is compared with Jen's record, which the old `not in_flight` skipped
        self._world(monkeypatch, pending_block="", pending=None)
        assert "not the one Jen last recorded" in api.api_daemon_differs(self.SERVER, "dhcp4")

    def test_a_restore_is_the_way_out_and_is_not_stopped_by_a_pending_change(self, monkeypatch):
        calls = self._world(monkeypatch, pending_block="an earlier change is unresolved", pending={"id": 1})
        assert api.api_daemon_differs(self.SERVER, "dhcp4", restore=True) == "" and calls == []

    def test_a_server_on_another_mode_is_not_asked(self, monkeypatch):
        calls = self._world(monkeypatch, pending_block="x", pending={"id": 1})
        assert api.api_daemon_differs({**self.SERVER, "config_transport": "file"}, "dhcp4") == "" and calls == []

    def test_the_choke_point_says_which_write_is_a_restore(self):
        src = _function("jen/services/kea_host.py", "apply_config")
        assert '_api.api_daemon_differs(server, service, restore=source == "restore")' in src
        assert (
            'and source != "rollback"' in src
        )  # a rollback and investigation logging's own writes are still not asked at all


# ── AO25: a password inside a URL value ──────────────────────────────────────────────────────────────────────────────────


class TestASecretIsMaskedWhereverItSits:
    CFG = {
        "Dhcp4": {
            "lease-database": {"type": "mysql", "user": "kea", "password": "SYNTHETIC-DB-PASSWORD"},
            "hooks-libraries": [
                {
                    "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
                    "parameters": {
                        "high-availability": [
                            {
                                "peers": [
                                    {
                                        "name": "a",
                                        "url": "http://ha:SYNTHETIC-URL-PASSWORD@10.0.0.9:8000/",
                                        "role": "primary",
                                    },
                                    {"name": "b", "url": "http://10.0.0.10:8000/", "role": "standby"},
                                ]
                            }
                        ]
                    },
                }
            ],
            "option-data": [{"name": "tftp-server-name", "data": "someone@example.test"}],
            "valid-lifetime": 4000,
        }
    }

    def test_no_secret_of_either_kind_survives(self):
        out = kea_authoring.redact_secrets(self.CFG)
        assert "SYNTHETIC" not in repr(out)
        peers = out["Dhcp4"]["hooks-libraries"][0]["parameters"]["high-availability"][0]["peers"]
        assert peers[0]["url"] == "http://10.0.0.9:8000/" and peers[1]["url"] == "http://10.0.0.10:8000/"
        assert out["Dhcp4"]["lease-database"]["password"] == "********"

    def test_everything_else_is_as_it_was_and_the_input_is_untouched(self):
        out = kea_authoring.redact_secrets(self.CFG)
        assert out["Dhcp4"]["option-data"] == self.CFG["Dhcp4"]["option-data"]  # an `@` that is not in an address
        assert out["Dhcp4"]["valid-lifetime"] == 4000 and out["Dhcp4"]["lease-database"]["user"] == "kea"
        assert "SYNTHETIC-URL-PASSWORD" in repr(self.CFG)

    def test_both_sides_of_the_diff_go_through_it(self):
        src = (ROOT / "jen/routes/servers.py").read_text(encoding="utf-8")
        assert src.count("redact_secrets(") >= 2


# ── AO26, AO4 and the card ───────────────────────────────────────────────────────────────────────────────────────────────


class TestTheSmallerThings:
    def test_a_restore_that_raised_is_not_named_as_still_new(self):
        src = (ROOT / "jen/services/kea_changeset.py").read_text(encoding="utf-8")
        assert (
            "still_new_ids=[d.key for d in revert_failed if d.key not in file_unknown and d.key not in api_unknown],"
            in src
        )

    @pytest.mark.parametrize(
        "count, detail, done",
        [(None, "the channels could not be counted", False), (0, "none configured", False), (2, "2 enabled", True)],
    )
    def test_getting_started_says_when_the_channels_could_not_be_counted(self, count, detail, done):
        from tests.test_onboarding import _ctx

        summary = onboarding.checklist(_ctx(alert_channels_enabled=count))
        (row,) = [
            r
            for group in summary.values()
            if isinstance(group, list)
            for r in group
            if r.get("link") == "/settings/alerts"
        ]
        assert (row["detail"], row["done"]) == (detail, done)

    def test_the_count_that_could_not_be_read_is_none_not_zero(self):
        src = _function("jen/services/onboarding.py", "build_ctx")
        assert re.search(r"except Exception:\s+channels = None", src)

    @pytest.mark.parametrize("consents", [None, 7, "consent_rendering", {"consent_rendering": True}])
    def test_a_stored_consents_that_is_not_a_list_is_nothing_on_record(self, monkeypatch, consents):
        from tests import _write_mode_render as wm
        from tests.test_write_mode_card import _facts

        cards, _html = wm.render(monkeypatch, [wm.S_API], {2: _facts(consents=consents)})
        assert cards[0]["accepted_all"] is False

    def test_the_cards_time_is_formatted_and_its_note_names_the_panel(self):
        html = (ROOT / "templates/settings_kea.html").read_text(encoding="utf-8")
        # (Q230, AP11) `isofmt`: the stored value is ISO text, which `utcfmt` printed back unchanged
        assert "Accepted {{ c.accepted_at|isofmt }}" in html and "Accepted {{ c.accepted_at }}" not in html
        assert "(panel && panel.getAttribute('data-mode-panel')) || selected(card)" in html
        assert "remember(panel.closest('[data-wm-card]'), panel);" in html

    def test_the_comment_on_the_probe_says_the_rule_the_line_asks(self):
        src = (ROOT / "jen/routes/settings/infrastructure.py").read_text(encoding="utf-8")
        assert "CRED-002 compares scheme, host and port" not in src
