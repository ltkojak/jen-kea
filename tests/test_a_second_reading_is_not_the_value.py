"""Q230: the ONE patch Q of the two reviews of v7.0.0-beta.15 (Opus's pass AP1-AP28 and the independent review's five), shipped as 7.0.1.

The pass's finding in one sentence: a rule was asked of a SECOND READING of a value instead of the value the transport, the page or the decision uses.

AP1              a port is asked of urllib3, the parser `requests` dials with: `:+443` and a Unicode-digit port are refused.
AP7              a bare trailing `?` or `#` is asked of the text: it swallows whatever is appended to the address.
AP6, AP17, #1, #3  an SMTP host is a name or an IP address alone; an IPv6 host builds an endpoint the comparison can read.
AP2, AP21        an ntfy token is judged against the ONE address the sender builds, topic included; a topic is one path segment.
AP18             a stronger wire keeps the stored SMTP password; a weaker one is still refused.
#5               "unticked" is said only by a form that carries the box.
AP3              a restore that raised is NOT KNOWN: the certificate consumer neither drops Jen's copy nor reinstalls the previous one.
AP5              the certificate upload asks what a verifying client asks: the validity window and, when stated, the usages.
AP8              the redirect URI is the second address of the single sign-on form.
AP9, #2          user-info of any scheme and a secret-named query parameter are masked in a Kea config a person reads.
AP10, AP20       a backups folder that cannot be listed is "could not be read", never zero and never a 500.
AP11             a moment stored as ISO text is printed as a time, in a `<time>` element.
AP15, AP16       the drift record's write is read back when it fails; an expired certificate "expired N day(s) ago".
AP19, AP24       one radio group per card; the outbound POST names its timeout.

The ntfy cell runs against a REAL local server (CLAUDE.md: probe, redirect and TLS behavior is never tested behind a mocked client).
"""

import ast
import configparser
import datetime
import http.server
import json
import pathlib
import re
import threading
import types

import pytest

from jen.services import alerts, auth, kea_authoring, onboarding, secret_keys, timefmt

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _function(rel: str, name: str) -> str:
    src = (ROOT / rel).read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(src, fn)


def _route():
    from jen.routes.settings import alerts as route

    return route


def _keep(monkeypatch, channel_type, old, new):
    route = _route()
    monkeypatch.setattr("jen.services.alerts.get_channel_config", lambda row: dict(old))
    return route._kept_secrets(4, channel_type, dict(new), {"id": 4, "channel_type": channel_type, "config": "x"})


# ── AP1, AP7: the address is asked of what dials it and of its own text ──────────────────────────────────────

UNDIALABLE_PORTS = ["https://h.example:+443/x", "https://h.example:٤٤٣/x", "https://h.example:４４３/x"]
BARE_DELIMITERS = ["#", "?", "/#", "/?", "?#"]


class TestThePortIsAskedOfTheParserThatDials:
    @pytest.mark.parametrize("address", UNDIALABLE_PORTS)
    def test_a_port_urllib3_refuses_is_refused_by_every_address_question(self, address):
        from urllib3.util import parse_url

        with pytest.raises(ValueError):
            parse_url(address)
        assert not auth.http_address(address)
        assert not auth.plain_address(address)
        assert not auth.valid_oidc_issuer(address)

    @pytest.mark.parametrize(
        "address", ["https://h.example:443/x", "https://h.example/x", "http://[::1]:8080/x", "https://h.example:65535"]
    )
    def test_a_port_that_is_a_number_still_passes(self, address):
        assert auth.http_address(address) and auth.plain_address(address)


class TestABareDelimiterIsAskedOfTheText:
    @pytest.mark.parametrize("tail", BARE_DELIMITERS)
    def test_it_is_not_a_plain_address_and_not_an_issuer(self, tail):
        assert not auth.plain_address("https://idp.example/realms/jen" + tail)
        assert not auth.valid_oidc_issuer("https://idp.example/realms/jen" + tail)

    @pytest.mark.parametrize("tail", BARE_DELIMITERS)
    def test_an_ntfy_address_that_ends_in_one_is_refused_on_the_save(self, tail):
        route = _route()
        refused = route._address_refusal("ntfy", {"url": "https://ntfy.example/base" + tail})
        assert refused == ("ntfy_url", route.NTFY_ADDRESS_SHAPE)

    def test_a_webhook_keeps_its_query(self):
        """A webhook's address is write-only and commonly carries its token in the query: `http_address` is its question and is not narrowed."""
        assert auth.http_address("https://hooks.example/x?token=abc")
        assert _route()._address_refusal("webhook", {"webhook_url": "https://hooks.example/x?token=abc"}) is None


# ── AP6, AP17 and the review's #1 and #3: the SMTP host ──────────────────────────────────────────────────────

GOOD_HOSTS = [
    "mail.example.test",
    "mail.example.test.",
    "10.0.0.5",
    "::1",
    "fe80::1",
    "2001:db8::25",
    "relay_1",
    "smtp",
]
BAD_HOSTS = ["mail.example.test:25", "a:b:c", ".", "..", "-", "_", "[::1]", ".example", "a..b", "", "1.2.3.4:25"]


class TestAnSmtpHostIsANameOrAnAddressAlone:
    @pytest.mark.parametrize("host", GOOD_HOSTS)
    def test_a_host_is_accepted_and_its_endpoint_can_be_read(self, host):
        route = _route()
        assert auth.host_name(host)
        assert route._address_refusal("email", {"smtp_host": host}) is None
        for wire in ({"use_tls": "false"}, {"use_tls": "true"}, {"use_tls": "true", "tls_verify": "false"}):
            place = route._endpoint("email", {"smtp_host": host, "smtp_port": "587", **wire})
            assert auth.same_destination(place, place), place

    @pytest.mark.parametrize("host", BAD_HOSTS)
    def test_what_the_sentence_refuses_the_check_refuses(self, host):
        route = _route()
        assert not auth.host_name(host)
        if host:
            assert route._address_refusal("email", {"smtp_host": host}) == ("smtp_host", route.SMTP_HOST_SHAPE)

    @pytest.mark.parametrize("host", ["someone:pw@mail.example.test", "mail.example.test:25", "a:b:c", "[::1]"])
    def test_only_an_ipv6_address_is_bracketed(self, host):
        """(fixup 2) A stored host with a colon that is not an IPv6 address is left as written: bracketed, `urlsplit` on a current Python raises for it and on an older one does
        not, so the endpoint would depend on the interpreter."""
        place = _route()._endpoint("email", {"smtp_host": host, "smtp_port": "587", "use_tls": "true"})
        assert place == f"smtps://{host}:587"

    def test_a_stored_host_with_user_info_still_keeps_its_password_on_a_blank_host(self, monkeypatch):
        row = {"smtp_host": "someone:pw@mail.example.test", "smtp_port": "587", "smtp_user": "u", "use_tls": "true"}
        kept = _keep(monkeypatch, "email", {**row, "smtp_pass": "stored"}, {**row, "smtp_host": "", "smtp_pass": ""})
        assert isinstance(kept, dict) and kept["smtp_pass"] == "stored" and kept["smtp_host"] == row["smtp_host"]

    def test_an_edit_that_changes_nothing_keeps_the_password_of_an_ipv6_server(self, monkeypatch):
        row = {"smtp_host": "::1", "smtp_port": "587", "smtp_user": "u", "use_tls": "true", "smtp_pass": "stored"}
        kept = _keep(monkeypatch, "email", row, {**row, "smtp_pass": ""})
        assert isinstance(kept, dict) and kept["smtp_pass"] == "stored"

    def test_the_withheld_card_speaks_of_the_host_for_an_email_channel(self):
        page = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        line = next(ln for ln in page.splitlines() if "it is not shown. It is still used as saved." in ln)
        assert "{% if ch.channel_type == 'email' %} and enter the host name or IP address alone" in line
        assert line.count("access token") == 1 and line.index("{% else %}") < line.index("access token")


# ── AP18: a stronger wire is not a new place ──────────────────────────────────────────────────────────────────

CLEAR = {"use_tls": "false"}
UNVERIFIED = {"use_tls": "true", "tls_verify": "false"}
VERIFIED = {"use_tls": "true", "tls_verify": "true"}
LEGACY_TLS = {"use_tls": "true"}  # a row an earlier release stored: no `tls_verify`, and the sender verifies it


class TestAStrongerWireKeepsThePassword:
    BASE = {"smtp_host": "mail.example.test", "smtp_port": "587", "smtp_user": "u"}

    @pytest.mark.parametrize(
        "old,new,kept",
        [
            (CLEAR, UNVERIFIED, True),
            (CLEAR, VERIFIED, True),
            (UNVERIFIED, VERIFIED, True),
            (VERIFIED, VERIFIED, True),
            (LEGACY_TLS, VERIFIED, True),
            (VERIFIED, UNVERIFIED, False),
            (VERIFIED, CLEAR, False),
            (UNVERIFIED, CLEAR, False),
            (LEGACY_TLS, UNVERIFIED, False),
        ],
    )
    def test_the_wire(self, monkeypatch, old, new, kept):
        route = _route()
        answer = _keep(
            monkeypatch, "email", {**self.BASE, **old, "smtp_pass": "stored"}, {**self.BASE, **new, "smtp_pass": ""}
        )
        if kept:
            assert isinstance(answer, dict) and answer["smtp_pass"] == "stored"
        else:
            assert answer == ("smtp_pass", route.DESTINATION_CHANGED)

    def test_a_stronger_wire_on_another_host_is_still_another_place(self, monkeypatch):
        route = _route()
        answer = _keep(
            monkeypatch,
            "email",
            {**self.BASE, **CLEAR, "smtp_pass": "stored"},
            {**self.BASE, **VERIFIED, "smtp_host": "mail2.example.test", "smtp_pass": ""},
        )
        assert answer == ("smtp_pass", route.DESTINATION_CHANGED)

    def test_the_rank_reads_the_wire_as_the_endpoint_spells_it(self):
        route = _route()
        assert [route._wire_rank(w) for w in (CLEAR, UNVERIFIED, VERIFIED, LEGACY_TLS, {})] == [
            0,
            1,
            2,
            2,
            2,
        ]  # (Q234, AQ1) no key is the sender's default


class TestUntickedIsSaidOnlyByAFormThatCarriesTheBox:
    def test_the_save_reads_the_marker(self):
        src = (ROOT / "jen/routes/settings/alerts.py").read_text(encoding="utf-8")
        flat = " ".join(src.split())
        assert (
            '"tls_verify": ("true" if request.form.get("tls_verify") else "false") if request.form.get("tls_verify_shown") '
            'else (__alerts.get_channel_config(stored).get("tls_verify", "true") if stored else "true"),'
        ) in flat

    def test_the_form_carries_the_marker_beside_the_box(self):
        page = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        assert '<input type="hidden" name="tls_verify_shown" value="1"><input type="checkbox" name="tls_verify"' in page
        assert page.count('name="tls_verify_shown"') == 1


# ── AP2, AP21: the ntfy token is judged against the one address the sender builds ─────────────────────────────


class _Receiver(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.seen.append((self.path, self.headers.get("Authorization")))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def ntfy_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    server.seen = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


class TestTheNtfyTargetIsOneString:
    @pytest.mark.parametrize(
        "url,topic,target",
        [
            ("https://ntfy.example", "jen", "https://ntfy.example/jen"),
            ("https://ntfy.example/", "jen", "https://ntfy.example/jen"),
            ("https://ntfy.example/base/", "jen", "https://ntfy.example/base/jen"),
            ("https://ntfy.example/base#x", "jen", "https://ntfy.example/base/jen"),
            ("https://ntfy.example/base?a=1", "jen", "https://ntfy.example/base/jen"),
            ("https://ntfy.example/base", "../admin", "https://ntfy.example/base/..%2Fadmin"),
            ("https://ntfy.example/base", "a/b", "https://ntfy.example/base/a%2Fb"),
            ("https://ntfy.example/base", "jen?auth=x", "https://ntfy.example/base/jen%3Fauth%3Dx"),
        ],
    )
    def test_the_target(self, url, topic, target):
        assert alerts.ntfy_target({"url": url, "topic": topic}) == target

    def test_the_sender_and_the_comparison_ask_the_one_function(self):
        sender = _function("jen/services/alerts.py", "_send_ntfy_channel")
        assert (
            "target = ntfy_target(config)" in sender and "_post(target," in sender
        )  # (Q234, AQ2) and "" is not posted to
        assert "{url}/{topic}" not in (ROOT / "jen/services/alerts.py").read_text(encoding="utf-8")
        assert '__alerts.ntfy_target(config) if config.get("url") else ""' in _function(
            "jen/routes/settings/alerts.py", "_endpoint"
        )

    @pytest.mark.parametrize("topic", ["../admin", "../../admin", "a/b"])
    def test_a_stored_topic_cannot_leave_the_path_of_the_server(self, ntfy_server, topic):
        base = f"http://127.0.0.1:{ntfy_server.server_address[1]}/base"
        assert alerts._send_ntfy_channel("<b>x</b>", {"url": base, "topic": topic, "token": "tk-1"}) is True
        ((path, authorization),) = ntfy_server.seen
        assert path.startswith("/base/") and path.count("/") == 2, path
        assert authorization == "Bearer tk-1"

    @pytest.mark.parametrize("topic", ["../admin", "a/b", "jen?auth=x", "a b", "t" * 65, "jen#x"])
    def test_a_typed_topic_that_is_not_a_topic_is_refused(self, topic):
        route = _route()
        assert route._topic_refusal("ntfy", {"topic": topic}) == ("ntfy_topic", route.NTFY_TOPIC_SHAPE)

    @pytest.mark.parametrize("topic", ["jen-alerts", "Jen_1", "t" * 64, ""])
    def test_a_topic_and_a_blank_are_not_refused(self, topic):
        assert _route()._topic_refusal("ntfy", {"topic": topic}) is None
        assert _route()._topic_refusal("email", {"topic": "../x"}) is None

    def test_the_save_asks_the_topic(self):
        src = (ROOT / "jen/routes/settings/alerts.py").read_text(encoding="utf-8")
        assert "refused = _address_refusal(channel_type, config) or _topic_refusal(channel_type, config)" in src

    def test_a_blank_token_is_not_kept_for_another_topic(self, monkeypatch):
        route = _route()
        old = {"url": "https://ntfy.example", "topic": "jen", "token": "tk-1"}
        assert _keep(monkeypatch, "ntfy", old, {**old, "token": ""})["token"] == "tk-1"
        assert _keep(monkeypatch, "ntfy", old, {**old, "topic": "ops", "token": ""}) == (
            "ntfy_token",
            route.DESTINATION_CHANGED,
        )

    def test_a_blank_address_is_no_destination(self):
        assert _route()._endpoint("ntfy", {"url": "", "topic": "jen"}) == ""


# ── AP3: a restore that raised is not known ───────────────────────────────────────────────────────────────────


class TestARestoreThatRaisedIsNotKnown:
    def test_the_result_carries_the_second_list(self):
        from jen.services import kea_changeset

        assert kea_changeset.ChangeSetResult("ok", "", []).not_known_ids == []
        src = (ROOT / "jen/services/kea_changeset.py").read_text(encoding="utf-8")
        assert (
            "still_new_ids=[d.key for d in revert_failed if d.key not in file_unknown and d.key not in api_unknown],"
            in src
        )
        assert "not_known_ids=[d.key for d in revert_failed if d.key in file_unknown or d.key in api_unknown]," in src

    def _consume(self, monkeypatch, **lists):
        from jen.routes.settings import infrastructure as infra

        said, incidents, audits = [], [], []

        def never(*a, **k):
            raise AssertionError("the certificate was acted on although the config was not read back")

        monkeypatch.setattr(infra, "flash", lambda text, level="info": said.append((level, text)))
        monkeypatch.setattr(infra, "_record_incident", lambda *a, **k: incidents.append(a[3]))
        monkeypatch.setattr(infra, "_put_tls_back", never)
        monkeypatch.setattr("jen.services.kea_tls.discard_local_record", never)
        monkeypatch.setattr("jen.models.user.audit", lambda *a, **k: audits.append(a))
        result = types.SimpleNamespace(status="rollback_failed", still_new_ids=[], not_known_ids=[])
        for name, ids in lists.items():
            setattr(result, name, ids)
        infra._tls_after_unapplied_change({"id": 2, "name": "kea-a"}, "dhcp4", {"Dhcp4": {}}, result)
        return said, incidents, audits

    def test_the_consumer_neither_drops_its_copy_nor_reinstalls(self, monkeypatch):
        said, incidents, audits = self._consume(monkeypatch, not_known_ids=[2])
        assert incidents == ["remote-unknown"]
        ((level, text),) = said
        assert level == "error" and text.startswith("STATE NOT KNOWN on kea-a")
        assert "The previous certificate was NOT put back and Jen kept its copy of the new one." in text
        assert audits and audits[0][0] == "DIRECT_SOCKET_PARTIAL"

    def test_a_revert_that_was_refused_is_still_the_partial_state(self, monkeypatch):
        said, incidents, _audits = self._consume(monkeypatch, still_new_ids=[2])
        assert incidents == ["tls-not-restored"]
        assert said[0][1].startswith("PARTIAL STATE on kea-a")


# ── AP5: the certificate upload asks what a verifying client asks ─────────────────────────────────────────────


def _mint(days_from=-1, days_to=30, ca=None, key_usage=None, extended=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jen.example.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=days_from))
        .not_valid_after(now + datetime.timedelta(days=days_to))
    )
    if ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if key_usage is not None:
        flags = dict.fromkeys(
            (
                "digital_signature",
                "content_commitment",
                "key_encipherment",
                "data_encipherment",
                "key_agreement",
                "key_cert_sign",
                "crl_sign",
                "encipher_only",
                "decipher_only",
            ),
            False,
        )
        flags.update(dict.fromkeys(key_usage, True))
        builder = builder.add_extension(x509.KeyUsage(**flags), critical=True)
    if extended is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(extended), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    pem_key = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return cert.public_bytes(serialization.Encoding.PEM).decode(), pem_key


class TestTheUploadAsksWhatAVerifyingClientAsks:
    def _security(self):
        from jen.routes.settings import security

        return security

    def test_a_plain_self_signed_certificate_is_accepted_as_it_always_was(self):
        cert, key = _mint()
        assert self._security().validate_cert_material(cert, key, None) is None

    def test_a_server_certificate_with_its_usages_is_accepted(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        cert, key = _mint(ca=False, key_usage=["digital_signature"], extended=[ExtendedKeyUsageOID.SERVER_AUTH])
        assert self._security().validate_cert_material(cert, key, None) is None

    def test_an_expired_certificate_is_refused(self):
        cert, key = _mint(days_from=-30, days_to=-1)
        assert self._security().validate_cert_material(cert, key, None).startswith("the certificate expired on ")

    def test_a_certificate_that_is_not_valid_yet_is_refused(self):
        cert, key = _mint(days_from=2, days_to=30)
        assert (
            self._security().validate_cert_material(cert, key, None).startswith("the certificate is not valid until ")
        )

    def test_a_cas_own_certificate_in_the_servers_place_is_refused(self):
        cert, key = _mint(ca=True, key_usage=["key_cert_sign", "crl_sign"])
        reason = self._security().validate_cert_material(cert, key, None)
        assert reason.startswith("the certificate's key usage allows neither a signature nor a key exchange")

    def test_a_certificate_issued_for_a_client_only_is_refused(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        cert, key = _mint(extended=[ExtendedKeyUsageOID.CLIENT_AUTH])
        assert (
            self._security()
            .validate_cert_material(cert, key, None)
            .startswith("the certificate was not issued for a server")
        )

    def test_the_first_certificate_of_the_file_is_the_one_asked(self):
        good, _ = _mint()
        expired, _ = _mint(days_from=-30, days_to=-1)
        assert self._security().cert_refusal(good + expired) is None
        assert self._security().cert_refusal(expired + good).startswith("the certificate expired on ")

    def test_a_mismatched_key_is_still_refused_first(self):
        cert, _ = _mint()
        _, other = _mint()
        assert self._security().validate_cert_material(cert, other, None) is not None


# ── AP8: the redirect URI ─────────────────────────────────────────────────────────────────────────────────────


class TestTheRedirectUriIsAnAddress:
    def test_the_save_asks_it_the_address_question(self):
        src = _function("jen/routes/settings/security.py", "save_oidc")
        assert "if redirect_uri and not __auth.plain_address(redirect_uri):" in src
        assert 'flash_field("redirect_uri", __auth.userinfo_sentence(redirect_uri) or OIDC_REDIRECT_SHAPE)' in src
        assert src.index("plain_address(redirect_uri)") < src.index("write_values(items)")

    @pytest.mark.parametrize(
        "value",
        [
            "https://u:pw@jen.example/auth/oidc/callback",
            "https://jen.example/cb?x=1",
            "https://jen.example/cb#",
            "jen.example/cb",
        ],
    )
    def test_what_it_refuses(self, value):
        assert not auth.plain_address(value)

    @pytest.mark.parametrize(
        "value", ["https://jen.example/auth/oidc/callback", "http://jen.lan:5050/auth/oidc/callback"]
    )
    def test_what_it_accepts(self, value):
        assert auth.plain_address(value)

    def test_the_legacy_scan_names_it(self):
        cfg = configparser.ConfigParser()
        cfg.read_string("[oidc]\nissuer = https://idp.example/r\nredirect_uri = https://u:pw@jen.example/cb\n")
        assert auth.urls_with_userinfo(cfg) == [("oidc", "redirect_uri")]
        note = auth.userinfo_legacy_note("oidc", "redirect_uri")
        assert "a redirect URI has none" in note and "pw" not in note
        assert "an issuer has none" in auth.userinfo_legacy_note("oidc", "issuer")

    def test_the_page_never_prints_user_info_back(self):
        page = (ROOT / "templates/settings_security.html").read_text(encoding="utf-8")
        assert 'name="redirect_uri" value="{{ oidc.redirect_uri|no_userinfo }}"' in page


# ── AP9 and the review's #2: masking by where a secret sits ───────────────────────────────────────────────────

SENTINEL = "S3ntinel-pw"


class TestASecretInsideAnAddressIsMasked:
    @pytest.mark.parametrize(
        "scheme",
        [
            "http",
            "https",
            "HTTP",
            "ws",
            "wss",
            "ldap",
            "ldaps",
            "postgresql",
            "mysql",
            "redis",
            "amqp",
            "mongodb",
            "ftp",
            "ssh",
            "scp",
        ],
    )
    def test_user_info_of_any_scheme(self, scheme):
        shown = kea_authoring.redact_secrets(
            {"hooks": [{"parameters": {"url": f"{scheme}://ha:{SENTINEL}@10.0.0.9:8000/x"}}]}
        )
        assert SENTINEL not in json.dumps(shown)
        assert shown["hooks"][0]["parameters"]["url"].endswith("://10.0.0.9:8000/x")

    @pytest.mark.parametrize(
        "name", ["token", "api_key", "apikey", "password", "access_token", "client_secret", "API-Key"]
    )
    def test_a_query_parameter_named_like_a_secret(self, name):
        shown = kea_authoring.redact_secrets({"url": f"https://h.example/hook?room=7&{name}={SENTINEL}&x=1"})
        assert shown == {"url": f"https://h.example/hook?room=7&{name}=********&x=1"}

    def test_it_is_idempotent_and_leaves_the_rest_as_written(self):
        value = f"https://u:{SENTINEL}@h.example/hook?token={SENTINEL}&room=7#frag"
        once = secret_keys.without_credentials(value)
        assert once == "https://h.example/hook?token=********&room=7#frag"
        assert secret_keys.without_credentials(once) == once
        for untouched in ("https://h.example/x?room=7", "file:///etc/kea/x@y", "eth0", "a note with an @ in it", ""):
            assert secret_keys.without_credentials(untouched) == untouched

    def test_a_value_with_no_scheme_is_not_read_as_an_address(self):
        """The acknowledged limit: `user:pw@host` is also how a SIP or a mail address is written."""
        assert secret_keys.without_credentials("sip:bob@example.test") == "sip:bob@example.test"

    def test_the_masker_calls_it(self):
        assert "return without_credentials(cfg)" in _function("jen/services/kea_authoring.py", "redact_secrets")


# ── AP10, AP20: a backups folder that cannot be listed ────────────────────────────────────────────────────────


class TestAFolderThatCannotBeListedIsNotZero:
    def test_the_count_is_none(self, monkeypatch, tmp_path):
        from jen.services import dbexport

        def refuse(path):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(dbexport, "BACKUP_DIR", str(tmp_path))
        (tmp_path / "a.json.gz").write_bytes(b"x")
        assert dbexport.backup_count() == 1
        monkeypatch.setattr(dbexport.os, "listdir", refuse)
        assert dbexport.backup_count() is None

    def _row(self, **ctx):
        rows = onboarding.checklist({"checks": {}, "wizard_state": {}, **ctx})["rows"]
        return next(r for r in rows if r["title"] == "A backup exists or is scheduled")

    def test_the_row_says_so(self):
        row = self._row(backup_count=None)
        assert row["done"] is False and row["detail"] == "the backups folder could not be read"
        assert self._row(backup_count=0)["detail"] == "no backups yet"
        assert self._row(backup_count=2) == {**self._row(backup_count=2), "done": True, "detail": "present"}
        assert self._row(backup_count=None, backup_schedule_enabled=True)["done"] is True

    def test_the_settings_hint_says_so(self):
        src = (ROOT / "jen/routes/settings/__init__.py").read_text(encoding="utf-8")
        said = 'hints["databases"].append(("Backups could not be counted", "warn"))'
        assert said in src and src.index("if n is None:") < src.index(said) < src.index("elif n:")


# ── AP11: a moment stored as ISO text ─────────────────────────────────────────────────────────────────────────


class TestAStoredMomentIsPrintedAsATime:
    @pytest.mark.parametrize(
        "stored",
        ["2026-11-12T14:05:24+00:00", "2026-11-12T14:05:24Z", "2026-11-12T14:05:24", "2026-11-12T15:05:24+01:00"],
    )
    def test_the_filter_prints_the_utc_wording_in_a_time_element(self, stored):
        html = str(timefmt.iso_filter(stored))
        assert (
            html
            == '<time datetime="2026-11-12T14:05:24Z" data-jen-time="fmt" data-jen-fmt="%Y-%m-%d %H:%M">2026-11-12 14:05 UTC</time>'
        )

    def test_what_is_not_a_moment_is_printed_as_it_is(self):
        assert timefmt.iso_filter("yesterday <b>") == "yesterday <b>"
        assert not hasattr(timefmt.iso_filter("yesterday <b>"), "__html__"), "plain text: the template escapes it"
        assert timefmt.iso_filter("") == "—" and timefmt.iso_filter(None) == "—"

    def test_the_card_asks_it_at_its_three_times(self):
        page = (ROOT / "templates/settings_kea.html").read_text(encoding="utf-8")
        assert page.count("c.probe.at|isofmt") == 2 and page.count("c.accepted_at|isofmt") == 1
        assert "c.probe.at|utcfmt" not in page and "c.accepted_at|utcfmt" not in page
        assert 'app.add_template_filter(_timefmt.iso_filter, "isofmt")' in (ROOT / "jen/__init__.py").read_text(
            encoding="utf-8"
        )


# ── AP15, AP16: the alert loop ────────────────────────────────────────────────────────────────────────────────


class TestTheDriftRecordIsReadBackWhenItsWriteFails:
    def test_one_event_for_one_issue_over_three_passes(self, monkeypatch):
        events, stored = [], {"ok": False}
        monkeypatch.setattr(alerts, "_unsaved_states", {})
        monkeypatch.setattr("jen.services.alerts.__get_global_setting", lambda key, default="": default)
        monkeypatch.setattr("jen.services.alerts.__set_global_setting", lambda key, value: stored["ok"])
        monkeypatch.setattr("jen.services.alerts.__emit_event", lambda name, **kw: events.append(name))
        monkeypatch.setattr(alerts, "notify_condition", lambda *a, **k: None)
        monkeypatch.setattr(alerts, "_load_state", lambda *a, **k: {"a": False, "r": False})
        issue = {"family": "v4", "type": "missing", "subnet_id": 1, "message": "m"}
        for _ in range(3):
            alerts.check_drift_alerts([issue])
        assert events == ["drift.detected"]
        alerts.check_drift_alerts([])
        assert events == ["drift.detected", "drift.resolved"]
        assert alerts._DRIFT_KNOWN in alerts._unsaved_states
        stored["ok"] = True
        alerts.check_drift_alerts([])
        assert alerts._DRIFT_KNOWN not in alerts._unsaved_states, "a write that lands clears the fallback"


class TestAnExpiredCertificateIsSaidAsExpired:
    def _fire(self, monkeypatch, days):
        sent = []
        monkeypatch.setattr("jen.services.health.cert_days_left", lambda: days)
        monkeypatch.setattr("jen.services.alerts.__get_global_setting", lambda key, default="": "0")
        monkeypatch.setattr(alerts, "_load_state", lambda *a, **k: {"a": False, "r": False})
        monkeypatch.setattr(alerts, "mark_notified", lambda *a, **k: None)
        monkeypatch.setattr(
            alerts, "notify_condition", lambda t, key, active, kwargs=None, **k: sent.append((active, kwargs))
        )
        alerts.check_cert_expiry_alert()
        ((_active, kwargs),) = [s for s in sent if s[0]]
        return kwargs

    def test_the_two_sides_of_the_expiry(self, monkeypatch):
        assert self._fire(monkeypatch, 5) == {"days_left": 5, "when": "expires in <b>5</b> day(s)"}
        assert self._fire(monkeypatch, 0)["when"] == "expires in <b>0</b> day(s)"
        assert self._fire(monkeypatch, -400) == {"days_left": -400, "when": "expired <b>400</b> day(s) ago"}

    def test_the_shipped_sentence_prints_it(self):
        src = (ROOT / "jen/services/alerts.py").read_text(encoding="utf-8")
        assert "Jen's HTTPS certificate {when}." in src and "expires in <b>{days_left}</b>" not in src


# ── AP19, AP24 ────────────────────────────────────────────────────────────────────────────────────────────────


class TestTheSmallerThings:
    def test_a_card_without_its_form_has_its_own_radio_group(self):
        page = (ROOT / "templates/settings_kea.html").read_text(encoding="utf-8")
        assert (
            """<input type="radio" name="{{ 'transport' if c.full else 'transport-' ~ c.id }}" value="{{ m.value }}\""""
            in page
        )
        assert len(re.findall(r'<input type="radio" name="transport"', page)) == 0

    def test_the_outbound_post_names_its_timeout(self):
        assert 'timeout = kwargs.pop("timeout", 10)' in _function("jen/services/alerts.py", "_post")
        assert "resp = requests.post(url, allow_redirects=False, timeout=timeout, **kwargs)" in _function(
            "jen/services/alerts.py", "_post"
        )
        baseline = json.loads((ROOT / ".github/bandit-baseline.json").read_text(encoding="utf-8"))
        assert not [
            r for r in baseline["results"] if r["test_id"] == "B113" and r["filename"] == "jen/services/alerts.py"
        ], "the gate needs no reviewed exception for a call that names its timeout"

    def test_the_guard_says_it_can_write(self):
        from jen.services import kea_api_config as api

        assert "THIS QUESTION CAN WRITE" in api.api_daemon_differs.__doc__
        assert "UNLESS a change is pending" in api.api_daemon_differs.__doc__
        assert "No caller passes `restore=True`" in api.api_daemon_differs.__doc__
        assert "A WRITER, like `_reconcile_pending`" in api.pending_block.__doc__
