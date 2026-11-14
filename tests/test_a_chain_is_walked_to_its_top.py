"""v7.1.0-beta.3 (Q213): the fixes of the executing pass on v7.1.0-beta.2, each at the end the pass found open.

AS1    the certificate upload trusts ONE certificate, the top of the issuer path the upload holds, so every certificate under it is judged.
AS8    `anyExtendedKeyUsage` alone names no server, and the refusal says so.
AS4    the day count beside a server certificate Rotate will re-issue is never negative.
AS7    a helper that ran and answered nothing usable is "not known" to the change set, as a raise is; no SSH session is "nothing was sent".
AS9    the certificate upload is on the fail-closed audit.
AS2, AS5 (the forms)  the import confirmation page carries the `picker` marker the export card carries.

The DB-backed halves of AS2 and AS5 are in tests/test_database.py.
"""

import datetime
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _mint(cn, issuer=None, signer=None, ca=False, start=-10, end=300, eku=None, path_length=None):
    """`(certificate, key)`. `issuer` is the certificate whose NAME goes in the issuer field; `signer` the key that signs (the issuer's own, unless a test breaks it)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now, day = datetime.datetime.now(datetime.timezone.utc), datetime.timedelta(days=1)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer is not None else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + start * day)
        .not_valid_after(now + end * day)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(signer or key, hashes.SHA256()), key


def _pem(cert) -> str:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key(key) -> str:
    from cryptography.hazmat.primitives import serialization as s

    return key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()).decode()


def _path(out, tag, root, root_key, mid_more=None, forged_mid=False):
    """root -> mid -> sub -> leaf, stored as `<tag>_mid`, `<tag>_sub`, `<tag>_leaf`, `<tag>_leaf_key`."""
    stranger = _mint("a stranger", ca=True)[1]
    mid, mid_key = _mint(f"{tag}-mid", root, stranger if forged_mid else root_key, ca=True, **(mid_more or {}))
    sub, sub_key = _mint(f"{tag}-sub", mid, mid_key, ca=True)
    leaf, leaf_key = _mint("jen.example.test", sub, sub_key)
    out[f"{tag}_mid"], out[f"{tag}_sub"], out[f"{tag}_leaf"] = _pem(mid), _pem(sub), _pem(leaf)
    out[f"{tag}_leaf_key"] = _key(leaf_key)


@pytest.fixture(scope="module")
def pki():
    from cryptography.x509.oid import ExtendedKeyUsageOID

    root, root_key = _mint("root", ca=True)
    old_root, old_root_key = _mint("old-root", ca=True, start=-400, end=-5)
    out = {"root": _pem(root), "old_root": _pem(old_root)}
    _path(out, "good", root, root_key)
    _path(out, "expired", root, root_key, mid_more={"start": -400, "end": -5})
    _path(out, "soon", root, root_key, mid_more={"start": 5})
    _path(out, "forged", root, root_key, forged_mid=True)
    _path(out, "short", root, root_key, mid_more={"path_length": 0})
    _path(out, "under_old_root", old_root, old_root_key)
    for label, eku in (
        ("any", [ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]),
        ("client", [ExtendedKeyUsageOID.CLIENT_AUTH]),
        ("server", [ExtendedKeyUsageOID.SERVER_AUTH]),
        ("server_and_any", [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]),
    ):
        cert, key = _mint("jen.example.test", eku=eku)
        out[label], out[label + "_key"] = _pem(cert), _key(key)
    return out


def _judge(pki, certs, key, ca=()):
    from jen.routes.settings.security import validate_cert_material

    return validate_cert_material("".join(pki[c] for c in certs), pki[key], "".join(pki[c] for c in ca) if ca else None)


CHAIN = "a client that verifies the chain refuses it ("

ACCEPTED = [
    ("three deep, a fullchain paste", ("good_leaf", "good_sub", "good_mid"), "good_leaf_key", ()),
    ("three deep with the root", ("good_leaf", "good_sub", "good_mid", "root"), "good_leaf_key", ()),
    ("three deep, the rest in the CA box", ("good_leaf",), "good_leaf_key", ("good_sub", "good_mid", "root")),
    ("three deep, the CA box top first", ("good_leaf",), "good_leaf_key", ("root", "good_mid", "good_sub")),
    ("the leaf and the top with the middle missing", ("good_leaf",), "good_leaf_key", ("good_mid", "root")),
    ("a certificate off the path is not judged", ("good_leaf", "good_sub"), "good_leaf_key", ("old_root",)),
    ("the leaf twice", ("good_leaf", "good_leaf", "good_sub"), "good_leaf_key", ()),
]

REFUSED = [
    (
        "an expired certificate two above the leaf",
        ("expired_leaf", "expired_sub", "expired_mid"),
        "expired_leaf_key",
        (),
        "certificate has expired",
    ),
    (
        "the same, in the CA box top first",
        ("expired_leaf",),
        "expired_leaf_key",
        ("expired_mid", "expired_sub"),
        "certificate has expired",
    ),
    (
        "a certificate two above the leaf that is not valid yet",
        ("soon_leaf", "soon_sub", "soon_mid"),
        "soon_leaf_key",
        (),
        "not yet valid",
    ),
    (
        "an expired root in the CA box above a healthy path",
        ("under_old_root_leaf", "under_old_root_sub", "under_old_root_mid"),
        "under_old_root_leaf_key",
        ("old_root",),
        "certificate has expired",
    ),
    (
        "a certificate two above the leaf that its issuer did not sign",
        ("forged_leaf", "forged_sub", "forged_mid"),
        "forged_leaf_key",
        ("root",),
        "signature",
    ),
    (
        "a path longer than its CA allows",
        ("short_leaf", "short_sub", "short_mid"),
        "short_leaf_key",
        ("root",),
        "path length",
    ),
]


class TestTheWholePathIsJudged:
    """AS1."""

    @pytest.mark.parametrize("case", ACCEPTED, ids=[c[0] for c in ACCEPTED])
    def test_a_healthy_path_is_accepted(self, pki, case):
        _name, certs, key, ca = case
        assert _judge(pki, certs, key, ca) is None

    @pytest.mark.parametrize("case", REFUSED, ids=[c[0] for c in REFUSED])
    def test_a_defect_anywhere_on_the_path_is_refused_in_the_verifiers_words(self, pki, case):
        _name, certs, key, ca, words = case
        reason = _judge(pki, certs, key, ca)
        assert reason and reason.startswith(CHAIN) and words in reason, reason

    def test_the_refusal_is_the_one_a_real_client_gives_the_real_server(self, pki, tmp_path):
        """The oracle: the three-certificate paste on a real local TLS server, and a client that holds only the root."""
        import socket
        import ssl
        import threading

        chain, key = tmp_path / "chain.pem", tmp_path / "key.pem"
        chain.write_text(pki["expired_leaf"] + pki["expired_sub"] + pki["expired_mid"])
        key.write_text(pki["expired_leaf_key"])
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(chain), str(key))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve():
            conn, _ = listener.accept()
            try:
                server_ctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError):
                conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.load_verify_locations(cadata=pki["root"])
        try:
            with (
                pytest.raises(ssl.SSLCertVerificationError) as refused,
                socket.create_connection(listener.getsockname(), timeout=10) as raw,
            ):
                client.wrap_socket(raw, server_hostname="jen.example.test").close()
        finally:
            thread.join(10)
            listener.close()
        said = _judge(pki, ("expired_leaf", "expired_sub", "expired_mid"), "expired_leaf_key")
        assert refused.value.verify_message in said

    def test_one_certificate_is_trusted_never_a_list(self):
        src = (ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8")
        assert src.count("load_verify_locations(cadata=pems[top])") == 1
        assert "pems[1:]" not in src


class TestAnyPurposeIsNotAServer:
    """AS8."""

    def test_any_extended_key_usage_alone_is_refused_with_the_purpose_sentence(self, pki):
        reason = _judge(pki, ("any",), "any_key")
        assert reason.startswith("the certificate was not issued for a server")

    def test_a_client_certificate_is_refused_the_same_way(self, pki):
        assert _judge(pki, ("client",), "client_key").startswith("the certificate was not issued for a server")

    @pytest.mark.parametrize("label", ["server", "server_and_any"])
    def test_a_certificate_that_names_a_server_is_accepted(self, pki, label):
        assert _judge(pki, (label,), label + "_key") is None


class TestRotatesListNeverCountsBelowZero:
    """AS4: the number is `kea_tls.days_left` of a server certificate's copy, which is negative for an expired one."""

    @pytest.mark.parametrize(
        "days,words",
        [
            (-12, "(expired 12 days ago)"),
            (-1, "(expired 1 day ago)"),
            (0, "(0 d)"),
            (33, "(33 d)"),
            (None, "(expiry unreadable)"),
        ],
    )
    def test_the_clause(self, days, words):
        import jinja2

        from jen.services import reltime

        src = (ROOT / "templates/settings_kea.html").read_text(encoding="utf-8")
        (piece,) = re.findall(r"\(\{% if d is none %\}.*?\{% endif %\}\)", src)
        env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=True)
        env.filters["plural"] = reltime.plural
        said = env.from_string(piece).render(d=days)
        assert said == words and "-" not in said

    def test_no_template_prints_a_bare_day_count_of_a_certificate(self):
        """The whole tree: `{{ d }} d` with no branch for a negative number before it."""
        for page in sorted((ROOT / "templates").glob("*.html")):
            for line in page.read_text(encoding="utf-8").splitlines():
                for hit in re.finditer(r"\{\{ d \}\} d", line):
                    assert "{% elif d < 0 %}" in line[: hit.start()], page.name


class TestAHelperThatAnsweredNothingUsableIsNotKnown:
    """AS7."""

    SERVER = {"id": 7, "name": "kea-a", "ssh_host": "a.test", "ssh_user": "jen", "config_transport": "file"}

    def _apply(self, monkeypatch, error):
        from jen.services import kea_host

        def call(server, op, payload):
            raise error

        monkeypatch.setattr(kea_host, "guard_kea_write", lambda *a, **k: None)
        monkeypatch.setattr(kea_host, "helper_call", call)
        return kea_host.apply_config(self.SERVER, "dhcp4", {"Dhcp4": {}}, source="rollback")

    def test_the_helper_ran_and_said_nothing_usable(self, monkeypatch):
        from jen.services import kea_host

        result = self._apply(monkeypatch, kea_host.HelperError("no JSON from helper"))
        assert result["ok"] is False and result["raised"] is True

    def test_no_ssh_session_is_nothing_sent(self, monkeypatch):
        from jen.services import kea_host

        result = self._apply(monkeypatch, kea_host.HelperUnreachable("SSH to jen@a.test failed"))
        assert result["ok"] is False and "raised" not in result

    def test_the_change_set_reads_it_as_not_known(self, monkeypatch):
        from tests.test_a_fix_reaches_both_ends import FakeHost, _consume, _one_server_change

        class Garbled(FakeHost):
            def apply_config(self, server, service, cfg, **kw):
                if kw.get("source") == "rollback":
                    return {
                        "ok": False,
                        "code": "error",
                        "detail": "no JSON from helper",
                        "via": "helper",
                        "raised": True,
                    }
                return super().apply_config(server, service, cfg, **kw)

        monkeypatch.setattr("tests.test_a_fix_reaches_both_ends.FakeHost", Garbled)
        result = _one_server_change(monkeypatch, "refuse")
        assert (result.still_new_ids, result.not_known_ids) == ([], [7])
        said, incidents = _consume(monkeypatch, result)
        assert incidents == ["remote-unknown"] and said[0][1].startswith("STATE NOT KNOWN on kea-a")


class TestTheUploadIsOnTheFailClosedAudit:
    """AS9."""

    def test_the_module_is_listed(self):
        from tests.test_invariant_sweeps import S10_MODULES

        assert "jen/routes/settings/security.py" in S10_MODULES


class TestTheImportPageCarriesTheMarker:
    """AS2: the route's refusal is in tests/test_database.py."""

    def test_the_jen_form_says_it_is_a_picker(self):
        page = (ROOT / "templates/database_import_confirm.html").read_text(encoding="utf-8")
        assert page.count('<input type="hidden" name="picker" value="1">') == 1
        form = page.split("<!-- Jen options -->", 1)[1].split("{% e", 1)[0]
        assert 'name="picker"' in form and 'name="tables"' in form
