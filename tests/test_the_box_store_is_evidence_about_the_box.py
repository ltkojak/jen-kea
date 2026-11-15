"""v7.1.0-beta.5 (Q236): the certificate rows of the executing pass on v7.1.0-beta.4.

AU1    the box's own CA store refusing a chain is evidence about the BOX: a superseded copy of a renewed root there no longer refuses a chain every client accepts.
AU2    a wrong intermediate under a root this box holds is refused whatever key identifiers it carries, and "the issuer is not held" from a client that trusts the
       upload's own top is no longer an acceptance.
AU6    an upload of more than twenty certificates is refused before anything is verified.
AU12   the date clause is added to a refusal that is about a date, and to no other.

Every world is minted here and judged twice: by `validate_cert_material`, and by a real client on a real local TLS server.
"""

import datetime
import socket
import ssl
import threading

import pytest

BOX_SENTENCE = (
    'this box trusts a certificate named "CN={issuer}" and it did not sign "CN={subject}", which names it as issuer. '
)


def _mint(cn, issuer=None, signer=None, ca=False, start=-10, end=300, key=None, ids=False, aki_of=None):
    """`(certificate, key)`. `issuer`: the certificate whose NAME goes in the issuer field. `signer`: the key that signs. `key`: the subject's own key when two
    certificates share one. `ids`: carry a SubjectKeyIdentifier of the own key and an AuthorityKeyIdentifier of `aki_of` (a key; the signer's when not given),
    which is what every real CA emits."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now, day = datetime.datetime.now(datetime.timezone.utc), datetime.timedelta(days=1)
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer is not None else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + start * day)
        .not_valid_after(now + end * day)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    if ids:
        above = (aki_of or signer or key).public_key()
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(above), critical=False)
    return builder.sign(signer or key, hashes.SHA256()), key


def _pem(cert) -> str:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key(key) -> str:
    from cryptography.hazmat.primitives import serialization as s

    return key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()).decode()


@pytest.fixture(scope="module", params=[False, True], ids=["no key identifiers", "key identifiers"])
def pki(request):
    """PEM text by name, minted once without key identifiers and once with them: every world below is judged in both.

    `root` / `root_old`: a private root and its superseded copy (one name, one key, the old one expired). `root_rekeyed`: that name under ANOTHER key.
    `mid`, `leaf`: the honest chain under `root`. `forged_mid`, `forged_leaf`: a `mid` that names `root` and was signed by a stranger, and a leaf under it.
    `misnamed_leaf`: a leaf that names `mid` and was signed by a stranger. `late_mid`, `late_leaf`: an expired intermediate under `root` and a leaf under it."""
    ids = request.param
    out = {}
    root, root_key = _mint("box-root", ca=True, ids=ids)
    old, _ = _mint("box-root", ca=True, start=-400, end=-5, key=root_key, ids=ids)
    rekeyed, stranger = _mint("box-root", ca=True, ids=ids)
    mid, mid_key = _mint("box-mid", root, root_key, ca=True, ids=ids)
    leaf, leaf_key = _mint("jen.example.test", mid, mid_key, ids=ids)
    out.update(root=_pem(root), root_old=_pem(old), root_rekeyed=_pem(rekeyed), mid=_pem(mid))
    out.update(leaf=_pem(leaf), key=_key(leaf_key))

    forged_mid, forged_mid_key = _mint("box-mid", root, stranger, ca=True, ids=ids)
    forged_leaf, forged_leaf_key = _mint("jen.example.test", forged_mid, forged_mid_key, ids=ids)
    out.update(forged_mid=_pem(forged_mid), forged_leaf=_pem(forged_leaf), forged_key=_key(forged_leaf_key))

    misnamed, misnamed_key = _mint("jen.example.test", mid, stranger, ids=ids)
    out.update(misnamed_leaf=_pem(misnamed), misnamed_key=_key(misnamed_key))

    late_mid, late_mid_key = _mint("box-mid", root, root_key, ca=True, start=-400, end=-5, ids=ids)
    late_leaf, late_leaf_key = _mint("jen.example.test", late_mid, late_mid_key, ids=ids)
    out.update(late_mid=_pem(late_mid), late_leaf=_pem(late_leaf), late_key=_key(late_leaf_key))
    return out


@pytest.fixture(autouse=True)
def box_store(monkeypatch, pki):
    """What this box's own CA store holds: nothing, until a test says which certificate. Never the real one of the machine the suite runs on."""
    from jen.routes.settings import security

    held = []

    def load(client):
        if held:
            client.load_verify_locations(cadata="".join(pki[name] for name in held))

    monkeypatch.setattr(security, "_load_box_store", load)
    return held


def _judge(pki, certs, key):
    from jen.routes.settings.security import validate_cert_material

    return validate_cert_material("".join(pki[c] for c in certs), pki[key], None)


def _a_real_client_says(tmp_path, pki, certs, key, holds):
    """The oracle: `certs` on a real local TLS server, and a real client that trusts `holds`. The client's own refusal, or None when it accepts."""
    chain, key_file = tmp_path / "chain.pem", tmp_path / "key.pem"
    chain.write_text("".join(pki[c] for c in certs))
    key_file.write_text(pki[key])
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(chain), str(key_file))
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
    client.load_verify_locations(cadata=pki[holds])
    try:
        with socket.create_connection(listener.getsockname(), timeout=10) as raw:
            client.wrap_socket(raw, server_hostname="jen.example.test").close()
        return None
    except ssl.SSLCertVerificationError as e:
        return e.verify_message
    finally:
        thread.join(10)
        listener.close()


class TestASupersededCopyInTheBoxStore:
    """AU1. A private root was renewed under the same name with the same key, and the box's own store still holds the copy that has expired."""

    @pytest.mark.parametrize(
        "certs", [("leaf", "mid"), ("leaf", "mid", "root")], ids=["the chain alone", "the new root pasted"]
    )
    @pytest.mark.parametrize(
        "store", [["root_old"], ["root_old", "root"], ["root"], []], ids=lambda s: "+".join(s) or "empty"
    )
    def test_a_chain_every_client_accepts_is_accepted_whatever_copy_the_box_holds(
        self, pki, tmp_path, box_store, certs, store
    ):
        assert _a_real_client_says(tmp_path, pki, certs, "key", holds="root") is None
        box_store.extend(store)
        assert _judge(pki, certs, "key") is None

    def test_an_expired_certificate_of_the_upload_is_still_refused_and_named(self, pki, tmp_path, box_store):
        certs = ("late_leaf", "late_mid")
        assert _a_real_client_says(tmp_path, pki, certs, "late_key", holds="root") == "certificate has expired"
        box_store.append("root_old")
        said = _judge(pki, certs, "late_key")
        assert said.startswith("a client that verifies the chain refuses it (certificate has expired); in the upload: ")
        assert '"CN=box-mid" expired on ' in said and "box-root" not in said

    def test_the_box_holding_that_name_under_another_key_is_a_refusal_that_says_what_to_do(
        self, pki, tmp_path, box_store
    ):
        """The box cannot tell a wrong intermediate from a CA whose new root it was never given, and neither can a client that holds what the box holds. The sentence
        names the certificate, the name and both remedies; pasting the root is one of them."""
        certs = ("leaf", "mid")
        assert _a_real_client_says(tmp_path, pki, certs, "key", holds="root_rekeyed") is not None
        box_store.append("root_rekeyed")
        said = _judge(pki, certs, "key")
        assert said.startswith(BOX_SENTENCE.format(issuer="box-root", subject="box-mid"))
        assert "add its new certificate to the upload or to this box's CA store (update-ca-certificates)" in said
        assert _judge(pki, (*certs, "root"), "key") is None


class TestAWrongIntermediateIsRefusedWithAndWithoutKeyIdentifiers:
    """AU2. OpenSSL matches an AuthorityKeyIdentifier before it checks a signature and answers "issuer not found" for a mismatch, which read as "a private CA"."""

    def test_a_forged_intermediate_under_a_root_the_box_holds(self, pki, tmp_path, box_store):
        certs = ("forged_leaf", "forged_mid")
        assert _a_real_client_says(tmp_path, pki, certs, "forged_key", holds="root") is not None
        box_store.append("root")
        assert _judge(pki, certs, "forged_key").startswith(BOX_SENTENCE.format(issuer="box-root", subject="box-mid"))

    def test_a_leaf_under_an_uploaded_certificate_of_the_right_name_that_did_not_sign_it(
        self, pki, tmp_path, box_store
    ):
        certs = ("misnamed_leaf", "mid")
        theirs = _a_real_client_says(tmp_path, pki, certs, "misnamed_key", holds="root")
        assert theirs is not None
        for store in ([], ["root"]):
            box_store[:] = store
            said = _judge(pki, certs, "misnamed_key")
            assert said and said.startswith("a client that verifies the chain refuses it ("), (store, said)

    def test_the_same_leaf_over_a_forged_intermediate(self, pki, tmp_path, box_store):
        certs = ("misnamed_leaf", "forged_mid")
        assert _a_real_client_says(tmp_path, pki, certs, "misnamed_key", holds="root") is not None
        box_store.append("root")
        assert _judge(pki, certs, "misnamed_key") is not None

    def test_the_honest_chain_is_accepted_with_the_root_on_the_box_and_without(self, pki, tmp_path, box_store):
        certs = ("leaf", "mid")
        assert _a_real_client_says(tmp_path, pki, certs, "key", holds="root") is None
        assert _judge(pki, certs, "key") is None
        box_store.append("root")
        assert _judge(pki, certs, "key") is None

    def test_an_upload_that_carries_its_own_root_is_not_overruled_by_the_box(self, pki, tmp_path, box_store):
        """A whole chain under a root of the operator's own, whose name the box also trusts under another key: the uploaded root is the operator's statement."""
        certs = ("leaf", "mid", "root")
        assert _a_real_client_says(tmp_path, pki, certs, "key", holds="root") is None
        box_store.append("root_rekeyed")
        assert _judge(pki, certs, "key") is None


class TestWhatTheBoxAdds:
    """`_box_refusal`, one branch at a time."""

    def _args(self, pki, names, store):
        from cryptography import x509

        return (
            [x509.load_pem_x509_certificate(pki[n].encode()) for n in names],
            [x509.load_pem_x509_certificate(pki[n].encode()) for n in store],
        )

    def test_each_branch(self, pki):
        """(Q237, AV2) The box's store answers whose key signed the top, and nothing about its own copy: the box verifier's answer is no longer an argument."""
        from jen.routes.settings.security import _box_refusal

        certs, held = self._args(pki, ("leaf", "mid", "root"), ["root_rekeyed"])
        assert _box_refusal(certs, 2, held) is None  # the top signed itself
        certs, held = self._args(pki, ("leaf", "mid"), [])
        assert _box_refusal(certs, 1, held) is None  # the box trusts nobody of that name
        certs, held = self._args(pki, ("leaf", "mid"), ["root_rekeyed"])
        assert _box_refusal(certs, 1, held)[1] is None  # one of that name, and it did not sign
        certs, held = self._args(pki, ("leaf", "mid"), ["root_old"])
        assert _box_refusal(certs, 1, held) is None  # the box's own copy signed it: its dates are the box's
        certs, held = self._args(pki, ("leaf", "mid"), ["root_rekeyed", "root"])
        assert _box_refusal(certs, 1, held) is None  # one of the two of that name signed it

    def test_issuer_not_held_is_never_an_acceptance_any_more(self):
        import pathlib

        source = (pathlib.Path(__file__).resolve().parent.parent / "jen/routes/settings/security.py").read_text(
            encoding="utf-8"
        )
        assert "_ISSUER_NOT_HELD" not in source


class TestTheSmallRows:
    def test_more_than_twenty_certificates_is_refused_before_anything_is_verified(self, pki, monkeypatch):
        from jen.routes.settings import security

        def never(*a, **k):
            raise AssertionError("a certificate was verified")

        extra = "".join(_pem(_mint(f"filler-{i}", ca=True)[0]) for i in range(19))
        assert security.validate_cert_material(pki["leaf"] + extra, pki["key"], None) is None  # twenty
        assert (
            security.validate_cert_material(pki["leaf"] + extra + pki["leaf"], pki["key"], None) is None
        )  # a repeat is one certificate
        monkeypatch.setattr(security, "_chain_walk", never)
        said = security.validate_cert_material(pki["leaf"] + extra + pki["mid"], pki["key"], None)
        assert said == (
            "the upload carries 21 certificates and a server presents at most 20: upload the certificate and the chain above it, not a bundle of CAs"
        )

    def test_a_refusal_that_is_not_about_a_date_names_no_date(self, pki):
        """AU12: an expired certificate that is in the file and not on the path used to be named beside "certificate signature failure"."""
        from jen.routes.settings.security import validate_cert_material

        stray = _pem(_mint("a stray CA", ca=True, start=-400, end=-5)[0])
        said = validate_cert_material(pki["misnamed_leaf"] + pki["mid"] + stray, pki["misnamed_key"], None)
        assert said and "in the upload" not in said and "expired" not in said
