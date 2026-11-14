"""v7.1.0-beta.4 (Q235): the fixes of the executing pass on v7.1.0-beta.3 that need no database.

AT1    a `fullchain.pem` ends at an intermediate whose issuer is not in the file: the box's own CA store is asked first, so that intermediate's signature is judged.
AT2    the top of a chain is chosen by what signed what, never by the order of the paste: a root and its expired earlier copy in one bundle.
AT7    an extension that is there and cannot be parsed is a refusal with a sentence.
AT3    `remove_config` answers a helper that ran and said nothing usable as `apply_config` does.

The halves that need a database are in tests/test_database.py; the root script's in tests/test_sudoers_command_matching.py; the restart's in tests/test_runtime.py; the
fail-closed audit's in tests/test_invariant_sweeps.py.
"""

import datetime
import socket
import ssl
import threading

import pytest


def _mint(cn, issuer=None, signer=None, ca=False, start=-10, end=300, key=None, extra=None):
    """`(certificate, key)`. `issuer` is the certificate whose NAME goes in the issuer field; `signer` the key that signs; `key` the subject's own key when a test
    needs two certificates with one."""
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
    if extra is not None:
        builder = builder.add_extension(extra, critical=False)
    return builder.sign(signer or key, hashes.SHA256()), key


def _pem(cert) -> str:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key(key) -> str:
    from cryptography.hazmat.primitives import serialization as s

    return key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()).decode()


@pytest.fixture(scope="module")
def pki():
    """PEM text by name. `re_*`: a root, its expired earlier copy (one name, one key), an intermediate and a leaf. `x_*`: the cross-signed shape. `pub_*`: a root
    that is NOT in any upload - the box's store or a client holds it - and three two-certificate chains under it."""
    out = {}
    cur, root_key = _mint("re-root", ca=True)
    old, _ = _mint("re-root", ca=True, start=-400, end=-5, key=root_key)
    inter, inter_key = _mint("re-inter", cur, root_key, ca=True)
    leaf, leaf_key = _mint("jen.example.test", inter, inter_key)
    out.update(re_cur=_pem(cur), re_old=_pem(old), re_inter=_pem(inter), re_leaf=_pem(leaf), re_key=_key(leaf_key))

    dst, dst_key = _mint("dst", ca=True, start=-900, end=-5)
    x_self, x_key = _mint("x-root", ca=True)
    x_cross, _ = _mint("x-root", dst, dst_key, ca=True, start=-900, end=-5, key=x_key)
    r3, r3_key = _mint("r3", x_self, x_key, ca=True)
    leaf, leaf_key = _mint("jen.example.test", r3, r3_key)
    out.update(x_self=_pem(x_self), x_cross=_pem(x_cross), x_r3=_pem(r3), x_leaf=_pem(leaf), x_key=_key(leaf_key))

    root, pub_key = _mint("pub-root", ca=True)
    stranger = _mint("a stranger", ca=True)[1]
    out["pub_root"] = _pem(root)
    for tag, more in (("good", {}), ("forged", {"signer": stranger}), ("expired", {"start": -400, "end": -5})):
        mid, mid_key = _mint("pub-mid", root, more.pop("signer", pub_key), ca=True, **more)
        leaf, leaf_key = _mint("jen.example.test", mid, mid_key)
        out.update({f"{tag}_mid": _pem(mid), f"{tag}_leaf": _pem(leaf), f"{tag}_key": _key(leaf_key)})
        if tag == "good":
            misnamed, misnamed_key = _mint("jen.example.test", mid, stranger)
            out.update(misnamed_leaf=_pem(misnamed), misnamed_key=_key(misnamed_key))

    a, a_key = _mint("loop-a", ca=True)
    b, b_key = _mint("loop-b", a, a_key, ca=True)
    a_again, _ = _mint("loop-a", b, b_key, ca=True, key=a_key)
    leaf, leaf_key = _mint("jen.example.test", a_again, a_key)
    out.update(loop_a=_pem(a_again), loop_b=_pem(b), loop_leaf=_pem(leaf), loop_key=_key(leaf_key))
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


RE_ORDERS = [
    ("the current root, then the old one", ("re_leaf", "re_inter", "re_cur", "re_old")),
    ("the old root, then the current one", ("re_leaf", "re_inter", "re_old", "re_cur")),
    ("the current root alone", ("re_leaf", "re_inter", "re_cur")),
    ("no root", ("re_leaf", "re_inter")),
]


class TestARootAndItsEarlierCopy:
    """AT2. A CA re-issued its root under the same name with the same key, and its published bundle still carries the expired copy."""

    @pytest.mark.parametrize("case", RE_ORDERS, ids=[c[0] for c in RE_ORDERS])
    def test_the_order_of_the_paste_does_not_choose_the_verdict(self, pki, tmp_path, case):
        _name, certs = case
        assert _a_real_client_says(tmp_path, pki, certs, "re_key", holds="re_cur") is None
        assert _judge(pki, certs, "re_key") is None

    def test_only_the_expired_copy_is_refused_and_the_refusal_names_it(self, pki, tmp_path):
        """Deliberate: a client that holds only what this upload holds refuses it. The sentence says which certificate, so the way out is to take it out of the file."""
        certs = ("re_leaf", "re_inter", "re_old")
        theirs = _a_real_client_says(tmp_path, pki, certs, "re_key", holds="re_old")
        ours = _judge(pki, certs, "re_key")
        assert theirs == "certificate has expired"
        assert ours.startswith(f"a client that verifies the chain refuses it ({theirs}); in the upload: ")
        assert '"CN=re-root" expired on ' in ours and "re-inter" not in ours

    def test_a_leaf_that_names_an_uploaded_certificate_it_was_not_signed_by_is_refused(self, pki):
        said = _judge(pki, ("misnamed_leaf", "good_mid"), "misnamed_key")
        assert said and "signature" in said

    def test_certificates_that_name_each_other_have_no_top(self, pki):
        said = _judge(pki, ("loop_leaf", "loop_a", "loop_b"), "loop_key")
        assert said == "the certificates of the upload name each other as issuer in a loop, so the chain has no top"

    def test_the_tops_are_what_signed_what(self, pki):
        from cryptography import x509

        from jen.routes.settings.security import _chain_tops

        def tops(*names):
            return _chain_tops([x509.load_pem_x509_certificate(pki[n].encode()) for n in names])

        assert tops("re_leaf", "re_inter", "re_cur", "re_old") == [2, 3]
        assert tops("re_leaf", "re_inter", "re_old", "re_cur") == [2, 3]
        assert tops("re_leaf", "re_inter") == [1]
        assert tops("re_leaf") == [0]
        assert tops("re_leaf", "good_mid") == [0]
        assert tops("loop_leaf", "loop_a", "loop_b") == []


class TestTheBoxStoreJudgesTheTop:
    """AT1. A verifier does not check the signature of the certificate it was told to trust, and in a two-certificate `fullchain.pem` that was the intermediate."""

    def test_a_forged_intermediate_is_refused_in_the_words_of_a_client_that_holds_the_root(
        self, pki, tmp_path, box_store
    ):
        certs = ("forged_leaf", "forged_mid")
        theirs = _a_real_client_says(tmp_path, pki, certs, "forged_key", holds="pub_root")
        box_store.append("pub_root")
        assert theirs == "certificate signature failure"
        assert _judge(pki, certs, "forged_key") == f"a client that verifies the chain refuses it ({theirs})"

    def test_a_healthy_fullchain_is_accepted_with_and_without_the_root_on_the_box(self, pki, box_store):
        assert _judge(pki, ("good_leaf", "good_mid"), "good_key") is None
        box_store.append("pub_root")
        assert _judge(pki, ("good_leaf", "good_mid"), "good_key") is None

    def test_an_expired_intermediate_is_refused_with_and_without_the_root_on_the_box(self, pki, box_store):
        for _ in range(2):
            said = _judge(pki, ("expired_leaf", "expired_mid"), "expired_key")
            assert said.startswith("a client that verifies the chain refuses it (certificate has expired)")
            assert '"CN=pub-mid" expired on ' in said
            box_store.append("pub_root")

    def test_what_stays_outside_is_a_top_whose_issuer_nobody_here_holds(self, pki):
        """The stated limit (a private CA whose root is neither pasted nor installed on this box): the signature of that one certificate cannot be judged."""
        assert _judge(pki, ("forged_leaf", "forged_mid"), "forged_key") is None

    def test_a_cross_signed_root_is_judged_by_the_copy_the_box_holds(self, pki, tmp_path, box_store):
        certs = ("x_leaf", "x_r3", "x_cross")
        assert _a_real_client_says(tmp_path, pki, certs, "x_key", holds="x_self") is None
        assert "certificate has expired" in _judge(pki, certs, "x_key")
        box_store.append("x_self")
        assert _judge(pki, certs, "x_key") is None

    def test_a_store_that_cannot_be_loaded_is_a_box_that_holds_nothing(self, pki, monkeypatch):
        from jen.routes.settings import security

        def broken(client):
            raise OSError("no CA bundle here")

        monkeypatch.setattr(security, "_load_box_store", broken)
        assert _judge(pki, ("good_leaf", "good_mid"), "good_key") is None
        assert "certificate has expired" in _judge(pki, ("expired_leaf", "expired_mid"), "expired_key")

    def test_the_seam_is_the_systems_own_store(self):
        import pathlib

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen/routes/settings/security.py").read_text(
            encoding="utf-8"
        )
        seam = src[src.index("def _load_box_store") : src.index("def _handshake")]
        assert "client.load_default_certs()" in seam
        assert src.count("load_default_certs") == 1 and src.count("    _load_box_store(client)") == 1


class TestAnExtensionThatCannotBeRead:
    """AT7."""

    def test_an_empty_extended_key_usage_is_a_sentence(self, pki):
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        from jen.routes.settings.security import cert_refusal

        cert, _key_ = _mint(
            "jen.example.test", extra=x509.UnrecognizedExtension(ExtensionOID.EXTENDED_KEY_USAGE, b"\x30\x00")
        )
        assert cert_refusal(_pem(cert)) == "the certificate carries an extension that cannot be read"

    def test_a_key_usage_that_is_not_a_bit_string_is_a_sentence(self, pki):
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        from jen.routes.settings.security import cert_refusal

        cert, _key_ = _mint("jen.example.test", extra=x509.UnrecognizedExtension(ExtensionOID.KEY_USAGE, b"\x30\x00"))
        assert cert_refusal(_pem(cert)) == "the certificate carries an extension that cannot be read"


class TestRemovingAFileAnswersLikeWritingOne:
    """AT3. `remove_config` is the rollback of a target that had no config file before the change."""

    SERVER = {"id": 7, "name": "kea-a", "ssh_host": "a.test", "ssh_user": "jen", "config_transport": "file"}

    def _remove(self, monkeypatch, error):
        from jen.services import kea_host

        def call(server, op, payload):
            raise error

        monkeypatch.setattr(kea_host, "helper_call", call)
        return kea_host.remove_config(self.SERVER, "dhcp4", "ab" * 32)

    def test_the_helper_ran_and_said_nothing_usable(self, monkeypatch):
        from jen.services import kea_host

        result = self._remove(monkeypatch, kea_host.HelperError("no JSON from helper"))
        assert result["ok"] is False and result["raised"] is True

    def test_no_ssh_session_is_nothing_sent(self, monkeypatch):
        from jen.services import kea_host

        result = self._remove(monkeypatch, kea_host.HelperUnreachable("SSH to jen@a.test failed"))
        assert result["ok"] is False and "raised" not in result

    def test_every_helper_error_of_a_config_write_or_removal_is_split(self):
        """The whole module: a function that sends `apply-config` or `remove-config` answers `HelperUnreachable` before `HelperError`, and marks the second `raised`."""
        import ast
        import pathlib

        src = (pathlib.Path(__file__).resolve().parent.parent / "jen/services/kea_host.py").read_text(encoding="utf-8")
        seen = 0
        for fn in ast.walk(ast.parse(src)):
            if not isinstance(fn, ast.FunctionDef) or fn.name not in ("apply_config", "remove_config"):
                continue
            for node in ast.walk(fn):
                if (
                    isinstance(node, ast.ExceptHandler)
                    and isinstance(node.type, ast.Name)
                    and node.type.id == "HelperError"
                ):
                    seen += 1
                    assert "'raised': True" in ast.unparse(node), f"{fn.name}:{node.lineno}"
        assert seen == 2
