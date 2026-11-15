"""v7.1.0-beta.6 (Q237): the certificate rows of the executing pass on v7.1.0-beta.5 and of the independent review.

AV1    the upload's top is the certificate Jen tells the verifier to trust, and a verifier does not hold its own anchor to the rule it holds every CA below it to:
       an intermediate with no basic constraints passed. A top that signs a certificate of the upload and did not sign itself must say it is a CA.
AV2    the box's store answers ONE question, whose key signed the top. A property of the box's own copy of the issuer - its serial under a key identifier that
       names issuer and serial, its path length, its dates - no longer refuses a chain a client holding the CA's own root accepts.
AV3    decided, and pinned here: a certificate in the box's store that OpenSSL does not count as a CA is no certificate the box trusts.
AV10   removing the certificate removes the `.prev` copies too.
AV31   the size and the count are judged before anything is written, loaded or parsed.
#1     (the independent review) an expired certificate of the upload that is on no path decides nothing.

Every world is minted here and judged twice: by `validate_cert_material`, and by a real client on a real local TLS server that holds what a deployed client holds.
"""

import datetime
import pathlib
import socket
import ssl
import threading

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOST = "jen.example.test"


def _mint(
    cn,
    issuer=None,
    signer=None,
    key=None,
    ca=None,
    path_length=None,
    usage=None,
    start=-10,
    end=300,
    serial=None,
    aki=None,
    ski=None,
):
    """`(certificate, key)`. `ca`: True / False for a basic-constraints extension, None for a certificate that carries none. `usage`: "sign" for a key usage that
    allows signing certificates, "tls" for one that does not, None for no key usage. `aki`: "key" names the issuer by its key, "serial" by its name and serial
    (what Microsoft AD CS can emit), None for no key identifiers at all."""
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
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(now + start * day)
        .not_valid_after(now + end * day)
    )
    if ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    if usage is not None:
        signs = usage == "sign"
        builder = builder.add_extension(
            x509.KeyUsage(True, False, False, False, False, signs, signs, False, False), critical=True
        )
    if cn == HOST:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    if aki == "key":
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key((signer or key).public_key()), critical=False
        )
    elif isinstance(aki, bytes):
        builder = builder.add_extension(x509.AuthorityKeyIdentifier(aki, None, None), critical=False)
    elif aki == "serial" and issuer is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(None, [x509.DirectoryName(issuer.issuer)], issuer.serial_number), critical=False
        )
    if ski is not None:
        builder = builder.add_extension(x509.SubjectKeyIdentifier(ski), critical=False)
    return builder.sign(signer or key, hashes.SHA256()), key


def _derived(key) -> bytes:
    from cryptography import x509

    return x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest


def _pem(cert) -> str:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key(key) -> str:
    from cryptography.hazmat.primitives import serialization as s

    return key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()).decode()


@pytest.fixture(autouse=True)
def box_store(monkeypatch):
    """What this box's own CA store holds, as PEM text: nothing, until a test says. Never the real one of the machine the suite runs on."""
    from jen.routes.settings import security

    held = []

    def load(client):
        if held:
            client.load_verify_locations(cadata="".join(held))

    monkeypatch.setattr(security, "_load_box_store", load)
    return held


def _judge(certs, key, bundle=None):
    from jen.routes.settings.security import validate_cert_material

    return validate_cert_material("".join(_pem(c) for c in certs), _key(key), bundle)


def _a_client_holding(tmp_path, root, certs, key):
    """The oracle: `certs` on a real local TLS server, and a real client that trusts `root` and nothing else. Its own refusal, or None when it accepts."""
    chain, key_file = tmp_path / "chain.pem", tmp_path / "key.pem"
    chain.write_text("".join(_pem(c) for c in certs))
    key_file.write_text(_key(key))
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
    client.load_verify_locations(cadata=_pem(root))
    try:
        with socket.create_connection(listener.getsockname(), timeout=10) as raw:
            client.wrap_socket(raw, server_hostname=HOST).close()
        return None
    except ssl.SSLCertVerificationError as e:
        return e.verify_message
    finally:
        thread.join(10)
        listener.close()


AKI = pytest.mark.parametrize(
    "aki", [None, "key", "serial"], ids=["no identifiers", "key identifier", "issuer and serial"]
)


class TestTheBoxLendsItsKeyAndNothingElse:
    """AV2. The box's copy of the issuer differs from the one that signed the chain in everything but the key, and a client that holds the CA's own root accepts."""

    def _world(self, aki, **copy):
        root, root_key = _mint("renewed root", ca=True, aki=aki)
        copy_cert, _ = _mint("renewed root", key=root_key, ca=copy.pop("ca", True), aki=aki, **copy)
        mid, mid_key = _mint("renewed mid", root, root_key, ca=True, aki=aki)
        leaf, leaf_key = _mint(HOST, mid, mid_key, ca=False, aki=aki)
        return root, copy_cert, [leaf, mid], leaf_key

    @AKI
    @pytest.mark.parametrize("dates", [(-10, 300), (-400, -5)], ids=["the copy is valid", "the copy has expired"])
    def test_a_copy_with_another_serial(self, aki, dates, box_store, tmp_path):
        root, copy, chain, key = self._world(aki, start=dates[0], end=dates[1])
        box_store.append(_pem(copy))
        assert _a_client_holding(tmp_path, root, chain, key) is None
        assert _judge(chain, key) is None

    @AKI
    def test_a_copy_with_a_path_length_the_root_does_not_have(self, aki, box_store, tmp_path):
        root, copy, chain, key = self._world(aki, path_length=0)
        box_store.append(_pem(copy))
        assert _a_client_holding(tmp_path, root, chain, key) is None
        assert _judge(chain, key) is None

    @AKI
    def test_that_name_under_another_key_is_still_the_refusal_that_names_the_box(self, aki, box_store, tmp_path):
        root, _, chain, key = self._world(aki)
        stranger, _ = _mint("renewed root", ca=True, aki=aki)
        box_store.append(_pem(stranger))
        assert _a_client_holding(tmp_path, stranger, chain, key) is not None
        assert _judge(chain, key).startswith(
            'this box trusts a certificate named "CN=renewed root" and it did not sign'
        )

    @AKI
    def test_a_forged_intermediate_is_refused_whatever_the_boxs_copy_looks_like(self, aki, box_store, tmp_path):
        root, root_key = _mint("renewed root", ca=True, aki=aki)
        copy, _ = _mint("renewed root", key=root_key, ca=True, aki=aki, start=-400, end=-5)
        _, stranger = _mint("a stranger", ca=True)
        mid, mid_key = _mint("renewed mid", root, stranger, ca=True, aki=aki)
        leaf, leaf_key = _mint(HOST, mid, mid_key, ca=False, aki=aki)
        for held in (root, copy):
            box_store[:] = [_pem(held)]
            assert _a_client_holding(tmp_path, root, [leaf, mid], leaf_key) is not None
            assert _judge([leaf, mid], leaf_key).startswith("this box trusts a certificate named")

    def test_the_boxs_verifier_is_asked_once_and_only_an_acceptance_is_read(self):
        """The source: `chain_refusal` keeps nothing of the box handshake's refusal, and `_box_refusal` takes no verdict."""
        import inspect

        from jen.routes.settings import security

        assert list(inspect.signature(security._box_refusal).parameters) == ["certs", "top", "held"]
        assert "box_said" not in inspect.getsource(security)

    def test_a_certificate_the_box_holds_that_is_not_a_ca_is_not_one_the_box_trusts(self, box_store, tmp_path):
        """AV3, decided. The box's store holds the issuer's name and key in a certificate that says it is not a CA. OpenSSL does not list it among the CAs of the
        store, so the box "trusts nobody of that name" and the upload's own top decides - the private-CA case. A client that holds the CA's own root accepts."""
        root, copy, chain, key = self._world(None, ca=False)
        box_store.append(_pem(copy))
        assert _a_client_holding(tmp_path, root, chain, key) is None
        assert _judge(chain, key) is None


class TestTheTopIsACaByTheRuleOfTheClientsBelowIt:
    """AV1. The root is in neither the upload nor the box's store: the private-CA case, where the upload's top is all Jen has."""

    def _world(self, **mid):
        root, root_key = _mint("mis-issuing root", ca=True, usage="sign")
        mid_cert, mid_key = _mint("mis-issued mid", root, root_key, **mid)
        leaf, leaf_key = _mint(HOST, mid_cert, mid_key, ca=False)
        return root, [leaf, mid_cert], leaf_key

    def test_an_intermediate_with_no_basic_constraints_that_may_sign_is_refused(self, tmp_path):
        root, chain, key = self._world(ca=None, usage="sign")
        assert _a_client_holding(tmp_path, root, chain, key) is not None
        assert _judge(chain, key) == (
            '"CN=mis-issued mid" signed a certificate of the upload and does not say it is a CA (it carries no basic constraints with CA set), '
            "so a client that holds the CA above it refuses the chain"
        )

    @pytest.mark.parametrize(
        "mid",
        [{"ca": None, "usage": None}, {"ca": False, "usage": "sign"}, {"ca": True, "usage": "tls"}],
        ids=["no constraints, no usage", "CA false", "CA true, may not sign"],
    )
    def test_what_the_verifier_already_refused_is_still_refused(self, mid, tmp_path):
        root, chain, key = self._world(**mid)
        assert _a_client_holding(tmp_path, root, chain, key) is not None
        assert _judge(chain, key) is not None

    @pytest.mark.parametrize("usage", [None, "sign"], ids=["no key usage", "may sign"])
    def test_a_proper_intermediate_is_accepted(self, usage, tmp_path):
        root, chain, key = self._world(ca=True, usage=usage)
        assert _a_client_holding(tmp_path, root, chain, key) is None
        assert _judge(chain, key) is None

    def test_with_the_root_in_the_upload_the_verifier_says_it_itself(self, tmp_path):
        root, chain, key = self._world(ca=None, usage="sign")
        assert _a_client_holding(tmp_path, root, chain + [root], key) is not None
        assert _judge(chain + [root], key) is not None

    def test_a_root_of_the_upload_is_the_clients_anchor_and_is_judged_as_they_judge_it(self, tmp_path):
        """A self-signed top with no basic constraints: a client that holds it as its anchor is the oracle, and Jen says what that client says."""
        root, root_key = _mint("an old root", ca=None, usage="sign")
        leaf, leaf_key = _mint(HOST, root, root_key, ca=False)
        client = _a_client_holding(tmp_path, root, [leaf, root], leaf_key)
        assert (_judge([leaf, root], leaf_key) is None) == (client is None)

    def test_a_server_certificate_alone_signs_nothing_and_is_not_asked(self):
        root, root_key = _mint("a private root", ca=True)
        leaf, leaf_key = _mint(HOST, root, root_key, ca=None)
        assert _judge([leaf], leaf_key) is None


class TestAnExpiredCertificateOnNoPathDecidesNothing:
    """The independent review's #1: the box holds only the superseded, expired copy of the root; the upload is the honest chain plus an expired CA that signed nothing."""

    @pytest.fixture()
    def world(self, box_store):
        root, root_key = _mint("stale-store root", ca=True)
        old, _ = _mint("stale-store root", key=root_key, ca=True, start=-400, end=-5)
        mid, mid_key = _mint("stale-store mid", root, root_key, ca=True)
        leaf, leaf_key = _mint(HOST, mid, mid_key, ca=False)
        stray, _ = _mint("an unrelated expired CA", ca=True, start=-400, end=-5)
        box_store.append(_pem(old))
        return root, leaf, mid, stray, leaf_key, root_key

    @pytest.mark.parametrize("where", [1, 2], ids=["between the two", "after the chain"])
    def test_wherever_it_is_pasted(self, where, world, tmp_path):
        root, leaf, mid, stray, key, _ = world
        chain = [leaf, mid]
        chain.insert(where, stray)
        assert _a_client_holding(tmp_path, root, chain, key) is None
        assert _judge(chain, key) is None

    def test_in_the_ca_bundle_field(self, world):
        root, leaf, mid, stray, key, _ = world
        assert _judge([leaf], key, _pem(mid) + _pem(stray)) is None

    def test_an_expired_certificate_that_is_on_the_path_is_still_refused_and_it_alone_is_named(self, world, tmp_path):
        root, leaf, mid, stray, key, root_key = world
        late_mid, late_key = _mint("stale-store mid", root, root_key, ca=True, start=-400, end=-5)
        late_leaf, late_leaf_key = _mint(HOST, late_mid, late_key, ca=False)
        assert _a_client_holding(tmp_path, root, [late_leaf, late_mid, stray], late_leaf_key) is not None
        said = _judge([late_leaf, late_mid, stray], late_leaf_key)
        assert "certificate has expired" in said and '"CN=stale-store mid" expired on' in said
        assert "unrelated" not in said

    def test_an_upload_whose_own_root_has_expired_is_still_refused(self, world, tmp_path):
        root, leaf, mid, stray, key, root_key = world
        old, _ = _mint("stale-store root", key=root_key, ca=True, start=-400, end=-5)
        assert _a_client_holding(tmp_path, old, [leaf, mid, old], key) is not None
        assert "certificate has expired" in _judge([leaf, mid, old], key)


class TestTheBoundsComeFirst:
    """AV31."""

    BLOCK = "-----BEGIN CERTIFICATE-----\nAAAA{n}\n-----END CERTIFICATE-----\n"

    def test_the_count_is_taken_before_any_certificate_is_parsed_or_loaded(self):
        """Twenty-one blocks that are not certificates at all: the answer is the count, so nothing tried to read one."""
        from jen.routes.settings.security import validate_cert_material

        said = validate_cert_material(
            "".join(self.BLOCK.format(n=n) for n in range(21)), "-----BEGIN PRIVATE KEY-----", None
        )
        assert said == (
            "the upload carries 21 certificates and a server presents at most 20: upload the certificate and the chain above it, not a bundle of CAs"
        )

    def test_one_certificate_pasted_many_times_is_one_certificate(self):
        from jen.routes.settings.security import _distinct_pems

        root, root_key = _mint("a private root", ca=True)
        leaf, leaf_key = _mint(HOST, root, root_key, ca=False)
        text = _pem(leaf) + _pem(root) * 400
        assert len(_distinct_pems(text)) == 2
        assert len(_distinct_pems(text.replace("\n", "\r\n"))) == 2
        # the server presents what was pasted, so the repeats are few here: four hundred of them is a handshake no client completes, and Jen says so
        assert _judge([leaf] + [root] * 5, leaf_key) is None

    def test_an_upload_over_the_size_bound_is_refused_before_anything_else(self, monkeypatch):
        from jen.routes.settings import security

        def never(*a, **k):
            raise AssertionError("the upload was read")

        monkeypatch.setattr(security, "_distinct_pems", never)
        said = security.validate_cert_material(self.BLOCK.format(n=0) * 30000, "-----BEGIN PRIVATE KEY-----", None)
        assert said.startswith("the upload is ") and "characters" in said and "not a bundle of CAs" in said

    def test_the_duplicates_are_dropped_in_one_pass(self):
        """The source: no comparison of each certificate pasted with every one before it is left ahead of the count."""
        import inspect

        from jen.routes.settings import security

        body = inspect.getsource(security.chain_refusal)
        assert body.index("_MOST_CERTIFICATES") < body.index("load_pem_x509_certificate")
        assert body.index("_MOST_CERTIFICATES") < body.index("certs[:i]")


class TestTheImageNamesItsCaStore:
    """AV7. The check reads the box's CA store; with `--no-install-recommends` nothing in the image's package list promised one."""

    def test_the_dockerfile_installs_ca_certificates(self):
        import re

        block = re.search(
            r"apt-get install.*?apt-get clean", (ROOT / "Dockerfile").read_text(encoding="utf-8"), re.S
        ).group(0)
        assert re.search(r"^\s+ca-certificates \\$", block, re.M), block


class TestRemovingTheCertificateRemovesTheKeptCopies:
    """AV10."""

    def test_the_route_names_the_prev_copy_of_each_file(self):
        import ast

        tree = ast.parse((ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8"))
        route = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "remove_cert")
        loop = next(n for n in ast.walk(route) if isinstance(n, ast.For))
        assert '".prev"' in ast.unparse(loop.iter).replace("'", '"')

    def test_the_copies_go_before_the_live_files(self):
        """(Q238, AW11) A copy that will not go stopped the route after the four live files were gone: no audit row, no restart, and a site with no certificate."""
        import ast

        tree = ast.parse((ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8"))
        route = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "remove_cert")
        loop = next(n for n in route.body if isinstance(n, ast.For))
        order = eval(compile(ast.Expression(loop.iter), "iter", "eval"), {"live": ["a", "b"]})
        assert order == ["a.prev", "b.prev", "a", "b"]

    def test_every_file_and_its_copy_goes(self, tmp_path, monkeypatch):
        """The loop itself, run over a real directory: the four live files and the four `.prev` copies."""
        import ast

        tree = ast.parse((ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8"))
        route = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "remove_cert")
        names = ["jen.crt", "jen.key", "ca.crt", "combined.pem"]
        for name in names:
            (tmp_path / name).write_text("x")
            (tmp_path / (name + ".prev")).write_text("x")

        class Ext:
            SSL_CERT, SSL_KEY, SSL_CA, SSL_COMBINED = (str(tmp_path / n) for n in names)

        live = [Ext.SSL_CERT, Ext.SSL_KEY, Ext.SSL_CA, Ext.SSL_COMBINED]
        assign = next(n for n in route.body if isinstance(n, ast.Assign) and n.targets[0].id == "live")
        loop = next(n for n in route.body if isinstance(n, ast.For))
        scope = {"extensions": Ext}
        exec(compile(ast.Module([assign], []), "live", "exec"), scope)
        assert scope["live"] == live
        import os

        for f in eval(compile(ast.Expression(loop.iter), "iter", "eval"), scope):
            if os.path.exists(f):
                os.remove(f)
        assert list(tmp_path.iterdir()) == []


class TestTheTopNamesTheKeyThatSignedIt:
    """(Q238, AW40) The box's store holds the issuer of the top. The top may name the key that signed it by an identifier, and a client looks the issuer up by
    that before it checks a signature. An identifier is of a KEY, and every copy of the issuer that verifies the top holds the same key - so this one is decided."""

    def _world(self, top_aki, box_ski="derived", root_ski="derived"):
        from cryptography.hazmat.primitives.asymmetric import ec

        root_key = ec.generate_private_key(ec.SECP256R1())
        pick = lambda how: _derived(root_key) if how == "derived" else how  # noqa: E731
        root, _ = _mint("identified root", key=root_key, ca=True, ski=pick(root_ski))
        copy, _ = _mint("identified root", key=root_key, ca=True, ski=pick(box_ski))
        mid, mid_key = _mint("identified mid", root, root_key, ca=True, aki=pick(top_aki))
        leaf, leaf_key = _mint(HOST, mid, mid_key, ca=False)
        return root, copy, [leaf, mid], leaf_key

    def test_an_identifier_of_the_key_that_signed_it_is_accepted(self, box_store, tmp_path):
        root, copy, chain, key = self._world("derived")
        box_store.append(_pem(root))
        assert _a_client_holding(tmp_path, root, chain, key) is None
        assert _judge(chain, key) is None

    def test_an_identifier_of_another_key_is_refused(self, box_store, tmp_path):
        root, copy, chain, key = self._world(b"\x01" * 20)
        box_store.append(_pem(root))
        assert _a_client_holding(tmp_path, root, chain, key) is not None
        assert _judge(chain, key) == (
            '"CN=identified mid" names the key that signed it by an identifier, and the certificate this box trusts as "CN=identified root" does not carry that '
            "identifier, so a client that holds that CA does not find the issuer. If the CA's own certificate carries it, add that certificate to the upload"
        )

    def test_a_renewal_under_the_same_key_that_states_its_identifier_another_way(self, box_store, tmp_path):
        """The honest case 7.1.0-beta.5 refused: the box's copy states an identifier of its own, the clients' root states the derived one, and the top names that."""
        root, copy, chain, key = self._world("derived", box_ski=b"\x02" * 20)
        box_store.append(_pem(copy))
        assert _a_client_holding(tmp_path, root, chain, key) is None
        assert _judge(chain, key) is None

    def test_the_boxs_copy_states_the_identifier_the_top_names(self, box_store, tmp_path):
        stated = b"\x03" * 20
        root, copy, chain, key = self._world(stated, box_ski=stated, root_ski=stated)
        box_store.append(_pem(copy))
        assert _a_client_holding(tmp_path, root, chain, key) is None
        assert _judge(chain, key) is None

    def test_a_copy_that_states_no_identifier_is_not_compared(self, box_store, tmp_path):
        root, copy, chain, key = self._world(b"\x04" * 20, box_ski=None, root_ski=None)
        box_store.append(_pem(copy))
        assert _a_client_holding(tmp_path, root, chain, key) is None
        assert _judge(chain, key) is None

    def test_the_root_in_the_upload_decides_it_whatever_the_box_holds(self, box_store, tmp_path):
        """The remedy the sentence names: the stated limit is a CA whose identifier is neither derived nor the one the box's copy states."""
        stated = b"\x05" * 20
        root, copy, chain, key = self._world(stated, box_ski=b"\x06" * 20, root_ski=stated)
        box_store.append(_pem(copy))
        assert _judge(chain, key).startswith('"CN=identified mid" names the key that signed it')
        assert _a_client_holding(tmp_path, root, chain + [root], key) is None
        assert _judge(chain + [root], key) is None


class TestTheScanOfTheUploadOnlyMovesForward:
    """(Q238, AW1) The bound of Q237 was on characters and the pattern beside it was quadratic in the markers pasted."""

    def test_many_markers_with_no_end_cost_nothing(self):
        import time

        from jen.routes.settings.security import _distinct_pems, validate_cert_material

        text = "-----BEGIN CERTIFICATE-----\n" * 35700
        assert len(text) < 1_000_000
        started = time.monotonic()
        assert _distinct_pems(text) == []
        said = validate_cert_material(text, "-----BEGIN PRIVATE KEY-----", None)
        assert time.monotonic() - started < 20, "it took 100 seconds and more before"
        assert said is not None

    def test_it_uses_no_pattern(self):
        import inspect

        from jen.routes.settings import security

        body = inspect.getsource(security._distinct_pems)
        assert "re." not in body and "import re" not in body and body.count(".find(") == 3

    def test_it_finds_what_the_pattern_found(self):
        import re

        from jen.routes.settings.security import _distinct_pems

        a, b = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
        for text in (
            "",
            a,
            b + a,
            f"{a}\nAA\n{b}",
            f"x{a}AA{b}y{a}BB{b}{a}AA{b}",
            f"{a}AA{a}BB{b}{a}CC",
            f"{a}\r\nAA\r\n{b}\n{a}\nAA\n{b}",
            f"{a}{b}{b}{a}",
        ):
            seen: dict = {}
            for found in re.finditer(re.escape(a) + ".*?" + re.escape(b), text, re.S):
                seen.setdefault("".join(found.group(0).split()), found.group(0))
            assert _distinct_pems(text) == list(seen.values()), text

    def test_a_trusted_certificate_block_is_refused_by_name(self):
        """(Q238, AW12) OpenSSL's loader reads it and Jen's checks do not: the certificate the server presents and the one judged could be two."""
        from jen.routes.settings.security import validate_cert_material

        root, root_key = _mint("a private root", ca=True)
        leaf, leaf_key = _mint(HOST, root, root_key, ca=False)
        trusted = (
            _pem(leaf)
            .replace("BEGIN CERTIFICATE", "BEGIN TRUSTED CERTIFICATE")
            .replace("END CERTIFICATE", "END TRUSTED CERTIFICATE")
        )
        for cert_data, bundle in ((trusted + _pem(leaf), None), (_pem(leaf), trusted)):
            assert validate_cert_material(cert_data, _key(leaf_key), bundle).startswith(
                "the upload carries a TRUSTED CERTIFICATE block"
            )


class TestAnExtensionThisLibraryCannotReadIsNotARefusal:
    """(Q238, AW41) `_not_a_ca` runs after the verifier completed the handshake. A basic-constraints BOOLEAN in BER is `CA:TRUE` to OpenSSL and a `ValueError`
    here, and the upload was refused for it. The certificate is stood in for: building that encoding needs a signature over hand-written DER."""

    def test_it_answers_nothing(self):
        from jen.routes.settings import security

        class Unreadable:
            subject = issuer = None

            @property
            def extensions(self):
                raise ValueError("error parsing asn1 value")

        class Leaf:
            pass

        real = security._signed_by
        try:
            security._signed_by = lambda cert, issuer: False
            assert security._not_a_ca([Leaf(), Unreadable()], 1) is None
        finally:
            security._signed_by = real
