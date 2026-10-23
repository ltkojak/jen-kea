"""
tests/_tls_worlds.py
────────────────────
Q192 (AH0): the states a file `jen/services/kea_tls.py` reads can be in, as BUILDERS - shared by the Lab-based tests (`tests/test_kea_tls_rotation.py`), the generated matrix
(`tests/test_kea_tls_worlds.py`) and the setup/remove worlds (`tests/test_direct_socket_lock.py`'s harness).

A *state* is applied to ONE file in a directory that already holds a healthy baseline (a CA, Jen's client pair, a server pair for server 1's dhcp4). Nothing here knows about Flask, a route or
the fake daemon: it writes bytes.

  absent        the file is not there
  malformed     the file holds text that is not PEM
  unreadable    the path is a DIRECTORY (every `open()` of it raises; on a platform that honours modes this is what a permission error looks like)
  mismatched    a valid file that is NOT its partner's (a certificate whose key is not the one beside it, or a key that is not the certificate's)
  earlier-jen   a certificate (and its key) issued by an EARLIER Jen CA - one that is not the live CA
  other-ca      a certificate (and its key) issued by a CA that is not Jen's at all
"""

import os
import pathlib

from jen.services import kea_tls

STATES = ("absent", "malformed", "unreadable", "mismatched", "earlier-jen", "other-ca", "invalid-key")


def _write(path, data):
    path = pathlib.Path(path)
    if path.is_dir():
        path.rmdir()
    if path.exists() or path.is_symlink():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("ascii"))


def invalid_public_key(cert_pem: bytes) -> bytes:
    """The same certificate with ONE byte of its public key point flipped: valid PEM, valid DER, it PARSES - and `cert.public_key()` raises `ValueError: Invalid key` (Q192, second pass finding 1)."""
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    bad = bytearray(der)
    bad[der.find(spki) + len(spki) - 3] ^= 0xFF
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(bytes(bad)) + b"-----END CERTIFICATE-----\n"


def absent(path):
    path = pathlib.Path(path)
    if path.is_dir():
        path.rmdir()
    elif path.exists() or path.is_symlink():
        path.unlink()


def malformed(path):
    _write(path, "-----BEGIN NOT A THING-----\nnot pem at all\n-----END NOT A THING-----\n")


def unreadable(path):
    absent(path)
    pathlib.Path(path).mkdir(parents=True)


def another_key_pem() -> bytes:
    return kea_tls._key_pem(kea_tls._new_key())


def earlier_jen_ca():
    """A CA named like Jen's (O=Jen) with a different key - the CA a copy made before a rotation was issued by."""
    key = kea_tls._new_key()
    return kea_tls._build_ca(key, "Jen Kea CA earlier-host 2020-01-01"), key


def other_ca():
    """A CA that is not Jen's: no O=Jen."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    key = kea_tls._new_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "an administrator's CA")])
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def issued_pair(ca, client: bool, cn="a leaf", sans=()):
    """(certificate PEM bytes, key PEM bytes) of a leaf issued by `ca` = (cert, key)."""
    key = kea_tls._new_key()
    leaf = kea_tls._leaf(ca[0], ca[1], key, cn, list(sans), client=client)
    return kea_tls._cert_pem(leaf), kea_tls._key_pem(key)


#: Q194 (AJ1): the SEMANTIC states of a CA - the certificate parses, the key is its key, and it is still not a certificate-signing authority in ONE specific way. Q192's states were syntactic
#: (absent, malformed, unreadable, mismatched ...); none of them asked what the certificate is FOR.
SEMANTIC_CA_STATES = (
    "not-ca",  # BasicConstraints ca=False
    "no-basic-constraints",
    "no-key-cert-sign",  # KeyUsage present, keyCertSign off
    "expired",
    "not-yet-valid",
    "tampered-signature",  # one byte of the signature flipped: it still parses
    "issuer-not-subject",
    "unsupported-key",  # an Ed25519 pair: a pair, but not a kind Jen's CA is made of
    "duplicate-extension",  # (second pass) two BasicConstraints: it parses as PEM and `cert.extensions` raises - a read must say "damaged", never raise
)

#: a CA that WORKS but that Q194's first draft called damaged: no KeyUsage extension at all (RFC 5280: unrestricted - what `openssl req -x509` makes by default)
OPERATOR_CA_STATES = ("no-key-usage",)


def semantic_ca(kind: str):
    """(certificate, key) of a CA in the semantic state `kind`: objects, not PEM - `semantic_ca_pem` has the bytes."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519

    assert kind in SEMANTIC_CA_STATES + OPERATOR_CA_STATES, kind
    key = ed25519.Ed25519PrivateKey.generate() if kind == "unsupported-key" else kea_tls._new_key()
    name = kea_tls._name(f"Jen Kea CA semantic {kind}")
    issuer = kea_tls._name("an issuer that is not the subject") if kind == "issuer-not-subject" else name
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    before, after = now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=3650)
    if kind == "expired":
        before, after = now - datetime.timedelta(days=400), now - datetime.timedelta(days=1)
    elif kind == "not-yet-valid":
        before, after = now + datetime.timedelta(days=2), now + datetime.timedelta(days=3650)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
    )
    if kind != "no-basic-constraints":
        builder = builder.add_extension(
            x509.BasicConstraints(ca=kind != "not-ca", path_length=None if kind == "not-ca" else 0), critical=True
        )
    if kind != "no-key-usage":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=kind != "no-key-cert-sign",
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    cert = builder.sign(key, None if kind == "unsupported-key" else hashes.SHA256())
    if kind == "tampered-signature":
        cert = x509.load_pem_x509_certificate(_flip_last_byte_of_the_signature(kea_tls._cert_pem(cert)))
    if kind == "duplicate-extension":
        cert = x509.load_pem_x509_certificate(duplicate_an_extension(kea_tls._cert_pem(cert), keyusage_oid_last=0x0F))
    return cert, key


def duplicate_an_extension(cert_pem: bytes, *, keyusage_oid_last: int = 0x0F, into: int = 0x13) -> bytes:
    """The same certificate with ONE extension's OID rewritten to another it already carries (default: KeyUsage 2.5.29.15 -> BasicConstraints 2.5.29.19, the same length): valid PEM, valid DER, it PARSES,
    and `cert.extensions` raises `DuplicateExtension` - an `Exception`, not a `ValueError`. (`keyusage_oid_last` names the OID's last byte: 0x0F KeyUsage, 0x25 ExtendedKeyUsage.)"""
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)
    needle = bytes([0x06, 0x03, 0x55, 0x1D, keyusage_oid_last])
    assert der.count(needle) == 1, "the certificate carries exactly one such extension"
    bad = der.replace(needle, bytes([0x06, 0x03, 0x55, 0x1D, into]))
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(bad) + b"-----END CERTIFICATE-----\n"


def _flip_last_byte_of_the_signature(cert_pem: bytes) -> bytes:
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    der = bytearray(x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER))
    der[-1] ^= (
        0x01  # the signature is the last thing in the DER: the certificate parses, its signature no longer verifies
    )
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(bytes(der)) + b"-----END CERTIFICATE-----\n"


def semantic_ca_pem(kind: str) -> tuple[bytes, bytes]:
    cert, key = semantic_ca(kind)
    return kea_tls._cert_pem(cert), kea_tls._key_pem(key)


def stage_semantic_prepared(kind: str) -> dict:
    """A prepared rotation (`stage_rotation`'s four `.next` files) whose CA is replaced by the semantic CA `kind` - and, where the CA can sign, with a client certificate that CA CORRECTLY signed (the
    reviewer's world: a `ca=False` pair, a valid client certificate under it, and every check Q192 had passes)."""
    staged = kea_tls.stage_rotation()
    cert, key = semantic_ca(kind)
    pathlib.Path(staged["ca_cert"]).write_bytes(kea_tls._cert_pem(cert))
    pathlib.Path(staged["ca_key"]).write_bytes(kea_tls._key_pem(key))
    if kind != "unsupported-key":
        client_key = kea_tls._new_key()
        leaf = kea_tls._leaf(cert, key, client_key, "jen client under a CA that cannot sign", [], client=True)
        pathlib.Path(staged["client_cert"]).write_bytes(kea_tls._cert_pem(leaf))
        pathlib.Path(staged["client_key"]).write_bytes(kea_tls._key_pem(client_key))
    return staged


def apply_state(state: str, cert_path, key_path, *, which: str, client: bool, ca_key_for_mismatch=None):
    """Put the file `which` ("cert" or "key") of the pair at (cert_path, key_path) into `state`. `earlier-jen` / `other-ca` replace the WHOLE pair (a consistent pair from the wrong issuer)."""
    target = cert_path if which == "cert" else key_path
    if state == "absent":
        absent(target)
    elif state == "malformed":
        malformed(target)
    elif state == "unreadable":
        unreadable(target)
    elif state == "mismatched":
        if which == "cert":
            # a certificate that is valid and issued by the live CA - for a DIFFERENT key
            ca = kea_tls._load_ca() if ca_key_for_mismatch is None else ca_key_for_mismatch
            cert_pem, _unused = issued_pair(ca, client=client)
            _write(cert_path, cert_pem)
        else:
            _write(key_path, another_key_pem())
    elif state == "invalid-key":
        if which != "cert":
            raise AssertionError("only a certificate has a public key to corrupt")
        _write(cert_path, invalid_public_key(pathlib.Path(cert_path).read_bytes()))
    elif state in ("earlier-jen", "other-ca"):
        ca = earlier_jen_ca() if state == "earlier-jen" else other_ca()
        cert_pem, key_pem = issued_pair(ca, client=client)
        _write(cert_path, cert_pem)
        _write(key_path, key_pem)
    else:
        raise AssertionError(state)


def tree(root) -> dict:
    """Every file under `root` as {relative path: bytes} (a directory standing where a file belongs is listed as b'<dir>') - what 'nothing changed' compares."""
    out = {}
    root = str(root)
    for dirpath, dirs, files in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        for d in list(dirs):
            full = os.path.join(dirpath, d)
            if os.path.realpath(full) != os.path.join(os.path.realpath(dirpath), d):
                dirs.remove(
                    d
                )  # a link or a junction to somewhere else (an ALIAS of Jen's folder): it is a name, not a second copy of the files
                out[os.path.normpath(os.path.join(rel_dir, d))] = b"<alias>"
            elif not os.listdir(full):
                out[os.path.normpath(os.path.join(rel_dir, d))] = b"<dir>"
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                out[os.path.normpath(os.path.join(rel_dir, name))] = pathlib.Path(path).read_bytes()
            except OSError:
                out[os.path.normpath(os.path.join(rel_dir, name))] = b"<unreadable>"
    return out
