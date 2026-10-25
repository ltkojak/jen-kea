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
    "aki-not-ski",  # Q197 (AM1 a): a self-issued root whose AuthorityKeyIdentifier keyid is not its own SubjectKeyIdentifier - OpenSSL does not treat it as self-issued, no chain reaches it
    # the second pass (F5): the issuer and serial forms of an AKI are value families too - the library accepts them and both stacks reject them
    "aki-wrong-serial",
    "aki-issuer-other-name",
    "aki-keyid-wrong-serial",
    # Q198 (AN3): OpenSSL compares the FIRST DirectoryName of the issuer list and skips every other kind of name
    "aki-two-dirnames-wrong-first",
    "aki-dns-first-wrong-dirname",
)

#: Q196 (AL1): the VERIFIER states - a CA that parses, pairs, is a CA by purpose and validity, self-signed, and still not one a real verifier accepts what Jen issues from, because of a constraint
#: `cryptography` can express: an Extended Key Usage that leaves out a purpose, a name constraint that excludes every name. (The terminal check is the verifier; this list is what it was run on.)
VERIFIER_CA_STATES = (
    "eku-clientauth-only",  # an sslserver certificate from it is "unsuitable"
    "eku-serverauth-only",  # ... and an sslclient one
    "eku-codesigning",  # neither
    "name-constraints-exclude-all",  # no name verifies
    # Q197 (AM1 b): the EKU VALUE families - executed against openssl 3.2.4 and the library; a verifier that reads anyExtendedKeyUsage as "any purpose" is not what the daemon's library does
    "eku-anyeku",  # anyExtendedKeyUsage ALONE: OpenSSL ignores it on a CA, so neither purpose is named
    "eku-anyeku-and-serverauth",  # sslserver is named, sslclient is not
    "eku-serverauth-and-codesigning",  # ... the same, the other way round
    "eku-unknown-oid",  # an OID that is no purpose at all
    "eku-anyeku-and-unknown",
)
#: ... and the constraints a verifier ACCEPTS: they must stay healthy (no EKU, serverAuth+clientAuth, anyExtendedKeyUsage, a CA name-constrained to its OWN domain, policy constraints, inhibit-any-policy)
VERIFIER_OK_STATES = (
    "eku-none",
    "eku-server-and-client",
    "eku-anyeku-server-and-client",  # (Q197: anyExtendedKeyUsage beside BOTH purposes is healthy - the purposes are named)
    "aki-keyid-matches-ski",
    "aki-keyid-issuer-serial",
    "no-ski-with-aki-keyid",  # nothing to compare: both stacks chain to it
    # Q198 (AN3, executed against openssl 3.2.4 and the library): the first DirectoryName is the root's own, or the list holds no DirectoryName at all
    "aki-two-dirnames-right-first",
    "aki-dnsname-issuer",
    "aki-uri-issuer",
    "aki-dns-first-right-dirname",
    "issuer-string-type-differs",  # the issuer is a PrintableString and the subject the same text as a UTF8String: one name
    "name-constraints-permit-own-domain",
    "policy-constraints",
    "inhibit-any-policy",
    # the second pass of Q196: CAs an operator really owns, which the web-PKI profile rejected and OpenSSL accepts (the profile is relaxed for them), and a CA whose SKI is not the key's SHA-1
    "bc-non-critical",
    "eku-critical-server-and-client",
    "certificate-policies-critical",
    "ski-not-sha1",
)
#: ... CAs the verifier is STRICTER about than OpenSSL and offers no switch for (documented in the admin guide, pinned here as damaged): a leading-dot or directoryName name constraint, a key that is
#: not P-256/384/521 or RSA >= 2048
VERIFIER_STRICTER_STATES = (
    "name-constraints-leading-dot",
    "name-constraints-directory-name",
    "key-secp256k1",
    "key-brainpool",
    # Q197 (executed against openssl 3.2.4 and the library): the shapes OpenSSL accepts and the library does not, documented in the admin guide's table of Jen-stricter shapes
    "aki-issuer-serial-only",  # an AKI that names the issuer and serial and no keyid
    "crl-distribution-points-critical",
    "empty-subject-critical-san",
    "policy-mappings-critical",
    "aki-all-none",  # an AuthorityKeyIdentifier with no field set: the library demands the key identifier, openssl chains to it
)
#: Q197 (executed against openssl 3.2.4, `tests/test_kea_tls_rotation.py::TestTheValueFamiliesAgainstTheRealCli`): EVERY state where Jen calls the CA damaged and `openssl verify` accepts a leaf of it for both
#: purposes - the admin guide's "Shapes Jen's verifier is stricter about than OpenSSL". (An Ed25519 CA is also here in spirit: the CLI cannot be asked, Jen cannot issue from it.)
JEN_STRICTER_THAN_OPENSSL = frozenset(VERIFIER_STRICTER_STATES) | {"tampered-signature", "no-basic-constraints"}
#: ... and the words the admin guide's table uses for each, so a row cannot be dropped from it unseen
STRICTER_LABELS = {
    "name-constraints-leading-dot": "leading-dot name constraint",
    "name-constraints-directory-name": "directoryName name constraint",
    "key-secp256k1": "secp256k1",
    "key-brainpool": "Brainpool",
    "aki-issuer-serial-only": "issuer and serial number but no key identifier",
    "crl-distribution-points-critical": "critical CRLDistributionPoints",
    "empty-subject-critical-san": "empty subject",
    "policy-mappings-critical": "critical policyMappings",
    "aki-all-none": "no field set",
    "tampered-signature": "tampered self-signature",
    "no-basic-constraints": "no Basic Constraints",
}

#: ... and CAs the throwaway (DNS-only) probe accepts but that cannot sign for a particular SERVER's address: the REAL leaf Jen issues is verified before it is returned
REAL_LEAF_STATES = ("name-constraints-ip-outside", "name-constraints-ip-inside")

#: a CA that WORKS but that Q194's first draft called damaged: no KeyUsage extension at all (RFC 5280: unrestricted - what `openssl req -x509` makes by default)
OPERATOR_CA_STATES = ("no-key-usage",)


#: Q197: the VALUE FAMILIES of the extension classes a CA certificate carries, by class - the rule "enumerate values, not only classes". Q196's enumeration built every class once with a default value
#: and so had no row for anyExtendedKeyUsage alone or an AuthorityKeyIdentifier that names another key. `tests/test_kea_tls_worlds.py` asserts the AKI and EKU families have at least three rows each,
#: and that every state here is built by `semantic_ca` and judged by a table.
EXTENSION_VALUE_FAMILIES = {
    "ExtendedKeyUsage": (
        "eku-none",
        "eku-server-and-client",
        "eku-anyeku-server-and-client",
        "eku-clientauth-only",
        "eku-serverauth-only",
        "eku-codesigning",
        "eku-anyeku",
        "eku-anyeku-and-serverauth",
        "eku-serverauth-and-codesigning",
        "eku-unknown-oid",
        "eku-anyeku-and-unknown",
        "eku-critical-server-and-client",
    ),
    "AuthorityKeyIdentifier": (
        "aki-keyid-matches-ski",
        "aki-keyid-issuer-serial",
        "no-ski-with-aki-keyid",
        "aki-not-ski",
        "aki-wrong-serial",
        "aki-issuer-other-name",
        "aki-keyid-wrong-serial",
        "aki-issuer-serial-only",
        "aki-two-dirnames-wrong-first",
        "aki-two-dirnames-right-first",
        "aki-dnsname-issuer",
        "aki-uri-issuer",
        "aki-dns-first-right-dirname",
        "aki-dns-first-wrong-dirname",
        "aki-all-none",
    ),
    "SubjectKeyIdentifier": ("ski-not-sha1",),
    # the structure around the extensions: validity, the signature, the issuer, the key, an encoding the library reads as a duplicate
    "Validity": ("expired", "not-yet-valid"),
    "SignatureAndIssuer": ("tampered-signature", "issuer-not-subject", "issuer-string-type-differs"),
    "ExtensionEncoding": ("duplicate-extension",),
    "SubjectPublicKey": ("unsupported-key", "key-secp256k1", "key-brainpool"),
    "BasicConstraints": ("not-ca", "no-basic-constraints", "bc-non-critical"),
    "KeyUsage": ("no-key-cert-sign", "no-key-usage"),
    "NameConstraints": (
        "name-constraints-exclude-all",
        "name-constraints-permit-own-domain",
        "name-constraints-leading-dot",
        "name-constraints-directory-name",
        "name-constraints-ip-outside",
        "name-constraints-ip-inside",
    ),
    "PolicyConstraints": ("policy-constraints",),
    "InhibitAnyPolicy": ("inhibit-any-policy",),
    "CertificatePolicies": ("certificate-policies-critical",),
    "CRLDistributionPoints": ("crl-distribution-points-critical",),
    "SubjectAlternativeName": ("empty-subject-critical-san",),
    "PolicyMappings": ("policy-mappings-critical",),
}


def semantic_ca(kind: str):
    """(certificate, key) of a CA in the semantic state `kind`: objects, not PEM - `semantic_ca_pem` has the bytes."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    assert (
        kind
        in SEMANTIC_CA_STATES
        + OPERATOR_CA_STATES
        + VERIFIER_CA_STATES
        + VERIFIER_OK_STATES
        + VERIFIER_STRICTER_STATES
        + REAL_LEAF_STATES
    ), kind
    any_eku = x509.ObjectIdentifier("2.5.29.37.0")
    key = {
        "unsupported-key": lambda: ed25519.Ed25519PrivateKey.generate(),
        "key-secp256k1": lambda: ec.generate_private_key(ec.SECP256K1()),
        "key-brainpool": lambda: ec.generate_private_key(ec.BrainpoolP256R1()),
    }.get(kind, kea_tls._new_key)()
    name = kea_tls._name(f"Jen Kea CA semantic {kind}")
    if kind == "empty-subject-critical-san":
        name = x509.Name([])
    issuer = kea_tls._name("an issuer that is not the subject") if kind == "issuer-not-subject" else name
    if kind == "issuer-string-type-differs":
        from cryptography.x509.name import _ASN1Type
        from cryptography.x509.oid import NameOID

        # the same text, a different ASN.1 string type: X509_NAME_cmp, the chain verifier and `Name.__eq__` call it one name; the DER bytes differ
        issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Jen", _type=_ASN1Type.PrintableString),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, f"Jen Kea CA semantic {kind}"[:64], _type=_ASN1Type.PrintableString
                ),
            ]
        )
    serial = x509.random_serial_number()
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
        .serial_number(serial)
        .not_valid_before(before)
        .not_valid_after(after)
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key()) if kind.startswith("aki-") else None
    aki = {
        "aki-keyid-matches-ski": x509.AuthorityKeyIdentifier(ski.digest if ski else None, None, None),
        "aki-keyid-issuer-serial": x509.AuthorityKeyIdentifier(
            ski.digest if ski else None, [x509.DirectoryName(name)], serial
        ),
        "no-ski-with-aki-keyid": x509.AuthorityKeyIdentifier(os.urandom(20), None, None),
        "aki-not-ski": x509.AuthorityKeyIdentifier(os.urandom(20), None, None),
        "aki-wrong-serial": x509.AuthorityKeyIdentifier(None, [x509.DirectoryName(name)], serial + 1),
        "aki-issuer-other-name": x509.AuthorityKeyIdentifier(
            ski.digest if ski else None, [x509.DirectoryName(kea_tls._name("an issuer that is not this root"))], serial
        ),
        "aki-keyid-wrong-serial": x509.AuthorityKeyIdentifier(
            ski.digest if ski else None, [x509.DirectoryName(name)], serial + 1
        ),
        "aki-issuer-serial-only": x509.AuthorityKeyIdentifier(None, [x509.DirectoryName(name)], serial),
        "aki-two-dirnames-wrong-first": x509.AuthorityKeyIdentifier(
            ski.digest if ski else None,
            [x509.DirectoryName(kea_tls._name("an issuer that is not this root")), x509.DirectoryName(name)],
            serial,
        ),
        "aki-two-dirnames-right-first": x509.AuthorityKeyIdentifier(
            ski.digest if ski else None,
            [x509.DirectoryName(name), x509.DirectoryName(kea_tls._name("an issuer that is not this root"))],
            serial,
        ),
        "aki-dnsname-issuer": x509.AuthorityKeyIdentifier(
            ski.digest if ski else None, [x509.DNSName("ca.invalid")], serial
        ),
        "aki-uri-issuer": x509.AuthorityKeyIdentifier(
            ski.digest if ski else None, [x509.UniformResourceIdentifier("http://ca.invalid/")], serial
        ),
        "aki-dns-first-right-dirname": x509.AuthorityKeyIdentifier(
            ski.digest if ski else None, [x509.DNSName("a.invalid"), x509.DirectoryName(name)], serial
        ),
        "aki-dns-first-wrong-dirname": x509.AuthorityKeyIdentifier(
            ski.digest if ski else None,
            [x509.DNSName("a.invalid"), x509.DirectoryName(kea_tls._name("an issuer that is not this root"))],
            serial,
        ),
        "aki-all-none": x509.AuthorityKeyIdentifier(None, None, None),
    }.get(kind)
    if aki is not None:
        if kind != "no-ski-with-aki-keyid":
            builder = builder.add_extension(ski, critical=False)
        builder = builder.add_extension(aki, critical=False)
    if kind != "no-basic-constraints":
        builder = builder.add_extension(
            x509.BasicConstraints(ca=kind != "not-ca", path_length=None if kind == "not-ca" else 0),
            critical=kind != "bc-non-critical",
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
    from cryptography.x509.oid import ExtendedKeyUsageOID as EKU
    from cryptography.x509.oid import NameOID

    extra = {
        "eku-clientauth-only": x509.ExtendedKeyUsage([EKU.CLIENT_AUTH]),
        "eku-serverauth-only": x509.ExtendedKeyUsage([EKU.SERVER_AUTH]),
        "eku-codesigning": x509.ExtendedKeyUsage([EKU.CODE_SIGNING]),
        "eku-server-and-client": x509.ExtendedKeyUsage([EKU.SERVER_AUTH, EKU.CLIENT_AUTH]),
        "eku-anyeku": x509.ExtendedKeyUsage([any_eku]),
        "eku-anyeku-server-and-client": x509.ExtendedKeyUsage([any_eku, EKU.SERVER_AUTH, EKU.CLIENT_AUTH]),
        "eku-anyeku-and-serverauth": x509.ExtendedKeyUsage([any_eku, EKU.SERVER_AUTH]),
        "eku-serverauth-and-codesigning": x509.ExtendedKeyUsage([EKU.SERVER_AUTH, EKU.CODE_SIGNING]),
        "eku-unknown-oid": x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.2.3.4.5")]),
        "eku-anyeku-and-unknown": x509.ExtendedKeyUsage([any_eku, x509.ObjectIdentifier("1.2.3.4.5")]),
        "eku-critical-server-and-client": x509.ExtendedKeyUsage([EKU.SERVER_AUTH, EKU.CLIENT_AUTH]),
        "certificate-policies-critical": x509.CertificatePolicies(
            [x509.PolicyInformation(x509.ObjectIdentifier("2.5.29.32.0"), None)]
        ),
        "ski-not-sha1": x509.SubjectKeyIdentifier(os.urandom(20)),
        "crl-distribution-points-critical": x509.CRLDistributionPoints(
            [x509.DistributionPoint([x509.UniformResourceIdentifier("http://crl.invalid/ca.crl")], None, None, None)]
        ),
        "empty-subject-critical-san": x509.SubjectAlternativeName([x509.DNSName("ca.invalid")]),
        "policy-mappings-critical": x509.UnrecognizedExtension(x509.ObjectIdentifier("2.5.29.33"), b"\x30\x00"),
    }.get(kind)
    if extra is not None:
        builder = builder.add_extension(
            extra,
            critical=kind
            in (
                "eku-critical-server-and-client",
                "certificate-policies-critical",
                "crl-distribution-points-critical",
                "empty-subject-critical-san",
                "policy-mappings-critical",
            ),
        )
    constraint = {
        "name-constraints-exclude-all": x509.NameConstraints(
            permitted_subtrees=None, excluded_subtrees=[x509.DNSName("")]
        ),
        "name-constraints-permit-own-domain": x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None
        ),
        "name-constraints-leading-dot": x509.NameConstraints(
            permitted_subtrees=[x509.DNSName(".lan")], excluded_subtrees=None
        ),
        "name-constraints-directory-name": x509.NameConstraints(
            permitted_subtrees=[x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Jen")]))],
            excluded_subtrees=None,
        ),
        "name-constraints-ip-outside": x509.NameConstraints(
            permitted_subtrees=[x509.IPAddress(ipaddress.ip_network("172.16.0.0/12"))], excluded_subtrees=None
        ),
        "name-constraints-ip-inside": x509.NameConstraints(
            permitted_subtrees=[x509.IPAddress(ipaddress.ip_network("10.0.0.0/8"))], excluded_subtrees=None
        ),
        "policy-constraints": x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None),
        "inhibit-any-policy": x509.InhibitAnyPolicy(0),
    }.get(kind)
    if constraint is not None:
        builder = builder.add_extension(constraint, critical=True)
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


def replace_live_ca():
    """A NEW Jen CA at the live paths - the certificate and the key ONLY: the client pair and the server copies stay from the CA before, which is what "the CA changed underneath" looks like. (Q197, AM6 a:
    the product replaces a CA only through a staged rotation - `stage_rotation`, probes, `commit_rotation` - and no longer has an `ensure_ca(force=True)`; a test that needs the CA ALONE to change
    builds it here.)"""
    key = kea_tls._new_key()
    cert = kea_tls._build_ca(key, "Jen Kea CA replaced underneath")
    crt, key_path = kea_tls.ca_paths()
    pathlib.Path(key_path).write_bytes(kea_tls._key_pem(key))
    pathlib.Path(crt).write_bytes(kea_tls._cert_pem(cert))
    return cert, key


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
