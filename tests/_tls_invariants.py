"""
tests/_tls_invariants.py
────────────────────────
v5.69.0-beta.21 (Q190, AF0) - the parts of the TLS invariants that do not depend on a harness, shared by every test file that checks them after a scenario
(`tests/test_kea_tls_rotation.py`'s `Lab.check_invariants`, `tests/test_direct_socket_lock.py`'s `tls_world` teardown):

  * a certificate is JEN-ISSUED when a Jen CA is its issuer - judged by the certificate the HOST holds, never by Jen's own files (the files are what the invariant checks);
  * T4: nothing a request printed contains a PEM, a key, a configured password, or a `user:password` string from a configured address.
"""

from urllib.parse import urlsplit


def issued_by_a_jen_ca(cert_pem: str) -> bool:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except ValueError:
        return False
    return any(a.value == "Jen" for a in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME))


def secrets_of(passwords=(), urls=(), key_pems=()) -> list:
    """Every secret a harness configured: the passwords, the password and the `user:password` of every address that carries user-info, and the first body line of every private key."""
    out = [p for p in passwords if p]
    for url in urls:
        parts = urlsplit(url)
        if parts.password:
            out.append(parts.password)
        if parts.username or parts.password:
            out.append(f"{parts.username or ''}:{parts.password or ''}")
    for pem in key_pems:
        body = [ln for ln in pem.splitlines() if ln and "-----" not in ln]
        out.extend(body[:1])
    return out


def printed_secret(printed: str, secrets) -> str | None:
    """The first secret found in `printed` (a PEM marker counts), or None."""
    for needle in ["PRIVATE KEY", "BEGIN CERTIFICATE", *secrets]:
        if needle and needle in printed:
            return needle
    return None
