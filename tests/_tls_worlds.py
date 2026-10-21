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

STATES = ("absent", "malformed", "unreadable", "mismatched", "earlier-jen", "other-ca")


def _write(path, data):
    path = pathlib.Path(path)
    if path.is_dir():
        path.rmdir()
    if path.exists() or path.is_symlink():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("ascii"))


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
