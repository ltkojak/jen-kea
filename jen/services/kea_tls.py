"""
jen/services/kea_tls.py
───────────────────────
v5.29.0 (Q29, C1) — the Jen-managed private CA for Kea's https control
sockets. One CA on the Jen host issues one client certificate (Jen's
identity to every daemon) and one server certificate per (server,
daemon); the server material is pushed to the Kea host through the
helper's `install-tls` op (jen/services/kea_host.py::install_tls) and
the daemon's socket is written with `cert-required: true` — mutual TLS,
not the appearance of it.

Why a private CA and not Let's Encrypt: the Kea link needs CLIENT
certificates (that IS the security — a control socket that accepts any
client with the basic-auth password is only as strong as the password
crossing the wire), homelab management addresses are RFC 1918 IPs with
no public DNS name, and ACME issues server certs only. A CA Jen owns
issues both halves and can rotate them wholesale.

Where things live (Jen host, `/etc/jen/ssl` — never touched by upgrades):
  kea-ca.crt / kea-ca.key           the CA (EC P-256, 10 years)
  jen-kea-client.pem / .key         Jen's client cert (5 years, clientAuth)
  kea-servers/<id>-<service>.crt    a copy of each issued server cert, so
                                    Health can watch its expiry without SSH
Keys are written mode 0600 by the Jen service user through
certs.write_atomically (tmp + replace, previous file kept as `.prev`).
The CA key living on the Jen host is a recorded tradeoff — see
docs/ARCHITECTURE.md §3: a compromised service user already holds the
SSH key that pushes root-level config to every Kea host, so minting a
client cert adds no capability, only persistence, which `rotate_ca()`
revokes wholesale.

On the Kea host (written by the helper, fixed paths):
  /etc/kea/tls/<service>/ca.crt, server.crt, server.key

Pure cryptography; no Flask, no SSH. Everything here is deterministic
given the inputs except the keys and serial numbers.
"""

import contextlib
import ipaddress
import logging
import os
import socket
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from jen.services.certs import write_atomically

logger = logging.getLogger(__name__)

SSL_DIR = "/etc/jen/ssl"
CA_DAYS = 3650  # maintainer decision 2026-09-13: 10-year CA
LEAF_DAYS = 1826  # 5-year leaves
# The fixed layout the helper's install-tls op writes on a Kea host.
KEA_TLS_ROOT = "/etc/kea/tls"
_CLOCK_SKEW = timedelta(minutes=5)


# ── paths ───────────────────────────────────────────────────────────────────


def ca_paths() -> tuple[str, str]:
    return os.path.join(SSL_DIR, "kea-ca.crt"), os.path.join(SSL_DIR, "kea-ca.key")


def client_paths() -> tuple[str, str]:
    return os.path.join(SSL_DIR, "jen-kea-client.pem"), os.path.join(SSL_DIR, "jen-kea-client.key")


def server_copy_path(server_id, service: str) -> str:
    return os.path.join(SSL_DIR, "kea-servers", f"{server_id}-{service}.crt")


def remote_tls_paths(service: str) -> dict:
    """The three paths a daemon's https socket entry references — what
    kea_authoring.build_control_socket() takes as `tls`, and what
    apply_config() passes as `tls_paths` so a missing file is caught as
    `tlsmissing` before the daemon is restarted into a config it can't
    load."""
    d = f"{KEA_TLS_ROOT}/{service}"
    return {
        "trust_anchor": f"{d}/ca.crt",
        "cert_file": f"{d}/server.crt",
        "key_file": f"{d}/server.key",
        "cert_required": True,
    }


# ── primitives ──────────────────────────────────────────────────────────────


def _now() -> datetime:
    # cryptography wants naive UTC for the validity builder calls.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _new_key():
    return ec.generate_private_key(ec.SECP256R1())


def _key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Jen"), x509.NameAttribute(NameOID.COMMON_NAME, cn[:64])]
    )


def _hostname() -> str:
    try:
        return socket.gethostname() or "jen"
    except OSError:
        return "jen"


def _ensure_dir(path: str, mode: int = 0o750) -> None:
    os.makedirs(path, mode=mode, exist_ok=True)


def load_cert(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def cert_expiry(path: str) -> datetime | None:
    """notAfter as an aware UTC datetime, or None if the file is absent
    or isn't a PEM certificate."""
    try:
        return load_cert(path).not_valid_after_utc
    except (OSError, ValueError):
        return None


def days_left(path: str) -> int | None:
    exp = cert_expiry(path)
    if exp is None:
        return None
    return (exp - datetime.now(timezone.utc)).days


def issued_by(cert_path: str, ca_path: str) -> bool:
    """True iff the cert at `cert_path` was signed by the CA at `ca_path`
    (signature actually verified, not just the issuer name)."""
    try:
        cert = load_cert(cert_path)
        ca = load_cert(ca_path)
        cert.verify_directly_issued_by(ca)
        return True
    except Exception:  # OSError, ValueError, InvalidSignature, TypeError
        return False


# ── the CA ──────────────────────────────────────────────────────────────────


def _build_ca(key, cn: str):
    now = _now()
    name = _name(cn)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _CLOCK_SKEW)
        .not_valid_after(now + timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )


def ca_present() -> bool:
    crt, key = ca_paths()
    try:
        load_cert(crt)
        load_key(key)
        return True
    except (OSError, ValueError, TypeError):
        return False


def ensure_ca(force: bool = False) -> dict:
    """Create the CA if it isn't there (or `force`), idempotent
    otherwise. A cert without a loadable key (or vice versa) counts as
    absent — both halves are regenerated together; the previous files
    are kept as `.prev` by write_atomically. Returns
    {"cert": path, "key": path, "created": bool, "subject": cn}."""
    crt, key_path = ca_paths()
    if not force and ca_present():
        return {"cert": crt, "key": key_path, "created": False, "subject": _cn(crt)}
    _ensure_dir(SSL_DIR)
    key = _new_key()
    cn = f"Jen Kea CA {_hostname()} {datetime.now(timezone.utc):%Y-%m-%d}"
    cert = _build_ca(key, cn)
    # Key first, then cert: a reader that finds a cert always finds its key.
    write_atomically(key_path, _key_pem(key), 0o600)
    write_atomically(crt, _cert_pem(cert), 0o644)
    logger.info(f"kea_tls: {'rotated' if force else 'created'} the Kea CA at {crt}")
    return {"cert": crt, "key": key_path, "created": True, "subject": cn}


def _cn(cert_path: str) -> str:
    try:
        attrs = load_cert(cert_path).subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except (OSError, ValueError):
        return ""


def _load_ca():
    crt, key_path = ca_paths()
    return load_cert(crt), load_key(key_path)


def _leaf(ca_cert, ca_key, key, cn: str, sans: list, client: bool):
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _CLOCK_SKEW)
        .not_valid_after(now + timedelta(days=LEAF_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


def _san_for(value: str):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        return x509.DNSName(value)
    except ValueError:
        return None


# ── leaves ──────────────────────────────────────────────────────────────────


def issue_server_cert(server: dict, service: str, bind_address: str, ca: tuple[str, str] | None = None) -> dict:
    """Mint a server cert for `service` on `server`, SAN = the bind
    address (what Jen dials) plus the SSH host (IP or DNS name — the
    second name an operator might type as the URL), signed by the live
    CA (which must exist — call ensure_ca() first) or, for a staged
    rotation, by `ca = (cert_path, key_path)`. Keeps a copy of the cert
    under kea-servers/ for Health. Returns exactly the `files` payload
    the helper's install-tls op takes:
    {"ca.crt": pem, "server.crt": pem, "server.key": pem} (all str)."""
    ca_cert, ca_key = (load_cert(ca[0]), load_key(ca[1])) if ca else _load_ca()
    key = _new_key()
    sans, seen = [], set()
    for candidate in (bind_address, server.get("ssh_host", "")):
        san = _san_for(candidate)
        if san is not None and san.value not in seen:
            seen.add(san.value)
            sans.append(san)
    name = server.get("name") or f"Kea Server {server.get('id')}"
    cert = _leaf(ca_cert, ca_key, key, f"kea-{service} {name}", sans, client=False)
    copy_path = server_copy_path(server.get("id"), service)
    _ensure_dir(os.path.dirname(copy_path))
    write_atomically(copy_path, _cert_pem(cert), 0o644)
    return {
        "ca.crt": _cert_pem(ca_cert).decode(),
        "server.crt": _cert_pem(cert).decode(),
        "server.key": _key_pem(key).decode(),
    }


def client_cert_ok() -> bool:
    """True iff Jen's client cert exists, was signed by the CURRENT CA,
    its key loads, and it has more than 30 days left."""
    pem, key_path = client_paths()
    crt, _ = ca_paths()
    if not issued_by(pem, crt):
        return False
    try:
        load_key(key_path)
    except (OSError, ValueError, TypeError):
        return False
    left = days_left(pem)
    return left is not None and left > 30


def issue_client_cert(force: bool = False) -> dict:
    """Jen's own client certificate (clientAuth). Reissued when missing,
    not signed by the current CA, expiring, or `force`. Returns
    {"cert": path, "key": path, "issued": bool}."""
    pem, key_path = client_paths()
    if not force and client_cert_ok():
        return {"cert": pem, "key": key_path, "issued": False}
    ca_cert, ca_key = _load_ca()
    key = _new_key()
    cert = _leaf(ca_cert, ca_key, key, f"jen {_hostname()}", [], client=True)
    _ensure_dir(SSL_DIR)
    write_atomically(key_path, _key_pem(key), 0o600)
    write_atomically(pem, _cert_pem(cert), 0o644)
    logger.info(f"kea_tls: issued Jen's Kea client certificate at {pem}")
    return {"cert": pem, "key": key_path, "issued": True}


def rotate_ca() -> dict:
    """A new CA and a new client cert. Every server certificate issued by
    the old CA is now invalid from Jen's side (Jen no longer trusts the
    old CA) — the caller re-issues and re-pushes each one (step 4's
    Rotate flow); this function only does the Jen-host half. Returns
    {"ca": ensure_ca() result, "client": issue_client_cert() result}."""
    ca = ensure_ca(force=True)
    client = issue_client_cert(force=True)
    return {"ca": ca, "client": client}


# ── staged rotation (the route's "all servers or nothing" Rotate) ───────────

_STAGE_SUFFIX = ".next"


def stage_rotation() -> dict:
    """A new CA and a new client certificate written BESIDE the live
    files as `<name>.next` — nothing Jen trusts changes. The Rotate flow
    issues every server's new certificate from these, pushes, restarts
    and probes each server using them, and only then commit_rotation()s;
    any failure discard_rotation()s and the live CA was never touched.
    Returns {"ca_cert", "ca_key", "client_cert", "client_key"}: the
    staged paths."""
    _ensure_dir(SSL_DIR)
    ca_key = _new_key()
    ca_cert = _build_ca(ca_key, f"Jen Kea CA {_hostname()} {datetime.now(timezone.utc):%Y-%m-%d}")
    client_key = _new_key()
    client_cert = _leaf(ca_cert, ca_key, client_key, f"jen {_hostname()}", [], client=True)
    crt, key_path = ca_paths()
    pem, client_key_path = client_paths()
    staged = {
        "ca_cert": crt + _STAGE_SUFFIX,
        "ca_key": key_path + _STAGE_SUFFIX,
        "client_cert": pem + _STAGE_SUFFIX,
        "client_key": client_key_path + _STAGE_SUFFIX,
    }
    write_atomically(staged["ca_key"], _key_pem(ca_key), 0o600)
    write_atomically(staged["ca_cert"], _cert_pem(ca_cert), 0o644)
    write_atomically(staged["client_key"], _key_pem(client_key), 0o600)
    write_atomically(staged["client_cert"], _cert_pem(client_cert), 0o644)
    return staged


def _live_for(staged_path: str) -> str:
    return staged_path[: -len(_STAGE_SUFFIX)] if staged_path.endswith(_STAGE_SUFFIX) else staged_path


def commit_rotation(staged: dict) -> None:
    """Promote the staged files to live (each previous file kept as
    `.prev`). Keys first, then certs, so a reader that finds a new cert
    always finds its key."""
    for k in ("ca_key", "ca_cert", "client_key", "client_cert"):
        live = _live_for(staged[k])
        if os.path.exists(live):
            os.replace(live, live + ".prev")
        os.replace(staged[k], live)
    logger.info("kea_tls: rotated the Kea CA and Jen's client certificate")


def discard_rotation(staged: dict) -> None:
    for p in staged.values():
        with contextlib.suppress(OSError):
            os.unlink(p)


def issued_server_copies() -> list[dict]:
    """[{server_id, service, path, days_left}] for every server cert copy
    Jen keeps — Health's input."""
    d = os.path.join(SSL_DIR, "kea-servers")
    out = []
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return out
    for n in names:
        if not n.endswith(".crt") or "-" not in n:
            continue
        sid, service = n[:-4].split("-", 1)
        path = os.path.join(d, n)
        out.append({"server_id": sid, "service": service, "path": path, "days_left": days_left(path)})
    return out
