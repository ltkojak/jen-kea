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

Where things live (Jen host, `<config_dir>/ssl` — never touched by upgrades):
  kea-ca.crt / kea-ca.key           the CA (EC P-256, 10 years)
  jen-kea-client.pem / .key         Jen's client cert (5 years, clientAuth)
  kea-servers/<id>-<service>.crt    a copy of each issued server cert, so
                                    Health can watch its expiry without SSH
  kea-servers/<id>-<service>.key    its key (0600, v5.69.0-beta.18, Q187): what the host was
                                    given, so an https change that fails can put the
                                    certificate the daemon had back. `.crt.prev` / `.key.prev`
                                    hold the pair BEFORE the last commit - one generation, kept
                                    until the operation succeeds (retire_previous). The live
                                    pair is ALWAYS what Jen last installed on the host
                                    (commit_issued runs after install_tls succeeded)
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
import hashlib
import ipaddress
import logging
import os
import socket
import ssl
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from jen import extensions
from jen.services.certs import commit_file_set, write_atomically

logger = logging.getLogger(__name__)

SSL_DIR = os.path.join(extensions.CONFIG_DIR, "ssl")
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


def server_key_path(server_id, service: str) -> str:
    return os.path.join(SSL_DIR, "kea-servers", f"{server_id}-{service}.key")


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
    # Key first, then cert: a reader that finds a cert always finds its key - and the pair is installed as a SET (v5.68.0-beta.16, Q151).
    commit_file_set([(key_path, _key_pem(key), 0o600), (crt, _cert_pem(cert), 0o644)])
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


def issue_server_cert(
    server: dict, service: str, bind_address: str, ca: tuple[str, str] | None = None, commit: bool = True
) -> dict:
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
    files = {
        "ca.crt": _cert_pem(ca_cert).decode(),
        "server.crt": _cert_pem(cert).decode(),
        "server.key": _key_pem(key).decode(),
    }
    if commit:
        commit_issued(server.get("id"), service, files)
    return files


class HostRecordLost(OSError):
    """Q189 (AE2): Jen cannot record which pair a host holds - neither as its live copy nor as the `.prev` pair a marker points at. The caller records a `remote-unknown` incident (the
    database is then the durable record the SSL directory could not hold) and `host_material` answers None for that server and service until a later commit succeeds."""


def commit_issued(server_id, service: str, files: dict) -> None:
    """Make Jen's own pair for this server and service `files` (Q187, AC2): the key and the certificate that names it, installed as ONE set, and the pair they replace kept as `.prev`. The
    setup route calls this only AFTER the host has accepted the pair (`install_tls`), so the live pair is always what Jen last put on the host - never a pair that was issued and not
    installed - and `.prev` is always what the host had immediately before THIS operation, which is what a failure puts back. (An earlier version kept the first `.prev` across attempts;
    that restored material from before an earlier operation that had since stood.)

    Q189 (AE2): Jen's record of what a host holds IS the exact payload that host accepted, or "unknown" - never a copy made by the mechanism that failed. When the write fails,
    `commit_file_set` has already copied the LIVE pair to `.prev`, and that is not what the host holds (the host holds `files`): so `files` itself is written as `.prev` and the pair is
    marked stale (`host_material` then answers `.prev`), and the OSError is re-raised. When even that cannot be written the error is `HostRecordLost`."""
    copy_path, key_path = server_copy_path(server_id, service), server_key_path(server_id, service)
    try:
        _ensure_dir(os.path.dirname(copy_path))
        commit_file_set([(key_path, files["server.key"], 0o600), (copy_path, files["server.crt"], 0o644)])
    except OSError as failure:
        _record_host_pair(server_id, service, files, failure)
        raise
    clear_stale(server_id, service)  # the host was just given exactly this pair: Jen's copy agrees again


def _record_host_pair(server_id, service: str, files: dict, cause: BaseException) -> None:
    """Q189 (AE2): record `files` - the payload the host accepted - as `.prev`, THEN mark the live pair stale (in that order: a marker over a `.prev` that is not the host's pair is the bug).
    Raises `HostRecordLost` (from `cause`) when either cannot be written; whatever `.prev` is left is removed so a copy of the live pair does not stand as the host's."""
    crt, key = server_copy_path(server_id, service), server_key_path(server_id, service)
    try:
        commit_file_set(
            [(key + ".prev", files["server.key"], 0o600), (crt + ".prev", files["server.crt"], 0o644)], keep_prev=False
        )
        mark_stale(server_id, service)
    except OSError as lost:
        for path in (crt + ".prev", key + ".prev"):
            with contextlib.suppress(OSError):
                os.unlink(path)
        raise HostRecordLost(
            f"Jen cannot record which certificate server {server_id} {service} holds ({type(lost).__name__})"
        ) from cause


def _material(crt: str, key: str) -> dict | None:
    """The `install-tls` payload of a certificate and key on disk - {"ca.crt", "server.crt", "server.key"} (PEM str) - or None unless BOTH load and the key is the certificate's (a pair that does not
    belong together is never put on a host). The CA is the live one (a rotation re-issues every pair)."""
    try:
        cert, private = load_cert(crt), load_key(key)
        spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        if cert.public_key().public_bytes(*spki) != private.public_key().public_bytes(*spki):
            return None
        with open(crt, "rb") as f:
            crt_pem = f.read().decode()
        with open(key, "rb") as f:
            key_pem = f.read().decode()
        with open(ca_paths()[0], "rb") as f:
            ca_pem = f.read().decode()
    except (OSError, ValueError, TypeError):
        return None
    return {"ca.crt": ca_pem, "server.crt": crt_pem, "server.key": key_pem}


def stage_issued(server_id, service: str, files: dict) -> None:
    """Q188 (AD2): Jen's own recovery state is committed BEFORE the host is touched. `.prev` becomes a copy of the live pair - what the host has now, so what a failure puts back; a stale `.prev`
    from an older operation is removed, never kept as the rollback source - and the new pair is written beside the live one as `.staged` (private files). Nothing live changes. Raises
    OSError when it cannot be written: the caller stops before `install_tls`, with nothing changed on the host."""
    from jen.services.private_files import write_private_file

    crt, key = server_copy_path(server_id, service), server_key_path(server_id, service)
    _ensure_dir(os.path.dirname(crt))
    held = host_material(server_id, service)  # Q189: what Jen can say the HOST holds - not what happens to be live
    if held is None:
        # nothing is the host's previous material (a first https socket, a certificate installed by hand) - or Jen does not know which pair it is: either way there is nothing to put back
        retire_previous(server_id, service)
        live_crt = live_key = None
    elif is_stale(server_id, service):
        # Jen's live pair is KNOWN not to be the host's: `.prev` is (and stays) what the host has, so it must not be overwritten with the live pair
        live_crt = live_key = None
    else:
        try:
            with open(crt, "rb") as f:
                live_crt = f.read()
            with open(key, "rb") as f:
                live_key = f.read()
        except OSError:
            live_crt = live_key = None
    if live_crt is not None and live_key is not None:
        commit_file_set(
            [(key, live_key, 0o600), (crt, live_crt, 0o644)]
        )  # an identity commit: leaves `.prev` equal to the live pair (the one place `.prev` is made)
    write_private_file(key + ".staged", files["server.key"], 0o600)
    write_private_file(crt + ".staged", files["server.crt"], 0o644)


def promote_staged(server_id, service: str) -> None:
    """Q188 (AD2): the host accepted the staged pair - make it Jen's live pair, as ONE set (the key before the certificate that names it), leaving `.prev` as `stage_issued` made it. Raises OSError
    (the live pair untouched: `commit_file_set` puts back what it replaced) when it cannot; the route then reinstalls the previous material on the host and stops."""
    crt, key = server_copy_path(server_id, service), server_key_path(server_id, service)
    with open(key + ".staged", "rb") as f:
        staged_key = f.read()
    with open(crt + ".staged", "rb") as f:
        staged_crt = f.read()
    commit_file_set([(key, staged_key, 0o600), (crt, staged_crt, 0o644)], keep_prev=False)
    discard_staged(server_id, service)


def discard_staged(server_id, service: str) -> None:
    for p in (server_copy_path(server_id, service) + ".staged", server_key_path(server_id, service) + ".staged"):
        with contextlib.suppress(OSError):
            os.unlink(p)


def fingerprint(path: str) -> str | None:
    """SHA-256 of the certificate's DER encoding - what a TLS peer presents, comparable with `presented_fingerprint`."""
    try:
        return hashlib.sha256(load_cert(path).public_bytes(serialization.Encoding.DER)).hexdigest()
    except (OSError, ValueError, TypeError):
        return None


def presented_fingerprint(
    host: str, port: int, client: tuple[str, str] | None = None, timeout: float = 8.0
) -> str | None:
    """The SHA-256 of the certificate the listener at host:port PRESENTS (DER), or None when it cannot be read. Trust is not judged here - the Kea probe does that; this only says WHICH
    certificate answered, so a completed setup can be reported only when it is the one Jen holds (Q188, AD2)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        if client:
            context.load_cert_chain(*client)
        with socket.create_connection((host, port), timeout=timeout) as raw, context.wrap_socket(raw) as tls:
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return None
    return hashlib.sha256(der).hexdigest() if der else None


def previous_material(server_id, service: str) -> dict | None:
    """The pair the host had BEFORE the last commit for this server and service, or None when there is none to put back: a first https socket, a certificate installed by hand, or one
    installed before Jen kept the key."""
    return _material(server_copy_path(server_id, service) + ".prev", server_key_path(server_id, service) + ".prev")


def current_material(server_id, service: str) -> dict | None:
    """The pair Jen last put on the host (the live local pair), for re-asserting it after an install whose outcome is not known (a lost reply)."""
    return _material(server_copy_path(server_id, service), server_key_path(server_id, service))


def restore_previous(server_id, service: str) -> bool:
    """The pair the host was given before is back on the host (the caller installed it): make Jen's own copies agree and retire the `.prev` pair. All-or-nothing; False when there is none."""
    crt, key = server_copy_path(server_id, service), server_key_path(server_id, service)
    try:
        with open(crt + ".prev", "rb") as f:
            old_crt = f.read()
        with open(key + ".prev", "rb") as f:
            old_key = f.read()
        commit_file_set([(key, old_key, 0o600), (crt, old_crt, 0o644)], keep_prev=False)
    except OSError as failure:
        # the host has the previous pair (the caller installed `.prev`) and Jen's live copy is not it: `.prev` stays the host's truth until a later commit
        try:
            mark_stale(server_id, service)
        except OSError as lost:
            raise HostRecordLost(
                f"Jen cannot record which certificate server {server_id} {service} holds ({type(lost).__name__})"
            ) from failure
        return False
    retire_previous(server_id, service)
    return True


def discard_local_record(server_id, service: str) -> None:
    """Q189 (AE6c): drop Jen's own copy of the pair for this server and service - the live pair, `.prev`, `.staged` and the stale marker. For a failed https attempt on a daemon whose sockets do
    not reference Jen's TLS files: the host's files at the fixed paths are unreferenced, and a copy Jen keeps for them is a record of an endpoint that does not exist."""
    for base in (server_copy_path(server_id, service), server_key_path(server_id, service)):
        for suffix in ("", ".prev", ".staged"):
            with contextlib.suppress(OSError):
                os.unlink(base + suffix)
    clear_stale(server_id, service)


def retire_previous(server_id, service: str) -> None:
    """The operation that replaced the pair succeeded: the pair before it is no longer needed - and any known divergence between Jen's copy and the host is over."""
    for p in (server_copy_path(server_id, service) + ".prev", server_key_path(server_id, service) + ".prev"):
        with contextlib.suppress(OSError):
            os.unlink(p)
    clear_stale(server_id, service)


def _stale_path(server_id, service: str) -> str:
    return server_copy_path(server_id, service) + ".stale"


def mark_stale(server_id, service: str) -> None:
    """Q188 (second pass, finding 3): Jen's LIVE pair is KNOWN not to be what the host holds (the host took the previous pair back and Jen's own copy could not follow). Until the next successful
    commit the host's truth is `.prev`, not the live pair, and `host_material` says so. A marker file, so it survives a restart; it holds no secret."""
    from jen.services.private_files import write_private_file

    write_private_file(_stale_path(server_id, service), b"live differs from the host; .prev is the host's\n", 0o600)


def clear_stale(server_id, service: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(_stale_path(server_id, service))


def is_stale(server_id, service: str) -> bool:
    return os.path.exists(_stale_path(server_id, service))


def _open_incident_categories(server_id, service: str):
    """The categories of the unresolved recovery incidents for this server and service, or None when the incident record cannot be read (Q189, AE2). The database is the durable record the SSL
    directory could not hold."""
    try:
        from jen.services import kea_changeset

        return {
            i.get("category")
            for i in kea_changeset.recovery_incidents(strict=True)
            if str(i.get("server_id")) == str(server_id) and i.get("service") == service
        }
    except Exception as e:
        logger.warning(
            f"kea_tls: the recovery incidents could not be read ({type(e).__name__}); host_material answers unknown"
        )
        return None


def host_material(server_id, service: str) -> dict | None:
    """The pair the HOST holds, as far as Jen can tell, or None when Jen does not know (Q189, AE2) - never a guess:
    * an unresolved `remote-unknown` or `tls-not-restored` incident for this server and service: unknown, whatever the files say (the second says the host holds a certificate Jen did not
      mean to leave there - its live copy may well be a different pair);
    * the incident record cannot be read: unknown;
    * the live pair is marked stale: the `.prev` pair (unknown when it does not load);
    * a `tls-local-stale` incident with no marker (the marker could not be written): unknown;
    * otherwise its live pair (unknown when it does not load)."""
    categories = _open_incident_categories(server_id, service)
    if categories is None or categories & {"remote-unknown", "tls-not-restored"}:
        return None
    if is_stale(server_id, service):
        return previous_material(server_id, service)
    if "tls-local-stale" in categories:
        return None
    return current_material(server_id, service)


def ca_consistent() -> bool:
    """Is Jen's CA a PAIR - the certificate at `kea-ca.crt` belongs to the key at `kea-ca.key`? A promotion whose restore also failed can leave them apart, and every certificate issued from
    that CA is then signed by a key its certificate does not name."""
    crt, key = ca_paths()
    try:
        spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        return load_cert(crt).public_key().public_bytes(*spki) == load_key(key).public_key().public_bytes(*spki)
    except (OSError, ValueError, TypeError):
        return False


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
    commit_file_set([(key_path, _key_pem(key), 0o600), (pem, _cert_pem(cert), 0o644)])
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


# ── the rotation's inventory (Q189, AE1) ────────────────────────────────────
#
# A multi-host operation enumerates its targets from the CONFIGURATION - every endpoint Jen dials - and refuses when its record of any one of them is missing or unreadable. The rotation
# used to take its targets from a listing of the local copies (v5.29.0): a missing copy dropped a live https endpoint from the rotation, and an unlistable directory read as "nothing to
# rotate" - a rotation that "succeeded" cut Jen off from every daemon still presenting CA-A material.

INVENTORY_SERVICES = ("dhcp4", "dhcp6", "d2")
_DAEMON_LABEL = {"dhcp4": "kea-dhcp4", "dhcp6": "kea-dhcp6", "d2": "kea-dhcp-ddns"}


class RotationInventory:
    """`targets, refusals = inventory` unpacks the two things a rotation needs: `targets` are `(server, service, bind_address)` for every https endpoint Jen holds a complete record of;
    `refusals` are sentences, empty when the rotation may go ahead. `external` are the https endpoints whose certificate Jen's CA did not issue (named, left alone, never silently included
    or skipped), `stale` the copies of a server or service that is no longer an https endpoint (listed, ignored)."""

    def __init__(self, targets, refusals, external, stale, endpoints=frozenset()):
        self.targets, self.refusals, self.external, self.stale = targets, refusals, external, stale
        self.endpoints = frozenset(
            endpoints
        )  # every https endpoint Jen dials, (server id, service), whatever Jen holds for it - what a running rotation is compared with

    def __iter__(self):
        return iter((self.targets, self.refusals))


def _server_label(server: dict, service: str) -> str:
    return (
        f"{server.get('name') or 'Kea Server ' + str(server.get('id'))} {_DAEMON_LABEL.get(service, 'kea-' + service)}"
    )


def record_state(server_id, service: str) -> tuple[str, str]:
    """What Jen holds for one server and service, as `(state, why)`: `("jen", "")` - a certificate and key that load, are a pair and were issued by Jen's live CA; `("external", "")` - a pair
    whose certificate no Jen CA issued; `("refuse", why)` - anything Jen cannot rotate safely: copy missing, key missing, unreadable, malformed, not a pair, issued by an earlier Jen CA."""
    crt, key = server_copy_path(server_id, service), server_key_path(server_id, service)
    try:
        with open(crt, "rb") as f:
            crt_pem = f.read()
    except FileNotFoundError:
        return "refuse", "its certificate copy is missing"
    except OSError:
        return "refuse", "its certificate copy cannot be read"
    try:
        with open(key, "rb") as f:
            key_pem = f.read()
    except FileNotFoundError:
        return "refuse", "its key is missing"
    except OSError:
        return "refuse", "its key cannot be read"
    try:
        cert = x509.load_pem_x509_certificate(crt_pem)
        private = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError):
        return "refuse", "its certificate or key is malformed"
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if cert.public_key().public_bytes(*spki) != private.public_key().public_bytes(*spki):
        return "refuse", "its certificate and key are not a pair"
    if issued_by(crt, ca_paths()[0]):
        return "jen", ""
    if any(a.value == "Jen" for a in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)):
        return "refuse", "its certificate was issued by an earlier Jen CA, not the current one"
    return "external", ""


def rotation_inventory(servers, url_for=None) -> RotationInventory:
    """The ONE source of a rotation's targets (Q189, AE1): for every configured server and each of dhcp4 / dhcp6 / d2, the URL Jen dials (`url_for(server, service)`, default the Kea
    client's `_endpoint_for`); every `https://` endpoint is a target when Jen holds a complete record of its certificate (`record_state`) and a REFUSAL, with a sentence, when it does not.
    A certificate no Jen CA issued is an administrator-managed endpoint: named in `external`, left alone. A directory that cannot be listed is a refusal naming it - never an empty set.
    A copy for a server or service that is not an https endpoint now is `stale`: said, ignored. Pure (no network): only Jen's configuration and Jen's own files."""
    if url_for is None:
        from jen.services import kea as _kea

        def url_for(server, service):
            ep = _kea._endpoint_for(server, service)
            return ep[0] if isinstance(ep, tuple) else ""

    targets, refusals, external = [], [], []
    try:
        listed = issued_server_copies(strict=True)
    except OSError as e:
        listed = []
        refusals.append(
            f"Jen could not read its certificate directory {_copies_dir()} ({type(e).__name__}, errno {getattr(e, 'errno', '?')}), so it cannot tell which servers it issued certificates to; fix its permissions before rotating"
        )
    endpoints = set()
    for server in servers or []:
        for service in INVENTORY_SERVICES:
            url = (url_for(server, service) or "").strip()
            if not url.lower().startswith("https://"):
                continue
            sid = server.get("id")
            endpoints.add((str(sid), service))
            label = _server_label(server, service)
            state, why = record_state(sid, service)
            if state == "jen":
                from urllib.parse import urlparse

                targets.append((server, service, urlparse(url).hostname or ""))
            elif state == "external":
                external.append(f"{label} ({url})")
            else:
                refusals.append(
                    f"{label} is an https endpoint at {url} and Jen has no complete record of its certificate ({why}); remove the direct socket and set it up again so Jen issues "
                    "and keeps a certificate for it, or point Jen at a socket that is not on its CA, before rotating"
                )
    stale = [f"{c['server_id']}-{c['service']}" for c in listed if (str(c["server_id"]), c["service"]) not in endpoints]
    return RotationInventory(targets, refusals, external, stale, endpoints)


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
    try:
        write_atomically(staged["ca_key"], _key_pem(ca_key), 0o600)
        write_atomically(staged["ca_cert"], _cert_pem(ca_cert), 0o644)
        write_atomically(staged["client_key"], _key_pem(client_key), 0o600)
        write_atomically(staged["client_cert"], _cert_pem(client_cert), 0o644)
    except BaseException:
        discard_rotation(staged)  # (second pass, Q188: a staging that stopped half written leaves no key behind)
        raise
    return staged


def _live_for(staged_path: str) -> str:
    return staged_path[: -len(_STAGE_SUFFIX)] if staged_path.endswith(_STAGE_SUFFIX) else staged_path


def commit_rotation(staged: dict) -> None:
    """Promote the staged files to live as ONE set (v5.68.0-beta.16, Q151): `certs.commit_file_set` stages every member again, snapshots the live
    members without moving them (each previous file kept as a `.prev` COPY), replaces them keys first, then certs, and on any failure puts every
    replaced member back byte-for-byte. It used to `os.replace` the live file to `.prev` and then the staged one over it, four times in a row,
    after the remote servers had already moved to the new CA: a failure at any step left a mixed or missing set."""
    members = []
    for k, mode in (("ca_key", 0o600), ("ca_cert", 0o644), ("client_key", 0o600), ("client_cert", 0o644)):
        with open(staged[k], "rb") as f:
            members.append((_live_for(staged[k]), f.read(), mode))
    commit_file_set(members)
    discard_rotation(staged)
    logger.info("kea_tls: rotated the Kea CA and Jen's client certificate")


def discard_rotation(staged: dict) -> None:
    for p in staged.values():
        with contextlib.suppress(OSError):
            os.unlink(p)


def _copies_dir() -> str:
    return os.path.join(SSL_DIR, "kea-servers")


def issued_server_copies(strict: bool = False) -> list[dict]:
    """[{server_id, service, path, days_left}] for every server cert copy
    Jen keeps — Health's input. A directory that is not there lists as none; one that
    cannot be LISTED (a permission, a bad mount) lists as none too unless `strict`
    (Q189, AE1): then the OSError is raised, so an unreadable inventory is a refusal
    and never an empty set."""
    d = _copies_dir()
    out = []
    try:
        names = sorted(os.listdir(d))
    except FileNotFoundError:
        return out
    except OSError:
        if strict:
            raise
        return out
    for n in names:
        if not n.endswith(".crt") or "-" not in n:
            continue
        sid, service = n[:-4].split("-", 1)
        path = os.path.join(d, n)
        out.append({"server_id": sid, "service": service, "path": path, "days_left": days_left(path)})
    return out
