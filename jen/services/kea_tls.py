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
client cert adds no capability, only persistence, which a Rotate
revokes wholesale.

On the Kea host (written by the helper, fixed paths):
  /etc/kea/tls/<service>/ca.crt, server.crt, server.key

Pure cryptography; no Flask, no SSH. Everything here is deterministic
given the inputs except the keys and serial numbers.
"""

import contextlib
import glob
import hashlib
import ipaddress
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess  # nosec B404 - list-args only, a fixed `openssl verify` second opinion (Q196)
import tempfile
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import verification as x509_verification
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from jen import extensions
from jen.services.certs import (  # noqa: F401 - `write_atomically` is re-exported: the system scenarios and tests write identity files with it
    commit_file_set,
    write_atomically,
)

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


def _ensure_dir(path: str, mode: int = 0o700) -> None:
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


#: Q193 (AI3): the two actions that lead out of a damaged CA - the SAME words in Health, the Settings page, Rotate's refusal, the https setup's refusal and Prepare's: a sentence about a damaged CA names
#: these two and nothing that the damaged gate itself refuses.
DAMAGED_CA_ADVICE = (
    "restore the CA files from a backup, or replace the CA with Rotate Kea CA and tick the acknowledgement "
    "(a server that fails part-way cannot be put back on a damaged CA and would need its socket set up again)"
)

#: Q193 second pass (finding 4): what to do about an https endpoint Jen cannot classify while its CA is damaged. The https setup is refused until the CA is replaced, so "set it up again" is not on
#: offer; pointing the CA bundle at Jen's own CA file makes the endpoint Jen's for the replacement (an endpoint Jen verifies against its OWN CA file is a target whatever record it holds).
RECOVERY_OWN_CA_FIX = (
    "point the CA bundle under Settings → Kea at Jen's own CA file (kea-ca.crt in Jen's SSL folder, or a link to it) so the replacement treats the endpoint as Jen's, "
    "or restore the CA files from a backup"
)


class CaDamaged(Exception):
    """Q192 (AH2): Jen's CA is not usable and is NOT "absent" - one file missing, either unreadable or malformed, or a certificate and key that are not a pair - or it is absent in a world that
    shows it once existed (a client certificate, a server copy). Nothing ordinary may replace it: `ensure_ca` raises this instead of creating a new CA under existing https sockets, and
    `issue_server_cert` / `issue_client_cert` raise it instead of signing with something that cannot sign. `.why` names the damage (a file name and what is wrong with it - never a path's content)."""

    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


class NameRefused(Exception):
    """Q197 (AM2): Jen's CA is HEALTHY - the verifier accepts what it issues in general - but it cannot issue a certificate for THIS name (a name constraint that does not permit the address, a host name
    the verifier's DNS parser does not accept). Distinct from `CaDamaged` on purpose: the damaged-CA sentences send the operator to an acknowledgement for a CA that is not damaged. `.why` is the
    verifier's message; `.names` the names that failed, each tried alone."""

    def __init__(self, why: str, names: list):
        super().__init__(why)
        self.why = why
        self.names = list(names)


def _key_usage_may_be_absent(policy, cert, extension) -> None:
    """The ONE relaxation of the verifier's CA profile (Q194's decision, kept): RFC 5280 says a CA certificate with NO KeyUsage extension is not restricted - an operator's own `openssl req -x509` CA
    often has none and works - so absence passes; a KeyUsage that IS there must allow `keyCertSign`. (The strict profile requires the extension to be present.)"""
    if extension is not None and not extension.key_cert_sign:
        raise ValueError("KeyUsage lacks keyCertSign")


def _basic_constraints_ca_true(policy, cert, extension) -> None:
    if not extension.ca:
        raise ValueError("BasicConstraints ca is false")


def _eku_allows_the_purpose(policy, cert, extension) -> None:
    """Relaxing the CRITICALITY of a CA's Extended Key Usage must not relax its MEANING: the chain verifier enforces an EKU as a purpose through this very validator, and replacing it with nothing made
    a clientAuth-only CA verify for sslserver (executed). The CA's EKU must NAME the purpose being verified. The library also accepts `anyExtendedKeyUsage` as a wildcard; OpenSSL - the
    DAEMON's library - ignores it on a CA (executed, Q197: `anyEKU` alone, `anyEKU`+serverAuth for a client certificate and `anyEKU`+an unknown purpose all fail `openssl verify -purpose`
    with "unsuitable certificate purpose"), so a CA that relies on it is a CA the daemon will refuse, and the library's wildcard is not honoured here."""
    if extension is None:
        return  # no EKU on the CA: not restricted
    if policy.extended_key_usage not in extension:
        raise ValueError(
            "its Extended Key Usage does not name this purpose"
            + (
                " (anyExtendedKeyUsage does not count: OpenSSL ignores it on a CA)"
                if ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in extension
                else ""
            )
        )


def _verifier_policies():
    """The verifier's profile is the public web PKI's (CA/Browser Forum); Jen's question is whether the DAEMON's TLS stack accepts what Jen issues, so the profile is relaxed where RFC 5280 allows and the
    real stack (OpenSSL) accepts, and ONLY there: a KeyUsage may be absent (Q194's decision, `_key_usage_may_be_absent`); `policyConstraints` and `inhibitAnyPolicy` - valid CA extensions the web profile
    forbids - may be present; and the CRITICALITY of BasicConstraints, the Extended Key Usage and certificatePolicies is not judged (the web profile demands one; OpenSSL, RFC 5280 for a non-CA-critical
    reading and every operator's `openssl req -x509` do not) - BasicConstraints must still say `ca=True`, and an EKU is still enforced as a PURPOSE by the chain check. Everything else the verifier
    judges stands (name constraints, path length, algorithm strength, validity ...): the next constraint a review names is already covered. What stays STRICTER than OpenSSL, because the library offers no
    switch, is documented in the admin guide: a leading-dot or directoryName name constraint, a key that is not P-256/P-384/P-521 or RSA of 2048 bits or more."""
    agnostic = x509_verification.Criticality.AGNOSTIC
    ca = (
        x509_verification.ExtensionPolicy.webpki_defaults_ca()
        .may_be_present(x509.KeyUsage, agnostic, _key_usage_may_be_absent)
        .may_be_present(x509.PolicyConstraints, agnostic, None)
        .may_be_present(x509.InhibitAnyPolicy, agnostic, None)
        .require_present(x509.BasicConstraints, agnostic, _basic_constraints_ca_true)
        .may_be_present(x509.ExtendedKeyUsage, agnostic, _eku_allows_the_purpose)
        .may_be_present(x509.CertificatePolicies, agnostic, None)
    )
    return ca, x509_verification.ExtensionPolicy.webpki_defaults_ee()


def _probe_names(ca_cert) -> list[str]:
    """The DNS names a throwaway leaf is tried with: `probe.invalid`, and - when the CA is name-constrained to some domains - `probe.<each permitted domain>`. A CA that permits only its own domain is
    healthy for names inside it; one whose constraints exclude every name fails for all of them."""
    names = ["probe.invalid"]
    try:
        constraints = ca_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError):
        return names
    for subtree in constraints.permitted_subtrees or []:
        if isinstance(subtree, x509.DNSName) and subtree.value.lstrip("."):
            names.append(f"probe.{subtree.value.lstrip('.')}")
    return names[:8]  # (a CA with hundreds of permitted subtrees must not make every `ca_state` hundreds of probes)


def _verifier_message(error: BaseException) -> str:
    text = str(error) or type(error).__name__
    for noise in ("validation failed: ", "candidates exhausted: ", "Python extension validator failed: ValueError: "):
        text = text.replace(noise, "")
    text = (
        text.strip().rstrip(":").strip()[:200]
    )  # (Q198 AN5: a message that ends in a colon read "...: " in the sentence built from it)
    if "Neither EKU nor anyEKU" in text:
        text = f"its Extended Key Usage does not include this purpose ({text})"
    return text


def verify_probe(ca_cert, ca_key, client: bool):
    """Q196 (AL1): issue a throwaway leaf of ONE purpose from this CA - IN MEMORY, never written - and verify its chain with `cryptography.x509.verification`, the same chain verification a real TLS peer
    performs (server purpose: a server verifier for the name; client purpose: a client verifier). Returns ("", leaf) when some probe name verifies, else (the verifier's own message, the last leaf)."""
    now = datetime.now(timezone.utc)
    ca_policy, ee_policy = _verifier_policies()
    first, leaf = "", None
    for name in _probe_names(ca_cert):
        try:
            leaf = _leaf(
                ca_cert,
                ca_key,
                _new_key(),
                "jen-probe",
                [x509.DNSName(name)],
                client=client,
                now=now.replace(tzinfo=None),
            )
            builder = (
                x509_verification.PolicyBuilder()
                .store(x509_verification.Store([ca_cert]))
                .time(now)
                .extension_policies(ca_policy=ca_policy, ee_policy=ee_policy)
            )
            verifier = builder.build_client_verifier() if client else builder.build_server_verifier(x509.DNSName(name))
            verifier.verify(leaf, [])
            return "", leaf
        except (
            Exception
        ) as e:  # fail closed: whatever the check cannot do, or cannot read, is a CA that does not verify
            first = first or _verifier_message(e)
    return first, leaf


_ORACLE_VERDICTS: dict = {}


def ca_verifier_rejection(ca_cert, ca_key) -> str:
    """Q196 (AL1) - THE ORACLE. "" when a real chain verifier accepts a certificate issued from this CA for sslserver AND for sslclient; else "the verifier rejects certificates issued from it for <purpose>:
    <its own message>". Since beta.19 the reviewer found, one release at a time, the next property of a certificate `ca_identity` did not check (the pair, then the purpose, then the Extended Key Usage); X.509 has
    dozens (EKU, name constraints, policy constraints, path length, algorithm strength ...) and listing them is unbounded. The terminal check is the one the reviewer uses to PROVE a finding - a verifier -
    and the library Jen pins ships it, so "healthy" now means "a real verifier accepts what Jen issues from it, for both purposes". Nothing is written."""
    token = (ca_cert.fingerprint(hashes.SHA256()), int(time.time() // 60))
    if (
        token in _ORACLE_VERDICTS
    ):  # (an operator's RSA-4096 CA costs ~0.1 s a call and `ca_state` has ~22 callers: the verdict is a function of the certificate and the minute)
        return _ORACLE_VERDICTS[token]
    verdict = ""
    for purpose, client in (("sslserver", False), ("sslclient", True)):
        message, _leaf_cert = verify_probe(ca_cert, ca_key, client)
        if message:
            verdict = f"the verifier rejects certificates issued from it for {purpose}: {message}"
            break
    if len(_ORACLE_VERDICTS) > 64:
        _ORACLE_VERDICTS.clear()
    _ORACLE_VERDICTS[token] = verdict
    return verdict


def _openssl_exe():
    """The `openssl` CLI on the Jen host, or None - the ONE place it is looked up. The daemon's own TLS library (OpenSSL) is on the box wherever this answers, and a test that must not depend on it
    patches THIS."""
    return shutil.which("openssl")


def _run_openssl(args: list, timeout: float):
    """Run `openssl <args>` and return (exit code, its output), or None when it could not be run or did not finish in `timeout` seconds: NO opinion (Q197, AM3). The child runs in its OWN process
    group on POSIX and the group is killed at the timeout, so a wrapper's grandchild cannot hold Health for the grandchild's own time; on Windows only the child is killed (a job object is out of
    scope: Jen runs on Linux only)."""
    exe = _openssl_exe()
    if not exe:
        return None
    try:
        proc = subprocess.Popen(  # nosec B603 - list args, a fixed binary found on PATH, no shell
            [exe, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",  # (second pass, F4) output that is not UTF-8 is still output - it must not raise out of `communicate`
            start_new_session=(os.name != "nt"),
        )
    except OSError:
        return None
    try:
        out, _unused = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            if os.name != "nt":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        with contextlib.suppress(Exception):
            proc.communicate(timeout=2)
        return None
    except OSError:
        return None
    return proc.returncode, out or ""


_OPENSSL_REJECTION = re.compile(r"error \d+ at \d+ depth lookup: [^\r\n]+")
# Q199 (second pass, F2): the CLI that RUNS but cannot LOAD the CA it was handed (`Error loading file .../ca.pem`, `no certificate found`) is the daemon's library refusing the CA outright - a rejection
# with its own line, not "no opinion". (A missing library, a usage message or a bad configuration never names the CA file, so they stay no opinion.) Both gates write the CA as `ca.pem`.
_OPENSSL_CA_UNLOADABLE = re.compile(r"(?:Error loading file|unable to load)[^\r\n]*[\\/]ca\.pem[^\r\n]*")


def _openssl_verdict(ran) -> tuple:
    """(True | False | None, the line): a verdict exists ONLY when the output carries one - `: OK` with exit 0 accepts; `verification failed` or `error N at D depth lookup` rejects. Anything else - a
    missing shared library (exit 127), a usage message, a bad OPENSSL_CONF, an exit code with no verify verdict - is None: NO opinion, never a disagreement and never a rejection (Q197, AM3)."""
    if ran is None:
        return None, ""
    code, out = ran
    found = _OPENSSL_REJECTION.search(out) or _OPENSSL_CA_UNLOADABLE.search(out)
    if found or "verification failed" in out:
        return False, found.group(0) if found else "verification failed"
    if code == 0 and ": OK" in out:
        return True, ""
    return None, ""


def _write_public_pem(path: str, pem: bytes) -> None:
    with open(path, "wb") as f:
        f.write(pem)  # a PUBLIC certificate in a private temp directory, for `openssl verify`: no key is ever written


def _openssl_verify_args(purpose: str, ca_path: str, leaf_path: str) -> list:
    # `-auth_level 2` so the CLI and the daemon agree on key strength (Q197, AM6 f): a daemon built with the distribution's default security level refuses what level 1 accepts
    return ["verify", "-purpose", purpose, "-auth_level", "2", "-CAfile", ca_path, leaf_path]


def openssl_gate_rejection(ca_cert, ca_key, timeout: float = 10.0) -> str:
    """Q197 (AM1): where the `openssl` CLI exists on the Jen host the daemon's OWN library judges the CA at the GATE: the same throwaway leaves the library verified are run through
    `openssl verify -purpose sslserver|sslclient`. "" when the CLI is absent, broken or slow (NO opinion: the library's verdict stands) or accepts both; else "the daemon's own library rejects
    certificates issued from it for <purpose>: <the CLI's own line>". Q196 put this in Health only ("a warning, never a refusal") and the gates asked only the library, so a CA both real stacks
    reject was `ok` at the gate and the operator saw a healthy CA that could never set up an https socket."""
    if not _openssl_exe():
        return ""
    try:
        with tempfile.TemporaryDirectory(prefix="jen-openssl-gate-") as directory:
            ca_path, leaf_path = os.path.join(directory, "ca.pem"), os.path.join(directory, "probe.pem")
            _write_public_pem(ca_path, _cert_pem(ca_cert))
            for purpose, client in (("sslserver", False), ("sslclient", True)):
                _message, leaf = verify_probe(ca_cert, ca_key, client)
                if leaf is None:
                    continue
                _write_public_pem(leaf_path, _cert_pem(leaf))
                accepted, line = _openssl_verdict(
                    _run_openssl(_openssl_verify_args(purpose, ca_path, leaf_path), timeout)
                )
                if accepted is False:
                    return f"the daemon's own library rejects certificates issued from it for {purpose}: {line}"
    except OSError:
        return ""  # a temp directory that cannot be made: no opinion
    return ""


_GATE_VERDICTS: dict = {}


def ca_gate_rejection(ca_cert, ca_key) -> str:
    """The library's verdict first (`ca_verifier_rejection`), then the daemon's library where it is on the box (`openssl_gate_rejection`) - cached per certificate, minute and whether the CLI exists
    (a certificate is judged twice a minute at most; `ca_state` has about twenty callers)."""
    token = (ca_cert.fingerprint(hashes.SHA256()), int(time.time() // 60), _openssl_exe() is not None)
    if token in _GATE_VERDICTS:
        return _GATE_VERDICTS[token]
    verdict = ca_verifier_rejection(ca_cert, ca_key) or openssl_gate_rejection(ca_cert, ca_key)
    if len(_GATE_VERDICTS) > 64:
        _GATE_VERDICTS.clear()
    _GATE_VERDICTS[token] = verdict
    return verdict


def openssl_second_opinion(timeout: float = 10.0) -> str:
    """Informational (Q196, reshaped by Q197 AM3): when Jen has judged the CA DAMAGED, say where the daemon's own library (`openssl verify`) ACCEPTS what Jen rejects - Jen is the stricter judge there and the
    operator should know it. "" when there is no CLI, the CA is not damaged (a CLI that rejects what the library accepts is already a rejection at the gate), nothing can be loaded, or the CLI has no
    verdict. The comparison is with `ca_state`'s own verdict, not with the library probe alone, and the CA the CLI judges is the one that was loaded - never a path that can change under it."""
    if not _openssl_exe():
        return ""
    state, why = ca_state()
    if state != "damaged":
        return ""
    material = _ca_material_for_opinion()
    if material is None:
        return ""
    ca_cert, ca_key = material
    accepts = []
    try:
        with tempfile.TemporaryDirectory(prefix="jen-openssl-verify-") as directory:
            ca_path, leaf_path = os.path.join(directory, "ca.pem"), os.path.join(directory, "probe.pem")
            _write_public_pem(ca_path, _cert_pem(ca_cert))
            for purpose, client in (("sslserver", False), ("sslclient", True)):
                _message, leaf = verify_probe(ca_cert, ca_key, client)
                if leaf is None:
                    continue
                _write_public_pem(leaf_path, _cert_pem(leaf))
                accepted, _line = _openssl_verdict(
                    _run_openssl(_openssl_verify_args(purpose, ca_path, leaf_path), timeout)
                )
                if accepted is True:
                    accepts.append(purpose)
    except OSError:
        return ""  # a temp directory that cannot be made: no row - never an exception through Health
    if not accepts:
        return ""
    return f"openssl verify accepts a certificate issued from it for {' and '.join(accepts)}, but Jen judges the CA damaged ({why}) - Jen is the stricter judge here"


def _ca_material_for_opinion():
    """The CA's certificate and key for the second opinion - read directly, because the opinion is about a CA the library has judged DAMAGED (does the daemon's own library agree?). None when either
    file cannot be loaded."""
    crt, key = ca_paths()
    try:
        return load_cert(crt), load_key(key)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        return None


def _der_items(buf: bytes):
    """[(tag, content)] of the concatenated TLV elements in `buf` (definite lengths only - an X.509 name is DER)."""
    out, pos = [], 0
    while pos < len(buf):
        tag = buf[pos]
        length = buf[pos + 1]
        pos += 2
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(buf[pos : pos + count], "big")
            pos += count
        out.append((tag, buf[pos : pos + length]))
        pos += length
    return out


#: the string types OpenSSL accepts in a name AT ALL (executed, openssl 3.2.4, a CA whose subject and issuer are the same text in one type): UTF8, Numeric, Printable, T61, IA5, Universal, BMP.
#: OctetString, UTCTime, GeneralizedTime and VisibleString names are rejected even against themselves ("unable to get issuer certificate").
_NAME_TAGS_OPENSSL_ACCEPTS = frozenset({0x0C, 0x12, 0x13, 0x14, 0x16, 0x1C, 0x1E})
#: the types `X509_NAME_cmp` converts to UTF-8 and folds before comparing; the others are compared as their tag and bytes
_NAME_TAGS_CANONICALISED = {
    0x0C: "utf-8",
    0x13: "latin-1",
    0x14: "latin-1",
    0x16: "latin-1",
    0x1C: "utf-32-be",
    0x1E: "utf-16-be",
}
_SPACE = " \t\n\x0b\x0c\r"


def _name_attributes(name):
    """[[(oid DER, tag, content)]] - the RDNs of a name, as written."""
    out = []
    (_seq, rdns), *_unused = _der_items(name.public_bytes())  # the outer SEQUENCE; its content is the RDNs
    for _tag, rdn in _der_items(rdns):
        attrs = []
        for _t, attribute in _der_items(rdn):
            (_ot, oid), (vtag, value) = _der_items(attribute)[:2]
            attrs.append((oid, vtag, value))
        out.append(attrs)
    return out


def _name_types_ok(name) -> bool:
    """Is every attribute of this name in a string type OpenSSL accepts (Q199 AO3, executed)? A name in a type it does not read is one OpenSSL cannot match to itself."""
    try:
        return all(tag in _NAME_TAGS_OPENSSL_ACCEPTS for rdn in _name_attributes(name) for _oid, tag, _value in rdn)
    except (IndexError, ValueError):
        return False


def _canonical_value(tag: int, value: bytes):
    codec = _NAME_TAGS_CANONICALISED.get(tag)
    if codec is None:
        return ("raw", tag, value)
    try:
        text = value.decode(codec)
    except UnicodeDecodeError:
        return ("raw", tag, value)
    text = re.sub(f"[{_SPACE}]+", " ", text).strip(_SPACE)
    return ("text", "".join(c.lower() if c.isascii() else c for c in text))


def _same_name(a, b) -> bool:
    """Are two X.509 names ONE name as OpenSSL compares them (`X509_NAME_cmp`)? It reads each attribute of a canonicalised type (UTF8, Printable, T61, IA5, BMP, Universal) in ITS OWN encoding - T61
    as Latin-1, BMP as UTF-16, Universal as UTF-32 - folds ASCII case, strips and collapses white space, and compares the result; any other type is compared as its tag and bytes. So a PrintableString,
    a BMPString and a UTF8String holding the same ASCII text are ONE name, a letter-case or white-space difference is none, and a T61String holding the UTF-8 bytes of a non-ASCII letter (which
    OpenSSL reads as two Latin-1 characters) is another (Q199 AO3: executed against `openssl verify`; Q198's version said "T61, BMP and Universal are not one name", which is true of the last
    only for non-ASCII T61 and made Jen stricter than the stack it annotates). This is a structural pre-check for the SENTENCE; it may never return a verdict the verifier does not."""
    try:
        ra, rb = _name_attributes(a), _name_attributes(b)
    except (IndexError, ValueError):
        return False
    if len(ra) != len(rb):
        return False

    def canon(rdns):
        return [sorted((oid, _canonical_value(tag, value)) for oid, tag, value in rdn) for rdn in rdns]

    return canon(ra) == canon(rb)


def _verify_self_signature(cert, public) -> None:
    """Does the certificate's signature verify with its own public key? `Certificate.verify_directly_issued_by` compares the issuer and subject as BYTES, so a root whose issuer is a PrintableString
    and whose subject is the same text as a UTF8String - one name to OpenSSL, to the chain verifier and to `Name.__eq__` - read as "does not verify" (Q198 AN3, executed: openssl and the verifier
    accept it). Names are judged as names by the caller (issuer == subject); the SIGNATURE is verified here directly. Raises what `verify_directly_issued_by` raises."""
    try:
        cert.verify_directly_issued_by(cert)
        return
    except ValueError as e:
        if "subject does not match" not in str(e) or not _same_name(cert.issuer, cert.subject):
            raise
    if isinstance(cert.signature_hash_algorithm, (hashes.SHA1, hashes.MD5)):
        raise UnsupportedAlgorithm("a SHA-1 or MD5 self-signature is not verified")
    parameters = cert.signature_algorithm_parameters
    if isinstance(public, ec.EllipticCurvePublicKey):
        public.verify(cert.signature, cert.tbs_certificate_bytes, parameters)
    elif isinstance(public, rsa.RSAPublicKey):
        public.verify(cert.signature, cert.tbs_certificate_bytes, parameters, cert.signature_hash_algorithm)
    else:
        raise UnsupportedAlgorithm("this key type is not verified")


def _cert_structure(cert, crt_name: str, public) -> tuple[str, str]:
    """The structural ladder of a CA CERTIFICATE (no key needed): validity now, BasicConstraints ca=True, a KeyUsage - when there is one - with keyCertSign, an EC or RSA key, issuer == subject, a
    self-signature that verifies, and (Q197, AM1 a) an AuthorityKeyIdentifier that names the root's OWN key. The Lab's fake daemon asks this directly (`ca_identity(..., cert_only=True)`), so the
    fake and the product share one judgment of the certificate."""
    try:
        now = datetime.now(timezone.utc)
        if cert.not_valid_before_utc > now:
            return "damaged", f"{crt_name} is not valid until {cert.not_valid_before_utc:%Y-%m-%d}"
        if now >= cert.not_valid_after_utc:
            return "damaged", f"{crt_name} expired on {cert.not_valid_after_utc:%Y-%m-%d}"
        try:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            return "damaged", f"{crt_name} has no BasicConstraints, so it is not marked as a certificate authority"
        if not constraints.ca:
            return "damaged", f"{crt_name} is not marked as a certificate authority (BasicConstraints ca is false)"
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            usage = None  # RFC 5280: a certificate with NO KeyUsage extension is not restricted - an operator's own CA (`openssl req -x509`) often has none and works
        if usage is not None and not usage.key_cert_sign:
            return "damaged", f"{crt_name} is not allowed to sign certificates (its KeyUsage lacks keyCertSign)"
        if not isinstance(public, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
            return "damaged", f"{crt_name} uses a key type Jen does not support ({type(public).__name__})"
        if not (_name_types_ok(cert.subject) and _name_types_ok(cert.issuer)):
            return (
                "damaged",
                f"{crt_name} names itself in a string type OpenSSL does not read (VisibleString, a time or a byte string)",
            )
        if not _same_name(cert.issuer, cert.subject):
            return "damaged", f"{crt_name} is not self-signed (its issuer is not its subject)"
        try:
            authority = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
            subject_key = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        except x509.ExtensionNotFound:
            authority = subject_key = None
        if authority is not None and subject_key is not None and authority != subject_key:
            return (
                "damaged",
                f"{crt_name}'s AuthorityKeyIdentifier does not name its own key - OpenSSL will not chain to it",
            )
        try:
            aki_value = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        except x509.ExtensionNotFound:
            aki_value = None
        if aki_value is not None:
            # (second pass, F5; Q198 AN3) the issuer and serial forms of an AKI are value families too. OpenSSL (`X509_check_akid`) compares the FIRST DirectoryName of the issuer list with the issuing
            # certificate's issuer name and skips every other kind of name: a list of URIs or DNS names is not checked (and chains), a list whose first DirectoryName is another name does not. Compared as
            # NAMES (`cryptography`'s equality ignores the string type) - never as bytes.
            first_directory_name = next(
                (n for n in (aki_value.authority_cert_issuer or []) if isinstance(n, x509.DirectoryName)), None
            )
            names_ok = first_directory_name is None or _same_name(first_directory_name.value, cert.issuer)
            serial_ok = (
                aki_value.authority_cert_serial_number is None
                or aki_value.authority_cert_serial_number == cert.serial_number
            )
            if not (names_ok and serial_ok):
                return (
                    "damaged",
                    f"{crt_name}'s AuthorityKeyIdentifier does not name its own issuer and serial number - OpenSSL will not chain to it",
                )
        try:
            _verify_self_signature(cert, public)
        except UnsupportedAlgorithm:
            return "damaged", f"{crt_name}'s self-signature uses an algorithm Jen cannot verify"
        except InvalidSignature:
            return "damaged", f"{crt_name}'s signature does not verify against its own key"
        except (ValueError, TypeError) as e:
            # (`cryptography` reports a signature algorithm it will not verify - SHA-1 - as UnsupportedAlgorithm on one version and as ValueError("Unsupported signature algorithm") on another: that is
            # what Jen CANNOT do, not a claim that the signature is wrong)
            if "unsupported" in str(e).lower():
                return "damaged", f"{crt_name}'s self-signature uses an algorithm Jen cannot verify"
            return "damaged", f"{crt_name}'s signature does not verify against its own key"
    except (ValueError, TypeError, UnsupportedAlgorithm, x509.DuplicateExtension):
        # (Q194 second pass, finding 1: `DuplicateExtension` is an Exception, not a ValueError - a CA file with one must read "damaged", never raise through Health, the page, the setup, Rotate and Prepare)
        return "damaged", f"{crt_name} has an extension Jen cannot read"
    return "ok", ""


def ca_identity(
    cert_path: str, key_path: str | None, *, raise_io: bool = False, cert_only: bool = False
) -> tuple[str, str]:
    """The ONE judgment of CA material - the live pair, the prepared pair and the staged pair are all judged here. `("ok", "")` only when the certificate and key both load, the key is the
    certificate's (SPKI), the structural ladder passes (`_cert_structure`), the chain verifier accepts certificates issued from it for BOTH purposes (Q196), and - where the `openssl` CLI is on the Jen
    host - the daemon's own library does too (Q197, AM1); else `("damaged", why)` naming the FIRST failed check. `cert_only` (Q197, AM6 e) judges the CERTIFICATE alone - the structural ladder, no key,
    no oracle - which is what a trust anchor in a fake daemon is. `raise_io` lets a read error (an I/O failure, not a verdict) propagate: the prepared CA's reader treats it as unknown."""
    crt_name = os.path.basename(cert_path)
    try:
        cert = load_cert(cert_path)
    except OSError as e:
        if raise_io:
            raise
        return "damaged", f"{crt_name} cannot be read ({type(e).__name__})"
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "damaged", f"{crt_name} is not a certificate"
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    try:
        public = cert.public_key()
        cert_spki = public.public_bytes(*spki)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return (
            "damaged",
            f"{crt_name} is a certificate with an unusable public key",
        )  # (Q192 second pass, finding 1: it parses, so it is not 'not a certificate' - and it must not raise)
    private = None
    if not cert_only:
        key_name = os.path.basename(key_path)
        try:
            private = load_key(key_path)
        except OSError as e:
            if raise_io:
                raise
            return "damaged", f"{key_name} cannot be read ({type(e).__name__})"
        except (ValueError, TypeError, UnsupportedAlgorithm):
            return "damaged", f"{key_name} is not a private key"
        if cert_spki != private.public_key().public_bytes(*spki):
            return "damaged", f"{crt_name} and {key_name} are not a pair"
    state, why = _cert_structure(cert, crt_name, public)
    if state != "ok" or cert_only:
        return state, why
    try:
        # the structural checks above stay (they give the `why` a person recognises); the library's chain verifier has the next word (Q196), and the daemon's own library the last (Q197)
        rejection = ca_gate_rejection(cert, private)
    except (ValueError, TypeError, UnsupportedAlgorithm, x509.DuplicateExtension):
        return "damaged", f"{crt_name} has an extension Jen cannot read"
    if rejection:
        return "damaged", f"{crt_name}: {rejection}"
    return "ok", ""


def ca_state() -> tuple[str, str]:
    """The ONE definition of what Jen's CA is (Q192, AH2): `("none", "")` - neither file exists; `("ok", "")` - `ca_identity` says so (a pair that is a certificate-signing authority, valid now);
    `("damaged", why)` - one missing, or `ca_identity`'s first failed check (`why` says which). There is no other reading: the module used to load the two files independently, and "a cert
    without a loadable key counts as absent" made a NEW CA under existing https sockets (the existing client certificate no longer valid under the active CA, every server certificate
    unverifiable) - and from Q192 to Q193 an `ok` CA was only a pair (Q194: and a pair that cannot sign is damaged, never absent, never auto-replaced)."""
    crt, key = ca_paths()
    have_crt, have_key = os.path.lexists(crt), os.path.lexists(key)
    if not have_crt and not have_key:
        # (second pass, finding 4) neither file - but beside evidence that a CA existed it is DAMAGED, not "no CA yet": one definition, so Health, the setup, the page and Rotate agree
        evidence = _initialised_evidence()
        return ("damaged", f"both CA files are missing, and {evidence}") if evidence else ("none", "")
    crt_name, key_name = os.path.basename(crt), os.path.basename(key)
    if not have_crt:
        return "damaged", f"{crt_name} is missing ({key_name} is there)"
    if not have_key:
        return "damaged", f"{key_name} is missing ({crt_name} is there)"
    return ca_identity(crt, key)


def _initialised_evidence() -> str:
    """Q192 (AH2, T7): why this is NOT the uninitialised world - "" when it is. `ensure_ca` may create a CA only where nothing Jen ever issued can exist: no client certificate files, no copy of
    any server pair (live, `.prev`, `.staged`, a marker), no prepared rotation, and a directory that can be read at all (an unlistable one is unknown, and unknown is not 'empty')."""
    pem, key = client_paths()
    if os.path.lexists(pem) or os.path.lexists(key):
        return "Jen's client certificate exists, so a CA made it - the CA's files are gone, not never made"
    for path in (
        *glob.glob(glob.escape(ca_paths()[0]) + _STAGE_SUFFIX + "*"),
        *glob.glob(glob.escape(ca_paths()[1]) + _STAGE_SUFFIX + "*"),
        ca_paths()[0] + ".prev",
        ca_paths()[1] + ".prev",
        pem + ".prev",
        key + ".prev",
    ):
        if os.path.lexists(path):
            return f"{os.path.basename(path)} is beside the live files, so a CA existed"
    directory = _copies_dir()
    if not os.path.lexists(directory):
        return ""  # a CA has never issued anything here
    try:
        names = os.listdir(directory)
    except OSError as e:
        # (a directory that cannot be listed - a permission, a bad mount, a dangling link - is unknown, and unknown is not 'empty')
        return f"Jen cannot read its certificate directory ({type(e).__name__}), so it cannot tell whether it ever issued a certificate"
    names = [
        n for n in names if not PROBE_NAME.fullmatch(n)
    ]  # (Q195 AK2 c: Jen's own probe files are not certificates its CA issued)
    # an EXISTING directory, even an empty one, is `commit_issued`'s: it is only made when a pair is issued
    return (
        f"Jen holds {len(names)} file(s) for certificates its CA issued, so the CA existed - its files are gone, not never made"
        if names
        else "Jen's certificate directory exists, so a CA issued into it"
    )


def ca_refusal() -> str:
    """ "" when `ensure_ca()` may proceed (the CA is ok, or this is the uninitialised world); else the sentence for why it may not - the damage, or the evidence that a CA existed (Q192, AH2). Asked
    by a route BEFORE it reads from or sends anything to a host."""
    state, why = ca_state()
    return why if state == "damaged" else ""


def ensure_ca() -> dict:
    """Create the CA ONLY in the uninitialised world (Q192, AH2; invariant T7): `ok` returns it unchanged, `damaged` raises `CaDamaged`, and an absent CA beside evidence that one existed (a client
    certificate, a server copy, a prepared rotation, an unreadable directory) raises it too. It used to read "a cert without a loadable key counts as absent" and create a new CA whenever either file
    failed to load. (Q197, AM6 a: the `force` path - the pre-Q188 rotation that replaced the CA before any host had it - is gone; a rotation stages, probes and then commits.)
    Returns {"cert": path, "key": path, "created": bool, "subject": cn}."""
    crt, key_path = ca_paths()
    state, why = ca_state()
    if state == "ok":
        return {"cert": crt, "key": key_path, "created": False, "subject": _cn(crt)}
    if state == "damaged":
        raise CaDamaged(why)
    _ensure_dir(SSL_DIR)
    key = _new_key()
    cn = f"Jen Kea CA {_hostname()} {datetime.now(timezone.utc):%Y-%m-%d}"
    cert = _build_ca(key, cn)
    # Key first, then cert: a reader that finds a cert always finds its key - and the pair is installed as a SET (v5.68.0-beta.16, Q151).
    commit_file_set([(key_path, _key_pem(key), 0o600), (crt, _cert_pem(cert), 0o644)])
    logger.info(f"kea_tls: created the Kea CA at {crt}")
    return {"cert": crt, "key": key_path, "created": True, "subject": cn}


def _cn(cert_path: str) -> str:
    try:
        attrs = load_cert(cert_path).subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except (OSError, ValueError):
        return ""


def _load_ca():
    """The live CA certificate and key - ONLY from an ok CA (Q192, AH2): a damaged or absent one raises `CaDamaged`, and nothing is signed with it."""
    state, why = ca_state()
    if state != "ok":
        raise CaDamaged(why or "Jen has no Kea CA yet")
    crt, key_path = ca_paths()
    return load_cert(crt), load_key(key_path)


def _authority_key_identifier(ca_cert):
    """The leaf's AKI names the CA's key the way the CA's own SubjectKeyIdentifier does. An operator's CA whose SKI is not the SHA-1 of its public key (RFC 5280 allows any method) made OpenSSL reject
    every chain: the AKI Jen computed from the key did not match the SKI it found on the issuer (Q196 second pass, executed)."""
    try:
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        )
    except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError):
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())


def _leaf(ca_cert, ca_key, key, cn: str, sans: list, client: bool, now=None):
    now = (
        now if now is not None else _now()
    )  # (`now`: the oracle's throwaway leaf is valid at the instant it is VERIFIED, whatever `_now` says - Q196)
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
        .add_extension(_authority_key_identifier(ca_cert), critical=False)
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
    if not value.isascii():
        # (Q198 second pass, F1; Q199 AO4) a certificate carries a non-ASCII name as its A-label (punycode), which is what a client verifies and what `verifier_accepts_name` asks about; `DNSName` itself refuses a U-label
        from jen.services.auth import idna_a_label

        value = idna_a_label(value)
        if value is None:
            return None
    try:
        return x509.DNSName(value)
    except ValueError:
        return None


# ── leaves ──────────────────────────────────────────────────────────────────


def verify_issued(ca_cert, leaf, client: bool, name: str = "") -> str:
    """Q196 second pass (row 3, the real artifact): "" when the chain verifier accepts the leaf Jen ACTUALLY issued - with its real SANs (the bind address first: an IP, which the oracle's DNS-only
    probe leaf never carried), as a server certificate for `name` or as a client certificate (no SAN: the client profile is relaxed for it) - else the verifier's message. The throwaway oracle
    says whether the CA can sign for either purpose; THIS says whether it can sign for THIS server."""
    now = datetime.now(timezone.utc)
    ca_policy, ee_policy = _verifier_policies()
    if client:
        ee_policy = ee_policy.may_be_present(x509.SubjectAlternativeName, x509_verification.Criticality.AGNOSTIC, None)
    try:
        builder = (
            x509_verification.PolicyBuilder()
            .store(x509_verification.Store([ca_cert]))
            .time(now)
            .extension_policies(ca_policy=ca_policy, ee_policy=ee_policy)
        )
        if client:
            builder.build_client_verifier().verify(leaf, [])
        else:
            subject = x509.IPAddress(ipaddress.ip_address(name)) if _is_ip(name) else x509.DNSName(name)
            builder.build_server_verifier(subject).verify(leaf, [])
    except Exception as e:  # fail closed: a leaf the verifier cannot judge is a leaf a daemon may not accept
        return _verifier_message(e)
    return ""


def _name_refused(ca_cert, ca_key, san) -> bool:
    """Does the verifier refuse a server certificate that carries THIS one name (Q197, AM2)? A leaf that cannot even be built for the name is refused too."""
    value = str(san.value)
    try:
        leaf = _leaf(ca_cert, ca_key, _new_key(), "jen-probe", [san], client=False)
    except (ValueError, TypeError):
        return True
    return bool(verify_issued(ca_cert, leaf, False, value))


def verifier_accepts_name(host: str) -> bool:
    """Would the certificate verifier accept `host` as the name of a server (Q197, AM2)? An IP literal does; a DNS name does when the library's own DNS-name parser does. `kea_host` (an underscore), `kea-a.`
    (a trailing dot), an empty label, a label that starts or ends with a hyphen and an over-long label are names a form can save and no certificate Jen issues can carry - `valid_api_url` asks THIS
    for an https address in direct mode, so the two definitions agree before a leaf is attempted."""
    host = (host or "").strip()
    if not host:
        return False
    if _is_ip(host.strip("[]")):
        return True
    if not host.isascii():
        # (Q198 AN5; Q199 AO4) a name with non-ASCII letters is carried in a certificate as its A-label (punycode, IDNA 2008 as `requests` dials it); the verifier is asked about THAT
        from jen.services.auth import idna_a_label

        host = idna_a_label(host)
        if host is None:
            return False
    try:
        throwaway_key = _new_key()
        throwaway_ca = _build_ca(throwaway_key, "name check")
        x509_verification.PolicyBuilder().store(x509_verification.Store([throwaway_ca])).time(
            datetime.now(timezone.utc)
        ).build_server_verifier(x509.DNSName(host))
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return False
    return True


def name_refusal_remedy(names, rotating: bool = False, prepared: bool = False) -> str:
    """The sentence for what to DO about a name the verifier refused (Q197 second pass, F2). A name no certificate can carry (an underscore, a trailing dot ...) is not cured by a new CA - Rotate fails on it
    the same way - so the remedy is the address. A name a CA's constraints exclude is cured by the address or by a CA without the constraint (Rotate Kea CA issues one; no acknowledgement: the CA is healthy)."""
    if any(not verifier_accepts_name(n) for n in names):
        return "change the address saved for it under Settings → Kea (a certificate cannot carry that name; no acknowledgement is needed - the CA is not damaged)"
    if prepared:
        # (Q198 AN4) the CA being staged is a kept `.next` (Prepare'd, or placed by hand): ITS name constraints refuse the name, and rotating again reuses the same CA - the way out is to discard it (Jen
        # then stages its own, which has none) or to change the address
        return (
            f"the prepared CA's name constraints do not permit {', '.join(names)}: discard the prepared CA under Settings → Kea and rotate again (Jen stages its own CA), or change the address saved for it "
            "(no acknowledgement is needed - the CA is not damaged)"
        )
    if rotating:
        return "change the address saved for it under Settings → Kea (no acknowledgement is needed - the CA is not damaged)"
    return "change the address Jen dials, or replace the CA with Rotate Kea CA (no acknowledgement is needed - the CA is not damaged)"


def other_record_on_same_daemon(server: dict, service: str, servers, url_for=None) -> str:
    """Q197 (AM5): the NAME of ANOTHER server record that shares this record's SSH host (`same_host`: exact, no DNS) and already holds a Jen-issued record for `service` - "" when there is none. The rule
    the rotation applies (Q196 AL2: one daemon is one target) asked where the world is MADE: an https setup on a second record for the same daemon would put a certificate on the fixed remote paths
    that the first record's copy then no longer matches."""
    from jen.services.auth import same_host

    if url_for is None:
        from jen.services import kea as _kea

        url_for = _kea.configured_url
    ssh = (server.get("ssh_host") or "").strip()
    if not ssh:
        return ""
    for other in servers or []:
        if str(other.get("id")) == str(server.get("id")):
            continue
        other_ssh = (other.get("ssh_host") or "").strip()
        if not other_ssh or not (ssh == other_ssh or same_host(ssh, other_ssh)):
            continue
        if not (url_for(other, service) or "").strip().lower().startswith("https://"):
            continue  # (second pass, F3) a record whose endpoint is not https now is STALE - Rotate ignores it, so it is no second owner of the daemon
        if record_state(other.get("id"), service, server=other, url=url_for(other, service))[0] in (
            *JEN_STATES,
            "refuse",
        ):
            # (Q198 AN5: a record Jen cannot rotate safely - malformed, a pair that does not match, an earlier CA's - is still files at that daemon's fixed paths; it is a second owner too)
            return other.get("name") or f"Kea Server {other.get('id')}"
    return ""


_FORGETTABLE = re.compile(
    r"([1-9][0-9]*)-(dhcp4|dhcp6|d2)"
)  # (Q199 AO4: no leading zero - `007-dhcp4` is not a number Jen writes)


def forget_report(servers, url_for=None, include_parked: bool = False) -> dict:
    """Q197 (AM4), Q198 (AN2), Q199 (AO5/AO6): drop Jen's own copy of every certificate record that records NOTHING - a server that is not configured at all (the inventory's `stale`), an ORPHAN
    group of files with no live pair included. A local change only: no host is asked anything. A record for a CONFIGURED server whose endpoint is not https now is PARKED: its daemon may still present
    that certificate, so it is kept and named - unless the operator says (`include_parked`) that no daemon presents it any more. A record is `forgotten` only when every one of its files is gone
    (`discard_local_record` re-checks); one that could not be fully removed is `incomplete` and stays discoverable for a retry. Only a recognised file name is ever touched; an unrecognised one is
    `skipped`. A directory that cannot be listed is said, not read as "nothing to forget". Returns {"forgotten", "parked", "unreadable", "skipped", "incomplete", "on_word"}."""
    report = {"forgotten": [], "parked": [], "unreadable": "", "skipped": [], "incomplete": [], "on_word": []}
    try:
        record_groups(strict=True)
    except OSError as e:
        report["unreadable"] = f"{type(e).__name__}, errno {getattr(e, 'errno', '?')}"
        return report
    inventory = rotation_inventory(servers, url_for=url_for, prove_storage=False)
    report["parked"] = list(inventory.parked)
    report["skipped"] = list(inventory.skipped)
    wanted = [(ident, False) for ident in inventory.stale]
    if include_parked:
        # (second pass, F3) the operator's explicit act: "no daemon presents these any more" (the socket was removed by hand, the server was switched to the Control Agent for good, a removed server's id
        # was reused) - recorded by the route as a durable `record-forgotten` fact, never silently
        wanted += [(ident, True) for ident in inventory.parked]
    for ident, on_word in wanted:
        match = _FORGETTABLE.fullmatch(ident)
        if match is None:
            continue
        result = discard_local_record(match.group(1), match.group(2))
        if result["failed"]:
            report["incomplete"].append((ident, result["failed"]))
            continue
        report["forgotten"].append(ident)
        if on_word:
            report["on_word"].append(ident)
            report["parked"].remove(ident)
    return report


def forget_stale_records(servers, url_for=None) -> list:
    """The "<server id>-<service>" identifiers `forget_report` forgot (Q197 AM4)."""
    return forget_report(servers, url_for=url_for)["forgotten"]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


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
    if sans:
        # (Q196 second pass, row 3) the leaf Jen is about to put on a host, with the names it really carries, is verified BEFORE it is returned: a CA name-constrained away from this server's address
        # passed the oracle (a DNS-only probe) and would have been installed, restarted and failed its probe
        primary = str(sans[0].value)
        rejection = verify_issued(ca_cert, cert, False, primary)
        if rejection:
            # which name? each SAN alone (a name constraint applies to every name in a leaf, and the verifier's message does not say which one failed - the bind address OR the ssh_host name)
            failing = [str(s.value) for s in sans if _name_refused(ca_cert, ca_key, s)]
            if failing:
                raise NameRefused(rejection, failing)
            raise CaDamaged(f"the CA cannot issue a certificate the verifier accepts for {primary}: {rejection}")
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
    _known_again(server_id, service)  # the host was just given exactly this pair: Jen's copy agrees again


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
        with contextlib.suppress(OSError):
            mark_unknown(
                server_id, service
            )  # Jen does not know which pair the host holds: say so in a FILE too (no acknowledgement removes it)
        raise HostRecordLost(
            f"Jen cannot record which certificate server {server_id} {service} holds ({type(lost).__name__})"
        ) from cause


def _material(crt: str, key: str) -> dict | None:
    """The `install-tls` payload of a certificate and key on disk - {"ca.crt", "server.crt", "server.key"} (PEM str) - or None unless BOTH load and the key is the certificate's (a pair that does not
    belong together is never put on a host). The CA is the live one (a rotation re-issues every pair)."""
    if ca_state()[0] != "ok":
        return None  # (second pass, finding 3) the payload carries the CA certificate as the host's trust anchor: from a damaged or foreign file it would be pushed as one
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
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        return None
    return {"ca.crt": ca_pem, "server.crt": crt_pem, "server.key": key_pem}


def stage_issued(server_id, service: str, files: dict) -> None:
    """Q188 (AD2): Jen's own recovery state is committed BEFORE the host is touched. `.prev` becomes a copy of the live pair - what the host has now, so what a failure puts back; a stale `.prev`
    from an older operation is removed, never kept as the rollback source - and the new pair is written beside the live one as `.staged` (private files). Nothing live changes. Raises
    OSError when it cannot be written: the caller stops before `install_tls`, with nothing changed on the host."""
    from jen.services.private_files import write_private_file

    crt, key = server_copy_path(server_id, service), server_key_path(server_id, service)
    _ensure_dir(os.path.dirname(crt))
    # Q189: what Jen can say the HOST holds - not what happens to be live. A stale marker over a `.prev` pair that loads is the file layer KNOWING (second pass, finding 3): it is kept even
    # when the incident record cannot be read at this moment - a transient blip must not destroy the host's only file-layer record.
    held = previous_material(server_id, service) if is_stale(server_id, service) else None
    if held is None:
        held = host_material(server_id, service)
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
    _known_again(
        server_id, service
    )  # live IS the pair the host accepted: a divergence noted before this operation is over


def discard_staged(server_id, service: str) -> None:
    for p in (server_copy_path(server_id, service) + ".staged", server_key_path(server_id, service) + ".staged"):
        with contextlib.suppress(OSError):
            os.unlink(p)


def fingerprint(path: str) -> str | None:
    """SHA-256 of the certificate's DER encoding - what a TLS peer presents, comparable with `presented_fingerprint`."""
    try:
        return hashlib.sha256(load_cert(path).public_bytes(serialization.Encoding.DER)).hexdigest()
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
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
            with contextlib.suppress(OSError):
                mark_unknown(server_id, service)
            raise HostRecordLost(
                f"Jen cannot record which certificate server {server_id} {service} holds ({type(lost).__name__})"
            ) from failure
        return False
    retire_previous(server_id, service)
    _known_again(server_id, service)
    return True


def _record_paths(server_id, service: str) -> list:
    """Every file Jen can hold for one server and service: the live pair, `.prev`, `.staged` of each, and the two markers - eight paths."""
    crt, key = server_copy_path(server_id, service), server_key_path(server_id, service)
    return [base + suffix for base in (crt, key) for suffix in ("", ".prev", ".staged")] + [
        _stale_path(server_id, service),
        _unknown_path(server_id, service),
    ]


def discard_local_record(server_id, service: str) -> dict:
    """Q189 (AE6c): drop Jen's own copy of the pair for this server and service - the live pair, `.prev`, `.staged` and the markers. For a failed https attempt on a daemon whose sockets do not
    reference Jen's TLS files, a removed server, a Forget. Q199 (AO5): it REPORTS what it did - {"removed": [...], "absent": [...], "failed": [(file, error class, errno)]}, file NAMES only - after
    re-checking every path, and a caller calls the record forgotten only when `failed` is empty: it used to suppress every OSError and a read-only directory read as success (the files, a private key
    among them, still on disk)."""
    removed, absent, failed = [], [], []
    paths = _record_paths(server_id, service)
    for path in paths:
        name = os.path.basename(path)
        try:
            os.unlink(path)
            removed.append(name)
        except FileNotFoundError:
            absent.append(name)
        except OSError as e:
            failed.append((name, type(e).__name__, getattr(e, "errno", None)))
    broken = {f[0] for f in failed}
    for path in paths:
        name = os.path.basename(path)
        if name not in broken and os.path.lexists(path):
            failed.append((name, "StillPresent", None))
            if name in removed:
                removed.remove(name)
    return {"removed": removed, "absent": absent, "failed": failed}


def retire_previous(server_id, service: str) -> None:
    """The operation that replaced the pair succeeded: the pair before it is no longer needed - and any known divergence between Jen's copy and the host is over."""
    for p in (server_copy_path(server_id, service) + ".prev", server_key_path(server_id, service) + ".prev"):
        with contextlib.suppress(OSError):
            os.unlink(p)
    clear_stale(server_id, service)


def _stale_path(server_id, service: str) -> str:
    return server_copy_path(server_id, service) + ".stale"


def _unknown_path(server_id, service: str) -> str:
    return server_copy_path(server_id, service) + ".unknown"


def mark_unknown(server_id, service: str) -> None:
    """Q189 (second pass, finding 2): Jen does NOT know which pair this host holds, and the fact is kept in a FILE beside the pair - a recovery note is acknowledged away by a person, a
    verified recovery clears it, a database blip hides it; none of those makes the live copy the host's pair again. Cleared only by an operation that gives the host a pair Jen then records
    (`commit_issued`, `promote_staged`, `restore_previous`). Raises OSError when it cannot be written; the caller treats that as 'no durable record'."""
    from jen.services.private_files import write_private_file

    crt, key = server_copy_path(server_id, service), server_key_path(server_id, service)
    if not any(os.path.exists(p) for p in (crt, key, crt + ".prev", key + ".prev")):
        return  # Jen holds no pair for this server and service: there is no record that could be wrong, and `host_material` is already None
    _ensure_dir(os.path.dirname(crt))
    write_private_file(_unknown_path(server_id, service), b"Jen does not know which pair the host holds\n", 0o600)


def is_unknown(server_id, service: str) -> bool:
    return os.path.exists(_unknown_path(server_id, service))


def _known_again(server_id, service: str) -> None:
    """The host was just given a pair Jen has recorded as its live copy: the divergence marker and the 'unknown' marker are over. A marker that cannot be removed is a record that now LIES
    (it would make `host_material` answer a pair the host no longer holds), so that is `HostRecordLost`, not a silence."""
    for path in (_stale_path(server_id, service), _unknown_path(server_id, service)):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            raise HostRecordLost(
                f"Jen cannot clear its note about server {server_id} {service} ({type(e).__name__})"
            ) from e


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
    * the `.unknown` marker beside the pair (a file: no acknowledgement, resolution or database blip removes it - only an operation that gives the host a pair Jen records);
    * an unresolved `remote-unknown` or `tls-not-restored` incident for this server and service: unknown, whatever the files say (the second says the host holds a certificate Jen did not
      mean to leave there - its live copy may well be a different pair);
    * the incident record cannot be read: unknown;
    * the live pair is marked stale: the `.prev` pair (unknown when it does not load);
    * a `tls-local-stale` incident with no marker (the marker could not be written): unknown;
    * otherwise its live pair (unknown when it does not load)."""
    if is_unknown(server_id, service):
        return None
    categories = _open_incident_categories(server_id, service)
    if categories is None or categories & {"remote-unknown", "tls-not-restored"}:
        return None
    if is_stale(server_id, service):
        return previous_material(server_id, service)
    if "tls-local-stale" in categories:
        return None
    return current_material(server_id, service)


def ca_consistent() -> bool:
    """Can Jen sign with its CA - is `ca_state` `ok`? A promotion whose restore also failed can leave the certificate and key apart, and every certificate issued from that CA is then signed by a
    key its certificate does not name; since Q194 a pair that is not a certificate-signing authority (expired, not marked CA, no keyCertSign, a signature that does not verify) is equally unusable.
    The failure paths ask THIS, so "the CA is still damaged" is one answer wherever it is judged."""
    return ca_state()[0] == "ok"


def client_state(judge_issuer: bool = True) -> tuple[str, str]:
    """The ONE definition of Jen's client pair (Q192, AH3): `("none", "")` - neither file exists; `("ok", "")` - both load, the key is the certificate's (SPKI), the certificate was issued by the
    live CA, carries the `clientAuth` extended key usage and is inside its validity with more than 30 days left; `("expiring", why)` - all of that but 30 days or fewer remain; `("damaged", why)` -
    anything else (one file missing, unreadable or malformed, a key that is not the certificate's, an issuer that is not the live CA - or no CA to judge it against - no `clientAuth`, not yet valid,
    expired). It used to load the key and never ask whether it belonged to the certificate: Health read a pair of strangers as healthy and `issue_client_cert` skipped the re-issue."""
    pem, key = client_paths()
    have_pem, have_key = os.path.lexists(pem), os.path.lexists(key)
    if not have_pem and not have_key:
        return "none", ""
    pem_name, key_name = os.path.basename(pem), os.path.basename(key)
    if not have_pem:
        return "damaged", f"{pem_name} is missing ({key_name} is there)"
    if not have_key:
        return "damaged", f"{key_name} is missing ({pem_name} is there)"
    try:
        cert = load_cert(pem)
    except OSError as e:
        return "damaged", f"{pem_name} cannot be read ({type(e).__name__})"
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "damaged", f"{pem_name} is not a certificate"
    try:
        private = load_key(key)
    except OSError as e:
        return "damaged", f"{key_name} cannot be read ({type(e).__name__})"
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "damaged", f"{key_name} is not a private key"
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    try:
        cert_spki = cert.public_key().public_bytes(*spki)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "damaged", f"{pem_name} is a certificate with an unusable public key"
    if cert_spki != private.public_key().public_bytes(*spki):
        return "damaged", f"{key_name} is not the key of {pem_name}"
    if judge_issuer:
        # (`judge_issuer=False` - second pass, finding 5: replacing a DAMAGED CA, the live pair is judged without the issuer, which cannot be asked)
        ca_state_now, ca_why = ca_state()
        if ca_state_now != "ok":
            return "damaged", f"there is no usable CA to judge {pem_name} against ({ca_why or 'none yet'})"
        if not issued_by(pem, ca_paths()[0]):
            return "damaged", f"{pem_name} was not issued by the current CA"
    try:
        usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usages = []
    except (x509.DuplicateExtension, ValueError):
        return "damaged", f"{pem_name} has an extension Jen cannot read"
    if ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
        return "damaged", f"{pem_name} is not a client certificate (no clientAuth)"
    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now:
        return "damaged", f"{pem_name} is not valid yet"
    if cert.not_valid_after_utc <= now:
        return "damaged", f"{pem_name} has expired"
    left = (cert.not_valid_after_utc - now).days
    if left <= 30:
        return "expiring", f"{pem_name} expires in {left} day(s)"
    return "ok", ""


def client_cert_ok() -> bool:
    """True iff Jen's client pair is a pair that works: `client_state()` is `ok` (Q192, AH3 - the key is the certificate's, the CA is the live one, `clientAuth`, inside its validity, more than
    30 days left)."""
    return client_state()[0] == "ok"


def issue_client_cert(force: bool = False) -> dict:
    """Jen's own client certificate (clientAuth). Re-issued when it is missing, damaged (a key that is not the certificate's, an issuer that is not the live CA, no `clientAuth`, expired), expiring,
    or `force` - from the live CA, which must be `ok` (the same CA: every daemon that trusts it keeps trusting it); the pair it replaces is kept as `.prev` by `commit_file_set`. A damaged or absent CA
    raises `CaDamaged` (Q192, AH2): nothing is signed with a CA that cannot sign. Returns {"cert": path, "key": path, "issued": bool, "why": str} - `why` is the damage a re-issue repaired ("" for a first
    issue, an unforced no-op or a forced one)."""
    pem, key_path = client_paths()
    state, why = client_state()
    if not force and state == "ok":
        return {"cert": pem, "key": key_path, "issued": False, "why": ""}
    ca_cert, ca_key = _load_ca()
    key = _new_key()
    cert = _leaf(ca_cert, ca_key, key, f"jen {_hostname()}", [], client=True)
    rejection = verify_issued(ca_cert, cert, True)
    if rejection:
        raise CaDamaged(f"the CA cannot issue Jen's client certificate the verifier accepts: {rejection}")
    _ensure_dir(SSL_DIR)
    commit_file_set([(key_path, _key_pem(key), 0o600), (pem, _cert_pem(cert), 0o644)])
    logger.info(f"kea_tls: issued Jen's Kea client certificate at {pem}")
    return {"cert": pem, "key": key_path, "issued": True, "why": why if state in ("damaged", "expiring") else ""}


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

    def __init__(
        self,
        targets,
        refusals,
        external,
        stale,
        endpoints=frozenset(),
        external_endpoints=(),
        parked=(),
        orphans=(),
        skipped=(),
    ):
        self.targets, self.refusals, self.external, self.stale = targets, refusals, external, stale
        # Q199 (AO6): the records (stale or parked) that are a GROUP of files with no live pair, and the names in the directory Jen does not recognise (named, never touched)
        self.orphans, self.skipped = list(orphans), list(skipped)
        # Q198 (AN2): the copies of a CONFIGURED server that is not an https endpoint now - "<server id>-<service>". The daemon may still present the certificate (the socket is still in its config), so the
        # record is kept, watched and never forgotten while the socket exists; `stale` is only a record for a server that is not configured at all
        self.parked = list(parked)
        # Q192 (AH1): the `external` https endpoints as (server, service, url) - what a rotation PROBES with the staged client pair (the names above are sentences)
        self.external_endpoints = list(external_endpoints)
        self.endpoints = frozenset(
            endpoints
        )  # every https endpoint Jen dials, (server id, service), whatever Jen holds for it - what a running rotation is compared with

    def __iter__(self):
        return iter((self.targets, self.refusals))


def trust_bundle() -> tuple[bool, bool] | None:
    """What the CA bundle Jen verifies its https endpoints against (`[kea] api_ca`) CONTAINS, by certificate identity (Q190, AF1): `(includes_jens_ca, includes_another_ca)`. Every certificate in
    the file is loaded (a PEM bundle) and compared by DER with Jen's live CA certificate - so the bundle IS Jen's CA whether the path is Jen's own, a symlink, an equivalent path, a byte-copy or
    a bundle that contains it, and is the administrator's whatever it is named. `None` when there is nothing to judge: the path is empty, missing (a dangling symlink), unreadable, holds no PEM
    certificate, or Jen's own CA cannot be loaded. This and `trust_includes_jens_ca` are the only places a trust path is interpreted: tests/test_invariant_sweeps.py S13 refuses a comparison of
    `KEA_API_CA` with a path anywhere else (a path string is not an identity - the alias that was not Jen's own path made every Jen-issued endpoint 'the administrator's')."""
    configured = (getattr(extensions, "KEA_API_CA", "") or "").strip()
    if not configured:
        return None
    try:
        with open(configured, "rb") as f:
            found = x509.load_pem_x509_certificates(f.read())
        jens = load_cert(ca_paths()[0]).public_bytes(serialization.Encoding.DER)
        ders = [c.public_bytes(serialization.Encoding.DER) for c in found]
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        return None
    if not ders:
        return None
    return any(d == jens for d in ders), any(d != jens for d in ders)


def trust_kind() -> str:
    """HOW the CA bundle Jen verifies against relates to Jen's CA, by certificate identity first and only then by path (Q190, AF1) - the one function that looks at the path itself:
    `none` (empty), `unreadable` (missing, dangling, not PEM), `other` (an administrator's CAs only), `jens-file` (Jen's own file, or an equivalent spelling of its path), `alias` (the same
    file through a symlink), `copy` (a byte-copy of Jen's CA somewhere else), `bundle` (Jen's CA AND another CA in one file). What Rotate may rewrite follows from it: only `jens-file`."""
    configured = (getattr(extensions, "KEA_API_CA", "") or "").strip()
    if not configured:
        return "none"
    if ca_state()[0] == "damaged":
        # (second pass, findings 2 and 12) replacing a DAMAGED CA: its certificate may not load - or may load as something a byte-copy elsewhere is NOT (one flipped byte) - so a bundle cannot be compared
        # by certificate with it. By PATH alone: Jen's own file, or a link to it, is replaced under the operator; any other file that loads cannot be proved to follow it, so it is a `copy` - and
        # a copy under a Jen-issued target is a refusal (ambiguity is a refusal)
        jens_file = ca_paths()[0]
        if os.path.normpath(os.path.abspath(configured)) == os.path.normpath(os.path.abspath(jens_file)):
            return "jens-file"
        if os.path.realpath(configured) == os.path.realpath(jens_file):
            return "alias"
        try:
            with open(configured, "rb") as f:
                if x509.load_pem_x509_certificates(f.read()):
                    return "copy"
        except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
            pass
        return "unreadable"
    bundle = trust_bundle()
    if bundle is None:
        return "unreadable"
    includes_jens, includes_other = bundle
    if not includes_jens:
        return "other"
    if includes_other:
        return "bundle"
    jens_file = ca_paths()[0]
    if os.path.normpath(os.path.abspath(configured)) == os.path.normpath(os.path.abspath(jens_file)):
        return "jens-file"
    # an ALIAS follows Jen's file when it is replaced (a symlink, a symlinked directory, a junction); a hard link or a copy does not - it keeps the OLD certificate
    return "alias" if os.path.realpath(configured) == os.path.realpath(jens_file) else "copy"


def client_kind(cert_path: str | None = None, key_path: str | None = None) -> str:
    """HOW the client pair Jen presents to a daemon relates to Jen's own client pair, by certificate identity first and only then by path (Q191, AG1) - the twin of `trust_kind` and the
    ONE definition: `none` (no pair configured - a dial with no client certificate), `unreadable` (one half missing, a file that is not PEM, or a certificate and key that are not a pair),
    `jens-file` (Jen's own files, or an equivalent spelling of their paths), `alias` (the same files through a link, which follows a replacement), `copy` (a certificate Jen's CA issued, or
    that equals Jen's live client certificate by DER, at a path that does NOT follow Jen's files - after a rotation it is no longer the certificate the daemons accept), `other` (a certificate
    no Jen CA issued: the operator's own PKI). With no arguments it judges the configured pair (`[kea] api_client_cert` / `api_client_key`); the connection form passes the pair it was SUBMITTED.
    A daemon with `cert-required` checks this pair as well as the CA bundle, so it is part of the same identity (REMOTE-001 section 10)."""
    cert = ((getattr(extensions, "KEA_API_CLIENT_CERT", "") if cert_path is None else cert_path) or "").strip()
    key = ((getattr(extensions, "KEA_API_CLIENT_KEY", "") if key_path is None else key_path) or "").strip()
    if not cert and not key:
        return "none"
    if not cert or not key:
        return "unreadable"  # Jen sends a pair or nothing (`kea._tls_client_cert`): one half is a dial with no client certificate
    jens_cert, jens_key = client_paths()
    if os.path.realpath(cert) == os.path.realpath(jens_cert) and os.path.realpath(key) == os.path.realpath(jens_key):
        # (second pass, finding 1) these ARE Jen's files, whatever they hold: a missing or damaged pair of Jen's own is Jen's to repair (the https setup issues it again, the rotation replaces it), and
        # calling it `unreadable` sent the operator to "point them at Jen's own files" - where they already pointed
        spelled = os.path.normpath(os.path.abspath(cert)) == os.path.normpath(os.path.abspath(jens_cert))
        spelled = spelled and os.path.normpath(os.path.abspath(key)) == os.path.normpath(os.path.abspath(jens_key))
        return (
            "jens-file" if spelled else "alias"
        )  # an alias follows Jen's file when it is replaced (a link, a junction); a hard link or a copy does not - it keeps the OLD certificate
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    try:
        mine = load_cert(cert)
        if mine.public_key().public_bytes(*spki) != load_key(key).public_key().public_bytes(*spki):
            return "unreadable"
        mine_der = mine.public_bytes(serialization.Encoding.DER)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        return "unreadable"
    try:
        live_der = load_cert(jens_cert).public_bytes(serialization.Encoding.DER)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        live_der = None
    if mine_der == live_der or issued_by(cert, ca_paths()[0]):
        return "copy"
    return "other"


def client_refusal(kind: str | None = None, cert_path: str | None = None) -> str:
    """The sentence for a client pair a rotation, an https setup or the connection form cannot carry - "" when the pair is fine (`none`, `jens-file`, `alias`; `other` is the operator's own PKI,
    refused only where a Jen-issued endpoint depends on it). One text, so the three places say the same thing (Q191, AG1)."""
    kind = client_kind() if kind is None else kind
    cert = ((getattr(extensions, "KEA_API_CLIENT_CERT", "") if cert_path is None else cert_path) or "").strip()
    mine = ", ".join(client_paths())
    if kind == "copy":
        return (
            f"Jen's client certificate is configured as a copy at {cert}; after a rotation that copy would no longer be the certificate the daemons accept. "
            f"Point the client certificate and key under Settings → Kea at Jen's own files ({mine}) or clear them"
        )
    if kind == "other":
        return (
            f"The client certificate configured at {cert} was not issued by Jen's current CA (it is an operator's own, or a copy from before a rotation), so the daemons Jen issued certificates to do not accept it. "
            f"Point the client certificate and key under Settings → Kea at Jen's own files ({mine}) or clear them"
        )
    if kind == "unreadable":
        return (
            "The client certificate and key configured under Settings → Kea cannot be loaded as a pair, so Jen would dial the daemons without one. "
            f"Point them at Jen's own files ({mine}) or clear them"
        )
    return ""


def trust_includes_jens_ca() -> bool | None:
    """Is Jen's CA among the certificates Jen verifies its https endpoints against? True - the bundle holds it (the path is Jen's CA, an alias of it, a copy of it, or a bundle that contains it);
    False - it holds only an administrator's CAs; None - empty, unreadable or not PEM: ambiguous, and an ambiguity is a refusal wherever it matters (Q190, AF1)."""
    bundle = trust_bundle()
    return None if bundle is None else bundle[0]


def _server_label(server: dict, service: str) -> str:
    return (
        f"{server.get('name') or 'Kea Server ' + str(server.get('id'))} {_DAEMON_LABEL.get(service, 'kea-' + service)}"
    )


#: the two states of a record Jen's CA issued: `jen` is the pair the host holds, `jen-stale` one whose host holds the `.prev` pair instead (Jen's own copy of a pair it put on the host could not follow
#: a rollback - Q188). Both are rotation targets; the second says which pair is the host's.
JEN_STATES = ("jen", "jen-stale")


def _destination_refusal(cert, server, url) -> str:
    """Q199 (AO7): "" when the certificate Jen saved was issued for the daemon this server record names NOW, else the sentence. A server certificate Jen issues carries its destination - the bind address
    and the SSH host are its SANs - so a record kept under a server number that has since been pointed at a DIFFERENT daemon (the SSH host and the address both changed, or the number was reused) is
    not that daemon's, and rotating it would put one daemon's pair on another's host. Compared with `same_host` (the duplicate-daemon guard's contract: no DNS, a dot is a different name), any
    configured name against any SAN: a display-name change, an alias of the same host, a URL change on the same daemon all still match; a certificate with no SAN names no destination and is not judged."""
    from urllib.parse import urlparse

    from jen.services.auth import same_host

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError):
        return ""
    names = [str(v) for v in sans.get_values_for_type(x509.DNSName)] + [
        str(v) for v in sans.get_values_for_type(x509.IPAddress)
    ]
    try:
        url_host = urlparse(url or "").hostname or ""
    except ValueError:
        url_host = ""
    configured = [h for h in ((server or {}).get("ssh_host") or "", url_host) if h]
    if not names or not configured or any(same_host(n, c) for n in names for c in configured):
        return ""
    return (
        f"its certificate was issued for {', '.join(names)}, not for {', '.join(configured)} - this server record now points at a different daemon; "
        "remove the direct socket and set it up again, or restore the previous host"
    )


def record_state(server_id, service: str, recovery: bool = False, server=None, url: str = "") -> tuple[str, str]:
    """What Jen holds for one server and service, as `(state, why)`: `("jen", "")` - a certificate and key that load, are a pair and were issued by Jen's live CA (`("jen-stale", "")` when the stale
    marker says the host holds the `.prev` pair, Q198 AN1); `("external", "")` - a pair
    whose certificate no Jen CA issued; `("none", why)` - NEITHER file exists; `("refuse", why)` - anything Jen cannot rotate safely: one file missing, unreadable, malformed, not a pair, issued
    by an earlier Jen CA."""
    crt, key = server_copy_path(server_id, service), server_key_path(server_id, service)
    try:
        with open(crt, "rb") as f:
            crt_pem = f.read()
    except FileNotFoundError:
        if not os.path.lexists(key):
            leftovers = sorted(
                os.path.basename(p) for p in _record_paths(server_id, service) if os.path.lexists(p)
            )  # (Q199 AO6: files of the group with no live pair are not "never issued" - Jen did issue one)
            if leftovers:
                return "refuse", f"Jen holds only {', '.join(leftovers)} for it and no certificate record"
            return (
                "none",
                "Jen holds no certificate record for it",
            )  # neither file: Jen never issued one for this endpoint (or lost both) - the trust path breaks the tie
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
        spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        paired = cert.public_key().public_bytes(*spki) == private.public_key().public_bytes(*spki)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "refuse", "its certificate or key is malformed"
    if not paired:
        return "refuse", "its certificate and key are not a pair"
    if issued_by(crt, ca_paths()[0]):
        refusal = _destination_refusal(cert, server, url) if (server is not None or url) else ""
        if refusal:
            return "refuse", refusal
        return ("jen-stale" if is_stale(server_id, service) else "jen"), ""
    if any(a.value == "Jen" for a in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)):
        if recovery:
            return (
                ("jen-stale" if is_stale(server_id, service) else "jen"),
                "",
            )  # Q192 (AH2): replacing a DAMAGED CA - every Jen-issued pair is a target whichever Jen CA signed it; the live CA cannot be asked
        return "refuse", "its certificate was issued by an earlier Jen CA, not the current one"
    return "external", ""


def rotation_inventory(servers, url_for=None, recovery: bool = False, prove_storage: bool = True) -> RotationInventory:
    """The ONE source of a rotation's targets (Q189, AE1): for every configured server and each of dhcp4 / dhcp6 / d2, the URL Jen dials (`url_for(server, service)`, default the Kea
    client's `_endpoint_for`); every `https://` endpoint is a target when Jen holds a complete record of its certificate (`record_state`) and a REFUSAL, with a sentence, when it does not.
    A certificate no Jen CA issued is an administrator-managed endpoint: named in `external`, left alone. A directory that cannot be listed is a refusal naming it - never an empty set.
    A copy for a server or service that is not an https endpoint now is `stale`: said, ignored. No network: only Jen's configuration and Jen's own files - and, with `prove_storage`, a write probe
    in the record directory that leaves it as it found it (Q194)."""
    from jen.services.auth import shown_url  # (the ONE helper that shows an address - Q190, AF2)

    if url_for is None:
        from jen.services import kea as _kea

        url_for = _kea.configured_url  # the CONFIGURED address, whatever the credential rule says about the password

    targets, refusals, external = [], [], []
    external_endpoints = []
    bundle = trust_bundle()
    configured_ca = (getattr(extensions, "KEA_API_CA", "") or "").strip()
    try:
        listed, skipped_names = record_groups(strict=True)
    except OSError as e:
        listed, skipped_names = [], []
        if not recovery:  # (Q193, AI3: replacing a damaged CA issues every pair afresh - the old copies are not needed, so an unlistable directory is not a reason to refuse it)
            refusals.append(
                f"Jen could not read its certificate directory {_copies_dir()} ({type(e).__name__}, errno {getattr(e, 'errno', '?')}), so it cannot tell which servers it issued certificates to; fix its permissions before rotating"
            )
    if prove_storage:
        # Q194 (AJ2): EVERY rotation records the pairs it issues, so every inventory proves - by creating the directory and writing in it - that Jen can. (A recovery waives the READ of the old copies, never
        # this: the host would take a pair Jen cannot record.) The page's summary, Health and the end-of-rotation comparison pass `prove_storage=False`: they only read, and a read creates nothing.
        blocked = copies_dir_writable(keep=False)
        if blocked:
            refusals.append(
                f"Jen cannot write its certificate records in {_copies_dir()} ({blocked}), so it could not keep the certificate it issues for a server, and a daemon that took one would be left "
                "on a CA Jen never adopted; fix the folder's permissions or storage before rotating"
            )
    on_jens_own_ca = recovery and bool(configured_ca) and trust_kind() in ("jens-file", "alias")
    endpoints = set()
    for server in servers or []:
        for service in INVENTORY_SERVICES:
            url = (url_for(server, service) or "").strip()
            if not url.lower().startswith("https://"):
                continue
            sid = server.get("id")
            endpoints.add((str(sid), service))
            label = _server_label(server, service)
            state, why = record_state(sid, service, recovery=recovery, server=server, url=url)
            if on_jens_own_ca and state in ("none", "refuse"):
                # Q193 (AI3): Jen verifies this endpoint against its OWN CA - the file being replaced - so it is Jen's, whatever it holds or does not hold for it: the replacement issues it a pair afresh
                from urllib.parse import urlparse

                targets.append((server, service, urlparse(url).hostname or ""))
                continue
            if state == "none":
                # Q190 (AF1): Jen holds no record of this endpoint's certificate. Whose endpoint it is is a fact about CERTIFICATES, decided here - and only here, as the tiebreak - from what Jen is
                # configured to trust, by identity (`trust_bundle`), never from a path string: an endpoint with a Jen-issued copy is a target whatever the trust path says.
                if not configured_ca:
                    if getattr(extensions, "KEA_API_TLS_VERIFY", True):
                        # (verified against the system's CAs: Jen's CA is not what Jen trusts, so a certificate Jen did not issue is the administrator's)
                        external.append(f"{label} ({shown_url(url)}; verified against the system's CAs, not Jen's)")
                        external_endpoints.append((server, service, url))
                    else:
                        # (second pass, finding 4) NOTHING is verified: Jen looks at no certificate, so it cannot tell whose endpoint this is - and an ambiguity is a refusal
                        refusals.append(
                            f"{label} is an https endpoint at {shown_url(url)}, Jen holds no certificate record for it and Jen is set not to verify any certificate - it cannot tell whose CA the endpoint is on; "
                            + (
                                f"{RECOVERY_OWN_CA_FIX}, before rotating"
                                if recovery
                                else "set the CA bundle under Settings → Kea to Jen's CA, then remove the direct socket and set it up again so Jen holds its certificate (or point Jen at a socket that is not on its CA), before rotating"
                            )
                        )
                elif bundle is None:
                    refusals.append(
                        f"Jen cannot compare the CA bundle at {configured_ca} with its own CA, which is damaged, to tell whose CA {label} ({shown_url(url)}) is on; {RECOVERY_OWN_CA_FIX}, before rotating"
                        if recovery
                        else f"Jen cannot read the CA bundle at {configured_ca} to tell whose CA {label} ({shown_url(url)}) is on; fix the CA bundle under Settings → Kea before rotating"
                    )
                elif bundle[0] and bundle[1]:
                    refusals.append(
                        f"{label} is an https endpoint at {shown_url(url)} and Jen holds no certificate record for it, and the CA bundle at {configured_ca} holds Jen's CA AND another CA - it does not say "
                        "which one this endpoint is on; "
                        + (
                            f"{RECOVERY_OWN_CA_FIX}, before rotating"
                            if recovery
                            else "remove the direct socket and set it up again so Jen issues and keeps a certificate for it, or give Jen a bundle that names one, before rotating"
                        )
                    )
                elif bundle[0]:
                    refusals.append(
                        f"{label} is an https endpoint at {shown_url(url)}: Jen verifies it against its own CA and holds no certificate record for it; "
                        + (
                            f"{RECOVERY_OWN_CA_FIX}, before rotating"
                            if recovery
                            else "remove the direct socket and set it up again so Jen issues and keeps a certificate for it, before rotating"
                        )
                    )
                else:
                    external.append(f"{label} ({shown_url(url)}; its CA is not Jen's)")
                    external_endpoints.append((server, service, url))
            elif state in JEN_STATES:
                from urllib.parse import urlparse

                targets.append((server, service, urlparse(url).hostname or ""))
            elif state == "external":
                external.append(f"{label} ({shown_url(url)}; its certificate was not issued by Jen)")
                external_endpoints.append((server, service, url))
            else:
                refusals.append(
                    f"{label} is an https endpoint at {shown_url(url)} and Jen has no complete record of its certificate ({why}); "
                    + (
                        f"{RECOVERY_OWN_CA_FIX}, before rotating"
                        if recovery
                        else "remove the direct socket and set it up again so Jen issues and keeps a certificate for it, or point Jen at a socket that is not on its CA, before rotating"
                    )
                )
    # Q196 (AL2): ONE DAEMON IS ONE TARGET. Two records with the same SSH host and service are two targets whose installs land on the SAME fixed remote paths - the second over the first - with two local
    # records that cannot both be the daemon's. `same_host` is exact and DNS-free: two names that resolve to one daemon, or two spellings it does not equate, are the operator's to keep apart.
    from jen.services.auth import same_host

    owners: dict = {}
    for server, service, _bind in targets:
        ssh = (server.get("ssh_host") or "").strip()
        if not ssh:
            continue
        for other_server, other_ssh in owners.get(service, []):
            if ssh == other_ssh or same_host(
                ssh, other_ssh
            ):  # (the identical string is one host even where `same_host` cannot parse it)
                spelled = (
                    " (the two records write the host differently - Jen does not resolve names, so which spellings are one daemon is yours to decide)"
                    if ssh != other_ssh
                    else ""
                )
                refusals.append(
                    f"{_server_label(other_server, service)} and {_server_label(server, service)} both manage {_DAEMON_LABEL.get(service, 'kea-' + service)} on {ssh}: Jen would install two certificates on one daemon, "
                    f"the second over the first{spelled}. Remove one record or point it at its own host before rotating"
                )
        owners.setdefault(service, []).append((server, ssh))
    kind = trust_kind()
    if targets and kind in ("copy", "bundle"):
        # (second pass, finding 1) Jen-issued endpoints depend on Jen's CA, and Jen verifies them against a file that holds a COPY of that CA which Rotate cannot rewrite: after the promotion
        # Jen would hold the old CA and every rotated endpoint would present the new one. Refused BEFORE anything is staged, naming the path and the fix.
        if recovery:
            refusals.append(
                f"Jen verifies its https endpoints against {configured_ca}, which is not Jen's own CA file or a link to it, and Jen's CA is damaged - so it cannot be proved to follow the CA being "
                "replaced, and Rotate cannot rewrite it. Point the CA bundle under Settings → Kea at Jen's own CA file (kea-ca.crt in Jen's SSL folder, or a link to it) before rotating"
            )
        else:
            refusals.append(
                f"Jen verifies its https endpoints against {configured_ca}, which holds "
                + ("a copy of Jen's CA" if kind == "copy" else "Jen's CA beside another CA")
                + " - Rotate cannot rewrite that file, so after the rotation Jen could not verify the endpoints it issued certificates to. "
                "Point the CA bundle under Settings → Kea at Jen's own CA file (kea-ca.crt in Jen's SSL folder, or a link to it) before rotating"
            )
    if targets:
        # Q191 (AG1): Jen's identity to a daemon is its CA bundle AND its client pair. The pair is judged by certificate like the bundle: a copy (or a pair the dial never worked with, or one that
        # does not load) under a Jen-issued endpoint is a refusal BEFORE anything is staged - a rotation would replace Jen's own pair and leave the daemons demanding a certificate Jen no longer sends.
        client_kind_now = client_kind()
        if client_kind_now in ("copy", "other", "unreadable"):
            refusals.append(client_refusal(client_kind_now) + " before rotating")
    configured_ids = {str(s.get("id")) for s in servers or []}
    stale, parked, orphans = [], [], []
    for c in listed:
        if (str(c["server_id"]), c["service"]) in endpoints:
            continue
        ident = f"{c['server_id']}-{c['service']}"
        (parked if str(c["server_id"]) in configured_ids else stale).append(ident)
        if not c["pair"]:
            orphans.append(ident)
    return RotationInventory(
        targets, refusals, external, stale, endpoints, external_endpoints, parked, orphans, skipped_names
    )


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
        # ONE set, keys first, with `keep_prev=False` (Q197, AM6 b): the `.next` files are not identity files, and a `.next.prev` copy of a key is a second private key nobody listed
        commit_file_set(
            [
                (staged["ca_key"], _key_pem(ca_key), 0o600),
                (staged["ca_cert"], _cert_pem(ca_cert), 0o644),
                (staged["client_key"], _key_pem(client_key), 0o600),
                (staged["client_cert"], _cert_pem(client_cert), 0o644),
            ],
            keep_prev=False,
        )
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
        # (Q197 second pass, F8: a release before beta.28 copied each staged file to `<name>.next.prev` - a private-key copy nothing removed; discarding the staging removes it too)
        for path in (p, p + ".prev"):
            with contextlib.suppress(OSError):
                os.unlink(path)


def promotion_blockers() -> list[str]:
    """Q192 (found by the worlds matrix): why a rotation could NOT be promoted, known BEFORE any host is touched - `commit_file_set` refuses to replace a symlink and cannot replace a directory,
    so a live identity file that is either would make the promotion fail after every target had moved to the new CA (the rollback then re-issues them, and Jen has changed hosts for nothing).
    [] when all four live files can be replaced (an absent one is fine: that is a recovery)."""
    out = []
    for live in (*ca_paths(), *client_paths()):
        for path in (
            live,
            live + ".prev",
        ):  # (`commit_file_set` also writes the `.prev` COPY of each member it replaces)
            if os.path.islink(path):
                out.append(f"{os.path.basename(path)} is a link, which Jen will not replace")
            elif os.path.isdir(path):
                out.append(f"{os.path.basename(path)} is a directory where a file belongs")
    return out


def _staged_paths() -> dict:
    crt, key_path = ca_paths()
    pem, client_key_path = client_paths()
    return {
        "ca_cert": crt + _STAGE_SUFFIX,
        "ca_key": key_path + _STAGE_SUFFIX,
        "client_cert": pem + _STAGE_SUFFIX,
        "client_key": client_key_path + _STAGE_SUFFIX,
    }


class PreparedUnreadable(OSError):
    """Q192 (second pass, finding 6): the prepared CA's files could not be READ right now (an I/O error). It is not inconsistent - it is unknown - so it is neither reused nor discarded nor overwritten."""


def prepared_rotation(discard: bool = False) -> tuple[dict | None, str]:
    """Q192 (AH1): the prepared (`Prepare only`) rotation waiting beside the live files, as `(staged, "")` when all four `.next` files exist and are consistent - the new CA is a pair, the new client
    certificate was issued by it, is a `clientAuth` certificate inside its validity with more than 30 days left, and its key is its own; `(None, "")` when there is none; `(None, why)` when what is
    there is half-written or PROVED inconsistent - a rotation never reuses material it cannot prove. A READ cannot destroy (second pass, finding 6): only a caller that holds the identity lock and
    passes `discard=True` (Rotate, Prepare) deletes what it proved unusable; the Settings page just says it will be. A set that cannot be READ (an I/O error) raises `PreparedUnreadable` - unknown is
    neither reused nor discarded nor overwritten. A rotation that finds a consistent one REUSES it (the same CA-B an external daemon's trust anchor may already hold)."""
    staged = _staged_paths()
    present = [k for k, p in staged.items() if os.path.lexists(p)]
    if not present:
        return None, ""
    verb = "so it was discarded" if discard else "so Rotate or Prepare will discard it"

    def discarded() -> str:
        """The verb after an attempted discard: 'so it was discarded' only when every file is gone, else which one could not be removed (Q193, AI4 c)."""
        if not discard:
            return verb
        discard_rotation(staged)
        left = [os.path.basename(p) for p in staged.values() if os.path.lexists(p)]
        return verb if not left else f"but {', '.join(left)} could not be removed"

    if len(present) != len(staged):
        return None, f"the prepared CA was incomplete ({len(present)} of {len(staged)} files), {discarded()}"
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    identity_why = ""  # (set by the judgment below; a file that cannot even be loaded is "damaged or inconsistent" with no further reason)
    try:
        ca_cert = load_cert(staged["ca_cert"])
        client_cert, client_key = load_cert(staged["client_cert"]), load_key(staged["client_key"])
        now = datetime.now(timezone.utc)
        # Q194 (AJ1): the prepared CA is judged by the SAME function as the live one - a pair that is not a certificate-signing authority (the reviewer's `ca=False` pair with a correctly signed client
        # certificate) is not one to promote
        identity, identity_why = ca_identity(staged["ca_cert"], staged["ca_key"], raise_io=True)
        consistent = (
            identity == "ok"
            and client_cert.public_key().public_bytes(*spki) == client_key.public_key().public_bytes(*spki)
            and ExtendedKeyUsageOID.CLIENT_AUTH
            in client_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            # (finding 11) a prepared pair that is expired, not yet valid or about to expire is not one to promote
            and client_cert.not_valid_before_utc <= now
            and (client_cert.not_valid_after_utc - now).days > 30
        )
        if consistent:
            client_cert.verify_directly_issued_by(ca_cert)
    except OSError as e:
        raise PreparedUnreadable(e.errno, f"the prepared CA cannot be read right now ({type(e).__name__})") from e
    except Exception:  # ValueError, TypeError, InvalidSignature, ExtensionNotFound - PROVED unusable, not unread
        consistent = False
    if not consistent:
        return None, f"the prepared CA was damaged or inconsistent, {discarded()}" + (
            f" ({identity_why})" if identity_why else ""
        )
    return staged, ""


def prepared_fingerprint(staged: dict) -> str:
    """SHA-256 of the prepared CA certificate (DER), as the colon-separated hex an operator compares - what to add to an external daemon's trust anchor beside the current CA. "unavailable" when
    the certificate cannot be loaded at this instant (Q193, AI4 d: never the word None)."""
    plain = fingerprint(staged["ca_cert"])
    return ":".join(plain[i : i + 2] for i in range(0, len(plain), 2)).upper() if plain else "unavailable"


def _copies_dir() -> str:
    return os.path.join(SSL_DIR, "kea-servers")


#: Q195 (AK2 a): the name of a probe file `copies_dir_writable` writes - `.write-probe-<pid>-<16 hex>` - and nothing else. The cleanup of leftovers and the evidence count (`_initialised_evidence`) both
#: match THIS pattern exactly: a file an operator keeps in the record directory (`.write-probe-OPERATORS-NOTES.txt`) is not Jen's to delete or to ignore.
PROBE_NAME = re.compile(r"\.write-probe-\d+-[0-9a-f]{16}")
PROBE_LEFTOVER_SECONDS = 60


def copies_dir_writable(keep: bool = True) -> str:
    """Q194 (AJ2): "" when Jen can keep a certificate record in its certificate directory - PROVED by doing it: the directory is created when it is absent (Jen's own uid, mode 0700) and a probe
    file is written and removed inside it; else why not, as the exception's class and errno (a path that is a regular file, a directory that refuses the probe, a read-only parent, an unavailable
    mount). A directory this call created for a check that then fails is removed again. Q193's version inferred "a directory that is not there yet is writable" - and under a read-only parent the
    real create raised `PermissionError`; a recovery waives the READ of the old copies, never the WRITE: `commit_issued` records each new pair there after the host has taken it, and a host that
    took a pair Jen cannot record is cut off. Asked on EVERY path that will need it: every rotation's inventory, the https setup before `stage_issued`, and the recovery once more before its first
    install (the filesystem can change in between; `HostRecordLost` stays as the backstop after that).
    Second pass (rows 4, 5): the probe has a UNIQUE name (a fixed one, left by a killed process, refused a writable directory for good) and any leftover probe is removed; `keep=False` (the
    preflights: the inventory, the https setup) leaves the directory as it found it - a refusal changes nothing, and in the uninitialised world an EMPTY directory would read as evidence that a CA
    existed - while the check immediately before the first install keeps what it created (a write follows)."""
    d = _copies_dir()
    created = False
    try:
        if not os.path.lexists(d):
            os.makedirs(d, 0o700, exist_ok=True)
            created = True
        with contextlib.suppress(OSError):
            for leftover in os.listdir(d):
                path = os.path.join(d, leftover)
                # (Q195 second pass: only a LEFTOVER - a probe a killed process left, older than a minute - never another thread's probe that is being written right now)
                if PROBE_NAME.fullmatch(leftover) and time.time() - os.stat(path).st_mtime > PROBE_LEFTOVER_SECONDS:
                    os.unlink(path)
        probe = os.path.join(
            d, f".write-probe-{os.getpid()}-{secrets.token_hex(8)}"
        )  # (unique; no retry loop of `mkstemp` - one attempt, one answer)
        os.close(os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        os.unlink(probe)
    except OSError as e:
        if created:
            with contextlib.suppress(OSError):
                os.rmdir(d)
        return f"{type(e).__name__}, errno {getattr(e, 'errno', '?')}"
    if created and not keep:
        with contextlib.suppress(OSError):
            os.rmdir(d)
    return ""


_RECORD_FILE = re.compile(
    r"([1-9][0-9]*)-(dhcp4|dhcp6|d2)\.(crt|key|crt\.prev|key\.prev|crt\.staged|key\.staged|crt\.stale|crt\.unknown)"
)


def record_groups(strict: bool = False) -> tuple[list[dict], list[str]]:
    """Q199 (AO6): ([group], [skipped file names]) - every file Jen recognises in its certificate directory (`.crt`, `.key`, `.crt.prev`, `.key.prev`, `.crt.staged`, `.key.staged`, `.crt.stale`,
    `.crt.unknown`), grouped by `<server number>-<dhcp4|dhcp6|d2>`: {server_id, service, files: [kinds], pair: bool (a live certificate AND key), path}. A group without a live pair is an ORPHAN - the
    records used to be discovered by `.crt` alone, so a `.key` whose certificate was gone was invisible to the inventory, Health and Forget. A name Jen does not recognise (a stray file, a service it
    does not run, a leading zero) is `skipped`, named, never touched. A directory that is not there lists as none; one that cannot be LISTED is raised under `strict` (Q189, AE1) - unknown, never empty."""
    d = _copies_dir()
    try:
        names = sorted(os.listdir(d))
    except FileNotFoundError:
        return [], []
    except OSError:
        if strict:
            raise
        return [], []
    groups: dict = {}
    skipped = []
    for n in names:
        if PROBE_NAME.fullmatch(n):
            continue  # (Jen's own write probe is not a record)
        m = _RECORD_FILE.fullmatch(n)
        if m is None:
            skipped.append(n)
            continue
        g = groups.setdefault(
            (m.group(1), m.group(2)),
            {"server_id": m.group(1), "service": m.group(2), "files": [], "pair": False, "path": ""},
        )
        g["files"].append(m.group(3))
    for g in groups.values():
        g["pair"] = "crt" in g["files"] and "key" in g["files"]
        g["path"] = os.path.join(d, f"{g['server_id']}-{g['service']}.crt")
    return list(groups.values()), skipped


def issued_server_copies(strict: bool = False) -> list[dict]:
    """[{server_id, service, path, days_left}] for every server cert copy Jen keeps (a group with a live `.crt`) - Health's input. See `record_groups` for the directory's other files."""
    groups, _skipped = record_groups(strict=strict)
    return [
        {"server_id": g["server_id"], "service": g["service"], "path": g["path"], "days_left": days_left(g["path"])}
        for g in groups
        if "crt" in g["files"]
    ]
