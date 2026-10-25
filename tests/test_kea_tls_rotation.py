"""
tests/test_kea_tls_rotation.py
──────────────────────────────
v5.69.0-beta.19 (Q188, AD1 / AD6 / AD8) - CA rotation is ONE transaction, driven through the real route body (`rotate_kea_ca`) on REAL temporary certificate files:

  * Jen's own state is staged first (the new CA and client pair beside the live ones), every target is issued, installed, restarted and probed with the STAGED identity, Jen's TLS settings
    are saved, and only then is the staging promoted - each step inside one exception boundary, so a step that fails (or raises) stops the rotation and every attempted target is put back
    on the CA Jen still trusts, restarted, and PROBED with it;
  * the host is a simulated helper (`kea_host.helper_call`: install-tls stores the files, a restart makes the daemon load them) and the daemon is a fake that answers version-get only when
    the certificate it LOADED was issued by the CA it was asked with, and only to a client certificate issued by the CA IT loaded - so "answering" means something. The real `install_tls` /
    `service_action` wrappers sit on top, which is how a `socket.timeout`, `EOFError` or `SSHException` from the channel reaches the route (AD6);
  * never a success counter: every test reads the files on disk and what the fake daemon would answer.

v5.69.0-beta.20 (Q189, AE0) - THE INVARIANTS RUN AFTER EVERY TEST IN THIS FILE. The `lab` fixture calls `Lab.check_invariants()` in its teardown, so no test has to think of the question:

  T1 host record  - Jen's record of what each host holds (`kea_tls.host_material`) is byte-equal to the pair the fake host holds, OR it is None and a `tls-local-stale` / `remote-unknown` /
                    `tls-not-restored` incident names that server and service (or the `.unknown` marker beside the pair says so - an acknowledged incident leaves it). Never a third state.
  T2 CA pair      - Jen's CA certificate and key are a pair, or every target has a `tls-not-restored` incident and the flash says the CA is not a pair.
  T3 trust        - every daemon the fake host runs answers Jen's probe with Jen's LIVE client certificate against Jen's LIVE CA, OR an incident names it. A rotation that "succeeded" with a
                    daemon Jen can no longer reach fails here.
  T4 no secret    - the flashes, audit rows, log lines and incident records contain no PEM, no key material and no password.
  T5 refusal      - when the route answered with a refusal (no remote action happened and nothing was rotated) the fake hosts' files and every file under Jen's SSL directory are
                    byte-equal to their state before the request.

`TestTheInvariantsBite` has one deliberately failing test per invariant: it breaks the product on purpose and asserts the teardown check names the invariant, so a later edit cannot quietly
weaken a check. Why this and not more assertions: Q188 had a test that asserted `.prev` EXISTS and the marker is set; nobody asserted `.prev` was the right pair. An invariant over the host's
state does not need someone to think of the question.

Pure - no database, no Kea, no SSH (`pytest --noconftest tests/test_kea_tls_rotation.py`).
"""

import copy
import inspect
import logging
import os
import pathlib
import time
import types
from tempfile import (
    TemporaryDirectory as _REAL_TEMPORARY_DIRECTORY,  # (a test that denies `tempfile.TemporaryDirectory` to the PRODUCT must not take the fake daemon's judge down with it)
)

import flask
import pytest

import jen.config as jconfig
import jen.routes.settings.infrastructure as infra
from jen import extensions
from jen.services import health, kea_changeset, kea_host, kea_tls
from tests._fs_flake import retry_transient_replace, retrying_replace  # noqa: F401 (the fixture is autouse)
from tests._tls_invariants import issued_by_a_jen_ca, printed_secret, secrets_of

pytest_plugins = ("tests._investigation_world",)

SERVERS = {
    1: {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"},
    2: {"id": 2, "name": "standby", "ssh_host": "10.0.0.6"},
}
URLS = {1: "https://10.0.0.5:8004", 2: "https://10.0.0.6:8004"}
CRED = ("lab-user", "lab-secret-9137")  # distinctive: T4 looks for the password in everything the route printed
_ACTIVE: list = []  # the lab of the running test, so `_rotate()` needs no argument
#: the categories whose presence "names" a server for T1 / T3: Jen says it does not know, or that it is not right, there
_NAMES_A_SERVER = (
    "tls-not-restored",
    "restart-failed",
    "restored-endpoint-unreachable",
    "remote-unknown",
    "tls-local-stale",
)


def _issued_by(cert_pem: str, ca_path: str) -> bool:
    from cryptography import x509

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        ca = x509.load_pem_x509_certificate(pathlib.Path(ca_path).read_bytes())
        cert.verify_directly_issued_by(ca)
        return True
    except Exception:
        return False


def _issued_by_any(cert_pem: str, bundle_path: str) -> bool:
    """Was this certificate issued by ANY certificate of the PEM bundle at `bundle_path`? (A client that trusts a bundle trusts each of its certificates.)"""
    from cryptography import x509

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        found = x509.load_pem_x509_certificates(pathlib.Path(bundle_path).read_bytes())
    except Exception:
        return False
    for ca in found:
        try:
            cert.verify_directly_issued_by(ca)
            return True
        except Exception:  # nosec B112 - not this one
            continue
    return False


#: Q196: the keys of the CAs a test built, by certificate fingerprint - a trust anchor in the fake daemon is a bare certificate, but where the Lab KNOWS the key the fake asks the product's own verifier
#: (the client purpose: that is what a daemon does with a client certificate) instead of re-deriving what a verifier would say. ONLY for the EKU and name-constraint families (`VERIFIER_*_STATES`): the
#: executed table shows the verifier and the daemon's OpenSSL AGREE there; where they differ (a root with no BasicConstraints, a tampered self-signature) the fake models the daemon - OpenSSL - not the
#: verifier
_ANCHOR_KEYS: dict = {}


def _anchor_usable(cert) -> bool:
    """Q195 (AK1): would OpenSSL accept this certificate as the TRUST ANCHOR of a client chain? A fake models how a remote system is OBSERVED (LESSONS section 2), and the shipped fake accepted a client
    certificate issued by an EXPIRED anchor - so no test saw the world a recovery exists for. The checks OpenSSL makes of a trust anchor: inside its validity window now; a CA by `X509_check_ca`
    (BasicConstraints `ca=True`, or - with no BasicConstraints - a `keyCertSign`); a KeyUsage, when present, with `keyCertSign`. It does NOT verify the anchor's own signature (OpenSSL does not)."""
    from cryptography.hazmat.primitives import hashes

    # Q197 (AM6 e): the SAME judgment of the certificate the product makes - `ca_identity(cert_only=True)`, the structural ladder with no key - so the fake and the product cannot disagree on any kind.
    # (The earlier hand-written copy accepted a tampered self-signature and a root with no BasicConstraints because OpenSSL does; the product is the stricter judge there and the fake now says so too -
    # registered: OpenSSL itself still chains to those two, and a recovery beside an external that trusts one is therefore rotated through Prepare.)
    with _REAL_TEMPORARY_DIRECTORY() as directory:
        anchor_path = os.path.join(directory, "anchor.crt")
        pathlib.Path(anchor_path).write_bytes(kea_tls._cert_pem(cert))
        if kea_tls.ca_identity(anchor_path, None, cert_only=True)[0] != "ok":
            return False

    key = _ANCHOR_KEYS.get(cert.fingerprint(hashes.SHA256()))
    return key is None or not kea_tls.verify_probe(cert, key, True)[0]


def _issued_by_pem(cert_pem: str, ca_pem: str) -> bool:
    from cryptography import x509

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        ca = x509.load_pem_x509_certificate(ca_pem.encode())
        cert.verify_directly_issued_by(ca)
        return True
    except Exception:
        return False


def _tree(root) -> dict:
    """Every file under `root` as {relative path: bytes} - what T5 compares."""
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                out[os.path.relpath(path, root)] = pathlib.Path(path).read_bytes()
            except OSError:
                out[os.path.relpath(path, root)] = b"<unreadable>"
    return out


class Lab:
    """The simulated Kea hosts, the fake daemons and everything the route reports.

    Q190 (AF0): THE INVARIANT HAS NO KNOB. There is no set of "managed" servers for a test to edit: T1, T3 and T4 range over EVERY daemon the fake host runs and every secret the Lab was
    configured with, whatever a test did to Jen's records. T3 is RELATIVE (a daemon that answered Jen's live identity before a request answers after it, or an incident names it; one that did
    not answer before is untouched and answers the same), and T1 is judged by the fake host's certificate - not by Jen's files - so nothing in the test and nothing in the code has to agree
    on a word like "managed" for the invariant to hold."""

    def __init__(self):
        self.servers = {sid: dict(s) for sid, s in SERVERS.items()}
        self.urls = dict(URLS)
        self.hosts = {
            sid: {"files": None, "loaded": None, "installs": [], "restarts": 0, "calls": {}} for sid in SERVERS
        }
        self.refuse = set()  # (server id, op, nth call of that op): the helper answers not-ok
        self.raise_at = {}  # (server id, op, nth call): an exception the channel raises
        self.faults = {}  # server id -> a persistent fault of the control socket: "refused" | "timeout" | "handshake"
        self.identify_as = {}  # server id -> what a config-get answers as (default "Dhcp4")
        self.stuck_restart = set()  # server ids whose daemon ignores a restart (it keeps what it loaded)
        self.passwords = [
            CRED[1]
        ]  # every secret the Lab configured: T4 looks for each one in everything the route printed
        self.flashes, self.audits, self.incidents, self.settings_writes = [], [], [], []
        self.incident_records = []  # the whole record_attention call, for T4
        self.settings_error = None
        self.ca_a = None  # bytes of the CA Jen trusts before the rotation
        self.caplog = None
        self.expected_violations: set = (
            set()
        )  # ONLY the biting tests (`TestTheInvariantsBite`) name the invariants they expect the teardown to find
        self.before = None  # the state before the last request (T5, T3)
        self.flash_mark = 0
        self.answered_before: dict = {}  # server id -> did its daemon answer Jen's live identity before the last request (T3)
        self.ca_ok_before = True  # was Jen's CA a pair before the last request (T2 is RELATIVE: an action must not be the one that breaks it)
        self.record_before: dict = {}  # server id -> "match" | "none" | "mismatch": Jen's record of what its host holds, before the last request (T1 is RELATIVE too, Q192)
        self.dial_before: dict = {}  # server id -> did its daemon answer Jen's CONFIGURED dial (api_ca bundle + client certificate) before the last request (T3, second pass of Q190)

    def texts(self) -> str:
        return " ".join(t for _s, t in self.flashes)

    def request_texts(self) -> str:
        return " ".join(t for _s, t in self.flashes[self.flash_mark :])

    def everything_printed(self) -> str:
        logs = " ".join(r.getMessage() for r in self.caplog.records) if self.caplog is not None else ""
        return " ".join(
            [self.texts(), " ".join(str(a) for a in self.audits), " ".join(map(str, self.incident_records)), logs]
        )

    def answers(self, sid, ca_path, client_path=None) -> bool:
        """Would the daemon of server `sid` answer a client that trusts the CA at `ca_path` - and, with `client_path`, that presents the client certificate there? The daemon answers only to a
        client certificate issued by the CA IT loaded (`ca.crt` of the files it started with)."""
        loaded = self.hosts[sid]["loaded"]
        if not loaded or not _issued_by(loaded["server.crt"], ca_path):
            return False
        if client_path is not None:
            try:
                client_pem = pathlib.Path(client_path).read_text(encoding="ascii")
            except OSError:
                return False
            return _issued_by_pem(client_pem, loaded["ca.crt"])
        return True

    def answers_jens_live_identity(self, sid) -> bool:
        return self.answers(sid, kea_tls.ca_paths()[0], kea_tls.client_paths()[0])

    # ── the fake daemon's two separate relationships (Q192, AH0/AH1): the SERVER certificate it presents, and the CA it trusts for CLIENT certificates ──
    def jen_issued(self, sid) -> bool:
        loaded = self.hosts[sid]["loaded"]
        return bool(loaded) and _issued_by_jens(loaded["server.crt"])

    def accepts_client(self, sid, client_path) -> bool:
        """Does the daemon accept the client certificate at `client_path` (None: no certificate sent)? `client_trust` is the PEM of the CA it trusts for clients, INDEPENDENT of the CA that issued its
        server certificate; `None` means it requires no client certificate. The default is the old single-CA world: a Jen-issued daemon trusts the CA it loaded, an administrator's daemon asks for no
        client certificate."""
        h = self.hosts[sid]
        trust = h.get("client_trust", "default")
        if trust == "default":
            trust = h["loaded"]["ca.crt"] if self.jen_issued(sid) else None
        if trust is None:
            return True
        if not client_path:
            return False
        if trust == "any":
            return True  # a trust anchor that accepts any client certificate (a bundle that already holds the new CA, or no real check)
        try:
            pem = pathlib.Path(client_path).read_text(encoding="ascii")
        except OSError:
            return False
        # `trust` may be a BUNDLE (the operator added the new CA beside the current one): the certificate must be issued by any of them
        from cryptography import x509

        try:
            anchors = x509.load_pem_x509_certificates(trust.encode())
        except ValueError:
            return False
        return any(
            _anchor_usable(a) and _issued_by_pem(pem, a.public_bytes(kea_tls.serialization.Encoding.PEM).decode())
            for a in anchors
        )

    def server_verifies(self, sid, verify) -> bool:
        """Would a client verifying with `verify` (a CA bundle path, True for the system's CAs, False for none) accept the daemon's server certificate? `verifies` True is the stand-in for a daemon
        whose server certificate chains to something the client's configured verification accepts; the default is that an administrator's daemon does and a Jen-issued one must really chain."""
        h = self.hosts[sid]
        verifies = h.get("verifies", "default")
        if verifies == "default":
            verifies = not self.jen_issued(sid)
        if verifies or verify is False:
            return True
        if isinstance(verify, str):
            return _issued_by_any(h["loaded"]["server.crt"], verify)
        return False

    def answers_jens_configured_dial(self, sid) -> bool:
        """Would the daemon answer Jen as Jen is CONFIGURED to dial it: a server certificate issued by ANY certificate of the bundle at `[kea] api_ca` (or no verification at all when it is empty
        and verification is off), and the client certificate Jen presents issued by the CA the daemon loaded? A rotation that leaves the configured bundle on the old CA cuts this off even though
        the daemon answers Jen's live identity (the second pass of Q190: the dial, not the file Jen would like to be dialling with)."""
        loaded = self.hosts[sid]["loaded"]
        if not loaded:
            return False
        bundle = (extensions.KEA_API_CA or "").strip()
        verify = bundle or bool(getattr(extensions, "KEA_API_TLS_VERIFY", True))
        if not self.server_verifies(sid, verify):
            return False
        return self.accepts_client(sid, (extensions.KEA_API_CLIENT_CERT or "").strip() or None)

    def snapshot_dial(self):
        self.dial_before = {
            sid: self.answers_jens_configured_dial(sid) for sid in self.hosts if self.hosts[sid]["loaded"]
        }

    def add_server(self, sid, name, ssh_host, url, *, jen_issued=True, ca=None, password=None):
        """A server the rotation can see: configured, with a daemon that has loaded a certificate. `jen_issued` False is an administrator-managed endpoint (a certificate Jen's CA did not issue);
        a `password` is a secret the Lab configured, so T4 looks for it."""
        server = {"id": sid, "name": name, "ssh_host": ssh_host}
        self.servers[sid] = server
        self.urls[sid] = url
        self.hosts[sid] = {"files": None, "loaded": None, "installs": [], "restarts": 0, "calls": {}}
        if jen_issued:
            files = kea_tls.issue_server_cert(server, "dhcp4", ssh_host)
        else:
            files = ca or _external_files(ssh_host)
        self.hosts[sid]["files"] = self.hosts[sid]["loaded"] = copy.deepcopy(files)
        if password:
            self.passwords.append(password)
        extensions.KEA_SERVERS[:] = list(self.servers.values())
        self.answered_before[sid] = self.answers_jens_live_identity(sid)
        self.snapshot_dial()
        return server

    def install(self, sid, files):
        """What the route does: ask the helper to install `files` (the real `install_tls`, over the simulated helper)."""
        return kea_host.install_tls(self.servers[sid], "dhcp4", files)

    # ── the state before a request, and the invariants after every test ──
    def remote_actions(self) -> int:
        """Every install or restart the route ATTEMPTED - a host that refuses one was still asked (a lost reply may have applied it), so a refusal of the whole request is one where none was asked."""
        return sum(h["calls"].get("install-tls", 0) + h["calls"].get("service", 0) for h in self.hosts.values())

    def snapshot(self) -> dict:
        return {
            "local": _tree(kea_tls.SSL_DIR),
            "hosts": {sid: copy.deepcopy(h["files"]) for sid, h in self.hosts.items()},
            "remote": self.remote_actions(),
        }

    def begin(self):
        """Called by `_rotate()` just before the route runs."""
        self.before = self.snapshot()
        self.ca_ok_before = kea_tls.ca_consistent()
        self.record_before = {sid: self.record_state_of(sid) for sid in self.hosts}
        self.flash_mark = len(self.flashes)
        self.answered_before = {
            sid: self.answers_jens_live_identity(sid) for sid in self.hosts if self.hosts[sid]["loaded"]
        }
        self.snapshot_dial()

    def record_state_of(self, sid) -> str:
        """Jen's record of the pair this server's host holds, against the host: "match", "none" (Jen does not know) or "mismatch" (it names a pair the host does not hold)."""
        files = self.hosts[sid]["files"]
        if not files or not _issued_by_jens(files["server.crt"]):
            return "match"
        record = kea_tls.host_material(sid, "dhcp4")
        if record is None:
            return "none"
        return (
            "match"
            if record["server.crt"] == files["server.crt"] and record["server.key"] == files["server.key"]
            else "mismatch"
        )

    def _named(self, sid, categories) -> bool:
        return any(i[0] == sid and i[1] == "dhcp4" and i[2] in categories for i in self.incidents)

    def _refusal_names(self, sid) -> bool:
        """Did THIS request's own words say Jen has no record for that server (a refusal names it)?"""
        text = self.request_texts()
        label = self.servers.get(sid, {}).get("name", "")
        return (
            bool(label)
            and label in text
            and any(
                phrase in text
                for phrase in ("no complete record", "no certificate record", "cannot read the CA bundle")
            )
        )

    def _secrets(self) -> list:
        return secrets_of(
            self.passwords, self.urls.values(), [h["files"]["server.key"] for h in self.hosts.values() if h["files"]]
        )

    def check_invariants(self) -> list:
        """[(invariant, what is wrong)] - empty when T1-T5 hold."""
        bad = []
        jens_sids = [sid for sid, h in self.hosts.items() if h["files"] and _issued_by_jens(h["files"]["server.crt"])]
        # T1 - for every daemon whose pair JEN'S CA ISSUED (judged by the HOST's certificate), Jen's record of it is the pair the host holds, or Jen says it does not know. RELATIVE (Q192): a world that
        # STARTS with a lost or wrong record is the input (Health and the Rotate refusal say so - the worlds matrix checks that); what an ACTION may not do is lose or falsify a record it had.
        for sid in sorted(self.hosts):
            files = self.hosts[sid]["files"]
            if not files:
                continue
            if sid in jens_sids:
                record = kea_tls.host_material(sid, "dhcp4")
                before_state = self.record_before.get(sid, "match")
                if record is None:
                    if before_state == "none":
                        continue
                    if not (
                        self._named(sid, ("tls-local-stale", "remote-unknown", "tls-not-restored"))
                        or kea_tls.is_unknown(sid, "dhcp4")
                        or self._refusal_names(sid)
                        or kea_tls.ca_state()[0]
                        != "ok"  # Q192: the install payload needs the live CA certificate; a CA that is damaged or gone is itself the visible fact (Health fail, https setup refused)
                    ):
                        bad.append(
                            ("T1", f"server {sid}: Jen has no record of the pair its host holds and nothing says so")
                        )
                elif (
                    record["server.crt"] != files["server.crt"] or record["server.key"] != files["server.key"]
                ) and before_state != "mismatch":
                    bad.append(("T1", f"server {sid}: host_material is not the pair the host holds"))
            else:
                state, _why = kea_tls.record_state(sid, "dhcp4")
                if state == "jen":
                    bad.append(
                        (
                            "T1",
                            f"server {sid}: its certificate was not issued by a Jen CA and Jen holds a 'jen' record of it",
                        )
                    )
        # T2 - the CA is a pair, or every target says it is not
        if (
            not kea_tls.ca_consistent()
            and self.ca_ok_before
            and not (
                all(self._named(sid, ("tls-not-restored",)) for sid in jens_sids)
                and kea_tls.ca_state()[1]
                in self.texts()  # Q195 (AK2 b): the flash names what the CA IS now (`ca_state`'s why, never empty for an unusable CA) - no fallback word that any flash could match
            )
        ):
            bad.append(("T2", "Jen's CA certificate and key are not a pair and nothing says so"))
        # T3 (relative) - a daemon that answered Jen's live identity before the request answers after it, or an incident names it; one that did not answer before is untouched
        for sid in sorted(self.hosts):
            if not self.hosts[sid]["loaded"] and not self.answered_before.get(sid):
                continue
            before = self.answered_before.get(sid)
            now = self.answers_jens_live_identity(sid)
            if (
                self.dial_before.get(sid)
                and not self.answers_jens_configured_dial(sid)
                and not self._named(sid, _NAMES_A_SERVER)
            ):
                bad.append(
                    (
                        "T3",
                        f"server {sid}'s daemon answered Jen's CONFIGURED dial (api_ca and client certificate) before the request and does not now, and no incident names it",
                    )
                )
            if before and not now and not self._named(sid, _NAMES_A_SERVER):
                bad.append(
                    (
                        "T3",
                        f"server {sid}'s daemon answered Jen's live CA and client certificate before the request and does not now, and no incident names it",
                    )
                )
            # Q192: a rotation that REPORTS success is the one request that may move a Jen-issued daemon that did not answer before (a damaged client pair, a damaged CA replaced with the
            # acknowledgement) - and on that report EVERY Jen-issued daemon must answer Jen's live identity afterwards
            succeeded = "Kea CA rotated" in self.request_texts()
            if succeeded and self.jen_issued(sid) and not now:
                bad.append(
                    (
                        "T3",
                        f"server {sid}: a rotation reported success and its daemon does not answer Jen's live identity",
                    )
                )
            if before is False and not (succeeded and self.jen_issued(sid)):
                # (Q192: a recovery that FAILS part-way leaves hosts on the new CA that Jen cannot put back - named by a `tls-not-restored` / `remote-unknown` incident; that is saying so)
                if (
                    self.before is not None
                    and self.hosts[sid]["files"] != self.before["hosts"].get(sid)
                    and not self._named(sid, _NAMES_A_SERVER)
                ):
                    bad.append(
                        (
                            "T3",
                            f"server {sid}'s daemon did not answer Jen before the request and its files on the host CHANGED",
                        )
                    )
                if (
                    now and not self.jen_issued(sid)
                ):  # (a Jen-issued daemon answering once Jen's OWN identity is repaired is Jen's daemon, not a changed trust relationship)
                    bad.append(
                        (
                            "T3",
                            f"server {sid}'s daemon did not answer Jen before the request and does now (its trust relationship changed)",
                        )
                    )
        # T4 - no secret was printed anywhere: no PEM, no key, no configured password, no user-info
        found_secret = printed_secret(self.everything_printed(), self._secrets())
        if found_secret:
            bad.append(("T4", f"a secret was printed: {found_secret[:12]}..."))
        # T5 - a refusal changed nothing
        if self.before is not None:
            refused = self.remote_actions() == self.before["remote"] and "Kea CA rotated" not in self.request_texts()
            if refused:
                if _tree(kea_tls.SSL_DIR) != self.before["local"]:
                    bad.append(("T5", "a refusal changed a file under Jen's SSL directory"))
                if {sid: h["files"] for sid, h in self.hosts.items()} != self.before["hosts"]:
                    bad.append(("T5", "a refusal changed what a host holds"))
        return bad


def _issued_by_jens(cert_pem: str) -> bool:
    """Was this certificate issued by A Jen CA (the live one or an earlier one)? Judged by the HOST's certificate, not by Jen's files."""
    return issued_by_a_jen_ca(cert_pem)


def _external_files(ssh_host):
    """A certificate a Jen CA did not issue - an administrator's own CA."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(name("the administrator's CA"))
        .issuer_name(name("the administrator's CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("kea"))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ssh_host))]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    return {
        "ca.crt": ca.public_bytes(pem).decode(),
        "server.crt": leaf.public_bytes(pem).decode(),
        "server.key": key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
    }


@pytest.fixture
def lab(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    lab = Lab()
    lab.caplog = caplog
    monkeypatch.setattr(kea_tls, "SSL_DIR", str(tmp_path))
    monkeypatch.setattr(extensions, "KEA_SERVERS", list(lab.servers.values()))
    # Q197: the `openssl` CLI is the daemon's own library at the gate WHERE IT IS ON THE BOX; a Lab that did not decide would pass or fail with the machine. Off here - `_with_the_cli` turns it on
    monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: None)
    kea_tls._ORACLE_VERDICTS.clear()
    kea_tls._GATE_VERDICTS.clear()
    # Q197 (AM4): Health asks the inventory with the DEFAULT url source (`kea.configured_url`, a server's `api_url`); the Lab's servers carry their address in `lab.urls`, so that source answers from it - else every
    # copy would read as a record of an endpoint that is not https, and Health's stale-record rows would be the Lab's artefact
    from jen.services import kea as _kea

    monkeypatch.setattr(
        _kea,
        "configured_url",
        lambda server, service: lab.urls.get((server or {}).get("id"), "") if service == "dhcp4" else "",
    )

    def helper_call(server, op, payload=None, timeout=60):
        sid = server["id"]
        host = lab.hosts[sid]
        n = host["calls"][op] = host["calls"].get(op, 0) + 1
        if (sid, op, n) in lab.raise_at:
            raise lab.raise_at[(sid, op, n)]
        if (sid, op, n) in lab.refuse:
            return {"ok": False, "error": "write-failed", "detail": "refused"}
        if op == "install-tls":
            host["files"] = copy.deepcopy(payload["files"])
            host["installs"].append(copy.deepcopy(payload["files"]))
            return {"ok": True, "paths": {}, "owner": ""}
        if op == "service" and payload["action"] == "restart":
            if sid not in lab.stuck_restart:
                host["loaded"] = copy.deepcopy(host["files"])
            host["restarts"] += 1
            return {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        raise AssertionError(f"unexpected helper op {op!r}")

    monkeypatch.setattr(kea_host, "helper_call", helper_call)
    monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "_known_version", lambda *a, **k: 4)

    class _Reply:
        def __init__(self, body):
            self._body = body

        def raise_for_status(self):
            return None

        def json(self):
            return self._body

    def fake_post(url, json=None, auth=None, timeout=None, verify=None, cert=None):
        """The control socket, at the transport: Jen's REAL probe, identify and scrubbing code run over this. Every failure raises a `requests` exception whose TEXT carries the address as it was
        configured - user-info and all (Q190, AF2: that is what a real one can do)."""
        import requests as _rq

        sid = next((i for i, u in lab.urls.items() if u == url), None)
        assert sid is not None, f"the route dialled an address the Lab does not know: {url}"
        where = f"HTTPSConnectionPool: Max retries exceeded with url: {url}"
        fault = lab.faults.get(sid)
        loaded = lab.hosts[sid]["loaded"]
        if fault == "refused" or not loaded:
            raise _rq.exceptions.ConnectionError(f"{where} (Caused by NewConnectionError: Connection refused)")
        if fault == "timeout":
            raise _rq.exceptions.ConnectTimeout(f"{where} (Caused by ConnectTimeoutError)")
        if fault == "handshake":
            raise _rq.exceptions.SSLError(f"{where} (Caused by SSLError: handshake failure)")
        if not lab.server_verifies(sid, verify):
            raise _rq.exceptions.SSLError(f"{where} (Caused by SSLError: certificate verify failed)")
        if not lab.accepts_client(sid, cert[0] if cert else None):
            raise _rq.exceptions.SSLError(f"{where} (Caused by SSLError: client certificate rejected)")
        command = (json or {}).get("command")
        if command == "version-get":
            body = [{"result": 0, "text": "Kea 3.0.3", "arguments": {"extended": "Kea 3.0.3"}}]
        elif command == "config-get":
            body = [{"result": 0, "arguments": {lab.identify_as.get(sid, "Dhcp4"): {}, "hash": "x"}}]
        else:
            body = [{"result": 0}]
        return _Reply(body)

    import requests as _requests

    from jen.services import kea as _kea_svc

    monkeypatch.setattr(_kea_svc, "http", types.SimpleNamespace(post=fake_post, exceptions=_requests.exceptions))
    monkeypatch.setattr(infra, "_PROBE_DELAY_S", 0)
    monkeypatch.setattr(infra, "_server_by_id", lambda sid: lab.servers.get(sid))
    monkeypatch.setattr(
        infra, "_service_url", lambda server, service: lab.urls[server["id"]] if service == "dhcp4" else ""
    )
    monkeypatch.setattr(
        infra, "_configured_url", lambda server, service: lab.urls[server["id"]] if service == "dhcp4" else ""
    )  # (the inventory asks the CONFIGURED address; `_service_url` is the one the credential rule may blank)
    monkeypatch.setattr(
        extensions, "KEA_API_CA", kea_tls.ca_paths()[0]
    )  # Jen verifies against its own CA: its https endpoints are Jen's to rotate
    monkeypatch.setattr(infra, "_daemon_creds", lambda server, service, url="": CRED)
    monkeypatch.setattr(infra, "url_for", lambda *a, **k: "/settings/kea")
    monkeypatch.setattr(infra, "flash", lambda text, style="message": lab.flashes.append((style, str(text))))
    monkeypatch.setattr(infra.__dict__["__user"], "audit", lambda *a, **k: lab.audits.append(a))
    monkeypatch.setattr(
        "jen.services.capabilities.for_server", lambda sid, probe_kea=True: types.SimpleNamespace(tls=True)
    )

    def record_attention(server_id, service, operation, category, when=None, **kw):
        lab.incidents.append((server_id, service, category))
        lab.incident_records.append(
            (server_id, service, operation, category, kw.get("server_name", ""), kw.get("detail", ""))
        )
        return True

    def recovery_incidents(strict=False):
        return [
            {"kind": "attention", "category": c, "status": c, "service": s, "server_id": sid}
            for sid, s, c in lab.incidents
        ]

    def resolve_attention(server_id, service, *, categories=None):
        before = len(lab.incidents)
        lab.incidents[:] = [
            i
            for i in lab.incidents
            if not (str(i[0]) == str(server_id) and i[1] == service and (categories is None or i[2] in categories))
        ]
        return before - len(lab.incidents)

    monkeypatch.setattr(kea_changeset, "record_attention", record_attention)
    monkeypatch.setattr(kea_changeset, "recovery_incidents", recovery_incidents)
    monkeypatch.setattr(kea_changeset, "resolve_attention", resolve_attention)

    def write_values(items, typed=None):
        if lab.settings_error:
            raise lab.settings_error
        lab.settings_writes.append(list(items))

    monkeypatch.setattr(jconfig.app_config, "write_values", write_values)

    # the state before the rotation: the CA and Jen's client pair (CA-A), and a certificate issued by it on each host, loaded by its daemon
    kea_tls.ensure_ca()
    kea_tls.issue_client_cert()
    for sid, server in lab.servers.items():
        files = kea_tls.issue_server_cert(server, "dhcp4", server["ssh_host"])
        lab.hosts[sid]["files"] = lab.hosts[sid]["loaded"] = copy.deepcopy(files)
        lab.hosts[sid]["installs"].clear()
    lab.ca_a = pathlib.Path(kea_tls.ca_paths()[0]).read_bytes()
    lab.client_a = pathlib.Path(kea_tls.client_paths()[1]).read_bytes()
    monkeypatch.setattr(extensions, "KEA_API_CLIENT_CERT", kea_tls.client_paths()[0])
    monkeypatch.setattr(extensions, "KEA_API_CLIENT_KEY", kea_tls.client_paths()[1])
    lab.answered_before = {sid: lab.answers_jens_live_identity(sid) for sid in lab.hosts}
    lab.snapshot_dial()
    _ACTIVE.append(lab)
    yield lab
    _ACTIVE.pop()
    # AE0: the invariants, after EVERY test in this file
    found = lab.check_invariants()
    names = {name for name, _what in found}
    if lab.expected_violations:
        assert lab.expected_violations <= names, (
            f"the teardown should have named {sorted(lab.expected_violations)} (it found {sorted(names)}): {found}"
        )
    else:
        assert not found, f"INVARIANT(S) BROKEN at the end of the test: {found}"


def _rotate(form=None):
    lab = _ACTIVE[-1] if _ACTIVE else None
    if lab is not None:
        lab.begin()
    rotate = inspect.unwrap(infra.rotate_kea_ca)
    app = flask.Flask(__name__)
    app.secret_key = "x"
    with app.test_request_context(method="POST", data=form or {}):
        rotate()


def _fail_replace(monkeypatch, suffix: str, nth: int):
    """Make the `nth` `os.replace` whose destination ends with `suffix` raise (an I/O error at the FILE layer - below every function of the product that records things)."""
    real, seen = os.replace, [0]
    retrying = retrying_replace(real)

    def failing(src, dst, *a, **k):
        if str(dst).endswith(suffix):
            seen[0] += 1
            if seen[0] == nth:
                raise OSError(5, "Input/output error")
        return retrying(src, dst, *a, **k)

    monkeypatch.setattr(os, "replace", failing)
    return lambda: monkeypatch.setattr(os, "replace", real)  # the failure is over


def _local_pair_agrees_with_host(lab, sid):
    mine = kea_tls.current_material(sid, "dhcp4")
    host = lab.hosts[sid]["files"]
    return mine is not None and mine["server.crt"] == host["server.crt"] and mine["server.key"] == host["server.key"]


def _everyone_is_back_on_ca_a_and_answering(lab):
    ca = kea_tls.ca_paths()[0]
    assert pathlib.Path(ca).read_bytes() == lab.ca_a, "Jen still trusts CA-A"
    assert pathlib.Path(kea_tls.client_paths()[1]).read_bytes() == lab.client_a, "... and presents its own client pair"
    for sid in SERVERS:
        assert lab.answers(sid, ca), f"server {sid}'s daemon answers a client that trusts CA-A"
        assert _local_pair_agrees_with_host(lab, sid), f"Jen's copy for server {sid} IS what its host holds"
        assert kea_tls.issued_by(kea_tls.server_copy_path(sid, "dhcp4"), ca)
    assert not any(pathlib.Path(p).exists() for p in (ca + ".next", kea_tls.client_paths()[1] + ".next")), (
        "the staging is gone"
    )


class TestAPromotionThatFailsPutsEveryTargetBack:
    def test_the_promotion_failing_after_every_target_succeeded(self, lab, monkeypatch):
        def refuse(staged):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(kea_tls, "commit_rotation", refuse)
        _rotate()
        assert "Jen could not promote the new CA locally" in lab.texts() and "answering" in lab.texts()
        _everyone_is_back_on_ca_a_and_answering(lab)
        assert lab.incidents == []

    @pytest.mark.parametrize("victim", ["kea-ca.key", "kea-ca.crt", "jen-kea-client.key", "jen-kea-client.pem"])
    def test_a_file_of_the_set_that_cannot_be_replaced(self, lab, monkeypatch, victim):
        """The REAL `commit_rotation` -> `commit_file_set`: the set is replaced member by member and the failure of one puts the replaced ones back byte for byte."""
        real = os.replace
        retrying = retrying_replace(real)

        def failing(src, dst, *a, **k):
            if str(dst).endswith(victim):
                raise OSError(13, "Permission denied")
            return retrying(src, dst, *a, **k)

        monkeypatch.setattr(os, "replace", failing)
        _rotate()
        monkeypatch.setattr(os, "replace", real)
        assert "Jen could not promote the new CA locally" in lab.texts()
        _everyone_is_back_on_ca_a_and_answering(lab)
        assert lab.incidents == []

    def test_jens_settings_refused_stops_the_rotation_before_the_promotion(self, lab):
        lab.settings_error = jconfig.ConfigChangeRefused("Jen's settings could not be written")
        _rotate()
        assert "Jen could not save its TLS settings" in lab.texts()
        _everyone_is_back_on_ca_a_and_answering(lab)

    def test_the_success_path_old_material_survives_until_the_commit_and_only_the_new_exists_after(
        self, lab, monkeypatch
    ):
        seen = {}
        real = kea_tls.commit_rotation

        def spy(staged):
            ca = kea_tls.ca_paths()[0]
            seen["live_ca_is_a"] = pathlib.Path(ca).read_bytes() == lab.ca_a
            seen["staged_exist"] = all(pathlib.Path(p).exists() for p in staged.values())
            seen["prev_pairs"] = [
                pathlib.Path(kea_tls.server_copy_path(sid, "dhcp4") + ".prev").exists() for sid in SERVERS
            ]
            return real(staged)

        monkeypatch.setattr(kea_tls, "commit_rotation", spy)
        _rotate()
        assert seen == {"live_ca_is_a": True, "staged_exist": True, "prev_pairs": [True, True]}, (
            "until the commit: CA-A and Jen's client pair are live, the staging exists, and every target's earlier pair is kept"
        )
        ca = kea_tls.ca_paths()[0]
        assert pathlib.Path(ca).read_bytes() != lab.ca_a, "after the commit CA-B is the CA"
        for sid in SERVERS:
            assert lab.answers(sid, ca) and _local_pair_agrees_with_host(lab, sid)
            assert not pathlib.Path(kea_tls.server_copy_path(sid, "dhcp4") + ".prev").exists(), (
                "the earlier pairs are retired last"
            )
        assert not pathlib.Path(ca + ".next").exists() and lab.incidents == []
        assert "Kea CA rotated" in lab.texts()


class TestATargetThatFailsAfterTheFirstIsRolledBackAndTheNextIsNeverTouched:
    def test_the_local_copy_of_the_first_targets_pair_cannot_be_kept(self, lab, monkeypatch):
        real = kea_tls.commit_issued
        calls = []

        def failing_once(sid, service, files):
            calls.append(sid)
            if len(calls) == 1:
                raise OSError(28, "No space left on device")
            return real(sid, service, files)

        monkeypatch.setattr(kea_tls, "commit_issued", failing_once)
        _rotate()
        assert "Jen could not keep its own copy of the new certificate" in lab.texts()
        assert lab.hosts[2]["installs"] == [] and lab.hosts[2]["restarts"] == 0, "the second target was never touched"
        _everyone_is_back_on_ca_a_and_answering(lab)
        assert lab.incidents == []


class TestARollbackThatCannotCompleteIsNamed:
    def test_one_of_two_cannot_be_put_back_and_the_other_is_restored(self, lab, monkeypatch):
        def refuse(staged):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(kea_tls, "commit_rotation", refuse)
        lab.refuse.add((2, "install-tls", 2))  # server 2's rollback install (its 1st was the staged one) is refused
        _rotate()
        ca = kea_tls.ca_paths()[0]
        assert lab.answers(1, ca) and _local_pair_agrees_with_host(lab, 1), "the first target is restored"
        assert lab.incidents == [(2, "dhcp4", "tls-not-restored")], "... and the other is ONE incident naming it"
        assert "ROLLBACK FAILED on standby kea-dhcp4" in lab.texts()

    def test_a_restart_that_fails_after_the_old_pair_is_back_says_the_daemon_may_be_stopped(self, lab, monkeypatch):
        """AD8 (rewrites the beta.18 test that pinned the wrong rule): the old-CA reinstall SUCCEEDED and the restart failed - `restart-failed`, not `tls-not-restored`, and not 'holds a certificate from a CA Jen never adopted'."""

        def refuse(staged):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(kea_tls, "commit_rotation", refuse)
        lab.refuse.add((2, "service", 2))  # server 2's ROLLBACK restart (its 1st was the staged one) fails
        _rotate()
        assert lab.incidents == [(2, "dhcp4", "restart-failed")]
        texts = lab.texts()
        assert "may be stopped" in texts and "ROLLBACK FAILED" not in texts and "CA Jen never adopted" not in texts
        assert _local_pair_agrees_with_host(lab, 2), "the previous pair IS on the host and is Jen's copy"

    def test_a_target_whose_staged_install_was_refused_is_never_re_issued_or_restarted(self, lab):
        """AD8 (rewrites `test_the_failing_target_is_re_issued_from_the_live_ca...`): 'never known to have changed' means untouched - the pair Jen last put there is re-asserted WITHOUT a
        restart, and nothing is claimed rolled back."""
        lab.refuse.add((1, "install-tls", 1))
        _rotate()
        assert (
            "Rotate stopped" in lab.texts()
            and "Rolled back" not in lab.texts()
            and "ROLLBACK FAILED" not in lab.texts()
        )
        assert lab.hosts[1]["restarts"] == 0 and lab.hosts[2]["restarts"] == 0, "no daemon was restarted"
        assert lab.hosts[1]["installs"] == [lab.hosts[1]["files"]], (
            "the pair Jen last installed was re-asserted (a lost reply may have applied the staged one)"
        )
        assert lab.hosts[2]["installs"] == []
        _everyone_is_back_on_ca_a_and_answering(lab)
        assert lab.incidents == []

    def test_a_refused_install_that_cannot_be_re_asserted_is_an_incident_not_a_rollback_failure(self, lab):
        lab.refuse.update({(1, "install-tls", 1), (1, "install-tls", 2)})
        _rotate()
        # (Q193, AI4 e, adjusted: the helper REFUSED the new pair and Jen could not re-assert the old one - what the host holds is UNKNOWN, so `remote-unknown`; `tls-not-restored` says it is KNOWN to hold the staged pair)
        assert lab.incidents == [(1, "dhcp4", "remote-unknown")]
        assert "ROLLBACK FAILED" not in lab.texts() and lab.hosts[1]["restarts"] == 0


@pytest.mark.parametrize(
    "exc",
    [TimeoutError("timed out"), EOFError(), OSError(104, "Connection reset by peer")],
    ids=["timeout", "eof", "reset"],
)
class TestATransportExceptionNeverEscapes:
    """AD6: paramiko raises `socket.timeout`, `EOFError` or a reset-socket `OSError` from the channel; they are not `HelperError`. The real `install_tls` / `service_action` answer them as a failed
    answer, and the rotation's boundary does the rest - the route returns, says what happened, and leaves nothing on one CA with Jen on another."""

    @pytest.mark.parametrize(
        ("sid", "op", "nth"),
        [(1, "install-tls", 1), (1, "service", 1), (2, "install-tls", 1), (2, "service", 1)],
    )
    def test_at_each_call_site(self, lab, exc, sid, op, nth):
        lab.raise_at[(sid, op, nth)] = exc
        _rotate()  # no exception reaches here
        assert "Rotate stopped" in lab.texts()
        assert not any(pathlib.Path(p).exists() for p in (kea_tls.ca_paths()[0] + ".next",)), "the staging is discarded"
        ca = kea_tls.ca_paths()[0]
        assert pathlib.Path(ca).read_bytes() == lab.ca_a, "Jen still trusts CA-A"
        # every daemon that was restarted is either back on CA-A and answering, or recorded - never silently on CA-B
        for s in SERVERS:
            if not lab.answers(s, ca):
                assert any(i[0] == s for i in lab.incidents), f"server {s} is neither answering on CA-A nor an incident"

    @pytest.mark.parametrize(
        ("sid", "op", "nth"), [(1, "install-tls", 2), (1, "service", 2), (2, "install-tls", 2), (2, "service", 2)]
    )
    def test_inside_the_rollback_itself(self, lab, monkeypatch, exc, sid, op, nth):
        """A rotation that fails at the promotion, and then the CHANNEL fails during the rollback of one target: the route returns, the other target is restored, this one is an incident."""

        def refuse(staged):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(kea_tls, "commit_rotation", refuse)
        lab.raise_at[(sid, op, nth)] = exc
        _rotate()
        other = 2 if sid == 1 else 1
        assert lab.answers(other, kea_tls.ca_paths()[0]) and not any(i[0] == other for i in lab.incidents)
        assert any(i[0] == sid for i in lab.incidents), "the target whose rollback was cut is recorded, never silent"
        assert not pathlib.Path(kea_tls.ca_paths()[0] + ".next").exists()

    def test_setup_install_and_restart_are_failed_answers_not_exceptions(self, lab, exc):
        lab.raise_at[(1, "install-tls", 1)] = exc
        assert kea_host.install_tls(SERVERS[1], "dhcp4", {"ca.crt": "x"})["ok"] is False
        lab.raise_at[(1, "service", 1)] = exc
        out = kea_host.service_action(SERVERS[1], "dhcp4", "restart")
        assert out["ok"] is False and out["transport"] is True and out["detail"] == type(exc).__name__


def test_a_programming_error_in_the_rotation_still_leaves_the_hosts_where_they_were(lab, monkeypatch):
    """The boundary also holds against an exception nobody planned for: it stops the rotation, rolls back, discards the staging."""
    real = kea_tls.issue_server_cert
    calls = []

    def boom(server, service, bind, ca=None, commit=True):
        calls.append(server["id"])
        if len(calls) == 2:
            raise RuntimeError("a bug")
        return real(server, service, bind, ca=ca, commit=commit)

    monkeypatch.setattr(kea_tls, "issue_server_cert", boom)
    _rotate()
    assert "Rotate stopped" in lab.texts()
    _everyone_is_back_on_ca_a_and_answering(lab)


class TestTheSecondPassOfQ188:
    """The findings of the adversarial second pass, each as the sequence that found it."""

    def test_the_previous_ca_pair_that_cannot_be_kept_locally_is_a_stale_copy_not_a_stuck_host(self, lab, monkeypatch):
        """The rollback put the CA-A pair on the host and the daemon answers; only Jen's own copy of it could not follow. That is `tls-local-stale` - not `tls-not-restored`, and the host is still
        restarted and probed. Q189 (AE2): and the record of what the host holds is that pair - `.prev` IS the pair the host was given, and `host_material` answers it byte for byte.
        (Adjusted from beta.19: the failure used to be injected by replacing `commit_issued` itself, which also replaced the very recording this Q is about; it is injected at the file layer now.)"""
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        _fail_replace(
            monkeypatch, "1-dhcp4.key", nth=2
        )  # the 2nd write of server 1's live key is the rollback's, before either file of the pair
        _rotate()
        ca = kea_tls.ca_paths()[0]
        assert lab.answers(1, ca) and lab.answers(2, ca), "both daemons answer on CA-A afterwards"
        assert (1, "dhcp4", "tls-local-stale") in lab.incidents and not any(
            i[2] == "tls-not-restored" for i in lab.incidents
        )
        assert kea_tls.is_stale(1, "dhcp4") and not kea_tls.is_stale(2, "dhcp4")
        held = lab.hosts[1]["files"]
        record = kea_tls.host_material(1, "dhcp4")
        assert record is not None and (record["server.crt"], record["server.key"]) == (
            held["server.crt"],
            held["server.key"],
        )
        prev = kea_tls.server_copy_path(1, "dhcp4") + ".prev"
        assert pathlib.Path(prev).read_bytes().decode() == held["server.crt"], "`.prev` IS the pair the host was given"

    def test_a_ca_whose_certificate_and_key_are_apart_issues_nothing(self, lab, monkeypatch):
        """A promotion that replaced the CA certificate and could not put it back leaves a certificate and key that are not a pair; nothing is issued from it and the sentence does not say Jen still trusts the previous CA."""
        real_commit = kea_tls.commit_rotation

        def half(staged):
            pathlib.Path(kea_tls.ca_paths()[0]).write_bytes(pathlib.Path(staged["ca_cert"]).read_bytes())
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(kea_tls, "commit_rotation", half)
        issued = []
        real_issue = kea_tls.issue_server_cert
        monkeypatch.setattr(
            kea_tls,
            "issue_server_cert",
            lambda *a, **k: issued.append(k.get("ca")) or real_issue(*a, **k),
        )
        assert real_commit is not None
        _rotate()
        assert not kea_tls.ca_consistent()
        assert issued.count(None) == 0, "no certificate is issued from a CA that is not a pair"
        assert "no longer a matching pair" in lab.texts() and "Jen still trusts the previous CA" not in lab.texts()
        assert sorted(i[2] for i in lab.incidents) == ["tls-not-restored", "tls-not-restored"]

    def test_a_staging_that_stops_half_written_leaves_no_key_behind(self, lab, monkeypatch):
        real = kea_tls.commit_file_set

        def the_staging_set_fails(members, *a, **k):
            if any(str(path).endswith(".next") for path, _data, _mode in members):
                raise OSError(
                    28, "No space left on device"
                )  # (Q197, AM6 b: the four `.next` files are ONE set now - a failure leaves none of them)
            return real(members, *a, **k)

        monkeypatch.setattr(kea_tls, "commit_file_set", the_staging_set_fails)
        _rotate()
        ca = kea_tls.ca_paths()[0]
        assert "Rotate refused" in lab.texts() and "Nothing was changed" in lab.texts()
        assert not any(pathlib.Path(ca).parent.glob("*.next")), "the staging is gone, key included"
        assert all(h["installs"] == [] and h["restarts"] == 0 for h in lab.hosts.values()), "no host was touched"

    def test_an_exception_in_the_rollback_of_one_target_does_not_stop_the_next(self, lab, monkeypatch):
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        real = infra._endpoint_answers
        calls = []

        def boom_once(ctx, service):
            calls.append(ctx["url"])
            if len(calls) == 1:
                raise RuntimeError("a bug")
            return real(ctx, service)

        monkeypatch.setattr(infra, "_endpoint_answers", boom_once)
        _rotate()
        assert len(calls) >= 2, "the second target was still rolled back and probed"
        assert (1, "dhcp4", "restored-endpoint-unreachable") in lab.incidents


class TestAStaleCopyIsTheHostsPreviousPair:
    """`.stale`: Jen's live pair is KNOWN not to be the host's; `.prev` is, until a later commit."""

    def _issue(self, sid, host):
        return kea_tls.issue_server_cert({"id": sid, "name": "k", "ssh_host": host}, "dhcp4", host, commit=False)

    def test_the_marker_decides_which_pair_is_the_hosts_and_a_commit_ends_it(self, lab, monkeypatch):
        sid = 1
        first = pathlib.Path(kea_tls.server_copy_path(sid, "dhcp4")).read_text(encoding="ascii")
        staged = self._issue(sid, "10.0.0.5")
        kea_tls.stage_issued(sid, "dhcp4", staged)
        assert lab.install(sid, staged)["ok"]  # the host takes the new pair, as the route does before it promotes
        kea_tls.promote_staged(sid, "dhcp4")  # live = B, .prev = the pair the host had (first)
        assert not kea_tls.is_stale(sid, "dhcp4")
        assert lab.install(sid, kea_tls.previous_material(sid, "dhcp4"))[
            "ok"
        ]  # ... and the route puts the previous pair back on the host
        with monkeypatch.context() as scoped:
            scoped.setattr(kea_tls, "commit_file_set", lambda *a, **k: (_ for _ in ()).throw(OSError(13, "denied")))
            assert kea_tls.restore_previous(sid, "dhcp4") is False
        assert kea_tls.is_stale(sid, "dhcp4")
        host = kea_tls.host_material(sid, "dhcp4")
        assert host is not None and host["server.crt"] == first, "the host's truth is .prev, not the live pair"
        again = self._issue(sid, "10.0.0.5")
        kea_tls.stage_issued(sid, "dhcp4", again)
        assert pathlib.Path(kea_tls.server_copy_path(sid, "dhcp4") + ".prev").read_text(encoding="ascii") == first, (
            "the next operation does not overwrite the host's pair with the live one"
        )
        assert lab.install(sid, again)["ok"]
        kea_tls.promote_staged(sid, "dhcp4")
        kea_tls.commit_issued(sid, "dhcp4", again)
        assert not kea_tls.is_stale(sid, "dhcp4"), "a commit means the host was given exactly this pair"

    def test_a_re_assert_installs_the_pair_the_host_holds_not_jens_stale_live_copy(self, lab, monkeypatch):
        sid = 1
        first = pathlib.Path(kea_tls.server_copy_path(sid, "dhcp4")).read_text(encoding="ascii")
        staged = self._issue(sid, "10.0.0.5")
        kea_tls.stage_issued(sid, "dhcp4", staged)
        assert lab.install(sid, staged)["ok"]
        kea_tls.promote_staged(sid, "dhcp4")
        assert lab.install(sid, kea_tls.previous_material(sid, "dhcp4"))["ok"]
        with monkeypatch.context() as scoped:
            scoped.setattr(kea_tls, "commit_file_set", lambda *a, **k: (_ for _ in ()).throw(OSError(13, "denied")))
            assert kea_tls.restore_previous(sid, "dhcp4") is False
        assert infra._reinstall_live_material(SERVERS[sid], "dhcp4") == "restored"
        assert lab.hosts[sid]["installs"][-1]["server.crt"] == first, (
            "the host gets ITS pair back, not Jen's newer live one"
        )

    def test_a_first_setup_whose_promotion_fails_does_not_claim_a_certificate_was_put_back(self, lab):
        sid = 1
        lab.hosts[sid]["files"] = lab.hosts[sid]["loaded"] = (
            None  # a FIRST https setup: the host holds no Jen pair, and Jen keeps none
        )
        for suffix in ("", ".prev"):
            for path in (kea_tls.server_copy_path(sid, "dhcp4"), kea_tls.server_key_path(sid, "dhcp4")):
                if os.path.exists(path + suffix):
                    os.unlink(path + suffix)
        lab.begin()  # (the world the operation starts from: no daemon, no copies)
        infra._stop_after_failed_promotion(SERVERS[sid], "dhcp4", OSError(13, "Permission denied"), [], None)
        assert "was put back" not in lab.texts() and "no earlier copy to put back" in lab.texts(), lab.texts()


class TestInventory:
    """Q189 (AE1): the rotation's targets are every https endpoint Jen DIALS, each with a complete record of its certificate - never the listing of local copy files. T5 (a refusal changes
    nothing) is checked by the fixture's teardown after every one of these."""

    def _no_remote_action(self, lab):
        assert lab.remote_actions() == 0, "a refusal happens before any host is touched"
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() == lab.ca_a

    def test_both_copies_present_two_targets_rotated(self, lab):
        _rotate()
        ca, client = kea_tls.ca_paths()[0], kea_tls.client_paths()[0]
        assert (
            "Kea CA rotated" in lab.texts() and "kea-a kea-dhcp4" in lab.texts() and "standby kea-dhcp4" in lab.texts()
        )
        assert lab.answers(1, ca, client) and lab.answers(2, ca, client)
        assert pathlib.Path(ca).read_bytes() != lab.ca_a

    def test_a_missing_copy_is_a_refusal_naming_the_server_and_its_url(self, lab):
        os.unlink(kea_tls.server_copy_path(2, "dhcp4"))
        _rotate()
        text = lab.texts()
        assert "Rotate refused" in text and "standby kea-dhcp4" in text and "https://10.0.0.6:8004" in text
        assert "no complete record of its certificate" in text and "missing" in text
        assert "nothing to rotate" not in text.lower() and "Kea CA rotated" not in text
        self._no_remote_action(lab)

    def test_the_copies_directory_missing_with_https_endpoints_is_a_refusal_for_each(self, lab):
        import shutil

        shutil.rmtree(os.path.dirname(kea_tls.server_copy_path(1, "dhcp4")))
        _rotate()
        text = lab.texts()
        assert (
            text.count("holds no certificate record for it") == 2
            and "kea-a kea-dhcp4" in text
            and "standby kea-dhcp4" in text
        )
        self._no_remote_action(lab)

    def test_a_directory_that_cannot_be_listed_is_a_refusal_not_nothing_to_rotate(self, lab, monkeypatch):
        directory = os.path.dirname(kea_tls.server_copy_path(1, "dhcp4"))
        real = os.listdir

        def listdir(path="."):
            if os.fspath(path) == directory:
                raise PermissionError(13, "Permission denied")
            return real(path)

        monkeypatch.setattr(os, "listdir", listdir)
        _rotate()
        text = lab.texts()
        assert "could not read its certificate directory" in text and directory in text and "Rotate refused" in text
        assert "Kea CA rotated" not in text
        self._no_remote_action(lab)
        # strict raises; the non-strict form (Health's) stays quiet
        with pytest.raises(PermissionError):
            kea_tls.issued_server_copies(strict=True)
        assert kea_tls.issued_server_copies() == []

    def test_a_copy_that_is_not_a_certificate_is_a_refusal(self, lab):
        pathlib.Path(kea_tls.server_copy_path(1, "dhcp4")).write_text("this is not a certificate", encoding="ascii")
        _rotate()
        assert "malformed" in lab.texts() and "kea-a kea-dhcp4" in lab.texts()
        self._no_remote_action(lab)

    def test_a_copy_with_its_key_missing_is_a_refusal(self, lab):
        os.unlink(kea_tls.server_key_path(1, "dhcp4"))
        _rotate()
        assert "its key is missing" in lab.texts()
        self._no_remote_action(lab)

    def test_a_key_that_is_another_certificates_is_a_refusal(self, lab):
        other = kea_tls.issue_server_cert(
            {"id": 7, "name": "x", "ssh_host": "10.0.0.7"}, "dhcp4", "10.0.0.7", commit=False
        )
        pathlib.Path(kea_tls.server_key_path(1, "dhcp4")).write_text(other["server.key"], encoding="ascii")
        _rotate()
        assert "not a pair" in lab.texts()
        self._no_remote_action(lab)

    def test_a_certificate_an_earlier_jen_ca_issued_is_a_refusal_not_an_external_endpoint(self, lab):
        """Jen's own CA name on the issuer is the difference: an endpoint left on CA-A after a rotation moved Jen to CA-B is Jen's to fix, not an administrator's to leave alone."""
        staged = kea_tls.stage_rotation()
        kea_tls.commit_rotation(staged)  # Jen's live CA is now CA-B; server copies are still CA-A's
        _rotate()
        assert "earlier Jen CA" in lab.texts() and "Kea CA rotated" not in lab.texts()

    def test_an_administrator_managed_endpoint_is_named_and_left_alone(self, lab):
        server = lab.add_server(3, "external", "10.0.0.7", "https://10.0.0.7:8004", jen_issued=False)
        external = lab.hosts[3]["files"]
        pathlib.Path(kea_tls.server_copy_path(3, "dhcp4")).write_text(external["server.crt"], encoding="ascii")
        pathlib.Path(kea_tls.server_key_path(3, "dhcp4")).write_text(external["server.key"], encoding="ascii")
        assert server["id"] == 3
        _rotate()
        text = lab.texts()
        assert "Not on Jen's CA, so not rotated and left alone" in text and "external" in text
        assert "Kea CA rotated" in text
        assert lab.hosts[3]["installs"] == [] and lab.hosts[3]["restarts"] == 0, (
            "the administrator's endpoint was never touched"
        )
        ca, client = kea_tls.ca_paths()[0], kea_tls.client_paths()[0]
        assert lab.answers(1, ca, client) and lab.answers(2, ca, client)

    def test_a_copy_for_a_server_that_is_gone_is_ignored_and_said(self, lab):
        kea_tls.issue_server_cert({"id": 9, "name": "gone", "ssh_host": "10.0.0.9"}, "dhcp4", "10.0.0.9")
        _rotate()
        assert "Kea CA rotated" in lab.texts() and "9-dhcp4" in lab.texts() and "ignored" in lab.texts()

    def test_zero_https_endpoints_rotates_jens_ca_and_client_only(self, lab):
        for sid in (1, 2):
            lab.urls[sid] = lab.urls[sid].replace("https://", "http://")
            lab.hosts[sid]["files"] = lab.hosts[sid]["loaded"] = None  # no daemon runs Jen's TLS material
        _rotate()
        assert "Kea CA rotated" in lab.texts() and "no server certificate was involved" in lab.texts()
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() != lab.ca_a
        assert lab.remote_actions() == 0

    def test_a_server_without_an_ssh_host_still_blocks_the_rotation(self, lab):
        lab.servers[2]["ssh_host"] = ""
        _rotate()
        assert "no SSH host" in lab.texts() and "Rotate refused" in lab.texts()
        self._no_remote_action(lab)

    def test_the_confirm_page_summary_is_the_inventory(self, lab):
        summary = infra._kea_ca_summary()
        assert [(n, s) for n, s, _d in summary["issued"]] == [("kea-a", "dhcp4"), ("standby", "dhcp4")]
        os.unlink(kea_tls.server_copy_path(2, "dhcp4"))
        os.unlink(
            kea_tls.server_key_path(2, "dhcp4")
        )  # (standby: Jen's record is gone - the page and the route must say the same thing about it)
        summary = infra._kea_ca_summary()
        assert [(n, s) for n, s, _d in summary["issued"]] == [("kea-a", "dhcp4")]
        assert summary["refused"] and "standby kea-dhcp4" in summary["refused"][0]
        _rotate()
        assert "standby kea-dhcp4" in lab.texts() and "Rotate refused" in lab.texts()


class TestHostRecord:
    """Q189 (AE2): Jen's record of what a host holds is the exact payload that host accepted - or "unknown". The review's sequence, on real files: A1 under CA-A, B under the staged CA-B
    committed, the promotion fails, A2 is issued and installed on the rollback, and Jen's write of A2 fails."""

    @staticmethod
    def _rollback_with_the_write_of_a2_failing(monkeypatch, suffix, nth):
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        return _fail_replace(monkeypatch, suffix, nth)

    def _record_is_the_hosts_pair(self, lab, sid=1):
        held = lab.hosts[sid]["files"]
        record = kea_tls.host_material(sid, "dhcp4")
        assert record is not None, "Jen's record names the pair the host holds"
        assert (record["server.crt"], record["server.key"]) == (held["server.crt"], held["server.key"])
        prev = kea_tls.server_copy_path(sid, "dhcp4") + ".prev"
        assert pathlib.Path(prev).read_bytes().decode() == held["server.crt"], (
            "`.prev` IS the payload the host accepted"
        )
        assert pathlib.Path(kea_tls.server_key_path(sid, "dhcp4") + ".prev").read_bytes().decode() == held["server.key"]
        assert kea_tls.is_stale(sid, "dhcp4")
        return held

    def test_the_reviews_sequence_a2_fails_before_either_file(self, lab, monkeypatch):
        before = copy.deepcopy(lab.hosts[1]["files"])
        self._rollback_with_the_write_of_a2_failing(monkeypatch, "1-dhcp4.key", nth=2)
        _rotate()
        held = self._record_is_the_hosts_pair(lab)
        assert held["server.crt"] != before["server.crt"], "the host holds a NEW pair (A2), not the one it started with"
        assert (1, "dhcp4", "tls-local-stale") in lab.incidents
        # the live local pair is still the staged-CA pair (B), and is NOT what the host holds - exactly the state the beta.19 code called 'the host's truth'
        assert kea_tls.current_material(1, "dhcp4")["server.crt"] != held["server.crt"]

    def test_the_same_with_the_failure_after_the_first_file(self, lab, monkeypatch):
        """The key is replaced, the certificate is not: `commit_file_set` puts the key back, and the record is still A2."""
        self._rollback_with_the_write_of_a2_failing(monkeypatch, "1-dhcp4.crt", nth=2)
        _rotate()
        self._record_is_the_hosts_pair(lab)
        assert (1, "dhcp4", "tls-local-stale") in lab.incidents

    def test_a_re_assert_installs_the_pair_the_host_holds(self, lab, monkeypatch):
        stop = self._rollback_with_the_write_of_a2_failing(monkeypatch, "1-dhcp4.key", nth=2)
        _rotate()
        held = copy.deepcopy(lab.hosts[1]["files"])
        stop()  # the file-layer failure is over
        assert infra._reinstall_live_material(SERVERS[1], "dhcp4") == "restored"
        assert lab.hosts[1]["installs"][-1]["server.crt"] == held["server.crt"], (
            "the host gets ITS pair back - never the CA-B pair that is Jen's live copy"
        )

    def test_an_unwritable_ssl_directory_loses_the_record_and_Jen_says_so(self, lab, monkeypatch):
        """Neither the live pair nor `.prev` nor the marker can be written: HostRecordLost, a remote-unknown incident, host_material None - and a following re-assert installs NOTHING."""
        from jen.services import private_files

        state = {"on": False}
        real_commit, real_write = kea_tls.commit_file_set, private_files.write_private_file

        def commit(*a, **k):
            if state["on"]:
                raise OSError(30, "Read-only file system")
            return real_commit(*a, **k)

        def write(*a, **k):
            if state["on"]:
                raise OSError(30, "Read-only file system")
            return real_write(*a, **k)

        monkeypatch.setattr(kea_tls, "commit_file_set", commit)
        monkeypatch.setattr(private_files, "write_private_file", write)

        def promotion_fails_and_the_directory_goes_read_only(staged):
            state["on"] = True
            raise OSError(28, "full")

        monkeypatch.setattr(kea_tls, "commit_rotation", promotion_fails_and_the_directory_goes_read_only)
        _rotate()
        assert (1, "dhcp4", "remote-unknown") in lab.incidents and (2, "dhcp4", "remote-unknown") in lab.incidents
        assert "cannot record which certificate" in lab.texts() and "do not rely on Jen's copy" in lab.texts()
        assert kea_tls.host_material(1, "dhcp4") is None
        state["on"] = False
        installs = len(lab.hosts[1]["installs"])
        assert infra._reinstall_live_material(SERVERS[1], "dhcp4") == "none", "unknown: no install"
        assert len(lab.hosts[1]["installs"]) == installs

    def test_commit_issued_raises_host_record_lost_when_nothing_can_be_recorded(self, lab, monkeypatch):
        files = kea_tls.issue_server_cert(SERVERS[1], "dhcp4", "10.0.0.5", commit=False)
        monkeypatch.setattr(
            kea_tls, "commit_file_set", lambda *a, **k: (_ for _ in ()).throw(OSError(30, "Read-only file system"))
        )
        with pytest.raises(kea_tls.HostRecordLost):
            kea_tls.commit_issued(1, "dhcp4", files)
        # whatever `.prev` is left is not mistaken for the host's pair, and the FILE layer says Jen does not know (this directory still takes a small file)
        assert not pathlib.Path(kea_tls.server_copy_path(1, "dhcp4") + ".prev").exists()
        assert kea_tls.is_unknown(1, "dhcp4") and kea_tls.host_material(1, "dhcp4") is None
        lab.incidents.append(
            (1, "dhcp4", "remote-unknown")
        )  # (the route records this; the lab's teardown wants the incident naming the server)

    def test_a_retry_that_succeeds_clears_the_marker(self, lab, monkeypatch):
        stop = self._rollback_with_the_write_of_a2_failing(monkeypatch, "1-dhcp4.key", nth=2)
        _rotate()
        stop()
        held = copy.deepcopy(lab.hosts[1]["files"])
        kea_tls.commit_issued(1, "dhcp4", held)  # the directory is writable again: the host holds exactly `held`
        assert not kea_tls.is_stale(1, "dhcp4")
        # a standing 'Jen's copy differs' note with no marker left is UNKNOWN until the route that retried resolves it (the route does, after the answer it got)
        assert kea_tls.host_material(1, "dhcp4") is None
        assert kea_changeset.resolve_attention(1, "dhcp4", categories=("tls-local-stale",)) == 1
        record = kea_tls.host_material(1, "dhcp4")
        assert record is not None and record["server.crt"] == held["server.crt"]

    def test_the_marker_is_a_file_so_it_survives_a_restart(self, lab, monkeypatch):
        self._rollback_with_the_write_of_a2_failing(monkeypatch, "1-dhcp4.key", nth=2)
        _rotate()
        marker = kea_tls.server_copy_path(1, "dhcp4") + ".stale"
        assert os.path.exists(marker) and kea_tls.is_stale(1, "dhcp4")
        # a new process reads the same directory: nothing is held in memory
        assert kea_tls.host_material(1, "dhcp4")["server.crt"] == lab.hosts[1]["files"]["server.crt"]

    def test_a_later_successful_setup_on_that_server_clears_it(self, lab, monkeypatch):
        stop = self._rollback_with_the_write_of_a2_failing(monkeypatch, "1-dhcp4.key", nth=2)
        _rotate()
        stop()
        staged = kea_tls.issue_server_cert(SERVERS[1], "dhcp4", "10.0.0.5", commit=False)
        kea_tls.stage_issued(1, "dhcp4", staged)
        assert lab.install(1, staged)["ok"]
        kea_tls.promote_staged(1, "dhcp4")
        kea_tls.retire_previous(1, "dhcp4")  # what the setup route does when it stands
        assert not kea_tls.is_stale(1, "dhcp4")
        kea_changeset.resolve_attention(1, "dhcp4")


class TestTheInvariantsBite:
    """Q189 (AE0): one deliberately failing test per invariant - the product is broken on purpose and the teardown check must name the invariant, so a later edit cannot quietly weaken a check."""

    def test_T1_bites_when_the_record_is_made_the_way_beta19_made_it(self, lab, monkeypatch):
        lab.expected_violations = {"T1"}
        monkeypatch.setattr(
            kea_tls,
            "_record_host_pair",
            lambda server_id, service, files, cause: kea_tls.mark_stale(server_id, service),
        )  # the beta.19 behaviour: `.prev` is whatever commit_file_set copied
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        _fail_replace(monkeypatch, "1-dhcp4.key", nth=2)
        _rotate()
        assert (1, "dhcp4", "tls-local-stale") in lab.incidents, (
            "the route still said so - and the record it points at is the wrong pair"
        )

    def test_T2_bites_when_a_split_ca_is_not_said(self, lab, monkeypatch):
        lab.expected_violations = {"T2"}

        def half(staged):
            pathlib.Path(kea_tls.ca_paths()[0]).write_bytes(pathlib.Path(staged["ca_cert"]).read_bytes())
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(kea_tls, "commit_rotation", half)
        monkeypatch.setattr(kea_changeset, "record_attention", lambda *a, **k: True)  # the incidents are lost
        monkeypatch.setattr(infra, "flash", lambda text, style="message": None)  # ... and so is the sentence
        _rotate()
        assert not kea_tls.ca_consistent()

    def test_T3_bites_when_the_rotation_forgets_an_endpoint(self, lab, monkeypatch):
        """The beta.19 defect itself: the targets came from a listing of local files, an unlistable one read as empty, the rotation 'succeeded', and every daemon still presented CA-A material."""
        lab.expected_violations = {"T3"}
        monkeypatch.setattr(
            kea_tls,
            "rotation_inventory",
            lambda servers, url_for=None, **kw: kea_tls.RotationInventory([], [], [], [], frozenset()),
        )
        _rotate()
        assert "Kea CA rotated" in lab.texts(), "the rotation reported success"

    def test_T4_bites_when_a_key_reaches_a_sentence(self, lab, monkeypatch):
        lab.expected_violations = {"T4"}
        key = lab.hosts[1]["files"]["server.key"]
        real = kea_host.service_action
        monkeypatch.setattr(
            kea_host,
            "service_action",
            lambda server, service, action: (
                {"ok": False, "detail": key} if server["id"] == 1 else real(server, service, action)
            ),
        )
        _rotate()

    def test_T5_bites_when_a_refusal_leaves_a_file_behind(self, lab, monkeypatch):
        lab.expected_violations = {"T5"}
        real = kea_tls.rotation_inventory

        def refusing_after_writing(servers, url_for=None, **kw):
            (pathlib.Path(kea_tls.SSL_DIR) / "stray-file").write_text("left behind", encoding="ascii")
            inv = real(servers, url_for=url_for, **kw)
            inv.refusals.append("refused on purpose")
            return inv

        monkeypatch.setattr(kea_tls, "rotation_inventory", refusing_after_writing)
        _rotate()
        assert "Rotate refused" in lab.texts()


def _fail_replace_matching(monkeypatch, suffixes):
    """Make EVERY `os.replace` whose destination ends with one of `suffixes` raise (a directory where the pair and its `.prev` copy cannot be written but a small marker file can)."""
    real = os.replace
    retrying = retrying_replace(real)

    def failing(src, dst, *a, **k):
        if any(str(dst).endswith(s) for s in suffixes):
            raise OSError(5, "Input/output error")
        return retrying(src, dst, *a, **k)

    monkeypatch.setattr(os, "replace", failing)
    return lambda: monkeypatch.setattr(os, "replace", real)


class TestTheSecondPassOfQ189:
    """The findings of the adversarial second pass of beta.20, each as the sequence that found it."""

    # finding 1 - the inventory reads the CONFIGURED address, not the transport's answer
    def test_configured_url_is_the_address_whatever_the_credential_rule_says(self):
        from jen.services import kea

        server = {
            "id": 2,
            "name": "standby",
            "api_url": "https://10.0.0.6:8004",
            "api_withheld": "kea",
            "api6_url": "https://10.0.0.6:8006",
            "api6_withheld": "kea",
        }
        assert isinstance(kea._endpoint_for(server, "dhcp4"), dict), (
            "the transport answers a sentence for a withheld password"
        )
        assert kea.configured_url(server, "dhcp4") == "https://10.0.0.6:8004"
        assert kea.configured_url(server, "dhcp6") == "https://10.0.0.6:8006"
        assert kea.configured_url({"id": 3}, "d2") == ""

    def test_an_endpoint_whose_credential_is_withheld_blocks_the_rotation_instead_of_dropping_out(
        self, lab, monkeypatch
    ):
        monkeypatch.setattr(
            infra, "_service_url", lambda server, service: "" if server["id"] == 2 else lab.urls[server["id"]]
        )
        _rotate()
        text = lab.texts()
        assert "Rotate refused" in text and "standby kea-dhcp4" in text and "no credential" in text
        assert "Kea CA rotated" not in text and lab.remote_actions() == 0

    # finding 5 - a trust anchor that is not Jen's makes the https endpoints the administrator's
    def test_https_endpoints_Jen_never_issued_a_certificate_for_are_not_a_refusal(self, lab, monkeypatch, tmp_path):
        """A bundle of an administrator's CAs only (two of them): every endpoint runs the administrator's material, Jen holds no record of any, and Rotate rotates Jen's own CA and client alone."""
        bundle = tmp_path / "the-administrators-cas.pem"
        bundle.write_text(
            _external_files("10.0.0.5")["ca.crt"] + _external_files("10.0.0.6")["ca.crt"], encoding="ascii"
        )
        monkeypatch.setattr(extensions, "KEA_API_CA", str(bundle))
        for sid in (1, 2):
            lab.hosts[sid]["files"] = lab.hosts[sid]["loaded"] = _external_files(lab.servers[sid]["ssh_host"])
            os.unlink(kea_tls.server_copy_path(sid, "dhcp4"))
            os.unlink(kea_tls.server_key_path(sid, "dhcp4"))
        _rotate()
        text = lab.texts()
        assert (
            "Not on Jen's CA, so not rotated and left alone" in text
            and "kea-a kea-dhcp4" in text
            and "standby kea-dhcp4" in text
        )
        assert (
            "Rotate refused" not in text and "Kea CA rotated" in text and "no server certificate was involved" in text
        )
        assert lab.remote_actions() == 0 and lab.settings_writes == [], (
            "nothing was pushed, and Jen's own TLS settings were not repointed"
        )

    # finding 10 - no user-info in a sentence
    def test_an_address_with_a_password_in_it_is_shown_without_it(self, lab):
        lab.urls[1] = "https://admin:s3cret-pw@10.0.0.5:8004/path?x=1"
        os.unlink(kea_tls.server_copy_path(1, "dhcp4"))
        _rotate()
        assert (
            "https://10.0.0.5:8004" in lab.texts()
            and "s3cret-pw" not in lab.everything_printed()
            and "/path" not in lab.texts()
        )

    # hypothesis 2 - an unsupported key algorithm is a malformed record, never a 500
    def test_a_certificate_the_library_cannot_read_is_a_malformed_record(self, lab, monkeypatch):
        from cryptography.exceptions import UnsupportedAlgorithm

        def unsupported(*a, **k):
            raise UnsupportedAlgorithm("unsupported curve")

        with monkeypatch.context() as only_here:
            only_here.setattr(kea_tls.x509, "load_pem_x509_certificate", unsupported)
            assert kea_tls.record_state(1, "dhcp4") == ("refuse", "its certificate or key is malformed")

    # finding 2 - acknowledging does not make the live copy the host's pair again
    def test_an_acknowledged_lost_record_stays_unknown(self, lab, monkeypatch):
        """The directory takes a small marker file but not the pair or its copy: the record is lost, `remote-unknown` is recorded, the FILE layer says unknown. The superadmin acknowledges (the incident is
        gone): `host_material` is still None - the live copy is the CA-B pair, the host holds the CA-A pair, and nothing may install the first on the strength of the second."""
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        stop = _fail_replace_matching(monkeypatch, (".key", ".crt", ".key.prev", ".crt.prev", ".stale"))
        # the forward commit_issued fails too, so the targets' records are lost at the first step already
        _rotate()
        stop()
        assert (1, "dhcp4", "remote-unknown") in lab.incidents and kea_tls.is_unknown(1, "dhcp4")
        kea_changeset.resolve_attention(1, "dhcp4")  # the acknowledge's effect on the note
        assert lab.incidents == []
        assert kea_tls.host_material(1, "dhcp4") is None, "acknowledged - and still unknown"
        assert kea_tls.host_material(2, "dhcp4") is not None, "server 2 was never touched: its record is its live pair"

    def test_a_setup_that_gives_the_host_a_pair_ends_the_unknown(self, lab):
        kea_tls.mark_unknown(1, "dhcp4")
        staged = kea_tls.issue_server_cert(SERVERS[1], "dhcp4", "10.0.0.5", commit=False)
        kea_tls.stage_issued(1, "dhcp4", staged)
        assert kea_tls.is_unknown(1, "dhcp4"), (
            "starting an operation does not make the state known - the install might fail"
        )
        assert lab.install(1, staged)["ok"]
        kea_tls.promote_staged(1, "dhcp4")
        assert not kea_tls.is_unknown(1, "dhcp4")
        assert kea_tls.host_material(1, "dhcp4")["server.crt"] == staged["server.crt"]

    # finding 3 - a transient failure to read the incident record does not destroy the file layer's knowledge
    def test_stage_issued_keeps_the_stale_marker_and_prev_when_the_incident_record_cannot_be_read(
        self, lab, monkeypatch
    ):
        stop = _fail_replace_matching(monkeypatch, ("1-dhcp4.key",))
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        # fail only the second write of the live key (the rollback's) so the record becomes 'stale, .prev is the host's'
        stop()
        _fail_replace(monkeypatch, "1-dhcp4.key", nth=2)
        _rotate()
        assert kea_tls.is_stale(1, "dhcp4")
        prev_before = pathlib.Path(kea_tls.server_copy_path(1, "dhcp4") + ".prev").read_bytes()
        with monkeypatch.context() as down:

            def unreadable(strict=False):
                raise ValueError("the incident note could not be read (OperationalError)")

            down.setattr(kea_changeset, "recovery_incidents", unreadable)
            kea_tls.stage_issued(1, "dhcp4", kea_tls.issue_server_cert(SERVERS[1], "dhcp4", "10.0.0.5", commit=False))
        assert (
            kea_tls.is_stale(1, "dhcp4")
            and pathlib.Path(kea_tls.server_copy_path(1, "dhcp4") + ".prev").read_bytes() == prev_before
        )
        kea_tls.discard_staged(1, "dhcp4")

    # finding 7 - the stale marker does not survive a promotion
    def test_promote_staged_ends_a_stale_marker(self, lab, monkeypatch):
        _fail_replace(monkeypatch, "1-dhcp4.key", nth=2)
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        _rotate()
        assert kea_tls.is_stale(1, "dhcp4")
        staged = kea_tls.issue_server_cert(SERVERS[1], "dhcp4", "10.0.0.5", commit=False)
        kea_tls.stage_issued(1, "dhcp4", staged)
        assert lab.install(1, staged)["ok"]
        kea_tls.promote_staged(1, "dhcp4")
        assert not kea_tls.is_stale(1, "dhcp4"), "live IS the pair the host accepted"
        kea_changeset.resolve_attention(1, "dhcp4")


def _symlink(target, link):
    """A symlink - or a skip, on a platform that will not make one without a privilege (Windows without developer mode)."""
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("this platform will not create a symlink here")


def _alias_of_jens_ca(tmp_path):
    """A path that is ANOTHER NAME for Jen's CA file and follows it when it is replaced: a symlink to the file; on Windows without that privilege, a directory junction (no privilege needed)
    to Jen's SSL folder. Skips when neither can be made."""
    target = kea_tls.ca_paths()[0]
    link = tmp_path / "alias-of-jens-ca.crt"
    try:
        os.symlink(target, link)
        return str(link)
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        import subprocess

        junction = tmp_path / "ssl-alias"
        done = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), kea_tls.SSL_DIR], capture_output=True, check=False
        )
        if done.returncode == 0:
            return str(junction / "kea-ca.crt")
    pytest.skip("this platform will not create an alias of a file here")


def _drop_jens_record(sid):
    for path in (kea_tls.server_copy_path(sid, "dhcp4"), kea_tls.server_key_path(sid, "dhcp4")):
        if os.path.exists(path):
            os.unlink(path)


class TestWhoIsOnJensCaIsDecidedByCertificatesNotPaths:
    """Q190 (AF1, the P1): whether an endpoint depends on Jen's CA is a fact about CERTIFICATES, decided per endpoint - never from a path string and never for all endpoints at once. Beta.20
    compared `[kea] api_ca` with Jen's path: a symlink, a copy or a bundle made every Jen-issued endpoint 'the administrator's', the rotation proceeded with ZERO targets, promoted the new CA, and Jen
    was cut off from every endpoint it manages with 'rotated' on the screen. Every row ends in the teardown (T1-T5, with no set a test can narrow); the assertions here are about the fake HOST's
    answer, not the classifier's word."""

    def _rotated_and_every_daemon_answers_the_new_identity(self, lab):
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() != lab.ca_a, "the CA was replaced"
        for sid in lab.hosts:
            assert lab.answers_jens_live_identity(sid), f"server {sid}'s daemon answers Jen's NEW identity"

    def test_the_path_is_jens_own_file(self, lab):
        _rotate()
        self._rotated_and_every_daemon_answers_the_new_identity(lab)
        assert lab.settings_writes, "Jen rewrote its own TLS settings (the path IS its file)"

    def test_a_symlink_to_jens_ca_the_reviews_reproduction(self, lab, monkeypatch, tmp_path):
        alias = _alias_of_jens_ca(tmp_path)
        monkeypatch.setattr(extensions, "KEA_API_CA", alias)
        assert kea_tls.trust_kind() == "alias" and kea_tls.trust_includes_jens_ca() is True
        _rotate()
        self._rotated_and_every_daemon_answers_the_new_identity(lab)
        assert lab.settings_writes == [] and alias == extensions.KEA_API_CA, (
            "the alias is left as the operator wrote it"
        )
        assert "Jen's CA file changed under" in lab.texts()

    def test_an_equivalent_spelling_of_the_path(self, lab, monkeypatch):
        spelled = os.path.join(kea_tls.SSL_DIR, "..", os.path.basename(kea_tls.SSL_DIR), "kea-ca.crt")
        monkeypatch.setattr(extensions, "KEA_API_CA", spelled)
        assert kea_tls.trust_kind() == "jens-file"
        _rotate()
        self._rotated_and_every_daemon_answers_the_new_identity(lab)

    def test_a_byte_copy_at_another_path_is_jens_ca_and_the_rotation_is_refused_because_it_cannot_be_rewritten(
        self, lab, monkeypatch, tmp_path
    ):
        copy_path = tmp_path / "a-copy-of-jens-ca.crt"
        copy_path.write_bytes(pathlib.Path(kea_tls.ca_paths()[0]).read_bytes())
        monkeypatch.setattr(extensions, "KEA_API_CA", str(copy_path))
        assert kea_tls.trust_kind() == "copy"
        _rotate()
        # (second pass) Rotate cannot rewrite a copy, so after a rotation Jen's dial would hold the OLD CA: the whole rotation is refused before anything is staged or any host is asked
        assert "Rotate refused" in lab.texts() and "a copy of Jen's CA" in lab.texts() and str(copy_path) in lab.texts()
        assert lab.remote_actions() == 0 and lab.settings_writes == []
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() == lab.ca_a

    def test_a_bundle_with_jens_ca_and_another_is_refused_when_a_jen_issued_endpoint_depends_on_it(
        self, lab, monkeypatch, tmp_path
    ):
        bundle = tmp_path / "bundle.pem"
        bundle.write_text(
            pathlib.Path(kea_tls.ca_paths()[0]).read_text(encoding="ascii") + _external_files("10.0.0.9")["ca.crt"],
            encoding="ascii",
        )
        monkeypatch.setattr(extensions, "KEA_API_CA", str(bundle))
        assert kea_tls.trust_kind() == "bundle" and kea_tls.trust_includes_jens_ca() is True
        _rotate()
        assert "Rotate refused" in lab.texts() and "Jen's CA beside another CA" in lab.texts()
        assert lab.remote_actions() == 0 and lab.settings_writes == []
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() == lab.ca_a

    def test_the_same_bundle_and_an_endpoint_with_no_copy_is_a_refusal_because_the_bundle_does_not_say(
        self, lab, monkeypatch, tmp_path
    ):
        bundle = tmp_path / "bundle.pem"
        bundle.write_text(
            pathlib.Path(kea_tls.ca_paths()[0]).read_text(encoding="ascii") + _external_files("10.0.0.9")["ca.crt"],
            encoding="ascii",
        )
        monkeypatch.setattr(extensions, "KEA_API_CA", str(bundle))
        _drop_jens_record(2)
        inv = kea_tls.rotation_inventory(
            extensions.KEA_SERVERS, url_for=lambda s, svc: lab.urls[s["id"]] if svc == "dhcp4" else ""
        )
        assert [s["id"] for s, _svc, _b in inv.targets] == [1]
        assert (
            len(inv.refusals) == 2
        )  # the endpoint with no record (the bundle does not say) AND the bundle itself (Rotate cannot rewrite it with a target on it)
        _rotate()
        assert (
            "Jen's CA AND another CA" in lab.texts() and "Rotate refused" in lab.texts() and lab.remote_actions() == 0
        )

    def test_a_bundle_of_two_other_cas_leaves_every_endpoint_alone_and_rotates_jens_identity_alone(
        self, lab, monkeypatch, tmp_path
    ):
        bundle = tmp_path / "others.pem"
        bundle.write_text(
            _external_files("10.0.0.7")["ca.crt"] + _external_files("10.0.0.8")["ca.crt"], encoding="ascii"
        )
        monkeypatch.setattr(extensions, "KEA_API_CA", str(bundle))
        for sid in (1, 2):
            lab.hosts[sid]["files"] = lab.hosts[sid]["loaded"] = _external_files(lab.servers[sid]["ssh_host"])
            _drop_jens_record(sid)
        _rotate()
        assert "Kea CA rotated" in lab.texts() and "no server certificate was involved" in lab.texts()
        assert lab.remote_actions() == 0 and lab.settings_writes == []

    def test_an_unreadable_bundle_is_a_refusal_for_an_endpoint_with_no_copy(self, lab, monkeypatch, tmp_path):
        monkeypatch.setattr(extensions, "KEA_API_CA", str(tmp_path / "does-not-exist.pem"))
        _drop_jens_record(2)
        _rotate()
        assert "cannot read the CA bundle" in lab.texts() and "Rotate refused" in lab.texts()
        assert lab.remote_actions() == 0

    def test_a_dangling_symlink_is_unreadable_too(self, lab, monkeypatch, tmp_path):
        dangling = tmp_path / "dangling.crt"
        _symlink(tmp_path / "nowhere.crt", dangling)
        monkeypatch.setattr(extensions, "KEA_API_CA", str(dangling))
        assert kea_tls.trust_kind() == "unreadable" and kea_tls.trust_includes_jens_ca() is None
        _drop_jens_record(1)
        _rotate()
        assert "cannot read the CA bundle" in lab.texts() and lab.remote_actions() == 0

    def test_no_bundle_and_verification_on_leaves_a_jen_issued_endpoint_a_target_and_an_administrators_alone(
        self, lab, monkeypatch
    ):
        """`api_ca` empty + verify true: requests' default - Jen's CA is not trusted at all. An endpoint with a Jen-issued copy is still a target (its daemon presents Jen's material and
        requires Jen's client certificate); one with no copy and the administrator's material is the administrator's."""
        monkeypatch.setattr(extensions, "KEA_API_CA", "")
        monkeypatch.setattr(extensions, "KEA_API_TLS_VERIFY", True)
        lab.hosts[2]["files"] = lab.hosts[2]["loaded"] = _external_files("10.0.0.6")
        _drop_jens_record(2)
        _rotate()
        assert "Kea CA rotated" in lab.texts() and "verified against the system's CAs" in lab.texts()
        assert lab.answers_jens_live_identity(1) and lab.hosts[2]["installs"] == [] and lab.hosts[2]["restarts"] == 0

    def test_no_bundle_and_verification_off_is_a_refusal_for_an_endpoint_with_no_record_because_nothing_is_looked_at(
        self, lab, monkeypatch
    ):
        monkeypatch.setattr(extensions, "KEA_API_CA", "")
        monkeypatch.setattr(extensions, "KEA_API_TLS_VERIFY", False)
        for sid in (1, 2):
            lab.hosts[sid]["files"] = lab.hosts[sid]["loaded"] = _external_files(lab.servers[sid]["ssh_host"])
            _drop_jens_record(sid)
        _rotate()
        assert "set not to verify any certificate" in lab.texts() and "Rotate refused" in lab.texts()
        assert lab.remote_actions() == 0

    def test_an_administrators_endpoint_with_its_own_client_credentials_is_untouched_and_answers_the_same(self, lab):
        lab.add_server(3, "external", "10.0.0.7", "https://10.0.0.7:8004", jen_issued=False)
        external = lab.hosts[3]["files"]
        pathlib.Path(kea_tls.server_copy_path(3, "dhcp4")).write_text(external["server.crt"], encoding="ascii")
        pathlib.Path(kea_tls.server_key_path(3, "dhcp4")).write_text(external["server.key"], encoding="ascii")
        before = lab.answers_jens_live_identity(3)
        _rotate()
        self._rotated_and_every_daemon_answers_the_new_identity_except(lab, 3)
        assert lab.hosts[3]["files"] == external and lab.hosts[3]["installs"] == [] and lab.hosts[3]["restarts"] == 0
        assert lab.answers_jens_live_identity(3) == before, "its trust relationship is exactly what it was"

    def _rotated_and_every_daemon_answers_the_new_identity_except(self, lab, skip):
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        for sid in lab.hosts:
            if sid != skip:
                assert lab.answers_jens_live_identity(sid)

    def test_the_confirm_page_lists_targets_external_and_refused_with_the_reason(self, lab, monkeypatch, tmp_path):
        bundle = tmp_path / "others.pem"
        bundle.write_text(_external_files("10.0.0.7")["ca.crt"], encoding="ascii")
        monkeypatch.setattr(extensions, "KEA_API_CA", str(bundle))
        lab.hosts[2]["files"] = lab.hosts[2]["loaded"] = _external_files("10.0.0.6")
        _drop_jens_record(2)
        summary = infra._kea_ca_summary()
        assert [n for n, _s, _d in summary["issued"]] == ["kea-a"]
        assert any("standby kea-dhcp4" in e and "its CA is not Jen's" in e for e in summary["external"])
        assert summary["external_ca"] is True
        _rotate()
        assert "Kea CA rotated" in lab.texts()
        lab.hosts[1]["files"] = lab.hosts[1]["files"]  # (server 1 was rotated; nothing else to settle)


class TestALegacyUrlWithAPasswordNeverReachesText:
    """Q190 (AF2): a URL with user-info already in jen.config is legacy input. Jen keeps dialling it, and the password it carries is in NOTHING Jen prints - a flash, an audit row, a log line, an
    incident - however the dial fails. The fake transport raises `requests` exceptions whose TEXT carries the address as configured; the real probe, identify and scrub code run over it. T4 in
    the teardown looks for the password and for `user:password` in everything printed, for every failure below."""

    LEGACY = "https://admin:s3cret-legacy-pw@10.0.0.5:8004"

    @pytest.mark.parametrize("fault", ["refused", "timeout", "handshake"])
    def test_a_rotation_whose_probe_fails(self, lab, fault):
        lab.urls[1] = self.LEGACY
        lab.faults[1] = fault
        _rotate()
        printed = lab.everything_printed()
        assert "Rotate stopped" in printed and "s3cret-legacy-pw" not in printed and "admin:" not in printed
        assert "https://10.0.0.5:8004" in printed, "the address is still named - without its user-info"

    def test_a_failed_identify(self, lab):
        lab.urls[1] = self.LEGACY
        lab.identify_as[1] = "wrong-daemon"
        lab.hosts[1]["loaded"] = lab.hosts[1][
            "loaded"
        ]  # (the forward probe only version-gets; the rollback identifies)
        lab.refuse.add(
            (1, "install-tls", 1)
        )  # the staged install is refused -> the route re-asserts and the rollback path asks who answers
        _rotate()
        assert "s3cret-legacy-pw" not in lab.everything_printed()

    def test_the_audit_row_and_the_log_after_each(self, lab, caplog):
        lab.urls[1] = self.LEGACY
        lab.faults[1] = "refused"
        _rotate()
        assert any("ROTATE_KEA_CA" in str(a) for a in lab.audits)
        assert "s3cret-legacy-pw" not in " ".join(str(a) for a in lab.audits)
        assert "s3cret-legacy-pw" not in " ".join(r.getMessage() for r in caplog.records)


class TestTheInvariantsBiteTooQ190:
    """The sixth biting test and the one for the new T1: the invariants have no knob, and each can still be seen to fire."""

    def test_T3_bites_when_a_daemon_that_answered_stops_answering_and_nothing_names_it(self, lab, monkeypatch):
        """Monkeypatch the route to skip the probe, and make one daemon ignore its restart: the rotation reports success, promotes the new CA, and a daemon Jen answered before is left on the old one."""
        lab.expected_violations = {"T3"}
        lab.stuck_restart.add(2)
        monkeypatch.setattr(infra, "_probe_after_restart", lambda *a, **k: ("Kea 3.0.3", None))
        _rotate()
        assert "Kea CA rotated" in lab.texts()
        assert lab.answered_before[2] and not lab.answers_jens_live_identity(2)

    def test_T3_bites_on_the_configured_dial_when_the_bundle_jen_verifies_against_holds_the_old_ca(
        self, lab, monkeypatch, tmp_path
    ):
        """The second pass's cut-off: the daemon answers Jen's LIVE identity but Jen is configured to verify against a copy of the OLD CA - Jen is cut off, and no incident says so."""
        lab.expected_violations = {"T3"}
        old_copy = tmp_path / "old-ca-copy.crt"
        old_copy.write_bytes(lab.ca_a)
        monkeypatch.setattr(extensions, "KEA_API_CA", str(old_copy))
        lab.begin()  # the dial answers: the copy IS the CA the daemons were issued by
        assert all(lab.dial_before.values())
        staged = kea_tls.stage_rotation()
        kea_tls.commit_rotation(staged)  # Jen's CA is replaced; the copy keeps the old one
        for sid, server in lab.servers.items():
            files = kea_tls.issue_server_cert(server, "dhcp4", server["ssh_host"])
            lab.hosts[sid]["files"] = lab.hosts[sid]["loaded"] = copy.deepcopy(files)
        assert all(lab.answers_jens_live_identity(sid) for sid in lab.hosts) and not any(
            lab.answers_jens_configured_dial(sid) for sid in lab.hosts
        )

    def test_T1_bites_when_an_action_silently_loses_a_record_it_had(self, lab, monkeypatch):
        """Q192 (adjusted: T1 is RELATIVE now - a world that STARTS without a record is the input and Health says so). Judged by the HOST's certificate: the daemon runs a pair a Jen CA issued, Jen
        HAD a record of it, and the action ends with the files gone and nothing - no request text, no incident, no marker - saying so."""
        lab.expected_violations = {"T1"}
        real = kea_tls.retire_previous

        def retire_and_lose(server_id, service):
            real(server_id, service)
            _drop_jens_record(server_id)  # the product loses the record it had, silently

        monkeypatch.setattr(kea_tls, "retire_previous", retire_and_lose)
        _rotate()
        assert "Kea CA rotated" in lab.texts()


# ── Q191 (AG1): Jen's identity to a daemon is its CA bundle AND its client pair ──────────────────────────────────────────────────────────────────────


def _alias_dir(tmp_path):
    """A directory that is ANOTHER NAME for Jen's SSL folder and follows it when a file in it is replaced: a directory symlink; on Windows without that privilege, a junction (none needed).
    Skips when neither can be made."""
    link = tmp_path / "ssl-alias"
    if os.path.lexists(link):
        return link  # (one alias per world: the bundle and the client pair may both go through it)
    try:
        os.symlink(kea_tls.SSL_DIR, link, target_is_directory=True)
        return link
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        import subprocess

        done = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), kea_tls.SSL_DIR], capture_output=True, check=False
        )
        if done.returncode == 0:
            return link
    pytest.skip("this platform will not create an alias of a directory here")


def _client_world(kind, tmp_path, monkeypatch):
    """Configure `[kea] api_client_cert` / `api_client_key` as a client pair of the given SHAPE and return its (cert, key) paths - one world per shape of the identity's input."""
    pem, key = kea_tls.client_paths()
    if kind == "jens-file":
        cert_path, key_path = pem, key
    elif kind == "alias":
        folder = _alias_dir(tmp_path)
        cert_path, key_path = str(folder / os.path.basename(pem)), str(folder / os.path.basename(key))
    elif kind == "copy":
        cert_path, key_path = str(tmp_path / "copy-client.pem"), str(tmp_path / "copy-client.key")
        pathlib.Path(cert_path).write_bytes(pathlib.Path(pem).read_bytes())
        pathlib.Path(key_path).write_bytes(pathlib.Path(key).read_bytes())
    elif kind == "other":
        mine = _external_files("10.0.0.99")
        cert_path, key_path = str(tmp_path / "own-pki.pem"), str(tmp_path / "own-pki.key")
        pathlib.Path(cert_path).write_text(mine["server.crt"], encoding="ascii")
        pathlib.Path(key_path).write_text(mine["server.key"], encoding="ascii")
    elif kind == "unreadable":
        cert_path, key_path = str(tmp_path / "garbage.pem"), str(tmp_path / "garbage.key")
        pathlib.Path(cert_path).write_text("not a certificate", encoding="ascii")
        pathlib.Path(key_path).write_text("not a key", encoding="ascii")
    elif kind == "none":
        cert_path, key_path = "", ""
    else:
        raise AssertionError(kind)
    monkeypatch.setattr(extensions, "KEA_API_CLIENT_CERT", cert_path)
    monkeypatch.setattr(extensions, "KEA_API_CLIENT_KEY", key_path)
    return cert_path, key_path


def _bundle_world(kind, tmp_path, monkeypatch):
    """Configure the CA bundle as one SHAPE: Jen's own file, an alias of it, or no bundle with verification off."""
    if kind == "jens-file":
        return
    if kind == "alias":
        monkeypatch.setattr(
            extensions, "KEA_API_CA", str(_alias_dir(tmp_path) / os.path.basename(kea_tls.ca_paths()[0]))
        )
    elif kind == "empty-verify-off":
        monkeypatch.setattr(extensions, "KEA_API_CA", "")
        monkeypatch.setattr(extensions, "KEA_API_TLS_VERIFY", False)
    else:
        raise AssertionError(kind)


class TestClientIdentity:
    """Q191 (AG1, the P1): the client pair is half of what a daemon with `cert-required` checks, and beta.21 judged only the CA bundle. With `api_client_cert` a byte COPY of Jen's client pem and the
    bundle an alias (or empty with verification off), a rotation promoted the new CA and client pair, every daemon demanded a certificate from the NEW CA, Jen kept dialling with the old copy, and the
    screen said "rotated". Every row is a WORLD the Lab builds from a shape of the input; the teardown's T3 judges the daemon's answer to the CONFIGURED dial."""

    def _refused_before_staging(self, lab, needle):
        assert "Rotate refused" in lab.texts() and needle in lab.texts(), lab.texts()
        assert lab.remote_actions() == 0 and lab.settings_writes == []
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() == lab.ca_a, "nothing was staged or promoted"
        assert not os.path.exists(kea_tls.ca_paths()[0] + ".next")

    @pytest.mark.parametrize("bundle", ["jens-file", "alias", "empty-verify-off"])
    def test_a_copy_of_jens_client_pair_is_refused_before_staging_whatever_the_bundle(
        self, lab, monkeypatch, tmp_path, bundle
    ):
        _bundle_world(bundle, tmp_path, monkeypatch)
        cert_path, _key = _client_world("copy", tmp_path, monkeypatch)
        assert kea_tls.client_kind() == "copy"
        lab.begin()
        assert all(lab.dial_before.values()), (
            "in this world the daemons ANSWER Jen's configured dial before the request"
        )
        _rotate()
        self._refused_before_staging(lab, "configured as a copy")
        assert cert_path in lab.texts()
        assert all(lab.answers_jens_configured_dial(sid) for sid in lab.hosts), "the dial is unchanged"

    @pytest.mark.parametrize("bundle", ["jens-file", "alias"])
    def test_an_alias_of_jens_client_pair_follows_the_rotation_and_the_dial_holds(
        self, lab, monkeypatch, tmp_path, bundle
    ):
        _bundle_world(bundle, tmp_path, monkeypatch)
        _client_world("alias", tmp_path, monkeypatch)
        assert kea_tls.client_kind() == "alias"
        lab.begin()
        assert all(lab.dial_before.values())
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert all(lab.answers_jens_live_identity(sid) for sid in lab.hosts)
        assert all(lab.answers_jens_configured_dial(sid) for sid in lab.hosts), "the alias follows the replaced file"

    def test_a_pair_no_jen_ca_issued_with_a_jen_issued_target_is_refused_and_said(self, lab, monkeypatch, tmp_path):
        _client_world("other", tmp_path, monkeypatch)
        assert kea_tls.client_kind() == "other"
        lab.begin()
        assert not any(lab.dial_before.values()), "the dial never worked with it"
        _rotate()
        self._refused_before_staging(lab, "do not accept it")

    def test_an_unreadable_pair_is_refused(self, lab, monkeypatch, tmp_path):
        _client_world("unreadable", tmp_path, monkeypatch)
        assert kea_tls.client_kind() == "unreadable"
        _rotate()
        self._refused_before_staging(lab, "cannot be loaded as a pair")

    def test_one_half_of_a_pair_is_unreadable(self, lab, monkeypatch):
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_KEY", "")
        assert kea_tls.client_kind() == "unreadable"

    def test_no_pair_rotates_as_before(self, lab, monkeypatch, tmp_path):
        _client_world("none", tmp_path, monkeypatch)
        assert kea_tls.client_kind() == "none"
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert all(lab.answers_jens_live_identity(sid) for sid in lab.hosts)

    def test_jens_own_files_rotate_and_the_settings_are_rewritten(self, lab):
        assert kea_tls.client_kind() == "jens-file"
        _rotate()
        assert "Kea CA rotated" in lab.texts() and lab.settings_writes

    @pytest.mark.parametrize("kind", ["copy", "other", "unreadable"])
    def test_a_pair_the_rotation_cannot_carry_does_not_matter_when_no_jen_issued_endpoint_depends_on_it(
        self, lab, monkeypatch, tmp_path, kind
    ):
        """No target, nothing to cut off: an administrator's endpoints only. (The refusal is for a Jen-issued target.)"""
        bundle = tmp_path / "administrators.pem"
        bundle.write_text(_external_files("10.0.0.7")["ca.crt"], encoding="ascii")
        monkeypatch.setattr(extensions, "KEA_API_CA", str(bundle))
        for sid in lab.hosts:
            lab.hosts[sid]["files"] = lab.hosts[sid]["loaded"] = _external_files(lab.servers[sid]["ssh_host"])
            _drop_jens_record(sid)
        _client_world(kind, tmp_path, monkeypatch)
        lab.begin()
        _rotate()
        assert "Kea CA rotated" in lab.texts() and "no server certificate was involved" in lab.texts(), lab.texts()

    def test_the_kinds_are_decided_by_certificate_not_by_path(self, lab, monkeypatch, tmp_path):
        """A copy at a path that merely LOOKS like Jen's (same file name, other folder) is a copy; Jen's own file spelled with a `..` is Jen's own file; a certificate Jen's live CA issued but Jen does
        not hold is a copy too (a pair Jen cannot carry)."""
        folder = tmp_path / "elsewhere"
        folder.mkdir()
        pem, key = kea_tls.client_paths()
        (folder / os.path.basename(pem)).write_bytes(pathlib.Path(pem).read_bytes())
        (folder / os.path.basename(key)).write_bytes(pathlib.Path(key).read_bytes())
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_CERT", str(folder / os.path.basename(pem)))
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_KEY", str(folder / os.path.basename(key)))
        assert kea_tls.client_kind() == "copy"
        spelled = os.path.join(kea_tls.SSL_DIR, "..", os.path.basename(kea_tls.SSL_DIR))
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_CERT", os.path.join(spelled, os.path.basename(pem)))
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_KEY", os.path.join(spelled, os.path.basename(key)))
        assert kea_tls.client_kind() == "jens-file"
        # a client certificate Jen's live CA issued, whose files Jen does not hold at its own path
        ca_cert, ca_key = kea_tls._load_ca()
        newkey = kea_tls._new_key()
        issued = kea_tls._leaf(ca_cert, ca_key, newkey, "someone else", [], client=True)
        (folder / "issued.pem").write_bytes(kea_tls._cert_pem(issued))
        (folder / "issued.key").write_bytes(kea_tls._key_pem(newkey))
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_CERT", str(folder / "issued.pem"))
        monkeypatch.setattr(extensions, "KEA_API_CLIENT_KEY", str(folder / "issued.key"))
        assert kea_tls.client_kind() == "copy"


class TestTheConnectionFormJudgesTheClientPair:
    """Q191 (AG1): nothing legitimate needs a COPY of Jen's own pair as the client pair - it is the configuration the P1 needs - so the connection form refuses it; an alias and an operator's own PKI
    stay allowed."""

    def _save(self, lab, monkeypatch, cert, key):
        import configparser

        monkeypatch.setattr(extensions, "cfg", configparser.ConfigParser(interpolation=None))
        monkeypatch.setattr(infra.__dict__["__user"], "set_global_setting", lambda *a, **k: True)
        form = {
            "api_url": "https://10.0.0.5:8004",
            "connection_mode": "direct",
            "api_ca": kea_tls.ca_paths()[0],
            "api_tls_verify": "1",
            "api_client_cert": cert,
            "api_client_key": key,
        }
        lab.begin()  # the world (the configured pair) is built: this is the state before the request
        app = flask.Flask(__name__)
        app.secret_key = "x"
        with app.test_request_context(method="POST", data=form):
            inspect.unwrap(infra.save_infra_kea)()

    def test_a_copy_is_refused_and_nothing_is_written(self, lab, monkeypatch, tmp_path):
        cert, key = _client_world("copy", tmp_path, monkeypatch)
        self._save(lab, monkeypatch, cert, key)
        assert "TLS settings not saved" in lab.texts() and "configured as a copy" in lab.texts()
        assert cert in lab.texts(), "the SUBMITTED path is named, not the configured one"
        assert lab.settings_writes == []

    @pytest.mark.parametrize("kind", ["alias", "other", "jens-file"])
    def test_an_alias_an_own_pki_and_jens_own_files_are_saved(self, lab, monkeypatch, tmp_path, kind):
        cert, key = _client_world(kind, tmp_path, monkeypatch)
        self._save(lab, monkeypatch, cert, key)
        assert "Kea API settings saved" in lab.texts(), lab.texts()
        assert lab.settings_writes


class TestTheInvariantsBiteTooQ191:
    def test_T3_bites_on_the_P1_world_when_the_client_refusal_is_monkeypatched_away(self, lab, monkeypatch, tmp_path):
        """The pass's C1X, now a shipped test: client pair a COPY, bundle an alias - with the refusal removed the rotation promotes a new CA and client pair, every daemon demands a certificate from the
        new CA, Jen keeps dialling with the old copy, and the teardown names it."""
        lab.expected_violations = {"T3"}
        _bundle_world("alias", tmp_path, monkeypatch)
        _client_world("copy", tmp_path, monkeypatch)
        real = kea_tls.client_kind
        monkeypatch.setattr(kea_tls, "client_kind", lambda *a, **k: "jens-file")
        lab.begin()
        _rotate()
        monkeypatch.setattr(kea_tls, "client_kind", real)
        assert "Kea CA rotated" in lab.texts(), "the rotation reported success"
        assert all(lab.answers_jens_live_identity(sid) for sid in lab.hosts)
        assert lab.dial_before and not any(lab.answers_jens_configured_dial(sid) for sid in lab.hosts)


class TestTheSecondPassOfQ191:
    """The findings of the adversarial second pass of the code commit, each as the sequence that found it (the rows were written before the code)."""

    # finding 1 - Jen's own files are Jen's to repair, whatever they hold
    @pytest.mark.parametrize("damage", ["missing", "garbage"])
    def test_a_configured_pair_that_IS_jens_own_file_is_never_unreadable(self, lab, damage):
        pem, key = kea_tls.client_paths()
        if damage == "missing":
            os.unlink(pem)
            os.unlink(key)
        else:
            pathlib.Path(pem).write_text("not a certificate", encoding="ascii")
        assert kea_tls.client_kind() == "jens-file"
        assert kea_tls.client_refusal() == ""
        lab.begin()  # (the damage is the world; this is the state before any request)

    # finding 7 - the lists are CROSSED, not sampled
    @pytest.mark.parametrize("bundle", ["jens-file", "alias", "empty-verify-off"])
    @pytest.mark.parametrize("client", ["none", "jens-file", "alias", "copy", "other", "unreadable"])
    def test_every_client_shape_crossed_with_every_bundle_shape(self, lab, monkeypatch, tmp_path, bundle, client):
        _bundle_world(bundle, tmp_path, monkeypatch)
        _client_world(client, tmp_path, monkeypatch)
        lab.begin()
        _rotate()
        if client in ("copy", "other", "unreadable"):
            assert "Rotate refused" in lab.texts() and lab.remote_actions() == 0, (bundle, client, lab.texts())
        else:
            assert "Kea CA rotated" in lab.texts(), (bundle, client, lab.texts())
            assert all(lab.answers_jens_live_identity(sid) for sid in lab.hosts)
        # (the teardown's T1-T5 judge every world)


# ── Q192 (AH1-AH3): the staged identity is proved against every endpoint it is presented to; a damaged CA is a recovery condition; a pair is a pair ──────────────


def _ca_pem() -> str:
    return pathlib.Path(kea_tls.ca_paths()[0]).read_text(encoding="ascii")


def _add_external(lab, sid=3, trust="default", address="10.0.0.7", jen_issued=False):
    """An administrator's https endpoint Jen also dials: its server certificate is the administrator's, Jen holds the copy of its pair (so the inventory calls it external), and `trust` is the CA it
    trusts for CLIENT certificates - independent of the CA that issued its server certificate (`"any"`, None = no client certificate required, or the PEM of a CA)."""
    server = lab.add_server(sid, "external", address, f"https://{address}:8004", jen_issued=jen_issued)
    external = lab.hosts[sid]["files"]
    pathlib.Path(kea_tls.server_copy_path(sid, "dhcp4")).write_text(external["server.crt"], encoding="ascii")
    pathlib.Path(kea_tls.server_key_path(sid, "dhcp4")).write_text(external["server.key"], encoding="ascii")
    lab.hosts[sid]["client_trust"] = trust
    lab.snapshot_dial()
    lab.answered_before[sid] = lab.answers_jens_live_identity(sid)
    return server


def _prepare():
    prepare = inspect.unwrap(infra.prepare_kea_ca)
    app = flask.Flask(__name__)
    app.secret_key = "x"
    with app.test_request_context(method="POST"):
        prepare()


def _discard_prepared():
    discard = inspect.unwrap(infra.discard_prepared_kea_ca)
    app = flask.Flask(__name__)
    app.secret_key = "x"
    with app.test_request_context(method="POST"):
        discard()


class TestSplitTrust:
    """Q192 (AH1, the P1): a daemon's trust for CLIENT certificates is independent of the CA that issued its SERVER certificate. Beta.22 judged the client pair only when a Jen-issued server certificate
    existed; an external endpoint that accepted Jen's CA-A client certificate was left demanding one after the rotation promoted CA-B - Jen locked out of it with 'rotated' on the screen. Every row is a
    Lab world with the daemon's `client_trust` set independently; T3 runs in every teardown and T5 after every refusal."""

    def _refused_before_promotion(self, lab, needle):
        assert "Rotate refused" in lab.texts() and needle in lab.texts(), lab.texts()
        assert lab.remote_actions() == 0 and lab.settings_writes == []
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() == lab.ca_a, "Jen's CA was not replaced"
        assert not any(os.path.exists(p) for p in kea_tls._staged_paths().values()), "the staging is gone"

    def test_a_jen_server_and_a_jen_client_rotate_as_before(self, lab):
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()

    def test_an_external_server_with_a_permissive_client_trust_answers_both_pairs_and_rotates(self, lab):
        _add_external(lab, trust="any")
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert lab.hosts[3]["installs"] == [] and lab.hosts[3]["restarts"] == 0

    def test_an_external_server_that_asks_for_no_client_certificate_rotates(self, lab):
        _add_external(lab, trust=None)
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()

    def test_the_P1_an_external_server_that_trusts_jens_current_ca_for_clients_is_refused_before_promotion(self, lab):
        _add_external(lab, trust=_ca_pem())
        lab.begin()
        assert lab.dial_before[3], "in this world the daemon ANSWERS Jen's configured dial today"
        _rotate()
        self._refused_before_promotion(lab, "accepts Jen's current client certificate and refuses the new one")
        assert "external kea-dhcp4" in lab.texts() and "Prepare" in lab.texts(), (
            "the refusal names the endpoint and the way out"
        )
        assert all(lab.answers_jens_configured_dial(sid) for sid in lab.hosts), "the dial holds on every endpoint"

    def test_two_jen_targets_and_one_such_external_are_refused_and_nothing_is_installed_on_the_two(self, lab):
        _add_external(lab, trust=_ca_pem())
        _rotate()
        self._refused_before_promotion(lab, "accepts Jen's current client certificate")
        assert all(lab.hosts[sid]["installs"] == [] and lab.hosts[sid]["restarts"] == 0 for sid in (1, 2))

    def test_an_external_endpoint_that_does_not_answer_the_live_pair_is_refused_as_unreachable(self, lab):
        _add_external(lab, trust=_ca_pem())
        lab.faults[3] = "refused"
        _rotate()
        self._refused_before_promotion(lab, "does not answer Jen's current client certificate")

    def test_a_client_kind_of_none_presents_nothing_and_needs_no_probe(self, lab, monkeypatch, tmp_path):
        _client_world("none", tmp_path, monkeypatch)
        _add_external(lab, trust=_ca_pem())
        lab.begin()
        _rotate()
        assert "Rotate refused" not in lab.texts() or "accepts Jen's current client certificate" not in lab.texts()

    def test_prepare_keeps_the_next_ca_and_a_later_rotate_reuses_it_after_the_daemons_trust_gained_it(self, lab):
        _add_external(lab, trust=_ca_pem())
        _prepare()
        staged = kea_tls._staged_paths()
        assert all(os.path.exists(p) for p in staged.values()), "Prepare keeps .next"
        fingerprint = kea_tls.prepared_fingerprint(staged)
        assert fingerprint in lab.texts() and staged["ca_cert"] in lab.texts()
        assert any("PREPARE_KEA_CA" in str(a) for a in lab.audits)
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() == lab.ca_a and lab.remote_actions() == 0
        if os.name != "nt":
            assert stat_mode(staged["ca_key"]) == 0o600 and stat_mode(staged["client_key"]) == 0o600
        # the rotation is refused until the external daemon's trust anchor holds the new CA ...
        _rotate()
        assert "accepts Jen's current client certificate" in lab.texts()
        assert all(os.path.exists(p) for p in staged.values()), "a REFUSED rotation keeps the prepared CA"
        assert "The prepared CA is kept" in lab.texts()
        # ... the operator adds it beside the current one, and the same CA-B is what the rotation promotes
        prepared_ca = pathlib.Path(staged["ca_cert"]).read_bytes()
        lab.hosts[3]["client_trust"] = _ca_pem() + prepared_ca.decode("ascii")
        lab.flashes.clear()
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() == prepared_ca, "the prepared CA IS the new CA"
        assert not any(os.path.exists(p) for p in staged.values()), "a successful rotation consumes it"
        for sid in lab.hosts:
            assert lab.answers_jens_configured_dial(sid), f"endpoint {sid} answers after the rotation"

    def test_an_inconsistent_prepared_ca_is_discarded_and_said_and_a_fresh_one_is_staged(self, lab):
        _prepare()
        staged = kea_tls._staged_paths()
        pathlib.Path(staged["client_key"]).write_text("not a key", encoding="ascii")
        lab.flashes.clear()
        _rotate()
        assert "damaged or inconsistent, so it was discarded" in lab.texts(), lab.texts()
        assert "Kea CA rotated" in lab.texts()

    def test_an_incomplete_prepared_ca_is_discarded_and_said(self, lab):
        _prepare()
        os.unlink(kea_tls._staged_paths()["client_cert"])
        lab.flashes.clear()
        _rotate()
        assert "was incomplete (3 of 4 files), so it was discarded" in lab.texts(), lab.texts()

    def test_the_discard_button_removes_it(self, lab):
        _prepare()
        _discard_prepared()
        assert not any(os.path.exists(p) for p in kea_tls._staged_paths().values())
        assert "The prepared CA was discarded" in lab.texts()
        assert any("DISCARD_PREPARED_KEA_CA" in str(a) for a in lab.audits)

    def test_a_rotation_that_fails_part_way_keeps_a_prepared_ca_but_not_one_it_staged_itself(self, lab, monkeypatch):
        _prepare()
        staged = kea_tls._staged_paths()
        lab.refuse.add((2, "install-tls", 1))
        _rotate()
        assert "kept" in lab.texts().lower() and all(os.path.exists(p) for p in staged.values())
        _discard_prepared()
        lab.refuse.add((2, "install-tls", 2))
        lab.flashes.clear()
        _rotate()
        assert not any(os.path.exists(p) for p in staged.values()), "a staging this rotation made is discarded"

    def test_the_staged_probe_is_a_failure_at_every_step_still_judged_by_the_invariants(self, lab, monkeypatch):
        """The probe itself failing in odd ways (a raise from the transport) is a refusal or a rolled-back rotation, never a promotion with the external endpoint unproved."""
        _add_external(lab, trust=_ca_pem())
        real = infra._probe_once

        def broken(url, user, pwd, omit_service, **kw):
            if "10.0.0.7" in url and kw.get("cert") and "next" in str(kw["cert"][0]):
                raise RuntimeError("the transport failed")
            return real(url, user, pwd, omit_service, **kw)

        monkeypatch.setattr(infra, "_probe_once", broken)
        _rotate()
        assert "could not be probed (RuntimeError)" in lab.texts() and "Rotate refused" in lab.texts(), lab.texts()
        assert lab.remote_actions() == 0 and lab.settings_writes == []
        assert not any(os.path.exists(p) for p in kea_tls._staged_paths().values())


def stat_mode(path):
    return os.stat(path).st_mode & 0o777


class TestTheInvariantsBiteTooQ192:
    def test_T3_bites_when_the_staged_identity_check_is_monkeypatched_away(self, lab, monkeypatch):
        """The P1 world with the new check removed: the rotation promotes CA-B, the external daemon still trusts only CA-A for clients, and Jen keeps presenting CA-B pairs - the teardown names it."""
        lab.expected_violations = {"T3"}
        _add_external(lab, trust=_ca_pem())
        monkeypatch.setattr(infra, "_staged_identity_refusal", lambda *a, **k: "")
        lab.begin()
        _rotate()
        assert "Kea CA rotated" in lab.texts(), "the rotation reported success"
        assert lab.dial_before[3] and not lab.answers_jens_configured_dial(3)


class TestCaState:
    """Q192 (AH2, the P1): a damaged CA is a recovery condition, never "no CA yet". `ensure_ca` used to read "a cert without a loadable key counts as absent" and made a NEW CA under existing https
    sockets (the existing client certificate no longer valid under the active CA); a mismatched pair loaded as present and issued certificates no CA verified."""

    def _snapshot(self):
        from tests import _tls_worlds as worlds

        return worlds.tree(kea_tls.SSL_DIR)

    def test_a_valid_pair_is_ok_and_ensure_ca_returns_it_unchanged(self, lab):
        assert kea_tls.ca_state() == ("ok", "")
        before = self._snapshot()
        assert kea_tls.ensure_ca()["created"] is False and self._snapshot() == before

    def test_both_files_absent_in_a_fresh_world_is_created(self, lab):
        import shutil

        shutil.rmtree(kea_tls.SSL_DIR)
        os.makedirs(kea_tls.SSL_DIR)
        assert kea_tls.ca_state() == ("none", "")
        assert kea_tls.ensure_ca()["created"] is True and kea_tls.ca_state() == ("ok", "")
        lab.hosts.clear()  # (no daemon holds anything in this world)

    @pytest.mark.parametrize("keep", ["a server copy", "the client pair", "a prepared rotation"])
    def test_both_files_absent_beside_evidence_a_CA_existed_is_refused_and_nothing_is_created(self, lab, keep):
        import shutil

        shutil.rmtree(kea_tls.SSL_DIR)
        os.makedirs(os.path.join(kea_tls.SSL_DIR, "kea-servers"))
        if keep == "a server copy":
            pathlib.Path(kea_tls.server_copy_path(1, "dhcp4")).write_text("x", encoding="ascii")
        elif keep == "the client pair":
            pathlib.Path(kea_tls.client_paths()[0]).write_text("x", encoding="ascii")
        else:
            pathlib.Path(kea_tls.ca_paths()[0] + ".next").write_text("x", encoding="ascii")
        before = self._snapshot()
        lab.begin()
        # (Q192 second pass, finding 4, adjusted: an absent CA beside evidence it existed is DAMAGED - one definition, so Health, setup, the page and Rotate all agree)
        assert kea_tls.ca_state()[0] == "damaged" and "both CA files are missing" in kea_tls.ca_state()[1]
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.ensure_ca()
        assert self._snapshot() == before and not os.path.exists(kea_tls.ca_paths()[0])

    def test_both_files_absent_with_a_jen_issued_https_endpoint_is_refused(self, lab):
        crt, key = kea_tls.ca_paths()
        os.unlink(crt)
        os.unlink(key)
        lab.begin()
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.ensure_ca()
        assert not os.path.exists(crt) and not os.path.exists(key)

    @pytest.mark.parametrize(
        ("damage", "why"),
        [
            ("cert-missing", "kea-ca.crt is missing"),
            ("key-missing", "kea-ca.key is missing"),
            ("cert-malformed", "kea-ca.crt is not a certificate"),
            ("key-malformed", "kea-ca.key is not a private key"),
            ("mismatched", "are not a pair"),
        ],
    )
    def test_every_damage_is_named_refused_and_leaves_the_identity_byte_equal(self, lab, damage, why):
        from tests import _tls_worlds as worlds

        crt, key = kea_tls.ca_paths()
        if damage == "cert-missing":
            os.unlink(crt)
        elif damage == "key-missing":
            os.unlink(key)
        elif damage == "cert-malformed":
            worlds.malformed(crt)
        elif damage == "key-malformed":
            worlds.malformed(key)
        else:
            pathlib.Path(key).write_bytes(worlds.another_key_pem())
        lab.begin()
        state, said = kea_tls.ca_state()
        assert state == "damaged" and why in said, said
        before = self._snapshot()
        with pytest.raises(kea_tls.CaDamaged, match=why):
            kea_tls.ensure_ca()
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.issue_client_cert(force=True)
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.issue_server_cert(lab.servers[1], "dhcp4", "10.0.0.5")
        assert self._snapshot() == before, "no new CA, no new pair, no copy changed (T6)"
        c = health._kea_tls_expiry({})
        assert c.status == "fail" and "damaged" in c.detail and why in c.detail
        lab.begin()
        _rotate()
        assert "Rotate refused" not in lab.texts() and "Jen's CA is damaged" in lab.texts()
        assert "Tick the acknowledgement" in lab.texts() and lab.remote_actions() == 0
        assert self._snapshot() == before

    def test_rotate_with_the_acknowledgement_replaces_a_damaged_ca_and_re_issues_every_target(self, lab):
        os.unlink(kea_tls.ca_paths()[1])
        old_cert = pathlib.Path(kea_tls.ca_paths()[0]).read_bytes()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert kea_tls.ca_state() == ("ok", "") and pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() != old_cert
        for sid in lab.hosts:
            assert lab.answers_jens_live_identity(sid), f"server {sid}'s daemon answers the replacement CA"
        assert pathlib.Path(kea_tls.ca_paths()[0] + ".prev").read_bytes() == old_cert, (
            "the old certificate is kept as .prev"
        )
        assert any("replaced a damaged CA: acknowledged" in str(a) for a in lab.audits)

    @pytest.mark.parametrize("damage", ["cert-missing", "cert-malformed"])
    def test_the_recovery_works_when_the_certificate_is_the_missing_half_too(self, lab, damage):
        from tests import _tls_worlds as worlds

        crt = kea_tls.ca_paths()[0]
        os.unlink(crt) if damage == "cert-missing" else worlds.malformed(crt)
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert kea_tls.ca_state() == ("ok", "")
        for sid in lab.hosts:
            assert lab.answers_jens_live_identity(sid)

    def test_a_failed_target_in_a_recovery_is_tls_not_restored_and_said_beforehand(self, lab):
        os.unlink(kea_tls.ca_paths()[1])
        lab.refuse.add((2, "install-tls", 1))
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" not in lab.texts()
        assert (1, "dhcp4", "tls-not-restored") in lab.incidents, lab.incidents
        assert kea_tls.ca_state()[0] == "damaged", "the damaged CA was not replaced by a rotation that failed"
        assert not any(os.path.exists(p) for p in kea_tls._staged_paths().values())


class TestClientState:
    """Q192 (AH3, the P2): `client_cert_ok` loaded the key and never asked whether it belonged to the certificate - Health read a pair of strangers as healthy and `issue_client_cert` skipped the
    re-issue. A pair is a pair only when the key is the certificate's, the CA is the live one, the certificate is a clientAuth one and it is inside its validity."""

    def test_a_valid_pair_is_ok(self, lab):
        assert kea_tls.client_state() == ("ok", "") and kea_tls.client_cert_ok()
        assert kea_tls.issue_client_cert()["issued"] is False

    def _reissued(self, lab, expected_why):
        assert kea_tls.client_cert_ok() is False
        state, why = kea_tls.client_state()
        assert state == "damaged" and expected_why in why, why
        c = health._kea_tls_expiry({})
        assert c.status == "fail" and "damaged" in c.detail and expected_why in c.detail, c.detail
        pem, key = kea_tls.client_paths()
        old_pem = pathlib.Path(pem).read_bytes() if os.path.isfile(pem) else None
        result = kea_tls.issue_client_cert()
        lab.before = (
            None  # (a direct call to the module, not a request: T5 - "a refusal changed nothing" - is about requests)
        )
        assert result["issued"] is True and expected_why in result["why"]
        assert kea_tls.client_state() == ("ok", "")
        if old_pem is not None:
            assert pathlib.Path(pem + ".prev").read_bytes() == old_pem, "the pair it replaced is kept as .prev"

    def test_a_valid_certificate_with_an_unrelated_key_is_damaged_and_re_issued(self, lab):
        from tests import _tls_worlds as worlds

        pathlib.Path(kea_tls.client_paths()[1]).write_bytes(worlds.another_key_pem())
        self._reissued(lab, "is not the key of")

    def test_a_malformed_certificate_is_re_issued(self, lab):
        from tests import _tls_worlds as worlds

        worlds.malformed(kea_tls.client_paths()[0])
        self._reissued(lab, "is not a certificate")

    def test_a_malformed_key_is_re_issued(self, lab):
        from tests import _tls_worlds as worlds

        worlds.malformed(kea_tls.client_paths()[1])
        self._reissued(lab, "is not a private key")

    def test_an_unreadable_key_is_damaged_and_a_re_issue_that_cannot_write_says_so(self, lab):
        from tests import _tls_worlds as worlds

        worlds.unreadable(kea_tls.client_paths()[1])
        state, why = kea_tls.client_state()
        assert state == "damaged" and "cannot be read" in why, why
        assert health._kea_tls_expiry({}).status == "fail"
        with pytest.raises(OSError):
            kea_tls.issue_client_cert()  # (a directory where the key belongs: refused as an error, never silently skipped)

    @staticmethod
    def _client_pair_minted_at(offset_days):
        """A client pair the live CA issued with its validity shifted by `offset_days`. Since Q196's second pass `issue_client_cert` verifies the leaf it issues, so it refuses to mint an expired or
        not-yet-valid one: the damaged pair these tests need is fabricated with `_leaf(..., now=...)` instead of by patching the module's clock under the product."""
        import datetime

        ca_cert, ca_key = kea_tls._load_ca()
        key = kea_tls._new_key()
        leaf = kea_tls._leaf(
            ca_cert,
            ca_key,
            key,
            "jen test client",
            [],
            client=True,
            now=kea_tls._now() + datetime.timedelta(days=offset_days),
        )
        pem, key_path = kea_tls.client_paths()
        pathlib.Path(pem).write_bytes(kea_tls._cert_pem(leaf))
        pathlib.Path(key_path).write_bytes(kea_tls._key_pem(key))

    def test_an_expired_pair_is_damaged_and_re_issued(self, lab, monkeypatch):
        self._client_pair_minted_at(-3000)
        self._reissued(lab, "has expired")

    def test_a_pair_that_is_not_valid_yet_is_damaged(self, lab, monkeypatch):
        self._client_pair_minted_at(30)
        assert kea_tls.client_state()[0] == "damaged" and "not valid yet" in kea_tls.client_state()[1]

    def test_a_pair_issued_by_an_earlier_jen_ca_is_damaged_and_re_issued(self, lab):
        from tests import _tls_worlds as worlds

        worlds.replace_live_ca()  # a new live CA; the client pair is from the one before
        lab.begin()  # (the world is built: this is the state before any action)
        self._reissued(lab, "was not issued by the current CA")

    def test_a_certificate_without_clientAuth_is_damaged_and_re_issued(self, lab):
        ca_cert, ca_key = kea_tls._load_ca()
        pem, key_path = kea_tls.client_paths()
        key = kea_tls._new_key()
        wrong = kea_tls._leaf(ca_cert, ca_key, key, "a server leaf", [], client=False)
        pathlib.Path(pem).write_bytes(kea_tls._cert_pem(wrong))
        pathlib.Path(key_path).write_bytes(kea_tls._key_pem(key))
        self._reissued(lab, "no clientAuth")

    def test_a_pair_with_thirty_days_left_is_expiring_not_damaged_and_health_warns(self, lab, monkeypatch):
        import datetime

        real_now = kea_tls._now
        monkeypatch.setattr(kea_tls, "_now", lambda: real_now() - datetime.timedelta(days=kea_tls.LEAF_DAYS - 20))
        kea_tls.issue_client_cert(force=True)
        monkeypatch.setattr(kea_tls, "_now", real_now)
        state, why = kea_tls.client_state()
        assert state == "expiring" and "expires in" in why
        assert kea_tls.client_cert_ok() is False
        assert health._kea_tls_expiry({}).status in ("warn", "fail")
        assert kea_tls.issue_client_cert()["issued"] is True

    def test_neither_file_is_none_not_damaged_and_the_first_issue_says_nothing_was_repaired(self, lab):
        for p in kea_tls.client_paths():
            os.unlink(p)
        assert kea_tls.client_state() == ("none", "")
        assert health._kea_tls_expiry({}).status == "fail"
        result = kea_tls.issue_client_cert()
        assert result["issued"] is True and result["why"] == ""

    def test_with_a_damaged_ca_the_client_pair_is_judged_damaged_and_nothing_is_signed(self, lab):
        os.unlink(kea_tls.ca_paths()[1])
        lab.begin()
        state, why = kea_tls.client_state()
        assert state == "damaged" and "no usable CA" in why
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.issue_client_cert()


# ── Q193: the recovery's sentences say what happened and name an action that works ──────────────────────────────────────────────────────────────


def _recovery_damage(kind, tmp_path=None):
    if kind == "key-missing":
        os.unlink(kea_tls.ca_paths()[1])
    elif kind == "cert-missing":
        os.unlink(kea_tls.ca_paths()[0])
    else:
        from tests import _tls_worlds as worlds

        worlds.malformed(kea_tls.ca_paths()[0])


RECOVERY_FAULTS = [
    ("install-1", "refuse", (1, "install-tls", 1)),
    ("install-2", "refuse", (2, "install-tls", 1)),
    ("restart-1", "refuse", (1, "service", 1)),
    ("restart-2", "refuse", (2, "service", 1)),
    ("probe-1", "fault", (1, "timeout")),
    ("probe-2", "fault", (2, "timeout")),
]


class TestAFailedRecoverySaysWhatHappened:
    """Q193 (AI1): a recovery that fails - the CA was damaged BEFORE staging, no promotion ran - used to say "a promotion failed part-way and its own put-back failed too ... restore from the .prev
    copies" (neither is true) and "remove the direct socket and set it up again" (which the damaged gate refuses); the action that recovers is the acknowledged Rotate again. Each of the 18 rows
    (3 damages x 6 faults) names the count and the daemons, never "promotion" or ".prev", and the second acknowledged Rotate recovers."""

    @pytest.mark.parametrize("fault", RECOVERY_FAULTS, ids=[f[0] for f in RECOVERY_FAULTS])
    @pytest.mark.parametrize("damage", ["key-missing", "cert-missing", "cert-malformed"])
    def test_the_sentence_names_the_count_and_the_daemons_and_a_second_acknowledged_rotate_recovers(
        self, lab, damage, fault
    ):
        import re

        _name, kind, spec = fault
        _recovery_damage(damage)
        if kind == "refuse":
            lab.refuse.add(spec)
        else:
            lab.faults[spec[0]] = spec[1]
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "Kea CA rotated" not in texts, "an injected failure is never a success"
        assert "The recovery did not complete" in texts, texts
        counted = re.search(r"(\d) of 2 daemon\(s\) were left in a state that needs it repeated - ([^;]*)", texts)
        assert counted or "no daemon was changed" in texts, texts
        if counted:
            assert int(counted.group(1)) >= 1 and ("kea-dhcp4" in counted.group(2)), counted.group(0)
        for forbidden in (
            "promotion",
            "promote",
            ".prev",
            "matching pair",
            "set it up again",
            "remove the direct socket",
        ):
            assert forbidden not in texts, f"the sentence of a recovery that never promoted says {forbidden!r}: {texts}"
        assert "Rotate again with the acknowledgement" in texts and "Jen's CA is still damaged" in texts
        # the executed truth, now pinned: the second acknowledged Rotate, with the fault gone, recovers every daemon
        lab.refuse.clear()
        lab.faults.clear()
        lab.flashes.clear()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert kea_tls.ca_state() == ("ok", "")
        for sid in lab.hosts:
            assert lab.answers_jens_live_identity(sid), f"server {sid}'s daemon answers the replacement"

    def test_a_refused_first_install_in_a_recovery_is_remote_unknown(self, lab):
        """AI4 (e): the helper REFUSED the new pair and Jen could not re-assert the old one - what the host holds is unknown; `tls-not-restored` says it is KNOWN to hold the staged pair."""
        os.unlink(kea_tls.ca_paths()[1])
        lab.refuse.add((1, "install-tls", 1))
        _rotate({"acknowledge_damaged_ca": "1"})
        assert (1, "dhcp4", "remote-unknown") in lab.incidents and (1, "dhcp4", "tls-not-restored") not in lab.incidents


class TestTheSecondPassOfQ193:
    """The second pass on Q193 (agent a11a48176bf2e670c), each finding as its row first: 1 a recovery waives the READ of the old copies, never the WRITE (a host that took a pair Jen cannot record is
    cut off); 2 a recovery whose promotion fails is still a recovery - the CA is as damaged as it was and the sentences say so; 3 the sentence says what each daemon IS (cut off / unknown / not
    changed) and the incident of a cut-off daemon says it too."""

    def _damaged_with_a_copies_path_that_is_a_file(self, lab):
        import shutil

        directory = os.path.dirname(kea_tls.server_copy_path(1, "dhcp4"))
        shutil.rmtree(directory)
        pathlib.Path(directory).write_text("not a directory", encoding="ascii")  # unlistable AND unwritable
        os.unlink(kea_tls.ca_paths()[1])
        lab.begin()

    def test_row_1_a_recovery_with_a_copies_directory_it_cannot_write_is_refused_before_the_first_install(self, lab):
        self._damaged_with_a_copies_path_that_is_a_file(lab)
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "Rotate refused" in texts and "Nothing was changed" in texts, texts
        assert "cannot write its certificate records" in texts and "fix the folder's permissions" in texts, texts
        assert all(h["installs"] == [] and h["restarts"] == 0 for h in lab.hosts.values()), "no host was touched"
        assert lab.incidents == []

    def test_row_1_the_write_check_proves_by_creating_what_it_checks(self, lab, tmp_path, monkeypatch):
        """Q194 (AJ2) replaced Q193's inference ("a directory that is not there yet is writable"): the check now CREATES it, so a read-only parent is a refusal and not a surprise at the first commit."""
        assert kea_tls.copies_dir_writable() == ""
        import shutil

        directory = os.path.dirname(kea_tls.server_copy_path(1, "dhcp4"))
        shutil.rmtree(directory)
        assert kea_tls.copies_dir_writable() == "" and os.path.isdir(directory), "created, not inferred"
        shutil.rmtree(directory)
        pathlib.Path(directory).write_text("x", encoding="ascii")
        assert kea_tls.copies_dir_writable() != ""
        lab.begin()

    @pytest.mark.parametrize("damage", ["key-missing", "cert-missing", "cert-malformed"])
    @pytest.mark.parametrize("how", ["commit_rotation", "inside_commit_file_set"])
    def test_row_2_a_recovery_whose_promotion_fails_is_still_a_recovery(self, lab, monkeypatch, damage, how):
        _recovery_damage(damage)
        lab.begin()
        real = kea_tls.commit_rotation

        def failing_inside_the_real_promotion(staged):
            with (
                monkeypatch.context() as inner
            ):  # (only the promotion's own file-set commit fails: `commit_issued` before it still works)
                inner.setattr(kea_tls, "commit_file_set", lambda *a, **k: (_ for _ in ()).throw(OSError(13, "denied")))
                return real(staged)

        with monkeypatch.context() as scoped:
            if how == "commit_rotation":
                scoped.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
            else:
                scoped.setattr(kea_tls, "commit_rotation", failing_inside_the_real_promotion)
            _rotate({"acknowledge_damaged_ca": "1"})
            texts = lab.texts()
            assert "Kea CA rotated" not in texts
            assert "The recovery did not complete" in texts and "Rotate again with the acknowledgement" in texts, texts
            for forbidden in ("matching pair", "put-back failed", ".prev", "set it up again", "ROLLBACK FAILED"):
                assert forbidden not in texts, f"{forbidden!r}: {texts}"
            assert kea_tls.ca_state()[0] == "damaged"
            assert sorted(r[3] for r in lab.incident_records) == ["tls-not-restored", "tls-not-restored"]
            assert {r[5] for r in lab.incident_records} == {infra._RECOVERY_CUT_OFF}
        lab.flashes.clear()
        lab.incident_records.clear()
        lab.incidents.clear()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert kea_tls.ca_state() == ("ok", "")
        for sid in lab.hosts:
            assert lab.answers_jens_live_identity(sid)

    def test_row_3_the_sentence_says_which_daemon_is_cut_off_which_is_unknown_and_which_was_not_changed(self, lab):
        os.unlink(kea_tls.ca_paths()[1])
        lab.refuse.add((2, "install-tls", 1))
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "kea-a kea-dhcp4: the replacement CA's certificate is installed" in texts, texts
        assert "standby kea-dhcp4: the helper refused the replacement certificate" in texts, texts
        assert "2 of 2 daemon(s) were left in a state that needs it repeated" in texts and "Not changed" not in texts
        by_server = {r[0]: (r[3], r[5]) for r in lab.incident_records}
        assert by_server[1] == ("tls-not-restored", infra._RECOVERY_CUT_OFF)
        assert by_server[2][0] == "remote-unknown"

    def test_row_3_a_daemon_nothing_reached_is_named_as_not_changed(self, lab):
        os.unlink(kea_tls.ca_paths()[1])
        lab.refuse.add((1, "install-tls", 1))
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "1 of 2 daemon(s) were left in a state that needs it repeated" in texts, texts
        assert "Not changed: standby kea-dhcp4." in texts, texts
        assert "replacement CA's certificate is installed" not in texts


# ── Q194: a CA is healthy only when it is a certificate-signing authority; a preflight proves by doing ───────────────────────────────────────────


CA_IDENTITY_WHY = {
    "not-ca": "not marked as a certificate authority (BasicConstraints ca is false)",
    "no-basic-constraints": "has no BasicConstraints",
    "no-key-cert-sign": "lacks keyCertSign",
    "expired": "expired on",
    "not-yet-valid": "is not valid until",
    "tampered-signature": "signature does not verify against its own key",
    "issuer-not-subject": "is not self-signed",
    "unsupported-key": "key type Jen does not support",
    "duplicate-extension": "has an extension Jen cannot read",
    "aki-not-ski": "AuthorityKeyIdentifier does not name its own key",
}


def _ca_bytes():
    return {
        p: (pathlib.Path(p).read_bytes() if os.path.lexists(p) else None)
        for p in (*kea_tls.ca_paths(), *kea_tls.client_paths())
    }


class TestCaIdentity:
    """Q194 (AJ1): `kea_tls.ca_identity` is the ONE judgment of CA material, applied to the live, the prepared and the staged pair. Real certificates, one per way a pair that parses and pairs can still fail to be
    a certificate-signing authority. Q192's `ca_state` returned `ok` for every one of them and Jen signed with them (the reviewer: `ca=False` -> `ca_state ok`, `issue_client_cert issued=True`, OpenSSL "invalid
    CA certificate"; an expired CA -> `ok`, `days_left -2`)."""

    def test_jens_own_ca_is_ok(self, lab):
        assert kea_tls.ca_identity(*kea_tls.ca_paths()) == ("ok", "")

    @pytest.mark.parametrize("kind", __import__("tests._tls_worlds", fromlist=["x"]).SEMANTIC_CA_STATES)
    def test_every_semantic_damage_is_named_by_the_first_check_it_fails(self, tmp_path, kind):
        from tests import _tls_worlds as worlds

        cert_pem, key_pem = worlds.semantic_ca_pem(kind)
        crt, key = tmp_path / "ca.crt", tmp_path / "ca.key"
        crt.write_bytes(cert_pem)
        key.write_bytes(key_pem)
        state, why = kea_tls.ca_identity(str(crt), str(key))
        assert state == "damaged" and CA_IDENTITY_WHY[kind] in why, (kind, state, why)

    @pytest.mark.parametrize("kind", __import__("tests._tls_worlds", fromlist=["x"]).SEMANTIC_CA_STATES)
    def test_a_live_ca_that_cannot_sign_is_damaged_never_replaced_and_the_acknowledged_rotate_recovers(self, lab, kind):
        from tests import _tls_worlds as worlds

        crt, key = kea_tls.ca_paths()
        cert_pem, key_pem = worlds.semantic_ca_pem(kind)
        pathlib.Path(crt).write_bytes(cert_pem)
        pathlib.Path(key).write_bytes(key_pem)
        lab.begin()
        lab.before = None  # (direct calls to the module are not requests: T5 is about requests)
        state, why = kea_tls.ca_state()
        assert state == "damaged" and CA_IDENTITY_WHY[kind] in why, (kind, state, why)
        assert not kea_tls.ca_consistent(), "the failure paths ask the same question"
        before = _ca_bytes()
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.ensure_ca()
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.issue_client_cert()
        assert _ca_bytes() == before, "T6/T7: nothing was replaced, nothing created"
        row = health._kea_tls_expiry({})
        assert row.status == "fail" and CA_IDENTITY_WHY[kind] in row.detail, row.detail
        lab.begin()
        _rotate()  # without the acknowledgement: refused, and the files are exactly what they were
        assert "Jen's CA is damaged" in lab.texts() and _ca_bytes() == before and lab.remote_actions() == 0
        lab.flashes.clear()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert kea_tls.ca_state() == ("ok", "") and kea_tls.ca_identity(*kea_tls.ca_paths()) == ("ok", "")
        for sid in lab.hosts:
            assert lab.answers_jens_live_identity(sid)

    @pytest.mark.parametrize("kind", __import__("tests._tls_worlds", fromlist=["x"]).SEMANTIC_CA_STATES)
    def test_a_prepared_ca_that_is_not_an_authority_is_refused_discarded_by_the_writer_and_never_installed(
        self, lab, kind
    ):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from tests import _tls_worlds as worlds

        staged = worlds.stage_semantic_prepared(kind)
        invalid_cert = pathlib.Path(staged["ca_cert"]).read_bytes()
        found, note = kea_tls.prepared_rotation()  # a READ: it never deletes
        assert found is None and "damaged or inconsistent" in note and CA_IDENTITY_WHY[kind] in note, note
        assert all(os.path.lexists(p) for p in staged.values()), "a read left the files where they were"
        lab.begin()
        live_before = _ca_bytes()
        _rotate()  # Rotate (the writer) discards it, says why, and rotates with a fresh CA - never the invalid one
        texts = lab.texts()
        assert "damaged or inconsistent" in texts and CA_IDENTITY_WHY[kind] in texts, texts
        assert "Kea CA rotated" in texts and _ca_bytes() != live_before
        for sid, host in lab.hosts.items():
            installed = x509.load_pem_x509_certificate(host["files"]["ca.crt"].encode())
            assert installed.public_bytes(serialization.Encoding.PEM) != invalid_cert, (
                f"server {sid} was given the CA that cannot sign"
            )

    def test_the_prepare_action_discards_it_with_the_reason_and_writes_a_fresh_one(self, lab):
        from tests import _tls_worlds as worlds

        worlds.stage_semantic_prepared("not-ca")
        lab.begin()
        lab.before = None  # (Prepare writes `.next` on purpose)
        _prepare()
        assert CA_IDENTITY_WHY["not-ca"] in lab.texts() and "A new CA is prepared" in lab.texts(), lab.texts()
        found, note = kea_tls.prepared_rotation()
        assert found is not None and note == ""
        assert kea_tls.ca_identity(found["ca_cert"], found["ca_key"]) == ("ok", "")

    def test_the_staged_ca_is_judged_once_more_immediately_before_anything_is_installed(self, lab, monkeypatch):
        """A prepared CA was read earlier; a file can change between that read and the first install. The preflight applies the same function to the set Rotate is about to use."""
        from tests import _tls_worlds as worlds

        staged = worlds.stage_semantic_prepared("not-ca")
        monkeypatch.setattr(kea_tls, "prepared_rotation", lambda discard=False: (staged, ""))
        lab.begin()
        before = _ca_bytes()
        _rotate()
        texts = lab.texts()
        assert "Rotate refused - the new CA is not a certificate-signing authority" in texts, texts
        assert CA_IDENTITY_WHY["not-ca"] in texts and lab.remote_actions() == 0 and _ca_bytes() == before
        assert all(h["installs"] == [] and h["restarts"] == 0 for h in lab.hosts.values())


def _can_block_writes_by_mode():
    return os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0


class TestCopiesDir:
    """Q194 (AJ2): the certificate-record directory is proved writable BY WRITING - created when absent (0700), a probe file written and removed - and on every path that will need it: every rotation's
    inventory, the https setup before `stage_issued`, and the recovery once more before its first install. Q193's version inferred "a directory that is not there yet is writable" (executed under a
    read-only parent: `PermissionError errno 13` on the real create) and was asked only when listing raised, so a recovery with the directory MISSING never asked."""

    @staticmethod
    def _directory():
        return os.path.dirname(kea_tls.server_copy_path(1, "dhcp4"))

    @staticmethod
    def _wiped_recovery(lab):
        import shutil

        shutil.rmtree(TestCopiesDir._directory())
        os.unlink(kea_tls.ca_paths()[1])  # the common world: the CA damaged AND the record directory gone
        lab.begin()

    @staticmethod
    def _parent_is_read_only(monkeypatch):
        """A read-only parent, portably: the create of the record directory raises what the real create raises (EACCES)."""
        directory = TestCopiesDir._directory()
        real = os.makedirs

        def makedirs(path, *a, **k):
            if os.path.normcase(os.path.abspath(str(path))) == os.path.normcase(os.path.abspath(directory)):
                raise PermissionError(13, "Permission denied")
            return real(path, *a, **k)

        monkeypatch.setattr(os, "makedirs", makedirs)

    def test_an_existing_writable_directory_is_ok_and_the_probe_leaves_nothing(self, lab):
        before = sorted(os.listdir(self._directory()))
        assert kea_tls.copies_dir_writable() == ""
        assert sorted(os.listdir(self._directory())) == before

    @pytest.mark.skipif(not _can_block_writes_by_mode(), reason="a privileged account (or Windows) writes anyway")
    def test_an_existing_read_only_directory_is_refused_with_its_class(self, lab):
        d = self._directory()
        os.chmod(d, 0o500)
        try:
            why = kea_tls.copies_dir_writable()
        finally:
            os.chmod(d, 0o700)
        assert why.startswith("PermissionError") and "errno 13" in why, why

    def test_an_existing_directory_that_cannot_be_listed_but_can_be_written_is_ok(self, lab, monkeypatch):
        d = self._directory()
        real = os.listdir

        def listdir(path="."):
            if os.path.normcase(os.path.abspath(str(path))) == os.path.normcase(os.path.abspath(d)):
                raise PermissionError(13, "Permission denied")
            return real(path)

        monkeypatch.setattr(os, "listdir", listdir)
        assert kea_tls.copies_dir_writable() == ""
        os.unlink(kea_tls.ca_paths()[1])
        lab.begin()
        inventory = kea_tls.rotation_inventory(
            extensions.KEA_SERVERS, url_for=lambda s, svc: lab.urls[s["id"]] if svc == "dhcp4" else "", recovery=True
        )
        assert not any("certificate records" in r for r in inventory.refusals), inventory.refusals

    def test_a_missing_directory_under_a_writable_parent_is_created_private_and_then_rotated(self, lab):
        import stat

        self._wiped_recovery(lab)
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert os.path.isdir(self._directory())
        if os.name != "nt":
            assert stat.S_IMODE(os.stat(self._directory()).st_mode) == 0o700

    def test_a_missing_directory_under_a_read_only_parent_is_refused_before_staging_with_nothing_changed(
        self, lab, monkeypatch
    ):
        self._wiped_recovery(lab)
        self._parent_is_read_only(monkeypatch)
        before = _ca_bytes()
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "Rotate refused" in texts and "cannot write its certificate records" in texts, texts
        assert "PermissionError, errno 13" in texts, "the refusal names the storage failure"
        assert lab.remote_actions() == 0 and all(h["installs"] == [] for h in lab.hosts.values())
        assert _ca_bytes() == before, "the CA is byte-equal"
        assert not list(pathlib.Path(kea_tls.ca_paths()[0]).parent.glob("*.next")), "nothing was staged"
        assert not os.path.lexists(self._directory())

    def test_a_missing_directory_under_a_read_only_parent_refuses_an_ordinary_rotation_too(self, lab, monkeypatch):
        """'recovery or not - every rotation records new pairs': Q193 asked only when listing raised."""
        import shutil

        shutil.rmtree(self._directory())
        lab.begin()
        self._parent_is_read_only(monkeypatch)
        _rotate()
        assert "cannot write its certificate records" in lab.texts() and lab.remote_actions() == 0, lab.texts()

    def test_the_path_being_a_regular_file_is_refused_with_its_class(self, lab):
        import shutil

        shutil.rmtree(self._directory())
        pathlib.Path(self._directory()).write_text("not a directory", encoding="ascii")
        why = kea_tls.copies_dir_writable()
        assert why and "errno" in why, why
        lab.begin()

    def test_a_directory_created_for_a_check_that_then_fails_is_removed_again(self, lab):
        import shutil

        d = self._directory()
        shutil.rmtree(d)
        real_open = os.open

        def deny(path, flags, mode=0o777, **kw):
            if ".write-probe-" in str(path):
                raise PermissionError(13, "Permission denied")
            return real_open(path, flags, mode, **kw)

        import pytest as _pytest

        with _pytest.MonkeyPatch.context() as scoped:
            scoped.setattr(os, "open", deny)
            why = kea_tls.copies_dir_writable()
        assert why.startswith("PermissionError") and not os.path.lexists(d), "the check left no directory behind"
        lab.begin()

    def test_the_filesystem_made_read_only_between_the_preflight_and_the_first_install_is_refused_before_it(
        self, lab, monkeypatch
    ):
        os.unlink(kea_tls.ca_paths()[1])
        lab.begin()
        real, calls = kea_tls.copies_dir_writable, []

        def flaky(keep=True):
            calls.append(1)
            return real(keep=keep) if len(calls) == 1 else "PermissionError, errno 13"

        monkeypatch.setattr(kea_tls, "copies_dir_writable", flaky)
        before = _ca_bytes()
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert len(calls) >= 2, "the recovery asked again immediately before the first install"
        assert "cannot write its certificate records any more" in texts and "Nothing was changed on any host" in texts
        assert lab.remote_actions() == 0 and all(h["installs"] == [] for h in lab.hosts.values())
        assert _ca_bytes() == before
        assert not list(pathlib.Path(kea_tls.ca_paths()[0]).parent.glob("*.next")), "the staging was discarded"

    def test_the_reviewers_sequence_a_prepared_ca_then_a_recovery_with_a_missing_directory_under_a_read_only_parent(
        self, lab, monkeypatch
    ):
        os.unlink(kea_tls.ca_paths()[1])
        lab.begin()
        lab.before = None  # (Prepare writes `.next` on purpose)
        _prepare()
        import shutil

        shutil.rmtree(self._directory())
        lab.begin()
        self._parent_is_read_only(monkeypatch)
        prepared = {p: pathlib.Path(p).read_bytes() for p in kea_tls._staged_paths().values()}
        before = _ca_bytes()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "cannot write its certificate records" in lab.texts() and lab.remote_actions() == 0, lab.texts()
        assert _ca_bytes() == before
        assert {p: pathlib.Path(p).read_bytes() for p in kea_tls._staged_paths().values()} == prepared, (
            "the prepared CA an external daemon may already hold is kept"
        )

    def test_the_https_setup_proves_the_directory_before_it_stages_anything(self):
        """Source: the setup asks `copies_dir_writable` before `stage_issued` (the setup harness runs the https path; this pins the ORDER, which a mocked collaborator cannot)."""
        source = (
            pathlib.Path(__file__).resolve().parents[1] / "jen" / "routes" / "settings" / "infrastructure.py"
        ).read_text(encoding="utf-8")
        setup = source[source.index("def setup_direct_socket") :]
        assert (
            0
            < setup.index("copies_dir_writable(")
            < setup.index("ensure_ca()")
            < setup.index("stage_issued(server_id, service, files)")
        )


class TestTheSecondPassOfQ194:
    """The second pass on Q194 (agent ad738f2e0befcf065), each finding as its row first: 1 a CA file with a duplicated extension is "damaged" and never raises (`DuplicateExtension` is not a ValueError);
    2 a WORKING operator CA - no KeyUsage extension (RFC 5280: unrestricted) - is not called damaged, and a self-signature Jen cannot verify has its own sentence; 4 a leftover probe never refuses a
    writable directory; 5 a preflight leaves the directory as it found it (a refusal changes nothing; the uninitialised world stays uninitialised)."""

    def test_row_1_a_duplicated_extension_in_the_ca_is_damaged_in_every_reader_and_never_raises(self, lab):
        from tests import _tls_worlds as worlds

        crt, key = kea_tls.ca_paths()
        cert_pem, key_pem = worlds.semantic_ca_pem("duplicate-extension")
        pathlib.Path(crt).write_bytes(cert_pem)
        pathlib.Path(key).write_bytes(key_pem)
        lab.begin()
        lab.before = None
        state, why = kea_tls.ca_state()
        assert state == "damaged" and "has an extension Jen cannot read" in why, (state, why)
        assert kea_tls.ca_consistent() is False
        row = health._kea_tls_expiry({})
        assert row.status == "fail" and "extension Jen cannot read" in row.detail
        assert infra._kea_ca_summary()["damaged"] is True, "the Settings page renders it"
        assert kea_tls.ca_refusal(), "the https setup's gate refuses"

    def test_row_1_a_client_certificate_with_a_duplicated_extension_is_damaged_never_raises(self, lab):
        from tests import _tls_worlds as worlds

        pem, _key = kea_tls.client_paths()
        pathlib.Path(pem).write_bytes(
            worlds.duplicate_an_extension(pathlib.Path(pem).read_bytes(), keyusage_oid_last=0x25)
        )
        lab.begin()
        lab.before = None
        state, why = kea_tls.client_state(judge_issuer=False)
        assert state == "damaged" and "extension Jen cannot read" in why, (state, why)

    def test_row_2_a_ca_without_a_key_usage_extension_is_ok_as_rfc_5280_says_and_signs(self, lab):
        from tests import _tls_worlds as worlds

        cert_pem, key_pem = worlds.semantic_ca_pem("no-key-usage")
        crt, key = kea_tls.ca_paths()
        pathlib.Path(crt).write_bytes(cert_pem)
        pathlib.Path(key).write_bytes(key_pem)
        lab.begin()
        lab.before = None
        assert kea_tls.ca_state() == ("ok", "") and kea_tls.ca_consistent() is True
        result = kea_tls.issue_client_cert()  # the pair the old CA issued is re-issued from the CA that is live now
        assert result["issued"] is True and kea_tls.client_state() == ("ok", "")
        assert health._kea_tls_expiry({}).status != "fail" or "CA" not in health._kea_tls_expiry({}).detail

    def test_row_2_a_key_usage_that_forbids_signing_is_still_damaged(self, lab, tmp_path):
        from tests import _tls_worlds as worlds

        cert_pem, key_pem = worlds.semantic_ca_pem("no-key-cert-sign")
        (tmp_path / "c.crt").write_bytes(cert_pem)
        (tmp_path / "c.key").write_bytes(key_pem)
        state, why = kea_tls.ca_identity(str(tmp_path / "c.crt"), str(tmp_path / "c.key"))
        assert state == "damaged" and "lacks keyCertSign" in why

    def test_row_2_a_self_signature_jen_cannot_verify_says_so_and_does_not_claim_it_is_false(self, tmp_path):
        """A SHA-1 self-signed CA (an operator's) - built with the openssl CLI, because `cryptography` will not sign with SHA-1 here. The sentence is about what Jen CANNOT do, not a claim that the signature is wrong."""
        import shutil
        import subprocess  # nosec B404

        openssl = shutil.which("openssl")
        if not openssl:
            pytest.skip("no openssl on this machine")
        crt, key = tmp_path / "sha1.crt", tmp_path / "sha1.key"
        done = subprocess.run(  # nosec B603
            [
                openssl, "req", "-x509", "-newkey", "rsa:2048", "-sha1", "-nodes", "-days", "30", "-subj", "/CN=sha1 ca",
                "-keyout", str(key), "-out", str(crt),
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign",
            ],
            capture_output=True,
            check=False,
        )  # fmt: skip
        if done.returncode != 0 or not crt.exists():
            pytest.skip("this openssl will not make a SHA-1 certificate")
        state, why = kea_tls.ca_identity(str(crt), str(key))
        assert state == "damaged" and "algorithm Jen cannot verify" in why and "does not verify" not in why, (
            state,
            why,
        )

    def test_row_4_a_leftover_probe_never_refuses_a_writable_directory(self, lab):
        d = os.path.dirname(kea_tls.server_copy_path(1, "dhcp4"))
        for name in (f".write-probe-{os.getpid()}-0123456789abcdef", ".write-probe-4242-fedcba9876543210"):
            pathlib.Path(d, name).write_text("", encoding="ascii")
            os.utime(
                pathlib.Path(d, name), (time.time() - 3600, time.time() - 3600)
            )  # a probe a killed process left an hour ago
        assert kea_tls.copies_dir_writable() == ""
        assert not [n for n in os.listdir(d) if kea_tls.PROBE_NAME.fullmatch(n)], "the leftovers were cleaned"
        assert kea_tls.copies_dir_writable() == "", "and a second check is as clear as the first"

    def test_row_5_a_preflight_leaves_the_directory_as_it_found_it_and_the_check_before_the_install_keeps_it(self, lab):
        import shutil

        d = os.path.dirname(kea_tls.server_copy_path(1, "dhcp4"))
        shutil.rmtree(d)
        assert kea_tls.copies_dir_writable(keep=False) == "" and not os.path.lexists(d), "the preflight made nothing"
        assert kea_tls.copies_dir_writable() == "" and os.path.isdir(d), "the check before a write keeps what it made"
        lab.begin()

    def test_row_5_the_inventory_in_the_uninitialised_world_leaves_it_uninitialised(self, lab):
        import shutil

        shutil.rmtree(kea_tls.SSL_DIR)
        os.makedirs(kea_tls.SSL_DIR)
        assert kea_tls.ca_state() == ("none", "")
        kea_tls.rotation_inventory(extensions.KEA_SERVERS)  # the DEFAULT proves storage
        assert kea_tls.ca_state() == ("none", ""), "an empty record directory would read as 'a CA issued into it'"
        lab.hosts.clear()
        lab.begin()

    def test_row_5_a_refusal_for_another_reason_creates_no_directory(self, lab):
        import shutil

        shutil.rmtree(os.path.dirname(kea_tls.server_copy_path(1, "dhcp4")))  # every record gone: Rotate refuses
        lab.begin()
        before = {p.relative_to(kea_tls.SSL_DIR) for p in pathlib.Path(kea_tls.SSL_DIR).rglob("*")}
        _rotate()
        assert "Rotate refused" in lab.texts() and lab.remote_actions() == 0, lab.texts()
        after = {p.relative_to(kea_tls.SSL_DIR) for p in pathlib.Path(kea_tls.SSL_DIR).rglob("*")}
        assert after == before, "a refusal changed no file and made no directory"


# ── Q195: in a recovery an external endpoint is judged by the REPLACEMENT identity ─────────────────────────────────────────────────────────────────


def _recovery_world_under(kind):
    """The live CA is the semantic damage `kind`, and Jen's live client pair was issued BY it (valid itself): the world where an external endpoint trusts the damaged CA for client authentication.
    Returns the damaged CA's PEM - what that endpoint's trust anchor holds."""
    from tests import _tls_worlds as worlds

    cert, key = worlds.semantic_ca(kind)
    from cryptography.hazmat.primitives import hashes

    if kind in worlds.VERIFIER_CA_STATES + worlds.VERIFIER_OK_STATES:
        _ANCHOR_KEYS[cert.fingerprint(hashes.SHA256())] = key
    crt, key_path = kea_tls.ca_paths()
    pathlib.Path(crt).write_bytes(kea_tls._cert_pem(cert))
    pathlib.Path(key_path).write_bytes(kea_tls._key_pem(key))
    pem, client_key_path = kea_tls.client_paths()
    client_key = kea_tls._new_key()
    leaf = kea_tls._leaf(cert, key, client_key, "jen client under the damaged CA", [], client=True)
    pathlib.Path(pem).write_bytes(kea_tls._cert_pem(leaf))
    pathlib.Path(client_key_path).write_bytes(kea_tls._key_pem(client_key))
    return kea_tls._cert_pem(cert).decode()


class TestRecoveryBesideAnExternal:
    """Q195 (AK1, the P2): Q192's rule "an endpoint that does not answer the live pair is unreachable regardless" is false in a RECOVERY - the live pair fails BECAUSE the CA being replaced is the one the
    external trusts and it can no longer vouch (expired, not a CA, not yet valid). The shipped fake accepted an expired anchor, so no test saw it; `Lab.accepts_client` now checks the anchor as OpenSSL does
    (`_anchor_usable`). In a recovery the staged pair is tried when the live pair is REJECTED BY CERTIFICATE: accepted = not a refusal; rejected too = Prepare, install, rotate again; a transport fault is
    unchanged. Non-recovery behaviour is unchanged."""

    PREPARE_SENTENCE = "rejects Jen's current client certificate (usually because the damaged CA is the one it trusts) and does not accept the new one yet"

    @pytest.mark.parametrize("kind", ["expired", "not-ca", "not-yet-valid"])
    def test_the_strict_fake_does_not_accept_a_client_certificate_from_an_anchor_openssl_would_not(self, lab, kind):
        # the positive control FIRST, in the healthy world: a certificate the healthy original CA issued (server 1's record copy) is accepted by an anchor that is that CA
        healthy_ca = _ca_pem_of_original(lab)
        _add_external(lab, sid=3, trust=healthy_ca)
        assert lab.accepts_client(3, kea_tls.server_copy_path(1, "dhcp4")) is True
        anchor = _recovery_world_under(kind)
        lab.hosts[3]["client_trust"] = anchor
        lab.begin()
        assert lab.accepts_client(3, kea_tls.client_paths()[0]) is False, (
            f"an anchor that is {kind} vouches for nothing"
        )

    @pytest.mark.parametrize("kind", ["expired", "not-ca", "not-yet-valid"])
    def test_prepare_then_install_then_the_acknowledged_rotate_recovers_beside_an_external_that_trusted_the_damaged_ca(
        self, lab, kind
    ):
        anchor = _recovery_world_under(kind)
        _add_external(lab, trust=anchor)
        lab.begin()
        before = _ca_bytes()
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "Rotate refused" in texts and self.PREPARE_SENTENCE in texts, texts
        assert "Prepare the new CA" in texts and "does not answer Jen's current client certificate" not in texts
        assert lab.remote_actions() == 0 and _ca_bytes() == before, "nothing was installed and the CA is byte-equal"
        # Prepare, and the external's trust anchor gains the new CA beside the damaged one
        lab.before = None
        _prepare()
        prepared_ca = pathlib.Path(kea_tls._staged_paths()["ca_cert"]).read_bytes()
        lab.hosts[3]["client_trust"] = anchor + prepared_ca.decode("ascii")
        lab.begin()
        lab.flashes.clear()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert pathlib.Path(kea_tls.ca_paths()[0]).read_bytes() == prepared_ca, "the prepared CA IS the new CA"
        for sid in lab.hosts:
            assert lab.answers_jens_configured_dial(sid), f"endpoint {sid} answers the configured dial"

    def test_an_external_that_rejects_both_pairs_is_refused_with_the_prepare_sentence(self, lab):
        from tests import _tls_worlds as worlds

        _recovery_world_under("expired")
        unrelated = kea_tls._cert_pem(worlds.other_ca()[0]).decode()
        _add_external(lab, trust=unrelated)
        lab.begin()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert self.PREPARE_SENTENCE in lab.texts() and lab.remote_actions() == 0, lab.texts()

    def test_a_transport_fault_at_the_live_probe_keeps_the_unchanged_sentence(self, lab):
        anchor = _recovery_world_under("expired")
        _add_external(lab, trust=anchor)
        lab.faults[3] = "refused"
        lab.begin()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "does not answer Jen's current client certificate" in lab.texts(), lab.texts()
        assert self.PREPARE_SENTENCE not in lab.texts() and lab.remote_actions() == 0

    def test_a_transport_fault_at_the_staged_probe_after_a_certificate_rejection_says_could_not_be_probed(
        self, lab, monkeypatch
    ):
        anchor = _recovery_world_under("expired")
        _add_external(lab, trust=anchor)
        real = infra._probe_once

        def flaky(url, user, pwd, omit_service, **kw):
            if "10.0.0.7" in url and kw.get("cert") and "next" in str(kw["cert"][0]):
                return "", "HTTPSConnectionPool: Read timed out."
            return real(url, user, pwd, omit_service, **kw)

        monkeypatch.setattr(infra, "_probe_once", flaky)
        lab.begin()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "could not be probed with the new client certificate (a timeout)" in lab.texts(), lab.texts()
        assert lab.remote_actions() == 0

    def test_a_healthy_rotation_beside_an_external_that_rejects_the_live_pair_is_refused_as_today(self, lab):
        from tests import _tls_worlds as worlds

        unrelated = kea_tls._cert_pem(worlds.other_ca()[0]).decode()
        _add_external(lab, trust=unrelated)
        lab.begin()
        _rotate()
        assert "does not answer Jen's current client certificate" in lab.texts(), lab.texts()
        assert self.PREPARE_SENTENCE not in lab.texts() and lab.remote_actions() == 0


def _ca_pem_of_original(lab) -> str:
    """The PEM of the CA the Jen-issued daemons loaded (their `ca.crt`)."""
    return lab.hosts[1]["loaded"]["ca.crt"]


class TestTheSmallOnesOfQ195:
    """AK2: (a) the cleanup of leftover probes matches Jen's own pattern and nothing else; (b) the non-recovery failure path says the CA's state NOW and the action that works; (c) the evidence count
    ignores Jen's own probe files."""

    def test_a_the_cleanup_removes_jens_probes_and_never_an_operators_file(self, lab):
        d = os.path.dirname(kea_tls.server_copy_path(1, "dhcp4"))
        mine = [f".write-probe-{os.getpid()}-0123456789abcdef", ".write-probe-4242-fedcba9876543210"]
        theirs = [
            ".write-probe-OPERATORS-NOTES.txt",
            ".write-probe-123",
            ".write-probe-1-ABCDEF0123456789",
            ".write-probe-1-abc",
        ]
        for name in mine + theirs:
            pathlib.Path(d, name).write_text("x", encoding="ascii")
            os.utime(pathlib.Path(d, name), (time.time() - 3600, time.time() - 3600))
        assert kea_tls.copies_dir_writable() == ""
        left = set(os.listdir(d))
        assert not (set(mine) & left), "Jen's own leftovers were removed"
        assert set(theirs) <= left, "a file an operator keeps there survives"

    def test_b_a_ca_that_becomes_unusable_during_a_rotation_without_a_promotion_says_what_it_is_now(
        self, lab, monkeypatch
    ):
        stub = jconfig.app_config.write_values

        def key_vanishes_then_the_write_is_refused(*a, **k):
            os.unlink(
                kea_tls.ca_paths()[1]
            )  # the CA's key goes between the installs and the settings write: no promotion ever ran
            return stub(*a, **k)

        with monkeypatch.context() as scoped:
            scoped.setattr(jconfig.app_config, "write_values", key_vanishes_then_the_write_is_refused)
            lab.settings_error = jconfig.ConfigChangeRefused("Jen's settings could not be written")
            _rotate()
        texts = lab.texts()
        assert not kea_tls.ca_consistent(), "the STATE: the CA is unusable"
        why = kea_tls.ca_state()[1]
        assert why and f"Jen's CA became unusable during the rotation ({why})" in texts, texts
        assert "Rotate again with the acknowledgement" in texts, texts
        for forbidden in ("a promotion failed part-way", ".prev", "set it up again", "remove the direct socket"):
            assert forbidden not in texts, f"{forbidden!r}: {texts}"
        assert sorted(i[2] for i in lab.incidents) == ["tls-not-restored", "tls-not-restored"]
        # ... and the action it names recovers
        lab.settings_error = None
        lab.flashes.clear()
        lab.incidents.clear()
        lab.incident_records.clear()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()

    def test_c_the_evidence_count_ignores_jens_own_probe_files(self, lab):
        import shutil

        shutil.rmtree(kea_tls.SSL_DIR)
        os.makedirs(os.path.join(kea_tls.SSL_DIR, "kea-servers"))
        pathlib.Path(kea_tls.SSL_DIR, "kea-servers", f".write-probe-{os.getpid()}-0123456789abcdef").write_text(
            "", encoding="ascii"
        )
        evidence = kea_tls._initialised_evidence()
        assert "holds" not in evidence and "certificate directory exists" in evidence, evidence
        pathlib.Path(kea_tls.SSL_DIR, "kea-servers", "1-dhcp4.crt").write_text("x", encoding="ascii")
        assert "holds 1 file(s)" in kea_tls._initialised_evidence()
        lab.hosts.clear()
        lab.begin()


class TestTheSecondPassOfQ195:
    """The second pass on Q195 (agent a3d86ae2ab7c13ebd), each finding as its row first: 1 the detector recognises what a real TLS 1.3 stack sends (the server's alert races its close: 88-95 percent of
    real rejections were 'EOF occurred in violation of protocol' / 'Remote end closed connection'), so the recovery goes on when the replacement is accepted; 2 a name or an alert that is not about the
    client certificate is never read as a rejection of it; 4 the strict fake agrees with the OpenSSL table that was EXECUTED; 6 the Prepare sentence says 'usually because'; the cleanup never deletes a probe
    that is being written."""

    @pytest.mark.parametrize(
        ("text", "rejected"),
        [
            ("SSLError(1, '[SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required')", True),
            ("HTTPSConnectionPool(host='kea.lan', port=8000): sslv3 alert bad certificate", True),
            ("tlsv1 alert unknown ca", True),
            ("sslv3 alert handshake failure", True),
            ("('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))", True),
            ("SSLEOFError(8, 'EOF occurred in violation of protocol (_ssl.c:2427)')", True),
            ("client certificate rejected", True),
            ("Failed to resolve 'kea-alert.lan' ([Errno -2] Name or service not known)", False),
            ("tlsv1 alert protocol version", False),
            ("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired", False),
            ("HTTPSConnectionPool: Read timed out.", False),
            (
                "HTTPSConnectionPool(host='kea-alert.lan', port=8000): NewConnectionError: [Errno 111] Connection refused",
                False,
            ),
            ("", False),
        ],
    )
    def test_the_detector_reads_real_stacks_not_a_phrase_the_fake_invented(self, text, rejected):
        assert infra._rejects_the_client_certificate(text) is rejected, text

    @pytest.mark.parametrize(
        "live_text",
        [
            "('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))",
            "SSLEOFError(8, 'EOF occurred in violation of protocol (_ssl.c:2427)')",
        ],
    )
    def test_row_1_a_tls13_closure_is_a_rejection_the_recovery_goes_on_when_the_replacement_is_accepted(
        self, lab, monkeypatch, live_text
    ):
        anchor = _recovery_world_under("expired")
        _add_external(lab, trust=anchor)
        real = infra._probe_once

        def tls13(url, user, pwd, omit_service, **kw):
            version, err = real(url, user, pwd, omit_service, **kw)
            if not version and "10.0.0.7" in url and "next" not in str(kw.get("cert", ("",))[0]):
                return "", live_text  # the live pair's rejection, as a real TLS 1.3 server says it
            return version, err

        monkeypatch.setattr(infra, "_probe_once", tls13)
        lab.begin()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert TestRecoveryBesideAnExternal.PREPARE_SENTENCE in lab.texts(), lab.texts()
        assert "it has to answer before a rotation can be proved safe" not in lab.texts()
        lab.before = None
        _prepare()
        prepared_ca = pathlib.Path(kea_tls._staged_paths()["ca_cert"]).read_bytes()
        lab.hosts[3]["client_trust"] = anchor + prepared_ca.decode("ascii")
        lab.begin()
        lab.flashes.clear()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()

    @pytest.mark.parametrize(
        ("kind", "accepts"),
        [
            ("not-ca", False),
            ("no-key-cert-sign", False),
            ("expired", False),
            ("not-yet-valid", False),
            ("issuer-not-subject", False),
            ("duplicate-extension", False),
            # Q197 (AM6 e): the fake judges with the product's `ca_identity(cert_only=True)`. OpenSSL itself still chains to a trust anchor with a tampered self-signature and to a root with no
            # BasicConstraints but keyCertSign (executed, openssl 3.2.4); Jen is the stricter judge on both and the fake now agrees with Jen (registered, admin-guide table of Jen-stricter shapes)
            ("tampered-signature", False),
            ("no-basic-constraints", False),
            ("no-key-usage", True),  # the operator's own CA
            (
                "aki-not-ski",
                False,
            ),  # Q197 (AM1 a): OpenSSL does not treat the root as self-issued: "unable to get issuer certificate"
        ],
    )
    def test_row_4_the_strict_fake_agrees_with_what_openssl_did_when_it_was_executed(self, kind, accepts):
        from tests import _tls_worlds as worlds

        cert, _key = worlds.semantic_ca(kind)
        assert _anchor_usable(cert) is accepts, kind

    @pytest.mark.parametrize(
        ("kind", "first_refusal"),
        [
            ("no-key-cert-sign", "prepare"),
            ("issuer-not-subject", "prepare"),
            ("tampered-signature", "prepare"),  # Q197 (AM6 e): the fake shares the product's judgment of the anchor
            ("no-basic-constraints", "prepare"),
            ("aki-not-ski", "prepare"),
            ("eku-anyeku", "prepare"),
            (
                "eku-serverauth-only",
                "prepare",
            ),  # Q196: a CA restricted to serverAuth cannot vouch for a client certificate
            ("eku-codesigning", "prepare"),
            ("name-constraints-exclude-all", "prepare"),
            (
                "eku-clientauth-only",
                "depends",
            ),  # ... and one restricted to clientAuth still can: the endpoint DEPENDS on the damaged CA
        ],
    )
    def test_the_same_recovery_for_every_other_damage_the_lab_can_build(self, lab, kind, first_refusal):
        """An anchor the daemon still accepts leaves the live pair working: the endpoint DEPENDS on the damaged CA, and the existing sentence says so (a clientAuth-only CA). Q197 (AM6 e): the fake judges
        an anchor with the product's own ladder, so a tampered self-signature or a root without BasicConstraints is an anchor the endpoint no longer trusts - the live pair is rejected and Prepare is the way."""
        anchor = _recovery_world_under(kind)
        _add_external(lab, trust=anchor)
        lab.begin()
        before = _ca_bytes()
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        sentence = (
            TestRecoveryBesideAnExternal.PREPARE_SENTENCE
            if first_refusal == "prepare"
            else "accepts Jen's current client certificate and refuses the new one"
        )
        assert "Rotate refused" in texts and sentence in texts, texts
        assert lab.remote_actions() == 0 and _ca_bytes() == before
        lab.before = None
        _prepare()
        prepared_ca = pathlib.Path(kea_tls._staged_paths()["ca_cert"]).read_bytes()
        lab.hosts[3]["client_trust"] = anchor + prepared_ca.decode("ascii")
        lab.begin()
        lab.flashes.clear()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        for sid in lab.hosts:
            assert lab.answers_jens_configured_dial(sid)

    def test_a_probe_being_written_right_now_is_never_cleaned_up(self, lab):
        d = os.path.dirname(kea_tls.server_copy_path(1, "dhcp4"))
        fresh = pathlib.Path(d, f".write-probe-{os.getpid()}-aaaaaaaaaaaaaaaa")
        fresh.write_text("", encoding="ascii")  # another thread's in-flight probe: seconds old
        assert kea_tls.copies_dir_writable() == ""
        assert fresh.exists(), "only a leftover older than a minute is removed"
        fresh.unlink()


# ── Q196: the terminal check - a CA is healthy when the REAL verifier accepts what Jen issues from it, for both purposes ───────────────────────────


VERIFIER_WHY = {
    "eku-clientauth-only": "for sslserver",
    "eku-serverauth-only": "for sslclient",
    "eku-codesigning": "for sslserver",
    "name-constraints-exclude-all": "for sslserver",
    # Q197 (AM1 b): the EKU and AKI value families the daemon's library rejects and Q196's library alone did not
    "eku-anyeku": "for sslserver",
    "eku-anyeku-and-serverauth": "for sslclient",
    "eku-serverauth-and-codesigning": "for sslclient",
    "eku-unknown-oid": "for sslserver",
    "eku-anyeku-and-unknown": "for sslserver",
    "aki-wrong-serial": "authorityKeyIdentifier must contain keyIdentifier",
}


def _with_the_cli(monkeypatch):
    """Turn the `openssl` CLI ON for this test (the Lab has it off so a result never depends on the machine); skip - never xfail - where the machine has none (Q197)."""
    import shutil

    exe = shutil.which("openssl")
    if not exe:
        pytest.skip("no openssl CLI on this machine")
    monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: exe)
    kea_tls._ORACLE_VERDICTS.clear()
    kea_tls._GATE_VERDICTS.clear()
    return exe


def _openssl_accepts(cert, key, client):
    """What `openssl verify -purpose sslserver|sslclient` says about a throwaway leaf of this CA: True / False, None when there is no CLI (the cross-check is skipped there, never xfail)."""
    import shutil
    import subprocess
    import tempfile

    from cryptography.hazmat.primitives import serialization

    exe = shutil.which("openssl")
    if not exe:
        return None
    _message, leaf = kea_tls.verify_probe(cert, key, client)
    with tempfile.TemporaryDirectory() as d:
        ca, probe = os.path.join(d, "ca.pem"), os.path.join(d, "leaf.pem")
        pathlib.Path(ca).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        pathlib.Path(probe).write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        done = subprocess.run(  # nosec B603
            [exe, "verify", "-purpose", "sslclient" if client else "sslserver", "-CAfile", ca, probe],
            capture_output=True,
            text=True,
            check=False,
        )
    return done.returncode == 0


def _write_live_ca(kind):
    from tests import _tls_worlds as worlds

    cert_pem, key_pem = worlds.semantic_ca_pem(kind)
    crt, key = kea_tls.ca_paths()
    pathlib.Path(crt).write_bytes(cert_pem)
    pathlib.Path(key).write_bytes(key_pem)


class TestCaIdentityIsTheVerifier:
    """Q196 (AL1): since beta.19 the reviewer found, one release at a time, the next property of a certificate `ca_identity` did not check - the pair, the purpose, the Extended Key Usage. X.509 has dozens;
    the terminal check is the one the reviewer proves a finding with: a verifier. `ca_identity` now ends with `cryptography.x509.verification` over throwaway in-memory leaves of BOTH purposes, and the
    verifier's own message is the `why`. The profile is relaxed in three places only, where RFC 5280 allows and OpenSSL accepts (an absent KeyUsage, policyConstraints, inhibitAnyPolicy)."""

    def test_jens_own_ca_passes_the_oracle_and_the_oracle_writes_nothing(self, lab):
        from tests import _tls_worlds as worlds

        before = worlds.tree(kea_tls.SSL_DIR)
        assert kea_tls.ca_verifier_rejection(kea_tls._load_ca()[0], kea_tls._load_ca()[1]) == ""
        assert kea_tls.ca_identity(*kea_tls.ca_paths()) == ("ok", "")
        assert worlds.tree(kea_tls.SSL_DIR) == before, "nothing is written: the leaves exist only in memory"

    @pytest.mark.parametrize("kind", __import__("tests._tls_worlds", fromlist=["x"]).VERIFIER_OK_STATES)
    def test_a_ca_the_verifier_accepts_is_ok_and_openssl_agrees_except_where_it_is_known_not_to(
        self, lab, tmp_path, kind
    ):
        from tests import _tls_worlds as worlds

        cert, key = worlds.semantic_ca(kind)
        (tmp_path / "c.crt").write_bytes(kea_tls._cert_pem(cert))
        (tmp_path / "c.key").write_bytes(kea_tls._key_pem(key))
        assert kea_tls.ca_identity(str(tmp_path / "c.crt"), str(tmp_path / "c.key")) == ("ok", ""), kind
        for client in (False, True):
            theirs = _openssl_accepts(cert, key, client)
            if theirs is None:
                pytest.skip("no openssl CLI on this machine")
            # (Q197: no exception any more - anyExtendedKeyUsage ALONE is a damaged CA, so every CA Jen's verifier accepts is one openssl accepts)
            assert theirs is True, (
                f"{kind}: openssl verify rejects what Jen's verifier accepts ({'sslclient' if client else 'sslserver'})"
            )

    @pytest.mark.parametrize("kind", __import__("tests._tls_worlds", fromlist=["x"]).VERIFIER_CA_STATES)
    def test_a_ca_the_verifier_rejects_is_damaged_with_the_verifiers_own_message_and_openssl_agrees(
        self, lab, tmp_path, kind
    ):
        from tests import _tls_worlds as worlds

        cert, key = worlds.semantic_ca(kind)
        (tmp_path / "c.crt").write_bytes(kea_tls._cert_pem(cert))
        (tmp_path / "c.key").write_bytes(kea_tls._key_pem(key))
        state, why = kea_tls.ca_identity(str(tmp_path / "c.crt"), str(tmp_path / "c.key"))
        assert state == "damaged" and "the verifier rejects certificates issued from it" in why, (kind, why)
        assert VERIFIER_WHY[kind] in why, (kind, why)
        # the purposes the verifier rejects, openssl rejects too (where there is a CLI)
        for client, purpose in ((False, "sslserver"), (True, "sslclient")):
            ours_rejects = bool(kea_tls.verify_probe(cert, key, client)[0])
            theirs = _openssl_accepts(cert, key, client)
            if theirs is not None:
                assert theirs is (not ours_rejects), f"{kind} {purpose}: the two verifiers disagree"

    @pytest.mark.parametrize("kind", __import__("tests._tls_worlds", fromlist=["x"]).VERIFIER_CA_STATES)
    def test_a_live_ca_the_verifier_rejects_is_damaged_never_replaced_and_the_acknowledged_rotate_recovers(
        self, lab, kind
    ):
        _write_live_ca(kind)
        lab.begin()
        lab.before = None
        state, why = kea_tls.ca_state()
        assert state == "damaged" and VERIFIER_WHY[kind] in why, (kind, state, why)
        before = _ca_bytes()
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.ensure_ca()
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.issue_client_cert()
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.issue_server_cert({"id": 9, "name": "x", "ssh_host": "10.9.9.9"}, "dhcp4", "10.9.9.9", commit=False)
        assert _ca_bytes() == before, "T6/T7: nothing was replaced, nothing created"
        row = health._kea_tls_expiry({})
        assert row.status == "fail" and VERIFIER_WHY[kind] in row.detail and "the verifier rejects" in row.detail
        lab.begin()
        _rotate()
        assert "Jen's CA is damaged" in lab.texts() and _ca_bytes() == before and lab.remote_actions() == 0
        lab.flashes.clear()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert kea_tls.ca_state() == ("ok", "")
        for sid in lab.hosts:
            assert lab.answers_jens_live_identity(sid)

    @pytest.mark.parametrize("kind", __import__("tests._tls_worlds", fromlist=["x"]).VERIFIER_CA_STATES)
    def test_a_prepared_ca_the_verifier_rejects_is_refused_discarded_by_the_writer_and_never_installed(self, lab, kind):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from tests import _tls_worlds as worlds

        staged = worlds.stage_semantic_prepared(kind)
        invalid_cert = pathlib.Path(staged["ca_cert"]).read_bytes()
        found, note = kea_tls.prepared_rotation()
        assert found is None and "damaged or inconsistent" in note and VERIFIER_WHY[kind] in note, note
        assert all(os.path.lexists(p) for p in staged.values()), "a read left the files where they were"
        lab.begin()
        _rotate()
        assert "damaged or inconsistent" in lab.texts() and "Kea CA rotated" in lab.texts(), lab.texts()
        for sid, host in lab.hosts.items():
            installed = x509.load_pem_x509_certificate(host["files"]["ca.crt"].encode())
            assert installed.public_bytes(serialization.Encoding.PEM) != invalid_cert, (
                f"server {sid} got the rejected CA"
            )

    def test_a_name_constrained_ca_that_permits_its_own_domain_is_healthy_as_a_live_ca(self, lab):
        _write_live_ca("name-constraints-permit-own-domain")
        lab.begin()
        lab.before = None
        assert kea_tls.ca_state() == ("ok", ""), "probe names include a name the CA's own constraints permit"

    def test_the_oracle_does_not_depend_on_the_modules_clock(self, lab, monkeypatch):
        """The expired-pair test shifts `kea_tls._now` back 3000 days to mint an expired client certificate; the oracle's throwaway leaf is valid at the instant it is VERIFIED, whatever `_now` says."""
        import datetime

        real_now = kea_tls._now
        monkeypatch.setattr(kea_tls, "_now", lambda: real_now() - datetime.timedelta(days=3000))
        assert kea_tls.ca_state() == ("ok", "")

    def test_the_second_opinion_is_informational_and_only_where_jen_rejects_what_the_cli_accepts(
        self, lab, monkeypatch
    ):
        """Q197 (AM1/AM3): a CA both judges accept has NO opinion line; a CA the daemon's library REJECTS is damaged at the gate (`TestTheDaemonsVerifierJudges`), so the line exists only for the other direction - Jen
        stricter than the CLI (the admin guide's table). Compared with `ca_state`'s own verdict, never with the library probe alone."""
        import shutil

        if not shutil.which("openssl"):
            pytest.skip("no openssl CLI on this machine")
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: shutil.which("openssl"))
        assert kea_tls.ca_state() == ("ok", "")
        assert kea_tls.openssl_second_opinion() == "", "a healthy CA has no opinion line"
        _write_live_ca("aki-issuer-serial-only")  # executed: openssl accepts it, the library does not
        kea_tls._ORACLE_VERDICTS.clear()
        kea_tls._GATE_VERDICTS.clear()
        lab.begin()
        lab.before = None
        assert kea_tls.ca_state()[0] == "damaged"
        opinion = kea_tls.openssl_second_opinion()
        assert "openssl verify accepts" in opinion and "Jen is the stricter judge here" in opinion, opinion
        row = health._kea_tls_expiry({})
        assert row.status == "fail" and "openssl verify accepts" in row.detail, row.detail
        _write_live_ca("eku-anyeku")  # ... and a CA the CLI rejects too: Jen and the daemon agree, nothing to add
        kea_tls._ORACLE_VERDICTS.clear()
        kea_tls._GATE_VERDICTS.clear()
        assert kea_tls.ca_state()[0] == "damaged" and kea_tls.openssl_second_opinion() == ""

    def test_no_openssl_cli_is_no_row(self, lab, monkeypatch):
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: None)
        assert kea_tls.openssl_second_opinion() == ""


class TestOneDaemonOneTarget:
    """Q196 (AL2): one listener is one listener (Q187 AC5), and the rotation did not apply the rule: two records with the same SSH host and service are two targets whose installs land on the SAME fixed
    remote paths - the second over the first - with two local records that cannot both be the daemon's. The inventory refuses them before anything is staged; the route probes EVERY target once more
    with the staged identity after the last install, so each endpoint answers the FINAL material on its host."""

    @staticmethod
    def _servers(lab, ssh2, url2=None):
        lab.servers[2]["ssh_host"] = ssh2
        if url2 is not None:
            lab.urls[2] = url2
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        lab.begin()

    def test_two_ha_servers_on_distinct_hosts_rotate(self, lab):
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()

    def test_identical_ssh_host_service_and_url_is_refused_before_anything_changes(self, lab):
        self._servers(lab, lab.servers[1]["ssh_host"], url2=lab.urls[1])
        before = _ca_bytes()
        _rotate()
        texts = lab.texts()
        assert "Rotate refused" in texts and "both manage kea-dhcp4 on 10.0.0.5" in texts, texts
        assert "kea-a kea-dhcp4 and standby kea-dhcp4" in texts and "the second over the first" in texts
        assert lab.remote_actions() == 0 and _ca_bytes() == before

    def test_identical_ssh_host_and_service_with_different_api_aliases_is_refused_naming_both(self, lab):
        self._servers(lab, lab.servers[1]["ssh_host"], url2="https://alias.lan:8004")
        _rotate()
        assert "kea-a kea-dhcp4 and standby kea-dhcp4" in lab.texts() and lab.remote_actions() == 0, lab.texts()

    def test_two_spellings_of_one_host_that_same_host_equates_are_refused_and_the_sentence_says_the_operator_decides(
        self, lab
    ):
        self._servers(lab, "10.0.0.5", url2="https://10.0.0.5:8004")
        lab.servers[1]["ssh_host"] = "KEA-A"
        lab.servers[2]["ssh_host"] = "kea-a"
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        lab.begin()
        _rotate()
        assert "write the host differently" in lab.texts() and lab.remote_actions() == 0, lab.texts()

    def test_a_trailing_dot_is_a_different_name_to_same_host_so_it_is_two_targets(self):
        """Pinned: `kea-a` and `kea-a.` are NOT one host to `same_host` today (a dot is a different name - LESSONS); two names that resolve to one daemon are the operator's to keep apart."""
        from jen.services.auth import same_host

        assert same_host("kea-a", "kea-a.") is False and same_host("kea-a", "KEA-A") is True

    def test_dhcp4_and_dhcp6_on_one_host_are_two_daemons_and_two_targets(self, lab):
        a = {"id": 41, "name": "dual", "ssh_host": "10.9.9.9"}
        for service in ("dhcp4", "dhcp6"):
            kea_tls.issue_server_cert(a, service, "10.9.9.9")
        urls = {"dhcp4": "https://10.9.9.9:8004", "dhcp6": "https://10.9.9.9:8006"}
        inventory = kea_tls.rotation_inventory([a], url_for=lambda s, svc: urls.get(svc, ""), prove_storage=False)
        assert sorted(svc for _s, svc, _b in inventory.targets) == ["dhcp4", "dhcp6"], inventory
        assert not [r for r in inventory.refusals if "both manage" in r]

    def test_the_final_probe_of_every_target_failing_for_target_1_after_target_2_is_installed_rolls_back_and_says_so(
        self, lab, monkeypatch
    ):
        real = infra._probe_after_restart
        calls: dict = {}

        def probe(url, user, pwd, service, verify=None, cert=None):
            calls[url] = calls.get(url, 0) + 1
            if (
                url == lab.urls[1] and calls[url] == 2
            ):  # the first probe was right after its own install; this is the FINAL one
                return "", "the daemon stopped answering"
            return real(url, user, pwd, service, verify=verify, cert=cert)

        monkeypatch.setattr(infra, "_probe_after_restart", probe)
        before = _ca_bytes()
        _rotate()
        texts = lab.texts()
        assert "no longer answers once every target has its new certificates" in texts, texts
        assert "Kea CA rotated" not in texts and _ca_bytes() == before, "nothing was promoted"
        assert "Rolled back to the previous CA" in texts, texts
        assert lab.settings_writes == []


class TestTheSecondPassOfQ196:
    """The second pass on Q196 (agent a20701e5a2adbec0f, 0 P1 / 3 P2 / 6 P3), each finding as its row first: 1 an operator's CA the web-PKI profile rejected and OpenSSL accepts is healthy (the profile is
    relaxed where its API allows), and what stays stricter is pinned; 2 the openssl second opinion runs in BOTH directions; 3 the REAL leaf Jen issues - with its bind IP - is verified before it is
    returned (the oracle's DNS-only probe could not see an IP name constraint); 4 a leaf's AKI follows the CA's actual SKI; 5 an openssl binary that is broken or a temp directory that cannot be made is no
    opinion; 6 the oracle runs once per certificate and minute; 7/8 the sentences and the duplicate fallbacks."""

    SERVER = {"id": 9, "name": "probe-server", "ssh_host": "10.0.0.5"}

    @pytest.mark.parametrize("kind", __import__("tests._tls_worlds", fromlist=["x"]).VERIFIER_STRICTER_STATES)
    def test_row_1_what_the_verifier_is_stricter_about_than_openssl_is_pinned_as_damaged_not_surprising(
        self, lab, tmp_path, kind
    ):
        from tests import _tls_worlds as worlds

        cert, key = worlds.semantic_ca(kind)
        (tmp_path / "c.crt").write_bytes(kea_tls._cert_pem(cert))
        (tmp_path / "c.key").write_bytes(kea_tls._key_pem(key))
        state, why = kea_tls.ca_identity(str(tmp_path / "c.crt"), str(tmp_path / "c.key"))
        expected = {
            "name-constraints-leading-dot": "malformed DNS name constraint",
            "name-constraints-directory-name": "directoryName",
            "key-secp256k1": "Forbidden public key",
            "key-brainpool": "Forbidden public key",
            # Q197: the shapes OpenSSL accepts and the library does not, executed
            "aki-issuer-serial-only": "authorityKeyIdentifier must contain keyIdentifier",
            "crl-distribution-points-critical": "2.5.29.31",
            "empty-subject-critical-san": "non-empty Issuer",
            "policy-mappings-critical": "2.5.29.33",
        }[kind]
        assert state == "damaged" and "the verifier rejects" in why and expected in why, (kind, why)

    def test_row_1_an_eku_restriction_is_still_enforced_after_its_criticality_stopped_being_judged(self, lab):
        """Replacing the EKU rule with a no-op validator made a clientAuth-only CA verify for sslserver (executed): the criticality is relaxed, the PURPOSE is not."""
        from tests import _tls_worlds as worlds

        for kind, purpose in (("eku-clientauth-only", "sslserver"), ("eku-serverauth-only", "sslclient")):
            cert, key = worlds.semantic_ca(kind)
            assert purpose in kea_tls.ca_verifier_rejection(cert, key), kind
        cert, key = worlds.semantic_ca("eku-critical-server-and-client")
        assert kea_tls.ca_verifier_rejection(cert, key) == ""

    def test_row_2_the_second_opinion_also_runs_on_a_damaged_ca_and_says_when_openssl_accepts_what_the_verifier_rejects(
        self, lab, monkeypatch
    ):
        _with_the_cli(monkeypatch)
        _write_live_ca("key-secp256k1")
        lab.begin()
        lab.before = None
        assert kea_tls.ca_state()[0] == "damaged"
        cert, key = kea_tls._ca_material_for_opinion()
        openssl_accepts_something_the_verifier_rejects = any(
            _openssl_accepts(cert, key, client) is True and bool(kea_tls.verify_probe(cert, key, client)[0])
            for client in (False, True)
        )
        opinion = kea_tls.openssl_second_opinion()
        assert (opinion != "") is openssl_accepts_something_the_verifier_rejects, opinion
        row = health._kea_tls_expiry({})
        assert row.status == "fail" and ("openssl verify accepts" in row.detail) is bool(opinion), row.detail

    def test_row_3_a_ca_name_constrained_away_from_a_servers_address_passes_the_oracle_and_is_refused_at_issuing(
        self, lab
    ):
        import shutil
        import subprocess
        import tempfile

        _write_live_ca("name-constraints-ip-outside")
        lab.begin()
        lab.before = None
        assert kea_tls.ca_state() == ("ok", ""), "the oracle's DNS-only probe cannot see an IP constraint"
        with (
            pytest.raises(kea_tls.NameRefused) as refused
        ):  # Q197 (AM2): the CA is HEALTHY (the assertion above) and cannot issue for THIS name - not `CaDamaged`
            kea_tls.issue_server_cert(self.SERVER, "dhcp4", "10.0.0.5", commit=False)
        assert refused.value.names == ["10.0.0.5"] and refused.value.why, (refused.value.names, refused.value.why)
        _write_live_ca("name-constraints-ip-inside")
        files = kea_tls.issue_server_cert(self.SERVER, "dhcp4", "10.0.0.5", commit=False)
        exe = shutil.which("openssl")
        if exe:  # the REAL leaf, checked by openssl too
            with tempfile.TemporaryDirectory() as d:
                pathlib.Path(d, "ca.pem").write_text(files["ca.crt"], encoding="ascii")
                pathlib.Path(d, "leaf.pem").write_text(files["server.crt"], encoding="ascii")
                done = subprocess.run(  # nosec B603
                    [
                        exe,
                        "verify",
                        "-purpose",
                        "sslserver",
                        "-CAfile",
                        os.path.join(d, "ca.pem"),
                        os.path.join(d, "leaf.pem"),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            assert done.returncode == 0, done.stdout + done.stderr

    def test_row_3_the_rotation_says_the_ca_cannot_issue_for_a_server_and_has_touched_no_host(self, lab, monkeypatch):
        def refuse(*a, **k):
            raise kea_tls.CaDamaged("the CA cannot issue a certificate the verifier accepts for 10.0.0.5: boom")

        monkeypatch.setattr(kea_tls, "issue_server_cert", refuse)
        before = _ca_bytes()
        _rotate()
        assert (
            "the CA cannot issue its certificate (the CA cannot issue a certificate the verifier accepts" in lab.texts()
        )
        assert lab.remote_actions() == 0 and "Kea CA rotated" not in lab.texts() and _ca_bytes() == before

    def test_row_3_the_real_client_leaf_is_verified_too(self, lab):
        ca_cert, _ca_key = kea_tls._load_ca()
        pem, _key = kea_tls.client_paths()
        from cryptography import x509

        leaf = x509.load_pem_x509_certificate(pathlib.Path(pem).read_bytes())
        assert kea_tls.verify_issued(ca_cert, leaf, True) == "", (
            "Jen's own client certificate (no SAN) verifies under the relaxed client profile"
        )

    def test_row_4_a_leaf_names_the_cas_actual_ski_as_its_aki(self, lab):
        import shutil
        import subprocess
        import tempfile

        from cryptography import x509

        _write_live_ca("ski-not-sha1")
        lab.begin()
        lab.before = None
        ca_cert, _key = kea_tls._load_ca()
        files = kea_tls.issue_server_cert(self.SERVER, "dhcp4", "10.0.0.5", commit=False)
        leaf = x509.load_pem_x509_certificate(files["server.crt"].encode())
        aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        assert aki == ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        exe = shutil.which("openssl")
        if exe:
            with tempfile.TemporaryDirectory() as d:
                pathlib.Path(d, "ca.pem").write_text(files["ca.crt"], encoding="ascii")
                pathlib.Path(d, "leaf.pem").write_text(files["server.crt"], encoding="ascii")
                done = subprocess.run(  # nosec B603
                    [exe, "verify", "-CAfile", os.path.join(d, "ca.pem"), os.path.join(d, "leaf.pem")],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            assert done.returncode == 0, "openssl chains the leaf to a CA whose SKI is not the key's SHA-1"

    def test_row_5_a_broken_openssl_binary_is_no_opinion_not_a_disagreement(self, lab, monkeypatch):
        import subprocess

        monkeypatch.setattr(kea_tls.shutil, "which", lambda name: "/usr/bin/openssl")
        monkeypatch.setattr(
            kea_tls.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 127, "", "openssl: not found")
        )
        assert kea_tls.openssl_second_opinion() == ""

    def test_row_5_a_temp_directory_that_cannot_be_made_is_no_row_and_never_an_exception_through_health(
        self, lab, monkeypatch
    ):
        monkeypatch.setattr(kea_tls.shutil, "which", lambda name: "/usr/bin/openssl")

        def denied(*a, **k):
            raise PermissionError(13, "denied")

        monkeypatch.setattr(kea_tls.tempfile, "TemporaryDirectory", denied)
        assert kea_tls.openssl_second_opinion() == ""
        assert health._kea_tls_expiry({}).status in ("ok", "warn", "fail")

    def test_row_6_the_oracle_runs_once_per_certificate_and_minute(self, lab, monkeypatch):
        kea_tls._ORACLE_VERDICTS.clear()
        kea_tls._GATE_VERDICTS.clear()
        calls = []
        real = kea_tls.verify_probe
        monkeypatch.setattr(kea_tls, "verify_probe", lambda *a, **k: calls.append(1) or real(*a, **k))
        kea_tls.ca_state()
        first = len(calls)
        kea_tls.ca_state()
        kea_tls.ca_state()
        assert first == 2 and len(calls) == 2, "two purposes, once; the next calls are answered from the verdict"
        _write_live_ca("eku-clientauth-only")  # a changed certificate is judged afresh
        lab.begin()
        lab.before = None
        assert kea_tls.ca_state()[0] == "damaged" and len(calls) > 2

    def test_row_7_the_eku_sentence_is_plain_and_the_d2_label_is_the_daemons(self, lab):
        from tests import _tls_worlds as worlds

        cert, key = worlds.semantic_ca("eku-clientauth-only")
        assert "its Extended Key Usage does not name this purpose" in kea_tls.ca_verifier_rejection(cert, key)
        a = {"id": 51, "name": "ddns-a", "ssh_host": "10.9.9.9"}
        b = {"id": 52, "name": "ddns-b", "ssh_host": "10.9.9.9"}
        for server in (a, b):
            kea_tls.issue_server_cert(server, "d2", "10.9.9." + str(server["id"]))
        inventory = kea_tls.rotation_inventory(
            [a, b],
            url_for=lambda s, svc: f"https://10.9.9.{s['id']}:8003" if svc == "d2" else "",
            prove_storage=False,
        )
        assert any("both manage kea-dhcp-ddns on 10.9.9.9" in r for r in inventory.refusals), inventory.refusals

    def test_row_8_two_identical_ssh_host_strings_that_cannot_be_parsed_are_still_one_host(self, lab):
        hosts = "h\u200bost"  # a zero-width character: `same_host` cannot name a place, the string is identical
        a = {"id": 61, "name": "odd-a", "ssh_host": hosts}
        b = {"id": 62, "name": "odd-b", "ssh_host": hosts}
        for server in (a, b):
            kea_tls.issue_server_cert(server, "dhcp4", "10.9.9." + str(server["id"]))
        inventory = kea_tls.rotation_inventory(
            [a, b],
            url_for=lambda s, svc: f"https://10.9.9.{s['id']}:8004" if svc == "dhcp4" else "",
            prove_storage=False,
        )
        assert any("both manage" in r for r in inventory.refusals), inventory.refusals

    def test_the_probe_names_are_capped(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        key = kea_tls._new_key()
        name = kea_tls._name("many domains")
        now = kea_tls._now()
        import datetime

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.NameConstraints([x509.DNSName(f"d{i}.example.com") for i in range(40)], None), critical=True
            )
            .sign(key, hashes.SHA256())
        )
        assert len(kea_tls._probe_names(cert)) <= 8


# ── Q197: the daemon's own verifier judges at the GATE, not only in Health ────────────────────────────────────────────────────────────────────────


def _the_cli_says(lab, monkeypatch, ran):
    """A CLI that is on the box and answers `ran` (as `_run_openssl` returns it) - with the verdict caches empty and the Lab's invariants re-based on the world as it is now."""
    monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: "/usr/bin/openssl")
    monkeypatch.setattr(kea_tls, "_run_openssl", lambda args, timeout: ran)
    kea_tls._ORACLE_VERDICTS.clear()
    kea_tls._GATE_VERDICTS.clear()
    lab.begin()
    lab.before = None


def _install_ca_files(tmp_path, kind):
    """(certificate path, key path, certificate, key) of the CA in the world state `kind`, written under `tmp_path`."""
    from tests import _tls_worlds as worlds

    cert, key = worlds.semantic_ca(kind)
    crt, key_path = tmp_path / "c.crt", tmp_path / "c.key"
    crt.write_bytes(kea_tls._cert_pem(cert))
    key_path.write_bytes(kea_tls._key_pem(key))
    return str(crt), str(key_path), cert, key


#: what `openssl verify` prints for a leaf it rejects (executed, openssl 3.2.4), as `_run_openssl` returns it: (exit code, output)
_CLI_REJECTS = (
    2,
    "CN=probe\nerror 26 at 1 depth lookup: unsuitable certificate purpose\nerror probe.pem: verification failed\n",
)


class TestTheDaemonsVerifierJudges:
    """Q197 (AM1): the first pre-reviewer pass (two agents, ~1 400 cells) found two CA shapes Jen's library verifier called `ok` while BOTH real stacks rejected every leaf Jen issued from them: a CA whose
    EKU is `anyExtendedKeyUsage` alone, and a self-issued root whose AuthorityKeyIdentifier keyid is not its SubjectKeyIdentifier. Both are damaged now, and where the `openssl` CLI is on the Jen host
    it judges at the gate as the LAST step of `ca_identity` (a rejection is damaged with the CLI's own line; absent, broken or slow is no opinion). The live/prepared flows for the two shapes are the
    parametrized flows of `TestCaIdentity` (semantic: `aki-not-ski`) and `TestCaIdentityIsTheVerifier` (verifier: the `eku-*` and `aki-wrong-serial` value rows) - the states are in those lists."""

    CODED = ("eku-anyeku", "eku-anyeku-and-serverauth", "aki-not-ski", "aki-wrong-serial")

    def test_the_coded_divergences_are_rows_of_the_flows_that_drive_every_gate(self):
        from tests import _tls_worlds as worlds

        assert "aki-not-ski" in worlds.SEMANTIC_CA_STATES
        for kind in ("eku-anyeku", "eku-anyeku-and-serverauth", "eku-anyeku-and-unknown", "aki-wrong-serial"):
            assert kind in worlds.VERIFIER_CA_STATES, kind

    @pytest.mark.parametrize("kind", CODED)
    @pytest.mark.parametrize("cli", ["off", "on"])
    def test_a_ca_both_stacks_reject_is_damaged_with_or_without_the_cli(self, lab, tmp_path, monkeypatch, kind, cli):
        if cli == "on":
            _with_the_cli(monkeypatch)
        crt, key, _cert, _key = _install_ca_files(tmp_path, kind)
        state, why = kea_tls.ca_identity(crt, key)
        assert state == "damaged", (kind, cli, why)
        assert (CA_IDENTITY_WHY.get(kind) or VERIFIER_WHY[kind]) in why, (kind, why)

    @pytest.mark.parametrize("kind", CODED)
    def test_a_live_coded_ca_is_damaged_in_ca_state_and_health_names_it_and_issuing_refuses(self, lab, kind):
        _write_live_ca(kind)
        lab.begin()
        lab.before = None
        state, why = kea_tls.ca_state()
        assert state == "damaged", (kind, why)
        with pytest.raises(kea_tls.CaDamaged):
            kea_tls.issue_server_cert({"id": 9, "name": "x", "ssh_host": "10.9.9.9"}, "dhcp4", "10.9.9.9", commit=False)
        row = health._kea_tls_expiry({})
        assert row.status == "fail" and (CA_IDENTITY_WHY.get(kind) or VERIFIER_WHY[kind]) in row.detail, row.detail

    def test_the_control_ca_is_ok_under_both_judges(self, lab, monkeypatch):
        assert kea_tls.ca_state() == ("ok", "")
        _with_the_cli(monkeypatch)
        assert kea_tls.ca_state() == ("ok", "")

    # ── a CLI rejection of a CA the library accepted: pinned both ways ──

    def test_a_cli_rejection_is_damaged_with_the_clis_own_line(self, lab, monkeypatch):
        _the_cli_says(lab, monkeypatch, _CLI_REJECTS)
        state, why = kea_tls.ca_state()
        assert state == "damaged"
        assert (
            "the daemon's own library rejects certificates issued from it for sslserver: error 26 at 1 depth lookup: unsuitable certificate purpose"
            in why
        ), why
        row = health._kea_tls_expiry({})
        assert row.status == "fail" and "the daemon's own library rejects" in row.detail, row.detail

    def test_the_same_ca_is_ok_where_there_is_no_cli_and_the_register_says_which_judge_is_on_duty(
        self, lab, monkeypatch
    ):
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: None)
        monkeypatch.setattr(
            kea_tls, "_run_openssl", lambda args, timeout: pytest.fail("the CLI is never run where it is absent")
        )
        kea_tls._GATE_VERDICTS.clear()
        assert kea_tls.ca_state() == ("ok", "")
        guide = pathlib.Path("docs/admin-guide.md").read_text(encoding="utf-8")
        assert "which judge is on duty" in guide.lower() and "openssl" in guide

    def test_the_gate_cache_knows_whether_the_cli_existed(self, lab, monkeypatch):
        """The same certificate in the same minute is judged again when the CLI appears or disappears - a cached `ok` from before it was installed must not stand."""
        kea_tls._GATE_VERDICTS.clear()
        assert kea_tls.ca_state() == ("ok", "")
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: "/usr/bin/openssl")
        monkeypatch.setattr(kea_tls, "_run_openssl", lambda args, timeout: _CLI_REJECTS)
        lab.begin()
        lab.before = None
        assert kea_tls.ca_state()[0] == "damaged"

    @pytest.mark.parametrize(
        ("what", "ran"),
        [
            (
                "exit-127-missing-library",
                (127, "openssl: error while loading shared libraries: libssl.so.3: cannot open shared object file"),
            ),
            ("usage-message", (1, "Usage: verify [options] [cert...]")),
            ("an-exit-code-and-no-verdict", (3, "")),
            ("never-started-or-timed-out", None),
        ],
    )
    def test_a_cli_with_no_verdict_is_no_opinion_and_the_librarys_verdict_stands(self, lab, monkeypatch, what, ran):
        _the_cli_says(lab, monkeypatch, ran)
        assert kea_tls.ca_state() == ("ok", ""), what
        assert kea_tls.openssl_second_opinion() == ""

    def test_a_cli_that_accepts_changes_nothing(self, lab, monkeypatch):
        _the_cli_says(lab, monkeypatch, (0, "probe.pem: OK\n"))
        assert kea_tls.ca_state() == ("ok", "")

    def test_the_cli_is_looked_up_in_one_place(self, monkeypatch):
        monkeypatch.setattr(kea_tls.shutil, "which", lambda name: "/opt/ssl/bin/openssl")
        assert kea_tls._openssl_exe() == "/opt/ssl/bin/openssl"
        monkeypatch.setattr(kea_tls.shutil, "which", lambda name: None)
        assert kea_tls._openssl_exe() is None


_ALL_VALUE_STATES = [
    state
    for states in __import__("tests._tls_worlds", fromlist=["x"]).EXTENSION_VALUE_FAMILIES.values()
    for state in states
]


class TestTheValueFamiliesAgainstTheRealCli:
    """Q197 (AM1, the enumeration rule): every VALUE family of every extension class a CA certificate carries (`_tls_worlds.EXTENSION_VALUE_FAMILIES`) is a CA that Jen judges and, where the CLI exists,
    that the CLI judges - and the property that matters is one-directional: **a CA Jen calls healthy is never one the CLI rejects**. Where Jen is the stricter judge the row is in the documented table
    (`JEN_STRICTER_THAN_OPENSSL`, the admin guide's), so a new disagreement is a failing test, not a surprise."""

    @pytest.mark.parametrize("kind", _ALL_VALUE_STATES)
    def test_a_ca_jen_calls_healthy_is_never_one_the_cli_rejects(self, lab, tmp_path, monkeypatch, kind):
        from tests import _tls_worlds as worlds

        _with_the_cli(monkeypatch)
        crt, key, cert, private = _install_ca_files(tmp_path, kind)
        monkeypatch.setattr(
            kea_tls, "_openssl_exe", lambda: None
        )  # the LIBRARY's own verdict, to compare with the CLI's
        kea_tls._GATE_VERDICTS.clear()
        state, _why = kea_tls.ca_identity(crt, key)
        verdicts = []
        for client in (False, True):
            _message, leaf = kea_tls.verify_probe(cert, private, client)
            if leaf is None:
                continue
            verdicts.append(_openssl_accepts(cert, private, client))
        if state == "ok":
            assert verdicts and all(v is True for v in verdicts), (
                f"{kind}: Jen calls it healthy and openssl rejects a leaf"
            )
        elif verdicts and all(v is True for v in verdicts):
            assert kind in worlds.JEN_STRICTER_THAN_OPENSSL, (
                f"{kind}: Jen is the stricter judge here and the admin guide's table does not list it"
            )
        else:
            assert kind not in worlds.JEN_STRICTER_THAN_OPENSSL, (
                f"{kind} is listed as Jen-stricter and openssl rejects it too"
            )

    def test_the_stricter_table_is_documented_in_the_admin_guide(self):
        from tests import _tls_worlds as worlds

        guide = pathlib.Path("docs/admin-guide.md").read_text(encoding="utf-8")
        assert "Shapes Jen's verifier is stricter about than OpenSSL" in guide
        for kind in worlds.JEN_STRICTER_THAN_OPENSSL:
            assert worlds.STRICTER_LABELS[kind] in guide, f"the admin guide's table has no row for {kind}"


class TestTheCliGateIsBounded:
    """Q197 (AM3): a verdict exists only when the output carries one, and a child that hangs cannot hold Health - the wrapper's grandchild included."""

    @pytest.mark.parametrize(
        ("ran", "expected"),
        [
            ((0, "probe.pem: OK\n"), (True, "")),
            ((0, "probe.pem: OK\nsomething else\n"), (True, "")),
            (_CLI_REJECTS, (False, "error 26 at 1 depth lookup: unsuitable certificate purpose")),
            ((2, "error probe.pem: verification failed\n"), (False, "verification failed")),
            (
                (20, "error 20 at 0 depth lookup: unable to get local issuer certificate\n"),
                (False, "error 20 at 0 depth lookup: unable to get local issuer certificate"),
            ),
            ((127, "openssl: error while loading shared libraries: libssl.so.3"), (None, "")),
            ((1, "Usage: verify [options]"), (None, "")),
            ((0, "no verdict at all"), (None, "")),
            ((2, ""), (None, "")),
            (None, (None, "")),
        ],
    )
    def test_the_verdict_parser_table(self, ran, expected):
        assert kea_tls._openssl_verdict(ran) == expected

    def test_a_real_binary_that_is_not_openssl_is_no_opinion(self, monkeypatch):
        """A real subprocess: the Python interpreter standing in for a broken `openssl` - it exits non-zero with a usage error and no verify verdict."""
        import sys

        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: sys.executable)
        ran = kea_tls._run_openssl(["verify", "-purpose", "sslserver"], 10.0)
        assert ran is not None and ran[0] != 0
        assert kea_tls._openssl_verdict(ran) == (None, "")

    def test_a_binary_that_cannot_be_started_is_no_opinion(self, monkeypatch, tmp_path):
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: str(tmp_path / "does-not-exist"))
        assert kea_tls._run_openssl(["verify"], 5.0) is None

    @pytest.mark.skipif(
        os.name == "nt", reason="process groups: Jen runs on Linux only (a job object is registered, out of scope)"
    )
    def test_a_wrapper_that_leaves_a_grandchild_is_killed_as_a_group_at_the_timeout(self, monkeypatch, tmp_path):
        pidfile = tmp_path / "grandchild.pid"
        script = tmp_path / "openssl"
        script.write_text(f"#!/bin/sh\nsleep 60 &\necho $! > {pidfile}\nsleep 60\n", encoding="ascii")
        script.chmod(0o755)
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: str(script))
        started = time.monotonic()
        assert kea_tls._run_openssl(["verify"], 1.0) is None, "a child that does not finish is NO opinion"
        assert time.monotonic() - started < 15, "the timeout bounds the child AND its group"
        grandchild = int(pidfile.read_text().strip())
        deadline = time.monotonic() + 5
        gone = False
        while time.monotonic() < deadline:
            try:
                os.kill(grandchild, 0)
            except ProcessLookupError:
                gone = True
                break
            time.sleep(0.1)
        assert gone, "the grandchild survived the timeout"

    def test_the_cli_runs_with_auth_level_2_so_it_and_the_daemon_agree_on_key_strength(self, lab, monkeypatch):
        seen = []
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: "/usr/bin/openssl")
        monkeypatch.setattr(kea_tls, "_run_openssl", lambda args, timeout: seen.append(list(args)) or (0, "x: OK"))
        kea_tls._GATE_VERDICTS.clear()
        assert kea_tls.ca_state() == ("ok", "")
        assert seen and all(
            a[a.index("-auth_level") : a.index("-auth_level") + 2] == ["-auth_level", "2"] for a in seen
        ), seen
        assert {a[a.index("-purpose") + 1] for a in seen} == {"sslserver", "sslclient"}

    def test_the_second_opinion_compares_with_jens_verdict_not_with_the_probe_alone(self, lab, monkeypatch):
        """The disagreement line exists only for a CA Jen has judged DAMAGED - a `damaged` row never says "Jen accepts" (the first pass's finding 5)."""
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: "/usr/bin/openssl")
        monkeypatch.setattr(kea_tls, "_run_openssl", lambda args, timeout: (0, "x: OK"))
        assert kea_tls.ca_state() == ("ok", "")
        assert kea_tls.openssl_second_opinion() == "", "an ok CA has no opinion line, whatever the CLI says"
        _write_live_ca("aki-issuer-serial-only")
        kea_tls._ORACLE_VERDICTS.clear()
        kea_tls._GATE_VERDICTS.clear()
        lab.begin()
        lab.before = None
        assert kea_tls.ca_state()[0] == "damaged"
        assert "Jen is the stricter judge here" in kea_tls.openssl_second_opinion()


class TestTheStaleRecords:
    """Q197 (AM4): a copy whose endpoint is not an https endpoint now is a record of nothing. Health does not count it as a valid (or an expiring) certificate and says it is stale; Rotate already ignores it; a removed
    socket drops its record; and a superadmin can forget the rest in one click (a local change - no host is asked anything)."""

    GONE = {"id": 77, "name": "retired-kea", "ssh_host": "10.7.7.7"}

    def _stale_copy(self):
        """A certificate for a server that is not an https endpoint now, issued 3000 days ago (so it is long expired): built directly, because `issue_server_cert` verifies the leaf it returns at the real
        time and would refuse an expired one."""
        import datetime

        ca_cert, ca_key = kea_tls._load_ca()
        key = kea_tls._new_key()
        leaf = kea_tls._leaf(
            ca_cert,
            ca_key,
            key,
            "kea-dhcp4 retired",
            [kea_tls._san_for("10.7.7.7")],
            client=False,
            now=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(days=3000),
        )
        kea_tls.commit_issued(
            self.GONE["id"],
            "dhcp4",
            {
                "ca.crt": kea_tls._cert_pem(ca_cert).decode(),
                "server.crt": kea_tls._cert_pem(leaf).decode(),
                "server.key": kea_tls._key_pem(key).decode(),
            },
        )

    def test_an_expired_copy_for_a_server_that_is_no_longer_https_is_named_stale_not_counted(self, lab):
        self._stale_copy()
        lab.begin()
        lab.before = None
        inventory = kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False)
        assert "77-dhcp4" in inventory.stale
        row = health._kea_tls_expiry({})
        assert (
            "stale record for server 77 kea-dhcp4 (its endpoint is no longer https): Rotate ignores it" in row.detail
        ), row.detail
        assert "remove the socket's record under Settings → Kea" in row.detail
        assert "2 server certificate(s) valid" in row.detail, "the stale copy is not counted as a valid certificate"
        assert row.status != "fail" or "expired" not in row.detail, "a stale record's expiry is not a warning"

    def test_rotate_ignores_it(self, lab):
        self._stale_copy()
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert not any(i[0] == 77 for i in lab.incidents)

    def test_forgetting_clears_it_and_asks_no_host_anything(self, lab):
        self._stale_copy()
        lab.begin()
        before_calls = {sid: dict(h["calls"]) for sid, h in lab.hosts.items()}
        forgotten = kea_tls.forget_stale_records(extensions.KEA_SERVERS)
        lab.before = None  # (a direct call to the module is not a request: T5 is about requests)
        assert forgotten == ["77-dhcp4"]
        assert not os.path.lexists(kea_tls.server_copy_path(77, "dhcp4")), "the record is gone"
        assert {sid: dict(h["calls"]) for sid, h in lab.hosts.items()} == before_calls, "no host was asked anything"
        assert kea_tls.forget_stale_records(extensions.KEA_SERVERS) == []
        assert "stale record" not in health._kea_tls_expiry({}).detail

    def test_a_live_https_endpoint_is_never_forgotten(self, lab):
        self._stale_copy()
        forgotten = kea_tls.forget_stale_records(extensions.KEA_SERVERS)
        lab.before = None
        assert forgotten == ["77-dhcp4"]
        for sid in lab.servers:
            assert os.path.lexists(kea_tls.server_copy_path(sid, "dhcp4")), f"server {sid}'s record is untouched"

    def test_the_forget_route_is_local_audited_and_says_what_it_forgot(self, lab, monkeypatch):
        self._stale_copy()
        audits = []
        monkeypatch.setattr(infra.__dict__["__user"], "audit", lambda *a, **k: audits.append(a))
        app = flask.Flask(__name__)
        app.secret_key = "x"
        monkeypatch.setattr(infra, "url_for", lambda *a, **k: "/settings/kea")
        monkeypatch.setattr(infra, "flash", lambda text, style="message": lab.flashes.append((style, str(text))))
        with app.test_request_context(method="POST"):
            inspect.unwrap(infra.forget_stale_kea_records)()
        assert "Forgot Jen's own copy of 1 certificate" in lab.texts() and "77-dhcp4" in lab.texts()
        assert "Nothing was changed on any host" in lab.texts()
        assert any(a[0] == "FORGET_STALE_KEA_RECORDS" for a in audits)
        lab.flashes.clear()
        with app.test_request_context(method="POST"):
            inspect.unwrap(infra.forget_stale_kea_records)()
        assert "There were no stale certificate records." in lab.texts()

    def test_the_settings_page_summary_lists_the_stale_records_and_the_template_has_the_button(self, lab):
        self._stale_copy()
        summary = infra._kea_ca_summary()
        assert summary["stale"] == ["server 77 kea-dhcp4"], summary
        template = pathlib.Path("templates/settings_kea.html").read_text(encoding="utf-8")
        assert "/settings/infrastructure/kea-ca/forget-stale" in template and "Forget stale records" in template

    def test_the_page_prints_expiry_unreadable_not_a_none_of_days(self):
        template = pathlib.Path("templates/settings_kea.html").read_text(encoding="utf-8")
        assert "kea_ca.days_left is none" in template and "expiry unreadable" in template
        assert "{% if d is none %}expiry unreadable{% else %}{{ d }} d{% endif %}" in template


class TestHygieneOfQ197:
    """Q197 (AM6 b, c, e): the staged `.next` set leaves no `.prev` key copy; every directory under the SSL dir is 0700; the Lab fake judges an anchor with the product's own ladder."""

    def test_staging_a_rotation_makes_no_next_prev_key_copy_and_one_set_of_four(self, lab):
        staged = kea_tls.stage_rotation()
        names = sorted(os.listdir(kea_tls.SSL_DIR))
        assert not any(n.endswith(".next.prev") for n in names), names
        assert sum(n.endswith(".next") for n in names) == 4, names
        kea_tls.discard_rotation(staged)
        assert not any(".next" in n for n in os.listdir(kea_tls.SSL_DIR))

    def test_a_restaged_rotation_does_not_keep_the_earlier_key_either(self, lab):
        kea_tls.stage_rotation()
        kea_tls.discard_rotation(kea_tls.stage_rotation())
        assert not any(".next" in n for n in os.listdir(kea_tls.SSL_DIR)), os.listdir(kea_tls.SSL_DIR)

    def test_a_next_file_beside_nothing_is_evidence_that_a_ca_existed(self, lab):
        for name in os.listdir(kea_tls.SSL_DIR):
            path = os.path.join(kea_tls.SSL_DIR, name)
            if os.path.isfile(path) and not name.endswith(".next"):
                os.unlink(path)
        shutil_rmtree = __import__("shutil").rmtree
        shutil_rmtree(kea_tls._copies_dir(), ignore_errors=True)
        pathlib.Path(kea_tls.ca_paths()[1] + ".next.prev").write_bytes(b"an old staged key")
        lab.begin()
        lab.before = None
        assert "a CA existed" in kea_tls._initialised_evidence()

    @pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
    def test_a_directory_made_under_the_ssl_dir_is_private_by_default(self, tmp_path):
        target = tmp_path / "made-by-ensure-dir"
        kea_tls._ensure_dir(str(target))
        assert (target.stat().st_mode & 0o777) == 0o700

    def test_the_default_mode_of_ensure_dir_is_0700(self):
        assert inspect.signature(kea_tls._ensure_dir).parameters["mode"].default == 0o700

    def test_the_fake_daemon_judges_an_anchor_with_the_products_own_ladder(self):
        source = inspect.getsource(_anchor_usable)
        assert "ca_identity(" in source and "cert_only=True" in source, "the fake and the product share one judgment"

    def test_ca_identity_cert_only_needs_no_key_and_runs_no_oracle(self, tmp_path, monkeypatch):
        crt, _key, _cert, _private = _install_ca_files(tmp_path, "eku-clientauth-only")
        monkeypatch.setattr(kea_tls, "ca_gate_rejection", lambda *a, **k: pytest.fail("cert_only runs no oracle"))
        assert kea_tls.ca_identity(crt, None, cert_only=True) == ("ok", ""), "the structural ladder alone"
        crt, _key, _cert, _private = _install_ca_files(tmp_path, "aki-not-ski")
        assert kea_tls.ca_identity(crt, None, cert_only=True)[0] == "damaged"


class TestTheNameWorldsOfRotate:
    """Q197 (AM2): a saved https address whose host the verifier cannot name (an underscore) is a NAME refusal in Rotate: the CA is healthy, the sentence names the host, and no acknowledgement is asked for."""

    def test_a_saved_https_host_the_verifier_cannot_name_stops_the_rotation_and_leaves_every_host_on_the_old_ca(
        self, lab
    ):
        lab.urls[2] = "https://kea_host:8004"
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        lab.begin()
        _rotate()
        texts = lab.texts()
        assert "the CA cannot issue its certificate for kea_host" in texts, texts
        assert "Kea CA rotated" not in texts
        assert "acknowledg" not in texts.lower(), "a healthy CA is never sent to the damaged-CA acknowledgement"
        assert kea_tls.ca_state() == ("ok", "")
        for sid, host in lab.hosts.items():
            assert host["files"] is None or lab.answers(sid, kea_tls.ca_paths()[0]), (
                f"server {sid} still answers on the old CA"
            )
