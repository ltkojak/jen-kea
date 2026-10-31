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
import ipaddress
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
    "tls-superseded",  # Q199 (AO1): a parked daemon the rotation left on the replaced CA
    "record-forgotten",  # Q199 (AO1): a record forgotten on the operator's word
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
        # Q201 (AQ6 a): the Lab routes a helper call by MACHINE, not by server id. `machine_addr` is the SSH address of the machine each `hosts` entry IS; a server whose `ssh_host` is changed reaches the
        # machine that address names (`machine_for`), or a THIRD machine (`third_machines`) when it names none the Lab has - so "the helper installed on the wrong machine" is OBSERVED.
        self.machine_addr = {sid: s.get("ssh_host") for sid, s in SERVERS.items()}
        self.third_machines = {}
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
        self.incident_extra = {}  # (server id, service, category) -> {"server_name", "ca_fingerprint"}: what a `recovery_incidents` row carries beyond the tuple (Q201 second pass)
        self.settings_error = None
        self.ca_a = None  # bytes of the CA Jen trusts before the rotation
        self.caplog = None
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

    def hold_certificate_naming(self, sid, names):
        """Q200 (AP1): a record - and the daemon that has loaded it - whose certificate names `names` even though today's verifier would refuse to ISSUE one for them (the world is a CA that was
        constrained after the record was made, or a hand-kept address). The destination check passes (the certificate names the host), so the rotation reaches the re-issue and meets the NAME refusal."""
        ca_cert, ca_key = kea_tls._load_ca()
        key = kea_tls._new_key()
        sans = [s for s in (kea_tls._san_for(n) for n in names) if s is not None]
        cert = kea_tls._leaf(ca_cert, ca_key, key, "kea-dhcp4 held", sans, client=False)
        files = {
            "ca.crt": kea_tls._cert_pem(ca_cert).decode(),
            "server.crt": kea_tls._cert_pem(cert).decode(),
            "server.key": kea_tls._key_pem(key).decode(),
        }
        kea_tls.commit_issued(sid, "dhcp4", files)
        self.hosts[sid]["files"] = self.hosts[sid]["loaded"] = copy.deepcopy(files)
        self.answered_before[sid] = self.answers_jens_live_identity(sid)

    def machine_for(self, server):
        """The machine the helper reaches for this server record RIGHT NOW: the Lab host whose SSH address `same_host` equates with the record's `ssh_host`, else a third machine for that address."""
        from jen.services.auth import same_host

        ssh = (server.get("ssh_host") or "").strip()
        for sid, origin in self.machine_addr.items():
            if origin and ssh and (origin == ssh or same_host(origin, ssh)):
                return self.hosts[sid]
        return self.third_machines.setdefault(
            ssh, {"files": None, "loaded": None, "installs": [], "restarts": 0, "calls": {}}
        )

    def machines(self) -> dict:
        """Every machine the Lab has, third machines included - 'both machines byte-equal' is this before == after."""
        return {
            **self.hosts,
            **{f"third:{a}": h for a, h in self.third_machines.items()},
        }

    def add_server(self, sid, name, ssh_host, url, *, jen_issued=True, ca=None, password=None):
        """A server the rotation can see: configured, with a daemon that has loaded a certificate. `jen_issued` False is an administrator-managed endpoint (a certificate Jen's CA did not issue);
        a `password` is a secret the Lab configured, so T4 looks for it."""
        server = {"id": sid, "name": name, "ssh_host": ssh_host}
        self.servers[sid] = server
        self.urls[sid] = url
        self.hosts[sid] = {"files": None, "loaded": None, "installs": [], "restarts": 0, "calls": {}}
        self.machine_addr[sid] = ssh_host
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
        return sum(h["calls"].get("install-tls", 0) + h["calls"].get("service", 0) for h in self.machines().values())

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
                        self._named(sid, ("tls-local-stale", "remote-unknown", "tls-not-restored", "record-forgotten"))
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
                if state in kea_tls.JEN_STATES:
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
            if succeeded and self.jen_issued(sid) and not now and not self._named(sid, ("tls-superseded",)):
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
def lab_world(monkeypatch, tmp_path, caplog):
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
        host = lab.machine_for(server)  # (Q201 AQ6 a: by MACHINE - the SSH address the record names now)
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
        if category == "rotation-pending":
            # (Q202 AR1: the product's choke point - a note is refreshed only under the fingerprint it was written with)
            for sid, s, c in lab.incidents:
                if (str(sid), s, c) == (str(server_id), service, category):
                    stored = lab.incident_extra.get((sid, s, c), {}).get("ca_fingerprint", "")
                    if stored not in ("", kw.get("ca_fingerprint", "")):
                        return False
        lab.incidents[:] = [
            i for i in lab.incidents if not (str(i[0]) == str(server_id) and i[1] == service and i[2] == category)
        ]
        lab.incidents.append((server_id, service, category))
        lab.incident_extra[(server_id, service, category)] = {
            "server_name": kw.get("server_name", ""),
            "ca_fingerprint": kw.get("ca_fingerprint", ""),
        }
        lab.incident_records.append(
            (server_id, service, operation, category, kw.get("server_name", ""), kw.get("detail", ""))
        )
        return True

    def recovery_incidents(strict=False):
        return [
            {"kind": "attention", "category": c, "status": c, "service": s, "server_id": sid}
            | lab.incident_extra.get((sid, s, c), {})
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


@pytest.fixture
def lab(lab_world):
    """The Lab, with the invariants (T1-T5) checked after EVERY test in this file (AE0). Q199 (AO1): there is NO way to ask this fixture to tolerate a violation - it used to carry an
    `expected_violations` set a test could fill, and a test did (it removed the parked daemon from the world, or declared T1 expected, so a relative invariant would pass). A world that must break an
    invariant on purpose is a `TestTheInvariantsBite` class, whose own `lab` fixture is the bare world and whose tests assert `_bites(lab, "T3")` themselves; a world that SHOULD hold an invariant
    gets the durable product fact (an incident) that makes it hold."""
    yield lab_world
    found = lab_world.check_invariants()
    assert not found, f"INVARIANT(S) BROKEN at the end of the test: {found}"


def _bites(lab, *names):
    """The invariants named are violated NOW - the biting tests' own assertion (their `lab` fixture does not check at teardown)."""
    found = lab.check_invariants()
    seen = {name for name, _what in found}
    assert set(names) <= seen, (
        f"the invariant check should have named {sorted(names)} (it found {sorted(seen)}): {found}"
    )
    return found


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

    @pytest.fixture
    def lab(self, lab_world):
        """The bare world: every test here breaks the product on purpose and asserts the invariant it breaks itself (`_bites`) - this class's `lab` does not check at teardown."""
        yield lab_world

    def test_T1_bites_when_the_record_is_made_the_way_beta19_made_it(self, lab, monkeypatch):
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
        _bites(lab, "T1")

    def test_T2_bites_when_a_split_ca_is_not_said(self, lab, monkeypatch):

        def half(staged):
            pathlib.Path(kea_tls.ca_paths()[0]).write_bytes(pathlib.Path(staged["ca_cert"]).read_bytes())
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(kea_tls, "commit_rotation", half)
        monkeypatch.setattr(kea_changeset, "record_attention", lambda *a, **k: True)  # the incidents are lost
        monkeypatch.setattr(infra, "flash", lambda text, style="message": None)  # ... and so is the sentence
        _rotate()
        assert not kea_tls.ca_consistent()
        _bites(lab, "T2")

    def test_T3_bites_when_the_rotation_forgets_an_endpoint(self, lab, monkeypatch):
        """The beta.19 defect itself: the targets came from a listing of local files, an unlistable one read as empty, the rotation 'succeeded', and every daemon still presented CA-A material."""
        monkeypatch.setattr(
            kea_tls,
            "rotation_inventory",
            lambda servers, url_for=None, **kw: kea_tls.RotationInventory([], [], [], [], frozenset()),
        )
        _rotate()
        assert "Kea CA rotated" in lab.texts(), "the rotation reported success"
        _bites(lab, "T3")

    def test_T4_bites_when_a_key_reaches_a_sentence(self, lab, monkeypatch):
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
        _bites(lab, "T4")

    def test_T5_bites_when_a_refusal_leaves_a_file_behind(self, lab, monkeypatch):
        real = kea_tls.rotation_inventory

        def refusing_after_writing(servers, url_for=None, **kw):
            (pathlib.Path(kea_tls.SSL_DIR) / "stray-file").write_text("left behind", encoding="ascii")
            inv = real(servers, url_for=url_for, **kw)
            inv.refusals.append("refused on purpose")
            return inv

        monkeypatch.setattr(kea_tls, "rotation_inventory", refusing_after_writing)
        _rotate()
        assert "Rotate refused" in lab.texts()
        _bites(lab, "T5")


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

    @pytest.fixture
    def lab(self, lab_world):
        """The bare world: every test here breaks the product on purpose and asserts the invariant it breaks itself (`_bites`) - this class's `lab` does not check at teardown."""
        yield lab_world

    def test_T3_bites_when_a_daemon_that_answered_stops_answering_and_nothing_names_it(self, lab, monkeypatch):
        """Monkeypatch the route to skip the probe, and make one daemon ignore its restart: the rotation reports success, promotes the new CA, and a daemon Jen answered before is left on the old one."""
        lab.stuck_restart.add(2)
        monkeypatch.setattr(infra, "_probe_after_restart", lambda *a, **k: ("Kea 3.0.3", None))
        _rotate()
        assert "Kea CA rotated" in lab.texts()
        assert lab.answered_before[2] and not lab.answers_jens_live_identity(2)
        _bites(lab, "T3")

    def test_T3_bites_on_the_configured_dial_when_the_bundle_jen_verifies_against_holds_the_old_ca(
        self, lab, monkeypatch, tmp_path
    ):
        """The second pass's cut-off: the daemon answers Jen's LIVE identity but Jen is configured to verify against a copy of the OLD CA - Jen is cut off, and no incident says so."""
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
        _bites(lab, "T3")

    def test_T1_bites_when_an_action_silently_loses_a_record_it_had(self, lab, monkeypatch):
        """Q192 (adjusted: T1 is RELATIVE now - a world that STARTS without a record is the input and Health says so). Judged by the HOST's certificate: the daemon runs a pair a Jen CA issued, Jen
        HAD a record of it, and the action ends with the files gone and nothing - no request text, no incident, no marker - saying so."""
        real = kea_tls.retire_previous

        def retire_and_lose(server_id, service):
            real(server_id, service)
            _drop_jens_record(server_id)  # the product loses the record it had, silently

        monkeypatch.setattr(kea_tls, "retire_previous", retire_and_lose)
        _rotate()
        assert "Kea CA rotated" in lab.texts()
        _bites(lab, "T1")


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
    @pytest.fixture
    def lab(self, lab_world):
        """The bare world: every test here breaks the product on purpose and asserts the invariant it breaks itself (`_bites`) - this class's `lab` does not check at teardown."""
        yield lab_world

    def test_T3_bites_on_the_P1_world_when_the_client_refusal_is_monkeypatched_away(self, lab, monkeypatch, tmp_path):
        """The pass's C1X, now a shipped test: client pair a COPY, bundle an alias - with the refusal removed the rotation promotes a new CA and client pair, every daemon demands a certificate from the
        new CA, Jen keeps dialling with the old copy, and the teardown names it."""
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
        _bites(lab, "T3")


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
    @pytest.fixture
    def lab(self, lab_world):
        """The bare world: every test here breaks the product on purpose and asserts the invariant it breaks itself (`_bites`) - this class's `lab` does not check at teardown."""
        yield lab_world

    def test_T3_bites_when_the_staged_identity_check_is_monkeypatched_away(self, lab, monkeypatch):
        """The P1 world with the new check removed: the rotation promotes CA-B, the external daemon still trusts only CA-A for clients, and Jen keeps presenting CA-B pairs - the teardown names it."""
        _add_external(lab, trust=_ca_pem())
        monkeypatch.setattr(infra, "_staged_identity_refusal", lambda *a, **k: "")
        lab.begin()
        _rotate()
        assert "Kea CA rotated" in lab.texts(), "the rotation reported success"
        assert lab.dial_before[3] and not lab.answers_jens_configured_dial(3)
        _bites(lab, "T3")


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
    "aki-wrong-serial": "AuthorityKeyIdentifier does not name its own issuer and serial number",
    "aki-issuer-other-name": "AuthorityKeyIdentifier does not name its own issuer and serial number",
    "aki-keyid-wrong-serial": "AuthorityKeyIdentifier does not name its own issuer and serial number",
    "aki-two-dirnames-wrong-first": "AuthorityKeyIdentifier does not name its own issuer and serial number",
    "aki-dns-first-wrong-dirname": "AuthorityKeyIdentifier does not name its own issuer and serial number",
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
        # (Q199 AO7) the operator re-pointed server 2 at another host: the setup for THAT host issued it a pair for it - the record is the new destination's, so only the duplicate-daemon rule is in play
        host_of_url = urlparse_host(lab.urls[2])
        if kea_tls._is_ip_literal(host_of_url):
            kea_tls.issue_server_cert(lab.servers[2], "dhcp4", host_of_url)
        else:
            lab.hold_certificate_naming(
                2, [host_of_url, ssh2]
            )  # (Q202 AR9 c: a bind is an address; the name the URL carries is the certificate's other name)
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
        # (Q200: a record is the daemon's only when the certificate names the SSH host - so both records are issued afresh for the spellings under test, as the setup would)
        kea_tls.issue_server_cert(lab.servers[1], "dhcp4", "10.0.0.5")
        kea_tls.issue_server_cert(lab.servers[2], "dhcp4", "10.0.0.5")
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
            "aki-all-none": "authorityKeyIdentifier must contain keyIdentifier",
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
        """Rebuilt again (Q204 AT5 b). Q201 AQ6 d built this with a certificate that NAMED the odd host (an ASCII name with a control character, "which a certificate CAN carry"). A certificate's DNS names
        are now the verifier's parser's names, and the parser refuses a control character: no certificate Jen reads names such a host, so the rule is asked of the rule itself - two records, identical
        host strings `same_host` cannot parse, both holding files - with nothing in the product patched off."""
        hosts = "h\x07ost"  # a control character: `same_host` cannot name a place, the string is identical
        a = {"id": 61, "name": "odd-a", "ssh_host": hosts}
        b = {"id": 62, "name": "odd-b", "ssh_host": hosts}
        for server in (a, b):
            _commit_naming(server["id"], ["10.9.9." + str(server["id"])])
        urls = lambda s, svc: f"https://10.9.9.{s['id']}:8004" if svc == "dhcp4" else ""  # noqa: E731
        assert kea_tls.other_record_on_same_daemon(a, "dhcp4", [a, b], url_for=urls) == "odd-b"
        assert kea_tls.other_record_on_same_daemon(b, "dhcp4", [a, b], url_for=urls) == "odd-a"
        lab.before = None

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

    CODED = (
        "eku-anyeku",
        "eku-anyeku-and-serverauth",
        "aki-not-ski",
        "aki-wrong-serial",
        "aki-issuer-other-name",
        "aki-keyid-wrong-serial",
    )

    def test_the_coded_divergences_are_rows_of_the_flows_that_drive_every_gate(self):
        from tests import _tls_worlds as worlds

        for kind in ("aki-not-ski", "aki-wrong-serial", "aki-issuer-other-name", "aki-keyid-wrong-serial"):
            assert kind in worlds.SEMANTIC_CA_STATES, kind
        for kind in ("eku-anyeku", "eku-anyeku-and-serverauth", "eku-anyeku-and-unknown"):
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
        asked = []
        monkeypatch.setattr(
            kea_tls.shutil, "which", lambda name, path=None: asked.append(path) or "/opt/ssl/bin/openssl"
        )
        assert kea_tls._openssl_exe() == "/opt/ssl/bin/openssl"
        monkeypatch.setattr(kea_tls.shutil, "which", lambda name, path=None: None)
        assert kea_tls._openssl_exe() is None
        assert asked == ["/usr/bin:/bin"], "Q202 AR9 l: looked up on a fixed list, never the service's PATH"


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
            "stale record for server 77 kea-dhcp4 (its server is no longer configured): Rotate ignores it" in row.detail
        ), row.detail
        assert "forget it under Settings → Kea to clear this" in row.detail
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
        lab.hold_certificate_naming(2, ["kea_host", lab.servers[2]["ssh_host"]])
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        lab.begin()
        _rotate()
        texts = lab.texts()
        # Q204 AT5 b: this row asserted the NAME refusal ("the CA cannot issue its certificate for kea_host"), reached because the record's certificate was read as NAMING `kea_host`. A certificate's DNS names
        # are the verifier's parser's names now, and the parser refuses an underscore: the certificate names only 10.0.0.6, the URL's host is not one of its names, and the rotation is refused one step earlier
        # by the record check - the same outcome (the rotation stops, every host stays on the old CA, no acknowledgement is asked) with the record's own sentence.
        assert "Rotate refused" in texts and "kea_host" in texts, texts
        assert "Kea CA rotated" not in texts
        assert kea_tls.DAMAGED_CA_ADVICE not in texts and "tick the acknowledgement" not in texts, (
            "a healthy CA is never sent to the damaged-CA acknowledgement"
        )
        assert kea_tls.ca_state() == ("ok", "")
        for sid, host in lab.hosts.items():
            assert host["files"] is None or lab.answers(sid, kea_tls.ca_paths()[0]), (
                f"server {sid} still answers on the old CA"
            )


class TestTheSecondPassOfQ197:
    """F2: Rotate issues EVERY target's certificate before the first install. F4: output that is not UTF-8 is output. F5: the issuer and serial forms of an AKI. F8: a leftover `.next.prev` key copy."""

    def test_f2_a_name_refused_for_the_second_target_touches_no_host(self, lab):
        """Executed against the first draft: target 1 was installed, restarted and probed before target 2's name was refused, and then put back - two restarts for nothing."""
        lab.urls[2] = "https://kea_host:8004"
        lab.hold_certificate_naming(2, ["kea_host", lab.servers[2]["ssh_host"]])
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        lab.begin()
        _rotate()
        texts = lab.texts()
        # Q204 AT5 b: see test_a_saved_https_host_the_verifier_cannot_name... - the record check refuses before any certificate is issued
        assert "Rotate refused" in texts and "kea_host" in texts, texts
        assert "Rotate Kea CA" not in texts.replace("Rotate stopped", ""), (
            "the remedy is the address, not another Rotate"
        )
        assert lab.remote_actions() == 0, "no host was asked anything"
        assert all(h["restarts"] == 0 and not h["installs"] for h in lab.hosts.values()), "no daemon was restarted"
        assert kea_tls.ca_state() == ("ok", "")

    def test_f4_output_that_is_not_utf8_is_no_exception(self, monkeypatch, tmp_path):
        import sys

        script = tmp_path / "noisy.py"
        script.write_bytes(b"import sys\nsys.stdout.buffer.write(bytes([0xff, 0xfe, 0x80]) + b' junk')\n")
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: sys.executable)
        ran = kea_tls._run_openssl([str(script)], 10.0)
        assert ran is not None and kea_tls._openssl_verdict(ran) == (None, "")

    @pytest.mark.parametrize("kind", ["aki-issuer-other-name", "aki-keyid-wrong-serial", "aki-wrong-serial"])
    def test_f5_an_aki_that_names_another_issuer_or_serial_is_damaged_without_the_cli(self, lab, tmp_path, kind):
        crt, key, cert, private = _install_ca_files(tmp_path, kind)
        state, why = kea_tls.ca_identity(crt, key)
        assert state == "damaged" and CA_IDENTITY_WHY[kind] in why, (kind, why)
        assert kea_tls.ca_verifier_rejection(cert, private) == "" or kind == "aki-wrong-serial", (
            "the library alone accepted these (so the structural check is the gate)"
        )

    def test_f5_an_aki_naming_its_own_issuer_and_serial_stays_healthy(self, lab, tmp_path):
        crt, key, *_ = _install_ca_files(tmp_path, "aki-keyid-issuer-serial")
        assert kea_tls.ca_identity(crt, key) == ("ok", "")

    def test_f8_discarding_a_staging_removes_a_leftover_next_prev_key_copy(self, lab):
        staged = kea_tls.stage_rotation()
        leftover = pathlib.Path(staged["ca_key"] + ".prev")
        leftover.write_bytes(b"a key copy an earlier release left")
        kea_tls.discard_rotation(staged)
        assert not leftover.exists() and not any(".next" in n for n in os.listdir(kea_tls.SSL_DIR))


# ── Q198: a refusal changes nothing; "stale" is a fact about the daemon; a prepared CA that cannot name a host is told to be discarded ──────────────


def urlparse_host(url):
    from urllib.parse import urlparse

    return urlparse(url).hostname or ""


def _give_prev(sid, stale=False):
    """Put a `.prev` pair beside a server's live record (and, with `stale`, the marker that says the HOST holds that pair): the records of a target a refusal must leave exactly as they are."""
    import shutil

    crt, key = kea_tls.server_copy_path(sid, "dhcp4"), kea_tls.server_key_path(sid, "dhcp4")
    shutil.copyfile(crt, crt + ".prev")
    shutil.copyfile(key, key + ".prev")
    if stale:
        kea_tls.mark_stale(sid, "dhcp4")


def _records(sid):
    """Every Jen-side record of one server's dhcp4 certificate as bytes (None = absent), and what Jen believes the host holds."""
    out = {}
    for base in (kea_tls.server_copy_path(sid, "dhcp4"), kea_tls.server_key_path(sid, "dhcp4")):
        for suffix in ("", ".prev", ".stale", ".unknown"):
            path = base + suffix
            out[os.path.basename(path)] = pathlib.Path(path).read_bytes() if os.path.lexists(path) else None
    material = kea_tls.host_material(sid, "dhcp4")
    out["host_material"] = None if material is None else (material["server.crt"], material["server.key"])
    return out


class TestARefusalChangesNothing:
    """Q198 (AN1, REMOTE-001 §1): the failure branch of Rotate retired `.prev` and the stale marker of EVERY target that was not stuck - including a target this run never attempted, whose `.prev` was the
    only copy of what its host holds. Found by the fresh reader: a rotation refused for target 2's NAME destroyed target 1's record (T5 fired). Every refusal branch, with `.prev`-bearing untouched
    targets (and a stale marker on one of them), leaves their Jen-side records byte-equal."""

    @staticmethod
    def _arrange_name(lab, monkeypatch):
        lab.urls[2] = "https://kea_host:8004"
        lab.hold_certificate_naming(2, ["kea_host", lab.servers[2]["ssh_host"]])
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        return "Rotate refused", (
            1,
            2,
        )  # (Q204 AT5 b: the record check refuses before the name is tried; see test_f2_...)

    @staticmethod
    def _arrange_ca_damaged(lab, monkeypatch):
        def refuse(*a, **k):
            raise kea_tls.CaDamaged("boom")

        monkeypatch.setattr(kea_tls, "issue_server_cert", refuse)
        return "the CA cannot issue its certificate (boom)", (1, 2)

    @staticmethod
    def _arrange_inventory(lab, monkeypatch):
        os.unlink(kea_tls.server_copy_path(2, "dhcp4"))
        os.unlink(kea_tls.server_key_path(2, "dhcp4"))
        return "Jen holds only", (1, 2)  # Q199 (AO6): leftover files are named, not read as "never issued"

    @staticmethod
    def _arrange_storage(lab, monkeypatch):
        monkeypatch.setattr(kea_tls, "copies_dir_writable", lambda keep=True: "Input/output error")
        return "cannot write its certificate records", (1, 2)

    @staticmethod
    def _arrange_external(lab, monkeypatch):
        _add_external(lab, trust=_ca_pem())
        return "refuses the new one", (1, 2)

    @staticmethod
    def _arrange_final_probe(lab, monkeypatch):
        real = infra._probe_after_restart
        calls: dict = {}

        def probe(url, user, pwd, service, verify=None, cert=None):
            calls[url] = calls.get(url, 0) + 1
            if url == lab.urls[1] and calls[url] == 2:
                return "", "the daemon stopped answering"
            return real(url, user, pwd, service, verify=verify, cert=cert)

        monkeypatch.setattr(infra, "_probe_after_restart", probe)
        # the targets are rewritten and rolled back by this run; the PARKED server (configured, http) is the untouched one
        lab.add_server(3, "parked", "10.0.0.8", "http://10.0.0.8:8004", jen_issued=True)
        _give_prev(3, stale=True)
        return "no longer answers once every target has its new certificates", (3,)

    BRANCHES = {
        "a name refused for the second target": "_arrange_name",
        "the verifier refuses at issuing": "_arrange_ca_damaged",
        "the inventory refuses a missing record": "_arrange_inventory",
        "the storage proof refuses": "_arrange_storage",
        "the external probe refuses": "_arrange_external",
        "the final probe rolls the targets back": "_arrange_final_probe",
    }

    @pytest.mark.parametrize("branch", list(BRANCHES))
    def test_every_refusal_leaves_the_untouched_targets_records_byte_equal(self, lab, monkeypatch, branch):
        _give_prev(1, stale=True)
        _give_prev(2)
        expected_text, untouched = getattr(self, self.BRANCHES[branch])(lab, monkeypatch)
        before = {sid: _records(sid) for sid in untouched}
        assert any(v for r in before.values() for k, v in r.items() if k.endswith(".prev")) or branch.startswith(
            "the inventory"
        ), "the world has a .prev"
        lab.begin()
        _rotate()
        assert expected_text in lab.texts(), (branch, lab.texts())
        assert "Kea CA rotated" not in lab.texts()
        for sid in untouched:
            assert _records(sid) == before[sid], f"{branch}: server {sid}'s Jen-side records changed in a refusal"

    def test_a_target_the_run_committed_is_still_retired_when_the_run_is_rolled_back(self, lab, monkeypatch):
        """The fix is SCOPE, not a switch: a target the failed run really rewrote and put back has no use for the `.prev` of the operation that is over."""
        self._arrange_final_probe(lab, monkeypatch)
        _give_prev(1)
        _give_prev(2)
        lab.begin()
        _rotate()
        assert "Rolled back to the previous CA" in lab.texts(), lab.texts()
        for sid in (1, 2):
            assert not os.path.exists(kea_tls.server_copy_path(sid, "dhcp4") + ".prev"), sid
            assert not kea_tls.is_stale(sid, "dhcp4")

    def test_a_stale_marked_record_is_a_target_and_the_state_says_which_pair_is_the_hosts(self, lab):
        _give_prev(1, stale=True)
        assert kea_tls.record_state(1, "dhcp4") == ("jen-stale", "")
        assert kea_tls.record_state(2, "dhcp4") == ("jen", "")
        inventory = kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False)
        assert sorted(s["id"] for s, _svc, _b in inventory.targets) == [1, 2], "a stale-marked record is still a target"
        assert kea_tls.host_material(1, "dhcp4")["server.crt"] == pathlib.Path(
            kea_tls.server_copy_path(1, "dhcp4") + ".prev"
        ).read_text(encoding="ascii")

    def test_a_stale_marked_record_is_still_a_twin(self, lab):
        _give_prev(2, stale=True)
        one = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.6"}
        assert kea_tls.other_record_on_same_daemon(
            one, "dhcp4", [one, lab.servers[2]], url_for=lambda s, svc: "https://10.0.0.6:8004"
        ) == lab.servers[2].get("name")


class TestStaleIsAFactAboutTheDaemon:
    """Q198 (AN2): a record whose server is CONFIGURED is never stale - the socket is still in that daemon's config and it may still present the certificate. It is PARKED: kept, watched, named, never
    forgotten while the socket exists, the daemon's again when the server is switched back to https. `stale` is only a record for a server that is not configured at all."""

    @staticmethod
    def _park_server_2(lab):
        lab.urls[2] = (
            "http://10.0.0.6:8004"  # the server is switched to the Control Agent / http: configured, not an https endpoint
        )
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        lab.begin()
        lab.before = None

    def test_a_configured_server_that_is_not_https_now_is_parked_not_stale(self, lab):
        self._park_server_2(lab)
        inventory = kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False)
        assert inventory.parked == ["2-dhcp4"] and inventory.stale == []

    def test_a_server_that_is_not_configured_at_all_is_stale(self, lab):
        TestTheStaleRecords()._stale_copy()
        inventory = kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False)
        assert inventory.stale == ["77-dhcp4"] and inventory.parked == []

    def test_health_counts_and_names_a_parked_record(self, lab):
        self._park_server_2(lab)
        row = health._kea_tls_expiry({})
        assert "2 server certificate(s) valid" in row.detail, (
            "the parked record is counted: its daemon may still present it"
        )
        assert "parked record for standby kea-dhcp4" in row.detail and "stale record" not in row.detail, row.detail
        assert "remove the socket under Settings → Kea to drop it" in row.detail

    def test_health_watches_a_parked_records_expiry(self, lab):
        """A 3000-day-old parked copy is EXPIRED and says so; Q197's version excluded it from the count and warned of nothing."""
        import datetime

        ca_cert, ca_key = kea_tls._load_ca()
        key = kea_tls._new_key()
        leaf = kea_tls._leaf(
            ca_cert,
            ca_key,
            key,
            "kea-dhcp4 standby",
            [kea_tls._san_for("10.0.0.6")],
            client=False,
            now=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(days=3000),
        )
        kea_tls.commit_issued(
            2,
            "dhcp4",
            {
                "ca.crt": kea_tls._cert_pem(ca_cert).decode(),
                "server.crt": kea_tls._cert_pem(leaf).decode(),
                "server.key": kea_tls._key_pem(key).decode(),
            },
        )
        self._park_server_2(lab)
        row = health._kea_tls_expiry({})
        assert row.status == "fail" and "standby kea-dhcp4 expired" in row.detail, row.detail
        assert "remove the socket under Settings → Kea, or forget the parked record there" in row.detail
        assert "Rotate the Kea CA" not in row.detail, "Rotate leaves a parked record alone: it is not the remedy"

    def test_forget_refuses_a_parked_record_and_says_so(self, lab):
        self._park_server_2(lab)
        report = kea_tls.forget_report(extensions.KEA_SERVERS)
        assert report["forgotten"] == [] and report["parked"] == ["2-dhcp4"], report
        assert os.path.lexists(kea_tls.server_copy_path(2, "dhcp4")), "the record is still there"
        assert kea_tls.forget_stale_records(extensions.KEA_SERVERS) == []

    def test_the_forget_route_says_what_it_kept(self, lab, monkeypatch):
        self._park_server_2(lab)
        monkeypatch.setattr(infra, "url_for", lambda *a, **k: "/settings/kea")
        monkeypatch.setattr(infra, "flash", lambda text, style="message": lab.flashes.append((style, str(text))))
        monkeypatch.setattr(infra.__dict__["__user"], "audit", lambda *a, **k: None)
        app = flask.Flask(__name__)
        app.secret_key = "x"
        with app.test_request_context(method="POST"):
            inspect.unwrap(infra.forget_stale_kea_records)()
        texts = lab.texts()
        assert (
            "Kept 1 parked record(s): 2-dhcp4" in texts and "remove the socket under Settings → Kea to drop it" in texts
        )
        assert "There were no stale certificate records" not in texts and os.path.lexists(
            kea_tls.server_copy_path(2, "dhcp4")
        )

    def test_forget_on_a_directory_that_cannot_be_listed_says_so_and_forgets_nothing(self, lab, monkeypatch):
        TestTheStaleRecords()._stale_copy()

        def unreadable(strict=False):
            raise PermissionError(13, "denied")

        monkeypatch.setattr(kea_tls, "record_groups", unreadable)
        report = kea_tls.forget_report(extensions.KEA_SERVERS)
        assert report["forgotten"] == [] and "PermissionError" in report["unreadable"], report
        monkeypatch.setattr(infra, "url_for", lambda *a, **k: "/settings/kea")
        monkeypatch.setattr(infra, "flash", lambda text, style="message": lab.flashes.append((style, str(text))))
        app = flask.Flask(__name__)
        app.secret_key = "x"
        with app.test_request_context(method="POST"):
            inspect.unwrap(infra.forget_stale_kea_records)()
        assert "could not read its certificate directory" in lab.texts() and "forgot nothing" in lab.texts()
        lab.before = None

    def test_switched_back_to_https_the_parked_record_is_the_daemons_again(self, lab):
        self._park_server_2(lab)
        assert kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False).parked == ["2-dhcp4"]
        lab.urls[2] = "https://10.0.0.6:8004"
        lab.begin()
        inventory = kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False)
        assert inventory.parked == [] and sorted(s["id"] for s, _svc, _b in inventory.targets) == [1, 2]
        assert kea_tls.record_state(2, "dhcp4") == ("jen", "")

    def test_only_a_record_named_like_one_is_forgotten(self, lab):
        TestTheStaleRecords()._stale_copy()
        stray = pathlib.Path(kea_tls._copies_dir(), "zz-dhcp4.crt")
        stray.write_text("not a record Jen wrote", encoding="ascii")
        odd = pathlib.Path(kea_tls._copies_dir(), "5-weird.crt")
        odd.write_text("nor this", encoding="ascii")
        report = kea_tls.forget_report(extensions.KEA_SERVERS)
        assert report["forgotten"] == ["77-dhcp4"], report
        assert stray.exists() and odd.exists(), "a file that is not a record Jen wrote is not Jen's to delete"
        lab.before = None


class TestTheAkiAndNameRowsOfQ198:
    """Q198 (AN3): OpenSSL (`X509_check_akid`) compares the FIRST DirectoryName of an AKI's issuer list and skips every other kind of name; a root's issuer and subject are compared as NAMES."""

    @pytest.mark.parametrize("kind", ["aki-two-dirnames-wrong-first", "aki-dns-first-wrong-dirname"])
    def test_a_wrong_first_directory_name_is_damaged_and_openssl_agrees(self, lab, tmp_path, monkeypatch, kind):
        crt, key, cert, private = _install_ca_files(tmp_path, kind)
        state, why = kea_tls.ca_identity(crt, key)
        assert state == "damaged" and "does not name its own issuer and serial number" in why, (kind, why)
        if _openssl_accepts(cert, private, False) is not None:
            assert not _openssl_accepts(cert, private, False) and not _openssl_accepts(cert, private, True), kind

    @pytest.mark.parametrize(
        "kind",
        [
            "aki-two-dirnames-right-first",
            "aki-dnsname-issuer",
            "aki-uri-issuer",
            "aki-dns-first-right-dirname",
            "issuer-string-type-differs",
        ],
    )
    def test_an_aki_or_name_openssl_chains_to_is_healthy(self, lab, tmp_path, kind):
        crt, key, cert, private = _install_ca_files(tmp_path, kind)
        assert kea_tls.ca_identity(crt, key) == ("ok", ""), kind
        for client in (False, True):
            theirs = _openssl_accepts(cert, private, client)
            assert theirs is not False, f"{kind}: Jen calls it healthy and openssl rejects it"

    def test_an_aki_with_every_field_absent_is_jen_stricter_not_a_false_openssl_claim(self, lab, tmp_path):
        crt, key, cert, private = _install_ca_files(tmp_path, "aki-all-none")
        state, why = kea_tls.ca_identity(crt, key)
        assert state == "damaged" and "OpenSSL will not chain" not in why, (state, why)
        assert "authorityKeyIdentifier must contain keyIdentifier" in why

    def test_an_issuer_and_a_subject_that_differ_only_in_string_type_are_one_name(self, tmp_path):
        from tests import _tls_worlds as worlds

        cert, _key = worlds.semantic_ca("issuer-string-type-differs")
        assert cert.issuer == cert.subject and cert.issuer.public_bytes() != cert.subject.public_bytes()
        assert kea_tls._cert_structure(cert, "kea-ca.crt", cert.public_key()) == ("ok", "")


class TestPreparedCaThatCannotNameAHost:
    """Q198 (AN4): a kept `.next` CA whose name constraints refuse a host is reused by every rotation, so "change the address" was half the answer: the other half is to DISCARD it."""

    def test_the_rotation_with_a_prepared_ca_that_cannot_name_a_host_says_to_discard_it(self, lab):
        from tests import _tls_worlds as worlds

        worlds.stage_semantic_prepared("name-constraints-ip-outside")
        lab.begin()
        _rotate()
        texts = lab.texts()
        assert "the prepared CA's name constraints do not permit" in texts and "discard the prepared CA" in texts, texts
        assert "10.0.0.5" in texts or "10.0.0.6" in texts, texts
        assert lab.remote_actions() == 0, "no host was asked anything"
        assert os.path.lexists(kea_tls._staged_paths()["ca_cert"]), "the prepared CA is kept, as its button says"

    def test_the_remedies_are_distinct_and_each_names_its_action(self):
        shape = kea_tls.name_refusal_remedy(["kea_host"], rotating=True, prepared=True)
        assert "change the address saved for it" in shape and "discard" not in shape, (
            "a name no CA can carry is the address"
        )
        discard = kea_tls.name_refusal_remedy(["10.0.0.5"], rotating=True, prepared=True)
        assert (
            "discard the prepared CA under Settings → Kea and rotate again" in discard
            and "change the address" in discard
        )
        setup = kea_tls.name_refusal_remedy(["10.0.0.5"])
        assert "Rotate Kea CA" in setup and "discard" not in setup
        plain = kea_tls.name_refusal_remedy(["10.0.0.5"], rotating=True)
        assert "Rotate Kea CA" not in plain and "discard" not in plain


class TestTheSmallOnesOfQ198:
    """Q198 (AN5)."""

    def test_unchanged_url_is_one_address_however_it_is_spelled(self):
        saved = "https://Kea_Host:8000"
        for same in (saved, saved + "/", "  " + saved + " ", "https://kea_host:8000", "HTTPS://KEA_HOST:8000/"):
            assert infra._unchanged_url(same, saved), same
        assert not infra._unchanged_url("https://kea_host:8001", saved), "a port-only change is a change"
        assert not infra._unchanged_url("http://kea_host:8000", saved), "a scheme change is a change"
        assert not infra._unchanged_url("", saved)

    def test_a_u_label_is_asked_about_as_its_a_label(self):
        assert kea_tls.verifier_accepts_name("bücher.example") is True
        assert kea_tls.verifier_accepts_name("bü_cher.example") is False
        assert kea_tls.verifier_accepts_name("☃☃.example") is False, (
            "IDNA 2008 (what `requests` dials) does not allow a snowman"
        )

    def test_the_second_opinion_sentence_says_what_each_judge_said(self, lab, monkeypatch):
        _with_the_cli(monkeypatch)
        _write_live_ca("aki-issuer-serial-only")
        kea_tls._ORACLE_VERDICTS.clear()
        kea_tls._GATE_VERDICTS.clear()
        lab.begin()
        lab.before = None
        opinion = kea_tls.openssl_second_opinion()
        assert (
            "openssl verify accepts a certificate issued from it for sslserver and sslclient, but Jen judges the CA damaged"
            in opinion
        )

    def test_the_twin_counts_a_record_jen_cannot_rotate_safely(self, lab):
        one = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.6"}
        broken = {
            "id": 9,
            "name": "broken-record",
            "ssh_host": "10.0.0.6",
        }  # (not a daemon of the Lab: only its records matter here)
        kea_tls.issue_server_cert(broken, "dhcp4", "10.0.0.6")
        os.unlink(kea_tls.server_key_path(9, "dhcp4"))  # its record is now `refuse` (its key is missing)
        assert kea_tls.record_state(9, "dhcp4")[0] == "refuse"
        assert (
            kea_tls.other_record_on_same_daemon(
                one, "dhcp4", [one, broken], url_for=lambda s, svc: "https://10.0.0.6:8004"
            )
            == "broken-record"
        )
        lab.before = None

    def test_a_verifier_message_never_ends_in_a_colon(self):
        assert kea_tls._verifier_message(ValueError("invalid extension: ")) == "invalid extension"
        assert kea_tls._verifier_message(ValueError("boom:")) == "boom"

    def test_the_wizards_v6_gate_and_the_installer_merge_carry_the_name_rule(self):
        source = pathlib.Path("jen/routes/setup.py").read_text(encoding="utf-8")
        assert "certificate_name=True" in source and "dns_name_sentence(v6_url" in source
        merge = pathlib.Path("tools/config_merge.py").read_text(encoding="utf-8")
        assert "def name_warnings" in merge and "name_warnings(merged)" in merge


class TestTheSecondPassOfQ198:
    """The second pass on Q198 (agent a1112744c494cb1d1, 0 P1 / 4 P2 / 6 P3), each finding as its row first. F1 a definition changed in one use: a U-label host is accepted by the verifier question and the
    leaf must carry its A-label; F2 a name is one name across string types only where OpenSSL canonicalises them alike; F3 a removed server's records go with it and a parked record has a way out; F4 the
    parked flash and Health's remedy tell the truth; F6/F8/F10 the small ones."""

    def test_f1_a_u_label_host_gets_a_leaf_that_carries_its_a_label(self, lab):
        server = {
            "id": 9,
            "name": "unicode-host",
            "ssh_host": "m\u00fcnchen.example",
        }  # (Q202 AR9 c: a bind is an IP literal; the U-label is the SSH host's name, the other name the leaf carries)
        files = kea_tls.issue_server_cert(server, "dhcp4", "10.0.0.5", commit=False)
        from cryptography import x509

        leaf = x509.load_pem_x509_certificate(files["server.crt"].encode())
        sans = [str(v.value) for v in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
        assert "xn--mnchen-3ya.example" in sans, sans
        ca_cert, _key = kea_tls._load_ca()
        assert kea_tls.verify_issued(ca_cert, leaf, False, "xn--mnchen-3ya.example") == ""
        assert kea_tls.verify_issued(ca_cert, leaf, False, "10.0.0.5") == ""

    def test_f1_the_question_and_the_leaf_agree_for_every_name(self):
        for name in ("m\u00fcnchen.example", "b\u00fccher.example", "kea-a.example", "10.0.0.5", "\u2603.example"):
            accepted = kea_tls.verifier_accepts_name(name)
            san = kea_tls._san_for(name)
            assert accepted is (san is not None), (name, accepted, san)

    def test_f2_printable_and_utf8_remain_one_name(self):
        from tests import _tls_worlds as worlds

        cert, _key = worlds.semantic_ca("issuer-string-type-differs")
        assert kea_tls._same_name(cert.issuer, cert.subject)

    def test_f3_the_page_offers_the_box_only_where_a_parked_record_exists(self):
        template = pathlib.Path("templates/settings_kea.html").read_text(encoding="utf-8")
        assert 'name="include_parked"' in template and "{% if kea_ca.stale or kea_ca.parked %}" in template

    def test_f6_forget_names_a_stale_file_it_will_not_delete(self, lab):
        TestTheStaleRecords()._stale_copy()
        stray = pathlib.Path(kea_tls._copies_dir(), "zz-dhcp4.crt")
        stray.write_text("not a record Jen wrote", encoding="ascii")
        report = kea_tls.forget_report(extensions.KEA_SERVERS)
        assert report["skipped"] == ["zz-dhcp4.crt"] and report["forgotten"] == ["77-dhcp4"], report
        lab.before = None

    def test_f9_the_lab_flags_a_jen_stale_record_of_a_certificate_no_jen_ca_issued_too(self):
        source = inspect.getsource(Lab.check_invariants)
        assert "JEN_STATES" in source or 'in ("jen", "jen-stale")' in source, "T1 must range over jen-stale records"


# ── Q199 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def _forget(form=None):
    """The Forget route, as a superadmin's POST (the real body, the decorators unwrapped)."""
    app = flask.Flask(__name__)
    app.secret_key = "x"
    with app.test_request_context(method="POST", data=form or {}):
        inspect.unwrap(infra.forget_stale_kea_records)()


class TestADaemonLeftBehindIsAFact:
    """Q199 (AO1): a PARKED daemon (a configured server not dialled over https now) whose daemon still runs its https socket is on the CA a successful rotation just replaced. That is a durable fact -
    `tls-superseded` on Servers and in Health, the page naming whose certificate it is - not a flash. The world is HONEST: the parked daemon is loaded and answering before the rotation, so T3 passes
    because an incident names it. (Q198's version of this test removed the daemon from the world so the relative invariant would pass; the Lab has no way to ask for that any more.)"""

    def test_a_parked_daemon_a_rotation_leaves_behind_is_an_incident_health_and_the_page_name(self, lab):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        assert lab.hosts[2]["files"] and lab.hosts[2]["loaded"], "the parked daemon is loaded..."
        assert lab.answers_jens_live_identity(2) and lab.answered_before.get(2), "... and ANSWERING before the rotation"
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert (2, "dhcp4", "tls-superseded") in lab.incidents, lab.incidents
        assert not lab.answers_jens_live_identity(2), (
            "the parked daemon is on the CA Jen replaced - the incident is the whole difference"
        )
        assert lab.hosts[2]["files"] and lab.hosts[2]["loaded"], "the daemon is still in the world"
        row = health._kea_tls_expiry({})
        assert row.status in ("warn", "fail"), row
        assert "is parked and its daemon still runs a certificate from the CA Jen replaced" in row.detail, row.detail
        assert "(issued by an earlier CA)" in row.detail, row.detail
        summary = infra._kea_ca_summary()
        assert any("parked, issued by an earlier CA" in label for label in summary["parked"]), summary["parked"]
        assert lab.incident_records[-1][3] == "tls-superseded" or any(
            r[3] == "tls-superseded" for r in lab.incident_records
        )

    def test_the_attention_category_has_a_fixed_sentence_that_names_the_action(self):
        assert "set it up again" in kea_changeset.ATTENTION_CATEGORIES["tls-superseded"]
        assert "expiry is not watched" in kea_changeset.ATTENTION_CATEGORIES["record-forgotten"]

    def test_forget_with_the_box_leaves_a_durable_fact_and_t1_holds_because_it_is_named(self, lab):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        lab.begin()
        _forget({"include_parked": "1"})
        assert (2, "dhcp4", "record-forgotten") in lab.incidents, lab.incidents
        assert not os.path.lexists(kea_tls.server_copy_path(2, "dhcp4")), "the record is gone"
        assert lab.hosts[2]["files"], "the daemon is still in the world - T1 holds because the incident names it"
        texts = lab.texts()
        assert "on your word that no daemon presents them any more: 2-dhcp4" in texts, texts
        assert any("parked, on the operator's word: 2-dhcp4" in str(a) for a in lab.audits), lab.audits
        row = health._kea_tls_expiry({})
        assert (
            "was forgotten on the operator's word while the daemon may still present the certificate" in row.detail
        ), row.detail
        lab.before = None

    def test_forget_without_the_box_keeps_a_parked_record_and_records_nothing(self, lab):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        _forget()
        assert os.path.lexists(kea_tls.server_copy_path(2, "dhcp4"))
        assert not any(i[2] == "record-forgotten" for i in lab.incidents)
        lab.before = None


# ── AO3: the string-type family, every pair, against both oracles ───────────────────────────────────────────────────────────────────────────────


def _handshake_accepts(ca_cert, ca_key) -> bool:
    """A real TLS handshake (Python's ssl over a loopback socket): a server presenting a leaf issued from this CA, a client that trusts only this CA and checks the name. The third oracle."""
    import socket
    import ssl
    import tempfile
    import threading

    key = kea_tls._new_key()
    leaf = kea_tls._leaf(ca_cert, ca_key, key, "jen-probe", [kea_tls._san_for("probe.invalid")], client=False)
    with tempfile.TemporaryDirectory() as d:
        ca_path, crt_path, key_path = (os.path.join(d, n) for n in ("ca.pem", "leaf.pem", "leaf.key"))
        pathlib.Path(ca_path).write_bytes(kea_tls._cert_pem(ca_cert))
        pathlib.Path(crt_path).write_bytes(kea_tls._cert_pem(leaf))
        pathlib.Path(key_path).write_bytes(kea_tls._key_pem(key))
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(crt_path, key_path)
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.load_verify_locations(ca_path)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)

        def serve():
            try:
                conn, _addr = listener.accept()
                with server_ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with client_ctx.wrap_socket(
                socket.create_connection(listener.getsockname(), timeout=10), server_hostname="probe.invalid"
            ) as tls:
                tls.send(b"x")
            return True
        except (OSError, ssl.SSLError):
            return False
        finally:
            listener.close()
            thread.join(2)


class TestTheStringTypeFamily:
    """Q199 (AO3): a structural pre-check exists for the SENTENCE; it may never return a verdict the verifier and the stacks do not - the test for every such check is "stricter than the oracle = finding".
    Every pair of ASN.1 string types for a root's subject and issuer, in ASCII and non-ASCII text and with a case and a white-space variant, judged by `ca_identity` (no CLI), `openssl verify` and (for
    the representative rows) a real handshake. Q198's `_same_name` said "T61, BMP and Universal are not one name"; executed, BMP, Universal, IA5 and T61 holding ASCII ARE one name with UTF-8 and
    only T61 or IA5 holding the UTF-8 bytes of a non-ASCII letter are not - and OpenSSL rejects a name in VisibleString, a time or a byte string even against itself."""

    @staticmethod
    def _world(subject_type, issuer_type, text, variant=""):
        from tests import _tls_worlds as worlds

        return worlds.string_type_ca(subject_type, issuer_type, text, variant)

    @pytest.mark.parametrize(
        "pair", __import__("tests._tls_worlds", fromlist=["x"]).STRING_TYPE_PAIRS, ids=lambda p: "-".join(map(str, p))
    )
    def test_jen_is_never_stricter_than_openssl_and_never_looser(self, lab, tmp_path, monkeypatch, pair):
        from tests import _tls_worlds as worlds

        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: None)
        subject_type, issuer_type, text, variant = pair
        try:
            cert, key = self._world(subject_type, issuer_type, text, variant)
        except (ValueError, TypeError):
            pytest.skip("cryptography cannot build this name")
        (tmp_path / "c.crt").write_bytes(kea_tls._cert_pem(cert))
        (tmp_path / "c.key").write_bytes(kea_tls._key_pem(key))
        state, why = kea_tls.ca_identity(str(tmp_path / "c.crt"), str(tmp_path / "c.key"))
        theirs = [_openssl_accepts(cert, key, client) for client in (False, True)]
        if theirs[0] is None:
            pytest.skip("no openssl CLI on this machine")
        accepted = all(theirs)
        if state == "ok":
            assert accepted, f"{pair}: Jen calls it healthy and openssl rejects it"
        else:
            documented = pair in worlds.STRING_TYPE_JEN_STRICTER
            assert (not accepted) or documented, (
                f"{pair}: Jen calls it damaged ({why}) and openssl accepts it - stricter than the oracle"
            )

    @pytest.mark.parametrize(
        "pair",
        [
            ("UTF8String", "BMPString", "ascii", ""),
            ("UTF8String", "UniversalString", "ascii", ""),
            ("UTF8String", "T61String", "ascii", ""),
            ("UTF8String", "IA5String", "ascii", ""),
            ("UTF8String", "PrintableString", "ascii", ""),
            ("UTF8String", "T61String", "latin1", ""),
        ],
        ids=lambda p: "-".join(p),
    )
    def test_a_real_handshake_agrees_with_openssl_and_with_jen(self, lab, tmp_path, monkeypatch, pair):
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: None)
        cert, key = self._world(*pair)
        (tmp_path / "c.crt").write_bytes(kea_tls._cert_pem(cert))
        (tmp_path / "c.key").write_bytes(kea_tls._key_pem(key))
        jen_ok = kea_tls.ca_identity(str(tmp_path / "c.crt"), str(tmp_path / "c.key"))[0] == "ok"
        shake = _handshake_accepts(cert, key)
        assert jen_ok is shake, (
            f"{pair}: Jen {'ok' if jen_ok else 'damaged'}, a real handshake {'accepts' if shake else 'rejects'}"
        )

    def test_the_name_canonicalisation_is_openssls_not_the_librarys(self):
        from tests import _tls_worlds as worlds

        same = lambda a, b: kea_tls._same_name(a, b)  # noqa: E731
        c1, _ = self._world("UTF8String", "BMPString", "ascii")
        c2, _ = self._world("UTF8String", "T61String", "latin1")
        c3, _ = self._world("UTF8String", "UTF8String", "ascii", "case")
        c4, _ = self._world("UTF8String", "UTF8String", "ascii", "space")
        assert same(c1.issuer, c1.subject), "BMP and UTF-8 holding the same ASCII are one name"
        assert not same(c2.issuer, c2.subject), (
            "a T61String holding the UTF-8 bytes of a letter is two Latin-1 characters to OpenSSL"
        )
        assert same(c3.issuer, c3.subject) and same(c4.issuer, c4.subject), (
            "letter case and white space are folded as X509_NAME_cmp folds them"
        )
        assert worlds.STRING_TYPE_PAIRS

    def test_a_name_in_a_type_openssl_cannot_read_is_damaged_even_without_the_cli(self, lab, tmp_path, monkeypatch):
        monkeypatch.setattr(kea_tls, "_openssl_exe", lambda: None)
        for string_type in ("VisibleString", "UTCTime", "GeneralizedTime"):
            cert, key = self._world(string_type, string_type, "ascii")
            (tmp_path / "c.crt").write_bytes(kea_tls._cert_pem(cert))
            (tmp_path / "c.key").write_bytes(kea_tls._key_pem(key))
            state, why = kea_tls.ca_identity(str(tmp_path / "c.crt"), str(tmp_path / "c.key"))
            assert state == "damaged" and "string type OpenSSL does not read" in why, (string_type, why)

    def test_the_sentences_say_not_self_signed_only_when_the_names_differ(self):
        c, _ = self._world("UTF8String", "BMPString", "ascii")
        assert kea_tls._cert_structure(c, "kea-ca.crt", c.public_key()) == ("ok", "")
        d, _ = self._world("UTF8String", "T61String", "latin1")
        state, why = kea_tls._cert_structure(d, "kea-ca.crt", d.public_key())
        assert state == "damaged" and "is not self-signed" in why

    def test_the_claim_will_not_chain_is_made_only_where_it_is_true(self):
        source = inspect.getsource(kea_tls._cert_structure)
        assert source.count("OpenSSL will not chain to it") == 2, (
            "the keyid mismatch and the first-directory-name/serial mismatch: both executed to be rejected"
        )


# ── AO5: a cleanup reports what happened ────────────────────────────────────────────────────────────────────────────────────────────────────────


def _write_record(sid, which=None):
    """Write the files of a record (default all eight) with placeholder bytes; returns the paths."""
    crt, key = kea_tls.server_copy_path(sid, "dhcp4"), kea_tls.server_key_path(sid, "dhcp4")
    names = {
        "crt": crt,
        "key": key,
        "crt.prev": crt + ".prev",
        "key.prev": key + ".prev",
        "crt.staged": crt + ".staged",
        "key.staged": key + ".staged",
        "crt.stale": crt + ".stale",
        "crt.unknown": crt + ".unknown",
    }
    os.makedirs(os.path.dirname(crt), exist_ok=True)
    paths = {}
    for kind in which or names:
        pathlib.Path(names[kind]).write_bytes(b"placeholder")
        paths[kind] = names[kind]
    return paths


class TestACleanupReportsWhatHappened:
    """Q199 (AO5): `discard_local_record` re-checks every path and a record is `forgotten` only when `failed` is empty. It used to suppress every OSError: a read-only directory read as success, with the
    files - a private key among them - still on disk."""

    def test_every_file_present_and_removable(self, lab):
        _write_record(9)
        result = kea_tls.discard_local_record(9, "dhcp4")
        assert result["failed"] == [] and result["absent"] == [] and len(result["removed"]) == 8, result
        assert not [p for p in os.listdir(kea_tls._copies_dir()) if p.startswith("9-")]

    @pytest.mark.parametrize("missing", ["crt", "key"])
    def test_a_file_that_was_already_gone_is_absent_not_failed(self, lab, missing):
        paths = _write_record(9)
        os.unlink(paths[missing])
        result = kea_tls.discard_local_record(9, "dhcp4")
        assert result["failed"] == [] and os.path.basename(paths[missing]) in result["absent"], result

    @pytest.mark.parametrize(
        "kind", ["crt", "key", "crt.prev", "key.prev", "crt.staged", "key.staged", "crt.stale", "crt.unknown"]
    )
    def test_each_of_the_eight_files_failing_in_turn_is_named_and_the_record_is_not_forgotten(
        self, lab, monkeypatch, kind
    ):
        paths = _write_record(9)
        real = os.unlink

        def failing(path, *a, **k):
            if str(path) == paths[kind]:
                raise PermissionError(13, "denied")
            return real(path, *a, **k)

        monkeypatch.setattr(os, "unlink", failing)
        result = kea_tls.discard_local_record(9, "dhcp4")
        assert [f[:2] for f in result["failed"]] == [(os.path.basename(paths[kind]), "PermissionError")], result
        assert len(result["removed"]) == 7 and os.path.exists(paths[kind])
        assert result["failed"][0][2] == 13
        report_inventory = kea_tls.forget_report(extensions.KEA_SERVERS)
        assert report_inventory["incomplete"] and report_inventory["incomplete"][0][0] == "9-dhcp4", (
            "the record stays discoverable for a retry"
        )
        assert report_inventory["forgotten"] == []

    def test_a_read_only_filesystem_fails_every_file(self, lab, monkeypatch):
        paths = _write_record(9)

        real = os.unlink

        def readonly(path, *a, **k):
            if str(path).startswith(kea_tls._copies_dir()):
                raise OSError(30, "Read-only file system")
            return real(path, *a, **k)

        monkeypatch.setattr(os, "unlink", readonly)
        result = kea_tls.discard_local_record(9, "dhcp4")
        assert (
            len(result["failed"]) == 8 and {f[1] for f in result["failed"]} == {"OSError"} and result["removed"] == []
        )
        assert all(os.path.exists(p) for p in paths.values())

    def test_a_directory_that_vanishes_mid_cleanup_is_absent_not_failed(self, lab, monkeypatch):
        """After the first file the rest of the record vanishes under the cleanup (the folder removed, a restore, a second cleanup): FileNotFoundError for each, which is absent - nothing is left to fail."""
        _write_record(9)
        real = os.unlink
        state = {"n": 0}

        def vanishing(path, *a, **k):
            if not os.path.basename(str(path)).startswith("9-"):
                return real(path, *a, **k)
            state["n"] += 1
            if state["n"] == 1:
                return real(path, *a, **k)
            if os.path.lexists(path):
                real(path, *a, **k)
            raise FileNotFoundError(2, "No such file or directory")

        monkeypatch.setattr(os, "unlink", vanishing)
        result = kea_tls.discard_local_record(9, "dhcp4")
        assert result["failed"] == [] and len(result["removed"]) == 1 and len(result["absent"]) == 7, result

    def test_an_unlink_that_does_nothing_is_still_present_not_removed(self, lab, monkeypatch):
        paths = _write_record(9, which=["crt", "key"])
        real = os.unlink
        monkeypatch.setattr(
            os,
            "unlink",
            lambda path, *a, **k: None if str(path).startswith(kea_tls._copies_dir()) else real(path, *a, **k),
        )
        result = kea_tls.discard_local_record(9, "dhcp4")
        assert {f[1] for f in result["failed"]} == {"StillPresent"} and len(result["failed"]) == 2, result
        assert {f[0] for f in result["failed"]} == {os.path.basename(p) for p in paths.values()}
        assert not ({os.path.basename(p) for p in paths.values()} & set(result["removed"])), (
            "a file still there is not removed"
        )
        assert all(os.path.exists(p) for p in paths.values())

    def test_a_partial_failure_then_a_retry_that_completes(self, lab, monkeypatch):
        paths = _write_record(9)
        real = os.unlink

        def failing(path, *a, **k):
            if str(path) == paths["key"]:
                raise PermissionError(13, "denied")
            return real(path, *a, **k)

        monkeypatch.setattr(os, "unlink", failing)
        first = kea_tls.forget_report(extensions.KEA_SERVERS)
        assert first["forgotten"] == [] and [i for i, _f in first["incomplete"]] == ["9-dhcp4"]
        monkeypatch.setattr(os, "unlink", real)
        second = kea_tls.forget_report(extensions.KEA_SERVERS)
        assert second["forgotten"] == ["9-dhcp4"] and second["incomplete"] == []
        assert not [p for p in os.listdir(kea_tls._copies_dir()) if p.startswith("9-")]

    def test_the_forget_route_says_what_remained_and_never_a_keys_contents(self, lab, monkeypatch):
        paths = _write_record(9)
        real = os.unlink

        def failing(path, *a, **k):
            if str(path) == paths["key"]:
                raise PermissionError(13, "denied")
            return real(path, *a, **k)

        monkeypatch.setattr(os, "unlink", failing)
        _forget()
        texts = lab.texts()
        assert "1 file(s) of the record 9-dhcp4 could not be removed (PermissionError)" in texts, texts
        assert "Jen's copy may still be on disk" in texts
        assert "placeholder" not in texts and "placeholder" not in " ".join(str(a) for a in lab.audits)
        assert any("NOT fully removed: 9-dhcp4" in str(a) for a in lab.audits), lab.audits
        assert "Forgot Jen's own copy" not in texts, "the record was not forgotten"
        lab.before = None


# ── AO6: a record is the GROUP of its files ─────────────────────────────────────────────────────────────────────────────────────────────────────


class TestARecordIsTheGroupOfItsFiles:
    """Q199 (AO6): discovery enumerates every recognised record file and groups them by `<server number>-<service>`; a group without a live pair is an ORPHAN, shown by Health and the page and forgettable by
    the same route and rule. An unrecognised file name is never touched."""

    @pytest.mark.parametrize(
        ("which", "pair"),
        [
            (["crt", "key"], True),
            (["crt"], False),
            (["key"], False),
            (["crt.prev"], False),
            (["key.prev"], False),
            (["crt.staged"], False),
            (["crt.stale"], False),
            (["crt.unknown"], False),
            (["crt", "key", "crt.prev", "key.prev", "crt.stale"], True),
        ],
        ids=lambda v: "+".join(v) if isinstance(v, list) else str(v),
    )
    def test_each_shape_of_a_group(self, lab, which, pair):
        _write_record(31, which)
        groups, skipped = kea_tls.record_groups()
        mine = [g for g in groups if g["server_id"] == "31"]
        assert len(mine) == 1 and sorted(mine[0]["files"]) == sorted(which) and mine[0]["pair"] is pair, mine
        assert skipped == []

    def test_a_key_whose_certificate_is_gone_is_found_by_the_inventory_health_and_forget(self, lab):
        _write_record(77, ["key"])
        inventory = kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False)
        assert "77-dhcp4" in inventory.stale and "77-dhcp4" in inventory.orphans, (inventory.stale, inventory.orphans)
        row = health._kea_tls_expiry({})
        assert "Jen holds files but no certificate record for server 77 kea-dhcp4" in row.detail, row.detail
        report = kea_tls.forget_report(extensions.KEA_SERVERS)
        assert report["forgotten"] == ["77-dhcp4"] and not os.path.lexists(kea_tls.server_key_path(77, "dhcp4"))
        lab.before = None

    def test_mixed_complete_and_orphan_records_are_told_apart(self, lab):
        _write_record(77)  # complete (all eight files)
        _write_record(78, ["crt.prev"])  # orphan
        inventory = kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False)
        assert sorted(inventory.stale) == ["77-dhcp4", "78-dhcp4"] and inventory.orphans == ["78-dhcp4"]
        lab.before = None

    @staticmethod
    def _ghost(lab, url):
        """A configured server with no Lab daemon behind it (so no daemon invariant is about it): its records are all there is."""
        ghost = {"id": 79, "name": "ghost", "ssh_host": "10.0.0.79"}
        lab.urls[79] = url
        extensions.KEA_SERVERS[:] = [*lab.servers.values(), ghost]
        return ghost

    def test_a_parked_orphan_is_parked_and_named(self, lab):
        self._ghost(lab, "http://10.0.0.79:8004")
        _write_record(79, ["crt.prev"])
        inventory = kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False)
        assert inventory.parked == ["79-dhcp4"] and inventory.orphans == ["79-dhcp4"] and inventory.stale == []
        assert kea_tls.forget_report(extensions.KEA_SERVERS)["forgotten"] == [], (
            "a parked orphan is kept without the box"
        )
        assert kea_tls.forget_report(extensions.KEA_SERVERS, include_parked=True)["forgotten"] == [], (
            "(Q200 AP2) the box without a way to store the fact deletes nothing"
        )
        assert kea_tls.forget_report(extensions.KEA_SERVERS, include_parked=True, fact_first=lambda ident: True)[
            "forgotten"
        ] == ["79-dhcp4"]
        lab.before = None

    @pytest.mark.parametrize("remaining", [["crt.prev", "key.prev"], ["key"], ["crt"]])
    def test_a_configured_https_endpoint_with_incomplete_files_is_refused_naming_the_files(self, lab, remaining):
        self._ghost(lab, "https://10.0.0.79:8004")
        _write_record(79, remaining)
        state, why = kea_tls.record_state(79, "dhcp4")
        assert state == "refuse", (state, why)
        inventory = kea_tls.rotation_inventory(extensions.KEA_SERVERS, prove_storage=False)
        assert any("ghost" in r for r in inventory.refusals), inventory.refusals
        lab.before = None

    def test_unrecognised_names_are_skipped_and_never_touched(self, lab):
        d = kea_tls._copies_dir()
        os.makedirs(d, exist_ok=True)
        stray = ["007-dhcp4.crt", "5-other.crt", "abc-d2.key", ".hidden", "notes.txt", "1-dhcp4.crt.bak"]
        for name in stray:
            pathlib.Path(d, name).write_text("not Jen's", encoding="ascii")
        groups, skipped = kea_tls.record_groups()
        assert sorted(skipped) == sorted(stray), skipped
        assert {g["server_id"] for g in groups} == {"1", "2"}, "only the Lab's own records are groups"
        report = kea_tls.forget_report(extensions.KEA_SERVERS)
        assert sorted(report["skipped"]) == sorted(stray)
        assert all(pathlib.Path(d, n).exists() for n in stray), "nothing unrecognised is ever deleted"
        lab.before = None

    def test_an_unlistable_directory_is_unknown_never_empty(self, lab, monkeypatch):
        real = os.listdir

        def denied(path="."):
            if str(path) == kea_tls._copies_dir():
                raise PermissionError(13, "denied")
            return real(path)

        monkeypatch.setattr(os, "listdir", denied)
        with pytest.raises(PermissionError):
            kea_tls.record_groups(strict=True)
        assert kea_tls.record_groups() == ([], []), (
            "the non-strict reader (Health) lists none; the inventory and Forget ask strictly"
        )
        assert "PermissionError" in kea_tls.forget_report(extensions.KEA_SERVERS)["unreadable"]


# ── AO7: a record carries its destination ───────────────────────────────────────────────────────────────────────────────────────────────────────


class TestARecordCarriesItsDestination:
    """Q199 (AO7): a server certificate Jen issues names its destination (the bind address and the SSH host are its SANs). A record kept under a server number that has since been pointed at a DIFFERENT
    daemon is not that daemon's: the rotation refuses it, the record is kept (recovery material is never destroyed by a reassignment), Health names it, and the https setup for the new host replaces it."""

    @staticmethod
    def _state(lab, **changes):
        server = dict(lab.servers[2])
        url = lab.urls[2]
        server.update({k: v for k, v in changes.items() if k != "url"})
        url = changes.get("url", url)
        return kea_tls.record_state(2, "dhcp4", server=server, url=url)

    def test_the_unchanged_record_is_jens(self, lab):
        assert self._state(lab) == ("jen", "")

    def test_a_display_name_change_is_jens(self, lab):
        assert self._state(lab, name="a better name") == ("jen", "")

    def test_a_url_change_on_the_same_daemon_is_jens(self, lab):
        assert self._state(lab, url="https://10.0.0.6:9999") == ("jen", "")

    def test_an_alias_of_the_same_host_is_jens(self, lab):
        """Q204 AT5 a: this row said the mapped spelling is "the same host" for a certificate that names `10.0.0.6` (Q188 AD9's credential fold, used for a certificate name). No verifier folds it:
        a client dialling `[::ffff:10.0.0.6]` is refused by a certificate for `10.0.0.6`. The record reads as refused. (A spelling that really IS the same name still passes: the next rows.)"""
        assert self._state(lab, ssh_host="::ffff:10.0.0.6", url="https://[::ffff:10.0.0.6]:8004")[0] == "refuse"
        assert self._state(lab, ssh_host="10.0.0.6", url="https://[FD00::6]:8004")[0] == "refuse"

    def test_a_different_daemon_is_refused_and_says_what_to_do(self, lab):
        state, why = self._state(lab, ssh_host="10.0.0.77", url="https://10.0.0.77:8004")
        assert (
            state == "refuse"
            and "names 10.0.0.6 as the machine it was installed on" in why
            and "SSH host is now 10.0.0.77" in why
        ), (
            state,
            why,
        )
        assert "a different machine" in why and "remove the direct socket and set it up again on it" in why, why
        assert "or restore the previous SSH host" in why

    def test_only_the_ssh_host_changed_is_REFUSED_whatever_the_address_still_reaches(self, lab):
        """DEVIATION NAMED (Q200): Q199 pinned the OPPOSITE of this row (`..._but_the_address_still_reaches_the_daemon_is_jens`). The SSH host is the machine the helper logs into and modifies; a URL match
        proves nothing about it. The test above this docstring is the Q's own listed case, restored."""
        state, why = self._state(lab, ssh_host="10.0.0.77")
        assert state == "refuse" and "SSH host is now 10.0.0.77" in why, (state, why)

    def test_a_certificate_with_no_host_san_names_no_destination(self, lab):
        """DEVIATION NAMED (Q202 AR2): Q199/Q201 pinned the OPPOSITE of the first half of this row (a certificate with NO SAN names no destination, so it is not judged). A certificate that names nothing
        proves nothing - the absence of evidence is never evidence - so wherever there is a name to judge it is REFUSED (`TestACertificateThatNamesNothingProvesNothing` has the eleven rows). Nothing configured
        is still nothing to judge (second pass F7: the Q199 body issued one WITH a bind SAN and so never reached this branch)."""
        ca_cert, ca_key = kea_tls._load_ca()
        key = kea_tls._new_key()
        cert = kea_tls._leaf(ca_cert, ca_key, key, "kea-dhcp4 no-san", [], client=False)
        assert kea_tls._certificate_roles(cert) == (None, None)
        assert "names no address and no machine" in kea_tls.ssh_host_refusal(cert, {"id": 5, "ssh_host": "10.0.0.51"})
        assert "names no address and no machine" in kea_tls._destination_refusal(
            cert, {"id": 5, "ssh_host": "10.0.0.51"}, "https://10.0.0.50:8004"
        )
        assert kea_tls.ssh_host_refusal(cert, {"id": 5, "ssh_host": ""}) == ""
        assert kea_tls._destination_refusal(cert, {"id": 5, "ssh_host": ""}, "") == ""
        bare = {"id": 5, "name": "bare", "ssh_host": ""}
        kea_tls.issue_server_cert(bare, "dhcp4", "10.0.0.50")
        assert (
            kea_tls.record_state(5, "dhcp4", server={"id": 5, "ssh_host": ""}, url="https://10.0.0.50:8004")[0] == "jen"
        ), "no SSH host configured, the bind matches"
        lab.before = None

    def test_the_rotation_refuses_the_rebound_target_keeps_its_record_and_health_names_it(self, lab):
        lab.servers[2]["ssh_host"] = "10.0.0.77"
        lab.urls[2] = "https://10.0.0.77:8004"
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        before = _records(2)
        lab.begin()
        _rotate()
        texts = lab.texts()
        assert "Rotate refused" in texts and "a different machine" in texts, texts
        assert "names 10.0.0.6 as the machine it was installed on" in texts
        assert _records(2) == before, "the record is KEPT (recovery material is never destroyed by a reassignment)"
        assert lab.remote_actions() == 0
        row = health._kea_tls_expiry({})
        assert row.status == "warn" and "a different machine" in row.detail, row.detail
        lab.before = None

    def test_the_setup_for_the_new_host_replaces_the_record(self, lab):
        lab.servers[2]["ssh_host"] = "10.0.0.77"
        lab.urls[2] = "https://10.0.0.77:8004"
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        assert kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])[0] == "refuse"
        kea_tls.issue_server_cert(lab.servers[2], "dhcp4", "10.0.0.77")  # what the setup commits for the new host
        assert kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2]) == ("jen", "")
        lab.begin()
        lab.before = None

    def test_an_administrators_certificate_on_the_new_host_is_external_as_before(self, lab):
        external = _external_files("10.0.0.77")
        pathlib.Path(kea_tls.server_copy_path(2, "dhcp4")).write_text(external["server.crt"], encoding="ascii")
        pathlib.Path(kea_tls.server_key_path(2, "dhcp4")).write_text(external["server.key"], encoding="ascii")
        assert self._state(lab, ssh_host="10.0.0.77", url="https://10.0.0.77:8004") == ("external", "")
        lab.begin()
        lab.before = None

    def test_a_removed_servers_number_reused_for_another_host_is_refused_by_the_san_check(self, lab):
        """The AO2 save drops a removed server's records; a record that SURVIVED (a hand-edited config, a restore) under a reused number is still caught here."""
        reused = {"id": 2, "name": "someone else", "ssh_host": "10.0.0.90"}
        assert kea_tls.record_state(2, "dhcp4", server=reused, url="https://10.0.0.90:8004")[0] == "refuse"


class TestTheSecondPassOfQ199:
    """The pre-release second pass on Q199: F1 (forgetting a parked record before the rotation took the rotation's fact with it) and F2 (an openssl that cannot LOAD the CA is not 'no opinion')."""

    def test_f1_forget_then_rotate_still_leaves_the_fact_the_rotation_owes(self, lab):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        _forget({"include_parked": "1"})
        assert (2, "dhcp4", "record-forgotten") in lab.incidents, lab.incidents
        assert not os.path.lexists(kea_tls.server_copy_path(2, "dhcp4"))
        _rotate()
        assert (2, "dhcp4", "tls-superseded") in lab.incidents, (
            "the forgotten record was the only tie between the parked daemon and the replaced CA - the rotation still owes the fact"
        )
        assert not lab.answers_jens_live_identity(2), (
            "the daemon is on the replaced CA: the incident is the whole difference"
        )
        assert lab.hosts[2]["files"] and lab.hosts[2]["loaded"], "the daemon stays in the world"

    def test_f1_the_rotation_does_not_name_a_forgotten_record_it_did_rotate(self, lab):
        """A server that is an https endpoint again is a rotation target: its fact is resolved by the rotation, not re-written."""
        _rotate()
        assert not any(i[2] == "tls-superseded" for i in lab.incidents), lab.incidents

    def test_f2_an_openssl_that_cannot_load_the_ca_rejects_it_and_a_broken_openssl_has_no_opinion(self):
        loaded = (
            1,
            "Error loading file /tmp/jen-openssl-gate-x/ca.pem\n40A7:error:0480006C:PEM routines:get_name:no start line\nno certificate found",
        )
        assert kea_tls._openssl_verdict(loaded)[0] is False
        assert "ca.pem" in kea_tls._openssl_verdict(loaded)[1]
        assert kea_tls._openssl_verdict((127, "openssl: error while loading shared libraries: libssl.so.3"))[0] is None
        assert kea_tls._openssl_verdict((1, "Error loading file /tmp/jen-openssl-gate-x/probe.pem"))[0] is None, (
            "the leaf is Jen's own: a leaf the CLI cannot load says nothing about the CA"
        )
        assert kea_tls._openssl_verdict((0, "usage: openssl verify"))[0] is None


# ── Q200 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def _hosts_state(lab):
    """Every fake host's TLS files, installs and restarts - 'both fake hosts byte-equal' is this before == after."""
    return {
        sid: (
            copy.deepcopy(h["files"]),
            copy.deepcopy(h["loaded"]),
            len(h["installs"]),
            h["restarts"],
        )
        for sid, h in lab.machines().items()
    }


class TestTheSshHostIsTheTarget:
    """Q200 (AP1, REMOTE-001): the SSH host is the mutation target. A record is the daemon's only when the name the helper will reach matches the name the certificate was issued for, ON ITS OWN; a URL
    match proves nothing about the host the helper logs into. Q199 let ANY configured name match ANY SAN: with the SSH host moved to another machine and the URL unchanged the inventory accepted the
    record, the rotation installed material on the NEW machine and restarted its daemon, the probe of the old machine's URL failed, and the rollback put the old host's pair on the new one. Every row
    runs through the real route against the Lab's two fake hosts."""

    @staticmethod
    def _configure(lab, sid, **changes):
        url = changes.pop("url", None)
        lab.servers[sid].update(changes)
        if url is not None:
            lab.urls[sid] = url
        extensions.KEA_SERVERS[:] = list(lab.servers.values())

    @staticmethod
    def _state(lab, sid=2, **changes):
        server = dict(lab.servers[sid])
        url = changes.pop("url", lab.urls[sid])
        server.update(changes)
        return kea_tls.record_state(sid, "dhcp4", server=server, url=url)

    def test_unchanged_is_jens(self, lab):
        assert self._state(lab) == ("jen", "")
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()

    def test_a_display_name_change_is_jens(self, lab):
        assert self._state(lab, name="a better name") == ("jen", "")

    def test_a_url_alias_of_the_same_host_is_jens(self, lab):
        """Q204 AT5 a: inverted (it was `("jen", "")` for the mapped URL spelling) - see test_an_alias_of_the_same_host_is_jens. The case-folded DNS alias is still one name."""
        assert self._state(lab, url="https://[::ffff:10.0.0.6]:8004")[0] == "refuse"
        assert self._state(lab, url="https://10.0.0.6:8004") == ("jen", "")

    def test_an_ssh_alias_that_same_host_equates_is_jens(self, lab):
        """Q204 AT5 a: inverted (it was `("jen", "")`): the SSH host `::ffff:10.0.0.6` is not the machine name the certificate carries (`10.0.0.6`) as a verifier reads names."""
        assert self._state(lab, ssh_host="::ffff:10.0.0.6")[0] == "refuse"

    def test_an_alias_same_host_cannot_equate_is_a_refusal_with_the_sentence_by_design(self, lab):
        state, why = self._state(lab, ssh_host="kea-b.lan")
        assert state == "refuse" and "SSH host is now kea-b.lan" in why, (state, why)

    def test_the_ssh_host_moved_with_the_url_unchanged_is_refused_before_staging_through_the_real_route(self, lab):
        """THE P1 (reviewer's repro): server 2's SSH host is re-pointed at server 1's machine; its URL is unchanged."""
        self._configure(lab, 2, ssh_host=lab.servers[1]["ssh_host"])
        assert self._state(lab)[0] == "refuse"
        before, records = _hosts_state(lab), {sid: _records(sid) for sid in (1, 2)}
        ca_before = _ca_bytes()
        _rotate()
        texts = lab.texts()
        assert "Rotate refused" in texts and "this record's SSH host is now 10.0.0.5, a different machine" in texts, (
            texts
        )
        assert "Kea CA rotated" not in texts
        assert lab.remote_actions() == 0, "no host was asked anything"
        assert _hosts_state(lab) == before, "both fake hosts are byte-equal: nothing installed, nothing restarted"
        assert {sid: _records(sid) for sid in (1, 2)} == records, "the record is KEPT"
        assert _ca_bytes() == ca_before, "staging never began"
        row = health._kea_tls_expiry({})
        assert row.status == "warn" and "a different machine" in row.detail, row.detail
        lab.before = None

    def test_the_url_changed_with_the_ssh_host_unchanged_is_refused_on_the_url_side(self, lab):
        self._configure(lab, 2, url="https://10.0.0.88:8004")
        state, why = self._state(lab)
        assert state == "refuse" and "this record's address is now 10.0.0.88, a different daemon" in why, (state, why)
        before = _hosts_state(lab)
        _rotate()
        assert "Rotate refused" in lab.texts() and lab.remote_actions() == 0
        assert _hosts_state(lab) == before
        lab.before = None

    def test_both_moved_is_refused(self, lab):
        self._configure(lab, 2, ssh_host="10.0.0.77", url="https://10.0.0.77:8004")
        assert self._state(lab)[0] == "refuse"
        before = _hosts_state(lab)
        _rotate()
        assert "Rotate refused" in lab.texts() and lab.remote_actions() == 0
        assert _hosts_state(lab) == before
        lab.before = None

    def test_two_daemons_with_their_own_certificates_are_each_judged_on_their_own(self, lab):
        """Server 2 takes server 1's SSH host: server 2 is refused, and (Q202 second pass F1) so is server 1 - the host now has two records."""
        self._configure(lab, 2, ssh_host=lab.servers[1]["ssh_host"])
        assert self._state(lab, sid=1)[0] == "jen"
        inventory = kea_tls.rotation_inventory(
            extensions.KEA_SERVERS, url_for=lambda s, svc: lab.urls[s["id"]], prove_storage=False
        )
        refused = [r for r in inventory.refusals if "standby" in r or "10.0.0.6" in r]
        # DEVIATION NAMED (Q202 second pass F1): this row pinned that the UNCHANGED record (kea-a) is not refused when server 2 is pointed at its host. A record that holds files and names this SSH host is a
        # second owner of the daemon whatever its certificate says (no exemption for "names another machine"), so kea-a is refused too - with the twin sentence naming server 2; nothing is installed
        assert refused and any(
            r.startswith("kea-a kea-dhcp4") and "standby already manages" in r for r in inventory.refusals
        ), inventory.refusals
        lab.before = None

    def test_the_rollback_wall_a_pair_for_host_a_never_reaches_install_tls_for_host_b(self, lab, monkeypatch):
        self._configure(lab, 2, ssh_host="10.0.0.77")
        _give_prev(
            2
        )  # (Q201 AQ6 b: with a `.prev` pair the put-back has something to install - without one it answered `none-saved` and proved nothing about the wall)
        calls = []
        monkeypatch.setattr(
            kea_host, "install_tls", lambda server, service, files: calls.append(server["ssh_host"]) or {"ok": True}
        )
        assert infra._reinstall_live_material(lab.servers[2], "dhcp4") == "failed"
        assert infra._put_tls_back(lab.servers[2], "dhcp4")["remote"] == "failed"
        assert calls == [], "the saved pair is for 10.0.0.6; the host Jen would log into is 10.0.0.77"
        lab.before = None

    def test_the_rollback_wall_lets_the_matching_host_through(self, lab, monkeypatch):
        calls = []
        monkeypatch.setattr(
            kea_host, "install_tls", lambda server, service, files: calls.append(server["ssh_host"]) or {"ok": True}
        )
        assert infra._reinstall_live_material(lab.servers[2], "dhcp4") == "restored" and calls == ["10.0.0.6"]
        lab.before = None

    def test_DEVIATION_a_record_with_a_bind_only_SAN_is_judged_on_the_ssh_host_too(self, lab):
        """DEVIATION NAMED (Q200): the Q lists 'a pre-v5.29 record (bind-only SAN) -> jen with the Health note'. No such record exists: `issue_server_cert` has put the SSH host among the SANs since the
        module's first commit (5ec996b, 5.29.0 step 3/5), so a certificate with ONE name means the SSH host was empty or the same as the bind when it was issued - and exactly that shape is what a
        moved SSH host looks like when the two used to be the same. Judging a single-SAN certificate on the URL alone would re-admit the P1 for the commonest configuration (ssh_host == address), so it is
        judged on both, and an SSH host configured since an empty one is a refusal with the sentence (set up again)."""
        bare = {"id": 5, "name": "bare", "ssh_host": ""}
        kea_tls.issue_server_cert(bare, "dhcp4", "10.0.0.50")
        state, why = kea_tls.record_state(
            5, "dhcp4", server={"id": 5, "ssh_host": "10.0.0.51"}, url="https://10.0.0.50:8004"
        )
        assert state == "refuse" and "SSH host is now 10.0.0.51" in why, (state, why)
        lab.before = None


class TestAForgetPersistsItsFactBeforeItDeletes:
    """Q200 (AP2): the `record-forgotten` incident is stored AND read back before a parked record is deleted. Q199 deleted first and wrote after, ignoring the write's result, so a store that was down (or a
    crash between the two) left the record gone, no fact, and a success flash that said 'recorded on Servers'."""

    @staticmethod
    def _parked(lab):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)

    def test_the_fact_is_written_before_the_first_file_is_deleted(self, lab, monkeypatch):
        self._parked(lab)
        seen = []
        real = kea_tls.discard_local_record

        def watching(sid, service):
            seen.append(
                (
                    (int(sid), service, "record-forgotten") in lab.incidents,
                    os.path.lexists(kea_tls.server_copy_path(sid, service)),
                )
            )
            return real(sid, service)

        monkeypatch.setattr(kea_tls, "discard_local_record", watching)
        _forget({"include_parked": "1"})
        assert seen == [(True, True)], "the incident existed, and the record was still there, when the deletion began"
        assert not os.path.lexists(kea_tls.server_copy_path(2, "dhcp4"))
        assert "recorded on Servers" in lab.texts()

    def test_a_store_that_returns_false_leaves_every_file_untouched_and_the_sentence_says_so(self, lab, monkeypatch):
        self._parked(lab)
        before = _records(2)
        monkeypatch.setattr(kea_changeset, "record_attention", lambda *a, **k: False)
        _forget({"include_parked": "1"})
        texts = lab.texts()
        assert (
            "The record was kept: Jen could not write the fact of its removal (the incident store is unavailable)"
            in texts
        ), texts
        assert "Forgot Jen's own copy" not in texts and "recorded on Servers" not in texts, "no success is claimed"
        assert _records(2) == before, "every file untouched"

    def test_a_store_that_says_true_but_cannot_be_read_back_is_not_a_fact(self, lab, monkeypatch):
        self._parked(lab)
        before = _records(2)
        monkeypatch.setattr(kea_changeset, "recovery_incidents", lambda strict=False: [])
        _forget({"include_parked": "1"})
        assert "The record was kept" in lab.texts() and _records(2) == before

    @pytest.mark.parametrize("which", ["crt", "key"])
    def test_a_file_that_will_not_delete_updates_the_incident_to_incomplete(self, lab, monkeypatch, which):
        self._parked(lab)
        target = (kea_tls.server_copy_path if which == "crt" else kea_tls.server_key_path)(2, "dhcp4")
        real = os.unlink

        def failing(path, *a, **k):
            if str(path) == target:
                raise PermissionError(13, "denied")
            return real(path, *a, **k)

        monkeypatch.setattr(os, "unlink", failing)
        _forget({"include_parked": "1"})
        monkeypatch.setattr(os, "unlink", real)
        records = [r for r in lab.incident_records if r[3] == "record-forgotten"]
        assert records and "forget incomplete" in records[-1][2], records
        assert "could not be removed" in lab.texts()
        assert os.path.lexists(target), "the file that would not go is still there"
        row = health._kea_tls_expiry({})
        assert "was started and did not finish" in row.detail, row.detail

    def test_a_crash_between_the_write_and_the_deletion_is_visible_and_the_retry_completes_it(self, lab, monkeypatch):
        self._parked(lab)
        real = kea_tls.discard_local_record
        monkeypatch.setattr(
            kea_tls, "discard_local_record", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("the process died"))
        )
        with pytest.raises(RuntimeError):
            _forget({"include_parked": "1"})
        assert (2, "dhcp4", "record-forgotten") in lab.incidents, "the fact survived the crash"
        assert os.path.lexists(kea_tls.server_copy_path(2, "dhcp4")), "and the record is still there"
        row = health._kea_tls_expiry({})
        assert "was started and did not finish" in row.detail, row.detail
        monkeypatch.setattr(kea_tls, "discard_local_record", real)
        _forget({"include_parked": "1"})
        assert not os.path.lexists(kea_tls.server_copy_path(2, "dhcp4")), "the retry completed it"
        assert "was started and did not finish" not in health._kea_tls_expiry({}).detail

    def test_forget_without_the_box_stores_no_fact_and_deletes_nothing_parked(self, lab):
        self._parked(lab)
        _forget()
        assert not any(i[2] == "record-forgotten" for i in lab.incidents)
        assert os.path.lexists(kea_tls.server_copy_path(2, "dhcp4"))

    def test_two_forgets_in_a_row_the_second_finds_nothing(self, lab):
        """(The identity lock serialises two concurrent forgets - `test_identity_guard` walks the decorators; what is checked here is what the second one sees.)"""
        self._parked(lab)
        _forget({"include_parked": "1"})
        _forget({"include_parked": "1"})
        assert not os.path.lexists(kea_tls.server_copy_path(2, "dhcp4"))
        assert (2, "dhcp4", "record-forgotten") in lab.incidents


class TestAnOrphanIsJudgedByItsPreviousPair:
    """Q200 (AP3): the post-rotation loop skipped every parked orphan. A group with no live pair can still be a daemon's record: a complete `.prev` pair IS what the host holds (the stale-marker
    contract). Its certificate says whose CA it is; one that cannot say is recorded as unknown, never silence."""

    @staticmethod
    def _ghost(lab, sid=79):
        ghost = {"id": sid, "name": "ghost", "ssh_host": f"10.0.0.{sid}"}
        lab.urls[sid] = f"http://10.0.0.{sid}:8004"
        lab.servers[sid] = ghost
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        return ghost

    @staticmethod
    def _prev_pair_from_current_ca(sid):
        """A `.prev` pair (and nothing else) issued by the CA that the next rotation replaces."""
        server = {"id": sid, "name": "ghost", "ssh_host": f"10.0.0.{sid}"}
        kea_tls.issue_server_cert(server, "dhcp4", f"10.0.0.{sid}")
        for path in (kea_tls.server_copy_path(sid, "dhcp4"), kea_tls.server_key_path(sid, "dhcp4")):
            os.replace(path, path + ".prev")

    def _rotate_with(self, lab, prepare):
        self._ghost(lab)
        prepare()
        lab.begin()
        lab.before = None
        _rotate()

    def test_a_parked_live_pair_is_superseded(self, lab):
        self._rotate_with(lab, lambda: kea_tls.issue_server_cert(self._ghost(lab), "dhcp4", "10.0.0.79"))
        assert (79, "dhcp4", "tls-superseded") in lab.incidents, lab.incidents

    def test_a_prev_pair_only_issued_by_the_replaced_ca_is_superseded(self, lab):
        self._rotate_with(lab, lambda: self._prev_pair_from_current_ca(79))
        assert (79, "dhcp4", "tls-superseded") in lab.incidents, lab.incidents
        assert not any(i[0] == 79 and i[2] == "remote-unknown" for i in lab.incidents)

    def test_a_prev_pair_plus_a_stale_marker_is_superseded(self, lab):
        def prepare():
            self._prev_pair_from_current_ca(79)
            kea_tls.mark_stale(79, "dhcp4")

        self._rotate_with(lab, prepare)
        assert (79, "dhcp4", "tls-superseded") in lab.incidents, lab.incidents

    def test_a_lone_live_certificate_is_judged_by_its_issuer(self, lab):
        def prepare():
            self._prev_pair_from_current_ca(79)
            os.replace(kea_tls.server_copy_path(79, "dhcp4") + ".prev", kea_tls.server_copy_path(79, "dhcp4"))
            os.unlink(kea_tls.server_key_path(79, "dhcp4") + ".prev")

        self._rotate_with(lab, prepare)
        assert (79, "dhcp4", "tls-superseded") in lab.incidents, lab.incidents

    def test_a_lone_key_is_unknown_never_silence(self, lab):
        self._rotate_with(lab, lambda: _write_record(79, ["key"]))
        assert (79, "dhcp4", "remote-unknown") in lab.incidents, lab.incidents
        assert any(
            "Jen cannot tell whether ghost kea-dhcp4's daemon depends on the CA just replaced" in r[2]
            for r in lab.incident_records
        )

    def test_an_unknown_marker_only_is_unknown(self, lab):
        self._rotate_with(lab, lambda: _write_record(79, ["crt.unknown"]))
        assert (79, "dhcp4", "remote-unknown") in lab.incidents, lab.incidents

    def test_a_prev_pair_from_an_external_ca_is_external_with_no_incident(self, lab):
        def prepare():
            external = _external_files("10.0.0.79")
            pathlib.Path(kea_tls.server_copy_path(79, "dhcp4") + ".prev").write_text(
                external["server.crt"], encoding="ascii"
            )
            pathlib.Path(kea_tls.server_key_path(79, "dhcp4") + ".prev").write_text(
                external["server.key"], encoding="ascii"
            )

        self._rotate_with(lab, prepare)
        assert not any(i[0] == 79 for i in lab.incidents), lab.incidents

    def test_record_state_names_the_previous_pairs_state(self, lab):
        self._ghost(lab)
        self._prev_pair_from_current_ca(79)
        assert kea_tls.group_verdict(79, "dhcp4") == "current"
        why = kea_tls.record_state(79, "dhcp4")[1]
        assert "its previous pair was issued by Jen's current CA" in why, why
        lab.before = None
        _rotate()
        assert kea_tls.group_verdict(79, "dhcp4") == "superseded"
        assert "its previous pair was issued by an earlier Jen CA" in kea_tls.record_state(79, "dhcp4")[1]

    def test_re_enabling_https_after_the_rotation_gives_the_remove_and_set_up_sentence(self, lab):
        self._rotate_with(lab, lambda: self._prev_pair_from_current_ca(79))
        assert (79, "dhcp4", "tls-superseded") in lab.incidents
        assert infra._record_is_from_an_earlier_ca(79, "dhcp4"), "the setup's already-there branch reads the same fact"

    def test_the_incidents_survive_a_restart(self, lab):
        """The facts are in the incident store, not in a request: a second `recovery_incidents()` call - what a new app on the same store does - sees them."""
        self._rotate_with(lab, lambda: _write_record(79, ["key"]))
        assert (79, "dhcp4", "remote-unknown") in [
            (i["server_id"], i["service"], i["category"]) for i in kea_changeset.recovery_incidents()
        ]


class TestTheSecondPassOfQ200:
    """The pre-release second pass on Q200: F1 (a damaged-CA recovery bypassed the SSH-host wall), F2 (a pair from two rotations ago was called external), F3 (a parked live pair issued by an external CA was
    called superseded), F4 (an incomplete forget read as 'forgotten' on Servers)."""

    @pytest.mark.parametrize("damage", ["key-missing", "cert-malformed"])
    def test_f1_a_recovery_refuses_a_record_whose_ssh_host_moved_before_anything_is_installed(self, lab, damage):
        lab.servers[2]["ssh_host"] = (
            "10.0.0.77"  # the SSH host moved to a third machine; the URL (10.0.0.6) is unchanged
        )
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        if damage == "key-missing":
            os.unlink(kea_tls.ca_paths()[1])
        else:
            pathlib.Path(kea_tls.ca_paths()[0]).write_text("not a certificate", encoding="ascii")
        before = _hosts_state(lab)
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "Rotate refused" in texts and "a different machine" in texts, texts
        assert "Kea CA rotated" not in texts
        assert lab.remote_actions() == 0, "no host was asked anything"
        assert _hosts_state(lab) == before, "no machine received a certificate or a restart"
        lab.before = None

    def test_f1_a_recovery_with_the_records_unchanged_still_rotates(self, lab):
        os.unlink(kea_tls.ca_paths()[1])
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()

    def test_f2_a_pair_from_two_rotations_ago_is_an_earlier_jen_ca_not_an_external_one(self, lab):
        server = {"id": 79, "name": "ghost", "ssh_host": "10.0.0.79"}
        lab.urls[79] = "http://10.0.0.79:8004"
        lab.servers[79] = server
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        kea_tls.issue_server_cert(server, "dhcp4", "10.0.0.79")
        for path in (kea_tls.server_copy_path(79, "dhcp4"), kea_tls.server_key_path(79, "dhcp4")):
            os.replace(path, path + ".prev")
        _rotate()
        assert kea_tls.group_verdict(79, "dhcp4") == "superseded"
        lab.incidents.clear()
        _rotate()
        assert kea_tls.group_verdict(79, "dhcp4") == "superseded", (
            "the second rotation: the CA that issued it is two CAs ago"
        )
        assert (79, "dhcp4", "tls-superseded") in lab.incidents, lab.incidents
        assert "was not issued by Jen" not in kea_tls.record_state(79, "dhcp4")[1]
        lab.before = None

    def test_f3_a_parked_live_pair_issued_by_an_external_ca_records_nothing(self, lab):
        server = {"id": 79, "name": "ghost", "ssh_host": "10.0.0.79"}
        lab.urls[79] = "http://10.0.0.79:8004"
        lab.servers[79] = server
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        external = _external_files("10.0.0.79")
        pathlib.Path(kea_tls.server_copy_path(79, "dhcp4")).write_text(external["server.crt"], encoding="ascii")
        pathlib.Path(kea_tls.server_key_path(79, "dhcp4")).write_text(external["server.key"], encoding="ascii")
        _rotate()
        assert not any(i[0] == 79 for i in lab.incidents), lab.incidents
        lab.before = None

    def test_f4_an_incomplete_forget_says_so_in_the_detail_servers_shows(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        crt = kea_tls.server_copy_path(2, "dhcp4")
        real = os.unlink

        def failing(path, *a, **k):
            if str(path) == crt:
                raise PermissionError(13, "denied")
            return real(path, *a, **k)

        monkeypatch.setattr(os, "unlink", failing)
        _forget({"include_parked": "1"})
        monkeypatch.setattr(os, "unlink", real)
        record = [r for r in lab.incident_records if r[3] == "record-forgotten"][-1]
        assert "did not finish" in record[5], record

    def test_f9_a_forget_refused_for_want_of_a_fact_is_audited(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        monkeypatch.setattr(kea_changeset, "record_attention", lambda *a, **k: False)
        _forget({"include_parked": "1"})
        assert any("the fact could not be stored for 2-dhcp4" in str(a) for a in lab.audits), lab.audits


# ── Q201 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def _commit_naming(sid, names, service="dhcp4"):
    """Commit a record for `sid` whose certificate carries exactly `names`, IN THAT ORDER (the SAN order is the roles), even where today's verifier would refuse to issue one."""
    ca_cert, ca_key = kea_tls._load_ca()
    key = kea_tls._new_key()
    sans = [s for s in (kea_tls._san_for(n) for n in names) if s is not None]
    cert = kea_tls._leaf(ca_cert, ca_key, key, "kea-dhcp4 named", sans, client=False)
    files = {
        "ca.crt": kea_tls._cert_pem(ca_cert).decode(),
        "server.crt": kea_tls._cert_pem(cert).decode(),
        "server.key": kea_tls._key_pem(key).decode(),
    }
    kea_tls.commit_issued(sid, service, files)
    return files


class TestTheLabRoutesByMachine:
    """Q201 (AQ6 a): the Lab routes a helper call by the MACHINE the record's SSH host names now, so 'the change landed on the wrong machine' is observed, not inferred."""

    def test_a_record_whose_ssh_host_names_the_other_machine_reaches_that_machine(self, lab):
        lab.servers[2]["ssh_host"] = lab.servers[1]["ssh_host"]
        held = copy.deepcopy(lab.hosts[1])
        kea_host.install_tls(lab.servers[2], "dhcp4", {"ca.crt": "x", "server.crt": "y", "server.key": "z"})
        assert len(lab.hosts[1]["installs"]) == 1 and lab.hosts[2]["installs"] == []
        lab.hosts[1].update(
            held
        )  # (the test wrote placeholder bytes onto machine 1: put the world back before the invariants look at it)
        lab.before = None

    def test_a_record_whose_ssh_host_names_no_machine_the_lab_has_reaches_a_third(self, lab):
        lab.servers[2]["ssh_host"] = "10.0.0.77"
        kea_host.install_tls(lab.servers[2], "dhcp4", {"ca.crt": "x", "server.crt": "y", "server.key": "z"})
        assert list(lab.third_machines) == ["10.0.0.77"] and len(lab.third_machines["10.0.0.77"]["installs"]) == 1
        assert lab.hosts[1]["installs"] == [] and lab.hosts[2]["installs"] == []
        assert lab.remote_actions() == 1
        lab.before = None

    def test_an_alias_same_host_equates_reaches_its_own_machine(self, lab):
        lab.servers[2]["ssh_host"] = "::ffff:10.0.0.6"
        held = copy.deepcopy(lab.hosts[2])
        kea_host.install_tls(lab.servers[2], "dhcp4", {"ca.crt": "x", "server.crt": "y", "server.key": "z"})
        assert len(lab.hosts[2]["installs"]) == 1
        lab.hosts[2].update(held)
        lab.before = None


class TestTheRolesOfACertificateAreBoundByOrder:
    """Q201 (AQ1): a server certificate Jen issues carries `[bind address, SSH host]` in its SANs and DER keeps the order; the first name is the address the daemon serves, the last is the machine the helper
    installed it on, one name is both. Each role is compared with its OWN configured name (reviewer's list, through `record_state` and the real route)."""

    @staticmethod
    def _arrange(lab, names, ssh_host, url_host):
        lab.hold_certificate_naming(2, names)
        lab.servers[2]["ssh_host"] = ssh_host
        lab.urls[2] = f"https://{url_host}:8004"
        extensions.KEA_SERVERS[:] = list(lab.servers.values())

    @staticmethod
    def _state(lab):
        return kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])

    def test_ssh_and_api_identical_is_jens(self, lab):
        self._arrange(lab, ["10.0.0.6"], "10.0.0.6", "10.0.0.6")
        assert self._state(lab) == ("jen", "")
        _rotate()
        assert "Kea CA rotated" in lab.texts(), lab.texts()

    def test_different_names_unchanged_is_jens(self, lab):
        self._arrange(lab, ["10.0.0.6", "kea-b.lan"], "kea-b.lan", "10.0.0.6")
        assert self._state(lab) == ("jen", "")

    @pytest.mark.parametrize(
        ("ssh_host", "url_host"),
        [
            ("10.0.0.6", "10.0.0.6"),  # the SSH host changed to the PREVIOUS API NAME (the reviewer's row 1)
            ("10.0.0.6", "kea-b.lan"),  # the roles swapped
            ("10.0.0.9", "10.0.0.6"),  # the SSH host to a third name
            ("kea-b.lan", "10.0.0.9"),  # the API changed, the SSH host constant
        ],
    )
    def test_a_role_that_does_not_match_its_own_name_is_refused_before_anything_is_installed(
        self, lab, ssh_host, url_host
    ):
        self._arrange(lab, ["10.0.0.6", "kea-b.lan"], ssh_host, url_host)
        assert self._state(lab)[0] == "refuse", self._state(lab)
        before, records = _hosts_state(lab), _records(2)
        _rotate()
        assert "Rotate refused" in lab.texts() and "Kea CA rotated" not in lab.texts(), lab.texts()
        assert lab.remote_actions() == 0 and _hosts_state(lab) == before and _records(2) == records
        lab.before = None

    def test_the_roles_are_read_from_the_order_never_from_the_type(self, lab):
        mixed = _commit_naming(79, ["10.0.0.6", "kea-b.lan"])
        reversed_ = _commit_naming(78, ["kea-b.lan", "10.0.0.6"])
        from cryptography import x509

        def cert_of(files):
            return x509.load_pem_x509_certificate(files["server.crt"].encode())

        assert kea_tls._certificate_roles(cert_of(mixed)) == ("10.0.0.6", "kea-b.lan")
        assert kea_tls._certificate_roles(cert_of(reversed_)) == ("kea-b.lan", "10.0.0.6")
        ca_cert, ca_key = kea_tls._load_ca()
        bare = kea_tls._leaf(ca_cert, ca_key, kea_tls._new_key(), "no san", [], client=False)
        assert kea_tls._certificate_roles(bare) == (None, None)
        lab.before = None

    def test_a_one_name_certificate_accepts_that_name_in_both_roles(self, lab):
        self._arrange(lab, ["10.0.0.6"], "10.0.0.6", "10.0.0.6")
        assert self._state(lab) == ("jen", "")
        # Q204 AT5 a: the two rows that followed said a mapped spelling of either role was accepted; neither is (see test_an_alias_of_the_same_host_is_jens)
        self._arrange(lab, ["10.0.0.6"], "::ffff:10.0.0.6", "10.0.0.6")
        assert self._state(lab)[0] == "refuse"
        self._arrange(lab, ["10.0.0.6"], "10.0.0.6", "[::ffff:10.0.0.6]")
        assert self._state(lab)[0] == "refuse"

    def test_a_hand_built_certificate_with_the_names_reversed_is_judged_by_its_order(self, lab):
        """Whatever a human thinks the roles are: the first name is the address it serves, the last is the machine it was installed on."""
        self._arrange(lab, ["kea-b.lan", "10.0.0.6"], "kea-b.lan", "10.0.0.6")
        state, why = self._state(lab)
        assert state == "refuse" and "names 10.0.0.6 as the machine it was installed on" in why, (state, why)

    def test_the_second_wall_refuses_a_prev_pair_whose_ssh_role_name_is_not_the_configured_host(self, lab):
        _give_prev(2)
        lab.servers[2]["ssh_host"] = "10.0.0.77"
        before = _hosts_state(lab)
        result = infra._put_tls_back(lab.servers[2], "dhcp4")
        assert result["remote"] == "failed" and result.get("why") == "another-machine", result
        assert "names another machine" in infra._not_put_back_reason(result)
        assert infra._reinstall_live_material(lab.servers[2], "dhcp4") == "failed"
        assert lab.remote_actions() == 0 and _hosts_state(lab) == before, "no machine was asked anything"
        lab.before = None

    def test_the_rollback_never_installs_host_As_pair_on_host_B_observed_by_machine(self, lab):
        _give_prev(2, stale=True)
        lab.servers[2]["ssh_host"] = lab.servers[1]["ssh_host"]  # B is now machine 1
        before = _hosts_state(lab)
        assert infra._put_tls_back(lab.servers[2], "dhcp4")["remote"] == "failed"
        assert lab.hosts[1]["installs"] == [] and _hosts_state(lab) == before
        lab.before = None

    def test_two_servers_with_swapped_ssh_hosts_are_both_refused(self, lab):
        one, two = lab.servers[1]["ssh_host"], lab.servers[2]["ssh_host"]
        lab.servers[1]["ssh_host"], lab.servers[2]["ssh_host"] = two, one
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        before = _hosts_state(lab)
        _rotate()
        texts = lab.texts()
        assert "Rotate refused" in texts and texts.count("a different machine") >= 2, texts
        assert lab.remote_actions() == 0 and _hosts_state(lab) == before
        lab.before = None


class TestARecoveryJudgesTheRecordGroup:
    """Q201 (AQ2): a damaged-CA recovery judges the record GROUP by `host_material`'s rule - the live certificate when it loads, the `.prev` one when stale-marked or when the live one is absent or
    unreadable, never `.staged` - and REFUSES a group that has files and no certificate to compare. A record with no files at all keeps the recovery's override, by design."""

    STATES = ["live", "prev-only", "prev-stale", "prev-earlier-ca", "prev-unreadable", "lone-key", "lone-marker"]
    MOVES = ["ssh-third", "ssh-parked", "url-other"]

    @staticmethod
    def _state(lab, name):
        crt, key = kea_tls.server_copy_path(2, "dhcp4"), kea_tls.server_key_path(2, "dhcp4")
        if name == "live":
            return
        if name == "prev-earlier-ca":
            # a pair signed by a Jen CA that is neither the live one nor the previous one (the shape of "two rotations ago"), without rotating the Lab's world
            staged = kea_tls.stage_rotation()
            try:
                files = kea_tls.issue_server_cert(
                    lab.servers[2], "dhcp4", "10.0.0.6", ca=(staged["ca_cert"], staged["ca_key"]), commit=False
                )
            finally:
                kea_tls.discard_rotation(staged)
            os.unlink(crt)
            os.unlink(key)
            pathlib.Path(crt + ".prev").write_text(files["server.crt"], encoding="ascii")
            pathlib.Path(key + ".prev").write_text(files["server.key"], encoding="ascii")
        elif name in ("prev-only", "prev-stale", "prev-unreadable"):
            os.replace(crt, crt + ".prev")
            os.replace(key, key + ".prev")
            if name == "prev-stale":
                kea_tls.mark_stale(2, "dhcp4")
            if name == "prev-unreadable":
                pathlib.Path(crt + ".prev").write_text("not a certificate", encoding="ascii")
        elif name == "lone-key":
            os.unlink(crt)
        elif name == "lone-marker":
            os.unlink(crt)
            os.unlink(key)
            pathlib.Path(crt + ".stale").write_bytes(b"")

    @staticmethod
    def _move(lab, name):
        if name == "ssh-third":
            lab.servers[2]["ssh_host"] = "10.0.0.77"
        elif name == "ssh-parked":
            lab.add_server(3, "parked", "10.0.0.8", "http://10.0.0.8:8004", jen_issued=True)
            lab.servers[2]["ssh_host"] = "10.0.0.8"
        else:
            lab.urls[2] = "https://10.0.0.5:8004"
        extensions.KEA_SERVERS[:] = list(lab.servers.values())

    @pytest.mark.parametrize("move", MOVES)
    @pytest.mark.parametrize("state", STATES)
    def test_the_recovery_refuses_every_group_that_is_not_proved_to_belong_to_the_configured_host(
        self, lab, state, move
    ):
        self._state(lab, state)
        self._move(lab, move)
        os.unlink(kea_tls.ca_paths()[1])  # the CA is damaged: a recovery
        before = _hosts_state(lab)
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "Rotate refused" in texts and "Kea CA rotated" not in texts, (state, move, texts)
        assert lab.remote_actions() == 0, "refused before any install or restart"
        assert _hosts_state(lab) == before, "every machine's files are byte-equal"
        lab.before = None

    def test_a_recovery_does_not_accept_host_B_because_the_live_crt_is_missing(self, lab):
        """THE critical assertion (the reviewer's): if the surviving certificate belongs to host A and Jen is configured to modify host B, a recovery does not accept B because the live `.crt` is missing."""
        crt, key = kea_tls.server_copy_path(2, "dhcp4"), kea_tls.server_key_path(2, "dhcp4")
        os.replace(crt, crt + ".prev")
        os.replace(key, key + ".prev")  # the surviving certificate belongs to host A (10.0.0.6)
        os.unlink(kea_tls.ca_paths()[1])
        lab.servers[2]["ssh_host"] = "10.0.0.77"  # Jen is configured to modify host B
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        before = _hosts_state(lab)
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Rotate refused" in lab.texts() and "a different machine" in lab.texts(), lab.texts()
        assert lab.remote_actions() == 0 and _hosts_state(lab) == before
        assert os.path.lexists(crt + ".prev") and os.path.lexists(key + ".prev"), "every file is preserved on a refusal"
        lab.before = None

    def test_a_record_with_no_files_at_all_keeps_the_recovery_override_by_design(self, lab):
        crt, key = kea_tls.server_copy_path(2, "dhcp4"), kea_tls.server_key_path(2, "dhcp4")
        os.unlink(crt)
        os.unlink(key)
        os.unlink(kea_tls.ca_paths()[1])
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        lab.before = None

    def test_the_ordinary_sentence_names_the_moved_host_for_a_prev_only_group(self, lab):
        crt, key = kea_tls.server_copy_path(2, "dhcp4"), kea_tls.server_key_path(2, "dhcp4")
        os.replace(crt, crt + ".prev")
        os.replace(key, key + ".prev")
        state, why = kea_tls.record_state(
            2, "dhcp4", server={**lab.servers[2], "ssh_host": "10.0.0.77"}, url=lab.urls[2]
        )
        assert state == "refuse" and "SSH host is now 10.0.0.77" in why, (state, why)
        os.replace(crt + ".prev", crt)
        os.replace(key + ".prev", key)  # (the world back as it was)
        lab.before = None


class TestRotationBookkeepingIsDurable:
    """Q201 (AQ3): a rotation's bookkeeping is written BEFORE the first remote change (a `rotation-pending` note per record it does not rotate), read back, finished from Jen's files after the commit, and a
    note that could not be finished stays pending and is said - never lost."""

    @staticmethod
    def _ghost(lab, sid=79, files="pair"):
        ghost = {"id": sid, "name": "ghost", "ssh_host": f"10.0.0.{sid}"}
        lab.urls[sid] = f"http://10.0.0.{sid}:8004"
        lab.servers[sid] = ghost
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        if files == "pair":
            kea_tls.issue_server_cert(ghost, "dhcp4", f"10.0.0.{sid}")
        elif files == "key":
            _write_record(sid, ["key"])
        return ghost

    @staticmethod
    def _failing(monkeypatch, *categories):
        real = kea_changeset.record_attention

        def wrapper(sid, svc, op, category, *a, **k):
            return False if category in categories else real(sid, svc, op, category, *a, **k)

        monkeypatch.setattr(kea_changeset, "record_attention", wrapper)
        return real

    @staticmethod
    def _pending(lab):
        return [i for i in lab.incidents if i[2] == "rotation-pending"]

    def test_all_writes_succeed(self, lab):
        self._ghost(lab)
        lab.before = None
        _rotate()
        assert "Kea CA rotated" in lab.texts() and (79, "dhcp4", "tls-superseded") in lab.incidents
        assert self._pending(lab) == []

    def test_the_store_unavailable_before_the_rotation_refuses_it_before_staging(self, lab, monkeypatch):
        self._ghost(lab)
        self._failing(monkeypatch, "rotation-pending")
        ca = _ca_bytes()
        lab.before = None
        _rotate()
        texts = lab.texts()
        assert "Rotate refused" in texts and "does not start" in texts, texts
        assert lab.remote_actions() == 0 and _ca_bytes() == ca
        assert any("not stored: rotation-pending" in str(a) for a in lab.audits), lab.audits

    def test_the_store_failing_after_the_installs_before_the_commit_rolls_back_and_clears_the_notes(
        self, lab, monkeypatch
    ):
        self._ghost(lab)
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        lab.before = None
        _rotate()
        assert "Kea CA rotated" not in lab.texts()
        assert self._pending(lab) == [], lab.incidents

    def test_the_store_failing_after_the_commit_leaves_the_note_pending_says_so_and_health_only_names_it(
        self, lab, monkeypatch
    ):
        self._ghost(lab)
        real = self._failing(monkeypatch, "tls-superseded")
        lab.before = None
        _rotate()
        texts = lab.texts()
        assert "Kea CA rotated" in texts and "could not be updated" in texts and "finishes it" in texts, texts
        assert (79, "dhcp4", "rotation-pending") in lab.incidents and (
            79,
            "dhcp4",
            "tls-superseded",
        ) not in lab.incidents
        assert any("rotation-pending left for ghost kea-dhcp4" in str(a) for a in lab.audits), lab.audits
        monkeypatch.setattr(kea_changeset, "record_attention", real)  # the store answers again ...
        row = health._kea_tls_expiry({})  # Health only READS: it names the note and writes nothing (second pass F1) ...
        assert self._pending(lab) and "is unfinished" in row.detail and "kea-dhcp4" in row.detail, row.detail
        assert (79, "dhcp4", "tls-superseded") not in lab.incidents
        kea_changeset.reconcile_rotation_pending(
            extensions.KEA_SERVERS
        )  # ... the next Rotate / Forget (under the identity lock) finishes it from the files
        assert (79, "dhcp4", "tls-superseded") in lab.incidents and self._pending(lab) == [], lab.incidents
        assert row.status in ("warn", "fail")

    def test_the_next_rotate_reconciles_a_pending_note_before_it_writes_new_ones(self, lab, monkeypatch):
        self._ghost(lab)
        real = self._failing(monkeypatch, "tls-superseded")
        lab.before = None
        _rotate()
        assert self._pending(lab)
        monkeypatch.setattr(kea_changeset, "record_attention", real)
        _rotate()
        assert (79, "dhcp4", "tls-superseded") in lab.incidents and self._pending(lab) == [], lab.incidents

    def test_a_failed_remote_unknown_for_an_orphan_is_left_pending(self, lab, monkeypatch):
        self._ghost(lab, files="key")
        real = self._failing(monkeypatch, "remote-unknown")
        lab.before = None
        _rotate()
        assert (79, "dhcp4", "rotation-pending") in lab.incidents and "could not be updated" in lab.texts()
        monkeypatch.setattr(kea_changeset, "record_attention", real)
        kea_changeset.reconcile_rotation_pending(extensions.KEA_SERVERS)
        assert (79, "dhcp4", "remote-unknown") in lab.incidents and self._pending(lab) == []

    def test_a_failed_superseded_after_a_forgotten_record_is_left_pending(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        _forget({"include_parked": "1"})
        assert (2, "dhcp4", "record-forgotten") in lab.incidents
        real = self._failing(monkeypatch, "tls-superseded")
        _rotate()
        assert (2, "dhcp4", "rotation-pending") in lab.incidents, lab.incidents
        monkeypatch.setattr(kea_changeset, "record_attention", real)
        kea_changeset.reconcile_rotation_pending(extensions.KEA_SERVERS)
        assert (2, "dhcp4", "tls-superseded") in lab.incidents and self._pending(lab) == []

    def test_the_pending_note_survives_a_restart(self, lab, monkeypatch):
        self._ghost(lab)
        self._failing(monkeypatch, "tls-superseded")
        lab.before = None
        _rotate()
        assert (79, "dhcp4", "rotation-pending") in [
            (i["server_id"], i["service"], i["category"]) for i in kea_changeset.recovery_incidents()
        ], "a new app on the same store reads the same incident"

    def test_an_unrelated_setup_does_not_clear_a_pending_note_and_a_verified_one_on_the_same_server_does(
        self, lab, monkeypatch
    ):
        self._ghost(lab)
        self._failing(monkeypatch, "tls-superseded")
        lab.before = None
        _rotate()
        kea_changeset.resolve_attention(2, "dhcp4")  # ANOTHER server's verified setup
        assert (79, "dhcp4", "rotation-pending") in lab.incidents
        kea_changeset.resolve_attention(79, "dhcp4")  # THE SAME server's: the dependency is gone
        assert self._pending(lab) == []

    def test_every_incident_result_the_route_reads_is_audited_when_false(self, lab, monkeypatch):
        self._ghost(lab)
        self._failing(monkeypatch, "tls-superseded", "rotation-pending")
        lab.before = None
        _rotate()
        assert any("DIRECT_SOCKET_INCIDENT" in str(a) or "not stored" in str(a) for a in lab.audits), lab.audits


class TestTheGroupVerdictIsOneJudgment:
    """Q201 (AQ6 f): a parked LIVE pair and an orphan are judged by the same function; a malformed certificate is `remote-unknown` in both; the stale marker is consulted before `.prev` is preferred; a pair
    from the PREPARED CA is never an earlier CA's."""

    @staticmethod
    def _ghost(lab, sid=79):
        ghost = {"id": sid, "name": "ghost", "ssh_host": f"10.0.0.{sid}"}
        lab.urls[sid] = f"http://10.0.0.{sid}:8004"
        lab.servers[sid] = ghost
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        return ghost

    def test_a_malformed_certificate_is_unknown_for_a_live_pair_and_for_an_orphan(self, lab):
        self._ghost(lab)
        _write_record(79, ["crt", "key"])  # placeholder bytes: a live pair that does not load
        assert kea_tls.group_verdict(79, "dhcp4") == "unknown"
        _rotate()
        assert (79, "dhcp4", "remote-unknown") in lab.incidents, lab.incidents
        lab.before = None

    def test_the_stale_marker_is_consulted_before_prev_is_preferred(self, lab):
        ghost = self._ghost(lab)
        kea_tls.issue_server_cert(ghost, "dhcp4", "10.0.0.79")
        _give_prev(79)
        crt = kea_tls.server_copy_path(79, "dhcp4")
        pathlib.Path(crt + ".prev").write_text("not a certificate", encoding="ascii")
        assert kea_tls.group_verdict(79, "dhcp4") == "current", "not stale: the LIVE certificate represents the host"
        kea_tls.mark_stale(79, "dhcp4")
        assert kea_tls.group_verdict(79, "dhcp4") == "unknown", "stale: the host holds .prev, which does not load"
        lab.before = None

    def test_a_pair_from_the_prepared_ca_is_never_an_earlier_cas(self, lab):
        ghost = self._ghost(lab)
        staged = kea_tls.stage_rotation()
        try:
            kea_tls.issue_server_cert(ghost, "dhcp4", "10.0.0.79", ca=(staged["ca_cert"], staged["ca_key"]))
            assert kea_tls.group_verdict(79, "dhcp4") == "current"
        finally:
            kea_tls.discard_rotation(staged)
        lab.before = None


class TestTheHealthAndTheFlashesTellTheStateTheyAreIn:
    """Q201 (AQ6 g, h)."""

    def test_a_forget_that_did_not_finish_on_a_record_that_is_live_again_does_not_say_press_forget(
        self, lab, monkeypatch
    ):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        crt = kea_tls.server_copy_path(2, "dhcp4")
        real = os.unlink

        def failing(path, *a, **k):
            if str(path) == crt:
                raise PermissionError(13, "denied")
            return real(path, *a, **k)

        monkeypatch.setattr(os, "unlink", failing)
        _forget({"include_parked": "1"})
        monkeypatch.setattr(os, "unlink", real)
        assert "press Forget stale records again" in health._kea_tls_expiry({}).detail
        lab.urls[2] = "https://10.0.0.6:8004"  # the server is an https endpoint again
        detail = health._kea_tls_expiry({}).detail
        assert "the record is live again" in detail and "press Forget stale records again" not in detail, detail
        lab.before = None

    def test_a_refused_forget_does_not_also_say_tick_the_box(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        monkeypatch.setattr(kea_changeset, "record_attention", lambda *a, **k: False)
        _forget({"include_parked": "1"})
        texts = lab.texts()
        assert "The record was kept" in texts and "tick the box beside Forget stale records" not in texts, texts

    def test_a_fact_stored_but_not_readable_says_so(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        monkeypatch.setattr(kea_changeset, "recovery_incidents", lambda strict=False: [])
        _forget({"include_parked": "1"})
        assert "stored but could not be read back" in lab.texts(), lab.texts()


class TestAScopedAddressIsRefused:
    """Q201 (AQ5): a spelling a validator accepts is a spelling a certificate can carry. DER has no interface scope, so a scoped IPv6 SSH host is refused (with the reason), and a scope is folded away when
    two addresses are compared, so a record saved before this release compares as its certificate reads."""

    def test_the_validator_refuses_a_scoped_literal_and_says_why(self):
        from jen.services import auth

        assert not auth.valid_ssh_target("fe80::1%eth0")
        assert "interface scope" in auth.ssh_target_problem("fe80::1%eth0")
        assert auth.valid_ssh_target("fe80::1") and auth.valid_ssh_target("kea-b.lan")
        assert auth.ssh_target_problem("kea-b.lan") == "" and auth.ssh_target_problem("fe80::1") == ""

    @pytest.mark.parametrize(
        ("configured", "named", "same"),
        [
            ("fe80::1%eth0", "fe80::1", True),
            ("fe80::1", "fe80::1%eth0", True),
            ("[fe80::1%eth0]", "fe80::1", True),
            ("fe80::1", "fe80::1", True),
            (
                "::ffff:10.0.0.6",
                "10.0.0.6",
                False,
            ),  # Q204 AT5 a: was True (the credential fold); the matcher half below agrees with False
            ("10.0.0.6", "::ffff:10.0.0.6", False),
            ("10.0.0.6", "10.0.0.7", False),
            ("Kea-B.lan", "kea-b.lan", True),
            ("kea-b.lan.", "kea-b.lan", False),
        ],
    )
    def test_the_spelling_table_is_judged_by_same_host_and_by_the_matcher_in_one_assertion(
        self, configured, named, same
    ):
        """Q202 (AR9 b, the pass's O4): the matcher half uses `urllib3.util.ssl_match_hostname.match_hostname` - always installed, the one `requests` dials with, and the one that ANSWERS for the scoped
        rows (`ssl.match_hostname` refused them, and was removed in Python 3.12, where the whole table used to skip)."""
        from urllib3.util.ssl_match_hostname import CertificateError, match_hostname

        assert kea_tls.names_match(configured, named) is same, (configured, named)
        try:
            ipaddress_named = ipaddress.ip_address(named)
            cert = {"subjectAltName": (("IP Address", str(ipaddress_named)),)}
        except ValueError:
            cert = {"subjectAltName": (("DNS", named),)}
        try:
            match_hostname(cert, configured.strip("[]"))
            accepted = True
        except (CertificateError, ValueError):
            accepted = False
        # Jen stricter than the matcher on an UNCHANGED input fails the test: what the matcher accepts, `names_match` must accept
        assert not accepted or kea_tls.names_match(configured, named), (configured, named)

    def test_the_shared_endpoint_parser_does_not_fold_a_scope(self):
        """Second pass F4 (CRED-002): the scope fold lives in the certificate-name comparison (`kea_tls.names_match`), NOT in the parser the credential rule shares - a scope names a different link, so two
        endpoints that differ in it stay different for a password."""
        from jen.services.auth import same_endpoint, same_host

        assert same_host("fe80::1%eth0", "fe80::1") is False
        assert same_endpoint("https://[fe80::1%eth0]:8000", "https://[fe80::1%eth1]:8000") is False
        assert same_endpoint("https://[fe80::1%eth0]:8000", "https://[fe80::1%eth0]:8000") is True


class TestTheSecondPassOfQ201:
    """The pre-release second pass on Q201: F1 (Health, a read path, erased the notes of a rotation that was RUNNING), F2 (a forgotten record was called superseded with no CA replaced), F3 (a refused forget
    also said there was nothing to forget), F4 (the scope fold weakened the credential comparison), F5 (a scoped SSH host saved before this release locked the forms)."""

    @staticmethod
    def _pending(lab):
        return [i for i in lab.incidents if i[2] == "rotation-pending"]

    def test_f1_health_during_a_running_rotation_writes_nothing_and_the_fact_survives(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        _forget_not_needed = None  # (server 2 is parked, with its record: a dependency the rotation owes a note for)
        seen = {}
        real = kea_host.install_tls

        def watching(server, service, files):
            if "during" not in seen:
                seen["before"] = list(lab.incidents)
                health._kea_tls_expiry({})  # a viewer's page load in the middle of the rotation
                seen["during"] = list(lab.incidents)
            return real(server, service, files)

        monkeypatch.setattr(kea_host, "install_tls", watching)
        lab.before = None
        _rotate()
        assert seen["during"] == seen["before"] and (2, "dhcp4", "rotation-pending") in seen["during"], seen
        assert "Kea CA rotated" in lab.texts()
        assert (2, "dhcp4", "tls-superseded") in lab.incidents and self._pending(lab) == [], lab.incidents

    def test_f2_a_forgotten_record_in_a_rotation_that_rolled_back_is_never_called_superseded(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        _forget({"include_parked": "1"})
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        real_resolve = kea_changeset.resolve_attention
        monkeypatch.setattr(
            kea_changeset,
            "resolve_attention",
            lambda sid, svc, *, categories=None: (
                0 if categories == ("rotation-pending",) else real_resolve(sid, svc, categories=categories)
            ),
        )
        _rotate()
        assert "could not be cleared" in lab.texts(), "the clear in the finally was refused and said so"
        assert (2, "dhcp4", "rotation-pending") in lab.incidents
        monkeypatch.setattr(kea_changeset, "resolve_attention", real_resolve)
        kea_changeset.reconcile_rotation_pending(extensions.KEA_SERVERS)
        assert (2, "dhcp4", "tls-superseded") not in lab.incidents, "the CA was never replaced"
        assert self._pending(lab) == [], "the pending note was dropped: the live CA is the one it was written under"

    def test_f2_a_note_written_under_a_ca_that_has_since_changed_is_finished_from_the_files(self, lab):
        ghost = {"id": 79, "name": "ghost", "ssh_host": "10.0.0.79"}
        lab.urls[79] = "http://10.0.0.79:8004"
        lab.servers[79] = ghost
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        _write_record(79, ["key"])
        kea_changeset.record_attention(
            79, "dhcp4", "op", "rotation-pending", server_name="ghost", ca_fingerprint=kea_tls.live_ca_fingerprint()
        )
        kea_changeset.reconcile_rotation_pending(extensions.KEA_SERVERS)
        assert not any(i[0] == 79 for i in lab.incidents), (
            "a crash false alarm: the CA is unchanged, the note is dropped"
        )
        kea_changeset.record_attention(
            79, "dhcp4", "op", "rotation-pending", server_name="ghost", ca_fingerprint="00" * 32
        )
        kea_changeset.reconcile_rotation_pending(extensions.KEA_SERVERS)
        assert (79, "dhcp4", "remote-unknown") in lab.incidents and self._pending(lab) == []
        lab.before = None

    def test_f3_a_refused_forget_does_not_also_say_there_were_no_stale_records(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        monkeypatch.setattr(kea_changeset, "record_attention", lambda *a, **k: False)
        _forget({"include_parked": "1"})
        assert "The record was kept" in lab.texts() and "There were no stale certificate records" not in lab.texts()


# ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# Q202 - the 5.69.1 review and the Opus pass's register, one Q (AR1-AR9)
# ══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════


def _memory_note_store(monkeypatch):
    """The incident note as one in-memory list behind the REAL `record_attention` / `resolve_attention` / `recovery_incidents` - what the choke point decides is tested on the product's own functions,
    not on the Lab's stand-in (the settings table itself is `tests/test_incident_store_locking.py`)."""
    import json

    from jen.models import user as user_mod

    store: list = []
    audits: list = []

    def with_attention(fn, strict=True):
        new = fn(copy.deepcopy(store))
        if new is not None:
            store[:] = new
        return True

    def get_setting(key, default="", strict=False):
        return json.dumps({"incidents": store}) if store else ""

    monkeypatch.setattr(kea_changeset, "_with_attention", with_attention)
    monkeypatch.setattr(user_mod, "get_global_setting", get_setting)
    monkeypatch.setattr(user_mod, "audit", lambda *a, **k: audits.append(a))
    return store


class TestAPendingNoteBelongsToItsGeneration:
    """Q202 (AR1, the reviewer's finding 1): a `rotation-pending` note belongs to the CA generation it was written under. `record_attention` refuses to refresh it under another fingerprint, the route
    reconciles an earlier generation's note BEFORE it starts and refuses when it cannot, and its failure path clears only its own notes. The reviewer's ten rows, through the real route with the Lab's
    store faults (and the product's own `record_attention` over an in-memory note for the choke point)."""

    @staticmethod
    def _ghost(lab, sid=79, files="pair"):
        return TestRotationBookkeepingIsDurable._ghost(lab, sid, files)

    @staticmethod
    def _failing(monkeypatch, *categories):
        return TestRotationBookkeepingIsDurable._failing(monkeypatch, *categories)

    @staticmethod
    def _pending(lab):
        return [i for i in lab.incidents if i[2] == "rotation-pending"]

    def _first_rotation_that_leaves_a_pending_note(self, lab, monkeypatch, sid=79):
        """CA A -> B committed, the `tls-superseded` write refused: the note of generation A is what remains."""
        ghost = self._ghost(lab, sid)
        fingerprint_a = kea_tls.live_ca_fingerprint()
        real = self._failing(monkeypatch, "tls-superseded")
        lab.before = None
        _rotate()
        assert "Kea CA rotated" in lab.texts() and (sid, "dhcp4", "rotation-pending") in lab.incidents, lab.texts()
        assert lab.incident_extra[(sid, "dhcp4", "rotation-pending")]["ca_fingerprint"] == fingerprint_a
        assert kea_tls.live_ca_fingerprint() != fingerprint_a, "the CA was replaced"
        return ghost, fingerprint_a, real

    def test_1_the_previous_note_reconciles_before_the_new_rotation_starts(self, lab, monkeypatch):
        _ghost, _fp, real = self._first_rotation_that_leaves_a_pending_note(lab, monkeypatch)
        monkeypatch.setattr(kea_changeset, "record_attention", real)  # the store answers again
        _rotate()
        assert "Kea CA rotated" in lab.request_texts(), lab.request_texts()
        assert (79, "dhcp4", "tls-superseded") in lab.incidents and self._pending(lab) == [], lab.incidents

    def test_2_a_previous_note_that_cannot_be_reconciled_refuses_the_new_rotation_before_staging(
        self, lab, monkeypatch
    ):
        _ghost, fingerprint_a, _real = self._first_rotation_that_leaves_a_pending_note(lab, monkeypatch)
        ca = _ca_bytes()
        _rotate()  # the store still refuses `tls-superseded`
        texts = lab.request_texts()
        assert "Rotate refused" in texts and "bookkeeping of an earlier rotation for ghost kea-dhcp4" in texts, texts
        assert "Nothing was changed" in texts and "Forget stale records finishes it" in texts
        assert lab.remote_actions() == lab.before["remote"], "no host was asked anything"
        assert _ca_bytes() == ca, "nothing was staged or promoted"
        assert lab.incident_extra[(79, "dhcp4", "rotation-pending")]["ca_fingerprint"] == fingerprint_a
        assert any(
            "refused: an earlier rotation's note is unfinished for ghost kea-dhcp4" in str(a) for a in lab.audits
        )

    def test_3_the_choke_point_refuses_to_refresh_a_note_of_another_generation_and_the_note_is_byte_equal(
        self, monkeypatch
    ):
        import json

        store = _memory_note_store(monkeypatch)
        assert kea_changeset.record_attention(
            79, "dhcp4", "op", "rotation-pending", server_name="ghost", ca_fingerprint="aa" * 32
        )
        before = json.dumps(store, sort_keys=True)
        assert (
            kea_changeset.record_attention(
                79, "dhcp4", "op B", "rotation-pending", server_name="ghost", ca_fingerprint="bb" * 32
            )
            is False
        )
        assert json.dumps(store, sort_keys=True) == before, "byte for byte"
        assert kea_changeset.record_attention(79, "dhcp4", "op C", "rotation-pending", server_name="ghost") is False, (
            "a live CA that cannot be read does not erase the generation either"
        )
        assert json.dumps(store, sort_keys=True) == before
        # the same generation refreshes, and every other category still does
        assert kea_changeset.record_attention(
            79, "dhcp4", "again", "rotation-pending", server_name="ghost", ca_fingerprint="aa" * 32
        )
        assert [i["summary"] for i in store] == ["again"]
        assert kea_changeset.record_attention(79, "dhcp4", "one", "tls-superseded")
        assert kea_changeset.record_attention(79, "dhcp4", "two", "tls-superseded")
        assert [i["summary"] for i in store if i["category"] == "tls-superseded"] == ["two"]
        # a note written when the CA could not be read (no fingerprint) is refreshed by the next one that has it
        store.clear()
        assert kea_changeset.record_attention(80, "dhcp4", "x", "rotation-pending")
        assert kea_changeset.record_attention(80, "dhcp4", "y", "rotation-pending", ca_fingerprint="cc" * 32)
        assert store[0]["ca_fingerprint"] == "cc" * 32

    def test_4_two_notes_for_two_servers_from_two_generations_coexist_with_their_own_fingerprints(self, monkeypatch):
        store = _memory_note_store(monkeypatch)
        assert kea_changeset.record_attention(79, "dhcp4", "g1", "rotation-pending", ca_fingerprint="aa" * 32)
        assert kea_changeset.record_attention(80, "dhcp4", "g2", "rotation-pending", ca_fingerprint="bb" * 32)
        assert {(i["server_id"], i["ca_fingerprint"]) for i in store} == {(79, "aa" * 32), (80, "bb" * 32)}

    def test_5_a_rotation_that_fails_after_its_notes_clears_only_its_own(self, lab, monkeypatch):
        """The earlier generation's note for server 79 is left in place by a reconcile that raced (patched to answer "nothing unfinished"); the new rotation writes its own note for server 78 FIRST, then
        meets 79's - the choke point refuses the refresh - and its failure path clears 78's note and not 79's."""
        self._ghost(lab, 78)
        self._ghost(lab, 79)
        lab.incidents.append((79, "dhcp4", "rotation-pending"))
        lab.incident_extra[(79, "dhcp4", "rotation-pending")] = {"server_name": "ghost", "ca_fingerprint": "aa" * 32}
        monkeypatch.setattr(kea_changeset, "reconcile_rotation_pending", lambda servers: [])
        ca = _ca_bytes()
        lab.before = None
        _rotate()
        assert "Rotate refused" in lab.texts() and lab.remote_actions() == 0 and _ca_bytes() == ca
        assert (78, "dhcp4", "rotation-pending") not in lab.incidents, "its own note was cleared"
        assert lab.incident_extra[(79, "dhcp4", "rotation-pending")]["ca_fingerprint"] == "aa" * 32, (
            "the earlier generation's note is intact"
        )
        assert (79, "dhcp4", "rotation-pending") in lab.incidents

    def test_5b_the_clear_ranges_only_over_what_it_is_given(self, lab):
        ghost = self._ghost(lab, 78)
        lab.incidents.append((79, "dhcp4", "rotation-pending"))
        lab.incidents.append((78, "dhcp4", "rotation-pending"))
        infra._clear_rotation_pending([(ghost, "dhcp4")])
        assert lab.incidents == [(79, "dhcp4", "rotation-pending")]
        lab.before = None

    def test_6_a_successful_new_rotation_finishes_its_own_notes_and_the_earlier_one_was_reconciled_first(
        self, lab, monkeypatch
    ):
        _ghost, _fp, real = self._first_rotation_that_leaves_a_pending_note(lab, monkeypatch)
        monkeypatch.setattr(kea_changeset, "record_attention", real)
        self._ghost(lab, 80)
        _rotate()
        assert "Kea CA rotated" in lab.request_texts(), lab.request_texts()
        assert (79, "dhcp4", "tls-superseded") in lab.incidents and (80, "dhcp4", "tls-superseded") in lab.incidents
        assert self._pending(lab) == []

    def test_7_the_store_fails_then_recovers_and_the_next_rotate_reconciles_and_proceeds(self, lab, monkeypatch):
        _ghost, _fp, real = self._first_rotation_that_leaves_a_pending_note(lab, monkeypatch)
        _rotate()
        assert "Rotate refused" in lab.request_texts()
        monkeypatch.setattr(kea_changeset, "record_attention", real)
        _rotate()
        assert "Kea CA rotated" in lab.request_texts(), lab.request_texts()
        assert (79, "dhcp4", "tls-superseded") in lab.incidents and self._pending(lab) == []

    def test_8_a_process_restart_between_the_attempts_changes_none_of_it(self, lab, monkeypatch):
        _ghost, fingerprint_a, real = self._first_rotation_that_leaves_a_pending_note(lab, monkeypatch)
        # a fresh process: the configuration is derived again (new dicts), the app is a new one (`_rotate` builds it), the store is whatever it holds
        extensions.KEA_SERVERS[:] = [dict(s) for s in lab.servers.values()]
        seen = [
            (i["server_id"], i["service"], i["category"], i.get("ca_fingerprint"))
            for i in kea_changeset.recovery_incidents()
        ]
        assert (79, "dhcp4", "rotation-pending", fingerprint_a) in seen
        _rotate()
        assert "Rotate refused" in lab.request_texts() and lab.remote_actions() == lab.before["remote"]
        assert lab.incident_extra[(79, "dhcp4", "rotation-pending")]["ca_fingerprint"] == fingerprint_a
        monkeypatch.setattr(kea_changeset, "record_attention", real)
        extensions.KEA_SERVERS[:] = [dict(s) for s in lab.servers.values()]
        _rotate()
        assert "Kea CA rotated" in lab.request_texts() and (79, "dhcp4", "tls-superseded") in lab.incidents

    def test_9_an_unrelated_operation_never_clears_the_notes(self, lab, monkeypatch):
        self._first_rotation_that_leaves_a_pending_note(lab, monkeypatch)
        kea_changeset.resolve_attention(2, "dhcp4")  # the verified setup of a THIRD server
        kea_changeset.resolve_attention(3, "dhcp6")
        _forget({})  # a Forget of a fourth (nothing stale): it finishes nothing and clears nothing it was not asked to
        assert (79, "dhcp4", "rotation-pending") in lab.incidents
        assert kea_changeset.acknowledge_recovery(None, None, None) in (0, None)
        assert (79, "dhcp4", "rotation-pending") in lab.incidents

    def test_10_the_critical_assertion_after_A_to_B_committed_and_B_to_C_refused_the_store_holds_exactly_the_a_note(
        self, lab, monkeypatch
    ):
        _ghost, fingerprint_a, _real = self._first_rotation_that_leaves_a_pending_note(lab, monkeypatch)
        _rotate()
        assert "Rotate refused" in lab.request_texts()
        assert lab.incidents == [(79, "dhcp4", "rotation-pending")], lab.incidents
        assert lab.incident_extra[(79, "dhcp4", "rotation-pending")]["ca_fingerprint"] == fingerprint_a

    def test_the_lab_store_mirrors_the_choke_point(self, lab):
        """The Lab's stand-in refuses a different generation the way the product does (so the route rows above exercise the route, not a store that always accepts)."""
        assert kea_changeset.record_attention(5, "dhcp4", "x", "rotation-pending", ca_fingerprint="aa" * 32)
        assert kea_changeset.record_attention(5, "dhcp4", "y", "rotation-pending", ca_fingerprint="bb" * 32) is False
        lab.before = None

    def test_the_route_reads_what_reconcile_returns(self):
        source = inspect.getsource(infra.rotate_kea_ca)
        assert "unfinished_before = __changeset.reconcile_rotation_pending(" in source
        assert "if unfinished_before:" in source


def _san_certificate(sid, extension, service="dhcp4"):
    """Commit a Jen-signed record for `sid` whose certificate carries exactly `extension` as its only SAN extension (None: no SAN extension at all) - the shapes the library can build."""
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    ca_cert, ca_key = kea_tls._load_ca()
    key = kea_tls._new_key()
    now = kea_tls._now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(kea_tls._name("kea-dhcp4 odd"))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - kea_tls._CLOCK_SKEW)
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(kea_tls._authority_key_identifier(ca_cert), critical=False)
    )
    if extension is not None:
        builder = builder.add_extension(extension, critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    files = {
        "ca.crt": kea_tls._cert_pem(ca_cert).decode(),
        "server.crt": kea_tls._cert_pem(cert).decode(),
        "server.key": kea_tls._key_pem(key).decode(),
    }
    kea_tls.commit_issued(sid, service, files)
    return cert, files


class TestACertificateThatNamesNothingProvesNothing:
    """Q202 (AR2, the reviewer's finding 2; the register's A8): a Jen-signed certificate with no DNS or IP name is refused wherever a role is judged - `record_state` (both branches), the setup's own-record
    check, the put-back. The reviewer's eleven rows."""

    NOTHING = "names no address and no machine"

    @staticmethod
    def _arrange_nameless(lab, extension):
        from cryptography import x509  # noqa: F401

        cert, files = _san_certificate(2, extension)
        lab.hosts[2]["files"] = lab.hosts[2]["loaded"] = copy.deepcopy(
            files
        )  # (the daemon loaded it: the record IS what the host holds)
        lab.answered_before[2] = lab.answers_jens_live_identity(2)
        return cert

    def test_1_one_san_names_both_roles_and_is_accepted(self, lab):
        TestTheRolesOfACertificateAreBoundByOrder._arrange(lab, ["10.0.0.6"], "10.0.0.6", "10.0.0.6")
        assert kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2]) == ("jen", "")

    def test_2_distinct_bind_and_ssh_sans_are_accepted(self, lab):
        TestTheRolesOfACertificateAreBoundByOrder._arrange(lab, ["10.0.0.6", "kea-b.lan"], "kea-b.lan", "10.0.0.6")
        assert kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2]) == ("jen", "")

    def test_3_roles_swapped_is_refused_with_the_role_sentence(self, lab):
        TestTheRolesOfACertificateAreBoundByOrder._arrange(lab, ["10.0.0.6", "kea-b.lan"], "10.0.0.6", "kea-b.lan")
        state, why = kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse" and "as the machine it was installed on" in why and self.NOTHING not in why
        lab.before = None

    def test_4_a_jen_signed_certificate_with_no_san_extension_is_refused_everywhere(self, lab):
        cert = self._arrange_nameless(lab, None)
        state, why = kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse" and self.NOTHING in why and "it has no subject alternative names" in why, (state, why)
        assert "set it up again, or restore the certificate Jen issued" in why
        inventory = kea_tls.rotation_inventory(
            extensions.KEA_SERVERS,
            url_for=lambda s, svc: lab.urls[s["id"]] if svc == "dhcp4" else "",
            prove_storage=False,
        )
        assert [t[0]["id"] for t in inventory.targets] == [1] and len(inventory.refusals) == 1, inventory.refusals
        assert kea_tls._certificate_roles(cert) == (None, None)
        _rotate()
        assert "Rotate refused" in lab.texts() and lab.remote_actions() == 0
        lab.before = None

    def test_5_a_san_extension_holding_only_an_rfc822_name_is_refused(self, lab):
        from cryptography import x509

        self._arrange_nameless(lab, x509.SubjectAlternativeName([x509.RFC822Name("ops@kea.example")]))
        state, why = kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse" and self.NOTHING in why and "hold no DNS or IP name" in why, (state, why)
        lab.before = None

    def test_6_only_an_unsupported_san_type_is_refused(self, lab):
        from cryptography import x509

        self._arrange_nameless(
            lab, x509.SubjectAlternativeName([x509.UniformResourceIdentifier("https://kea.example/")])
        )
        state, why = kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse" and self.NOTHING in why, (state, why)
        lab.before = None

    def test_7_a_malformed_san_extension_is_refused_with_the_does_not_parse_wording(self, lab):
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        self._arrange_nameless(
            lab, x509.UnrecognizedExtension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, b"\x30\x03\x01\x01\xff")
        )
        state, why = kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse" and self.NOTHING in why and "do not parse" in why, (state, why)
        lab.before = None

    def test_8_a_missing_ssh_identity_with_a_configured_ssh_host_is_refused(self, lab):
        cert = self._arrange_nameless(lab, None)
        assert self.NOTHING in kea_tls.ssh_host_refusal(cert, {"id": 2, "ssh_host": "10.0.0.6"})
        assert kea_tls.ssh_host_refusal(cert, {"id": 2, "ssh_host": ""}) == "", "a configured-empty host is not judged"
        lab.before = None

    def test_9_a_missing_bind_identity_with_a_configured_url_is_refused(self, lab):
        cert = self._arrange_nameless(lab, None)
        assert self.NOTHING in kea_tls._destination_refusal(cert, {"id": 2, "ssh_host": ""}, "https://10.0.0.6:8004")
        assert kea_tls._destination_refusal(cert, {"id": 2, "ssh_host": ""}, "") == ""
        lab.before = None

    def test_10_a_damaged_ca_recovery_over_a_nameless_record_is_refused_before_staging(self, lab):
        self._arrange_nameless(lab, None)
        os.unlink(kea_tls.ca_paths()[1])  # the CA is damaged: a recovery
        before = _hosts_state(lab)
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "Rotate refused" in texts and "Kea CA rotated" not in texts, texts
        assert self.NOTHING in texts, "the override does not rescue a group whose certificate names nothing"
        assert lab.remote_actions() == 0 and _hosts_state(lab) == before, "both machines byte-equal"
        lab.before = None

    def test_11_the_rotation_refuses_before_any_remote_install_on_either_machine(self, lab):
        self._arrange_nameless(lab, None)
        _rotate()
        assert lab.remote_actions() == 0
        assert all(not h["installs"] and h["restarts"] == 0 for h in lab.machines().values())
        lab.before = None

    @staticmethod
    def _empty_dns():
        from cryptography import x509

        return x509.SubjectAlternativeName([x509.DNSName("")])

    @staticmethod
    def _ip_network():
        import ipaddress

        from cryptography import x509

        return x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_network("10.0.0.0/24"))])

    def _both_branches_the_setup_check_and_the_put_back(self, lab, extension):
        cert = self._arrange_nameless(lab, extension)
        assert kea_tls._certificate_names(cert) == [] and kea_tls._certificate_roles(cert) == (None, None)
        state, why = kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse" and self.NOTHING in why, (state, why)
        assert "as the machine it was installed on" not in why and "as the address it serves" not in why, why
        assert "set it up again, or restore the certificate Jen issued" in why
        state_r, why_r = kea_tls.record_state(2, "dhcp4", recovery=True, server=lab.servers[2], url=lab.urls[2])
        assert state_r == "refuse" and self.NOTHING in why_r, (state_r, why_r)
        assert self.NOTHING in kea_tls.record_destination_refusal(2, "dhcp4", lab.servers[2], lab.urls[2])
        files = lab.hosts[2]["files"]
        assert infra._pair_is_for_another_machine(files, lab.servers[2]) is True
        lab.before = None

    def test_12_an_empty_dns_name_is_no_name(self, lab):
        """Q203 AS4 (the pass's N3): `_certificate_names` kept `str(g.value)` for every DNSName, so a certificate whose only SAN is an EMPTY DNS name read as roles `("", "")` and was refused by the ROLE sentence
        (whose remedy, 'set it up again on it', is the wrong one). One layer down from AR9 i: an empty name is no name, so both record_state branches, the setup's check and the put-back say AR2's sentence."""
        self._both_branches_the_setup_check_and_the_put_back(lab, self._empty_dns())

    def test_13_an_ip_network_is_no_name(self, lab):
        """Q203 AS4: `x509.IPAddress` carries networks too; a CIDR is a range, not the address a daemon serves, and read as its text it was the role sentence's 'machine'."""
        self._both_branches_the_setup_check_and_the_put_back(lab, self._ip_network())

    @pytest.mark.parametrize(
        "name",
        [
            " ",
            "*",
            ".",
            " . ",
            "*.",
            "...",
            "a\tb",
            "a\x00b",
            "*.kea.lan",
            "x" * 64 + ".lan",
            " kea-b.lan",
            "kea_b.lan",
        ],
    )
    def test_14_degenerate_dns_names_are_no_name(self, lab, name):
        """Q203 second pass G3: a DNS name of only spaces, dots and stars is no name, so AR2's sentence (the right remedy) answers, not the role sentence."""
        from cryptography import x509

        cert = self._arrange_nameless(lab, x509.SubjectAlternativeName([x509.DNSName(name)]))
        assert kea_tls._certificate_names(cert) == []
        state, why = kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse" and self.NOTHING in why, (state, why)
        lab.before = None

    def test_14b_a_wildcard_is_the_one_shape_jen_never_issues(self, lab):
        """Q204 AT5 b: this row said a wildcard with a domain "is still a name" (Q203). The certificate Jen issues carries a DNS name or an address, never a wildcard, and the verifier's own parser
        refuses the shape - so a certificate whose only DNS name is `*.kea.lan` names nothing a record can be judged by. Inverted on purpose (the Q202/Q203 rule 'filter by character' became 'filter by the parser')."""
        from cryptography import x509

        cert = self._arrange_nameless(lab, x509.SubjectAlternativeName([x509.DNSName("*.kea.lan")]))
        assert kea_tls._certificate_names(cert) == []
        lab.before = None

    @pytest.mark.parametrize("name", ["a\tb", "a\x00b", "*.kea.lan", "x" * 64 + ".lan", "kea_b.lan"])
    def test_14c_the_setup_and_the_put_back_read_the_same_parser_rows(self, lab, name):
        """Q204 AT5 b, the other branch: the setup's own-record check and the put-back (`record_destination_refusal`, `_pair_is_for_another_machine`) read the same names."""
        from cryptography import x509

        server = {"id": 96, "name": "odd", "ssh_host": "10.0.0.96"}
        _cert, files = _san_certificate(96, x509.SubjectAlternativeName([x509.DNSName(name)]))
        _give_prev(96)
        assert self.NOTHING in kea_tls.record_destination_refusal(96, "dhcp4", server, "")
        assert infra._pair_is_for_another_machine(files, server) is True
        kea_tls.discard_local_record(96, "dhcp4")
        lab.before = None

    def test_12b_the_names_a_certificate_carries_are_dns_names_and_addresses_only(self, lab):
        import ipaddress

        from cryptography import x509

        mixed = x509.SubjectAlternativeName(
            [
                x509.DNSName(""),
                x509.IPAddress(ipaddress.ip_network("10.9.0.0/16")),
                x509.IPAddress(ipaddress.ip_address("10.0.0.6")),
                x509.DNSName("kea-b.lan"),
            ]
        )
        cert = self._arrange_nameless(lab, mixed)
        assert kea_tls._certificate_names(cert) == ["10.0.0.6", "kea-b.lan"]
        assert kea_tls._certificate_roles(cert) == ("10.0.0.6", "kea-b.lan")
        lab.before = None

    def test_the_setup_and_the_put_back_refuse_a_nameless_pair(self, lab):
        server = {"id": 95, "name": "nameless", "ssh_host": "10.0.0.95"}
        _cert, files = _san_certificate(95, None)
        _give_prev(95)
        assert self.NOTHING in kea_tls.record_destination_refusal(95, "dhcp4", server, "")
        assert infra._pair_is_for_another_machine(files, server) is True
        assert infra._pair_is_for_another_machine(files, {"id": 95, "ssh_host": ""}) is False, (
            "nothing configured: nothing to judge"
        )
        kea_tls.discard_local_record(95, "dhcp4")
        lab.before = None

    def test_the_admin_guides_stricter_table_says_it(self):
        text = pathlib.Path("docs/admin-guide.md").read_text(encoding="utf-8")
        assert "no DNS or IP name" in text and "openssl verify" in text


class TestACertificateNameIsJudgedAsTheVerifierJudgesIt:
    """Q204 AT5 (M21 P2, M8/M22/M23 P3): `names_match` answered through `auth.same_host`, whose IPv4-mapped fold (Q188 AD9) is the credential rule's "same place for a SECRET" and is NOT the rule
    any TLS verifier uses for a SAN: SAN `::ffff:a00:9` against the dial host `10.0.0.9` was True for Jen and "does not match" for openssl and urllib3, both directions. And Jen produced that record from
    a configuration every saver accepted. The comparison is the verifier's (addresses equal, A-labels equal, no fold); the issuance refuses the spelling before a leaf exists."""

    MAPPED, PLAIN = "::ffff:10.0.0.9", "10.0.0.9"
    MAPPED_SAN = str(ipaddress.ip_address("::ffff:10.0.0.6"))  # how a SAN prints it (`::ffff:a00:6` before Python 3.13)
    TABLE = [
        ("::ffff:a00:9", "10.0.0.9", False),
        ("10.0.0.9", "::ffff:a00:9", False),
        ("::ffff:10.0.0.9", "10.0.0.9", False),
        ("::ffff:10.0.0.9", "::ffff:a00:9", True),
        ("fe80::1%eth0", "fe80::1", True),
        ("[fd00::5]", "FD00:0:0:0:0:0:0:5", True),
        ("kea-a", "KEA-A", True),
        ("kea-a.", "kea-a", False),
        ("kea-a", "kea-a.", False),
        ("kea-a", "kea-b", False),
        ("10.0.0.9", "10.0.0.9", True),
        ("10.0.0.9", "kea-a", False),
        ("", "", False),
        ("kea-a", "", False),
    ]

    @pytest.mark.parametrize("a,b,expected", TABLE)
    def test_the_comparison_table(self, a, b, expected):
        assert kea_tls.names_match(a, b) is expected
        assert kea_tls.names_match(b, a) is expected, "symmetric"

    def test_names_match_agrees_with_the_librarys_own_verifier_on_real_leaves(self):
        """The oracle Jen ships (`verify_issued`, the library's chain verifier; `openssl` is not on the dev box): a leaf whose only SAN is the first name, verified for the second as a server name."""
        from cryptography import x509

        key = kea_tls._new_key()
        ca = kea_tls._build_ca(key, "q204 oracle")

        def verdict(cert_name, dial):
            san = (
                x509.IPAddress(ipaddress.ip_address(cert_name))
                if kea_tls._is_ip(cert_name)
                else x509.DNSName(cert_name)
            )
            leaf = kea_tls._leaf(ca, key, kea_tls._new_key(), "cn", [san], client=False)
            return kea_tls.verify_issued(ca, leaf, False, dial) == ""

        for cert_name, dial, expected in [
            ("::ffff:a00:9", "10.0.0.9", False),
            ("10.0.0.9", "::ffff:a00:9", False),
            ("::ffff:10.0.0.9", "::ffff:a00:9", True),
            ("fd00::5", "FD00:0:0:0:0:0:0:5", True),
            ("kea-a", "KEA-A", True),
            ("KEA-A", "kea-a", True),
            ("kea-a", "kea-a.", False),
            ("kea-a", "kea-b", False),
        ]:
            assert verdict(cert_name, dial) is expected, (cert_name, dial)
            assert kea_tls.names_match(cert_name, dial) is expected, (cert_name, dial)

    def test_the_verifier_refuses_the_mapped_spelling_and_accepts_the_plain_ones(self):
        assert kea_tls.verifier_accepts_name(self.MAPPED) is False
        assert kea_tls.verifier_accepts_name("[::ffff:a00:9]") is False
        for ok in (self.PLAIN, "fd00::5", "[fd00::5]", "kea-a", "kea-a.example.com"):
            assert kea_tls.verifier_accepts_name(ok) is True, ok

    def test_every_saver_and_the_san_refuse_the_mapped_spelling_with_the_sentence(self):
        from jen.services import auth

        assert auth.valid_ssh_target(self.MAPPED) is False
        assert auth.valid_ssh_target(self.PLAIN) is True and auth.valid_ssh_target("fd00::5") is True
        assert "IPv4-mapped" in auth.ssh_target_problem(self.MAPPED)
        url = f"https://[{self.MAPPED}]:8004"
        assert auth.valid_api_url(url, require_port=True, certificate_name=True) is False
        assert auth.dns_name_sentence(url, require_port=True) == auth.MAPPED_ADDRESS_SENTENCE
        # the plain and the plain-IPv6 spellings pass; the same mapped address as an http URL (no certificate) is not a certificate question
        assert auth.valid_api_url("https://10.0.0.9:8004", require_port=True, certificate_name=True) is True
        assert auth.valid_api_url("https://[fd00::5]:8004", require_port=True, certificate_name=True) is True
        assert auth.valid_api_url(f"http://[{self.MAPPED}]:8004", require_port=True, certificate_name=True) is True
        assert kea_tls._san_for(self.MAPPED) is None
        assert kea_tls._san_for(self.PLAIN) is not None and kea_tls._san_for("fd00::5") is not None
        # the credential rule is untouched: for a SECRET the two spellings are one place
        assert auth.same_host(f"https://[{self.MAPPED}]:8004", f"https://{self.PLAIN}:8004") is True

    def test_the_bind_wall_names_the_mapped_spelling_in_the_setup_route(self):
        src = pathlib.Path("jen/routes/settings/infrastructure.py").read_text(encoding="utf-8")
        wall = src[src.index("The bind address must be an IP literal on the Kea host") :]
        assert "is_v4_mapped_literal(address)" in wall[:900] and "MAPPED_ADDRESS_SENTENCE" in wall[:900]

    def test_issue_server_cert_refuses_a_mapped_bind_or_ssh_host_before_a_leaf_exists(self, lab):
        for server, bind in (
            ({"id": 97, "name": "m", "ssh_host": "10.0.0.97"}, self.MAPPED),
            ({"id": 97, "name": "m", "ssh_host": self.MAPPED}, "10.0.0.9"),
        ):
            with pytest.raises(kea_tls.NameRefused) as e:
                kea_tls.issue_server_cert(server, "dhcp4", bind, commit=False)
            assert e.value.names == [self.MAPPED] and "different name" in e.value.why
        remedy = kea_tls.name_refusal_remedy([self.MAPPED])
        assert "change the address saved for it" in remedy
        lab.before = None

    def _hold_mapped(self, lab, *, ssh_host, url):
        from cryptography import x509

        cert, files = _san_certificate(
            2, x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("::ffff:10.0.0.6"))])
        )
        lab.hosts[2]["files"] = lab.hosts[2]["loaded"] = copy.deepcopy(files)
        lab.servers[2]["ssh_host"] = ssh_host
        lab.machine_addr[2] = ssh_host
        lab.urls[2] = url
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        lab.answered_before[2] = lab.answers_jens_live_identity(2)
        return cert

    def test_a_record_saved_before_this_release_with_the_mapped_ssh_host_and_a_plain_url_is_refused(self, lab):
        """Opus's `v12_mapped.py` world: the SAN is the mapped spelling and Jen dials the plain one. `record_state` said `jen`; it now reads as refused, and a rotation changes nothing."""
        self._hold_mapped(lab, ssh_host="::ffff:10.0.0.6", url="https://10.0.0.6:8004")
        state, _why = kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse", state
        before = _hosts_state(lab)
        _rotate()
        assert "Rotate refused" in lab.texts() and lab.remote_actions() == 0 and _hosts_state(lab) == before
        lab.before = None

    def test_a_record_saved_with_the_mapped_spelling_everywhere_is_refused_at_the_rotation_never_silently_reissued(
        self, lab
    ):
        self._hold_mapped(lab, ssh_host="::ffff:10.0.0.6", url="https://[::ffff:10.0.0.6]:8004")
        assert kea_tls.rotation_bind(2, "dhcp4", lab.urls[2]) == self.MAPPED_SAN
        before = _hosts_state(lab)
        _rotate()
        texts = lab.texts()
        assert f"the CA cannot issue its certificate for {self.MAPPED_SAN}" in texts and "different name" in texts, (
            texts
        )
        assert "nothing was installed on any host" in texts and lab.remote_actions() == 0
        assert _hosts_state(lab) == before, "no file on any host changed"
        lab.before = None

    def test_the_names_a_certificate_carries_are_the_parsers_names(self, lab):
        from cryptography import x509

        mixed = x509.SubjectAlternativeName(
            [
                x509.DNSName("a\tb"),
                x509.DNSName("a\x00b"),
                x509.DNSName("*.kea.lan"),
                x509.DNSName("x" * 64 + ".lan"),
                x509.DNSName("kea-b.lan"),
                x509.IPAddress(ipaddress.ip_address("::ffff:10.0.0.6")),
            ]
        )
        cert, _files = _san_certificate(94, mixed)
        assert kea_tls._certificate_names(cert) == ["kea-b.lan", self.MAPPED_SAN]
        kea_tls.discard_local_record(94, "dhcp4")
        lab.before = None

    def test_an_unchanged_exemption_never_admits_the_mapped_spelling(self):
        """Q204 second pass H3: the saved value `10.0.0.9` re-submitted as `::ffff:10.0.0.9` is a CHANGE (a different certificate name), so the saver validates it and refuses it."""
        from tests.probe import credential_probe as probe

        got = probe.q204_h3_an_unchanged_value_never_admits_the_mapped_spelling()
        assert got[("ssh", "::ffff:10.0.0.9")] is False and got[("url", "https://[::ffff:10.0.0.9]:8004")] is False
        assert got[("ssh", "10.0.0.9")] is True and got[("url", "https://10.0.0.9:8004/")] is True
        assert got[("ssh, saved mapped", "::ffff:10.0.0.9")] is True, (
            "a record saved earlier is not locked out of an unrelated save"
        )

    def test_dns_typed_text_that_reads_as_an_address_is_no_name(self, lab):
        from cryptography import x509

        mixed = x509.SubjectAlternativeName(
            [
                x509.DNSName("10.0.0.9"),
                x509.DNSName("[fd00::5]"),
                x509.DNSName("fe80::1%eth0"),
                x509.DNSName("kea-b.lan"),
            ]
        )
        cert, _files = _san_certificate(93, mixed)
        assert kea_tls._certificate_names(cert) == ["kea-b.lan"]
        kea_tls.discard_local_record(93, "dhcp4")
        lab.before = None

    def test_the_names_nothing_sentence_is_named_for_what_it_does(self):
        """It formats, it does not test: the test is `roles[1] is None` / `ssh_name is None` at its two call sites."""
        assert hasattr(kea_tls, "_names_nothing_sentence") and not hasattr(kea_tls, "_names_nothing")
        src = pathlib.Path("jen/services/kea_tls.py").read_text(encoding="utf-8")
        assert src.count("_names_nothing_sentence(") == 3, "the definition and its two call sites"

    def test_the_admin_guides_stricter_table_has_the_row(self):
        text = pathlib.Path("docs/admin-guide.md").read_text(encoding="utf-8")
        assert "IPv4-mapped" in text and "openssl" in text


class TestAGrandfatheredHostStaysOnItsRecord:
    """Q202 (AR3, the reviewer's finding 3 = the pass's O6/B3/A-6): a legacy SSH host (saved before a rule refused it) is `unchanged` only on its OWN record, judged by `same_host` and not by exact text. The
    reviewer's eleven rows through the two real routes, plus A-6's spellings. (The F5 test of 5.69.1 stopped at set membership and drove neither route; it is replaced by this class.)"""

    PRIMARY = "10.0.0.5"

    def _world(self, lab, monkeypatch, primary=None, extras=None):
        import configparser
        import io

        primary = self.PRIMARY if primary is None else primary
        extras = {2: "10.0.0.6"} if extras is None else extras
        ini = f"[kea]\napi_url = https://10.0.0.5:8004\napi_user = u\napi_pass = p\n\n[kea_ssh]\nhost = {primary}\nuser = jen\n"
        servers = [{"id": 1, "name": "kea-a", "ssh_host": primary, "api_url": "https://10.0.0.5:8004"}]
        for n, host in extras.items():
            ini += (
                f"\n[kea_server_{n}]\nname = srv{n}\nrole = standby\napi_url = https://10.0.1.{n}:8004\napi_user = u\napi_pass = p\n"
                f"ssh_host = {host}\nssh_user = jen\nkea_conf = /etc/kea/kea-dhcp4.conf\n"
            )
            servers.append({"id": n, "name": f"srv{n}", "ssh_host": host, "api_url": f"https://10.0.1.{n}:8004"})
        world = {"ini": ini, "calls": []}

        def parse(text):
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(text)
            return parser

        def fake_mutate(self_, fn, reload=True, typed=None):
            parser = parse(world["ini"])
            fn(parser)
            world["calls"].append(1)
            out = io.StringIO()
            parser.write(out)
            world["ini"] = out.getvalue()

        monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
        monkeypatch.setattr(extensions, "KEA_SSH_HOST", primary)
        monkeypatch.setattr(extensions, "cfg", parse(ini))
        monkeypatch.setattr(type(jconfig.app_config), "mutate", fake_mutate)
        monkeypatch.setattr(jconfig.app_config, "_read_parser", lambda: parse(world["ini"]))
        monkeypatch.setattr("jen.services.capabilities.is_direct", lambda: True)
        monkeypatch.setattr(infra, "current_user", types.SimpleNamespace(username="alice", is_authenticated=True))
        monkeypatch.setattr(infra.__dict__["__inv"], "removal_refusal", lambda *a, **k: "")
        monkeypatch.setattr(infra.__dict__["__user"], "set_global_setting", lambda *a, **k: True)
        world["parse"] = parse
        return world

    @staticmethod
    def _save_primary(host):
        app = flask.Flask(__name__)
        app.secret_key = "x"
        with app.test_request_context(method="POST", data={"host": host, "user": "jen"}):
            inspect.unwrap(infra.save_infra_ssh)()

    @staticmethod
    def _rows(*rows):
        keys = (
            "id",
            "name",
            "role",
            "api_url",
            "api_user",
            "api_pass",
            "api6_url",
            "api6_user",
            "api6_pass",
            "ssh_host",
            "ssh_user",
            "kea_conf",
        )
        return {f"extra_{k}[]": [r.get(k, "") for r in rows] for k in keys}

    @staticmethod
    def _row(n, host, name=None):
        return {
            "id": str(n) if n else "",
            "name": name or f"srv{n or 'new'}",
            "role": "standby",
            "api_url": f"https://10.0.1.{n or 9}:8004",
            "api_user": "u",
            "ssh_host": host,
            "ssh_user": "jen",
        }

    @staticmethod
    def _save_extras(**data):
        app = flask.Flask(__name__)
        app.secret_key = "x"
        with app.test_request_context(method="POST", data=data):
            inspect.unwrap(infra.save_extra_servers)()

    def _refused(self, lab):
        return "Invalid SSH host" in lab.texts()

    def test_1_an_unchanged_valid_primary_is_saved(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch)
        self._save_primary("10.0.0.5")
        assert world["calls"] and not self._refused(lab)

    def test_2_an_unchanged_legacy_scoped_primary_is_saved(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, primary="fe80::1%eth0")
        self._save_primary("fe80::1%eth0")
        assert world["calls"] and not self._refused(lab), lab.texts()

    def test_3_a_primary_changed_to_a_new_valid_address_is_saved(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, primary="fe80::1%eth0")
        self._save_primary("10.0.0.9")
        assert world["calls"] and not self._refused(lab)

    def test_4_a_primary_changed_to_a_new_scoped_literal_is_refused(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, primary="fe80::1%eth0")
        self._save_primary("fe80::9%eth0")
        assert self._refused(lab) and "interface scope" in lab.texts() and world["calls"] == []

    def test_5_an_unchanged_legacy_scoped_additional_server_is_saved(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, extras={2: "fe80::2%eth0"})
        self._save_extras(**self._rows(self._row(2, "fe80::2%eth0")))
        assert world["calls"] and not self._refused(lab), lab.texts()

    def test_6_the_primarys_legacy_host_copied_into_another_server_is_refused(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, primary="fe80::1%eth0", extras={2: "10.0.0.6"})
        self._save_extras(**self._rows(self._row(2, "fe80::1%eth0")))
        assert self._refused(lab) and world["calls"] == [], lab.texts()

    def test_7_one_additional_servers_legacy_host_copied_into_another_is_refused(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, extras={2: "fe80::2%eth0", 3: "10.0.0.7"})
        self._save_extras(**self._rows(self._row(2, "fe80::2%eth0"), self._row(3, "fe80::2%eth0")))
        assert self._refused(lab) and world["calls"] == [], lab.texts()

    def test_8_two_new_rows_with_the_same_legacy_host_are_refused(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, extras={2: "fe80::2%eth0"})
        self._save_extras(
            **self._rows(
                self._row(2, "fe80::2%eth0"),
                self._row(0, "fe80::2%eth0", "new-a"),
                self._row(0, "fe80::2%eth0", "new-b"),
            )
        )
        assert self._refused(lab) and world["calls"] == [], lab.texts()

    def test_9_rows_reordered_in_the_form_keep_their_own_exemption(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, extras={2: "fe80::2%eth0", 3: "fe80::3%eth0"})
        self._save_extras(**self._rows(self._row(3, "fe80::3%eth0"), self._row(2, "fe80::2%eth0")))
        assert world["calls"] and not self._refused(lab), lab.texts()

    def test_9b_a_row_that_swaps_two_servers_hosts_is_refused(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, extras={2: "fe80::2%eth0", 3: "fe80::3%eth0"})
        self._save_extras(**self._rows(self._row(2, "fe80::3%eth0"), self._row(3, "fe80::2%eth0")))
        assert self._refused(lab) and world["calls"] == [], "the id decides, not the position or the set"

    def test_10_an_unrelated_field_changed_with_a_legacy_host_resubmitted_is_saved_and_the_host_untouched(
        self, lab, monkeypatch
    ):
        world = self._world(lab, monkeypatch, extras={2: "fe80::2%eth0"})
        self._save_extras(**self._rows(self._row(2, "fe80::2%eth0", name="srv2-renamed")))
        assert world["calls"] and not self._refused(lab), lab.texts()
        saved = world["parse"](world["ini"])
        assert (
            saved.get("kea_server_2", "ssh_host") == "fe80::2%eth0"
            and saved.get("kea_server_2", "name") == "srv2-renamed"
        )

    def test_11_a_refused_save_leaves_the_configuration_byte_equal(self, lab, monkeypatch):
        world = self._world(lab, monkeypatch, primary="fe80::1%eth0", extras={2: "fe80::2%eth0"})
        before = world["ini"]
        self._save_primary("fe80::9%eth0")
        self._save_extras(**self._rows(self._row(2, "fe80::1%eth0")))
        assert world["calls"] == [] and world["ini"] == before

    @pytest.mark.parametrize(
        ("spelling", "unchanged"),
        [
            ("fe80::1%eth0", True),
            ("[fe80::1%eth0]", True),
            ("FE80::1%eth0", True),
            ("fe80:0:0:0:0:0:0:1%eth0", True),
            (
                "fe80::1%ETH0",
                False,
            ),  # DEVIATION NAMED (Q202 second pass F2): the Q said "as same_host decides" (it lower-cases the scope); a different interface name is a different target
            ("fe80::1%eth1", False),
            ("fe80::9%eth0", False),
            ("-oProxyCommand=x@[fe80::1%eth0]", False),
            ("evil@[fe80::1%eth0]", False),
            ("[fe80::1%eth0]$(id)", False),
            ("[fe80::1%eth0]/../x", False),
            ("fe80::1%eth0]", False),
            ("[fe80::1%eth0]'\";|&&id", False),
        ],
    )
    def test_a6_the_saved_hosts_other_spellings_are_unchanged_and_nothing_a_url_parser_reads_it_out_of_is(
        self, lab, monkeypatch, spelling, unchanged
    ):
        """A-6's spellings, each with its OWN expected answer (second pass F2: the first draft asserted whatever `same_host` said, and `same_host` is a URL-authority parser - it read the host out of every junk
        string above and the route SAVED it, `valid_ssh_target` bypassed)."""
        world = self._world(lab, monkeypatch, primary="fe80::1%eth0")
        self._save_primary(spelling)
        assert bool(world["calls"]) is unchanged, (spelling, lab.texts())

    def test_a_row_with_a_blank_id_that_is_exactly_a_saved_server_keeps_its_exemption(self, lab, monkeypatch):
        """Second pass F5: the Q199 AO2 adoption (a blank id, the saved SSH host and API address) is that server, so its legacy scoped host is unchanged."""
        world = self._world(lab, monkeypatch, extras={2: "fe80::2%eth0"})
        row = self._row(0, "fe80::2%eth0", "srv2")
        row["api_url"] = "https://10.0.1.2:8004"  # exactly server 2's saved address
        self._save_extras(**self._rows(row))
        assert world["calls"] and not self._refused(lab), lab.texts()

    def test_a_blank_id_row_beside_the_row_that_carries_the_saved_servers_id_is_a_new_server_and_is_refused(
        self, lab, monkeypatch
    ):
        """Second pass F5b (executed by the pass): the adoption must apply the rewrite's own conditions. Row 1 carries id 2; a SECOND row with a blank id, the same host and address becomes a NEW server in the
        rewrite, so it gets no exemption - the first draft of F5 saved it with the legacy scoped host (the copy hole AR3 closes)."""
        world = self._world(lab, monkeypatch, extras={2: "fe80::2%eth0"})
        kept = self._row(2, "fe80::2%eth0")
        twin = self._row(0, "fe80::2%eth0", "twin")
        twin["api_url"] = kea_url = "https://10.0.1.2:8004"
        assert kea_url == kept["api_url"]
        self._save_extras(**self._rows(kept, twin))
        assert self._refused(lab) and world["calls"] == [], lab.texts()

    def test_every_posted_ssh_host_is_validated(self, lab, monkeypatch):
        """Q203 AS5 (the pass's N18): the validation loop walked `zip(ids, ssh_hosts, api_urls, strict=False)`, so a form with fewer `extra_api_url[]` than `extra_ssh_host[]` never asked `valid_ssh_target`
        of the trailing hosts (contained by the writer's strict zip - dead validation, not a hole). A well-formed form asks it of EVERY posted host; a short-listed form is refused with the
        inconsistency sentence before `mutate`, and `jen.config` is byte-equal."""
        world = self._world(lab, monkeypatch, extras={})
        auth_module = infra.__dict__["__auth"]
        asked = []
        real = auth_module.valid_ssh_target
        monkeypatch.setattr(
            auth_module, "valid_ssh_target", lambda host, *a, **k: asked.append(host) or real(host, *a, **k)
        )
        first, second = self._row(0, "10.0.0.7", "new-a"), self._row(0, "10.0.0.8", "new-b")
        second["api_url"] = "https://10.0.1.10:8004"
        self._save_extras(**self._rows(first, second))
        assert asked == ["10.0.0.7", "10.0.0.8"], asked
        assert world["calls"] and not self._refused(lab), lab.texts()

        # second pass G5: any one of the twelve lists short refuses the same way, before `mutate`
        for short in (
            "extra_name[]",
            "extra_role[]",
            "extra_api_user[]",
            "extra_api_pass[]",
            "extra_api6_url[]",
            "extra_api6_user[]",
            "extra_api6_pass[]",
            "extra_ssh_user[]",
            "extra_kea_conf[]",
        ):
            world = self._world(lab, monkeypatch, extras={})
            before_short = world["ini"]
            body = self._rows(first, second)
            body[short] = body[short][:1]
            self._save_extras(**body)
            assert world["calls"] == [] and world["ini"] == before_short, short

        # the short-listed form: one API URL fewer than the SSH hosts
        world = self._world(lab, monkeypatch, extras={})
        before = world["ini"]
        asked.clear()
        body = self._rows(first, second)
        body["extra_api_url[]"] = body["extra_api_url[]"][:1]
        self._save_extras(**body)
        assert "form data was inconsistent" in lab.texts(), lab.texts()
        assert world["calls"] == [] and world["ini"] == before, (
            "nothing reached `mutate`; the configuration is byte-equal"
        )
        assert asked == [], "the refusal comes before any validation of a list that is not all there"

    def test_the_every_ssh_host_writer_holds_the_identity_lock(self):
        """Q202 AR9 e: the primary's `save_infra_ssh` was the one `ssh_host` writer outside the lock its five siblings hold."""
        for name in (
            "save_infra_ssh",
            "save_extra_servers",
            "setup_direct_socket",
            "rotate_kea_ca",
            "forget_stale_kea_records",
            "remove_direct_socket",
        ):
            assert getattr(getattr(infra, name), "__holds_identity_lock__", False), name

    def test_the_union_helper_is_gone(self):
        assert not hasattr(infra, "_saved_ssh_hosts"), "the exemption is per record: `_saved_ssh_host_for`"
        assert infra._saved_ssh_host_for(1) == (extensions.KEA_SSH_HOST or "").strip()
        assert infra._saved_ssh_host_for("999") == ""


class TestOneDaemonIsOneTargetParkedIncluded:
    """Q202 (AR4, the pass's A-1; closes A-2 and O5): the rotation asks the SETUP's own question of every target over the parked records too - one function, one signature - and the remedy sentences name
    the action the setup accepts."""

    @staticmethod
    def _twin(lab, scheme="http"):
        return lab.add_server(3, "twin", "10.0.0.5", f"{scheme}://10.0.0.5:8004", jen_issued=True)

    def test_a_parked_twin_of_a_target_refuses_the_rotation_before_staging_and_touches_no_machine(self, lab):
        self._twin(lab)
        before, records, ca = _hosts_state(lab), {1: _records(1), 3: _records(3)}, _ca_bytes()
        _rotate()
        texts = lab.texts()
        assert "Rotate refused" in texts and "twin already manages kea-dhcp4 on 10.0.0.5" in texts, texts
        assert (
            "one daemon, two records" in texts and "kea-a kea-dhcp4" in texts and "re-point it at its own host" in texts
        )
        assert lab.remote_actions() == 0 and _hosts_state(lab) == before and _ca_bytes() == ca
        assert {1: _records(1), 3: _records(3)} == records, "both records byte-equal"
        lab.before = None

    def test_the_same_world_with_the_twins_url_https_is_the_q196_row_unchanged(self, lab):
        self._twin(lab, "https")
        _rotate()
        assert "both manage kea-dhcp4 on 10.0.0.5" in lab.texts() and "already manages" not in lab.texts(), lab.texts()
        assert lab.remote_actions() == 0
        lab.before = None

    def test_the_remedy_executed_to_its_end_remove_one_record_and_the_rotation_proceeds(self, lab):
        twin = self._twin(lab)
        _rotate()
        assert "Rotate refused" in lab.texts()
        # the action the sentence names: remove ONE of the two records (here the twin's server, as the operator would)
        del lab.servers[3]
        del lab.urls[3]
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        kea_tls.discard_local_record(twin["id"], "dhcp4")
        del lab.hosts[3]
        _rotate()
        assert "Kea CA rotated" in lab.request_texts(), lab.request_texts()

    def test_a_record_whose_files_name_another_machine_is_still_a_twin_of_this_daemon(self, lab):
        """Q202 second pass F1: the first draft skipped a record whose certificate names another machine; a certificate that cannot say which daemon it is for is not evidence that it is not this one's
        (the absence of evidence is never evidence). The record still names this SSH host, so the rotation of the target refuses, with the twin's own sentence."""
        lab.servers[2]["ssh_host"] = lab.servers[1][
            "ssh_host"
        ]  # server 2 now names machine 1, its certificate names machine 2
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        assert kea_tls.other_record_on_same_daemon(lab.servers[1], "dhcp4", extensions.KEA_SERVERS) == "standby"
        lab.before = None

    def test_a_parked_twin_whose_certificate_names_nothing_still_refuses_the_rotation(self, lab):
        """Q202 second pass F1 (executed by the pass through the real route): a PARKED second record on the target's SSH host whose certificate has no SAN was hidden and the rotation ROTATED."""
        twin = self._twin(lab)
        os.unlink(kea_tls.server_copy_path(3, "dhcp4"))
        os.unlink(kea_tls.server_key_path(3, "dhcp4"))
        _san_certificate(3, None)
        lab.hosts[3]["files"] = lab.hosts[3]["loaded"] = None
        assert kea_tls.other_record_on_same_daemon(lab.servers[1], "dhcp4", extensions.KEA_SERVERS) == twin["name"]
        _rotate()
        assert "Rotate refused" in lab.texts() and "twin already manages" in lab.texts(), lab.texts()
        assert lab.remote_actions() == 0
        lab.before = None

    def test_q203_as3_an_external_twin_refuses_the_setup_and_the_rotation(self, lab):
        """Q203 AS3 (the pass's N2; Opus's `w3b_external_twin.py` world): a second record of the same daemon whose pair an administrator's CA issued (`external`) holds files at the fixed remote paths
        too. `other_record_on_same_daemon` counted only `jen`, `jen-stale` and `refuse`, so the rotation installed over what that record's endpoint is dialled on and the setup would have ALLOWED the
        second record. Every state but `none` counts."""
        twin = self._twin(lab)  # server 3, parked (http), on the same SSH host as server 1
        kea_tls.commit_issued(3, "dhcp4", _external_files("10.0.0.5"))
        assert kea_tls.record_state(3, "dhcp4", server=twin, url=lab.urls[3])[0] == "external"
        assert (
            kea_tls.other_record_on_same_daemon(lab.servers[1], "dhcp4", extensions.KEA_SERVERS) == "twin"
        )  # the setup's own question
        assert kea_tls.other_record_on_same_daemon(twin, "dhcp4", extensions.KEA_SERVERS) == "kea-a"
        before, records, ca = _hosts_state(lab), {1: _records(1), 3: _records(3)}, _ca_bytes()
        _rotate()
        assert "Rotate refused" in lab.texts() and "twin already manages kea-dhcp4 on 10.0.0.5" in lab.texts(), (
            lab.texts()
        )
        assert lab.remote_actions() == 0 and _hosts_state(lab) == before and _ca_bytes() == ca
        assert {1: _records(1), 3: _records(3)} == records, "both records byte-equal"
        lab.before = None

    def test_q203_as3_a_record_with_no_files_is_still_not_a_twin(self, lab):
        self._twin(lab)  # parked, but Jen holds nothing at all for it
        kea_tls.discard_local_record(3, "dhcp4")
        lab.hosts[3]["files"] = lab.hosts[3]["loaded"] = (
            None  # (and its host holds nothing: there is no daemon to keep answering)
        )
        lab.answered_before[3] = lab.answers_jens_live_identity(3)
        assert kea_tls.record_state(3, "dhcp4", server=lab.servers[3], url=lab.urls[3])[0] == "none"
        assert kea_tls.other_record_on_same_daemon(lab.servers[1], "dhcp4", extensions.KEA_SERVERS) == ""
        _rotate()
        assert "already manages" not in lab.texts(), lab.texts()
        lab.before = None

    def test_one_signature_and_the_rotation_and_the_setup_call_the_same_function(self):
        assert "for_setup" not in inspect.signature(kea_tls.other_record_on_same_daemon).parameters
        assert "other_record_on_same_daemon(" in inspect.getsource(kea_tls.rotation_inventory)
        assert "other_record_on_same_daemon(" in inspect.getsource(infra.setup_direct_socket)
        assert "for_setup" not in inspect.getsource(infra) and "for_setup" not in inspect.getsource(kea_tls)

    def test_health_names_the_action_the_setup_accepts_for_a_parked_twin(self, lab):
        self._twin(lab)
        lab.incidents.append((3, "dhcp4", "tls-superseded"))
        lab.incident_extra[(3, "dhcp4", "tls-superseded")] = {"server_name": "twin"}
        row = health._kea_tls_expiry({})
        assert (
            "shares that daemon with another record" in row.detail and "remove one of the two records" in row.detail
        ), row.detail
        assert "set it up again" not in row.detail, "ONE remedy, the one the setup accepts (second pass)"
        lab.before = None


class TestTheUrlIsJudgedByEveryName:
    """Q202 (AR5, the pass's B1 = A-3): the URL half is judged as the TLS stack judges it - ANY name the certificate carries; the SSH half stays all of its own (the LAST name). Opus's `v12_quantifier.py`
    table as tests: every refusal the reviewer's finding needs still fires, and the one row that changes - `api_url` to the machine's DNS name - is accepted, with a real handshake."""

    NAMES = ["10.0.0.6", "kea-b.lan"]  # the bind address first, the machine's name last

    @staticmethod
    def _state(lab, ssh_host, url_host):
        TestTheRolesOfACertificateAreBoundByOrder._arrange(lab, TestTheUrlIsJudgedByEveryName.NAMES, ssh_host, url_host)
        return kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])

    def test_the_url_to_the_machines_dns_name_is_accepted_and_a_real_handshake_to_that_name_verifies(self, lab):
        state = self._state(lab, "kea-b.lan", "kea-b.lan")
        assert state == ("jen", ""), state
        files = lab.hosts[2]["files"]
        import socket
        import ssl
        import threading

        ca = kea_tls.ca_paths()[0]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            crt, key = pathlib.Path(tmp, "s.crt"), pathlib.Path(tmp, "s.key")
            crt.write_text(files["server.crt"], encoding="ascii")
            key.write_text(files["server.key"], encoding="ascii")
            context.load_cert_chain(str(crt), str(key))
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]

            def serve():
                try:
                    conn, _addr = listener.accept()
                    with context.wrap_socket(conn, server_side=True):
                        pass
                except OSError:
                    pass

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            client = ssl.create_default_context(cafile=ca)
            try:
                with (
                    socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
                    client.wrap_socket(raw, server_hostname="kea-b.lan"),
                ):
                    verified = True
            except ssl.SSLError:
                verified = False
            finally:
                listener.close()
                worker.join(5)
        assert verified, "a TLS client dialling that name accepts the certificate: Jen's check is the verifier's"

    @pytest.mark.parametrize(
        ("ssh_host", "url_host", "why"),
        [
            ("10.0.0.6", "10.0.0.6", "the SSH host changed to the API name"),
            ("10.0.0.6", "kea-b.lan", "the roles swapped"),
            ("10.0.0.9", "10.0.0.6", "the SSH host to a third machine"),
            ("kea-b.lan", "10.0.0.9", "the URL to a name the certificate does not carry"),
        ],
    )
    def test_the_rows_the_reviewers_finding_needs_still_refuse(self, lab, ssh_host, url_host, why):
        state, _text = self._state(lab, ssh_host, url_host)
        assert state == "refuse", why
        lab.before = None

    def test_the_ssh_half_is_all_of_its_own_even_when_the_url_matches_the_other_name(self, lab):
        state, why = self._state(lab, "10.0.0.6", "kea-b.lan")
        assert state == "refuse" and "as the machine it was installed on" in why, (state, why)
        lab.before = None

    def test_a_target_dialled_at_the_machines_name_is_rotated_with_the_certificates_own_bind_address(self, lab):
        assert self._state(lab, "kea-b.lan", "kea-b.lan") == ("jen", "")
        inventory = kea_tls.rotation_inventory(
            extensions.KEA_SERVERS, url_for=lambda s, svc: lab.urls[s["id"]], prove_storage=False
        )
        binds = {t[0]["id"]: t[2] for t in inventory.targets}
        assert binds[2] == "10.0.0.6", "the daemon binds the ADDRESS; the URL's host is a name for it"
        lab.before = None

    def test_the_docstring_and_the_upgrade_note_say_it_truthfully(self):
        assert "a TLS client accepts any name the certificate carries" in inspect.getsource(kea_tls.issue_server_cert)
        text = pathlib.Path("docs/upgrading.md").read_text(encoding="utf-8")
        assert "any name the certificate carries" in text


class TestEveryRestartOfJenIsBehindTheOneGate:
    """Q202 (AR6, the pass's B6): every function that calls `restart_service()` is a route carrying BOTH decorators - the verifier over the whole tree, never a list of four names."""

    @staticmethod
    def _callers():
        import ast

        found = []
        for path in sorted(pathlib.Path("jen").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            # (second pass H2: an aliased import - `from jen.services.runtime import restart_service as r` - is the same function under another name)
            names = {"restart_service"} | {
                a.asname
                for n in ast.walk(tree)
                if isinstance(n, ast.ImportFrom)
                for a in n.names
                if a.name == "restart_service" and a.asname
            }
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                for call in ast.walk(node):
                    if isinstance(call, ast.Call):
                        f = call.func
                        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                        if name in names:
                            found.append((str(path).replace("\\", "/"), node))
                            break
        return found

    def test_every_caller_outside_the_runtime_module_is_a_route_with_superadmin_and_step_up(self):
        import ast

        callers = [(p, n) for p, n in self._callers() if p != "jen/services/runtime.py"]
        assert {n.name for _p, n in callers} == {"restart_jen", "save_ports", "upload_cert", "remove_cert"}, [
            (p, n.name) for p, n in callers
        ]
        for path, node in callers:
            decorators = [ast.unparse(d) for d in node.decorator_list]
            assert any(d.startswith("bp.route") for d in decorators), (path, node.name, "not a route")
            assert "_superadmin_required" in decorators, (path, node.name, decorators)
            assert any(d.startswith("_recent_auth_required") for d in decorators), (path, node.name, decorators)

    def test_no_caller_carries_an_admin_only_gate(self):
        import ast

        for path, node in [(p, n) for p, n in self._callers() if p != "jen/services/runtime.py"]:
            decorators = [ast.unparse(d) for d in node.decorator_list]
            assert "_admin_required" not in decorators, (
                path,
                node.name,
                "an admin-only gate would let an admin restart Jen",
            )


class TestAPendingNoteIsNotAcknowledgeable:
    """Q202 (AR7, the pass's O2): Jen's own bookkeeping is finished from Jen's files and never acknowledged away."""

    @staticmethod
    def _post(note_store, **form):
        app = flask.Flask(__name__)
        app.secret_key = "x"
        app.add_url_rule("/servers", "servers.servers", lambda: "")
        with app.test_request_context(method="POST", data=form):
            from jen.routes import servers as servers_routes

            servers_routes.url_for = lambda *a, **k: "/servers"
            return inspect.unwrap(servers_routes.acknowledge_recovery_incident)()

    def test_the_route_with_the_category_is_refused_and_the_note_is_intact(self, monkeypatch):
        import json

        from jen.routes import servers as servers_routes

        store = _memory_note_store(monkeypatch)
        kea_changeset.record_attention(79, "dhcp4", "op", "rotation-pending", ca_fingerprint="aa" * 32)
        before = json.dumps(store, sort_keys=True)
        flashes = []
        monkeypatch.setattr(servers_routes, "flash", lambda text, style="message": flashes.append(text))
        self._post(store, server_id="79", service="dhcp4", category="rotation-pending")
        assert json.dumps(store, sort_keys=True) == before
        assert any("Jen's own bookkeeping" in f for f in flashes), flashes

    def test_with_no_category_every_other_incident_of_the_server_clears_and_the_pending_one_stays(self, monkeypatch):
        from jen.routes import servers as servers_routes

        store = _memory_note_store(monkeypatch)
        kea_changeset.record_attention(79, "dhcp4", "op", "rotation-pending", ca_fingerprint="aa" * 32)
        kea_changeset.record_attention(79, "dhcp4", "x", "probe-pending")
        kea_changeset.record_attention(80, "dhcp4", "y", "aborted")
        monkeypatch.setattr(servers_routes, "flash", lambda *a, **k: None)
        monkeypatch.setattr(servers_routes.__dict__["__user"], "audit", lambda *a, **k: None)
        self._post(store, server_id="79")
        assert [(i["server_id"], i["category"]) for i in store] == [(79, "rotation-pending"), (80, "aborted")]

    def test_acknowledge_recovery_with_no_filters_leaves_every_rotation_pending_note(self, monkeypatch):
        store = _memory_note_store(monkeypatch)
        kea_changeset.record_attention(79, "dhcp4", "op", "rotation-pending", ca_fingerprint="aa" * 32)
        kea_changeset.record_attention(80, "dhcp4", "y", "aborted")
        assert kea_changeset.acknowledge_recovery(None, None, None) == 1
        assert [i["category"] for i in store] == ["rotation-pending"]
        assert kea_changeset.acknowledge_recovery(None, None, "rotation-pending") == 0
        assert [i["category"] for i in store] == ["rotation-pending"]

    def test_the_page_has_no_button_for_a_pending_note_and_has_one_for_a_superseded_one(self):
        import jinja2

        source = pathlib.Path("templates/servers.html").read_text(encoding="utf-8")
        condition = "{% if current_user.role == 'superadmin' and ca.category is defined and ca.category != 'rotation-pending' %}"
        assert (
            condition in source
        )  # (Q203 AS7 d: `Undefined != 'rotation-pending'` is true - an incident with no category rendered the button)
        marker = source.index(condition)
        assert "acknowledge_recovery_incident" in source[marker : marker + 300]
        assert jinja2.Environment().parse(source) is not None


class TestTheDependencySetReadsFailClosed:
    """Q202 (AR8, the pass's O1; the previous register's F8): a store that cannot be READ is a refusal, never 'nothing is pending' and never 'the operator forgot nothing'. (The unreadable store is
    patched for the request only: the teardown's invariant check reads the store too.)"""

    @staticmethod
    def _unreadable(strict=False):
        raise ValueError("the incident note could not be read (OperationalError)")

    def test_the_store_that_cannot_be_read_at_the_start_refuses_before_staging_and_writes_nothing(
        self, lab, monkeypatch
    ):
        before_incidents = list(lab.incidents)
        ca = _ca_bytes()
        with monkeypatch.context() as down:
            down.setattr(kea_changeset, "recovery_incidents", self._unreadable)
            _rotate()
        texts = lab.texts()
        assert "Rotate refused" in texts and "could not be read" in texts and "does not start" in texts, texts
        assert lab.remote_actions() == 0 and _ca_bytes() == ca and lab.incidents == before_incidents

    def test_a_forgotten_record_with_an_unreadable_store_is_not_read_as_nothing_forgotten(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        _forget({"include_parked": "1"})
        assert (2, "dhcp4", "record-forgotten") in lab.incidents
        with monkeypatch.context() as down:
            down.setattr(kea_changeset, "recovery_incidents", self._unreadable)
            _rotate()
        assert "Rotate refused" in lab.request_texts() and lab.remote_actions() == 0

    def test_reconcile_lets_the_value_error_reach_its_callers(self, monkeypatch):
        monkeypatch.setattr(kea_changeset, "recovery_incidents", self._unreadable)
        with pytest.raises(ValueError):
            kea_changeset.reconcile_rotation_pending([])

    def test_forget_says_so_and_carries_on_when_the_store_cannot_be_read(self, lab, monkeypatch):
        with monkeypatch.context() as down:
            down.setattr(kea_changeset, "recovery_incidents", self._unreadable)
            _forget({})
        assert "could not read its incident notes" in lab.texts()
        lab.before = None


class TestTheSmallOnesOfQ202:
    """Q202 (AR9, each with its test): (a) the stale-marked rows, (b) the matcher, (c) the bind at the choke point, (d)-(l)."""

    def test_a_stale_marked_record_is_judged_on_its_prev_certificate_on_the_ordinary_path(self, lab):
        """O3 = H1: a stale-marked record whose `.prev` certificate names another machine was `jen-stale` (a rotation TARGET) while the group functions refused it."""
        _give_prev(2, stale=True)
        crt = kea_tls.server_copy_path(2, "dhcp4")
        other = _commit_naming(95, ["10.0.0.95"])  # a certificate for another machine, as the host's previous pair
        pathlib.Path(crt + ".prev").write_text(other["server.crt"], encoding="ascii")
        state, why = kea_tls.record_state(2, "dhcp4", server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse" and "a different machine" in why, (state, why)
        assert kea_tls.record_group_refusal(2, "dhcp4", lab.servers[2], lab.urls[2], "standby kea-dhcp4")
        kea_tls.discard_local_record(95, "dhcp4")
        os.unlink(crt + ".prev")
        os.unlink(kea_tls.server_key_path(2, "dhcp4") + ".prev")
        os.unlink(crt + ".stale")
        lab.before = None

    def test_a_stale_marked_record_is_judged_on_its_prev_certificate_in_a_recovery_too(self, lab):
        _give_prev(2, stale=True)
        crt = kea_tls.server_copy_path(2, "dhcp4")
        other = _commit_naming(95, ["10.0.0.95"])
        pathlib.Path(crt + ".prev").write_text(other["server.crt"], encoding="ascii")
        state, why = kea_tls.record_state(2, "dhcp4", recovery=True, server=lab.servers[2], url=lab.urls[2])
        assert state == "refuse" and "a different machine" in why, (state, why)
        kea_tls.discard_local_record(95, "dhcp4")
        os.unlink(crt + ".prev")
        os.unlink(kea_tls.server_key_path(2, "dhcp4") + ".prev")
        os.unlink(crt + ".stale")
        lab.before = None

    def test_b_the_matcher_accepts_the_scoped_row_the_fold_exists_for(self):
        from urllib3.util.ssl_match_hostname import match_hostname

        match_hostname({"subjectAltName": (("IP Address", "fe80:0:0:0:0:0:0:1"),)}, "fe80::1%eth0")  # (does not raise)

    def test_c_a_dns_bind_cannot_be_issued_a_certificate_and_the_rotation_says_so(self, lab):
        server = {"id": 9, "name": "dns-bind", "ssh_host": "10.0.0.9"}
        with pytest.raises(kea_tls.BindNotAnAddress):
            kea_tls.issue_server_cert(server, "dhcp4", "api-b.example", commit=False)
        with pytest.raises(ValueError):
            kea_tls.issue_server_cert(server, "dhcp4", "", commit=False)
        assert kea_tls._is_ip_literal(" 10.0.0.9 ") and not kea_tls._is_ip_literal("kea-b.lan")
        lab.urls[2] = (
            "https://kea-b.example:8004"  # a record dialled at a NAME the certificate does not carry as an address
        )
        lab.hold_certificate_naming(2, ["kea-b.example", "kea-b.example"])
        lab.servers[2]["ssh_host"] = "kea-b.example"
        lab.machine_addr[2] = "kea-b.example"
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        _rotate()
        texts = lab.texts()
        assert "the CA cannot issue its certificate for kea-b.example" in texts and "it is a name" in texts, texts
        assert "nothing was installed on any host" in texts and lab.remote_actions() == 0
        lab.before = None

    def test_c_a_recovery_over_a_dns_url_record_is_refused_with_the_same_sentence(self, lab):
        """Second pass F7: a damaged-CA recovery re-issues from the URL's host too; a record whose only name is a DNS one cannot be re-issued a certificate (the daemon binds an address), nothing is installed."""
        lab.urls[2] = "https://kea-b.example:8004"
        lab.hold_certificate_naming(2, ["kea-b.example", "kea-b.example"])
        lab.servers[2]["ssh_host"] = "kea-b.example"
        lab.machine_addr[2] = "kea-b.example"
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        os.unlink(kea_tls.ca_paths()[1])  # the CA is damaged: a recovery
        before = _hosts_state(lab)
        _rotate({"acknowledge_damaged_ca": "1"})
        texts = lab.texts()
        assert "the CA cannot issue its certificate for kea-b.example" in texts and "it is a name" in texts, texts
        assert lab.remote_actions() == 0 and _hosts_state(lab) == before
        lab.before = None

    def test_c_the_bind_is_the_certificates_own_address_whichever_name_the_url_uses(self, lab):
        """Second pass F3: cert [10.0.0.6, 10.0.0.77], SSH host 10.0.0.77, URL https://10.0.0.77 - accepted (a name the certificate carries) and the new certificate must still name 10.0.0.6."""
        lab.hold_certificate_naming(2, ["10.0.0.6", "10.0.0.77"])
        lab.servers[2]["ssh_host"] = "10.0.0.77"
        lab.machine_addr[2] = "10.0.0.77"
        lab.urls[2] = "https://10.0.0.77:8004"
        extensions.KEA_SERVERS[:] = list(lab.servers.values())
        assert kea_tls.rotation_bind(2, "dhcp4", lab.urls[2]) == "10.0.0.6"
        assert kea_tls.rotation_bind(2, "dhcp4", "https://[::ffff:10.0.0.6]:8004") == "10.0.0.6"
        assert kea_tls.rotation_bind(99, "dhcp4", "https://10.0.0.9:8004") == "10.0.0.9", "no record: the URL's address"
        lab.before = None

    def test_d_the_pending_after_commit_test_is_named_for_what_it_asserts(self):
        names = [
            n for n in dir(TestRotationBookkeepingIsDurable) if n.startswith("test_the_store_failing_after_the_commit")
        ]
        assert names == [
            "test_the_store_failing_after_the_commit_leaves_the_note_pending_says_so_and_health_only_names_it"
        ]

    def test_f_the_rotations_refusal_tells_could_not_be_written_from_stored_but_unreadable(self, lab, monkeypatch):
        TestRotationBookkeepingIsDurable._ghost(lab)
        real = kea_changeset.recovery_incidents

        def hidden(strict=False):
            return [i for i in real(strict) if i.get("category") != "rotation-pending"]

        monkeypatch.setattr(kea_changeset, "recovery_incidents", hidden)
        lab.before = None
        _rotate()
        texts = lab.texts()
        assert "was stored but could not be read back" in texts and "could not write the note" not in texts, texts
        assert any("was stored but could not be read back" in str(a) for a in lab.audits)
        assert lab.remote_actions() == 0

    def test_g_the_two_forget_refusals_are_told_apart_in_the_audit_row_too(self, lab, monkeypatch):
        TestStaleIsAFactAboutTheDaemon._park_server_2(lab)
        monkeypatch.setattr(kea_changeset, "record_attention", lambda *a, **k: False)
        _forget({"include_parked": "1"})
        audits = " ".join(str(a) for a in lab.audits)
        assert "the fact could not be stored for 2-dhcp4" in audits and "could not be read back" not in audits

    def test_h_the_docstrings_say_what_they_read(self):
        from jen.services import health as health_mod

        assert "FILES only" in " ".join(kea_tls._group_certificate.__doc__.split())
        assert "three lists" in " ".join(health_mod._forgotten_labels.__doc__.split())

    def test_i_two_empty_names_are_no_name(self):
        assert kea_tls.names_match("", "") is False and kea_tls.names_match("10.0.0.6", "") is False
        assert kea_tls.names_match("10.0.0.6", "10.0.0.6") is True

    def test_j_has_incident_compares_ids_as_text_on_both_sides(self, lab):
        lab.incidents.append((2, "dhcp4", "tls-superseded"))
        assert infra._has_incident("2", "dhcp4", "tls-superseded") and infra._has_incident(2, "dhcp4", "tls-superseded")
        assert not infra._has_incident("3", "dhcp4", "tls-superseded")
        lab.before = None

    def test_k_the_change_flash_is_only_for_a_removal_that_changed_something(self):
        source = inspect.getsource(infra.remove_direct_socket)
        assert 'if changed:\n        flash(f"{daemon} on {name}: {\'; \'.join(changed)}.", "success")' in source

    def test_l_the_cli_is_resolved_from_a_fixed_list_in_both_places(self, monkeypatch):
        from jen.services import certs

        assert certs.OPENSSL_PATH == "/usr/bin:/bin" and kea_tls.OPENSSL_PATH == certs.OPENSSL_PATH
        asked = []
        # Q203 AS7 c (the pass's N13): execute BOTH lookups. The first draft patched `certs.shutil.which` and compared the two constants; a lookup that ignored its constant would have passed.
        monkeypatch.setattr(certs.shutil, "which", lambda name, path=None: asked.append((name, path)))
        assert certs.cert_info("/nonexistent.pem") == {}
        assert kea_tls._openssl_exe() is None
        assert asked == [("openssl", "/usr/bin:/bin"), ("openssl", "/usr/bin:/bin")], asked
        service = pathlib.Path("jen.service.template").read_text(encoding="utf-8")
        assert "openssl" not in service


class TestTheSmallOnesOfQ203:
    """Q203 (AS7, each with its test where one applies): (a) the `_group_certificate` docstring says what is true, (b) the CHANGELOG full stop, (c) the openssl lookups are executed (in
    `TestTheSmallOnesOfQ202::test_l_...`), (d) the Acknowledge button is rendered only for a defined category, (e) troubleshooting names the fixed `openssl` list, (f) the S10 count."""

    @staticmethod
    def _button_for(category_context):
        import jinja2

        source = pathlib.Path("templates/servers.html").read_text(encoding="utf-8")
        start = source.index("{% if current_user.role == 'superadmin' and ca.category is defined")
        end = source.index("{% endif %}", start) + len("{% endif %}")
        # the real condition and its block, rendered with a stand-in for `url_for` and `csrf_token`
        env = jinja2.Environment()
        template = env.from_string(source[start:end])
        return "Acknowledge" in template.render(
            current_user=type("U", (), {"role": "superadmin"})(),
            ca=category_context,
            url_for=lambda *a, **k: "/x",
            csrf_token=lambda: "t",
        )

    def test_d_an_incident_with_no_category_has_no_acknowledge_button(self):
        assert self._button_for({}) is False

    def test_d_a_defined_category_has_one_and_a_rotation_note_has_none(self):
        assert self._button_for({"category": "aborted"}) is True
        assert self._button_for({"category": "config-restart-failed"}) is True
        assert self._button_for({"category": "rotation-pending"}) is False

    def test_a_the_group_certificate_docstring_says_what_group_verdict_does(self):
        doc = kea_tls._group_certificate.__doc__
        assert "no verdict of the 20 group shapes" not in doc
        assert "`group_verdict` DOES move" in doc and "five of the 20 shapes" in doc and "no RECORDED outcome" in doc

    def test_b_the_changelog_sentence_has_its_full_stop(self):
        text = pathlib.Path("CHANGELOG.md").read_text(encoding="utf-8")
        assert "All four now do, The forms" not in text and "All four now do. The forms" in text

    def test_e_troubleshooting_names_the_fixed_openssl_list_and_what_health_says(self):
        text = pathlib.Path("docs/troubleshooting.md").read_text(encoding="utf-8")
        assert "/usr/bin:/bin" in text and "openssl" in text
        marker = text.index("/usr/bin:/bin")
        paragraph = text[max(0, marker - 500) : marker + 800]
        assert "second opinion" in paragraph or "no second opinion" in paragraph

    def test_g6_the_restore_note_paragraph_says_the_servers_restart_is_dhcp4_only(self):
        text = pathlib.Path("docs/troubleshooting.md").read_text(encoding="utf-8")
        assert "restarts kea-dhcp4 only" in text
        assert "an import applied from Subnets" in text

    def test_g7_the_admin_guide_names_the_restore_step_up_and_the_superadmin_only_key(self):
        text = pathlib.Path("docs/admin-guide.md").read_text(encoding="utf-8")
        assert (
            "replacing Jen's SSH key is a superadmin's too" in text
            and "Restoring a revision from Config history" in text
        )

    def test_g_the_kea_3_0_5_paragraph_and_the_switchs_help_sentence_exist(self):
        """Q203 AS7 (g), first built in the second pass: the crash under DEBUG logging before Kea 3.0.5 (ISC change 2414)."""
        text = pathlib.Path("docs/troubleshooting.md").read_text(encoding="utf-8")
        assert "3.0.4 or earlier" in text and "Restart=on-failure" in text and "change 2414" in text
        page = pathlib.Path("templates/settings_kea.html").read_text(encoding="utf-8")
        assert "Kea 3.0.4 or earlier, DEBUG logging can crash it (fixed in 3.0.5)" in page

    def test_g_the_category_is_one_sentence_true_of_a_restore_and_an_import(self):
        sentence = kea_changeset.ATTENTION_CATEGORIES["config-restart-failed"]
        assert "restored revision, or an import" in sentence
        assert "restore-restart-failed" not in kea_changeset.ATTENTION_CATEGORIES
