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
import types

import flask
import pytest

import jen.config as jconfig
import jen.routes.settings.infrastructure as infra
from jen import extensions
from jen.services import kea_changeset, kea_host, kea_tls
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

    def answers_jens_configured_dial(self, sid) -> bool:
        """Would the daemon answer Jen as Jen is CONFIGURED to dial it: a server certificate issued by ANY certificate of the bundle at `[kea] api_ca` (or no verification at all when it is empty
        and verification is off), and the client certificate Jen presents issued by the CA the daemon loaded? A rotation that leaves the configured bundle on the old CA cuts this off even though
        the daemon answers Jen's live identity (the second pass of Q190: the dial, not the file Jen would like to be dialling with)."""
        loaded = self.hosts[sid]["loaded"]
        if not loaded:
            return False
        bundle = (extensions.KEA_API_CA or "").strip()
        if bundle:
            if not _issued_by_any(loaded["server.crt"], bundle):
                return False
        elif getattr(extensions, "KEA_API_TLS_VERIFY", True):
            return False
        client = (extensions.KEA_API_CLIENT_CERT or "").strip()
        if not client:
            return False
        try:
            return _issued_by_pem(pathlib.Path(client).read_text(encoding="ascii"), loaded["ca.crt"])
        except OSError:
            return False

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
        self.flash_mark = len(self.flashes)
        self.answered_before = {
            sid: self.answers_jens_live_identity(sid) for sid in self.hosts if self.hosts[sid]["loaded"]
        }
        self.snapshot_dial()

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
        # T1 - for every daemon whose pair JEN'S CA ISSUED (judged by the HOST's certificate), Jen's record of it is the pair the host holds, or Jen says it does not know
        for sid in sorted(self.hosts):
            files = self.hosts[sid]["files"]
            if not files:
                continue
            if sid in jens_sids:
                record = kea_tls.host_material(sid, "dhcp4")
                if record is None:
                    if not (
                        self._named(sid, ("tls-local-stale", "remote-unknown", "tls-not-restored"))
                        or kea_tls.is_unknown(sid, "dhcp4")
                        or self._refusal_names(sid)
                    ):
                        bad.append(
                            ("T1", f"server {sid}: Jen has no record of the pair its host holds and nothing says so")
                        )
                elif record["server.crt"] != files["server.crt"] or record["server.key"] != files["server.key"]:
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
        if not kea_tls.ca_consistent() and not (
            all(self._named(sid, ("tls-not-restored",)) for sid in jens_sids)
            and "no longer a matching pair" in self.texts()
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
            if before is False:
                if self.before is not None and self.hosts[sid]["files"] != self.before["hosts"].get(sid):
                    bad.append(
                        (
                            "T3",
                            f"server {sid}'s daemon did not answer Jen before the request and its files on the host CHANGED",
                        )
                    )
                if now:
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
        if isinstance(verify, str) and not _issued_by(loaded["server.crt"], verify):
            raise _rq.exceptions.SSLError(f"{where} (Caused by SSLError: certificate verify failed)")
        if verify is True:
            raise _rq.exceptions.SSLError(f"{where} (Caused by SSLError: certificate verify failed, the system's CAs)")
        if cert and not _issued_by_pem(pathlib.Path(cert[0]).read_text(encoding="ascii"), loaded["ca.crt"]):
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


def _rotate():
    lab = _ACTIVE[-1] if _ACTIVE else None
    if lab is not None:
        lab.begin()
    rotate = inspect.unwrap(infra.rotate_kea_ca)
    app = flask.Flask(__name__)
    app.secret_key = "x"
    with app.test_request_context(method="POST"):
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
        assert lab.incidents == [(1, "dhcp4", "tls-not-restored")]
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
        real = kea_tls.write_atomically
        calls = []

        def third_fails(path, data, mode):
            calls.append(path)
            if len(calls) == 3:
                raise OSError(28, "No space left on device")
            return real(path, data, mode)

        monkeypatch.setattr(kea_tls, "write_atomically", third_fails)
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
            lambda servers, url_for=None: kea_tls.RotationInventory([], [], [], [], frozenset()),
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

        def refusing_after_writing(servers, url_for=None):
            (pathlib.Path(kea_tls.SSL_DIR) / "stray-file").write_text("left behind", encoding="ascii")
            inv = real(servers, url_for=url_for)
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

    def test_T1_bites_when_a_jen_issued_pair_has_no_record_and_nothing_says_so(self, lab):
        """Judged by the HOST's certificate: the daemon runs a pair a Jen CA issued; Jen's files for it are gone; no request, no incident, no marker says so."""
        lab.expected_violations = {"T1"}
        _drop_jens_record(1)
        lab.begin()


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
        self._refused_before_staging(lab, "never accepted it")

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
