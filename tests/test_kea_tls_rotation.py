"""
tests/test_kea_tls_rotation.py
──────────────────────────────
v5.69.0-beta.19 (Q188, AD1 / AD6 / AD8) - CA rotation is ONE transaction, driven through the real route body (`rotate_kea_ca`) on REAL temporary certificate files:

  * Jen's own state is staged first (the new CA and client pair beside the live ones), every target is issued, installed, restarted and probed with the STAGED identity, Jen's TLS settings
    are saved, and only then is the staging promoted - each step inside one exception boundary, so a step that fails (or raises) stops the rotation and every attempted target is put back
    on the CA Jen still trusts, restarted, and PROBED with it;
  * the host is a simulated helper (`kea_host.helper_call`: install-tls stores the files, a restart makes the daemon load them) and the daemon is a fake that answers version-get only when
    the certificate it LOADED was issued by the CA it was asked with - so "answering" means something. The real `install_tls` / `service_action` wrappers sit on top, which is how a
    `socket.timeout`, `EOFError` or `SSHException` from the channel reaches the route (AD6);
  * never a success counter: every test reads the files on disk and what the fake daemon would answer.

Pure - no database, no Kea, no SSH (`pytest --noconftest tests/test_kea_tls_rotation.py`).
"""

import copy
import inspect
import os
import pathlib
import types

import flask
import pytest

import jen.config as jconfig
import jen.routes.settings.infrastructure as infra
from jen.services import kea_changeset, kea_host, kea_tls

pytest_plugins = ("tests._investigation_world",)

SERVERS = {
    1: {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"},
    2: {"id": 2, "name": "standby", "ssh_host": "10.0.0.6"},
}
URLS = {1: "https://10.0.0.5:8004", 2: "https://10.0.0.6:8004"}


def _issued_by(cert_pem: str, ca_path: str) -> bool:
    from cryptography import x509

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        ca = x509.load_pem_x509_certificate(pathlib.Path(ca_path).read_bytes())
        cert.verify_directly_issued_by(ca)
        return True
    except Exception:
        return False


class Lab:
    """The simulated Kea hosts, the fake daemons and everything the route reports."""

    def __init__(self):
        self.hosts = {
            sid: {"files": None, "loaded": None, "installs": [], "restarts": 0, "calls": {}} for sid in SERVERS
        }
        self.refuse = set()  # (server id, op, nth call of that op): the helper answers not-ok
        self.raise_at = {}  # (server id, op, nth call): an exception the channel raises
        self.flashes, self.audits, self.incidents, self.settings_writes = [], [], [], []
        self.settings_error = None
        self.ca_a = None  # bytes of the CA Jen trusts before the rotation

    def texts(self) -> str:
        return " ".join(t for _s, t in self.flashes)

    def answers(self, sid, ca_path) -> bool:
        """Would the daemon of server `sid` answer a client that trusts the CA at `ca_path`?"""
        loaded = self.hosts[sid]["loaded"]
        return bool(loaded) and _issued_by(loaded["server.crt"], ca_path)


@pytest.fixture
def lab(monkeypatch, tmp_path):
    lab = Lab()
    monkeypatch.setattr(kea_tls, "SSL_DIR", str(tmp_path))

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
            host["loaded"] = copy.deepcopy(host["files"])
            host["restarts"] += 1
            return {"ok": True, "unit": "kea-dhcp4-server", "state": "active"}
        raise AssertionError(f"unexpected helper op {op!r}")

    monkeypatch.setattr(kea_host, "helper_call", helper_call)
    monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "_known_version", lambda *a, **k: 4)

    def probe(url, user, pwd, service, verify=None, cert=None):
        sid = next(i for i, u in URLS.items() if u == url)
        if not lab.hosts[sid]["loaded"]:
            return "", "nothing is listening"
        if verify and not lab.answers(sid, verify):
            return "", "certificate verify failed"
        return "Kea 3.0.3", None

    monkeypatch.setattr(infra, "_probe_after_restart", probe)
    monkeypatch.setattr(infra, "_identify_daemon", lambda *a, **k: "Dhcp4")
    monkeypatch.setattr(infra, "_server_by_id", lambda sid: SERVERS.get(sid))
    monkeypatch.setattr(infra, "_service_url", lambda server, service: URLS[server["id"]])
    monkeypatch.setattr(infra, "_daemon_creds", lambda server, service, url="": ("u", "p"))
    monkeypatch.setattr(infra, "url_for", lambda *a, **k: "/settings/kea")
    monkeypatch.setattr(infra, "flash", lambda text, style="message": lab.flashes.append((style, str(text))))
    monkeypatch.setattr(infra.__dict__["__user"], "audit", lambda *a, **k: lab.audits.append(a))
    monkeypatch.setattr(
        "jen.services.capabilities.for_server", lambda sid, probe_kea=True: types.SimpleNamespace(tls=True)
    )
    monkeypatch.setattr(
        kea_changeset,
        "record_attention",
        lambda server_id, service, operation, category, when=None, **kw: (
            lab.incidents.append((server_id, service, category)) or True
        ),
    )

    def write_values(items, typed=None):
        if lab.settings_error:
            raise lab.settings_error
        lab.settings_writes.append(list(items))

    monkeypatch.setattr(jconfig.app_config, "write_values", write_values)

    # the state before the rotation: the CA and Jen's client pair (CA-A), and a certificate issued by it on each host, loaded by its daemon
    kea_tls.ensure_ca()
    kea_tls.issue_client_cert()
    for sid, server in SERVERS.items():
        files = kea_tls.issue_server_cert(server, "dhcp4", server["ssh_host"])
        lab.hosts[sid]["files"] = lab.hosts[sid]["loaded"] = copy.deepcopy(files)
        lab.hosts[sid]["installs"].clear()
    lab.ca_a = pathlib.Path(kea_tls.ca_paths()[0]).read_bytes()
    lab.client_a = pathlib.Path(kea_tls.client_paths()[1]).read_bytes()
    return lab


def _rotate():
    rotate = inspect.unwrap(infra.rotate_kea_ca)
    app = flask.Flask(__name__)
    app.secret_key = "x"
    with app.test_request_context(method="POST"):
        rotate()


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

        def failing(src, dst, *a, **k):
            if str(dst).endswith(victim):
                raise OSError(13, "Permission denied")
            return real(src, dst, *a, **k)

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
        """The rollback put the CA-A pair on the host and the daemon answers; only Jen's own copy of it could not follow. That is `tls-local-stale` - not `tls-not-restored`, and the host is still restarted and probed."""
        real = kea_tls.commit_issued
        seen = []

        def failing_on_the_rollback_of_server_1(sid, service, files):
            seen.append(sid)
            if sid == 1 and seen.count(1) == 2:
                raise OSError(28, "No space left on device")
            return real(sid, service, files)

        monkeypatch.setattr(kea_tls, "commit_issued", failing_on_the_rollback_of_server_1)
        monkeypatch.setattr(kea_tls, "commit_rotation", lambda staged: (_ for _ in ()).throw(OSError(28, "full")))
        _rotate()
        ca = kea_tls.ca_paths()[0]
        assert lab.answers(1, ca) and lab.answers(2, ca), "both daemons answer on CA-A afterwards"
        assert (1, "dhcp4", "tls-local-stale") in lab.incidents and not any(
            i[2] == "tls-not-restored" for i in lab.incidents
        )
        assert kea_tls.is_stale(1, "dhcp4") and not kea_tls.is_stale(2, "dhcp4")
        assert pathlib.Path(kea_tls.server_copy_path(1, "dhcp4") + ".prev").exists(), (
            "its .prev is kept: it is the host's truth now"
        )

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
        kea_tls.stage_issued(sid, "dhcp4", self._issue(sid, "10.0.0.5"))
        kea_tls.promote_staged(sid, "dhcp4")  # live = B, .prev = the pair the host had (first)
        assert not kea_tls.is_stale(sid, "dhcp4")
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
        kea_tls.promote_staged(sid, "dhcp4")
        kea_tls.commit_issued(sid, "dhcp4", again)
        assert not kea_tls.is_stale(sid, "dhcp4"), "a commit means the host was given exactly this pair"

    def test_a_re_assert_installs_the_pair_the_host_holds_not_jens_stale_live_copy(self, lab, monkeypatch):
        sid = 1
        first = pathlib.Path(kea_tls.server_copy_path(sid, "dhcp4")).read_text(encoding="ascii")
        kea_tls.stage_issued(sid, "dhcp4", self._issue(sid, "10.0.0.5"))
        kea_tls.promote_staged(sid, "dhcp4")
        with monkeypatch.context() as scoped:
            scoped.setattr(kea_tls, "commit_file_set", lambda *a, **k: (_ for _ in ()).throw(OSError(13, "denied")))
            assert kea_tls.restore_previous(sid, "dhcp4") is False
        assert infra._reinstall_live_material(SERVERS[sid], "dhcp4") == "restored"
        assert lab.hosts[sid]["installs"][-1]["server.crt"] == first, (
            "the host gets ITS pair back, not Jen's newer live one"
        )

    def test_a_first_setup_whose_promotion_fails_does_not_claim_a_certificate_was_put_back(self, lab):
        sid = 1
        for suffix in ("", ".prev"):
            for path in (kea_tls.server_copy_path(sid, "dhcp4"), kea_tls.server_key_path(sid, "dhcp4")):
                if os.path.exists(path + suffix):
                    os.unlink(path + suffix)
        infra._stop_after_failed_promotion(SERVERS[sid], "dhcp4", OSError(13, "Permission denied"), [], None)
        assert "was put back" not in lab.texts() and "no earlier copy to put back" in lab.texts(), lab.texts()
