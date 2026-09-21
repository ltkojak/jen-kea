"""
tests/test_restore_lifecycle.py
────────────────────────────────
v5.49.0-beta.4 (Q55-A) — `install.sh --restore` as a lifecycle: quiesce
(stop) → snapshot → apply → start → health-check → roll back on failure.

Pure: temp dirs only, `systemctl`/`subprocess.run`, the DB export/import
and the config switch are monkeypatched — nothing here touches /etc/jen or a
real service. The health poll itself is tested against a real local HTTP
server (CLAUDE.md: probes are tested against real servers).
"""

import http.server
import json
import os
import stat
import threading
import types

import pytest

from jen.services.recovery import build
from jen.tools import restore

PASS = "correct horse battery staple"
OLD_DB = b"old-database-export"


def _manifest():
    from jen import JEN_VERSION
    from jen.models.migrations import MIGRATIONS

    return {
        "jen_version": JEN_VERSION,
        "channel": "beta",
        "hostname": "old-box",
        "created_at": "2026-01-01T00:00:00Z",
        "schema_version": MIGRATIONS[-1][0],
        "kea_versions": {},
        "plugins": [],
        "helper_versions": {},
    }


def _tree(root):
    """{relative path: bytes} for every file under root (excluding snapshots)."""
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if rel.startswith("backups/"):
                continue
            with open(p, "rb") as fh:
                out[rel] = fh.read()
    return out


@pytest.fixture
def world(tmp_path, monkeypatch):
    """An 'installed Jen': /etc/jen and a content dir with real files, a bundle
    to restore, and every side effect recorded in `events`."""
    etc = tmp_path / "etc_jen"
    content = tmp_path / "content"
    (etc / "ssl").mkdir(parents=True)
    (etc / "jen.config").write_text("[server]\nhttp_port = 5999\n")
    (etc / "mfa_key").write_bytes(b"OLD-MFA")
    (etc / "ssl" / "certificate.crt").write_bytes(b"old-cert")
    (content / "icons").mkdir(parents=True)
    (content / "icons" / "logo.png").write_bytes(b"old-logo")
    (content / "backups").mkdir()
    (content / "backups" / "big-old-backup.gz").write_bytes(b"x" * 10)
    (content / "tmp").mkdir()
    (content / "tmp" / "scratch").write_bytes(b"t")

    members = {
        "manifest.json": json.dumps(_manifest()).encode(),
        "jen.config": b"[server]\nhttp_port = 5777\n",
        "mfa_key": b"NEW-MFA",
        "content/icons/logo.png": b"new-logo",
        "content/icons/extra.png": b"added-by-restore",
        "jen_db.json.gz": b"irrelevant-here",
    }
    bundle = tmp_path / "bundle.tar.enc"
    bundle.write_bytes(build(members, PASS))

    events = []
    state = types.SimpleNamespace(active=True, rc={}, healthy=True, apply_error=None, imports=[])

    def fake_run(argv, **kw):
        assert argv[0] == "systemctl" and isinstance(argv, list)
        events.append(("systemctl", *argv[1:]))
        rc = state.rc.get(argv[1], 0)
        if argv[1] == "is-active":
            rc = 0 if state.active else 3
        return types.SimpleNamespace(returncode=rc, stdout="", stderr="")

    monkeypatch.setattr(restore.subprocess, "run", fake_run)
    monkeypatch.setattr(restore.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(restore, "_export_db", lambda: OLD_DB)
    monkeypatch.setattr(restore, "check_kea_major", lambda manifest, bundle_dir: [])  # would reload the real app config

    def fake_import(gz):
        state.imports.append(gz)
        events.append(("db-import",))
        return ["ok"]

    monkeypatch.setattr(restore, "_import_db", fake_import)
    monkeypatch.setattr(restore, "_point_config_at", lambda cfg: events.append(("config", str(cfg))))

    def fake_restore_db(bundle_dir, config_file):
        events.append(("apply-db",))
        if state.apply_error:
            raise RuntimeError(state.apply_error)
        return ["✅ restored"]

    monkeypatch.setattr(restore, "restore_jen_db", fake_restore_db)

    def fake_health(port, **kw):
        events.append(("health", port))
        return state.healthy

    monkeypatch.setattr(restore, "_wait_healthy", fake_health)
    return types.SimpleNamespace(etc=etc, content=content, bundle=bundle, events=events, state=state, tmp=tmp_path)


def _run(w, **kw):
    return restore.run(str(w.bundle), PASS, etc_jen=str(w.etc), content_dir=str(w.content), **kw)


class TestSnapshot:
    def test_contents_and_permissions(self, world):
        import tarfile

        snap = restore.take_snapshot(world.etc, world.content)
        assert snap.parent == world.content / "backups" and snap.name.startswith("pre-restore-")
        with tarfile.open(snap / "etc-jen.tar") as tf:
            names = set(tf.getnames())
        assert {"jen.config", "mfa_key", "ssl", "ssl/certificate.crt"} <= names
        with tarfile.open(snap / "content.tar") as tf:
            cnames = set(tf.getnames())
        assert "icons/logo.png" in cnames
        assert not any(n.startswith(("backups", "tmp")) for n in cnames)  # excluded
        assert (snap / "jen_db.json.gz").read_bytes() == OLD_DB
        if os.name != "nt":
            for name in ("etc-jen.tar", "content.tar", "jen_db.json.gz"):
                assert stat.S_IMODE((snap / name).stat().st_mode) == 0o600
            assert stat.S_IMODE(snap.stat().st_mode) == 0o700


class TestHappyPath:
    def test_order_is_stop_snapshot_apply_start_health(self, world):
        rc = _run(world)
        assert rc == 0
        seq = [e[0] if e[0] != "systemctl" else "systemctl:" + e[1] for e in world.events]
        assert seq == [
            "systemctl:is-active",
            "systemctl:stop",
            "apply-db",
            "systemctl:start",
            "health",
        ]
        # the new files really landed, and the port came from the RESTORED config
        assert (world.etc / "mfa_key").read_bytes() == b"NEW-MFA"
        assert (world.content / "icons" / "extra.png").read_bytes() == b"added-by-restore"
        assert ("health", 5777) in world.events
        assert list((world.content / "backups").glob("pre-restore-*"))

    def test_not_running_is_left_stopped_unless_start_given(self, world):
        world.state.active = False
        assert _run(world) == 0
        assert not any(e[:2] == ("systemctl", "start") for e in world.events)
        assert not any(e[0] == "health" for e in world.events)
        world.events.clear()
        assert _run(world, start=True) == 0
        assert ("systemctl", "start", "jen") in world.events and any(e[0] == "health" for e in world.events)


class TestFailureRollsBack:
    def test_writer_raising_mid_apply_leaves_everything_as_it_was(self, world, monkeypatch):
        before_etc, before_content = _tree(world.etc), _tree(world.content)

        real = restore.restore_content

        def boom(bundle_dir, content_dir):
            real(bundle_dir, content_dir)  # writes some files first …
            raise OSError("disk full")  # … then dies

        monkeypatch.setattr(restore, "restore_content", boom)
        rc = _run(world)
        assert rc == 1
        assert _tree(world.etc) == before_etc
        assert _tree(world.content) == before_content  # extra.png is gone again
        assert world.state.imports == [OLD_DB]  # the DB snapshot was re-imported
        assert ("systemctl", "start", "jen") in world.events  # it was running: it runs again
        assert not any(e[0] == "health" for e in world.events)

    def test_failing_health_check_rolls_back_and_exits_nonzero(self, world):
        before_etc, before_content = _tree(world.etc), _tree(world.content)
        world.state.healthy = False
        rc = _run(world)
        assert rc != 0
        assert _tree(world.etc) == before_etc and _tree(world.content) == before_content
        assert world.state.imports == [OLD_DB]
        seq = [e[1] for e in world.events if e[0] == "systemctl"]
        assert seq == ["is-active", "stop", "start", "stop", "start"]  # …start(bad), stop, rollback, start(good)

    def test_db_apply_failure_rolls_back(self, world):
        world.state.apply_error = "import blew up"
        assert _run(world) == 1
        assert world.state.imports == [OLD_DB]

    def test_snapshot_failure_refuses_without_changes(self, world, monkeypatch):
        before = _tree(world.etc)

        def nope():
            raise RuntimeError("database unreachable")

        monkeypatch.setattr(restore, "_export_db", nope)
        assert _run(world) == 1
        assert _tree(world.etc) == before
        assert not any(e[0] == "apply-db" for e in world.events)
        assert ("systemctl", "start", "jen") in world.events  # we stopped it; put it back


class TestNoStop:
    def test_no_stop_never_calls_systemctl(self, world):
        assert _run(world, no_stop=True) == 0
        assert not any(e[0] == "systemctl" for e in world.events)
        assert not any(e[0] == "health" for e in world.events)

    def test_missing_systemctl_is_treated_as_no_stop(self, world, monkeypatch):
        monkeypatch.setattr(restore.shutil, "which", lambda name: None)
        assert _run(world) == 0
        assert not any(e[0] == "systemctl" for e in world.events)


class TestManualRollback:
    def test_rollback_dir_redoes_a_finished_restore(self, world):
        before_etc, before_content = _tree(world.etc), _tree(world.content)
        assert _run(world, no_stop=True) == 0
        assert _tree(world.etc) != before_etc
        snap = next((world.content / "backups").glob("pre-restore-*"))
        world.events.clear()
        assert restore.run_rollback(str(snap), etc_jen=str(world.etc), content_dir=str(world.content)) == 0
        assert _tree(world.etc) == before_etc and _tree(world.content) == before_content
        assert world.state.imports == [OLD_DB]
        assert [e[1] for e in world.events if e[0] == "systemctl"] == ["is-active", "stop", "start"]

    def test_not_a_snapshot_is_refused(self, tmp_path):
        assert restore.run_rollback(str(tmp_path)) == 1


class _H(http.server.BaseHTTPRequestHandler):
    """A stand-in for whatever answers on Jen's port. `server.mode` picks the reply."""

    def do_GET(self):
        mode = self.server.mode
        if mode == "jen":
            body = json.dumps({"jen_version": "5.49.0", "kea_up": False}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif mode == "html200":
            body = b"<html>a login page</html>"
            self.send_response(200)
        elif mode == "json-no-version":
            body = b'{"status": "ok"}'
            self.send_response(200)
        elif mode == "redirect":
            body = b""
            self.send_response(302)
            self.send_header("Location", self.server.location)
        else:  # a bare status code: "401", "404", "500"
            body = b""
            self.send_response(int(mode))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(mode, location=None, ssl_files=None):
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _H)
    httpd.mode = mode
    httpd.location = location
    if ssl_files:
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*ssl_files)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _self_signed(tmp_path):
    """A throwaway self-signed certificate, as Jen's own HTTPS uses."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jen.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )
    return str(cert_path), str(key_path)


def _healthy(httpd, timeout=1.0):
    try:
        return restore._wait_healthy(httpd.server_port, timeout=timeout, interval=0.1)
    finally:
        httpd.shutdown()


class TestHealthPoll:
    """v5.49.0-beta.6 (Q56-3) - healthy means HTTP 200 with a JSON body carrying
    jen_version; a redirect counts only to Jen's own loopback HTTPS, and there it
    must answer the same way. Against real local servers."""

    def test_200_with_jen_json_is_healthy(self):
        assert _healthy(_serve("jen")) is True

    @pytest.mark.parametrize("mode", ["401", "404", "500", "html200", "json-no-version"])
    def test_everything_else_is_unhealthy(self, mode):
        assert _healthy(_serve(mode)) is False

    def test_a_redirect_elsewhere_is_unhealthy(self):
        assert _healthy(_serve("redirect", location="https://example.com/api/v1/health")) is False
        assert _healthy(_serve("redirect", location="http://127.0.0.1:1/api/v1/health")) is False  # not https
        assert _healthy(_serve("redirect", location="/api/v1/health")) is False  # relative

    def test_a_redirect_to_jens_own_loopback_https_is_followed(self, tmp_path):
        tls = _serve("jen", ssl_files=_self_signed(tmp_path))
        try:
            plain = _serve("redirect", location=f"https://127.0.0.1:{tls.server_port}/api/v1/health")
            assert _healthy(plain, timeout=3) is True  # a self-signed certificate is fine on loopback
            plain = _serve("redirect", location=f"https://localhost:{tls.server_port}/api/v1/health")
            assert _healthy(plain, timeout=3) is True
        finally:
            tls.shutdown()

    def test_the_https_side_must_itself_be_jen(self, tmp_path):
        for mode in ("404", "html200"):
            tls = _serve(mode, ssl_files=_self_signed(tmp_path))
            try:
                plain = _serve("redirect", location=f"https://127.0.0.1:{tls.server_port}/api/v1/health")
                assert _healthy(plain, timeout=1) is False, mode
            finally:
                tls.shutdown()

    def test_nothing_listening_times_out(self):
        s = _serve("jen")
        port = s.server_port
        s.shutdown()
        s.server_close()
        assert restore._wait_healthy(port, timeout=0.5, interval=0.1) is False

    def test_port_comes_from_the_config(self, tmp_path):
        cfg = tmp_path / "jen.config"
        cfg.write_text("[server]\nhttp_port = 6123\n")
        assert restore._service_port(cfg) == 6123
        assert restore._service_port(tmp_path / "missing") == 5050


# ── v5.49.0-beta.5 (Q55-A extended): the destructive cases, one invariant ──
#
# Every failure path leaves the box in exactly one of two states: the previous
# install untouched, or the restored one healthy. "Untouched" is asserted as
# byte-identical /etc/jen and content, DB rows equal to the snapshot export,
# and - for refusals that happen before quiesce - no snapshot directory and
# no systemctl call at all.


def _make_bundle(w, manifest=None, extra=None, passphrase=PASS):
    m = _manifest()
    m.update(manifest or {})
    members = {
        "manifest.json": json.dumps(m).encode(),
        "jen.config": b"[server]\nhttp_port = 5777\n",
        "mfa_key": b"NEW-MFA",
        "content/icons/logo.png": b"new-logo",
        "jen_db.json.gz": b"irrelevant-here",
    }
    members.update(extra or {})
    blob = build(members, passphrase)
    w.bundle.write_bytes(blob)
    return blob


def _snapshot_dirs(w):
    b = w.content / "backups"
    return list(b.glob("pre-restore-*")) if b.is_dir() else []


def _systemctl_calls(w):
    return [e for e in w.events if e[0] == "systemctl"]


@pytest.fixture
def dbworld(world, monkeypatch):
    """`world` plus a tiny fake database so "DB rows equal the snapshot
    export" can be asserted, and an import that can die halfway."""
    db = {"users": [{"id": 1, "name": "old-admin"}], "settings": [{"k": "a", "v": "old"}]}
    world.db = db
    monkeypatch.setattr(restore, "_export_db", lambda: json.dumps(db).encode())

    def fake_import(gz):
        data = json.loads(gz)
        db.clear()
        db.update(data)
        world.events.append(("db-import",))
        world.state.imports.append(gz)
        return ["ok"]

    monkeypatch.setattr(restore, "_import_db", fake_import)
    world.db_before = json.loads(json.dumps(db))

    def fake_restore_db(bundle_dir, config_file):
        world.events.append(("apply-db",))
        db["users"] = [{"id": 1, "name": "restored-admin"}]  # the first table lands ...
        if world.state.apply_error:
            raise RuntimeError(world.state.apply_error)  # ... then the import dies
        db["settings"] = [{"k": "a", "v": "restored"}]
        return ["ok"]

    monkeypatch.setattr(restore, "restore_jen_db", fake_restore_db)
    return world


class TestRefusalsBeforeQuiesce:
    """Nothing may have happened: no snapshot dir, no systemctl call, no writes."""

    def _assert_nothing_happened(self, w, before_etc, before_content):
        assert _snapshot_dirs(w) == []
        assert _systemctl_calls(w) == []
        assert _tree(w.etc) == before_etc and _tree(w.content) == before_content

    def test_wrong_passphrase(self, world):
        before = (_tree(world.etc), _tree(world.content))
        rc = restore.run(
            str(world.bundle), "not the passphrase", etc_jen=str(world.etc), content_dir=str(world.content)
        )
        assert rc != 0
        self._assert_nothing_happened(world, *before)

    def test_truncated_bundle(self, world):
        blob = world.bundle.read_bytes()
        world.bundle.write_bytes(blob[: len(blob) // 2])
        before = (_tree(world.etc), _tree(world.content))
        assert _run(world) != 0
        self._assert_nothing_happened(world, *before)

    def test_corrupt_bundle(self, world):
        blob = bytearray(world.bundle.read_bytes())
        blob[len(blob) // 2] ^= 0xFF
        world.bundle.write_bytes(bytes(blob))
        before = (_tree(world.etc), _tree(world.content))
        assert _run(world) != 0
        self._assert_nothing_happened(world, *before)

    def test_bundle_from_a_newer_jen_without_force(self, world):
        _make_bundle(world, manifest={"jen_version": "5.999.0"})
        before = (_tree(world.etc), _tree(world.content))
        assert _run(world) != 0
        self._assert_nothing_happened(world, *before)

    def test_newer_jen_with_force_proceeds(self, world):
        _make_bundle(world, manifest={"jen_version": "5.999.0"})
        assert _run(world, force=True) == 0


class TestMidApplyFailuresRestoreThePreviousState:
    def _assert_previous(self, w):
        assert _tree(w.etc) == w.before_etc
        assert _tree(w.content) == w.before_content
        assert w.db == w.db_before  # DB rows equal the snapshot export

    def test_enospc_in_the_content_writer(self, dbworld, monkeypatch):
        import errno

        w = dbworld
        w.before_etc, w.before_content = _tree(w.etc), _tree(w.content)
        real = restore.restore_content

        def full(bundle_dir, content_dir):
            real(bundle_dir, content_dir)
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(restore, "restore_content", full)
        assert _run(w) == 1
        self._assert_previous(w)

    def test_database_import_dying_after_the_first_table(self, dbworld):
        w = dbworld
        w.before_etc, w.before_content = _tree(w.etc), _tree(w.content)
        w.state.apply_error = "connection lost after table 1"
        assert _run(w) == 1
        assert w.db["users"][0]["name"] == "old-admin"  # the half-imported table is back
        self._assert_previous(w)

    def test_health_check_never_coming_up(self, dbworld):
        w = dbworld
        w.before_etc, w.before_content = _tree(w.etc), _tree(w.content)
        w.state.healthy = False
        assert _run(w) != 0
        self._assert_previous(w)
        assert w.db["settings"][0]["v"] == "old"  # the fully-imported DB was rolled back too

    def test_success_leaves_the_restored_state(self, dbworld):
        w = dbworld
        assert _run(w) == 0
        assert w.db["settings"][0]["v"] == "restored"
        assert (w.etc / "mfa_key").read_bytes() == b"NEW-MFA"


class TestExistingFilesNotInTheBundle:
    def test_bundle_files_overwrite_unknown_files_stay_and_are_named(self, world, capsys):
        (world.etc / "extra.conf").write_bytes(b"operator-added")
        (world.content / "uploads").mkdir()
        (world.content / "uploads" / "keepme.txt").write_bytes(b"mine")
        assert _run(world) == 0
        out = capsys.readouterr().out
        assert (world.etc / "mfa_key").read_bytes() == b"NEW-MFA"  # overwritten
        assert (world.etc / "extra.conf").read_bytes() == b"operator-added"  # left in place
        assert (world.content / "uploads" / "keepme.txt").read_bytes() == b"mine"
        assert "left in place" in out and "extra.conf" in out and "uploads/keepme.txt" in out
        # files the bundle itself carries are never reported as unknown
        assert "mfa_key" not in out.split("left in place", 1)[1]

    def test_snapshots_and_backups_are_never_reported(self, world, capsys):
        assert _run(world) == 0
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("left in place")]
        assert not any("pre-restore" in ln or "backups" in ln for ln in lines)


class TestPluginsInTheManifest:
    def test_unknown_plugin_warns_and_restore_continues(self, world, capsys):
        _make_bundle(world, manifest={"plugins": [{"id": "no-such-plugin", "version": "9.9.9"}]})
        assert _run(world) == 0
        err = capsys.readouterr().err
        assert "no-such-plugin" in err and "database row is kept" in err

    def test_a_bundled_plugin_does_not_warn(self, world, capsys, monkeypatch):
        import pathlib

        from jen import extensions

        monkeypatch.setattr(extensions, "JEN_ROOT", str(pathlib.Path(__file__).resolve().parent.parent))
        _make_bundle(world, manifest={"plugins": [{"id": "ipam", "version": "1.5.1"}]})
        assert _run(world) == 0
        assert "ipam" not in capsys.readouterr().err


class TestCleanMachine:
    def test_nothing_pre_existing(self, world, tmp_path):
        etc, content = tmp_path / "fresh_etc", tmp_path / "fresh_content"
        world.state.active = False
        rc = restore.run(str(world.bundle), PASS, etc_jen=str(etc), content_dir=str(content))
        assert rc == 0
        assert (etc / "mfa_key").read_bytes() == b"NEW-MFA"
        assert (content / "icons" / "logo.png").read_bytes() == b"new-logo"
