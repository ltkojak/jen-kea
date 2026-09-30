"""
tests/test_restore.py
───────────────────────
v5.44.0 (Q45) — jen/tools/restore.py. The pure/filesystem-only pieces
(check_jen_major, extract_bundle, restore_etc_jen, restore_content) run
with `--noconftest`; the full run() round trip needs the real DB (it
actually imports jen_db.json.gz), same as everything else that
exercises dbexport.import_jen().
"""

import json

import pytest

from jen.services.recovery import build


def _manifest(**overrides):
    from jen import JEN_VERSION

    base = {
        "jen_version": JEN_VERSION,
        "channel": "beta",
        "hostname": "old-box",
        "created_at": "2026-01-01T00:00:00Z",
        "schema_version": 27,
        "kea_versions": {},
        "plugins": [],
        "helper_versions": {},
    }
    base.update(overrides)
    return base


class TestCheckJenMajor:
    def test_matching_major_passes(self):
        from jen.tools.restore import check_jen_major

        check_jen_major(_manifest())  # must not raise

    def test_mismatched_major_refused(self):
        from jen import JEN_VERSION
        from jen.tools.restore import RestoreRefused, check_jen_major
        from jen.version import parse_version

        here_major = parse_version(JEN_VERSION)[0]
        with pytest.raises(RestoreRefused):
            check_jen_major(_manifest(jen_version=f"{here_major + 1}.0.0"))

    def test_unparsable_bundle_version_refused(self):
        from jen.tools.restore import RestoreRefused, check_jen_major

        with pytest.raises(RestoreRefused):
            check_jen_major(_manifest(jen_version="not-a-version"))


class TestExtractAndManifest:
    def test_extract_bundle_writes_every_member(self, tmp_path):
        from jen.tools.restore import extract_bundle

        members = {"manifest.json": json.dumps(_manifest()).encode(), "jen.config": b"[kea]\n"}
        blob = build(members, "correct horse battery staple")
        dest = tmp_path / "extracted"
        extract_bundle(blob, "correct horse battery staple", dest)
        assert (dest / "manifest.json").is_file()
        assert (dest / "jen.config").read_bytes() == b"[kea]\n"

    def test_wrong_passphrase_raises_bad_passphrase(self, tmp_path):
        from jen.services.recovery import BadPassphrase
        from jen.tools.restore import extract_bundle

        blob = build({"x": b"y"}, "correct horse battery staple")
        with pytest.raises(BadPassphrase):
            extract_bundle(blob, "wrong one", tmp_path / "extracted")

    def test_load_manifest_missing_file_refused(self, tmp_path):
        from jen.tools.restore import RestoreRefused, load_manifest

        with pytest.raises(RestoreRefused):
            load_manifest(tmp_path)

    def test_load_manifest_reads_real_content(self, tmp_path):
        from jen.tools.restore import load_manifest

        (tmp_path / "manifest.json").write_text(json.dumps(_manifest(hostname="test-host")), encoding="utf-8")
        manifest = load_manifest(tmp_path)
        assert manifest["hostname"] == "test-host"


class TestRestoreEtcJen:
    def test_writes_config_key_and_ssl_ssh_with_restrictive_perms(self, tmp_path):
        import os
        import stat

        from jen.tools.restore import restore_etc_jen

        bundle_dir = tmp_path / "bundle"
        (bundle_dir / "ssl").mkdir(parents=True)
        (bundle_dir / "ssh").mkdir(parents=True)
        (bundle_dir / "jen.config").write_bytes(b"[kea]\n")
        (bundle_dir / "mfa_key").write_bytes(b"fake-key-bytes")
        (bundle_dir / "ssl" / "certificate.crt").write_bytes(b"cert")
        (bundle_dir / "ssh" / "jen_rsa").write_bytes(b"private-key")

        etc_jen = tmp_path / "etc_jen"
        lines = restore_etc_jen(bundle_dir, etc_jen)

        assert (etc_jen / "jen.config").read_bytes() == b"[kea]\n"
        assert (etc_jen / "mfa_key").read_bytes() == b"fake-key-bytes"
        assert (etc_jen / "ssl" / "certificate.crt").read_bytes() == b"cert"
        assert (etc_jen / "ssh" / "jen_rsa").read_bytes() == b"private-key"
        assert any("jen.config" in ln for ln in lines)

        if os.name != "nt":  # chmod is a no-op on Windows
            mode = stat.S_IMODE(os.stat(etc_jen / "jen.config").st_mode)
            assert mode == 0o600

    def test_missing_optional_members_are_skipped_not_errored(self, tmp_path):
        from jen.tools.restore import restore_etc_jen

        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        lines = restore_etc_jen(bundle_dir, tmp_path / "etc_jen")
        assert lines == []


class TestRestoreContent:
    def test_restores_nested_files(self, tmp_path):
        from jen.tools.restore import restore_content

        bundle_dir = tmp_path / "bundle"
        (bundle_dir / "content" / "icons").mkdir(parents=True)
        (bundle_dir / "content" / "icons" / "logo.png").write_bytes(b"fake-png")

        content_dir = tmp_path / "content"
        count = restore_content(bundle_dir, content_dir)

        assert count == 1
        assert (content_dir / "icons" / "logo.png").read_bytes() == b"fake-png"

    def test_no_content_member_is_a_harmless_no_op(self, tmp_path):
        from jen.tools.restore import restore_content

        assert restore_content(tmp_path / "bundle", tmp_path / "content") == 0


def _raw_tar(entries):
    """entries: list of (name, kind, payload) -> uncompressed tar bytes.
    kind: file | dir | sym | hard | fifo. Built by hand because
    recovery.build_tar only ever writes regular files."""
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name=name)
            if kind == "file":
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                tf.addfile(info)
            elif kind == "hard":
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                tf.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
                tf.addfile(info)
    return buf.getvalue()


class TestSafeExtract:
    """v5.49.0-beta.2 (audit A) - the root-run extractor never depends on the
    interpreter's tarfile `filter=` and refuses everything but plain,
    in-tree files and directories - before writing anything."""

    PASS = "correct horse battery staple"

    def _extract(self, entries, tmp_path):
        from jen.services.recovery import encrypt
        from jen.tools.restore import extract_bundle

        dest = tmp_path / "out"
        extract_bundle(encrypt(_raw_tar(entries), self.PASS), self.PASS, dest)
        return dest

    @pytest.mark.parametrize(
        "entry",
        [
            ("../../etc/passwd", "file", b"x"),
            ("/etc/passwd", "file", b"x"),
            ("a/../../escape", "file", b"x"),
            ("link", "sym", "/etc"),
            ("hard", "hard", "manifest.json"),
            ("pipe", "fifo", None),
        ],
    )
    def test_unsafe_member_refused_and_nothing_written(self, entry, tmp_path):
        from jen.tools.restore import RestoreRefused

        with pytest.raises(RestoreRefused) as exc:
            self._extract([("manifest.json", "file", b"{}"), entry], tmp_path)
        assert entry[0] in str(exc.value)
        # validated before writing: even the harmless first member is absent
        assert not (tmp_path / "out" / "manifest.json").exists()
        assert not (tmp_path / "escape").exists()
        assert not (tmp_path.parent / "escape").exists()

    def test_normal_bundle_restores_every_member(self, tmp_path):
        dest = self._extract(
            [
                ("manifest.json", "file", b"{}"),
                ("content", "dir", None),
                ("content/keys/x.txt", "file", b"k"),
                ("ssl/cert.pem", "file", b"c"),
            ],
            tmp_path,
        )
        assert (dest / "manifest.json").read_bytes() == b"{}"
        assert (dest / "content" / "keys" / "x.txt").read_bytes() == b"k"
        assert (dest / "ssl" / "cert.pem").read_bytes() == b"c"


class TestRestoreKeysAndVersionGate:
    def test_both_keys_written_0600(self, tmp_path):
        import os
        import stat

        from jen.tools.restore import restore_etc_jen

        bundle = tmp_path / "b"
        bundle.mkdir()
        (bundle / "mfa_key").write_bytes(b"m" * 44)
        (bundle / "secret_key").write_bytes(b"s" * 64)
        etc = tmp_path / "etc"
        etc.mkdir()
        lines = restore_etc_jen(bundle, etc)
        assert "wrote mfa_key" in lines and "wrote secret_key" in lines
        if os.name != "nt":
            for name in ("mfa_key", "secret_key"):
                assert stat.S_IMODE((etc / name).stat().st_mode) == 0o600

    def test_legacy_content_keys_are_written_0600_not_0644(self, tmp_path):
        import os
        import stat

        from jen.tools.restore import restore_content

        bundle = tmp_path / "b"
        (bundle / "content" / "keys").mkdir(parents=True)
        (bundle / "content" / "keys" / ".secret_key").write_bytes(b"s")
        (bundle / "content" / "logo.png").write_bytes(b"p")
        content = tmp_path / "content"
        restore_content(bundle, content)
        if os.name != "nt":
            assert stat.S_IMODE((content / "keys" / ".secret_key").stat().st_mode) == 0o600
            assert stat.S_IMODE((content / "logo.png").stat().st_mode) == 0o644

    def test_newer_jen_refused_unless_forced(self):
        from jen.tools.restore import RestoreRefused, check_bundle_version

        newer = _manifest(jen_version="5.999.0")
        with pytest.raises(RestoreRefused) as exc:
            check_bundle_version(newer)
        assert "newer" in str(exc.value)
        check_bundle_version(newer, force=True)  # must not raise

    def test_schema_ahead_refused_unless_forced(self):
        from jen.models.migrations import MIGRATIONS
        from jen.tools.restore import RestoreRefused, check_bundle_version

        ahead = _manifest(schema_version=MIGRATIONS[-1][0] + 1)
        with pytest.raises(RestoreRefused):
            check_bundle_version(ahead)
        check_bundle_version(ahead, force=True)

    def test_older_bundle_is_the_supported_direction(self):
        from jen.tools.restore import check_bundle_version

        check_bundle_version(_manifest(jen_version="5.1.0", schema_version=3))
        check_bundle_version(_manifest())  # same version, current schema


class TestCheckKeaMajor:
    """Needs a real (if minimal) jen.config to reload from — no DB
    access happens here, config.AppConfig.reload() only parses the INI
    and populates extensions.*, so this runs fine without a database."""

    def _write_config(self, path, api_url="http://127.0.0.1:1"):
        path.write_text(
            f"[kea]\napi_url = {api_url}\napi_user = u\napi_pass = p\n"
            "[kea_db]\nhost = localhost\nuser = u\npassword = p\n"
            "[jen_db]\nhost = localhost\nuser = u\npassword = p\n",
            encoding="utf-8",
        )

    def test_no_jen_config_in_bundle_skips_with_a_warning(self, tmp_path):
        from jen.tools.restore import check_kea_major

        warnings = check_kea_major(_manifest(), tmp_path / "bundle")
        assert any("no jen.config" in w for w in warnings)

    def test_unreachable_server_warns_but_does_not_refuse(self, tmp_path, monkeypatch):
        import contextlib

        from jen import config as jen_config
        from jen import extensions
        from jen.tools.restore import check_kea_major

        original = extensions.CONFIG_FILE
        good_original = tmp_path / "original.config"
        self._write_config(good_original)
        monkeypatch.setattr(extensions, "CONFIG_FILE", str(good_original))
        try:
            bundle_dir = tmp_path / "bundle"
            bundle_dir.mkdir()
            self._write_config(bundle_dir / "jen.config", api_url="http://127.0.0.1:1")
            warnings = check_kea_major(_manifest(), bundle_dir)
            assert any("unreachable" in w for w in warnings)
        finally:
            # check_kea_major() reloads extensions.* from `good_original`
            # (fake creds) as part of its own restore-CONFIG_FILE finally.
            # Resetting the CONFIG_FILE string back here isn't enough on
            # its own — extensions.JEN_DB_USER/PASS/etc stay pointed at
            # the fake config until reload() re-derives them, and a later
            # test in this same process (e.g. a real DB connection) would
            # otherwise inherit that corruption.
            monkeypatch.setattr(extensions, "CONFIG_FILE", original)
            with contextlib.suppress(Exception):
                jen_config.app_config.reload()


class TestMemAvailableBytes:
    """v5.66.0-beta.4 (Q106) — _mem_available_bytes() parses a real /proc/meminfo-shaped
    file; a test overrides the path rather than mocking /proc itself (which doesn't exist
    on every platform this suite runs on)."""

    def _write_meminfo(self, path, mem_available_kb):
        path.write_text(
            "MemTotal:       16330000 kB\n"
            "MemFree:         1234000 kB\n"
            f"MemAvailable:   {mem_available_kb} kB\n"
            "Buffers:          200000 kB\n",
            encoding="utf-8",
        )

    def test_parses_mem_available_kb_as_bytes(self, tmp_path):
        from jen.tools.restore import _mem_available_bytes

        p = tmp_path / "meminfo"
        self._write_meminfo(p, 2048000)
        assert _mem_available_bytes(str(p)) == 2048000 * 1024

    def test_missing_file_returns_none(self, tmp_path):
        from jen.tools.restore import _mem_available_bytes

        assert _mem_available_bytes(str(tmp_path / "does-not-exist")) is None

    def test_no_mem_available_line_returns_none(self, tmp_path):
        from jen.tools.restore import _mem_available_bytes

        p = tmp_path / "meminfo"
        p.write_text("MemTotal:       16330000 kB\nMemFree:         1234000 kB\n", encoding="utf-8")
        assert _mem_available_bytes(str(p)) is None

    def test_unparseable_value_returns_none(self, tmp_path):
        from jen.tools.restore import _mem_available_bytes

        p = tmp_path / "meminfo"
        p.write_text("MemAvailable:   not-a-number kB\n", encoding="utf-8")
        assert _mem_available_bytes(str(p)) is None


class TestCheckMemory:
    """v5.66.0-beta.6 (Q108) — the pre-restore admission guard: refuses BEFORE anything is
    stopped or touched when `max(incoming, existing) × RESTORE_MEMORY_FACTOR` exceeds what
    /proc/meminfo currently reports available, or the snapshot directory doesn't have room.
    `_sizing_pass()` (a real write_jen_export() to the box's CURRENT database) is mocked in
    every test here — it needs a real DB connection, which these pure tests don't have."""

    def test_no_recorded_size_and_tiny_existing_skips_the_check(self, monkeypatch, tmp_path):
        from jen.tools import restore

        monkeypatch.setattr(restore, "_mem_available_bytes", lambda: 0)  # would refuse if reached
        monkeypatch.setattr(restore, "_sizing_pass", lambda snap_dir: (0, 0))
        restore.check_memory(_manifest(), str(tmp_path))  # no jen_db_uncompressed_bytes key at all

    def test_unreadable_meminfo_skips_the_check_entirely(self, monkeypatch, tmp_path):
        """available is None short-circuits BEFORE the sizing pass ever runs."""
        from jen.tools import restore

        monkeypatch.setattr(restore, "_mem_available_bytes", lambda: None)

        def boom(snap_dir):
            raise AssertionError("the sizing pass ran even though meminfo was unreadable")

        monkeypatch.setattr(restore, "_sizing_pass", boom)
        restore.check_memory(_manifest(jen_db_uncompressed_bytes=10**12), str(tmp_path))

    def test_plenty_of_memory_passes(self, monkeypatch, tmp_path):
        from jen.tools import restore

        monkeypatch.setattr(restore, "_mem_available_bytes", lambda: 100 * 1024 * 1024 * 1024)  # 100 GB
        monkeypatch.setattr(restore, "_sizing_pass", lambda snap_dir: (1024, 1024))  # existing db negligible
        restore.check_memory(_manifest(jen_db_uncompressed_bytes=10 * 1024 * 1024), str(tmp_path))  # 10 MB

    def test_not_enough_memory_refuses_with_both_figures_named(self, monkeypatch, tmp_path):
        from jen.tools import restore

        monkeypatch.setattr(restore, "_mem_available_bytes", lambda: 100 * 1024 * 1024)  # 100 MB available
        monkeypatch.setattr(restore, "_sizing_pass", lambda snap_dir: (0, 0))  # existing db negligible
        with pytest.raises(restore.RestoreRefused) as exc:
            restore.check_memory(_manifest(jen_db_uncompressed_bytes=200 * 1024 * 1024), str(tmp_path))
        assert "MB" in str(exc.value)
        assert "MemAvailable" in str(exc.value)

    def test_the_existing_database_can_trigger_the_refusal_too(self, monkeypatch, tmp_path):
        """The actual property new in this Q: the OLD check only ever weighed the incoming
        bundle. A tiny incoming bundle onto a box whose CURRENT database is huge must still
        refuse — the pre-restore snapshot (and any later rollback) has to hold the existing
        database's own export just as much as an import holds the incoming one."""
        from jen.tools import restore

        monkeypatch.setattr(restore, "_mem_available_bytes", lambda: 100 * 1024 * 1024)  # 100 MB available
        monkeypatch.setattr(
            restore, "_sizing_pass", lambda snap_dir: (200 * 1024 * 1024, 20 * 1024 * 1024)
        )  # existing db needs ~1.4 GB at 7x
        with pytest.raises(restore.RestoreRefused) as exc:
            restore.check_memory(_manifest(jen_db_uncompressed_bytes=1024), str(tmp_path))  # tiny incoming
        assert "already on this machine" in str(exc.value)

    def test_a_sizing_pass_failure_degrades_to_the_incoming_side_alone(self, monkeypatch, tmp_path, capsys):
        """No DB reachable (or any other sizing-pass failure) must not block a restore over a
        measurement it simply couldn't take — it degrades, with a warning, rather than
        refusing outright."""
        from jen.tools import restore

        monkeypatch.setattr(restore, "_mem_available_bytes", lambda: 100 * 1024 * 1024 * 1024)  # 100 GB

        def boom(snap_dir):
            raise RuntimeError("database unreachable")

        monkeypatch.setattr(restore, "_sizing_pass", boom)
        restore.check_memory(_manifest(jen_db_uncompressed_bytes=10 * 1024 * 1024), str(tmp_path))
        assert "warning" in capsys.readouterr().err.lower()

    def test_insufficient_disk_space_refuses(self, monkeypatch, tmp_path):
        import types

        from jen.tools import restore

        monkeypatch.setattr(restore, "_mem_available_bytes", lambda: 100 * 1024 * 1024 * 1024)  # plenty of memory
        monkeypatch.setattr(restore, "_sizing_pass", lambda snap_dir: (1024, 500 * 1024 * 1024))  # 500 MB compressed
        monkeypatch.setattr(
            restore.shutil, "disk_usage", lambda path: types.SimpleNamespace(free=100 * 1024 * 1024)
        )  # only 100 MB free, needs 2x500=1000 MB
        with pytest.raises(restore.RestoreRefused) as exc:
            restore.check_memory(_manifest(jen_db_uncompressed_bytes=1024), str(tmp_path))
        assert "disk" in str(exc.value).lower()

    def test_refuses_before_anything_is_stopped_or_snapshotted(self, monkeypatch, tmp_path):
        """The property that actually matters: check_memory() runs strictly BEFORE
        run()'s quiesce/snapshot block — this drives run() far enough (with an
        artificially tiny available-memory answer) to prove it returns with nothing
        touched, rather than unit-testing check_memory() in isolation only."""
        import contextlib

        from jen import config as jen_config
        from jen import extensions
        from jen.tools import restore

        monkeypatch.setattr(restore, "_mem_available_bytes", lambda: 1)  # ~0 available
        monkeypatch.setattr(restore, "_sizing_pass", lambda snap_dir: (0, 0))
        called = {"stop": False, "snapshot": False}
        monkeypatch.setattr(restore, "_have_systemctl", lambda: True)
        monkeypatch.setattr(restore, "_service_active", lambda: (called.__setitem__("stop", True), True)[1])
        monkeypatch.setattr(restore, "take_snapshot", lambda *a, **k: called.__setitem__("snapshot", True))

        manifest = _manifest(jen_db_uncompressed_bytes=10 * 1024 * 1024 * 1024)  # 10 GB
        members = {"manifest.json": json.dumps(manifest).encode()}
        blob = build(members, "correct horse battery staple")
        bundle_path = tmp_path / "bundle.tar.enc"
        bundle_path.write_bytes(blob)

        original = extensions.CONFIG_FILE
        try:
            rc = restore.run(str(bundle_path), "correct horse battery staple", etc_jen=str(tmp_path / "etc_jen"))
        finally:
            monkeypatch.setattr(extensions, "CONFIG_FILE", original)
            with contextlib.suppress(Exception):
                jen_config.app_config.reload()

        assert rc == 1
        assert called == {"stop": False, "snapshot": False}


class TestRunEndToEnd:
    """The round trip the spec asks for: build a bundle from a temp
    tree, restore it into another temp tree. DB-backed — the bundle's
    jen_db.json.gz is a real export_jen() payload restored through
    dbexport.import_jen(), which needs a real connection."""

    def test_build_then_restore_round_trip(self, tmp_path, db, monkeypatch):
        import gzip

        from jen import extensions
        from jen.services import dbexport
        from jen.tools.restore import run

        # A settings row this test can look for after restore, to prove
        # the DB import actually ran (not just "didn't crash").
        with db.cursor() as cur:
            cur.execute("DELETE FROM settings WHERE setting_key='_q45_restore_probe'")
            cur.execute(
                "INSERT INTO settings (setting_key, setting_value) VALUES ('_q45_restore_probe', 'restored-ok')"
            )
        db.commit()

        content, _fname = dbexport.export_jen(["settings", "schema_migrations"])
        jen_db_gz = gzip.compress(content)

        # The bundle's own jen.config must carry THIS test's real DB
        # credentials — a restore onto "the same database" is exactly
        # what this simulates, and it's the only way dbexport.import_jen()
        # can reach the real test database from inside restore_jen_db()'s
        # own app_config.reload().
        bundle_config = (
            "[kea]\napi_url = http://127.0.0.1:1\napi_user = u\napi_pass = p\n"
            f"[kea_db]\nhost = {extensions.KEA_DB_HOST}\nuser = {extensions.KEA_DB_USER}\n"
            f"password = {extensions.KEA_DB_PASS}\ndatabase = {extensions.KEA_DB_NAME}\n"
            f"[jen_db]\nhost = {extensions.JEN_DB_HOST}\nuser = {extensions.JEN_DB_USER}\n"
            f"password = {extensions.JEN_DB_PASS}\ndatabase = {extensions.JEN_DB_NAME}\n"
        ).encode()

        members = {
            "manifest.json": json.dumps(_manifest()).encode(),
            "jen.config": bundle_config,
            "mfa_key": b"a" * 44,
            "ssl/certificate.crt": b"fake-cert",
            "content/icons/logo.png": b"fake-png",
            "jen_db.json.gz": jen_db_gz,
        }
        blob = build(members, "correct horse battery staple")
        bundle_path = tmp_path / "bundle.tar.enc"
        bundle_path.write_bytes(blob)

        etc_jen = tmp_path / "etc_jen"
        content_dir = tmp_path / "content"

        original_config_file = extensions.CONFIG_FILE
        try:
            rc = run(
                str(bundle_path), "correct horse battery staple", etc_jen=str(etc_jen), content_dir=str(content_dir)
            )
        finally:
            # run() leaves extensions.CONFIG_FILE pointed at etc_jen's
            # restored config (by design — see restore_jen_db) — put
            # the test environment's own config back for whatever runs
            # after this test in the same session.
            monkeypatch.setattr(extensions, "CONFIG_FILE", original_config_file)
            from jen import config as jen_config

            jen_config.app_config.reload()

        assert rc == 0
        assert (etc_jen / "jen.config").is_file()
        assert (etc_jen / "mfa_key").read_bytes() == b"a" * 44
        assert (etc_jen / "ssl" / "certificate.crt").read_bytes() == b"fake-cert"
        assert (content_dir / "icons" / "logo.png").read_bytes() == b"fake-png"

        with db.cursor() as cur:
            cur.execute("SELECT setting_value FROM settings WHERE setting_key='_q45_restore_probe'")
            row = cur.fetchone()
        assert row is not None and row["setting_value"] == "restored-ok"

        # v5.49.0-beta.3 — schema_migrations rode along: the restored DB
        # reports every migration as applied and the runner has nothing to do.
        from jen.models.migrations import MIGRATIONS, applied_versions, run_migrations

        assert applied_versions() == {v for v, _d, _fn in MIGRATIONS}
        assert run_migrations() == 0

    def test_wrong_passphrase_returns_nonzero_without_writing_anything(self, tmp_path):
        from jen.tools.restore import run

        members = {"manifest.json": json.dumps(_manifest()).encode()}
        blob = build(members, "correct horse battery staple")
        bundle_path = tmp_path / "bundle.tar.enc"
        bundle_path.write_bytes(blob)

        etc_jen = tmp_path / "etc_jen"
        rc = run(str(bundle_path), "wrong passphrase", etc_jen=str(etc_jen), content_dir=str(tmp_path / "content"))
        assert rc != 0
        assert not etc_jen.exists()

    def test_major_version_mismatch_refuses_without_writing_anything(self, tmp_path):
        from jen import JEN_VERSION
        from jen.tools.restore import run
        from jen.version import parse_version

        here_major = parse_version(JEN_VERSION)[0]
        members = {
            "manifest.json": json.dumps(_manifest(jen_version=f"{here_major + 1}.0.0")).encode(),
            "jen.config": b"[kea]\napi_url = x\napi_user = x\napi_pass = x\n",
        }
        blob = build(members, "correct horse battery staple")
        bundle_path = tmp_path / "bundle.tar.enc"
        bundle_path.write_bytes(blob)

        etc_jen = tmp_path / "etc_jen"
        rc = run(
            str(bundle_path),
            "correct horse battery staple",
            etc_jen=str(etc_jen),
            content_dir=str(tmp_path / "content"),
        )
        assert rc != 0
        assert not etc_jen.exists()
