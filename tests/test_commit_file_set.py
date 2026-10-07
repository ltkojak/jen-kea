"""
tests/test_commit_file_set.py - v5.68.0-beta.16 (Q151, item 5): a set of certificate files is installed ALL-OR-NOTHING.

`certs.write_atomically` moved the LIVE file to `<name>.prev` before its replacement existed (a failure right after left no live file at all), the HTTPS
upload wrote cert, key, CA and combined chain in sequence, and `kea_tls.commit_rotation` promoted four staged files one by one - after the remote
servers had already moved to the new CA. `certs.commit_file_set` stages every member (unique private temp), snapshots every live member WITHOUT moving
it (a `.prev` COPY), replaces each, and on any failure puts every replaced member back byte-for-byte. The failure injection below breaks the install
BEFORE and AFTER every member - in the staging, in the `.prev` copy, in the replace - and after every failure asserts the live set equals the original,
no key/cert mismatch exists, and no staged temp is left behind.

The helper's own `install-tls` has the same shape in its own code (tests/test_kea_helper.py::TestInstallTlsIsASetCommit).
"""

import os
import stat
import sys

import pytest

from jen.services import certs, private_files

MEMBERS = [
    ("key.pem", b"-----BEGIN PRIVATE KEY-----\nNEW\n-----END PRIVATE KEY-----\n", 0o640),
    ("cert.pem", b"-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----\n", 0o644),
    ("ca.pem", b"-----BEGIN CERTIFICATE-----\nNEW-CA\n-----END CERTIFICATE-----\n", 0o644),
    ("combined.pem", b"NEW-COMBINED\n", 0o644),
]
posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


def _live(tmp_path, existing=True):
    """The live set (as the OLD install left it) and the member list for the new one."""
    originals = {}
    for name, _new, mode in MEMBERS:
        if existing:
            path = tmp_path / name
            path.write_bytes(b"OLD-" + name.encode())
            os.chmod(path, mode)
            originals[name] = (b"OLD-" + name.encode(), mode)
    return originals, [(str(tmp_path / name), data, mode) for name, data, mode in MEMBERS]


def _assert_untouched(tmp_path, originals):
    for name, (content, mode) in originals.items():
        path = tmp_path / name
        assert path.read_bytes() == content, f"{name} is not what it was"
        if sys.platform != "win32":
            assert stat.S_IMODE(path.stat().st_mode) == mode, f"{name}'s mode changed"
    for name, _data, _mode in MEMBERS:
        if name not in originals:
            assert not (tmp_path / name).exists(), f"{name} did not exist before and must not exist now"
    allowed = {name for name, _d, _m in MEMBERS} | {name + ".prev" for name, _d, _m in MEMBERS}
    stray = sorted(p.name for p in tmp_path.iterdir() if p.name not in allowed)
    assert stray == [], f"staged temp files were left behind: {stray}"


class TestTheSetIsInstalled:
    def test_every_member_is_replaced_and_the_previous_files_are_kept_as_copies(self, tmp_path):
        originals, members = _live(tmp_path)
        certs.commit_file_set(members)
        for name, data, _mode in MEMBERS:
            assert (tmp_path / name).read_bytes() == data
            assert (tmp_path / (name + ".prev")).read_bytes() == originals[name][0], "the previous file, as a COPY"
        assert sorted(p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")) == []

    @posix
    def test_modes_are_the_final_ones(self, tmp_path):
        certs.commit_file_set(_live(tmp_path)[1])
        for name, _data, mode in MEMBERS:
            assert stat.S_IMODE((tmp_path / name).stat().st_mode) == mode

    def test_a_first_install_has_no_prev_and_creates_every_member(self, tmp_path):
        _originals, members = _live(tmp_path, existing=False)
        certs.commit_file_set(members)
        assert sorted(p.name for p in tmp_path.iterdir()) == sorted(name for name, _d, _m in MEMBERS)

    def test_write_atomically_is_a_set_of_one_and_the_live_file_never_disappears(self, tmp_path, monkeypatch):
        """The old writer did os.replace(live, live + '.prev') FIRST: between that and the replacement there was NO live file."""
        live = tmp_path / "cert.pem"
        live.write_bytes(b"OLD")
        real = os.replace
        seen = []

        def watching(src, dst, *a, **k):
            seen.append(live.exists())
            return real(src, dst, *a, **k)

        monkeypatch.setattr(os, "replace", watching)
        certs.write_atomically(str(live), b"NEW", 0o644)
        assert seen and all(seen), "the live file existed at every rename"
        assert live.read_bytes() == b"NEW" and (tmp_path / "cert.pem.prev").read_bytes() == b"OLD"


class TestAFailureAnywhereLeavesTheOriginalSet:
    """Before and after EVERY member: n = 0 fails the first member's step (nothing replaced yet), n = 3 the last (three already replaced)."""

    @pytest.mark.parametrize("n", range(len(MEMBERS)))
    def test_a_failing_replace_puts_every_replaced_member_back(self, tmp_path, monkeypatch, n):
        originals, members = _live(tmp_path)
        real = os.replace
        target = members[n][0]

        def failing(src, dst, *a, **k):
            if str(dst) == target:
                raise OSError(28, "No space left on device")
            return real(src, dst, *a, **k)

        monkeypatch.setattr(os, "replace", failing)
        with pytest.raises(OSError):
            certs.commit_file_set(members)
        monkeypatch.setattr(os, "replace", real)
        _assert_untouched(tmp_path, originals)

    @pytest.mark.parametrize("n", range(len(MEMBERS)))
    def test_a_failing_staging_touches_no_live_file(self, tmp_path, monkeypatch, n):
        originals, members = _live(tmp_path)
        real = private_files.stage_private_file
        calls = {"n": 0}

        def failing(path, data, mode=0o600, **kw):
            calls["n"] += 1
            if calls["n"] == n + 1:
                raise OSError(5, "Input/output error")
            return real(path, data, mode, **kw)

        monkeypatch.setattr(private_files, "stage_private_file", failing)
        with pytest.raises(OSError):
            certs.commit_file_set(members)
        _assert_untouched(tmp_path, originals)

    @pytest.mark.parametrize("n", range(len(MEMBERS)))
    def test_a_failing_prev_copy_replaces_nothing(self, tmp_path, monkeypatch, n):
        originals, members = _live(tmp_path)
        real = private_files.write_private_file
        calls = {"n": 0}

        def failing(path, data, mode=0o600, **kw):
            if str(path).endswith(".prev"):
                calls["n"] += 1
                if calls["n"] == n + 1:
                    raise OSError(28, "No space left on device")
            return real(path, data, mode, **kw)

        monkeypatch.setattr(private_files, "write_private_file", failing)
        with pytest.raises(OSError):
            certs.commit_file_set(members)
        monkeypatch.setattr(private_files, "write_private_file", real)
        _assert_untouched(tmp_path, originals)

    def test_a_member_that_did_not_exist_is_removed_again(self, tmp_path, monkeypatch):
        """A first CA bundle (no ca.pem before): the LAST member fails after it was created - it must not be left behind."""
        originals, members = _live(tmp_path)
        (tmp_path / "ca.pem").unlink()
        originals.pop("ca.pem")
        real = os.replace

        def failing(src, dst, *a, **k):
            if str(dst) == members[3][0]:
                raise OSError(28, "No space left on device")
            return real(src, dst, *a, **k)

        monkeypatch.setattr(os, "replace", failing)
        with pytest.raises(OSError):
            certs.commit_file_set(members)
        monkeypatch.setattr(os, "replace", real)
        _assert_untouched(tmp_path, originals)

    def test_no_key_and_certificate_mismatch_exists_after_any_failure(self, tmp_path, monkeypatch):
        """The set is a pair: whichever replace fails, key.pem and cert.pem are BOTH old or BOTH new - never one of each."""
        real = os.replace
        for n in range(len(MEMBERS)):
            for stale in tmp_path.iterdir():
                stale.unlink()
            _originals, members = _live(tmp_path)

            def failing(src, dst, *a, members=members, n=n, **k):
                if str(dst) == members[n][0]:
                    raise OSError(28, "No space left on device")
                return real(src, dst, *a, **k)

            monkeypatch.setattr(os, "replace", failing)
            with pytest.raises(OSError):
                certs.commit_file_set(members)
            monkeypatch.setattr(os, "replace", real)
            assert (tmp_path / "key.pem").read_bytes().startswith(b"OLD") and (
                tmp_path / "cert.pem"
            ).read_bytes().startswith(b"OLD")

    def test_a_restore_that_also_fails_names_every_path_that_is_now_wrong(self, tmp_path, monkeypatch):
        originals, members = _live(tmp_path)
        real_replace = os.replace
        real_write = private_files.write_private_file

        def fail_third_replace(src, dst, *a, **k):
            if str(dst) == members[2][0]:
                raise OSError(28, "No space left on device")
            return real_replace(src, dst, *a, **k)

        def fail_restoring_the_first(path, data, mode=0o600, **kw):
            if str(path) == members[0][0]:
                raise OSError(5, "Input/output error")
            return real_write(path, data, mode, **kw)

        monkeypatch.setattr(os, "replace", fail_third_replace)
        monkeypatch.setattr(private_files, "write_private_file", fail_restoring_the_first)
        with pytest.raises(OSError) as excinfo:
            certs.commit_file_set(members)
        assert members[0][0] in str(excinfo.value) and "now wrong" in str(excinfo.value)
        assert members[1][0] not in str(excinfo.value), "the second member WAS restored"
        assert isinstance(excinfo.value.__cause__, OSError) and excinfo.value.__cause__.errno == 28

    @posix
    def test_a_symlink_at_a_live_path_is_refused_and_nothing_changes(self, tmp_path):
        originals, members = _live(tmp_path)
        (tmp_path / "cert.pem").unlink()
        victim = tmp_path / "victim"
        victim.write_bytes(b"keep")
        os.symlink(victim, tmp_path / "cert.pem")
        with pytest.raises(OSError):
            certs.commit_file_set(members)
        assert victim.read_bytes() == b"keep" and (tmp_path / "cert.pem").is_symlink()
        assert (tmp_path / "key.pem").read_bytes() == b"OLD-key.pem"


class TestTheKeaCaRotationIsOneSet:
    def _staged(self, tmp_path):
        from jen.services import kea_tls

        live = {"ca_key": "ca.key", "ca_cert": "ca.crt", "client_key": "client.key", "client_cert": "client.crt"}
        staged = {}
        for kind, name in live.items():
            (tmp_path / name).write_bytes(b"OLD-" + name.encode())
            staged[kind] = str(tmp_path / (name + kea_tls._STAGE_SUFFIX))
            (tmp_path / (name + kea_tls._STAGE_SUFFIX)).write_bytes(b"NEW-" + name.encode())
        return kea_tls, staged, live

    def test_commit_promotes_all_four_and_discards_the_staged_files(self, tmp_path):
        kea_tls, staged, live = self._staged(tmp_path)
        kea_tls.commit_rotation(staged)
        for name in live.values():
            assert (tmp_path / name).read_bytes() == b"NEW-" + name.encode()
            assert (tmp_path / (name + ".prev")).read_bytes() == b"OLD-" + name.encode()
        assert not any(p.name.endswith(kea_tls._STAGE_SUFFIX) for p in tmp_path.iterdir())

    @pytest.mark.parametrize("n", range(4))
    def test_a_failure_before_or_after_any_member_restores_all_four(self, tmp_path, monkeypatch, n):
        kea_tls, staged, live = self._staged(tmp_path)
        order = [live[k] for k in ("ca_key", "ca_cert", "client_key", "client_cert")]
        real = os.replace

        def failing(src, dst, *a, **k):
            if str(dst) == str(tmp_path / order[n]):
                raise OSError(28, "No space left on device")
            return real(src, dst, *a, **k)

        monkeypatch.setattr(os, "replace", failing)
        with pytest.raises(OSError):
            kea_tls.commit_rotation(staged)
        monkeypatch.setattr(os, "replace", real)
        for name in order:
            assert (tmp_path / name).read_bytes() == b"OLD-" + name.encode(), (
                f"{name} is not the original CA/client material"
            )
        assert all(os.path.exists(p) for p in staged.values()), (
            "the staged files are kept so the rotation can be retried or discarded"
        )

    def test_ensure_ca_installs_the_key_and_certificate_as_a_pair(self, tmp_path, monkeypatch):
        from jen.services import kea_tls

        monkeypatch.setattr(kea_tls, "SSL_DIR", str(tmp_path))
        monkeypatch.setattr(kea_tls, "ca_paths", lambda: (str(tmp_path / "ca.crt"), str(tmp_path / "ca.key")))
        first = kea_tls.ensure_ca()
        assert first["created"] is True
        before = ((tmp_path / "ca.crt").read_bytes(), (tmp_path / "ca.key").read_bytes())
        real = os.replace

        def failing(src, dst, *a, **k):
            if str(dst) == str(tmp_path / "ca.crt"):
                raise OSError(28, "No space left on device")
            return real(src, dst, *a, **k)

        monkeypatch.setattr(os, "replace", failing)
        with pytest.raises(OSError):
            kea_tls.ensure_ca(force=True)
        monkeypatch.setattr(os, "replace", real)
        assert ((tmp_path / "ca.crt").read_bytes(), (tmp_path / "ca.key").read_bytes()) == before, (
            "a new key was NOT left beside the old certificate"
        )
