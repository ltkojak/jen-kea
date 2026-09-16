"""
tests/test_recovery.py
────────────────────────
v5.44.0 (Q45) — jen/services/recovery.py: the recovery bundle's
encryption envelope. Pure (no DB, no filesystem beyond what a test
hands it directly) — `python -m pytest --noconftest tests/test_recovery.py`.
"""

import pytest

from jen.services.recovery import (
    MAGIC,
    BadPassphrase,
    BundleTooLarge,
    build,
    build_tar,
    decrypt,
    encrypt,
    open_bundle,
)


class TestRoundTrip:
    def test_build_and_open_recovers_every_member(self):
        members = {"manifest.json": b'{"v": 1}', "jen.config": b"[server]\nhttp_port=80\n"}
        blob = build(members, "correct horse battery staple")
        tf = open_bundle(blob, "correct horse battery staple")
        assert set(tf.getnames()) == set(members)
        for name, content in members.items():
            assert tf.extractfile(name).read() == content

    def test_starts_with_magic(self):
        blob = build({"x": b"y"}, "correct horse battery staple")
        assert blob.startswith(MAGIC)

    def test_binary_content_survives(self):
        members = {"blob": bytes(range(256)) * 4}
        blob = build(members, "correct horse battery staple")
        tf = open_bundle(blob, "correct horse battery staple")
        assert tf.extractfile("blob").read() == members["blob"]

    def test_empty_members_still_produces_a_valid_bundle(self):
        blob = build({}, "correct horse battery staple")
        tf = open_bundle(blob, "correct horse battery staple")
        assert tf.getnames() == []

    def test_two_builds_of_the_same_content_differ(self):
        """Fresh salt+nonce every call — same plaintext, same passphrase,
        different ciphertext, so a bundle never reveals whether it's a
        repeat of an earlier one."""
        members = {"x": b"y"}
        a = build(members, "correct horse battery staple")
        b = build(members, "correct horse battery staple")
        assert a != b


class TestWrongPassphrase:
    def test_wrong_passphrase_refused(self):
        blob = build({"x": b"y"}, "correct horse battery staple")
        with pytest.raises(BadPassphrase):
            open_bundle(blob, "definitely the wrong one")

    def test_error_never_reveals_which_part_was_wrong(self):
        """AES-GCM can't distinguish 'wrong key' from 'tampered
        ciphertext' — and there's no reason a caller should be able to
        either; giving a different message for each would help an
        attacker verify guesses faster."""
        blob = build({"x": b"y"}, "correct horse battery staple")
        try:
            open_bundle(blob, "wrong")
            pytest.fail("expected BadPassphrase")
        except BadPassphrase as e:
            assert "corrupt" in str(e) or "wrong" in str(e)


class TestTamperDetection:
    def test_flipped_header_byte_refused(self):
        blob = bytearray(build({"x": b"y"}, "correct horse battery staple"))
        blob[3] ^= 0xFF  # inside MAGIC
        with pytest.raises(BadPassphrase):
            open_bundle(bytes(blob), "correct horse battery staple")

    def test_flipped_ciphertext_byte_refused(self):
        blob = bytearray(build({"x": b"y"}, "correct horse battery staple"))
        blob[-1] ^= 0xFF
        with pytest.raises(BadPassphrase):
            open_bundle(bytes(blob), "correct horse battery staple")

    def test_truncated_blob_refused(self):
        blob = build({"x": b"y"}, "correct horse battery staple")
        with pytest.raises(BadPassphrase):
            open_bundle(blob[:10], "correct horse battery staple")

    def test_empty_blob_refused(self):
        with pytest.raises(BadPassphrase):
            open_bundle(b"", "correct horse battery staple")

    def test_wrong_magic_refused(self):
        blob = build({"x": b"y"}, "correct horse battery staple")
        forged = b"NOTJENREC" + blob[len(MAGIC) :]
        with pytest.raises(BadPassphrase):
            open_bundle(forged, "correct horse battery staple")


class TestSizeCap:
    """Monkeypatches the module's own SIZE_CAP_BYTES to a small value —
    building real 200MB blobs in every test would work but is wasteful
    CI time/memory for exercising an off-by-one in a comparison."""

    def test_over_the_cap_refused(self, monkeypatch):
        import jen.services.recovery as recovery_mod

        monkeypatch.setattr(recovery_mod, "SIZE_CAP_BYTES", 100)
        with pytest.raises(BundleTooLarge):
            recovery_mod.build({"big": b"0" * 101}, "correct horse battery staple")

    def test_encrypt_checks_the_cap_directly_too(self, monkeypatch):
        import jen.services.recovery as recovery_mod

        monkeypatch.setattr(recovery_mod, "SIZE_CAP_BYTES", 100)
        with pytest.raises(BundleTooLarge):
            recovery_mod.encrypt(b"0" * 101, "correct horse battery staple")

    def test_exactly_at_the_cap_is_allowed(self, monkeypatch):
        import jen.services.recovery as recovery_mod

        monkeypatch.setattr(recovery_mod, "SIZE_CAP_BYTES", 100)
        recovery_mod.encrypt(b"0" * 100, "correct horse battery staple")  # no raise

    def test_realistic_full_size_bundle_still_refused(self):
        """One real-scale check (the actual 200MB default), not
        monkeypatched, so the production constant itself is exercised
        at least once."""
        with pytest.raises(BundleTooLarge):
            build({"big": b"0" * (200 * 1024 * 1024 + 1)}, "correct horse battery staple")


class TestLowLevelHelpers:
    def test_build_tar_then_decrypt_round_trips_without_the_high_level_api(self):
        tar_bytes = build_tar({"a.txt": b"hello"})
        blob = encrypt(tar_bytes, "correct horse battery staple")
        recovered = decrypt(blob, "correct horse battery staple")
        assert recovered == tar_bytes

    def test_unicode_passphrase(self):
        blob = build({"x": b"y"}, "pässwörd with ünïcode 日本語")
        tf = open_bundle(blob, "pässwörd with ünïcode 日本語")
        assert tf.extractfile("x").read() == b"y"
