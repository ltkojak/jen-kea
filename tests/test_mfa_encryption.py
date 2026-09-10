"""
tests/test_mfa_encryption.py
────────────────────────────
v5.4.0 — TOTP shared secrets (`mfa_methods.secret`) are encrypted at
rest with a Fernet key kept outside the database
(jen/services/crypto.py). These tests cover the crypto primitives,
migration 17 (which wraps pre-existing plaintext rows), the encrypt-on-
enrol / decrypt-on-verify wiring, and the fail-closed behaviour when a
secret can't be decrypted (e.g. a DB restored without its /etc/jen key).

conftest repoints extensions.MFA_KEY_PATH at /tmp for the whole suite.
"""

import pyotp
import pytest

from jen.models.db import jen_db
from jen.services import crypto


@pytest.fixture(autouse=True)
def _fresh_key_cache():
    crypto.reset_key_cache()
    yield
    crypto.reset_key_cache()


# ── Crypto primitives (no DB) ───────────────────────────────────────────────
class TestCryptoPrimitives:
    def test_round_trip(self):
        enc = crypto.encrypt_secret("JBSWY3DPEHPK3PXP")
        assert enc.startswith("v1:")
        assert "JBSWY3DPEHPK3PXP" not in enc
        assert crypto.decrypt_secret(enc) == "JBSWY3DPEHPK3PXP"

    def test_two_encryptions_differ_but_both_decrypt(self):
        a = crypto.encrypt_secret("SAME")
        b = crypto.encrypt_secret("SAME")
        assert a != b  # Fernet embeds a random IV + timestamp
        assert crypto.decrypt_secret(a) == crypto.decrypt_secret(b) == "SAME"

    def test_legacy_plaintext_passes_through(self):
        assert crypto.decrypt_secret("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"
        assert crypto.decrypt_secret("") == ""
        assert crypto.decrypt_secret(None) is None

    def test_is_encrypted(self):
        assert crypto.is_encrypted(crypto.encrypt_secret("x"))
        assert not crypto.is_encrypted("rawbase32value")
        assert not crypto.is_encrypted("")

    def test_corrupt_token_raises_secret_decrypt_error(self):
        with pytest.raises(crypto.SecretDecryptError):
            crypto.decrypt_secret("v1:this-is-not-a-valid-fernet-token")

    def test_wrong_key_raises_secret_decrypt_error(self, tmp_path, monkeypatch):
        """A ciphertext made under one key must not silently decrypt (or
        pass through) under a different key — models a DB restored onto a
        new install without copying /etc/jen/mfa_key."""
        from jen import extensions

        enc = crypto.encrypt_secret("SECRET")
        monkeypatch.setattr(extensions, "MFA_KEY_PATH", str(tmp_path / "other_key"))
        crypto.reset_key_cache()
        with pytest.raises(crypto.SecretDecryptError):
            crypto.decrypt_secret(enc)

    def test_key_unavailable_raises(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "MFA_KEY_PATH", "/proc/nonexistent/mfa_key")
        monkeypatch.setattr(extensions, "JEN_ROOT", "/proc/nonexistent")
        crypto.reset_key_cache()
        with pytest.raises(crypto.MfaKeyUnavailable):
            crypto.encrypt_secret("x")
        assert crypto.key_available() is False

    def test_malformed_existing_key_is_a_hard_stop_not_overwritten(self, tmp_path, monkeypatch):
        """A key file that exists but is garbage must NOT be replaced —
        that would permanently orphan every stored secret when the real
        key may just need restoring from a backup."""
        from jen import extensions

        key_file = tmp_path / "mfa_key"
        key_file.write_text("truncated-not-a-fernet-key")
        monkeypatch.setattr(extensions, "MFA_KEY_PATH", str(key_file))
        monkeypatch.setattr(extensions, "JEN_ROOT", str(tmp_path / "root"))
        crypto.reset_key_cache()
        with pytest.raises(crypto.MfaKeyUnavailable):
            crypto.encrypt_secret("x")
        assert key_file.read_text() == "truncated-not-a-fernet-key"

    def test_pyotp_interop(self):
        secret = pyotp.random_base32()
        stored = crypto.encrypt_secret(secret)
        code = pyotp.TOTP(secret).now()
        crypto.reset_key_cache()  # force a key reload from disk
        assert pyotp.TOTP(crypto.decrypt_secret(stored)).verify(code, valid_window=1)


# ── Migration 17 ────────────────────────────────────────────────────────────
class TestMigration17:
    def test_in_registry_and_applied(self):
        from jen.models.migrations import MIGRATIONS, applied_versions

        versions = [v for v, _, _ in MIGRATIONS]
        assert 17 in versions
        assert 17 in applied_versions()

    def test_encrypts_plaintext_row_and_is_idempotent(self):
        from jen.models.migrations import _m017_encrypt_mfa_secrets

        raw = pyotp.random_base32()
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM mfa_methods WHERE name='_enc_probe'")
                cur.execute(
                    "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) "
                    "VALUES (1, 'totp', %s, '_enc_probe', 1)",
                    (raw,),
                )
            db.commit()
        try:
            with jen_db() as db:
                _m017_encrypt_mfa_secrets(db)
                db.commit()
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT secret FROM mfa_methods WHERE name='_enc_probe'")
                after_first = cur.fetchone()["secret"]
            assert after_first.startswith("v1:")
            assert crypto.decrypt_secret(after_first) == raw

            # Re-run: the already-encrypted row must be left byte-for-byte alone
            with jen_db() as db:
                _m017_encrypt_mfa_secrets(db)
                db.commit()
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT secret FROM mfa_methods WHERE name='_enc_probe'")
                after_second = cur.fetchone()["secret"]
            assert after_second == after_first
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM mfa_methods WHERE name='_enc_probe'")
                db.commit()


# ── verify_totp: decrypt-on-read + fail-closed ──────────────────────────────
class TestVerifyTotp:
    def _insert(self, secret_value, name):
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM mfa_methods WHERE name=%s", (name,))
                cur.execute(
                    "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) "
                    "VALUES (1, 'totp', %s, %s, 1)",
                    (secret_value, name),
                )
            db.commit()

    def _cleanup(self, *names):
        with jen_db() as db:
            with db.cursor() as cur:
                for n in names:
                    cur.execute("DELETE FROM mfa_methods WHERE name=%s", (n,))
            db.commit()

    def test_encrypted_secret_verifies(self):
        from jen.services.mfa import verify_totp

        raw = pyotp.random_base32()
        self._insert(crypto.encrypt_secret(raw), "_v_enc")
        try:
            assert verify_totp(1, pyotp.TOTP(raw).now()) is True
        finally:
            self._cleanup("_v_enc")

    def test_legacy_plaintext_secret_still_verifies(self):
        """A row migration 17 somehow didn't reach must keep working."""
        from jen.services.mfa import verify_totp

        raw = pyotp.random_base32()
        self._insert(raw, "_v_legacy")
        try:
            assert verify_totp(1, pyotp.TOTP(raw).now()) is True
        finally:
            self._cleanup("_v_legacy")

    def test_undecryptable_secret_fails_closed(self):
        """No key match → the row is skipped, verify returns False, and it
        does NOT raise out of verify_totp."""
        from jen.services.mfa import verify_totp

        self._insert("v1:gAAAAABmangled-unusable-token", "_v_bad")
        try:
            assert verify_totp(1, "123456") is False
            assert verify_totp(1, pyotp.TOTP(pyotp.random_base32()).now()) is False
        finally:
            self._cleanup("_v_bad")

    def test_one_bad_row_does_not_block_a_good_sibling(self):
        from jen.services.mfa import verify_totp

        raw = pyotp.random_base32()
        self._insert("v1:brokenbrokenbroken", "_v_bad2")
        self._insert(crypto.encrypt_secret(raw), "_v_good2")
        try:
            assert verify_totp(1, pyotp.TOTP(raw).now()) is True
        finally:
            self._cleanup("_v_bad2", "_v_good2")


# ── Enrolment route stores ciphertext, not the submitted base32 ─────────────
class TestEnrollRoute:
    def test_enroll_stores_encrypted_secret(self, logged_in_client):
        raw = pyotp.random_base32()
        resp = logged_in_client.post(
            "/mfa/enroll",
            data={
                "action": "enroll",
                "secret": raw,
                "code": pyotp.TOTP(raw).now(),
                "device_name": "_enroll_probe",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        try:
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT secret FROM mfa_methods WHERE user_id=1 AND name='_enroll_probe'")
                row = cur.fetchone()
            assert row is not None, "enrolment did not persist a method"
            assert row["secret"].startswith("v1:")
            assert row["secret"] != raw
            assert crypto.decrypt_secret(row["secret"]) == raw
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM mfa_methods WHERE name='_enroll_probe'")
                    cur.execute("DELETE FROM mfa_backup_codes WHERE user_id=1")
                db.commit()
