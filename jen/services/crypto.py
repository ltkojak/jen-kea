"""
jen/services/crypto.py
──────────────────────
Symmetric encryption at rest for reversible secrets that Jen must be
able to read back in cleartext: TOTP shared secrets (`mfa_methods.secret`,
v5.4.0) and alert-channel notification tokens (`alert_channels.config`,
v5.7.0). One Fernet key (`/etc/jen/mfa_key`) protects both.

Why encryption and not hashing
──────────────────────────────
Backup codes, trusted-device tokens, and API keys are all one-way
sha256 hashes: Jen only ever needs to check "does this match", never
to recover the original. A TOTP secret is different — every 30 seconds
Jen has to recompute the current code *from the original secret*, so it
must be stored reversibly. That means the protection is encryption with
a key kept outside the database, not a hash.

Key management
──────────────
The Fernet key lives at `extensions.MFA_KEY_PATH` (`/etc/jen/mfa_key`),
with a fallback to `$JEN_ROOT/.mfa_key` if `/etc/jen` isn't writable —
the same two-candidate pattern as `_load_secret_key()` in
`jen/__init__.py`, and like that key it is created on first use rather
than by the installer. On an upgrade, migration 17 is the first thing
to touch it: it runs as the Jen service user, which `install.sh` has
just `chown`ed `/etc/jen` to, so the write succeeds.

Unlike the Flask session key, there is **no ephemeral in-memory
fallback**. An ephemeral session key just logs everyone out on restart;
an ephemeral MFA key would make every already-stored secret
undecryptable forever. If no key can be loaded *or* persisted,
`get_fernet()` raises `MfaKeyUnavailable` and callers fail closed
(see `jen/services/mfa.py::verify_totp` — the user falls back to backup
codes and an admin can reset their MFA).

Storage format
──────────────
`encrypt_secret()` returns `"v1:" + <fernet token>`. The `v1:` prefix
is a version tag so a future key rotation or algorithm change is a
recognizable, migratable format rather than an ambiguous blob.
`decrypt_secret()` accepts three inputs:
  1. `"v1:…"`            → Fernet-decrypt.
  2. a bare legacy value → returned unchanged (pre-v5.4.0 plaintext
                           rows that migration 17 hasn't reached, or a
                           test inserting a raw secret).
  3. anything else that  → `SecretDecryptError`.
     won't decrypt
"""

import logging
import os
import threading

from jen import extensions

logger = logging.getLogger(__name__)

PREFIX = "v1:"


class MfaKeyUnavailable(RuntimeError):
    """The encryption key could not be loaded or created — no key file
    present and no writable location to persist a new one."""


class SecretDecryptError(RuntimeError):
    """A `v1:`-tagged value could not be decrypted with the current key
    (wrong key, or corrupt/truncated ciphertext)."""


_fernet = None
_fernet_lock = threading.Lock()


def _key_candidates() -> list[str]:
    """Read `extensions.MFA_KEY_PATH` dynamically (never cached) so the
    test suite can repoint it, exactly like `AppConfig` reads
    `extensions.CONFIG_FILE`."""
    return [extensions.MFA_KEY_PATH, os.path.join(extensions.CONTENT_KEYS_DIR, ".mfa_key")]


def _looks_like_fernet_key(value: str) -> bool:
    """A Fernet key is 32 url-safe-base64 bytes → 44 chars ending in '='."""
    return len(value) == 44


def _load_or_create_key() -> bytes:
    """Return the Fernet key bytes: load the first readable candidate,
    otherwise generate one and persist it to the first writable
    candidate (0600). Raise MfaKeyUnavailable if neither is possible.

    Mirrors `_load_secret_key()` in jen/__init__.py, with two
    deliberate differences:

    - No ephemeral fallback. A session key we can't persist just logs
      everyone out on restart; an MFA key we can't persist orphans every
      stored secret. That path raises instead.
    - A key file that EXISTS but is malformed is a hard stop
      (MfaKeyUnavailable), not a cue to generate a replacement over it.
      Overwriting it would permanently orphan every `v1:` secret, when
      the real key may just be truncated/misplaced and restorable from a
      backup. Only a genuinely ABSENT file triggers generation.
    """
    from cryptography.fernet import Fernet

    last_error = None
    for key_file in _key_candidates():
        if os.path.exists(key_file):
            try:
                with open(key_file) as f:
                    existing = f.read().strip()
                if _looks_like_fernet_key(existing):
                    Fernet(existing.encode())  # validate it initializes
                    return existing.encode()
            except Exception as e:
                raise MfaKeyUnavailable(
                    f"MFA encryption key at {key_file} exists but could not be "
                    f"read/parsed ({e}). Refusing to overwrite it — restore the "
                    f"correct key from a backup, or delete this file to have a "
                    f"new one generated (which orphans existing enrolments)."
                ) from e
            raise MfaKeyUnavailable(
                f"MFA encryption key at {key_file} exists but is malformed "
                f"(length {len(existing)}, expected 44). Refusing to overwrite "
                f"it — restore the correct key from a backup, or delete this "
                f"file to have a new one generated (which orphans existing "
                f"enrolments)."
            )
        try:
            new_key = Fernet.generate_key()
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, "wb") as f:
                f.write(new_key)
            os.chmod(key_file, 0o600)
            logger.warning("Generated a new MFA encryption key at %s", key_file)
            return new_key
        except Exception as e:
            last_error = e
            logger.warning("Could not create MFA key at %s: %s", key_file, e)
            continue

    raise MfaKeyUnavailable(
        "No MFA encryption key could be created at "
        + " or ".join(_key_candidates())
        + f" (last error: {last_error}). TOTP verification will fail closed "
        "until this is fixed — check that the Jen service user can write to /etc/jen."
    )


def get_fernet():
    """Return the process-wide cached Fernet instance, creating/loading
    the key on first call. Raises MfaKeyUnavailable if the key is
    unavailable."""
    global _fernet
    if _fernet is None:
        with _fernet_lock:
            if _fernet is None:
                from cryptography.fernet import Fernet

                _fernet = Fernet(_load_or_create_key())
    return _fernet


def reset_key_cache() -> None:
    """Drop the cached Fernet instance so the next call reloads the key.
    For the test suite (which repoints extensions.MFA_KEY_PATH between
    cases) and for any future key-rotation flow."""
    global _fernet
    with _fernet_lock:
        _fernet = None


def key_available() -> bool:
    """True if the encryption key can be loaded/created right now —
    for health checks and the Settings page. Never raises."""
    try:
        get_fernet()
        return True
    except Exception:
        return False


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a cleartext secret for storage. Returns a `v1:`-prefixed
    token. Raises MfaKeyUnavailable if the key can't be loaded."""
    if plaintext is None:
        raise ValueError("encrypt_secret() got None")
    token = get_fernet().encrypt(plaintext.encode())
    return PREFIX + token.decode()


def is_encrypted(stored: str) -> bool:
    """True if `stored` is in the v5.4.0 encrypted format (vs. a legacy
    plaintext value)."""
    return bool(stored) and stored.startswith(PREFIX)


def decrypt_secret(stored: str, what: str = "MFA secret") -> str:
    """Return the cleartext secret for a stored value.

    - `v1:…`             → Fernet-decrypt (SecretDecryptError on failure)
    - a bare legacy value → returned unchanged
    - empty / None        → returned unchanged

    `what` only names the value in the SecretDecryptError message, so the
    same primitive can serve callers other than MFA (alert-channel tokens).
    """
    if not stored:
        return stored
    if not stored.startswith(PREFIX):
        return stored  # legacy plaintext — the backfill migration hasn't reached it
    from cryptography.fernet import InvalidToken

    token = stored[len(PREFIX) :]
    try:
        return get_fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise SecretDecryptError(
            f"Stored {what} could not be decrypted with the current key. "
            "If this database was restored or migrated from another install, "
            "its /etc/jen/mfa_key must be copied across too; otherwise the "
            "affected secret must be re-entered."
        ) from e
