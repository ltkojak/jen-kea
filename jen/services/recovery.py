"""
jen/services/recovery.py
──────────────────────────
v5.44.0 (Q45) — the recovery bundle format: a plain tar of files,
encrypted whole with a passphrase-derived key. Pure (bytes in, bytes
out) — `jen/routes/database.py`'s export route gathers the actual file
contents and a fresh `dbexport.export_jen()` dump and calls `build()`;
`jen/tools/restore.py` calls `open_bundle()` on the machine being
restored, which does not have Jen's own `cryptography`-backed MFA key
available yet (that's IN the bundle) — this module has no dependency
on anything else in `jen/`, so it can be imported standalone by the
restore CLI.

Format (`JENREC1`): `MAGIC(7) + salt(16) + nonce(12) + AES-GCM
ciphertext`, where the key is `Scrypt(passphrase, salt)` and MAGIC is
also the AEAD's associated data — so a bit-flipped header fails
decryption immediately (AES-GCM's tag check) rather than silently
producing garbage tar bytes.
"""

import io
import os
import tarfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"JENREC1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
# Scrypt cost — deliberately expensive (this runs once per export/restore,
# never in a hot path) so a stolen bundle resists offline passphrase
# guessing much better than a fast KDF would.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

SIZE_CAP_BYTES = 200 * 1024 * 1024
MIN_PASSPHRASE_LEN = 12


class BadPassphrase(RuntimeError):
    """Wrong passphrase, or the bundle is corrupted/tampered — AES-GCM's
    tag check can't tell these apart, and there's no reason to let a
    caller distinguish them either (either way, nothing decrypts)."""


class BundleTooLarge(RuntimeError):
    """The assembled tar exceeds SIZE_CAP_BYTES."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    # A fresh Scrypt instance every call — cryptography's KDF objects are
    # single-use and raise AlreadyFinalized on a second .derive() call.
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def build_tar(members: dict[str, bytes]) -> bytes:
    """`members`: `{archive_path: content}`. Returns an uncompressed tar
    (individual members like `jen_db.json.gz` carry their own
    compression; the AES-GCM ciphertext that wraps the whole tar is
    already incompressible, so a second, outer compression pass would
    only cost CPU)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for path, content in members.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def encrypt(tar_bytes: bytes, passphrase: str) -> bytes:
    if len(tar_bytes) > SIZE_CAP_BYTES:
        raise BundleTooLarge(f"recovery bundle would be {len(tar_bytes)} bytes, over the {SIZE_CAP_BYTES} cap")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, tar_bytes, MAGIC)
    return MAGIC + salt + nonce + ciphertext


def decrypt(blob: bytes, passphrase: str) -> bytes:
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
    if len(blob) < header_len or not blob.startswith(MAGIC):
        raise BadPassphrase("not a Jen recovery bundle (missing or wrong header)")
    salt = blob[len(MAGIC) : len(MAGIC) + SALT_LEN]
    nonce = blob[len(MAGIC) + SALT_LEN : header_len]
    ciphertext = blob[header_len:]
    key = _derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except Exception as e:
        raise BadPassphrase("wrong passphrase, or the bundle is corrupted or was tampered with") from e


def build(members: dict[str, bytes], passphrase: str) -> bytes:
    """`members` → encrypted bundle bytes. Raises `BundleTooLarge` before
    ever deriving a key or encrypting anything."""
    return encrypt(build_tar(members), passphrase)


def open_bundle(blob: bytes, passphrase: str) -> tarfile.TarFile:
    """Decrypt and return an open `tarfile.TarFile` positioned to read.
    Raises `BadPassphrase` — never partially decrypts."""
    tar_bytes = decrypt(blob, passphrase)
    return tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r")
