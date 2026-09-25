"""
jen/services/recovery.py
──────────────────────────
v5.44.0 (Q45) — the recovery bundle format: a plain tar of files,
encrypted with a passphrase-derived key. Pure (bytes/streams in, bytes/
streams out) — `jen/routes/database.py`'s export route gathers the actual
file contents and a fresh `dbexport.export_jen()` dump and calls
`build_stream()`; `jen/tools/restore.py` calls `decrypt_any()` on the
machine being restored, which does not have Jen's own `cryptography`-backed
MFA key available yet (that's IN the bundle) — this module has no
dependency on anything else in `jen/`, so it can be imported standalone by
the restore CLI.

Two formats, both readable (v5.65.0, Q85):

`JENREC1` (v5.44.0, still readable, no longer written by the export route):
`MAGIC(7) + salt(16) + nonce(12) + AES-GCM ciphertext` — the whole tar is one
AEAD message, so both sides hold the bundle in memory (peak about 3x its
size, hence the 200 MB cap that format keeps). The key is `Scrypt(passphrase,
salt)` and MAGIC is the AEAD's associated data, so a bit-flipped header fails
the tag check rather than yielding garbage tar bytes.

`JENREC2` (v5.65.0): a chunked AES-GCM stream, so a bundle is never held
whole in memory on either side (peak about two chunks, 4 MB each).

    header  = MAGIC "JENREC2"(7) + version(1) + salt(16) + chunk_size(4, big
              endian) + nonce_prefix(8)                          -> 36 bytes
    chunk n = AES-GCM(key, nonce = nonce_prefix || n(4),
                      plaintext = up to chunk_size bytes of the tar,
                      AAD = header || n(4) || is_last(1))

Every chunk except the last holds exactly `chunk_size` plaintext bytes (so
`chunk_size + 16` on disk). The last chunk has `is_last = 1` and its plaintext
ends with an 8-byte trailer: the total tar length, big endian. Because the
counter, the header (salt, nonce prefix, chunk size) and `is_last` are all
authenticated, a chunk cannot be dropped, duplicated, reordered, truncated
off the end, appended after, or moved into another bundle without the tag
check failing — and the reader treats ANY failure as `BadPassphrase`, deleting
what it had written. The reader decides "is this the last chunk" from EOF, and
the AAD makes a wrong guess fail authentication.
"""

import contextlib
import io
import logging
import os
import struct
import tarfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

logger = logging.getLogger(__name__)

MAGIC = b"JENREC1"
MAGIC2 = b"JENREC2"
FORMAT_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
TAG_LEN = 16
# JENREC2 header pieces
CHUNK_SIZE = 4 * 1024 * 1024
MIN_CHUNK_SIZE = 4 * 1024  # a reader refuses a header outside these bounds (a hostile
MAX_CHUNK_SIZE = 64 * 1024 * 1024  # bundle must not pick the reader's memory)
NONCE_PREFIX_LEN = 8
COUNTER_LEN = 4
TRAILER_LEN = 8
HEADER2_LEN = len(MAGIC2) + 1 + SALT_LEN + 4 + NONCE_PREFIX_LEN
# Scrypt cost — deliberately expensive (this runs once per export/restore,
# never in a hot path) so a stolen bundle resists offline passphrase
# guessing much better than a fast KDF would.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

# The cap on the plaintext tar of a JENREC2 bundle. JENREC1 keeps its old 200 MB
# ceiling (it is still assembled in memory): encrypt() applies the smaller of the two.
SIZE_CAP_BYTES = 2 * 1024 * 1024 * 1024
V1_SIZE_CAP_BYTES = 200 * 1024 * 1024
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
    cap = min(SIZE_CAP_BYTES, V1_SIZE_CAP_BYTES)
    if len(tar_bytes) > cap:
        raise BundleTooLarge(f"recovery bundle would be {len(tar_bytes)} bytes, over the {cap} cap")
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


def _sniff(head: bytes) -> int | None:
    """1 for a JENREC1 header, 2 for JENREC2, None for anything else."""
    if head.startswith(MAGIC2):
        return 2
    if head.startswith(MAGIC):
        return 1
    return None


def open_bundle(blob: bytes, passphrase: str) -> tarfile.TarFile:
    """Decrypt an in-memory bundle of EITHER format and return an open
    `tarfile.TarFile` positioned to read. Raises `BadPassphrase` — never
    partially decrypts. (For a large bundle on disk use `decrypt_any()` into a
    file instead; this holds the plaintext in memory.)"""
    if _sniff(blob[: len(MAGIC2)]) == 2:
        plain = io.BytesIO()
        decrypt_stream(io.BytesIO(blob), passphrase, plain)
        plain.seek(0)
        return tarfile.open(fileobj=plain, mode="r")
    tar_bytes = decrypt(blob, passphrase)
    return tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r")


# ── JENREC2: the chunked stream (v5.65.0, Q85) ───────────────────────────────


def _chunk_aad(header: bytes, counter: int, is_last: bool) -> bytes:
    return header + struct.pack(">IB", counter, 1 if is_last else 0)


def _chunk_nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">I", counter)


class _ChunkWriter:
    """A write-only file-like the tar writer streams into: buffers, and
    encrypts a chunk each time more than `chunk_size` bytes are waiting — so
    the buffer never holds more than about one chunk, and there is always a
    final (possibly short) tail left for the `is_last` chunk."""

    def __init__(self, out_fp, key: bytes, header: bytes, chunk_size: int, cap: int):
        self._out = out_fp
        self._aead = AESGCM(key)
        self._header = header
        self._prefix = header[-NONCE_PREFIX_LEN:]
        self._chunk = chunk_size
        self._cap = cap
        self._buf = bytearray()
        self._counter = 0
        self.plain_len = 0
        self.closed = False

    def writable(self):
        return True

    def flush(self):
        pass

    def write(self, data) -> int:
        n = len(data)
        self.plain_len += n
        if self.plain_len > self._cap:
            raise BundleTooLarge(f"recovery bundle is over the {self._cap} byte cap")
        self._buf += data
        while len(self._buf) > self._chunk:
            self._emit(bytes(self._buf[: self._chunk]), False)
            del self._buf[: self._chunk]
        return n

    def _emit(self, plaintext: bytes, is_last: bool) -> None:
        if self._counter >= 2**32:
            raise BundleTooLarge("recovery bundle has too many chunks")
        ct = self._aead.encrypt(
            _chunk_nonce(self._prefix, self._counter), plaintext, _chunk_aad(self._header, self._counter, is_last)
        )
        self._out.write(ct)
        self._counter += 1

    def finish(self) -> None:
        """Emit the tail plus the length trailer as the `is_last` chunk."""
        self._emit(bytes(self._buf) + struct.pack(">Q", self.plain_len), True)
        self._buf = bytearray()


def _tar_size_estimate(sizes) -> int:
    """Upper bound of a tar of members of these sizes: a header block and the
    content padded to 512 per member, plus the two zero end blocks (a PAX
    extended header for a long name can add more; the writer enforces the cap
    exactly while it streams, this only refuses the obvious case up front)."""
    return sum(512 + ((size + 511) // 512) * 512 for size in sizes) + 1024


def _member_size(content) -> int:
    if isinstance(content, (bytes, bytearray)):
        return len(content)
    return os.stat(content).st_size


def build_stream(members, passphrase: str, out_fp, chunk_size: int = CHUNK_SIZE) -> int:
    """Write a JENREC2 bundle of `members` to `out_fp` without ever holding it
    in memory. `members` is a dict, or an iterable, of `(archive path, content)`
    where content is `bytes` (used as is) or a filesystem path (`str`/`Path`,
    streamed from disk in small reads — a file that has vanished or cannot be
    read is skipped with a warning, the way the old in-memory walk did).

    Returns the number of bytes written to `out_fp`. Raises `BundleTooLarge`
    when the tar would exceed `SIZE_CAP_BYTES` — BEFORE anything is written
    when `members` is a sized collection (dict/list/tuple), otherwise as soon
    as the running total passes the cap. On any failure `out_fp` may hold a
    partial bundle; the caller owns deleting it (the export route does)."""
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError("chunk_size out of range")
    items = members.items() if isinstance(members, dict) else members
    if hasattr(items, "__len__"):
        items = list(items)
        sizes = []
        for _n, c in items:
            with contextlib.suppress(
                OSError
            ):  # a vanished file is skipped when reached; the streaming cap still applies
                sizes.append(_member_size(c))
        estimate = _tar_size_estimate(sizes)
        if estimate > SIZE_CAP_BYTES:
            raise BundleTooLarge(f"recovery bundle would be about {estimate} bytes, over the {SIZE_CAP_BYTES} cap")

    salt = os.urandom(SALT_LEN)
    prefix = os.urandom(NONCE_PREFIX_LEN)
    header = MAGIC2 + bytes([FORMAT_VERSION]) + salt + struct.pack(">I", chunk_size) + prefix
    key = _derive_key(passphrase, salt)
    start = out_fp.tell() if hasattr(out_fp, "tell") else 0
    out_fp.write(header)
    writer = _ChunkWriter(out_fp, key, header, chunk_size, SIZE_CAP_BYTES)
    with tarfile.open(fileobj=writer, mode="w|") as tf:
        for name, content in items:
            info = tarfile.TarInfo(name=name)
            if isinstance(content, (bytes, bytearray)):
                info.size = len(content)
                tf.addfile(info, io.BytesIO(bytes(content)))
                continue
            try:
                fh = open(content, "rb")  # noqa: SIM115 — opened here so an unreadable file is skipped BEFORE its tar header is written
            except OSError as e:
                logger.warning(f"recovery bundle: could not read {content}: {e}")
                continue
            with fh:
                info.size = os.fstat(fh.fileno()).st_size
                tf.addfile(info, fh)
    writer.finish()
    end = out_fp.tell() if hasattr(out_fp, "tell") else start
    return end - start


def _read_exact(fp, n: int) -> bytes:
    """Up to `n` bytes, looping over short reads; fewer only at EOF."""
    parts, got = [], 0
    while got < n:
        b = fp.read(n - got)
        if not b:
            break
        parts.append(b)
        got += len(b)
    return b"".join(parts)


def decrypt_stream(in_fp, passphrase: str, out_fp) -> int:
    """Decrypt a JENREC2 stream from `in_fp` into `out_fp` chunk by chunk,
    verifying each tag before writing its plaintext. Returns the plaintext
    length. On the first failure of any kind — a bad tag (wrong passphrase,
    edited, reordered, duplicated, dropped or foreign chunk), a stream that
    ends without an `is_last` chunk or carries data after one, or a trailer
    that disagrees with what was decrypted — it truncates `out_fp` back to
    empty (when it can seek) and raises `BadPassphrase`; a wrong passphrase
    and a damaged bundle are deliberately the same error."""
    try:
        return _decrypt_stream(in_fp, passphrase, out_fp)
    except BadPassphrase:
        _discard(out_fp)
        raise
    except Exception as e:  # a short read, a struct error, a bad size — all just "refused"
        _discard(out_fp)
        raise BadPassphrase("wrong passphrase, or the bundle is corrupted or was tampered with") from e


def _discard(out_fp) -> None:
    try:
        out_fp.seek(0)
        out_fp.truncate()
    except (OSError, ValueError, AttributeError):
        pass


def _decrypt_stream(in_fp, passphrase: str, out_fp) -> int:
    header = _read_exact(in_fp, HEADER2_LEN)
    if len(header) < HEADER2_LEN or not header.startswith(MAGIC2):
        raise BadPassphrase("not a Jen recovery bundle (missing or wrong header)")
    if header[len(MAGIC2)] != FORMAT_VERSION:
        raise BadPassphrase("this recovery bundle is a newer format than this Jen can read")
    o = len(MAGIC2) + 1
    salt = header[o : o + SALT_LEN]
    (chunk_size,) = struct.unpack(">I", header[o + SALT_LEN : o + SALT_LEN + 4])
    prefix = header[-NONCE_PREFIX_LEN:]
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise BadPassphrase("wrong passphrase, or the bundle is corrupted or was tampered with")

    aead = AESGCM(_derive_key(passphrase, salt))
    full = chunk_size + TAG_LEN  # every non-last record
    max_last = full + TRAILER_LEN  # the last one carries the trailer too
    pending = b""
    counter = 0
    total = 0
    while True:
        # Read far enough ahead to tell "a full non-last record" from "the last one":
        # if more than a last record's worth is available, the first `full` bytes are non-last.
        pending += _read_exact(in_fp, max_last + 1 - len(pending))
        if not pending:
            raise BadPassphrase("wrong passphrase, or the bundle is corrupted or was tampered with")
        is_last = len(pending) <= max_last
        rec = pending if is_last else pending[:full]
        pending = b"" if is_last else pending[full:]
        if counter >= 2**32:
            raise BadPassphrase("wrong passphrase, or the bundle is corrupted or was tampered with")
        plain = aead.decrypt(_chunk_nonce(prefix, counter), rec, _chunk_aad(header, counter, is_last))
        counter += 1
        if is_last:
            if len(plain) < TRAILER_LEN:
                raise BadPassphrase("wrong passphrase, or the bundle is corrupted or was tampered with")
            body, trailer = plain[:-TRAILER_LEN], plain[-TRAILER_LEN:]
            out_fp.write(body)
            total += len(body)
            if struct.unpack(">Q", trailer)[0] != total:
                raise BadPassphrase("the bundle's length trailer does not match its contents")
            return total
        out_fp.write(plain)
        total += len(plain)


def decrypt_any(in_fp, passphrase: str, out_fp) -> int:
    """Decrypt a bundle of either format from a SEEKABLE `in_fp` into `out_fp`
    (the plaintext tar). JENREC2 streams; JENREC1 is read whole, as before.
    Returns the plaintext length; `BadPassphrase` on any failure, with a JENREC2
    partial output discarded."""
    head = _read_exact(in_fp, len(MAGIC2))
    in_fp.seek(-len(head), os.SEEK_CUR)
    if _sniff(head) == 2:
        return decrypt_stream(in_fp, passphrase, out_fp)
    tar_bytes = decrypt(in_fp.read(), passphrase)  # v1 (and its errors for anything unrecognised)
    out_fp.write(tar_bytes)
    return len(tar_bytes)
