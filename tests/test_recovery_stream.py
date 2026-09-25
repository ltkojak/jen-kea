"""
tests/test_recovery_stream.py
──────────────────────────────
v5.65.0 (Q85) — JENREC2, the chunked AES-GCM recovery format that never holds
a bundle in memory. Pure (no DB): `python -m pytest --noconftest tests/test_recovery_stream.py`.

The refusals matter more than the round trip: a chunk that is dropped,
duplicated, reordered, truncated off the end, appended after, or moved in from
another bundle must fail authentication — and a wrong passphrase, a damaged
bundle and a hostile header must all read as the same `BadPassphrase`.
"""

import io
import json
import os
import struct
import subprocess
import sys
import tarfile

import pytest

from jen.services import recovery
from jen.services.recovery import (
    HEADER2_LEN,
    MAGIC,
    MAGIC2,
    BadPassphrase,
    BundleTooLarge,
    build,
    build_stream,
    decrypt_any,
    decrypt_stream,
    open_bundle,
)

PASS = "correct horse battery staple"
CHUNK = 4096  # the smallest legal chunk: many chunks from a small test bundle
FULL = CHUNK + 16  # a non-last record on disk


def stream(members, chunk_size=CHUNK, passphrase=PASS) -> bytes:
    out = io.BytesIO()
    build_stream(members, passphrase, out, chunk_size=chunk_size)
    return out.getvalue()


def sample() -> bytes:
    """A bundle of several chunks (about 40 KB of tar at 4 KB chunks)."""
    return stream({"a.txt": b"hello", "b.bin": bytes(range(256)) * 100, "c.txt": b"tail" * 2000})


def records(blob: bytes):
    """(header, [record, ...]) — every record but the last is exactly FULL bytes."""
    header, body = blob[:HEADER2_LEN], blob[HEADER2_LEN:]
    recs = []
    while len(body) > FULL + recovery.TRAILER_LEN:
        recs.append(body[:FULL])
        body = body[FULL:]
    recs.append(body)
    return header, recs


def join(header, recs) -> bytes:
    return header + b"".join(recs)


def dec(blob: bytes, passphrase=PASS) -> bytes:
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), passphrase, out)
    return out.getvalue()


def raw_stream(plaintext: bytes, chunk_size=CHUNK, trailer_skew=0) -> bytes:
    """Encrypt raw bytes through the chunk writer directly, so chunk-boundary
    lengths can be hit exactly (a tar's length is not free to choose)."""
    salt, prefix = os.urandom(recovery.SALT_LEN), os.urandom(recovery.NONCE_PREFIX_LEN)
    header = MAGIC2 + bytes([recovery.FORMAT_VERSION]) + salt + struct.pack(">I", chunk_size) + prefix
    out = io.BytesIO()
    out.write(header)
    w = recovery._ChunkWriter(out, recovery._derive_key(PASS, salt), header, chunk_size, 1 << 40)
    w.write(plaintext)
    w.plain_len += trailer_skew
    w.finish()
    return out.getvalue()


class TestRoundTrip:
    def test_several_chunks_come_back_intact(self):
        members = {"a.txt": b"hello", "b.bin": bytes(range(256)) * 100}
        blob = stream(members)
        assert len(blob) > HEADER2_LEN + 4 * FULL  # really did span chunks
        tf = open_bundle(blob, PASS)
        assert set(tf.getnames()) == set(members)
        for name, content in members.items():
            assert tf.extractfile(name).read() == content

    def test_starts_with_the_v2_magic_and_a_36_byte_header(self):
        blob = stream({"x": b"y"})
        assert blob.startswith(MAGIC2) and not blob.startswith(MAGIC)
        assert HEADER2_LEN == 36
        assert blob[7] == 1  # the format version byte
        assert struct.unpack(">I", blob[24:28])[0] == CHUNK

    @pytest.mark.parametrize(
        "n",
        [
            0,
            1,
            CHUNK - 9,
            CHUNK - 8,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            2 * CHUNK - 8,
            2 * CHUNK,
            2 * CHUNK + 1,
            5 * CHUNK + 7,
        ],
    )
    def test_every_chunk_boundary_length(self, n):
        """0 bytes, one under/at/over a chunk, and lengths where the trailer alone would spill."""
        data = os.urandom(n)
        assert dec(raw_stream(data)) == data

    def test_empty_members_still_a_valid_bundle(self):
        assert open_bundle(stream({}), PASS).getnames() == []

    def test_two_builds_of_the_same_content_differ(self):
        assert stream({"x": b"y"}) != stream({"x": b"y"})

    def test_unicode_passphrase(self):
        blob = stream({"x": b"y"}, passphrase="pässwörd with ünïcode 日本語")
        assert open_bundle(blob, "pässwörd with ünïcode 日本語").extractfile("x").read() == b"y"

    def test_path_members_are_read_from_disk_and_mixed_with_bytes(self, tmp_path):
        f = tmp_path / "big.dat"
        f.write_bytes(os.urandom(50_000))
        tf = open_bundle(stream({"m.json": b"{}", "content/big.dat": str(f)}), PASS)
        assert tf.extractfile("content/big.dat").read() == f.read_bytes()
        assert tf.extractfile("m.json").read() == b"{}"

    def test_a_missing_path_is_skipped_not_fatal(self, tmp_path):
        tf = open_bundle(stream({"gone": str(tmp_path / "nope"), "here": b"1"}), PASS)
        assert tf.getnames() == ["here"]

    def test_accepts_an_iterable_of_pairs(self):
        tf = open_bundle(stream(iter([("a", b"1"), ("b", b"2")])), PASS)
        assert tf.getnames() == ["a", "b"]

    def test_decrypt_stream_returns_the_plaintext_length(self):
        blob = sample()
        out = io.BytesIO()
        assert decrypt_stream(io.BytesIO(blob), PASS, out) == len(out.getvalue())


class TestRefusals:
    def test_wrong_passphrase(self):
        with pytest.raises(BadPassphrase):
            dec(sample(), "definitely the wrong one")

    def test_the_error_is_the_same_for_a_wrong_key_and_a_damaged_bundle(self):
        blob = bytearray(sample())
        blob[HEADER2_LEN + 5] ^= 1
        with pytest.raises(BadPassphrase) as damaged:
            dec(bytes(blob))
        with pytest.raises(BadPassphrase) as wrong:
            dec(sample(), "nope")
        assert str(damaged.value) == str(wrong.value)

    @pytest.mark.parametrize("offset", [0, 3, 7, 8, 12, 23, 24, 27, 28, 35], ids=lambda o: f"header-byte-{o}")
    def test_any_flipped_header_byte(self, offset):
        blob = bytearray(sample())
        blob[offset] ^= 0x01
        with pytest.raises(BadPassphrase):
            dec(bytes(blob))

    def test_flipped_byte_in_the_first_middle_and_last_chunk(self):
        header, recs = records(sample())
        for i in (0, len(recs) // 2, len(recs) - 1):
            bad = list(recs)
            r = bytearray(bad[i])
            r[len(r) // 2] ^= 0x01
            bad[i] = bytes(r)
            with pytest.raises(BadPassphrase):
                dec(join(header, bad))

    def test_the_last_chunk_dropped_is_refused(self):
        """Truncation at a chunk boundary: the new final chunk was not written as the last one."""
        header, recs = records(sample())
        assert len(recs) > 3
        with pytest.raises(BadPassphrase):
            dec(join(header, recs[:-1]))

    def test_truncated_mid_chunk_is_refused(self):
        blob = sample()
        for cut in (1, 5, 17, FULL // 2, FULL + 3):
            with pytest.raises(BadPassphrase):
                dec(blob[:-cut])

    def test_header_only_and_empty_and_tiny_input_are_refused(self):
        blob = sample()
        for cut in (0, 1, 10, HEADER2_LEN - 1, HEADER2_LEN):
            with pytest.raises(BadPassphrase):
                dec(blob[:cut])

    def test_a_middle_chunk_dropped_is_refused(self):
        header, recs = records(sample())
        with pytest.raises(BadPassphrase):
            dec(join(header, recs[:1] + recs[2:]))

    def test_a_chunk_duplicated_is_refused(self):
        header, recs = records(sample())
        with pytest.raises(BadPassphrase):
            dec(join(header, recs[:2] + [recs[1]] + recs[2:]))

    def test_the_last_chunk_duplicated_is_refused(self):
        header, recs = records(sample())
        with pytest.raises(BadPassphrase):
            dec(join(header, recs + [recs[-1]]))

    def test_two_chunks_reordered_is_refused(self):
        header, recs = records(sample())
        swapped = list(recs)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        with pytest.raises(BadPassphrase):
            dec(join(header, swapped))

    def test_data_appended_after_the_last_chunk_is_refused(self):
        blob = sample()
        for extra in (b"\x00", b"trailing junk", os.urandom(FULL + 40)):
            with pytest.raises(BadPassphrase):
                dec(blob + extra)

    def test_a_chunk_from_another_bundle_is_refused(self):
        """Same passphrase, same chunk size, same plaintext — a chunk from bundle B
        spliced into bundle A still fails: the salt/nonce prefix and header are in the AAD."""
        members = {"b.bin": bytes(range(256)) * 100}
        a_hdr, a_recs = records(stream(members))
        _b_hdr, b_recs = records(stream(members))
        for i in (0, 1, len(a_recs) - 1):
            spliced = list(a_recs)
            spliced[i] = b_recs[i]
            with pytest.raises(BadPassphrase):
                dec(join(a_hdr, spliced))

    def test_the_header_of_one_bundle_on_the_body_of_another_is_refused(self):
        a_hdr, _a = records(sample())
        _b_hdr, b_recs = records(sample())
        with pytest.raises(BadPassphrase):
            dec(join(a_hdr, b_recs))

    def test_a_trailer_that_disagrees_with_the_contents_is_refused(self):
        """A correctly authenticated last chunk whose recorded length is wrong."""
        for skew in (1, -1, 4096):
            with pytest.raises(BadPassphrase, match="trailer"):
                dec(raw_stream(os.urandom(3 * CHUNK + 5), trailer_skew=skew))

    @pytest.mark.parametrize("size", [0, 1, CHUNK - 1, recovery.MAX_CHUNK_SIZE + 1, 2**32 - 1])
    def test_a_hostile_chunk_size_is_refused_before_anything_is_allocated(self, size):
        blob = bytearray(sample())
        blob[24:28] = struct.pack(">I", size)
        with pytest.raises(BadPassphrase):
            dec(bytes(blob))

    def test_an_unknown_format_version_is_refused(self):
        blob = bytearray(sample())
        blob[7] = 2
        with pytest.raises(BadPassphrase, match="newer"):
            dec(bytes(blob))

    def test_partial_output_is_discarded_on_failure(self):
        """Earlier chunks were verified and written; a bad LATER chunk empties the output again."""
        header, recs = records(sample())
        r = bytearray(recs[-1])
        r[-1] ^= 0x01
        out = io.BytesIO()
        with pytest.raises(BadPassphrase):
            decrypt_stream(io.BytesIO(join(header, recs[:-1] + [bytes(r)])), PASS, out)
        assert out.getvalue() == b""

    def test_partial_output_file_is_truncated_too(self, tmp_path):
        header, recs = records(sample())
        p = tmp_path / "plain.tar"
        with open(p, "wb") as out, pytest.raises(BadPassphrase):
            decrypt_stream(io.BytesIO(join(header, recs[:-1])), PASS, out)
        assert p.stat().st_size == 0


class TestFormatCompatibility:
    def test_build_still_writes_jenrec1_and_open_bundle_reads_both(self):
        v1 = build({"x": b"y"}, PASS)
        v2 = stream({"x": b"y"})
        assert v1.startswith(MAGIC) and not v1.startswith(MAGIC2)
        assert open_bundle(v1, PASS).extractfile("x").read() == b"y"
        assert open_bundle(v2, PASS).extractfile("x").read() == b"y"

    def test_decrypt_any_reads_a_jenrec1_file(self, tmp_path):
        p = tmp_path / "old.tar.enc"
        p.write_bytes(build({"a": b"1", "b": b"2"}, PASS))
        out = io.BytesIO()
        with open(p, "rb") as fh:
            n = decrypt_any(fh, PASS, out)
        assert n == len(out.getvalue())
        out.seek(0)
        with tarfile.open(fileobj=out) as tf:
            assert tf.getnames() == ["a", "b"]

    def test_decrypt_any_reads_a_jenrec2_file(self, tmp_path):
        p = tmp_path / "new.tar.enc"
        p.write_bytes(stream({"a": b"1"}))
        out = io.BytesIO()
        with open(p, "rb") as fh:
            decrypt_any(fh, PASS, out)
        out.seek(0)
        with tarfile.open(fileobj=out) as tf:
            assert tf.getnames() == ["a"]

    @pytest.mark.parametrize("junk", [b"", b"JENREC", b"NOTJENREC" + b"\x00" * 60, b"JENREC3" + b"\x00" * 60])
    def test_decrypt_any_refuses_anything_unrecognised(self, junk):
        with pytest.raises(BadPassphrase):
            decrypt_any(io.BytesIO(junk), PASS, io.BytesIO())

    def test_jenrec1_keeps_its_200_mb_ceiling_even_though_the_new_cap_is_2_gb(self):
        assert recovery.SIZE_CAP_BYTES == 2 * 1024**3
        assert recovery.V1_SIZE_CAP_BYTES == 200 * 1024**2
        with pytest.raises(BundleTooLarge):
            recovery.encrypt(b"0" * (200 * 1024 * 1024 + 1), PASS)


class TestSizeCap:
    def test_a_sized_collection_over_the_cap_is_refused_before_a_byte_is_written(self, monkeypatch):
        monkeypatch.setattr(recovery, "SIZE_CAP_BYTES", 5000)
        out = io.BytesIO()
        with pytest.raises(BundleTooLarge):
            build_stream({"big": b"0" * 6000}, PASS, out)
        assert out.getvalue() == b""

    def test_file_sizes_count_without_reading_the_files(self, tmp_path, monkeypatch):
        f = tmp_path / "big"
        f.write_bytes(b"0" * 6000)
        monkeypatch.setattr(recovery, "SIZE_CAP_BYTES", 5000)
        out = io.BytesIO()
        with pytest.raises(BundleTooLarge):
            build_stream({"big": str(f)}, PASS, out)
        assert out.getvalue() == b""

    def test_a_generator_is_stopped_by_the_running_total(self, monkeypatch):
        monkeypatch.setattr(recovery, "SIZE_CAP_BYTES", 5000)
        with pytest.raises(BundleTooLarge):
            build_stream(((f"m{i}", b"0" * 1000) for i in range(20)), PASS, io.BytesIO())

    def test_under_the_cap_is_allowed(self, monkeypatch):
        monkeypatch.setattr(recovery, "SIZE_CAP_BYTES", 20_000)
        assert open_bundle(stream({"ok": b"0" * 3000}), PASS).extractfile("ok").read() == b"0" * 3000

    def test_a_chunk_size_outside_the_allowed_range_is_a_programming_error(self):
        with pytest.raises(ValueError):
            build_stream({"x": b"y"}, PASS, io.BytesIO(), chunk_size=100)


_RSS_SCRIPT = """
import json, os, resource, sys
sys.path.insert(0, sys.argv[1])
from jen.services import recovery as r

PASS, big, enc = "correct horse battery staple", sys.argv[2], sys.argv[3]
# scrypt's own 32 MiB working set is not the bundle: pay it once before taking the baseline
r._derive_key(PASS, os.urandom(16))
rss = lambda: resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # MiB on Linux
base = rss()
with open(enc, "wb") as out:
    written = r.build_stream({"manifest.json": b"{}", "content/big.bin": big}, PASS, out)
built = rss()
with open(enc, "rb") as fin, open(os.devnull, "wb") as sink:
    plain = r.decrypt_stream(fin, PASS, sink)
print(json.dumps({"base": base, "built": built, "decrypted": rss(), "written": written, "plain": plain}))
"""


@pytest.mark.skipif(sys.platform != "linux", reason="peak RSS via resource.ru_maxrss is only meaningful on Linux")
def test_a_300_mb_bundle_is_built_and_read_in_under_64_mb_of_extra_memory(tmp_path):
    """The point of the format: memory is a couple of chunks, not a multiple of the bundle."""
    big = tmp_path / "big.bin"
    with open(big, "wb") as f:
        f.truncate(300 * 1024 * 1024)  # a sparse 300 MB file of zeros
    enc = tmp_path / "out.tar.enc"
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run(
        [sys.executable, "-c", _RSS_SCRIPT, root, str(big), str(enc)], capture_output=True, text=True, timeout=300
    )
    assert r.returncode == 0, r.stderr
    m = json.loads(r.stdout.strip().splitlines()[-1])
    assert m["plain"] > 300 * 1024 * 1024 and m["written"] > 300 * 1024 * 1024
    assert m["built"] - m["base"] < 64, m
    assert m["decrypted"] - m["base"] < 64, m
