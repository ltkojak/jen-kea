#!/usr/bin/env python3
"""
tools/private_write.py - write a secret file private from its first byte (v5.68.0-beta.16, Q151). Pure stdlib; shipped in the release tarball.

`install.sh` runs as root and used to write `jen.config` (every database password and API credential) with `cat > "$CONFIG_FILE"` under umask 022
inside the SERVICE-WRITABLE config directory: created 0644, following a symlink the service account could have planted, and tightened to 0600
only after every password was in it. This is the same discipline as `jen/services/private_files.py` (the running app's writer) and the Kea
helper's `_install_private`, callable from bash with the content on stdin:

    printf '%s' "$text" | python3 tools/private_write.py DEST [--owner UID:GID] [--mode 0600]
    python3 tools/private_write.py DEST --copy-from SRC [--owner UID:GID] [--mode 0600]     # a backup copy

  1. a symlink (or anything that is not a regular file) already at DEST is REFUSED, and so is a symlink SRC: nothing is followed;
  2. a UNIQUE temp name in DEST's own directory, created `O_CREAT | O_EXCL | O_NOFOLLOW` with mode 0600 - nobody else can read it, and a
     pre-planted file or link of that name is never opened;
  3. the data written and fsynced, then the FINAL owner and mode applied to the open DESCRIPTOR (`fchown`, `fchmod`): a chown that fails ABORTS
     (it is never swallowed), the temp is removed and DEST is untouched;
  4. `os.replace` into place - DEST is either the old file or the complete new one, never partial.

Exit status: 0 written; 2 usage; 3 refused (a symlink or a non-regular file); 4 the write failed (DEST untouched, no temp left).
"""

import argparse
import contextlib
import os
import secrets
import stat
import sys

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _refuse(message):
    print(f"private_write: refused: {message}", file=sys.stderr)
    return 3


def _read_source(path):
    """The bytes of `path`, opened without following a symlink and only if it is a regular file."""
    fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise IsADirectoryError(path)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_private(dest, data, mode=0o600, owner=None):
    """Write `data` to `dest` as described above. Raises OSError on failure (nothing left behind)."""
    directory = os.path.dirname(os.path.abspath(dest))
    base = os.path.basename(dest)
    tmp = None
    for _ in range(64):
        candidate = os.path.join(directory, f".{base}.{secrets.token_hex(8)}.tmp")
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
        except FileExistsError:
            continue
        tmp = candidate
        break
    if tmp is None:
        raise FileExistsError(f"no unused temp name in {directory}")
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
            if owner is not None:
                os.fchown(
                    fd, owner[0], owner[1]
                )  # never swallowed: a config owned by the wrong account must not be installed
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Write a secret file private from its first byte.")
    parser.add_argument("dest")
    parser.add_argument("--mode", default="0600", help="final mode, octal (default 0600)")
    parser.add_argument("--owner", default=None, help="final owner as UID:GID (numeric)")
    parser.add_argument("--copy-from", default=None, help="copy this file instead of reading stdin")
    args = parser.parse_args(argv)

    try:
        mode = int(args.mode, 8)
    except ValueError:
        print("private_write: --mode must be octal", file=sys.stderr)
        return 2
    owner = None
    if args.owner is not None:
        try:
            uid, gid = (int(part) for part in args.owner.split(":", 1))
        except ValueError:
            print("private_write: --owner must be UID:GID (numeric)", file=sys.stderr)
            return 2
        owner = (uid, gid)

    try:
        existing = os.lstat(args.dest)
    except FileNotFoundError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        return _refuse(f"{args.dest} is a symlink or not a regular file")

    try:
        data = _read_source(args.copy_from) if args.copy_from else sys.stdin.buffer.read()
    except OSError as e:
        return _refuse(
            f"cannot read {args.copy_from} ({e.__class__.__name__}: a symlink or a non-regular file is never copied)"
        )
    try:
        write_private(args.dest, data, mode, owner)
    except OSError as e:
        print(f"private_write: could not write {args.dest}: {e}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
