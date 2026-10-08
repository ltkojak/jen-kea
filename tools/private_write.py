#!/usr/bin/env python3
"""
tools/private_write.py - write a secret file private from its first byte (v5.68.0-beta.16, Q151). Pure stdlib; shipped in the release tarball.

`install.sh` runs as root and used to write `jen.config` (every database password and API credential) with `cat > "$CONFIG_FILE"` under umask 022
inside the SERVICE-WRITABLE config directory: created 0644, following a symlink the service account could have planted, and tightened to 0600
only after every password was in it. This is the same discipline as `jen/services/private_files.py` (the running app's writer) and the Kea
helper's `_install_private`, callable from bash with the content on stdin:

    printf '%s' "$text" | python3 tools/private_write.py DEST [--owner UID:GID] [--mode 0600]
    python3 tools/private_write.py DEST --copy-from SRC [--owner UID:GID] [--mode 0600]     # a backup copy
    python3 tools/private_write.py DEST --lock DEST.lock [--lock-owner UID:GID] ...         # hold the config file lock for the write
    python3 tools/private_write.py DEST --trusted-root DIR ...                              # walk from DIR by directory descriptors
    python3 tools/private_write.py --hold-lock DEST.lock [--owner UID:GID]                  # take the lock, print "locked", hold it until stdin closes

  1. a symlink (or anything that is not a regular file) already at DEST is REFUSED, and so is a symlink SRC: nothing is followed;
  2. a UNIQUE temp name in DEST's own directory, created `O_CREAT | O_EXCL | O_NOFOLLOW` with mode 0600 - nobody else can read it, and a
     pre-planted file or link of that name is never opened;
  3. the data written and fsynced, then the FINAL owner and mode applied to the open DESCRIPTOR (`fchown`, `fchmod`): a chown that fails ABORTS
     (it is never swallowed), the temp is removed and DEST is untouched;
  4. `os.replace` into place - DEST is either the old file or the complete new one, never partial.

  5. with `--lock PATH` (v5.68.0-beta.18, Q153) an exclusive advisory `flock` on PATH is held for the whole write - the same `<config>.lock` Jen's
     `AppConfig` writers take, so the installer and the running service cannot both rewrite jen.config at once. `install.sh --configure` holds
     that lock itself for its whole wizard (`--hold-lock`) and does not pass --lock.

  6. with `--trusted-root DIR` (v5.68.0-beta.20, Q155) no pathname is re-resolved after it was checked. DIR is opened once (it is the operator's own,
     it may be reached by a link) and every component below it is opened with `O_DIRECTORY | O_NOFOLLOW` relative to the previous directory
     descriptor (created 0700 when absent); the temp, the lstat of DEST, the rename and the directory fsync are all `openat`-style, relative to the
     LAST descriptor. A symlink at any component is REFUSED, and a directory that is replaced while the write is in flight (a path that no longer
     names the directory the descriptor holds) is REFUSED before the rename. Before this, the parent of DEST was a pathname resolved by `open` and
     `rename` at the moment of use, so a symlink the service account planted at `$CONFIG_DIR/backups` was followed by root.

  A lock is an INODE. `take_lock` opens it ONCE with `O_NOFOLLOW` and normalises THAT inode in place (`fchown` to --owner, `fchmod` 0600 - neither
  drops a flock); it never renames a new file over the lock path, and it refuses anything that is not a regular file with a single link.

Exit status: 0 written; 2 usage; 3 refused (a symlink or a non-regular file); 4 the write failed (DEST untouched, no temp left); 6 the lock could
not be taken.
"""

import argparse
import contextlib
import errno
import os
import secrets
import select
import stat
import sys
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - not POSIX
    fcntl = None

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class Refused(OSError):
    """Something is not what a trusted write may use: a symlink, a non-regular file, a swapped directory."""


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


def _open_dirs_under(trusted_root, directory, dir_mode=0o700):
    """An open descriptor for `directory`, reached from `trusted_root` one `O_DIRECTORY | O_NOFOLLOW` descriptor at a time (missing components are
    created `dir_mode`). The root itself is opened normally: it is the operator's own path. A symlink or a non-directory at any component below it
    raises Refused."""
    root = os.path.abspath(trusted_root)
    target = os.path.abspath(directory)
    rel = os.path.relpath(target, root)
    if rel == os.pardir or rel.startswith(os.pardir + os.sep) or os.path.isabs(rel):
        raise Refused(errno.EPERM, f"{directory} is not under the trusted root {trusted_root}")
    fd = os.open(root, os.O_RDONLY | _DIRECTORY | _CLOEXEC)
    try:
        if rel != os.curdir:
            for part in rel.split(os.sep):
                try:
                    nxt = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    os.mkdir(part, dir_mode, dir_fd=fd)
                    nxt = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=fd)
                except OSError as e:
                    if e.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise Refused(e.errno, f"{part} under {trusted_root} is a symlink or not a directory") from e
                    raise
                os.close(fd)
                fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd


def _still_names(dfd, directory):
    """True while the pathname `directory` still resolves to the very directory `dfd` holds (it was not swapped out from under the write)."""
    try:
        a = os.fstat(dfd)
        b = os.stat(directory)
    except OSError:
        return False
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def write_private(dest, data, mode=0o600, owner=None, trusted_root=None):
    """Write `data` to `dest` as described above. Raises OSError on failure (nothing left behind); Refused for a symlink or a swapped directory.
    With `trusted_root` the parent is walked by directory descriptors and every operation is relative to the last one (item 6)."""
    if trusted_root is not None:
        return _write_private_under(dest, data, mode, owner, trusted_root)
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
            _fill(fd, data, mode, owner)
        finally:
            os.close(fd)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _fill(fd, data, mode, owner):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]
    os.fsync(fd)
    if owner is not None:
        os.fchown(fd, owner[0], owner[1])  # never swallowed: a file owned by the wrong account must not be installed
    os.fchmod(fd, mode)


def _write_private_under(dest, data, mode, owner, trusted_root):
    directory = os.path.dirname(os.path.abspath(dest))
    base = os.path.basename(dest)
    dfd = _open_dirs_under(trusted_root, directory)
    tmp = None
    try:
        try:
            existing = os.lstat(base, dir_fd=dfd)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise Refused(errno.EPERM, f"{dest} is a symlink or not a regular file")
        fd = None
        for _ in range(64):
            candidate = f".{base}.{secrets.token_hex(8)}.tmp"
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC, 0o600, dir_fd=dfd)
            except FileExistsError:
                continue
            tmp = candidate
            break
        if tmp is None:
            raise FileExistsError(f"no unused temp name in {directory}")
        try:
            _fill(fd, data, mode, owner)
        finally:
            os.close(fd)
        if not _still_names(dfd, directory):
            raise Refused(errno.EPERM, f"{directory} was replaced while {dest} was being written")
        os.replace(tmp, base, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = None
        with contextlib.suppress(OSError):  # a filesystem that cannot fsync a directory
            os.fsync(dfd)
    except BaseException:
        if tmp is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=dfd)
        raise
    finally:
        os.close(dfd)


def _normalise_lock(fd, path, owner):
    """Put the lock file the descriptor holds into its right state IN PLACE: a regular file, one link, the service user's, 0600. Same inode throughout
    - `fchown` and `fchmod` do not drop an flock."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise Refused(errno.EPERM, f"{path} is not a regular file")
    if st.st_nlink != 1:
        raise Refused(errno.EPERM, f"{path} has {st.st_nlink} links - it must be a file of its own")
    if owner is not None and (st.st_uid, st.st_gid) != tuple(owner):
        os.fchown(fd, owner[0], owner[1])
    if stat.S_IMODE(st.st_mode) != 0o600:
        os.fchmod(fd, 0o600)


def take_lock(path, owner=None, wait_s=60.0):
    """Open `path` ONCE (created 0600, `O_NOFOLLOW`), normalise that inode in place (see `_normalise_lock`) and take an exclusive flock on it,
    waiting up to `wait_s`. Returns the open fd (closing it releases the lock). Raises OSError when it cannot be opened or normalised (Refused for
    a symlink or a non-regular file) and TimeoutError when the wait runs out. It never replaces the file: the inode an installer locks is the
    inode Jen locks."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | _NOFOLLOW | _CLOEXEC, 0o600)
    try:
        _normalise_lock(fd, path, owner)
        if fcntl is None:
            return fd
        deadline = time.monotonic() + wait_s
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"{path} is held by another process") from e
                time.sleep(0.05)
    except BaseException:
        os.close(fd)
        raise


def _parse_owner(text):
    uid, gid = (int(part) for part in text.split(":", 1))
    return (uid, gid)


def _hold_lock(path, owner, wait_s=120.0):
    """`--hold-lock`: take the config lock, say so on stdout, and hold it until stdin reaches EOF (the installer closes it - or dies, which closes it
    for it). One process, one `take_lock`: the installer's wizard and Jen's `AppConfig` lock the same inode through the same open."""
    try:
        fd = take_lock(path, owner, wait_s)
    except Refused as e:
        return _refuse(str(e))
    except (OSError, TimeoutError) as e:
        print(f"private_write: could not take the lock {path}: {e}", file=sys.stderr)
        return 6
    try:
        sys.stdout.write("locked\n")
        sys.stdout.flush()
        # until stdin reaches EOF (the installer closed it), or the installer is gone (a child that inherited the pipe keeps EOF from coming), or it
        # is signalled (the installer's release); the parent is polled once a second
        parent = os.getppid()
        while True:
            ready, _w, _x = select.select([0], [], [], 1.0)
            if ready:
                if not os.read(0, 4096):
                    break
            elif os.getppid() != parent:
                break
    finally:
        os.close(fd)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Write a secret file private from its first byte.")
    parser.add_argument("dest", nargs="?")
    parser.add_argument("--mode", default="0600", help="final mode, octal (default 0600)")
    parser.add_argument("--owner", default=None, help="final owner as UID:GID (numeric)")
    parser.add_argument("--copy-from", default=None, help="copy this file instead of reading stdin")
    parser.add_argument(
        "--lock", default=None, help="hold an exclusive advisory flock on this file for the whole write"
    )
    parser.add_argument(
        "--lock-owner",
        default=None,
        help="owner of the --lock/--hold-lock file as UID:GID (default: --owner); the lock is the SERVICE user's even when the file written is root's",
    )
    parser.add_argument(
        "--trusted-root",
        default=None,
        help="walk DEST's parents from this directory by O_NOFOLLOW directory descriptors",
    )
    parser.add_argument(
        "--hold-lock",
        default=None,
        help="take the config lock on this file, print 'locked', hold it until stdin closes",
    )
    args = parser.parse_args(argv)

    try:
        mode = int(args.mode, 8)
    except ValueError:
        print("private_write: --mode must be octal", file=sys.stderr)
        return 2
    owner = None
    if args.owner is not None:
        try:
            owner = _parse_owner(args.owner)
        except ValueError:
            print("private_write: --owner must be UID:GID (numeric)", file=sys.stderr)
            return 2

    lock_owner = owner
    if args.lock_owner is not None:
        try:
            lock_owner = _parse_owner(args.lock_owner)
        except ValueError:
            print("private_write: --lock-owner must be UID:GID (numeric)", file=sys.stderr)
            return 2

    if args.hold_lock:
        return _hold_lock(args.hold_lock, lock_owner)
    if not args.dest:
        print("private_write: DEST is required", file=sys.stderr)
        return 2

    if args.trusted_root is None:
        try:
            existing = os.lstat(args.dest)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            return _refuse(f"{args.dest} is a symlink or not a regular file")

    # the lock first, so a backup copy of the live file is read INSIDE it (read-modify-replace is one critical section)
    lock_fd = None
    if args.lock:
        try:
            lock_fd = take_lock(args.lock, lock_owner)
        except Refused as e:
            return _refuse(str(e))
        except OSError as e:
            print(f"private_write: could not take the lock {args.lock}: {e}", file=sys.stderr)
            return 6
    try:
        try:
            data = _read_source(args.copy_from) if args.copy_from else sys.stdin.buffer.read()
        except OSError as e:
            return _refuse(
                f"cannot read {args.copy_from} ({e.__class__.__name__}: a symlink or a non-regular file is never copied)"
            )
        try:
            write_private(args.dest, data, mode, owner, trusted_root=args.trusted_root)
        except Refused as e:
            return _refuse(str(e))
        except OSError as e:
            print(f"private_write: could not write {args.dest}: {e}", file=sys.stderr)
            return 4
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
