"""
jen/services/private_files.py
─────────────────────────────
v5.68.0-beta.15 (Q150) — write a secret so that it is private from its FIRST BYTE.

The old writers (`jen.config`, the SSL private key, the Fernet key) did `open(tmp, "w")` and `os.chmod` afterwards. The file is created
with the process umask (0022 under systemd's default: world-readable), the secret is written into it, and only then is it tightened.
What closed that window was the directory's own mode, which is not something to depend on. `write_private_file` is the discipline in one
place, the same one jen-kea-helper's `_private_tempfile` uses for every file it writes on a Kea host:

  1. a UNIQUE temp name in the TARGET'S OWN directory (so the final `os.replace` is atomic and two writers never share a path),
     created `O_CREAT | O_EXCL | O_NOFOLLOW` with mode 0600 - nobody else can read it, and a pre-planted file or symlink of that
     name is never opened;
  2. the data written and fsynced to the descriptor;
  3. the file's FINAL owner and mode applied to the descriptor (`fchown`, `fchmod`) - never to a path another process could swap;
  4. `os.replace` into place.

A file that is meant to be more open than 0600 (the Flask secret key is 0640) is therefore 0600 until the moment it is complete and
only then becomes what it is meant to be. A failure at any step removes the temp file and raises; the target is never half-written.

Pure stdlib: it has to work from `jen/config.py` (imported before anything else) and from a service that cannot reach its database.
"""

from __future__ import annotations

import contextlib
import os
import secrets

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_ATTEMPTS = 64


def private_tempfile(directory: str, prefix: str) -> tuple[int, str]:
    """(fd, path) of a NEW file in `directory`: unique name, `O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600 (whatever the umask - the umask
    can only remove bits from 0600), opened for writing. The caller owns it and must remove it on failure."""
    for _ in range(_ATTEMPTS):
        path = os.path.join(directory, f".{prefix}.{secrets.token_hex(8)}.tmp")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW, 0o600)
        except FileExistsError:
            continue
        return fd, path
    raise FileExistsError(f"could not find an unused temp name in {directory}")


def write_private_file(
    path: str,
    data: bytes | str,
    mode: int = 0o600,
    *,
    owner: tuple[int, int] | None = None,
) -> None:
    """Write `data` to `path` atomically, private from its first byte, ending up with `mode` and (when given) `owner` = (uid, gid).
    The previous file, if any, is replaced in one `os.replace`. Raises OSError on failure, leaving no temp file behind."""
    directory = os.path.dirname(os.path.abspath(path))
    payload = data.encode("utf-8") if isinstance(data, str) else data
    fd, tmp = private_tempfile(directory, os.path.basename(path))
    try:
        try:
            view = memoryview(payload)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
            if owner is not None and hasattr(os, "fchown"):
                os.fchown(fd, owner[0], owner[1])
            if hasattr(os, "fchmod"):
                os.fchmod(fd, mode)
            else:  # Windows (the dev box): no fchmod; the file is still a private temp until the replace
                os.chmod(tmp, mode)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    with contextlib.suppress(OSError, AttributeError):  # make the rename itself durable; best effort
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
