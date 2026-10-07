"""
jen/services/certs.py
─────────────────────
v5.12.0 — the installed SSL certificate's metadata, via `openssl x509`.

Extracted from jen/routes/settings/__init__.py::_cert_info so the Health
Center (jen/services/health.py) and the cert-expiry alert can read
`days_left` without importing a route module. `_cert_info` there is now a
thin wrapper around `cert_info(installed_cert_path())`.
"""

import contextlib
import logging
import os
import subprocess

logger = logging.getLogger(__name__)


def commit_file_set(members, keep_prev: bool = True) -> None:
    """Install a SET of files all-or-nothing (v5.68.0-beta.16, Q151). `members` = [(live_path, data: str | bytes, mode)] in install order (keys before
    the certificates that name them, so a reader that finds a cert finds its key).

    The old writers moved the LIVE file to `<name>.prev` BEFORE its replacement existed (a failure right after left no live file at all - a service
    that cannot start), and a set (cert, key, CA, combined; the Kea CA's four files) was installed one file at a time, so a failure at any step left a
    new key beside an old certificate. Now:
      1. STAGE every member: a unique private temp next to it (O_EXCL 0600, written, fsynced, final mode applied) - nothing live has been touched;
      2. SNAPSHOT every live member into memory WITHOUT moving it, and (`keep_prev`) write `<name>.prev` as a COPY - never the only live copy;
      3. REPLACE each staged file over its live path, in order.
    On ANY failure every member already replaced is put back byte-for-byte with its old mode (one that did not exist is removed), every staged temp
    is removed, and the original error is re-raised - or an OSError naming every path that is now wrong if a restore ALSO failed. A symlink at a live
    path is refused. The one place a `.prev` may be made (tests/test_invariant_sweeps.py, S2)."""
    import errno
    import stat as _stat

    from jen.services.private_files import stage_private_file, write_private_file

    staged, snapshots, replaced = [], {}, []
    try:
        for live, data, mode in members:
            if os.path.islink(live):
                raise OSError(errno.ELOOP, "refusing to replace a symlink", live)
            staged.append((live, stage_private_file(live, data, mode)))
        for live, _tmp in staged:
            try:
                with open(live, "rb") as f:
                    snapshots[live] = (f.read(), _stat.S_IMODE(os.fstat(f.fileno()).st_mode))
            except FileNotFoundError:
                snapshots[live] = None
        if keep_prev:
            for live, _tmp in staged:
                if snapshots[live] is not None:
                    write_private_file(live + ".prev", snapshots[live][0], snapshots[live][1])
        for live, tmp in staged:
            os.replace(tmp, live)
            replaced.append(live)
    except BaseException as original:
        wrong = []
        for live in reversed(replaced):
            snap = snapshots.get(live)
            try:
                if snap is None:
                    os.unlink(live)
                else:
                    write_private_file(live, snap[0], snap[1])
            except OSError as e:
                wrong.append(f"{live} ({e})")
        for _live, tmp in staged:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
        if wrong:
            raise OSError(
                "the file set could not be put back; these paths are now wrong: " + ", ".join(wrong)
            ) from original
        raise
    for _live, tmp in staged:
        with contextlib.suppress(OSError):
            os.unlink(tmp)  # renamed away on success: nothing is left to remove


def write_atomically(path: str, data, mode: int) -> None:
    """One file, installed through `commit_file_set` (a set of one): a reader (or a restart) never sees a half-written PEM, the previous file is kept
    beside it as `<name>.prev` (a COPY, made before the replace - the live file is never moved away first), and the PEM - the private key above all -
    is private from its first byte (a unique O_EXCL 0600 temp, the final mode applied to the descriptor). `data` may be str or bytes. v5.29.0 (Q29) —
    moved here from routes/settings/security.py so the Kea CA (jen/services/kea_tls.py) and the SSL upload share one writer."""
    commit_file_set([(path, data, mode)])


def installed_cert_path() -> str:
    """The PEM Jen is actually serving from — the combined chain if it
    exists, else the bare leaf certificate."""
    from jen import extensions

    return extensions.SSL_COMBINED if os.path.exists(extensions.SSL_COMBINED) else extensions.SSL_CERT


def cert_info(path: str) -> dict:
    """`{subject, issuer, expires, days_left}` for a PEM cert file. Returns
    `{}` when openssl isn't available or the file can't be read, and
    `{"error": ...}` when openssl ran but its output didn't parse.
    `days_left` is only present when the notAfter date parsed."""
    info: dict = {}
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-subject", "-enddate", "-issuer"],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            if line.startswith("subject="):
                info["subject"] = line.replace("subject=", "").strip()
            elif line.startswith("notAfter="):
                info["expires"] = line.replace("notAfter=", "").strip()
            elif line.startswith("issuer="):
                info["issuer"] = line.replace("issuer=", "").strip()
        if info.get("expires"):
            from datetime import datetime, timezone

            try:
                exp = datetime.strptime(info["expires"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                info["days_left"] = (exp - datetime.now(timezone.utc)).days
            except ValueError:
                pass
    except Exception as e:
        logger.error(f"Error reading SSL certificate info: {e}")
        info["error"] = "Could not read certificate info. Check server logs for details."
    return info
