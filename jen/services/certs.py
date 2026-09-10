"""
jen/services/certs.py
─────────────────────
v5.12.0 — the installed SSL certificate's metadata, via `openssl x509`.

Extracted from jen/routes/settings/__init__.py::_cert_info so the Health
Center (jen/services/health.py) and the cert-expiry alert can read
`days_left` without importing a route module. `_cert_info` there is now a
thin wrapper around `cert_info(installed_cert_path())`.
"""

import logging
import os
import subprocess

logger = logging.getLogger(__name__)


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
