"""
jen/services/host_match.py
──────────────────────────
v5.68.0-beta.23 (Q158 fixup 4, F3) - does a Kea server's API host name the same machine as its SSH host?

Jen reads a Kea daemon through the API and edits its config file, restarts it and tails its log over SSH. If the two are not the same Kea, what Jen
reads back (investigation logging's `config-get`, Explain's evidence) describes a different daemon from the one whose file it changed. The Kea
settings save WARNS when the two hosts resolve to different addresses; it never refuses (an SSH jump host, a tunnel or a VIP are legitimate).

This lives here and not in `auth.py` because the resolver runs a short-lived thread (getaddrinfo has no timeout of its own), and
tests/test_auth.py guards `auth.py` and `models/user.py` against starting threads at all.
"""

from __future__ import annotations

import ipaddress


def _addresses_of(host: str, timeout: float = 2.0):
    """The addresses `host` resolves to, as a set, or None when it does not resolve inside `timeout` (a literal needs no lookup). The lookup runs on a
    short-lived daemon thread: getaddrinfo has no timeout of its own and a save must not hang on a slow resolver."""
    import socket
    import threading

    host = (host or "").strip().strip("[]")
    if not host:
        return None
    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    found: dict = {}

    def look():
        try:
            found["a"] = {str(i[4][0]) for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        except OSError:
            found["a"] = None

    th = threading.Thread(target=look, daemon=True)
    th.start()
    th.join(timeout)
    return found.get("a")


def api_ssh_mismatch(api_url: str, ssh_host: str) -> str:
    """A warning sentence ("" when there is nothing to say) when a Kea server's API host and its SSH host resolve to DIFFERENT addresses
    (v5.68.0-beta.23, Q158 fixup 4, F3). Jen reads a daemon through the API and edits its config file, restarts it and tails its log over SSH; if the two
    are not the same Kea, every confirmation Jen reads back (investigation logging's `config-get`, Explain's evidence) describes a different daemon from
    the one whose file it changed. Never a refusal: an SSH jump host, a tunnel or a VIP are legitimate, so this only says. Anything that does not resolve
    inside two seconds is not warned about - the warning must never be the reason a save is slow or fails."""
    from urllib.parse import urlparse

    try:
        api_host = urlparse((api_url or "").strip()).hostname or ""
    except ValueError:
        return ""
    if not api_host or not (ssh_host or "").strip():
        return ""
    a, b = _addresses_of(api_host), _addresses_of(ssh_host)
    if not a or not b or a & b:
        return ""
    return (
        f"The API host ({api_host}) and the SSH host ({ssh_host.strip()}) resolve to different addresses. Jen reads a Kea through the API and edits "
        "its config file over SSH; if they are not the same Kea, investigation logging and Explain will read back a different daemon from the one "
        "whose file was changed. Saved anyway - check that api_url and the SSH host name the same Kea (an SSH jump host or a VIP is fine)."
    )
