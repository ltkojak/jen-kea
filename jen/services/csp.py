"""
jen/services/csp.py
─────────────────────
v5.22.0 (Q18) — the per-request nonce that lets Content-Security-Policy
drop 'unsafe-inline' for script-src. One nonce per request, generated
before any template renders and reused verbatim in the response's CSP
header — the two have to match exactly or the browser refuses every
nonced <script> tag on the page.
"""

import secrets


def nonce() -> str:
    """A fresh, unguessable per-request token. 16 random bytes,
    URL-safe base64 — plenty for a value that only has to be unique
    and unpredictable for the lifetime of one response, never stored
    or compared across requests."""
    return secrets.token_urlsafe(16)
