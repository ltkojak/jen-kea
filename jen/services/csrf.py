"""
jen/services/csrf.py
─────────────────────
CSRF protection. Session-bound, signed, time-limited tokens using
itsdangerous (already a Flask dependency — no new install required).

Design:
- Each session gets a random nonce (session['_csrf_nonce']), created on
  first use and persisted in Flask's own signed session cookie.
- csrf_token() signs that nonce with a timestamp via itsdangerous and
  returns the result — this is the value forms/JS embed and submit back.
- validate_csrf_token() verifies the signature, checks it hasn't expired,
  and confirms the nonce inside it matches the current session's nonce
  (so a token from someone else's session can never validate here).

Requests authenticated via `Authorization: Bearer <api key>` are exempt —
not because they're less sensitive, but because CSRF specifically exploits
a browser automatically attaching *cookies* to a forged cross-site request.
A forged request (whether an auto-submitting <form> or cross-origin JS
without CORS permission) cannot attach a custom Authorization header, so
the attack this module defends against does not apply to API-key auth.
Jen sets no permissive CORS headers, so that guarantee holds.
"""

import secrets

from flask import request, session
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

CSRF_SALT    = "jen-csrf"
CSRF_MAX_AGE = 4 * 60 * 60  # 4 hours


def _serializer(app):
    return URLSafeTimedSerializer(app.secret_key, salt=CSRF_SALT)


def _session_nonce():
    if "_csrf_nonce" not in session:
        session["_csrf_nonce"] = secrets.token_hex(16)
    return session["_csrf_nonce"]


def generate_csrf_token(app):
    """Return a fresh signed CSRF token bound to the current session."""
    return _serializer(app).dumps(_session_nonce())


def validate_csrf_token(app, token):
    """Return True iff `token` is a valid, unexpired signature over the
    current session's nonce. Any missing/malformed/expired/mismatched
    token returns False — never raises."""
    if not token:
        return False
    try:
        nonce = _serializer(app).loads(token, max_age=CSRF_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return False
    except Exception:
        return False
    return secrets.compare_digest(nonce, session.get("_csrf_nonce", ""))


def is_api_key_request():
    """True if this request carries a Bearer credential — see module
    docstring for why that exempts it from CSRF checks."""
    return request.headers.get("Authorization", "").startswith("Bearer ")


def get_submitted_token():
    """Pull a submitted CSRF token from wherever the request puts it —
    a hidden form field for plain <form> POSTs, or a header for JS
    fetch()/HTMX requests that send JSON or don't have a form body."""
    return request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
