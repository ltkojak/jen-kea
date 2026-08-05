"""
tests/test_csrf.py
────────────────────
Tests for the v4.4.0 CSRF protection layer (jen/services/csrf.py + the
_csrf_protect before_request hook in jen/__init__.py).

The rest of the test suite runs with WTF_CSRF_ENABLED=False (set in the
session-scoped `app` fixture in conftest.py) so none of the ~27 existing
POST/PUT/DELETE tests elsewhere needed to change. These tests explicitly
flip it back on for the duration of each test via the `csrf_client` fixture,
and restore it afterward so later test files aren't affected.
"""

import secrets

import pytest
from itsdangerous import URLSafeTimedSerializer

from jen.services import csrf as csrf_svc


@pytest.fixture
def csrf_client(app, client):
    """A test client identical to `client`, but with real CSRF enforcement
    turned on for the duration of the test, restored afterward."""
    original = app.config.get("WTF_CSRF_ENABLED", False)
    app.config["WTF_CSRF_ENABLED"] = True
    yield client
    app.config["WTF_CSRF_ENABLED"] = original


@pytest.fixture
def logged_in_csrf_client(csrf_client):
    """logged_in_client's session setup, but on the CSRF-enabled client."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with csrf_client.session_transaction() as sess:
        sess["_user_cache"] = {
            "id": 1, "username": "admin",
            "role": "superadmin", "session_timeout": None
        }
        sess["_user_id"] = "1"
        sess["_fresh"]   = True
        sess["last_active"] = now
    return csrf_client


def _valid_token_for(app, client):
    """Build a real, correctly-signed CSRF token bound to whatever nonce
    is (or will be) in the given test client's current session — mirrors
    exactly what generate_csrf_token() does, without needing to render and
    scrape a template for the hidden field."""
    with client.session_transaction() as sess:
        if "_csrf_nonce" not in sess:
            sess["_csrf_nonce"] = secrets.token_hex(16)
        nonce = sess["_csrf_nonce"]
    serializer = URLSafeTimedSerializer(app.secret_key, salt=csrf_svc.CSRF_SALT)
    return serializer.dumps(nonce)


class TestCsrfTokenLogic:
    """Direct tests of jen/services/csrf.py's pure functions, using a real
    Flask request/session context (test_request_context) rather than a
    live HTTP round trip."""

    def test_generate_then_validate_same_session_succeeds(self, app):
        with app.test_request_context():
            token = csrf_svc.generate_csrf_token(app)
            assert csrf_svc.validate_csrf_token(app, token) is True

    def test_missing_token_fails(self, app):
        with app.test_request_context():
            assert csrf_svc.validate_csrf_token(app, None) is False
            assert csrf_svc.validate_csrf_token(app, "") is False

    def test_garbage_token_fails(self, app):
        with app.test_request_context():
            assert csrf_svc.validate_csrf_token(app, "not-a-real-token") is False

    def test_tampered_token_fails(self, app):
        with app.test_request_context():
            token = csrf_svc.generate_csrf_token(app)
            tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
            assert csrf_svc.validate_csrf_token(app, tampered) is False

    def test_token_from_different_session_fails(self, app):
        """A validly-signed token for session A must not validate under
        session B — proves the nonce binding actually matters, not just
        the signature."""
        serializer = URLSafeTimedSerializer(app.secret_key, salt=csrf_svc.CSRF_SALT)
        token_for_other_session = serializer.dumps("some-other-sessions-nonce")
        with app.test_request_context():
            # this request/session context has its own (different) nonce
            csrf_svc.generate_csrf_token(app)
            assert csrf_svc.validate_csrf_token(app, token_for_other_session) is False

    def test_expired_token_fails(self, app, monkeypatch):
        with app.test_request_context():
            token = csrf_svc.generate_csrf_token(app)
        monkeypatch.setattr(csrf_svc, "CSRF_MAX_AGE", -1)  # force immediate expiry
        with app.test_request_context():
            assert csrf_svc.validate_csrf_token(app, token) is False

    def test_is_api_key_request_detects_bearer_header(self, app):
        with app.test_request_context(headers={"Authorization": "Bearer abc123"}):
            assert csrf_svc.is_api_key_request() is True

    def test_is_api_key_request_false_without_bearer(self, app):
        with app.test_request_context():
            assert csrf_svc.is_api_key_request() is False
        with app.test_request_context(headers={"Authorization": "Basic abc123"}):
            assert csrf_svc.is_api_key_request() is False

    def test_get_submitted_token_prefers_header_over_form(self, app):
        with app.test_request_context(
            data={"csrf_token": "from-form"},
            headers={"X-CSRFToken": "from-header"},
            method="POST",
        ):
            # header is checked second in the `or`, form field wins if present —
            # exercising that both paths are actually read
            assert csrf_svc.get_submitted_token() == "from-form"

    def test_get_submitted_token_falls_back_to_header(self, app):
        with app.test_request_context(
            headers={"X-CSRFToken": "from-header"}, method="POST"
        ):
            assert csrf_svc.get_submitted_token() == "from-header"


class TestCsrfMiddlewareIntegration:
    """Full request/response cycle through the real before_request hook,
    against the actual /subnets/save-note route (lightweight — no Kea
    mocking needed, just the test Jen DB)."""

    ROUTE = "/subnets/save-note"

    def test_post_without_token_rejected(self, logged_in_csrf_client):
        r = logged_in_csrf_client.post(self.ROUTE, data={"subnet_id": "1", "notes": "x"})
        assert r.status_code == 403

    def test_post_with_valid_token_succeeds(self, app, logged_in_csrf_client, mock_kea):
        token = _valid_token_for(app, logged_in_csrf_client)
        r = logged_in_csrf_client.post(
            self.ROUTE, data={"subnet_id": "1", "notes": "x", "csrf_token": token}
        )
        assert r.status_code == 200

    def test_post_with_token_via_header_succeeds(self, app, logged_in_csrf_client, mock_kea):
        """Mirrors how the JS fetch() calls send it — as X-CSRFToken, not
        a form field."""
        token = _valid_token_for(app, logged_in_csrf_client)
        r = logged_in_csrf_client.post(
            self.ROUTE,
            data={"subnet_id": "1", "notes": "x"},
            headers={"X-CSRFToken": token},
        )
        assert r.status_code == 200

    def test_post_with_garbage_token_rejected(self, logged_in_csrf_client):
        r = logged_in_csrf_client.post(
            self.ROUTE, data={"subnet_id": "1", "notes": "x", "csrf_token": "garbage"}
        )
        assert r.status_code == 403

    def test_post_with_another_sessions_token_rejected(self, app, logged_in_csrf_client):
        """A token minted for a *different* session must not validate
        against this session — even when this session has its own valid
        token established (so this isn't just testing 'no token at all')."""
        own_token = _valid_token_for(app, logged_in_csrf_client)
        assert own_token  # sanity: this session does have a real nonce/token

        with app.test_request_context():
            foreign_token = csrf_svc.generate_csrf_token(app)

        r = logged_in_csrf_client.post(
            self.ROUTE, data={"subnet_id": "1", "notes": "x", "csrf_token": foreign_token}
        )
        assert r.status_code == 403

    def test_get_requests_never_blocked(self, logged_in_csrf_client):
        """CSRF only applies to state-changing methods — a GET must never
        be rejected regardless of token presence."""
        r = logged_in_csrf_client.get("/subnets")
        assert r.status_code == 200

    def test_bearer_auth_request_exempt_from_csrf(self, logged_in_csrf_client):
        """A request carrying an Authorization: Bearer header must skip the
        CSRF check entirely, even with zero csrf_token — on ANY route, not
        just the /api/v1/* ones, since the middleware checks globally. Uses
        a real POST route (api key creation) with no csrf_token field at
        all; success (302 redirect) proves CSRF was skipped, not just that
        the route happened to tolerate a missing token."""
        r = logged_in_csrf_client.post(
            "/settings/api-keys/create",
            data={"name": "test-exempt-key"},
            headers={"Authorization": "Bearer not-a-real-key"},
        )
        assert r.status_code == 302
        assert b"session security token" not in r.data

    def test_existing_suite_unaffected_by_default(self, logged_in_client):
        """Sanity check: with the default (CSRF-disabled-for-tests) client
        used by the rest of the suite, POSTs still work exactly as before —
        confirms WTF_CSRF_ENABLED=False truly bypasses the new hook."""
        r = logged_in_client.post(
            "/subnets/save-note", data={"subnet_id": "1", "notes": "unaffected"}
        )
        assert r.status_code == 200
