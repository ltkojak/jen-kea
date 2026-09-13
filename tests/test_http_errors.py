"""
tests/test_http_errors.py
──────────────────────────
v5.28.0 (Q24, D2) — jen/__init__.py's `@app.errorhandler(HTTPException)`.
Before this, the catch-all `@app.errorhandler(Exception)` caught every
`abort()`-raised HTTPException too (it IS an Exception) and always
rendered the generic 500 page — a 405 read as "Internal Server Error"
and lost its `Allow` header, a 401 lost `WWW-Authenticate`. The 404
handler stays untouched (Flask already prefers it, being more
specific).
"""

from werkzeug.datastructures import WWWAuthenticate
from werkzeug.exceptions import BadRequest, Forbidden, InternalServerError, Unauthorized


class TestHttpExceptionHandler:
    def test_405_keeps_its_status_and_allow_header(self, logged_in_client):
        # /settings/plugins/install/<id> is POST-only.
        r = logged_in_client.get("/settings/plugins/install/x")
        assert r.status_code == 405
        assert "POST" in r.headers.get("Allow", "")
        assert b"405" in r.data
        assert b"Internal Server Error" not in r.data

    def test_400_via_handle_http_exception(self, app):
        with app.test_request_context():
            resp = app.handle_http_exception(BadRequest())
            assert resp.status_code == 400

    def test_403_via_handle_http_exception(self, app):
        with app.test_request_context():
            resp = app.handle_http_exception(Forbidden())
            assert resp.status_code == 403

    def test_401_preserves_www_authenticate_header(self, app):
        with app.test_request_context():
            resp = app.handle_http_exception(Unauthorized(www_authenticate=WWWAuthenticate("basic", {"realm": "jen"})))
            assert resp.status_code == 401
            assert "WWW-Authenticate" in resp.headers

    def test_5xx_shows_the_generic_page_without_leaking_the_description(self, app):
        with app.test_request_context():
            # The 5xx branch returns a (body, status) tuple, same shape
            # as the existing 404/500 handlers — Flask's normal request
            # pipeline runs this through make_response() itself; calling
            # handle_http_exception() directly, as this test does,
            # skips that step, so do it explicitly here too.
            raw = app.handle_http_exception(InternalServerError("some sensitive internal detail"))
            resp = app.make_response(raw)
            assert resp.status_code == 500
            assert b"some sensitive internal detail" not in resp.data
            assert b"Internal server error" in resp.data

    def test_404_is_still_handled_by_its_own_more_specific_handler(self, client):
        r = client.get("/this-route-does-not-exist")
        assert r.status_code == 404
        assert b"Page not found" in r.data
