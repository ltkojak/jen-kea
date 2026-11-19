"""
tests/test_sign_in_page_token.py
────────────────────────────────
v7.2.0-beta.1 (Q243) - the maintainer's report: a session expires, the sign-in page says so, and signing in
from that page answers a 403 page with a "Back to Dashboard" button and no form. The sign-in page is the one
page a person leaves open for hours (the page an expired session lands on), and its form carries a token that
is good for four hours and bound to the session cookie it was rendered under.

What is held here, with the token check ON (the rest of the suite runs with it off):

* a sign-in POST whose token is past its age, missing, or another session's is still REFUSED (403, no sign-in),
  and the answer is the sign-in page again: a form, a fresh token that works, the username kept, one sentence;
* a message the old page had already shown is not shown a second time above it;
* the sign-in page says `Cache-Control: no-store`, so a browser asks for it again and never shows a kept copy;
* every OTHER form's refused token is the 403 page it always was.
"""

import re

import pytest

import jen.services.csrf as csrf_svc
from jen.routes.auth import SIGN_IN_AGAIN

TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
OLD_PAGE = "Your session security token is missing or expired"


@pytest.fixture
def csrf_on(app):
    original = app.config.get("WTF_CSRF_ENABLED", False)
    app.config["WTF_CSRF_ENABLED"] = True
    yield
    app.config["WTF_CSRF_ENABLED"] = original


def _token(html):
    found = TOKEN_RE.search(html)
    assert found, "the page carries no csrf_token field"
    return found.group(1)


def _signed_in(client):
    with client.session_transaction() as sess:
        return bool(sess.get("_user_id"))


class TestAnOldSignInPage:
    def test_a_token_past_its_age_gets_the_sign_in_page_again(self, client, csrf_on, monkeypatch):
        page = client.get("/login?local=1")
        old_token = _token(page.get_data(as_text=True))
        monkeypatch.setattr(
            csrf_svc, "CSRF_MAX_AGE", -1
        )  # every token is now past its age: the four hours have gone by
        r = client.post(
            "/login?local=1", data={"csrf_token": old_token, "username": "admin", "password": "wrong-password"}
        )
        body = r.get_data(as_text=True)
        assert r.status_code == 403
        assert OLD_PAGE not in body and "Back to Dashboard" not in body
        assert SIGN_IN_AGAIN in body
        assert 'name="password"' in body and 'value="admin"' in body
        assert not _signed_in(client)

    def test_the_fresh_token_on_that_page_is_accepted(self, client, csrf_on, monkeypatch):
        """The control for the test above: the refusal was the token's age, and the page it answered with carries a token the check takes. The password is wrong on purpose:
        a 200 with the ordinary wrong-password sentence proves the POST got past the token check and into the sign-in route."""
        old_token = _token(client.get("/login?local=1").get_data(as_text=True))
        monkeypatch.setattr(csrf_svc, "CSRF_MAX_AGE", -1)
        refused = client.post("/login?local=1", data={"csrf_token": old_token, "username": "admin", "password": "x"})
        monkeypatch.setattr(csrf_svc, "CSRF_MAX_AGE", 4 * 60 * 60)
        fresh = _token(refused.get_data(as_text=True))
        r = client.post(
            "/login?local=1", data={"csrf_token": fresh, "username": "admin", "password": "not-the-password"}
        )
        assert r.status_code == 200
        assert SIGN_IN_AGAIN not in r.get_data(as_text=True)
        assert not _signed_in(client)

    def test_a_token_of_a_session_cookie_that_is_gone(self, client, app, csrf_on):
        """A page the browser kept while its session cookie went (a restored tab): the token is signed and in date, and belongs to a session this browser no longer has."""
        token = _token(client.get("/login?local=1").get_data(as_text=True))
        other = app.test_client()
        r = other.post("/login?local=1", data={"csrf_token": token, "username": "admin", "password": "x"})
        body = r.get_data(as_text=True)
        assert r.status_code == 403 and SIGN_IN_AGAIN in body and 'name="password"' in body

    def test_no_token_at_all(self, client, csrf_on):
        r = client.post("/login?local=1", data={"username": "admin", "password": "x"})
        body = r.get_data(as_text=True)
        assert r.status_code == 403 and SIGN_IN_AGAIN in body and OLD_PAGE not in body

    def test_a_correct_password_with_a_refused_token_signs_nobody_in(self, client, csrf_on, db):
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username='q243_signin'")
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES ('q243_signin', %s, 'viewer')",
                (hash_password("a-correct-password-243"),),
            )
        db.commit()
        try:
            r = client.post("/login?local=1", data={"username": "q243_signin", "password": "a-correct-password-243"})
            assert r.status_code == 403
            assert not _signed_in(client)
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE username='q243_signin'")
            db.commit()

    def test_a_message_the_old_page_showed_is_not_shown_twice(self, client, csrf_on):
        with client.session_transaction() as sess:
            sess["_flashes"] = [("error", "Session expired. Please log in again.")]
        r = client.post("/login?local=1", data={"username": "admin", "password": "x"})
        body = r.get_data(as_text=True)
        assert SIGN_IN_AGAIN in body
        assert "Session expired" not in body

    def test_the_address_is_kept_so_next_still_works(self, client, csrf_on):
        """The page is rendered at the address the form posted to, and the form has no `action`: the fresh form posts to the same `?next=`."""
        r = client.post("/login?local=1&next=/leases", data={"username": "admin", "password": "x"})
        body = r.get_data(as_text=True)
        assert r.status_code == 403
        assert '<form method="POST" autocomplete="on">' in body


class TestTheSignInPageIsNeverAKeptCopy:
    def test_get_says_no_store(self, client):
        r = client.get("/login")
        assert r.status_code == 200
        assert r.headers.get("Cache-Control") == "no-store"

    def test_the_page_asks_again_when_the_browser_puts_it_back(self, client):
        body = client.get("/login").get_data(as_text=True)
        assert "pageshow" in body and "e.persisted" in body and "window.location.reload()" in body


class TestEveryOtherFormIsRefusedAsBefore:
    def test_a_signed_in_post_without_a_token_is_the_403_page(self, logged_in_client, csrf_on):
        r = logged_in_client.post("/logout", data={})
        body = r.get_data(as_text=True)
        assert r.status_code == 403
        assert OLD_PAGE in body and SIGN_IN_AGAIN not in body
