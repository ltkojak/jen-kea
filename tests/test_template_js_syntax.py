"""
tests/test_template_js_syntax.py
────────────────────────────────
v5.31.3 — every inline <script> on the MFA pages must at least PARSE.

Found live: the MFA challenge page's main script had an unescaped
apostrophe inside a single-quoted string ('Follow your browser's
prompt…'). One SyntaxError silently killed the whole block — the tab
buttons, the "remember for" toggle and the Use-passkey button all did
nothing, and nothing in the suite noticed because Python tests only
ever looked at the HTML. This renders the real pages through the app
and hands each <script> body to `node --check`. GitHub's ubuntu runners
ship node; where it's absent the check is skipped, not passed.
"""

import re
import shutil
import subprocess

import pytest

from jen.models.db import jen_db

_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_NODE = shutil.which("node")

REMEMBER_OPTIONS = ("1", "7", "14", "30", "60", "90", "120", "forever")


def _check_scripts(html: str, tmp_path, label: str):
    bodies = [b for b in _SCRIPT_RE.findall(html) if b.strip()]
    assert bodies, f"{label}: no inline scripts found — the extraction regex or the page changed"
    for i, body in enumerate(bodies):
        path = tmp_path / f"{label}_{i}.js"
        path.write_text(body, encoding="utf-8")
        result = subprocess.run([_NODE, "--check", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, f"{label} script #{i} does not parse:\n{result.stderr}\n--- script ---\n{body}"


@pytest.fixture
def admin_with_passkey_and_totp(db):
    """User 1 with both factors so every branch of the three pages renders."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM webauthn_credentials WHERE user_id=1")
        cur.execute("DELETE FROM mfa_methods WHERE user_id=1 AND name='_js_probe'")
        cur.execute(
            "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, name) "
            "VALUES (1, 'anNwcm9iZQ', 'cGs', 0, '_js_probe')"
        )
        cur.execute(
            "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) VALUES (1, 'totp', 'x', '_js_probe', 1)"
        )
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM webauthn_credentials WHERE user_id=1")
        cur.execute("DELETE FROM mfa_methods WHERE user_id=1 AND name='_js_probe'")
    db.commit()


@pytest.mark.skipif(_NODE is None, reason="node not installed — JS syntax check skipped")
class TestMfaPageScriptsParse:
    def test_challenge_page_every_factor_combination(self, client, admin_with_passkey_and_totp, tmp_path):
        with client.session_transaction() as sess:
            sess["mfa_pending_user_id"] = 1
            sess["mfa_pending_username"] = "admin"
        html = client.get("/mfa/verify").get_data(as_text=True)
        assert 'data-tab="passkey"' in html and 'data-tab="totp"' in html
        _check_scripts(html, tmp_path, "challenge_both")
        # Passkey-only and TOTP-only renders take different template branches.
        with jen_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE mfa_methods SET enabled=0 WHERE user_id=1 AND name='_js_probe'")
            conn.commit()
        _check_scripts(client.get("/mfa/verify").get_data(as_text=True), tmp_path, "challenge_passkey_only")
        with jen_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE mfa_methods SET enabled=1 WHERE user_id=1 AND name='_js_probe'")
                cur.execute("DELETE FROM webauthn_credentials WHERE user_id=1")
            conn.commit()
        _check_scripts(client.get("/mfa/verify").get_data(as_text=True), tmp_path, "challenge_totp_only")

    def test_enrol_page(self, logged_in_client, admin_with_passkey_and_totp, tmp_path):
        _check_scripts(logged_in_client.get("/mfa/enroll").get_data(as_text=True), tmp_path, "enroll")

    def test_reauth_page(self, logged_in_client, admin_with_passkey_and_totp, tmp_path):
        _check_scripts(logged_in_client.get("/auth/reauth").get_data(as_text=True), tmp_path, "reauth")


class TestRememberForOptions:
    """v5.31.3 — the same spread of "remember this device for" choices
    on every tab of the challenge page, passkey included (the passkey
    tab's selector existed but its toggle was dead — see module doc)."""

    def test_every_tab_offers_the_full_spread(self, client, admin_with_passkey_and_totp):
        with client.session_transaction() as sess:
            sess["mfa_pending_user_id"] = 1
            sess["mfa_pending_username"] = "admin"
        html = client.get("/mfa/verify").get_data(as_text=True)
        for value in REMEMBER_OPTIONS:
            assert html.count(f'<option value="{value}"') == 3, value  # passkey, totp, backup
        assert 'id="rememberDaysPasskey"' in html and 'id="rememberCbPasskey"' in html
