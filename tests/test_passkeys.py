"""
tests/test_passkeys.py
──────────────────────
v5.31.0 (Q31) — passkeys (WebAuthn) as a second factor.

py_webauthn does the cryptography; these tests cover the parts Jen owns
around it: relying-party identity derived from the request, the
single-use / expiring ceremony state, the signature-counter rule, the
storage round-trip, and `mfa.user_factors()`. The library's own verify
functions are replaced at the module boundary (string-form
monkeypatch — see memory on `__alias` name-mangling) with fakes that
return the dataclasses it would, so no real authenticator is needed.

The pure tests (`TestRpIdentity`, `TestCeremonyState`, `TestCounter`)
run without a database: `python -m pytest --noconftest tests/test_passkeys.py -k "RpIdentity or CeremonyState or Counter"`.
"""

import json
import time
from types import SimpleNamespace

import pytest
from flask import Flask

from jen.services import passkeys


def _req_app():
    app = Flask("passkeys-test")
    app.config["SERVER_NAME"] = None
    return app


class TestRpIdentity:
    @pytest.mark.parametrize(
        "host,expected",
        [
            ("jen.lan", "jen.lan"),
            ("jen.lan:8443", "jen.lan"),
            ("10.0.0.5", "10.0.0.5"),
            ("10.0.0.5:5000", "10.0.0.5"),
            ("[::1]:5000", "::1"),
            ("[fd00::10]", "fd00::10"),
            ("  Jen.Example.Com  ", "Jen.Example.Com"),
        ],
    )
    def test_rp_id_from_host(self, host, expected):
        assert passkeys.rp_id_from_host(host) == expected

    def test_rp_id_and_origin_come_from_the_request(self):
        app = _req_app()
        with app.test_request_context("/mfa/enroll", base_url="https://jen.lan:8443"):
            from flask import request

            assert passkeys.rp_id(request) == "jen.lan"
            assert passkeys.expected_origin(request) == "https://jen.lan:8443"

    def test_origin_reflects_the_scheme_the_proxy_middleware_set(self):
        """Behind [server] trusted_proxies the middleware rewrites
        wsgi.url_scheme; the origin must follow it, not the socket."""
        app = _req_app()
        with app.test_request_context("/", base_url="http://jen.lan", environ_overrides={"wsgi.url_scheme": "https"}):
            from flask import request

            assert passkeys.expected_origin(request) == "https://jen.lan"


class TestCeremonyState:
    def _state(self, base_url="https://jen.lan", user_id=7, now=1000.0):
        app = _req_app()
        with app.test_request_context("/", base_url=base_url):
            from flask import request

            return passkeys._new_state(b"\x01\x02\x03", request, user_id, now=now)

    def test_new_state_pins_challenge_rp_origin_user_and_expiry(self):
        s = self._state()
        assert s["challenge"] == "AQID"  # base64url, no padding
        assert s["rp_id"] == "jen.lan"
        assert s["origin"] == "https://jen.lan"
        assert s["user_id"] == 7
        assert s["exp"] == 1000.0 + passkeys.STATE_TTL_SECONDS

    def test_valid_state_has_no_problem(self):
        s = self._state()
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            assert passkeys.state_problem(s, request, 7, now=1001.0) is None

    def test_expired_state_is_refused(self):
        s = self._state()
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            problem = passkeys.state_problem(s, request, 7, now=1000.0 + passkeys.STATE_TTL_SECONDS + 1)
        assert problem and "expired" in problem

    def test_state_for_a_different_user_is_refused(self):
        s = self._state(user_id=7)
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            problem = passkeys.state_problem(s, request, 8, now=1001.0)
        assert problem and "different login" in problem

    @pytest.mark.parametrize("later_base", ["https://other.lan", "http://jen.lan", "https://jen.lan:9443"])
    def test_state_is_bound_to_rp_and_origin(self, later_base):
        """A challenge issued for one address can't be answered from
        another — origin/rp-id are pinned at issue time, not read from
        the response."""
        s = self._state(base_url="https://jen.lan")
        app = _req_app()
        with app.test_request_context("/", base_url=later_base):
            from flask import request

            problem = passkeys.state_problem(s, request, 7, now=1001.0)
        assert problem and "address changed" in problem

    @pytest.mark.parametrize("bad", [None, {}, {"exp": 99999}, "nonsense", {"challenge": ""}])
    def test_missing_or_malformed_state_is_refused(self, bad):
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            assert passkeys.state_problem(bad, request, 7) is not None

    def test_default_now_is_wall_clock(self):
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            s = passkeys._new_state(b"x", request, 1)
            assert s["exp"] > time.time()
            assert passkeys.state_problem(s, request, 1) is None


class TestStoredTransports:
    """v5.31.2 — the browser reports transports as strings and they are
    stored as a JSON list; py_webauthn's option serialiser calls
    `.value` on each entry, so they must come back as its enum. The
    first real passkey (Windows Hello → ["internal"]) broke every
    login/reauth `begin` with "could not start the passkey check"."""

    def test_json_strings_become_enum_values(self):
        from webauthn.helpers.structs import AuthenticatorTransport

        out = passkeys.transports_from_stored('["internal", "hybrid"]')
        assert out == [AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID]

    @pytest.mark.parametrize("raw", [None, "", "null", "[]", "not json", '{"a": 1}', '["made-up"]', 42])
    def test_unusable_values_become_none(self, raw):
        assert passkeys.transports_from_stored(raw) is None

    def test_unknown_entries_are_dropped_not_fatal(self):
        from webauthn.helpers.structs import AuthenticatorTransport

        assert passkeys.transports_from_stored('["usb", "teleport"]') == [AuthenticatorTransport.USB]

    def test_options_serialise_with_stored_transports(self):
        """The exact call that failed on the real box: allowCredentials
        built from a row with string transports, run through
        options_to_json."""
        import json as _json

        import webauthn
        from webauthn.helpers import options_to_json

        rows = [{"credential_id": "YWJj", "transports": '["internal"]'}]
        options = webauthn.generate_authentication_options(
            rp_id="jen.lan", allow_credentials=passkeys._descriptors(rows)
        )
        parsed = _json.loads(options_to_json(options))
        assert parsed["allowCredentials"][0]["transports"] == ["internal"]


class TestCounter:
    @pytest.mark.parametrize(
        "stored,new,regressed",
        [
            (0, 0, False),  # authenticator has no counter — allowed
            (0, 1, False),
            (5, 6, False),
            (5, 100, False),
            (5, 5, True),  # did not advance → clone
            (5, 4, True),
            (5, 0, True),
            (0, 0, False),
        ],
    )
    def test_counter_regressed(self, stored, new, regressed):
        assert passkeys.counter_regressed(stored, new) is regressed

    def test_credential_id_is_normalised_to_stored_form(self):
        # Padded standard alphabet in, padding-free url-safe out.
        assert passkeys._credential_id_of({"rawId": "AQID", "id": "AQID"}) == "AQID"
        assert passkeys._credential_id_of({"id": "AQID"}) == "AQID"
        assert passkeys._credential_id_of({}) is None
        assert passkeys._credential_id_of("not json") is None


# ── Database-backed: storage round trip with the library faked ──────────────


@pytest.fixture
def clean_passkeys(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM webauthn_credentials WHERE user_id=1")
    db.commit()
    yield
    with db.cursor() as cur:
        cur.execute("DELETE FROM webauthn_credentials WHERE user_id=1")
    db.commit()


def _fake_registration(credential_id=b"cred-1", sign_count=0, aaguid="00000000-0000-0000-0000-000000000001"):
    def fake(**kwargs):
        # The real verifier receives exactly these keyword args; a wrong
        # name here would be a wrong call in the service.
        assert set(kwargs) == {"credential", "expected_challenge", "expected_rp_id", "expected_origin"}
        return SimpleNamespace(
            credential_id=credential_id,
            credential_public_key=b"pubkey-bytes",
            sign_count=sign_count,
            aaguid=aaguid,
        )

    return fake


def _fake_authentication(new_sign_count):
    def fake(**kwargs):
        assert set(kwargs) == {
            "credential",
            "expected_challenge",
            "expected_rp_id",
            "expected_origin",
            "credential_public_key",
            "credential_current_sign_count",
        }
        assert kwargs["credential_public_key"] == b"pubkey-bytes"
        return SimpleNamespace(new_sign_count=new_sign_count, user_verified=True)

    return fake


class TestStorageRoundTrip:
    def _issue(self, base_url="https://jen.lan"):
        app = _req_app()
        with app.test_request_context("/", base_url=base_url):
            from flask import request

            options_json, state = passkeys.begin_registration(1, "admin", request)
        return json.loads(options_json), state

    def test_begin_registration_options_shape(self, clean_passkeys):
        options, state = self._issue()
        assert options["rp"] == {"name": passkeys.RP_NAME, "id": "jen.lan"}
        assert options["user"]["name"] == "admin"
        assert options["challenge"] == state["challenge"]
        assert options["authenticatorSelection"]["userVerification"] == "preferred"
        assert options["excludeCredentials"] == []

    def test_finish_registration_stores_the_credential(self, clean_passkeys, monkeypatch):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", _fake_registration())
        _options, state = self._issue()
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            response = {"id": "Y3JlZC0x", "rawId": "Y3JlZC0x", "response": {"transports": ["internal", "hybrid"]}}
            out = passkeys.finish_registration(1, response, state, request, name="  Work laptop  ")
        assert out["name"] == "Work laptop"
        rows = passkeys.list_for_user(1)
        assert len(rows) == 1
        assert rows[0]["credential_id"] == "Y3JlZC0x"  # base64url(b"cred-1")
        assert rows[0]["public_key"] == "cHVia2V5LWJ5dGVz"
        assert rows[0]["sign_count"] == 0
        assert json.loads(rows[0]["transports"]) == ["internal", "hybrid"]
        assert rows[0]["aaguid"] == "00000000-0000-0000-0000-000000000001"
        assert passkeys.count_for_user(1) == 1

    def test_finish_registration_refuses_a_stale_state(self, clean_passkeys, monkeypatch):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", _fake_registration())
        _options, state = self._issue()
        state["exp"] = time.time() - 1
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            with pytest.raises(passkeys.PasskeyError, match="expired"):
                passkeys.finish_registration(1, {"id": "x"}, state, request)
        assert passkeys.count_for_user(1) == 0

    def test_library_rejection_becomes_a_safe_message(self, clean_passkeys, monkeypatch):
        from webauthn.helpers.exceptions import InvalidRegistrationResponse

        def boom(**kwargs):
            raise InvalidRegistrationResponse("internal detail that must not reach the user")

        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", boom)
        _options, state = self._issue()
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            with pytest.raises(passkeys.PasskeyError) as exc:
                passkeys.finish_registration(1, {"id": "x"}, state, request)
        assert "internal detail" not in str(exc.value)

    def test_second_registration_excludes_the_first(self, clean_passkeys, monkeypatch):
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", _fake_registration())
        _options, state = self._issue()
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            passkeys.finish_registration(1, {"id": "Y3JlZC0x", "response": {}}, state, request)
        options, _state = self._issue()
        assert [c["id"] for c in options["excludeCredentials"]] == ["Y3JlZC0x"]

    def _enrol(self, monkeypatch, sign_count=0):
        monkeypatch.setattr(
            "jen.services.passkeys.webauthn.verify_registration_response", _fake_registration(sign_count=sign_count)
        )
        _options, state = self._issue()
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            # Transports as a real browser reports them (Windows Hello →
            # ["internal"]) — v5.31.2: begin_authentication must serialise
            # them back out, which is exactly what broke on the first real
            # passkey.
            passkeys.finish_registration(
                1, {"id": "Y3JlZC0x", "response": {"transports": ["internal", "hybrid"]}}, state, request
            )

    def _assert(self, monkeypatch, new_sign_count, response=None, base_url="https://jen.lan"):
        monkeypatch.setattr(
            "jen.services.passkeys.webauthn.verify_authentication_response", _fake_authentication(new_sign_count)
        )
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            options_json, state = passkeys.begin_authentication(1, request)
        with app.test_request_context("/", base_url=base_url):
            from flask import request

            ok = passkeys.finish_authentication(1, response or {"id": "Y3JlZC0x", "rawId": "Y3JlZC0x"}, state, request)
        return ok, json.loads(options_json)

    def test_begin_authentication_lists_the_users_credentials(self, clean_passkeys, monkeypatch):
        self._enrol(monkeypatch)
        _ok, options = self._assert(monkeypatch, new_sign_count=1)
        assert options["rpId"] == "jen.lan"
        assert [c["id"] for c in options["allowCredentials"]] == ["Y3JlZC0x"]
        assert options["allowCredentials"][0]["transports"] == ["internal", "hybrid"]

    def test_begin_authentication_without_a_passkey_raises(self, clean_passkeys):
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            with pytest.raises(passkeys.PasskeyError, match="no passkey"):
                passkeys.begin_authentication(1, request)

    def test_successful_assertion_advances_the_counter_and_last_used(self, clean_passkeys, monkeypatch):
        self._enrol(monkeypatch, sign_count=3)
        ok, _ = self._assert(monkeypatch, new_sign_count=4)
        assert ok is True
        row = passkeys.list_for_user(1)[0]
        assert row["sign_count"] == 4
        assert row["last_used"] is not None

    def test_counter_that_did_not_advance_is_rejected(self, clean_passkeys, monkeypatch):
        self._enrol(monkeypatch, sign_count=3)
        ok, _ = self._assert(monkeypatch, new_sign_count=3)
        assert ok is False
        assert passkeys.list_for_user(1)[0]["sign_count"] == 3  # untouched

    def test_unknown_credential_id_is_rejected_before_verification(self, clean_passkeys, monkeypatch):
        self._enrol(monkeypatch)

        def must_not_run(**kwargs):
            raise AssertionError("verify_authentication_response must not be called for an unknown credential")

        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_authentication_response", must_not_run)
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            _o, state = passkeys.begin_authentication(1, request)
            assert passkeys.finish_authentication(1, {"id": "b3RoZXI", "rawId": "b3RoZXI"}, state, request) is False

    def test_assertion_from_another_origin_is_rejected(self, clean_passkeys, monkeypatch):
        self._enrol(monkeypatch)
        ok, _ = self._assert(monkeypatch, new_sign_count=1, base_url="https://evil.lan")
        assert ok is False

    def test_remove_only_touches_the_users_own_row(self, clean_passkeys, monkeypatch):
        self._enrol(monkeypatch)
        cred_id = passkeys.list_for_user(1)[0]["id"]
        assert passkeys.remove(2, cred_id) is False
        assert passkeys.count_for_user(1) == 1
        assert passkeys.remove(1, cred_id) is True
        assert passkeys.count_for_user(1) == 0


class TestUserFactors:
    def test_reports_each_factor_independently(self, clean_passkeys, monkeypatch):
        from jen.models.db import jen_db
        from jen.services import mfa

        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM mfa_methods WHERE user_id=1 AND name='_probe_factors'")
            db.commit()
        assert mfa.user_factors(1)["passkey"] is False
        monkeypatch.setattr("jen.services.passkeys.webauthn.verify_registration_response", _fake_registration())
        app = _req_app()
        with app.test_request_context("/", base_url="https://jen.lan"):
            from flask import request

            _o, state = passkeys.begin_registration(1, "admin", request)
            passkeys.finish_registration(1, {"id": "Y3JlZC0x", "response": {}}, state, request)
        factors = mfa.user_factors(1)
        assert factors["passkey"] is True
        assert mfa.user_has_mfa(1) is True
        try:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute(
                        "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) "
                        "VALUES (1, 'totp', 'x', '_probe_factors', 1)"
                    )
                db.commit()
            assert mfa.user_factors(1) == {"totp": True, "passkey": True}
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM mfa_methods WHERE user_id=1 AND name='_probe_factors'")
                db.commit()
