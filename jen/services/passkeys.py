"""
jen/services/passkeys.py
─────────────────────────
v5.31.0 (Q31) — passkeys (WebAuthn / FIDO2) as a SECOND factor, beside
TOTP, behind the password. Not passwordless login.

What lives here is everything that isn't a Flask route: building the
browser's `navigator.credentials.create()` / `.get()` options, holding
the one-shot challenge between the two halves of each ceremony, and
verifying the browser's answer through py_webauthn before touching
`webauthn_credentials`.

Trust boundary
──────────────
* The relying-party id and origin come from the request Jen is
  serving (`rp_id()` / `expected_origin()`), are pinned into the
  ceremony state when the challenge is issued, and are verified
  against on the response — the browser's own `clientDataJSON.origin`
  is checked by py_webauthn against what WE expected, never trusted on
  its own. Behind a reverse proxy the `Host` header the proxy forwards
  is what users typed; `[server] trusted_proxies` (v5.17.0) supplies
  the scheme.
* A challenge is single-use and expires after `STATE_TTL_SECONDS`;
  the route pops it from the session BEFORE verification so a failed
  attempt can't be replayed.
* Only public keys are stored (base64url in the TEXT columns the
  v4.2.0 baseline created); nothing here needs encryption at rest.
* The signature counter is enforced: an assertion whose counter did
  not move forward when either side's counter is non-zero is a cloned
  authenticator and is rejected (py_webauthn raises; we also check).
"""

import json
import logging
import time
from datetime import datetime, timezone

import webauthn
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

import jen.models.db as __db

logger = logging.getLogger(__name__)

RP_NAME = "Jen DHCP"
STATE_TTL_SECONDS = 300
MAX_NAME = 100
DEFAULT_NAME = "Passkey"


class PasskeyError(Exception):
    """A user-facing, already-safe message (no library internals)."""


# ── Relying party identity ───────────────────────────────────────────────────


def rp_id_from_host(host: str) -> str:
    """The WebAuthn RP id for a Host header value: the hostname with any
    port removed and IPv6 brackets stripped. `jen.lan:8443` → `jen.lan`;
    `[::1]:5000` → `::1`; `10.0.0.5` → `10.0.0.5`."""
    host = (host or "").strip()
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end > 0 else host.strip("[]")
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def rp_id(request) -> str:
    return rp_id_from_host(request.host)


def expected_origin(request) -> str:
    """`scheme://host[:port]` exactly as the browser will report it in
    clientDataJSON. `request.host_url` already reflects the proxy-
    supplied scheme when trusted_proxies is configured."""
    return request.host_url.rstrip("/")


# ── Ceremony state (lives in the Flask session between begin/finish) ─────────


def _new_state(challenge: bytes, request, user_id: int, now: float | None = None) -> dict:
    return {
        "challenge": bytes_to_base64url(challenge),
        "rp_id": rp_id(request),
        "origin": expected_origin(request),
        "user_id": int(user_id),
        "exp": (now if now is not None else time.time()) + STATE_TTL_SECONDS,
    }


def state_problem(state, request, user_id: int, now: float | None = None) -> str | None:
    """Why a stored ceremony state can't be used for this request, or
    None when it can. Pure: `now` is injectable."""
    if not isinstance(state, dict) or not state.get("challenge"):
        return "no passkey challenge in progress — start again"
    if (now if now is not None else time.time()) > float(state.get("exp", 0)):
        return "the passkey challenge expired — start again"
    if int(state.get("user_id", -1)) != int(user_id):
        return "the passkey challenge belongs to a different login — start again"
    if state.get("rp_id") != rp_id(request) or state.get("origin") != expected_origin(request):
        return "the page address changed during the passkey challenge — start again"
    return None


# ── Storage ──────────────────────────────────────────────────────────────────


def list_for_user(user_id: int) -> list[dict]:
    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute(
            "SELECT id, credential_id, public_key, sign_count, name, created_at, last_used, transports, aaguid "
            "FROM webauthn_credentials WHERE user_id=%s ORDER BY created_at, id",
            (user_id,),
        )
        return list(cur.fetchall())


def count_for_user(user_id: int) -> int:
    with __db.jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS c FROM webauthn_credentials WHERE user_id=%s", (user_id,))
        return int(cur.fetchone()["c"])


def remove(user_id: int, cred_id: int) -> bool:
    """Delete one of the user's own passkeys. True when a row went."""
    with __db.jen_db() as db:
        with db.cursor() as cur:
            cur.execute("DELETE FROM webauthn_credentials WHERE id=%s AND user_id=%s", (cred_id, user_id))
            gone = cur.rowcount > 0
        db.commit()
    return gone


def _descriptors(rows: list[dict]) -> list[PublicKeyCredentialDescriptor]:
    out = []
    for r in rows:
        try:
            transports = json.loads(r.get("transports") or "null") or None
        except (TypeError, ValueError):
            transports = None
        out.append(PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"]), transports=transports))
    return out


# ── Registration ─────────────────────────────────────────────────────────────


def begin_registration(user_id: int, username: str, request) -> tuple[str, dict]:
    """(options JSON for `navigator.credentials.create()`, state to keep
    in the session). Existing passkeys are excluded so the same
    authenticator can't be enrolled twice."""
    options = webauthn.generate_registration_options(
        rp_id=rp_id(request),
        rp_name=RP_NAME,
        user_name=username,
        user_id=str(int(user_id)).encode(),
        user_display_name=username,
        exclude_credentials=_descriptors(list_for_user(user_id)),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        timeout=STATE_TTL_SECONDS * 1000,
    )
    return options_to_json(options), _new_state(options.challenge, request, user_id)


def finish_registration(user_id: int, response, state: dict, request, name: str = "") -> dict:
    """Verify the browser's `create()` result against `state` and store
    the credential. Returns {id, name}. Raises PasskeyError with a
    message safe to flash."""
    problem = state_problem(state, request, user_id)
    if problem:
        raise PasskeyError(problem)
    name = (name or "").strip()[:MAX_NAME] or DEFAULT_NAME
    try:
        verified = webauthn.verify_registration_response(
            credential=response,
            expected_challenge=base64url_to_bytes(state["challenge"]),
            expected_rp_id=state["rp_id"],
            expected_origin=state["origin"],
        )
    except WebAuthnException as e:
        logger.warning(f"passkey registration rejected for user {user_id}: {e}")
        raise PasskeyError("the passkey could not be verified — try again") from None
    except Exception as e:
        logger.warning(f"passkey registration failed for user {user_id}: {e}")
        raise PasskeyError("the browser sent an unreadable passkey response") from None
    transports = None
    try:
        raw = response if isinstance(response, dict) else json.loads(response)
        t = (raw.get("response") or {}).get("transports")
        if isinstance(t, list) and all(isinstance(x, str) for x in t):
            transports = json.dumps(t[:8])[:100]
    except Exception:
        transports = None
    aaguid = (str(verified.aaguid) if verified.aaguid else "")[:36] or None
    with __db.jen_db() as db:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, name, transports, aaguid) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    user_id,
                    bytes_to_base64url(verified.credential_id),
                    bytes_to_base64url(verified.credential_public_key),
                    int(verified.sign_count),
                    name,
                    transports,
                    aaguid,
                ),
            )
            new_id = cur.lastrowid
        db.commit()
    return {"id": new_id, "name": name}


# ── Authentication ───────────────────────────────────────────────────────────


def begin_authentication(user_id: int, request) -> tuple[str, dict]:
    """(options JSON for `navigator.credentials.get()`, state). Raises
    PasskeyError when the user has no passkey."""
    rows = list_for_user(user_id)
    if not rows:
        raise PasskeyError("no passkey is enrolled for this account")
    options = webauthn.generate_authentication_options(
        rp_id=rp_id(request),
        allow_credentials=_descriptors(rows),
        user_verification=UserVerificationRequirement.PREFERRED,
        timeout=STATE_TTL_SECONDS * 1000,
    )
    return options_to_json(options), _new_state(options.challenge, request, user_id)


def _credential_id_of(response) -> str | None:
    try:
        raw = response if isinstance(response, dict) else json.loads(response)
        cid = raw.get("rawId") or raw.get("id")
        # Normalise whatever padding/alphabet the browser used to our stored form.
        return bytes_to_base64url(base64url_to_bytes(cid)) if cid else None
    except Exception:
        return None


def counter_regressed(stored: int, new: int) -> bool:
    """True when the authenticator's signature counter did not advance
    although counters are in use (either side non-zero). A counter that
    stays at 0 on both sides means the authenticator doesn't implement
    one, which the spec allows."""
    stored, new = int(stored or 0), int(new or 0)
    if stored == 0 and new == 0:
        return False
    return new <= stored


def finish_authentication(user_id: int, response, state: dict, request) -> bool:
    """Verify the browser's `get()` result. True on success (and the
    row's sign_count/last_used are updated); False on any failure —
    the caller counts it as a failed MFA attempt."""
    if state_problem(state, request, user_id):
        return False
    cid = _credential_id_of(response)
    if not cid:
        return False
    row = next((r for r in list_for_user(user_id) if r["credential_id"] == cid), None)
    if row is None:
        logger.warning(f"passkey assertion for user {user_id} named an unknown credential")
        return False
    try:
        verified = webauthn.verify_authentication_response(
            credential=response,
            expected_challenge=base64url_to_bytes(state["challenge"]),
            expected_rp_id=state["rp_id"],
            expected_origin=state["origin"],
            credential_public_key=base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=int(row.get("sign_count") or 0),
        )
    except WebAuthnException as e:
        logger.warning(f"passkey assertion rejected for user {user_id}: {e}")
        return False
    except Exception as e:
        logger.warning(f"passkey assertion failed for user {user_id}: {e}")
        return False
    if counter_regressed(row.get("sign_count") or 0, verified.new_sign_count):
        logger.warning(f"passkey counter did not advance for user {user_id} credential {row['id']} — possible clone")
        return False
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "UPDATE webauthn_credentials SET sign_count=%s, last_used=%s WHERE id=%s",
                    (int(verified.new_sign_count), datetime.now(timezone.utc), row["id"]),
                )
            db.commit()
    except Exception as e:
        logger.error(f"passkey counter update failed for credential {row['id']}: {e}")
    return True
