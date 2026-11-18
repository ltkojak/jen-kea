"""
jen/routes/settings/security.py
─────────────────────────────
Session timeout, login rate limiting, SSL certificate upload.
"""

import logging
import os

from flask import flash, redirect, request, url_for
from flask_login import current_user, login_required

import jen.config as __config
import jen.models.db as __db
import jen.models.user as __user
import jen.services.auth as __auth
import jen.services.oidc as __oidc
import jen.services.runtime as __runtime
import jen.services.session_timeout as __session_timeout
from jen import extensions
from jen.routes.settings import bp
from jen.services.access import admin_required as _admin_required
from jen.services.access import recent_auth_required as _recent_auth_required
from jen.services.access import superadmin_required as _superadmin_required
from jen.services.forms import flash_field
from jen.services.text import is_whole

logger = logging.getLogger(__name__)


def _session_looser(enabled: str, minutes: int) -> bool:
    """Would storing (`enabled`, `minutes`) make the idle timeout LESS strict than the one applied now? Off and 0 (never) are the least strict, equal to each other; otherwise fewer minutes is stricter."""

    def rank(on: bool, m: int) -> int:
        return 0 if not on or m == 0 else __session_timeout.MAX_MINUTES + 1 - m  # 1440 min -> 1, 1 min -> 1440

    now_on = __user.get_global_setting("session_timeout_enabled", "true") != "false"
    return rank(enabled == "true", minutes) < rank(now_on, __session_timeout.global_minutes())


#: (Q227, AM3) the three sentences of the lockout controls, named so a test and the page read the same words
PERMANENT_IS_A_SUPERADMINS = "Only a superadmin can set a lockout that lasts until it is cleared (0 minutes)."
CLEARED_SENTENCE = "Cleared {attempts} failed login attempt(s) and ended {lockouts} permanent lockout(s)."
OIDC_ISSUER_CHANGED = "The issuer changed - enter the client secret again."
OIDC_CLIENT_CHANGED = "The client ID changed - enter the client secret again."
#: (Q229) the refusal of an issuer that is not a plain address
#: (Q230, AP8) the refusal of a typed redirect URI
OIDC_REDIRECT_SHAPE = "The redirect URI must be an http:// or https:// URL with a host and nothing after its path: no query and no fragment."
OIDC_ISSUER_SHAPE = (
    "The issuer must be an https:// URL with a host and nothing after its path: no query and no fragment "
    "(http:// is only allowed for a local 127.0.0.1/localhost test IdP)."
)
OIDC_SAVED = "Single sign-on settings saved. A change to the issuer, the client ID or the client secret takes effect when Jen restarts."


def _rate_limit_looser(mode: str, max_attempts: int, lockout_minutes: int) -> bool:
    """Would storing these make login rate limiting LESS strict than it is now? `off` (or 0 attempts) is the least strict; more attempts allowed, or a shorter lockout (0 is until cleared, the
    longest), is looser. (Q225, AK2) The mode is part of the strictness: `both` counts the address's attempts AND the account's and locks on the larger (`is_locked_out`), so it is at least as
    strict as either alone - leaving it drops a bucket, and `ip` <-> `username` drops one and adds one, which is not a tightening. An admin may move TO `both` from either and may not leave it
    or trade one bucket for the other. The three measures are judged together and a change is looser when any one of them is (AK24: an admin cannot trade attempts for lockout length in
    either direction; that is the rule's conservative side, and a superadmin makes such a trade)."""
    now = __auth.get_rate_limit_settings()
    now_off = now["mode"] == "off" or now["max_attempts"] == 0
    new_off = mode == "off" or max_attempts == 0
    if new_off:
        return not now_off
    if now_off:
        return False

    def longer(a: int, b: int) -> bool:  # is lockout `a` longer than `b`, with 0 the longest?
        return (a == 0 and b != 0) or (a != 0 and b != 0 and a > b)

    mode_looser = mode != now["mode"] and mode != "both"
    return max_attempts > now["max_attempts"] or longer(now["lockout_minutes"], lockout_minutes) or mode_looser


@bp.route("/settings/save-session", methods=["POST"])
@login_required
@_admin_required
def save_session_settings():
    timeout = request.form.get("timeout_minutes", "60").strip()
    enabled = request.form.get("timeout_enabled", "true").strip()
    if enabled not in ("true", "false"):
        enabled = "true"

    minutes = __session_timeout.parse_minutes(timeout)
    if minutes is None:
        flash_field("timeout_minutes", "Session timeout must be between 0 and 1440 minutes (0 = never).")
        return redirect(url_for("settings.settings_security"))
    timeout = str(minutes)  # the canonical text: `00005` is stored as 5, and what is stored is what the reader applies
    # (Q224, AJ14) an admin makes the policy STRICTER only, as for the MFA mode (Q171): the idle timeout is one of three global authentication knobs on this page. Off, or 0 (never), is the least
    # strict; among timeouts a shorter one is stricter. A superadmin may loosen it
    if current_user.role != "superadmin" and _session_looser(enabled, minutes):
        flash("Only a superadmin can make the session timeout less strict.", "error")
        return redirect(url_for("settings.settings_security"))

    # (Q226, the review's P2 #5) one transaction, and "saved" only when it is: two commits left half a policy applied under a success message
    if not __user.set_global_settings({"session_timeout_minutes": timeout, "session_timeout_enabled": enabled}):
        flash("The session timeout could not be saved. Check server logs for details.", "error")
        return redirect(url_for("settings.settings_security"))

    if enabled == "false":
        flash("Session timeout disabled — sessions will not expire.", "success")
    elif int(timeout) == 0:
        flash("Session timeout enabled — sessions will never expire.", "success")
    else:
        flash(f"Session timeout set to {timeout} minutes.", "success")
    __user.audit("SAVE_SETTINGS", "session", f"enabled={enabled} timeout={timeout}min")
    return redirect(url_for("settings.settings_security"))


@bp.route("/settings/save-rate-limit", methods=["POST"])
@login_required
@_admin_required
def save_rate_limit():
    max_attempts = request.form.get("max_attempts", "10").strip()
    lockout_minutes = request.form.get("lockout_minutes", "15").strip()
    mode = request.form.get("mode", "both").strip()

    # (Q224, AJ18) bounded, as `save_config_revision_keep` bounds its own: the minutes reach a `DATE_SUB(NOW(), INTERVAL %s MINUTE)` and a count beyond any login's reach is a typo, not a policy
    if not is_whole(max_attempts) or not 0 <= int(max_attempts) <= __auth.MAX_ATTEMPTS_BOUND:
        flash_field(
            "max_attempts", f"Max attempts must be a whole number from 0 (unlimited) to {__auth.MAX_ATTEMPTS_BOUND}."
        )
        return redirect(url_for("settings.settings_security"))
    if not is_whole(lockout_minutes) or not 0 <= int(lockout_minutes) <= __auth.MAX_LOCKOUT_MINUTES:
        flash_field(
            "lockout_minutes",
            f"Lockout duration must be a whole number of minutes from 0 (until cleared) to {__auth.MAX_LOCKOUT_MINUTES} (a week).",
        )
        return redirect(url_for("settings.settings_security"))
    if mode not in __auth.RATE_LIMIT_MODES:
        flash("Invalid lockout mode.", "error")
        return redirect(url_for("settings.settings_security"))
    max_attempts, lockout_minutes = (
        str(int(max_attempts)),
        str(int(lockout_minutes)),
    )  # the canonical text, as the session route stores its minutes
    # (Q224, AJ14) an admin makes the policy STRICTER only (Q171's rule for the MFA mode): rate limiting cannot be turned off, the attempts allowed cannot grow (0 is unlimited) and the lockout
    # cannot shorten (0 is until cleared). A superadmin may loosen it
    if current_user.role != "superadmin" and _rate_limit_looser(mode, int(max_attempts), int(lockout_minutes)):
        flash("Only a superadmin can make login rate limiting less strict.", "error")
        return redirect(url_for("settings.settings_security"))
    # (Q227, AM3) and only a superadmin makes a lockout permanent. 0 is the strictest value, so the ratchet above lets an admin move TO it and never away: an admin could set it, fail a
    # superadmin's name at /login and leave that account locked until someone cleared it. An admin may keep a 0 a superadmin set
    if (
        current_user.role != "superadmin"
        and int(lockout_minutes) == 0
        and __auth.get_rate_limit_settings()["lockout_minutes"] != 0
    ):
        flash_field("lockout_minutes", PERMANENT_IS_A_SUPERADMINS)
        return redirect(url_for("settings.settings_security"))

    if not __user.set_global_settings(
        {"rl_max_attempts": max_attempts, "rl_lockout_minutes": lockout_minutes, "rl_mode": mode}
    ):  # (Q226, the review's P2 #5) one transaction, and "saved" only when it is
        flash("Rate limiting settings could not be saved. Check server logs for details.", "error")
        return redirect(url_for("settings.settings_security"))
    flash("Rate limiting settings saved.", "success")
    __user.audit("SAVE_SETTINGS", "rate_limit", f"max={max_attempts} lockout={lockout_minutes}min mode={mode}")
    return redirect(url_for("settings.settings_security"))


@bp.route("/settings/clear-lockouts", methods=["POST"])
@login_required
@_admin_required
def clear_lockouts():
    try:
        with __db.jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM login_attempts")
                attempts = max(cur.rowcount, 0)
                # (Q226) the permanent lockouts: this button is the one way they end
                cur.execute("DELETE FROM login_lockouts")
                lockouts = max(cur.rowcount, 0)
            db.commit()
        # (Q226, AL22 and the review's note) an ADMIN's act, kept so: it resets counters and ends lockouts (a locked-out colleague is the common case), changes no stored policy, and is
        # audited; the ratchet (RBAC-003) is about policy. (Q227, AM3) The flash and the audit row say what it did: it said "All login attempt records cleared." and named no lockout
        flash(CLEARED_SENTENCE.format(attempts=attempts, lockouts=lockouts), "success")
        __user.audit(
            "CLEAR_LOCKOUTS", "settings", f"login attempts cleared={attempts} permanent lockouts ended={lockouts}"
        )
    except Exception as e:
        logger.error(f"Error clearing lockouts: {e}")
        flash("Error clearing lockouts. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_security"))


def validate_cert_material(cert_data: str, key_data: str, ca_data: str | None) -> str | None:
    """
    v5.9.1 — return None if cert + key (+ CA bundle, when given) load as a
    real TLS server chain, else a short reason. The old check was textual
    ("contains BEGIN CERTIFICATE"), so a valid certificate paired with the
    wrong private key sailed through, got written to the config dir's ssl/, and
    gunicorn then refused to start — a self-inflicted outage. Loading the
    material with the same API gunicorn uses catches malformed PEMs and a
    mismatched key before anything on disk is touched. Pure — tested in
    tests/test_ssl_material.py.
    """
    import ssl
    import tempfile

    # (Q238, AW12; Q239, AX24) What OpenSSL loads and serves must be what Jen counted and judged. OpenSSL reads a certificate under three PEM labels
    # (`CERTIFICATE`, `X509 CERTIFICATE`, `TRUSTED CERTIFICATE`) and Jen's checks read the first. Q238 refused the third by name and left the second: an
    # expired CA spelled `X509 CERTIFICATE` was loaded, served and judged by nothing. The rule is the label, not a list of spellings: in the certificate
    # and CA fields, a block whose label names a certificate and is not exactly `CERTIFICATE` is refused
    label = _other_certificate_label(cert_data + "\n" + (ca_data or ""))
    if label and "REQUEST" in label.upper():
        return f"the upload carries a block labeled {label}: that is a certificate REQUEST, which a CA answers with a certificate. Upload the certificate the CA issued for it"
    if label:
        return f"the upload carries a block labeled {label}; Jen reads a certificate only as a plain PEM block (BEGIN CERTIFICATE): convert it with openssl x509 -in <file> -out <file>"
    if "BEGIN CERTIFICATE" not in cert_data:
        return "the certificate file is not a PEM certificate"
    if "PRIVATE KEY" not in key_data:
        return "the private key file is not a PEM private key"
    if ca_data and "BEGIN CERTIFICATE" not in ca_data:
        return "the CA bundle is not a PEM certificate bundle"
    # (Q237, AV31) both bounds come before anything is written, loaded or parsed: the count used to be taken after every certificate pasted had been parsed and
    # compared with every one before it, so one certificate pasted 200,000 times held the one worker past its timeout
    size = len(cert_data) + len(key_data) + len(ca_data or "")
    if size > _MOST_CHARACTERS:
        return f"the upload is {size:,} characters and a certificate, its key and the chain above it are a few thousand: upload those, not a bundle of CAs"
    count = len(_distinct_pems(cert_data + "\n" + (ca_data or "")))
    if count > _MOST_CERTIFICATES:
        return f"the upload carries {count} certificates and a server presents at most {_MOST_CERTIFICATES}: upload the certificate and the chain above it, not a bundle of CAs"
    with tempfile.TemporaryDirectory() as tmp:
        chain = os.path.join(tmp, "chain.pem")
        key = os.path.join(tmp, "key.pem")
        with open(chain, "w") as f:
            f.write(cert_data)
            if ca_data:
                f.write("\n" if not cert_data.endswith("\n") else "")
                f.write(ca_data)
        with open(key, "w") as f:
            f.write(key_data)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(chain, key)
        except ssl.SSLError as e:
            msg = (e.strerror or str(e)).lower()
            if "mismatch" in msg:
                return "the private key does not match the certificate"
            return f"the certificate/key could not be loaded ({e.strerror or e})"
        except (OSError, ValueError) as e:
            return f"the certificate/key could not be loaded ({e})"
    return cert_refusal(cert_data) or chain_refusal(ctx, cert_data, ca_data)


# OpenSSL's answers that are about a certificate's dates ("not yet valid", "has expired"): the only ones `_out_of_date` has something to add to
_ABOUT_A_DATE = frozenset({9, 10})
# (Q236, AU6) a server presents a leaf and the few CAs above it; the walk verifies a signature for every pair and runs a handshake for every top
_MOST_CERTIFICATES = 20
# (Q237, AV31) twenty certificates and a key are well under a tenth of this
_MOST_CHARACTERS = 1_000_000


def _other_certificate_label(text: str) -> str:
    """The first PEM label of `text` that names a certificate and is not exactly `CERTIFICATE`, or "". One forward scan over the BEGIN lines."""
    at = text.find("-----BEGIN ")
    while at != -1:
        stop = text.find("-----", at + 11)
        if stop == -1:
            return ""
        label = text[at + 11 : stop]
        # (Q240, AY5) no bound on its length: `and len(label) <= 64` was here, and a 65-character label was skipped and served
        if "CERTIFICATE" in label.upper() and label != "CERTIFICATE" and "\n" not in label:
            return label[:80]
        at = text.find("-----BEGIN ", stop)
    return ""


def _distinct_pems(text: str) -> list:
    """Every PEM certificate of `text`, each once, in the order pasted. Compared as text with the white space taken out, in one pass, so the number of DISTINCT
    certificates is known before any of them is parsed."""
    # (Q238, AW1) two `find`s that only move forward. This was a lazy pattern, and a lazy pattern starts again from every BEGIN that has no END and reads to
    # the end of the text each time: 35,000 unterminated markers, inside the character bound, held the one worker past its timeout
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    seen: dict = {}
    at = text.find(begin)
    while at != -1:
        stop = text.find(end, at + len(begin))
        if stop == -1:
            break  # no END after this BEGIN, so none after any later one
        block = text[at : stop + len(end)]
        seen.setdefault("".join(block.split()), block)
        at = text.find(begin, stop + len(end))
    return list(seen.values())


def _load_box_store(client) -> None:
    """The CA certificates this box itself trusts (its `ca-certificates`), into `client`. A seam: the tests give it a store of their own."""
    client.load_default_certs()


def _handshake(server_ctx, client):
    """A TLS handshake in memory between the server context that loaded the upload and `client`. None when both sides complete, else `(sentence, verify_code)`;
    `verify_code` is None for a failure that is not the chain's verification."""
    import ssl

    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    sides = (
        (client.wrap_bio(c_in, c_out), c_out, s_in),
        (server_ctx.wrap_bio(s_in, s_out, server_side=True), s_out, c_in),
    )
    for _ in range(20):
        done = 0
        for side, out, peer_in in sides:
            try:
                side.do_handshake()
                done += 1
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except ssl.SSLCertVerificationError as e:
                return f"a client that verifies the chain refuses it ({e.verify_message})", e.verify_code
            except ssl.SSLError as e:
                return f"a TLS handshake with this certificate and key fails ({e.strerror or e})", None
            peer_in.write(out.read())
        if done == 2:
            return None
    return "a TLS handshake with this certificate and key did not complete", None


def _held_by_box(client) -> list:
    """The CA certificates `client`'s store has loaded, parsed. After a handshake that is every certificate of the box's store the verifier looked at: a store kept
    in one file is loaded whole, and one kept as a directory loads each certificate it is asked for by name."""
    import warnings

    from cryptography import x509

    held = []
    with warnings.catch_warnings():
        warnings.simplefilter(
            "ignore"
        )  # an old root with a serial number a newer `cryptography` warns about is still a root this box trusts
        for der in client.get_ca_certs(binary_form=True):
            try:
                held.append(x509.load_der_x509_certificate(der))
            except ValueError:
                continue  # a certificate of the box's store that cannot be parsed signed nothing Jen can check
    return held


def _box_refusal(certs, top: int, held: list):
    """(Q236, AU2; Q237, AV2) The one pair the upload's own top cannot be asked about: `certs[top]` and its issuer, when that issuer is not in the upload. A client that
    trusts the top accepted the chain; this says what the BOX'S store adds, as `(sentence, None)` or None. The box's store answers ONE question: whose key signed the
    top. None when the top signed itself (the upload carries its own root, and the operator's root is not the box's to overrule), when the box trusts no certificate
    of the issuer's name (a private CA: the root is the client's) and when one of that name signed the top. When the box trusts some of that name and none of them
    signed the top, that is the refusal - a wrong intermediate under a root this box holds, whatever key identifiers it carries.
    Nothing else about the box's own copy is read. Q236 returned the box verifier's refusal here unless it was about a date, and every way the box's copy can differ
    from the one a client holds - its serial under an issuer-and-serial key identifier, its path length, its dates - refused an honest chain. Those are properties
    of the BOX'S copy; the clients' copy is the clients'."""
    cert = certs[top]
    if _signed_by(cert, cert):
        return None
    named = [c for c in held if c.subject == cert.issuer]
    if not named:
        return None
    signers = [c for c in named if _signed_by(cert, c)]
    if not signers:
        return (
            f'this box trusts a certificate named "{cert.issuer.rfc4514_string()}" and it did not sign "{cert.subject.rfc4514_string()}", which names it as issuer. '
            "If that CA was issued again with a new key, add its new certificate to the upload or to this box's CA store (update-ca-certificates)",
            None,
        )
    # (Q238, AW40) and the key's NAME: the top may say which key signed it (an authority key identifier), and a client looks its issuer up by that before it
    # checks any signature. Dropping the box verifier's refusal (Q237) dropped this with it. It is the one such property that can be decided here: an
    # identifier is of a KEY, and every copy of the issuer that verifies the top holds the same key.
    wanted = _authority_key_id(cert)
    if wanted is None or any(_carries_key_id(c, wanted) for c in signers):
        return None
    return (
        f'"{cert.subject.rfc4514_string()}" names the key that signed it by an identifier, and the certificate this box trusts as '
        f'"{cert.issuer.rfc4514_string()}" does not carry that identifier, so a client that holds that CA does not find the issuer. '
        "If the CA's own certificate carries it, add that certificate to the upload",
        None,
    )


def _authority_key_id(cert):
    """The key identifier `cert` names its issuer by, or None when it names none (no extension, one that cannot be read, or the issuer-and-serial form alone)."""
    from cryptography import x509

    try:
        return cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    except (x509.ExtensionNotFound, ValueError):
        return None


def _carries_key_id(issuer, wanted: bytes) -> bool:
    """Does `issuer` answer to the key identifier `wanted`? Yes when it states none (a client then does not compare), when it states that one, and when
    `wanted` is the identifier RFC 5280 derives from its key: a renewal of a CA under the same key may state its identifier another way than the copy a
    client holds, and the derived one is what an issuing CA writes unless it was told otherwise."""
    from cryptography import x509

    try:
        stated = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except (x509.ExtensionNotFound, ValueError):
        return True
    return wanted in (stated, x509.SubjectKeyIdentifier.from_public_key(issuer.public_key()).digest)


def _not_a_ca(certs, top: int):
    """(Q237, AV1) What the verifier does not say about the certificate it was told to trust: whether it is a CA by the rule a client applies to every CA BELOW its own
    anchor. OpenSSL counts an anchor as a CA when it has no basic constraints and its key usage allows signing certificates; one step down the same certificate is
    "invalid CA certificate". The upload's top is Jen's anchor and, unless it signed itself, an intermediate for every client: `(sentence, None)` when it signs a
    certificate of the upload and carries no basic constraints with CA set, else None. A top that is the server's own certificate signs nothing, and one that signed
    itself is the clients' anchor too."""
    from cryptography import x509

    cert = certs[top]
    if top == 0 or _signed_by(cert, cert):
        return None
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    except ValueError:
        # (Q238, AW41) the verifier read this certificate and completed the handshake; this library cannot parse one of its extensions (a BOOLEAN in BER
        # is one). That is no ground for a refusal no client makes
        return None
    if is_ca:
        return None
    return (
        f'"{cert.subject.rfc4514_string()}" signed a certificate of the upload and does not say it is a CA (it carries no basic constraints with CA set), '
        "so a client that holds the CA above it refuses the chain",
        None,
    )


def _signed_by(cert, issuer) -> bool:
    """True when `issuer`'s name is `cert`'s issuer AND `issuer`'s key made `cert`'s signature."""
    try:
        cert.verify_directly_issued_by(issuer)
    except Exception:
        return False
    return True


def _chain_tops(certs) -> list:
    return _chain_walk(certs)[0]


def _chain_walk(certs) -> tuple:
    """`(tops, on_a_path)`. The indexes of the certificates at the top of every issuer path the upload holds, walked up from the first one. One step up from a certificate is every
    uploaded certificate that carries its issuer's name and whose key signed it - or, when none of that name signed it, every one of that name, so the verifier is
    the one that says the signature is wrong. A certificate that signed itself is a top and nothing is above it. (Q235, AT2: the walk used to follow the NAME alone
    and keep the last match, so of two roots with one name - a root and its re-issue - the order of the paste chose which one judged the chain.) `on_a_path` is every
    index the walk visited: a certificate of the upload that is on no path from the first one is judged by nobody and named by no refusal (Q237)."""
    tops, seen, stack = [], set(), [0]
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        above = []
        if not _signed_by(certs[i], certs[i]):
            named = [j for j, c in enumerate(certs) if j != i and c.subject == certs[i].issuer]
            above = [j for j in named if _signed_by(certs[i], certs[j])] or named
        if above:
            stack.extend(above)
        else:
            tops.append(i)
    return sorted(tops), sorted(seen)


def _out_of_date(certs, now=None) -> str:
    """Which uploaded certificates are outside their dates, as a clause for a refusal that is about a date: the verifier says "certificate has expired" and not which."""
    from datetime import datetime, timezone

    now = now or datetime.now(timezone.utc)
    said = []
    for cert in certs:
        if now > cert.not_valid_after_utc:
            said.append(f'"{cert.subject.rfc4514_string()}" expired on {cert.not_valid_after_utc:%Y-%m-%d}')
        elif now < cert.not_valid_before_utc:
            said.append(f'"{cert.subject.rfc4514_string()}" is not valid until {cert.not_valid_before_utc:%Y-%m-%d}')
    return ("; in the upload: " + ", ".join(said)) if said else ""


def chain_refusal(server_ctx, cert_data: str, ca_data: str | None) -> str | None:
    """(Q234, AQ11, AQ18) What a verifying client refuses the PRESENTED CHAIN for, or None. `cert_refusal` reads one certificate and a `fullchain.pem` holds several: a valid
    leaf under an expired intermediate was accepted, installed and followed by a restart into an HTTPS every client refuses. This asks the verifier clients use: a TLS
    handshake in memory between the server context that just loaded the material and a client that trusts ONE certificate: the top of the issuer path the upload itself holds,
    walked from the first certificate by issuer name (the first itself when nothing uploaded issued it). So an expired or not-yet-valid certificate anywhere on that path, a
    critical extension no client handles, a CA that may not sign and a broken signature are each refused in OpenSSL's own words. "Issuer not found" is not a refusal: the root
    is the client's, not the upload's.
    (Q213, AS1) It used to trust EVERY certificate after the first, so the verifier stopped at the first one it could chain to: a leaf, its issuer and an expired certificate
    above them was accepted. One anchor, at the top, makes the verifier walk the whole path. A certificate of the upload that is not on the path is not judged.
    (Q235, AT1, AT2) Two questions, both asked of the verifier. FIRST with the CA certificates this box itself trusts and nothing else: a `fullchain.pem` from a public
    CA ends at an intermediate whose issuer is not in the file, and trusting that intermediate judged its dates and never its signature, because a verifier does not
    check the signature of the certificate it was told to trust. With the box's store the root is held, so the intermediate is judged like the rest. THEN one handshake for each top of the paths the upload holds (`_chain_tops`), trusting that one
    certificate: the chain is accepted when a client that holds ANY of them accepts it, so a root and its expired earlier copy in one bundle are judged by the one
    that verifies, whatever the order of the paste. What stays outside: the signature of a top certificate whose issuer neither the upload nor this box holds.
    (Q236, AU1, AU2) The box's answer is final only when it ACCEPTS. A refusal there is evidence about the box - its store may hold a superseded copy of a renewed
    root - so the upload's own tops are asked next, and a client that trusts one must COMPLETE the handshake: "the issuer is not held" from it used to be an acceptance,
    and it is what OpenSSL answers for a key identifier that does not match, before it checks any signature. What the box adds to an accepting top is `_box_refusal`.
    (Q237, AV1, AV2) What the box adds is ONE answer: whose key signed the top. Its verifier's refusal is no longer read at all - it is about the box's own copy of the
    issuer (a serial, a path length, a date), and the clients' copy is the clients'. And the top Jen trusts is asked what the verifier does not ask of an anchor: is
    it a CA by the rule every client applies one step below its own (`_not_a_ca`). Outside, by decision: a property of the box's own copy of an issuer, and a
    certificate in the box's store that OpenSSL does not count as a CA, which is no certificate the box trusts (AV3)."""
    import ssl

    from cryptography import x509

    pems = _distinct_pems(cert_data + "\n" + (ca_data or ""))
    if not pems:
        return "the certificate file is not a PEM certificate"
    if len(pems) > _MOST_CERTIFICATES:
        return f"the upload carries {len(pems)} certificates and a server presents at most {_MOST_CERTIFICATES}: upload the certificate and the chain above it, not a bundle of CAs"
    try:
        certs = [x509.load_pem_x509_certificate(pem.encode("utf-8")) for pem in pems]
    except ValueError as e:
        return f"a certificate of the chain could not be read ({e})"
    # one certificate in two encodings is one certificate (at most twenty are compared)
    kept = [i for i, c in enumerate(certs) if c not in certs[:i]]
    pems, certs = [pems[i] for i in kept], [certs[i] for i in kept]
    tops, on_a_path = _chain_walk(certs)
    if not tops:
        return "the certificates of the upload name each other as issuer in a loop, so the chain has no top"
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    try:
        _load_box_store(client)
    except (ssl.SSLError, OSError) as e:
        logger.warning(f"The box's own CA store could not be loaded for the certificate check: {e}")
    if _handshake(server_ctx, client) is None:
        return None
    held = _held_by_box(client)
    refusal = None
    for top in tops:
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.check_hostname = False
        client.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        try:
            client.load_verify_locations(cadata=pems[top])
        except (ssl.SSLError, ValueError) as e:
            return f"a certificate of the chain could not be read ({getattr(e, 'strerror', None) or e})"
        answer = _handshake(server_ctx, client) or _not_a_ca(certs, top) or _box_refusal(certs, top, held)
        if answer is None:
            return None
        refusal = refusal or answer
    return refusal[0] + (_out_of_date([certs[i] for i in on_a_path]) if refusal[1] in _ABOUT_A_DATE else "")


def cert_refusal(cert_data: str, now=None) -> str | None:
    """(Q230, AP5) What a verifying client refuses the server certificate for, or None. `load_cert_chain` is a LOADER: an expired certificate, one that is not valid yet and a CA's
    own certificate in the server's place all load, were written to the config directory and followed by a restart into an HTTPS every browser refuses - on the page that holds
    the way back. Asked of the FIRST certificate of the file, which is the one the server presents: its validity window, and - only when the certificate states them - that its
    extended key usage names a server and its key usage allows a signature or a key exchange. A self-signed certificate with neither extension is accepted, as it always was."""
    from datetime import datetime, timezone

    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID

    try:
        leaf = x509.load_pem_x509_certificate(cert_data.encode("utf-8"))
    except ValueError:
        return "the certificate file's first certificate could not be read"
    now = now or datetime.now(timezone.utc)
    if now < leaf.not_valid_before_utc:
        return f"the certificate is not valid until {leaf.not_valid_before_utc:%Y-%m-%d %H:%M} UTC"
    if now > leaf.not_valid_after_utc:
        return f"the certificate expired on {leaf.not_valid_after_utc:%Y-%m-%d %H:%M} UTC"
    try:
        usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    except ValueError:
        # (Q235, AT7) the extension is parsed when it is read: one that is there and empty raised out of this function, and the upload said nothing about why
        return "the certificate carries an extension that cannot be read"
    # (Q213, AS8) serverAuth, named. `anyExtendedKeyUsage` alone used to pass here; OpenSSL does not read it as a purpose, so the handshake below refused the same
    # certificate with a sentence that did not say why
    if usage is not None and ExtendedKeyUsageOID.SERVER_AUTH not in set(usage):
        return (
            "the certificate was not issued for a server (its extended key usage does not name server authentication)"
        )
    try:
        key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None
    except ValueError:
        return "the certificate carries an extension that cannot be read"
    if key_usage is not None and not (
        key_usage.digital_signature or key_usage.key_encipherment or key_usage.key_agreement
    ):
        return (
            "the certificate's key usage allows neither a signature nor a key exchange, so no client accepts it for HTTPS "
            "(a CA's own certificate goes in the CA bundle field)"
        )
    return None


@bp.route("/settings/upload-cert", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def upload_cert():
    # Q202 (AR6): Jen's own SSL certificate ends in `runtime.restart_service()` - every restart of Jen is behind the one gate (superadmin + step-up), like `restart_jen`
    cert_file = request.files.get("certificate")
    key_file = request.files.get("private_key")
    ca_file = request.files.get("ca_bundle")
    if not cert_file or not key_file:
        flash("Certificate and private key are required.", "error")
        return redirect(url_for("settings.settings_security"))
    os.makedirs(os.path.dirname(extensions.SSL_CERT), exist_ok=True)
    try:
        cert_data = cert_file.read().decode("utf-8")
        key_data = key_file.read().decode("utf-8")
        ca_data = ca_file.read().decode("utf-8") if ca_file and ca_file.filename else None
        reason = validate_cert_material(cert_data, key_data, ca_data)
        if reason:
            flash(f"Certificate rejected — {reason}. Nothing was changed.", "error")
            return redirect(url_for("settings.settings_security"))
        combined = cert_data + ("" if cert_data.endswith("\n") else "\n") + (ca_data or "")
        # v5.68.0-beta.16 (Q151): the whole set (certificate, key, CA bundle, combined chain) is installed ALL-OR-NOTHING - it used to be written one file
        # at a time, so a failure at any step left a new key beside an old certificate (gunicorn then refuses to start). A failure puts every file back.
        from jen.services.certs import commit_file_set

        members = [(extensions.SSL_KEY, key_data, 0o640), (extensions.SSL_CERT, cert_data, 0o644)]
        if ca_data:
            members.append((extensions.SSL_CA, ca_data, 0o644))
        members.append((extensions.SSL_COMBINED, combined, 0o644))
        commit_file_set(members)
        __user.audit("UPLOAD_CERT", "settings", "SSL certificate uploaded")
        # v5.67.0-beta.10 (Q122) — restart by deployment (systemd or Docker); say so when neither.
        if __runtime.restart_service() == "none":
            flash("Certificate validated and installed. " + __runtime.RESTART_BY_HAND, "warning")
        else:
            flash("Certificate validated and installed. Jen is restarting...", "success")
    except UnicodeDecodeError:
        flash("Certificate files must be PEM format (text), not DER (binary).", "error")
    except Exception as e:
        logger.error(f"Error uploading certificate: {e}")
        flash("Error uploading certificate. Check server logs for details.", "error")
    return redirect(url_for("settings.settings_security"))


@bp.route("/settings/remove-cert", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(minutes=10)
def remove_cert():
    # Q202 (AR6): see upload_cert - removing the certificate takes the site back to HTTP and restarts Jen
    # (Q237, AV10) and the `.prev` copy `commit_file_set` keeps beside each: a removal that left `private.key.prev` on disk had not removed the key
    live = [extensions.SSL_CERT, extensions.SSL_KEY, extensions.SSL_CA, extensions.SSL_COMBINED]
    if not any(os.path.exists(name) or os.path.exists(name + ".prev") for name in live):
        # (Q240, AY14) with no certificate installed the route removed nothing, audited a removal and restarted Jen
        flash("No certificate is installed. Nothing was changed.", "warning")
        return redirect(url_for("settings.settings_security"))
    # (Q238, AW11) the copies FIRST: one that will not go stops the route with the live files and the serving setup as they were
    for f in [name + ".prev" for name in live] + live:
        try:
            if os.path.exists(f):
                os.remove(f)
        except OSError as e:  # (Q226, AL26) a file that will not go is said, never a 500 after the first one went
            logger.error("remove_cert: %s could not be removed: %s", f, type(e).__name__)
            flash("The certificate files could not all be removed. Check server logs for details.", "error")
            return redirect(url_for("settings.settings_security"))
    # v5.69.0-beta.2 (Q171): removing the certificate takes the site back to HTTP - an event the audit log carries like every other change of the serving setup
    __user.audit("REMOVE_CERT", "ssl", f"Certificate removed by {current_user.username}")
    if __runtime.restart_service() == "none":
        flash("Certificate removed. " + __runtime.RESTART_BY_HAND, "warning")
    else:
        flash("Certificate removed. Restarting in HTTP mode...", "success")
    return redirect(url_for("settings.settings_security"))


@bp.route("/settings/save-oidc", methods=["POST"])
@login_required
@_superadmin_required
@_recent_auth_required(
    minutes=10
)  # Q203 AS2: who may sign in, and with what role (`role_map`, `default_role`, `auto_create`), is what RBAC-003 calls deciding who the superadmins are
def save_oidc():
    """v5.25.0 (Q21) — [oidc] single sign-on. Superadmin only: this
    controls who can log in and with what role, a step above the rest
    of this page's admin-editable settings. client_secret behaves like
    every other password field in Jen — blank keeps the existing value,
    non-blank replaces it; there's nothing to "inherit" here, so no
    checkbox."""
    enabled = request.form.get("enabled", "") == "1"
    issuer = request.form.get("issuer", "").strip()
    client_id = request.form.get("client_id", "").strip()
    client_secret = request.form.get("client_secret", "").strip()
    scopes = request.form.get("scopes", "").strip() or "openid profile email"
    username_claim = request.form.get("username_claim", "").strip() or "preferred_username"
    role_claim = request.form.get("role_claim", "").strip() or "groups"
    role_map = request.form.get("role_map", "").strip()
    default_role = request.form.get("default_role", "viewer").strip().lower()
    auto_create = request.form.get("auto_create", "") == "1"
    button_label = request.form.get("button_label", "").strip() or "Sign in with SSO"
    redirect_uri = request.form.get("redirect_uri", "").strip()
    local_login = request.form.get("local_login", "") == "1"
    subnet_map = request.form.get("subnet_map", "").strip()
    subnet_map_default = request.form.get("subnet_map_default", "none").strip().lower()

    # (Q229, AO1, AO2, AO6) asked of every issuer that is saved, not only of an enabled one: a disabled save stored and audited whatever was typed
    if (enabled or issuer) and not __auth.valid_oidc_issuer(issuer):
        flash_field("issuer", __auth.userinfo_sentence(issuer) or OIDC_ISSUER_SHAPE)
        return redirect(url_for("settings.settings_security"))
    # (Q230, AP8) the redirect URI is the second address of this form and is asked what the first is: it goes into the authorize URL Jen sends the browser to the identity
    # provider with, so a password or a token inside it would leave the box. Blank is "auto-detected" and is not an address
    if redirect_uri and not __auth.plain_address(redirect_uri):
        flash_field("redirect_uri", __auth.userinfo_sentence(redirect_uri) or OIDC_REDIRECT_SHAPE)
        return redirect(url_for("settings.settings_security"))
    if enabled and not client_id:
        flash_field("client_id", "A client ID is required to enable single sign-on.")
        return redirect(url_for("settings.settings_security"))
    if default_role not in ("superadmin", "admin", "viewer", "none"):
        flash_field("default_role", "Default role must be superadmin, admin, viewer, or none.")
        return redirect(url_for("settings.settings_security"))
    if role_map and not __oidc.parse_role_map(role_map):
        flash_field("role_map", "Role mapping could not be parsed — check the format (role=value;role=value,value).")
        return redirect(url_for("settings.settings_security"))
    if subnet_map_default not in ("none", "all"):
        flash_field("subnet_map_default", "Subnet mapping default must be none or all.")
        return redirect(url_for("settings.settings_security"))
    if subnet_map and not __oidc.parse_subnet_map(subnet_map):
        flash(
            "Subnet mapping could not be parsed — check the format (group:id,id;group:*).",
            "error",
        )
        return redirect(url_for("settings.settings_security"))
    bad = __oidc.subnet_map_errors(subnet_map)
    if bad:
        # (Q226, AL4) a segment the parser would SKIP is refused here, with the segment named: a skipped segment is a group the operator meant to scope, and the login treats a map that
        # carries one as naming no default until it is fixed
        flash_field(
            "subnet_map", "Subnet mapping: " + "; ".join(bad[:3]) + ". Every segment is group:id,id or group:*."
        )
        return redirect(url_for("settings.settings_security"))

    # (Q227, AM5; CRED-002) a blank client secret keeps the stored one only while the issuer is the same place. The secret typed for one identity provider was registered against the next
    # one's discovery document and sent to its token endpoint. A stored issuer that is blank is a different place too (two saves would walk the secret across); an emptied issuer sends the secret nowhere and keeps it
    # (Q228, AN2 and the beta.13 review's #1) the issuer is compared WITH its path (`auth.same_destination`): `init_oidc` builds the discovery URL from the path, so the path selects
    # the realm or the tenant whose token endpoint is sent the secret, and `same_endpoint` (scheme, host, port) called two realms of one Keycloak, or two tenants of one cloud
    # login host, the same place. A client secret also belongs to ONE client registration: a changed client ID with a blank secret is refused the same way
    if not client_secret and issuer and extensions.OIDC_CLIENT_SECRET:
        # (Q229) `same_issuer` is `same_destination` of the two as `init_oidc` dials them
        if not __auth.same_issuer(issuer, extensions.OIDC_ISSUER):
            flash_field("client_secret", OIDC_ISSUER_CHANGED)
            return redirect(url_for("settings.settings_security"))
        if client_id != extensions.OIDC_CLIENT_ID:
            flash_field("client_secret", OIDC_CLIENT_CHANGED)
            return redirect(url_for("settings.settings_security"))

    items = [
        ("oidc", "enabled", "true" if enabled else "false"),
        ("oidc", "issuer", issuer),
        ("oidc", "client_id", client_id),
        ("oidc", "scopes", scopes),
        ("oidc", "username_claim", username_claim),
        ("oidc", "role_claim", role_claim),
        ("oidc", "role_map", role_map),
        ("oidc", "default_role", default_role),
        ("oidc", "auto_create", "true" if auto_create else "false"),
        ("oidc", "button_label", button_label),
        ("oidc", "redirect_uri", redirect_uri),
        ("oidc", "local_login", "true" if local_login else "false"),
        ("oidc", "subnet_map", subnet_map),
        ("oidc", "subnet_map_default", subnet_map_default),
    ]
    if client_secret:
        items.append(("oidc", "client_secret", client_secret))

    __config.app_config.write_values(items)
    # (Q228, AN2) the client is registered once, when Jen starts (`init_oidc`): the page said "saved" and the running process kept the old issuer, client and secret until a restart
    flash(OIDC_SAVED, "success")
    __user.audit("SAVE_SETTINGS", "oidc", f"enabled={enabled} issuer={issuer}")
    return redirect(url_for("settings.settings_security"))
