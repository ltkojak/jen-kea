"""Q234: the rows of Opus's pass on v7.0.1 (AQ1-AQ27), shipped as 7.1.0-beta.2.

The pass's finding in one sentence: a fix was verified at ONE end. The consumer of a list was right and no producer on its own route filled it (AQ10); one certificate of a
chain was judged (AQ11); a generated script was parsed and never run (AQ12); a rule read a stored value with another default than the code that acts on it (AQ1). Every cell
here drives the real producer into the real consumer, or runs the thing it names.

AQ12   the helper-less config script is RUN by a real interpreter with booleans and a null in the config.
AQ10   a ONE-server change set whose restore raised reaches the certificate consumer as NOT KNOWN (the real `_run_change` into the real `_tls_after_unapplied_change`).
AQ16   an api target whose rollback raised is not named as still new.
AQ11   the presented CHAIN is judged by a TLS handshake with a verifying client: an expired or not-yet-valid intermediate is refused.
AQ18   a critical extension no client handles is refused by the same handshake.
AQ1    `use_tls` has one reading: a row with no such key is STARTTLS, as the sender sends it.
AQ2    a stored ntfy topic of `.` or `..` is no destination; AQ5 user-info of a stored ntfy address is not dialed.
AQ15   the Kea CA card never prints a negative number of days.
"""

import datetime
import pathlib
import re
import subprocess
import sys

import pytest

from jen.services import alerts, kea_authoring
from jen.services import kea_changeset as cs

ROOT = pathlib.Path(__file__).resolve().parents[1]


# ── AQ12: the script is run, not parsed ───────────────────────────────────────────────────────────────────────

REALISTIC = {
    "Dhcp4": {
        "authoritative": True,
        "match-client-id": False,
        "user-context": None,
        "comment": 'it\'s a "quoted" back\\slash and a\nnew line',
        "subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "reservations-global": False}],
    }
}


class TestTheLegacyScriptIsRun:
    @pytest.mark.parametrize("dry_run", [True, False])
    def test_a_config_with_booleans_and_a_null_gets_past_its_own_first_line(self, tmp_path, dry_run):
        """`cfg = {json}` put `true`, `false` and `null` into Python source: NameError before anything was written, for every realistic config. The script is run here until it
        asks for Kea's own binary, which this box does not have - the answer the engine reads as `missingbinary`."""
        conf = tmp_path / "kea-dhcp4.conf"
        script = kea_authoring.render_author_config_script("dhcp4", str(conf), REALISTIC, True, dry_run)
        done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
        assert "NameError" not in done.stderr and "SyntaxError" not in done.stderr, done.stderr[-400:]
        assert "missingbinary:kea-dhcp4" in done.stdout, (done.stdout, done.stderr[-400:])
        assert not conf.exists() and list(tmp_path.iterdir()) == []

    def test_the_config_arrives_as_the_dict_it_was(self):
        script = kea_authoring.render_author_config_script("dhcp4", "/x/kea-dhcp4.conf", REALISTIC, True, True)
        line = next(ln for ln in script.splitlines() if ln.startswith("cfg = "))
        import json

        scope = {"json": json}
        exec(line, scope)  # one line of Jen's own rendering, which is what the Kea host runs
        assert scope["cfg"] == REALISTIC


# ── AQ10, AQ16: the real rollback into the real consumer ──────────────────────────────────────────────────────


class Raised(Exception):
    pass


class FakeHost:
    """`jen.services.kea_host` as `kea_changeset` calls it. `restore`: "ok", "refuse" (answers not ok) or "raise"; `restart_ok` False fails the FIRST restart."""

    def __init__(self, restore, restart_ok=False):
        self.restore, self.restart_ok, self.restarts = restore, restart_ok, 0

    def read_config_versioned(self, server, service, errors=None):
        return ({"Dhcp4": {"x": server["id"]}}, f"sha{server['id']}")

    def test_config(self, server, service, cfg, tls_paths=(), **kw):
        return {"ok": True, "code": "ok"}

    def apply_config(self, server, service, cfg, **kw):
        if kw.get("source") != "rollback":
            return {"ok": True, "code": "ok", "sha256": "new"}
        if self.restore == "raise":
            raise Raised("the host went away during the restore")
        if self.restore == "refuse":
            return {"ok": False, "code": "conflict", "detail": "the file changed"}
        return {"ok": True, "code": "ok", "sha256": "old"}

    def remove_config(self, server, service, expect_sha256=None):
        return {"ok": True}

    def service_action(self, server, service, action):
        if action == "restart":
            self.restarts += 1
            if not self.restart_ok and self.restarts == 1:
                return {"ok": False, "detail": "kea did not start on the new socket"}
        return {"ok": True}


SERVER = {"id": 7, "name": "kea-a", "ssh_host": "a.test", "config_transport": "file"}


def _one_server_change(monkeypatch, restore):
    """What `setup_direct_socket` runs: ONE server, the file transport, a restart."""
    monkeypatch.setattr(cs, "_host", FakeHost(restore))
    monkeypatch.setattr(cs, "_declared", lambda s: "file")
    return cs._run_change(
        "dhcp4",
        lambda cfg: ({"Dhcp4": {"new": True}}, "ok"),
        "added an https control socket",
        servers=[SERVER],
        restart=True,
        transport="file",
    )


def _consume(monkeypatch, result):
    from jen.routes.settings import infrastructure as infra

    said, incidents = [], []

    def never(*a, **k):
        raise AssertionError("the certificate was acted on although the config was not read back")

    monkeypatch.setattr(infra, "flash", lambda text, level="info": said.append((level, text)))
    monkeypatch.setattr(infra, "_record_incident", lambda *a, **k: incidents.append(a[3]))
    monkeypatch.setattr(infra, "_put_tls_back", never)
    monkeypatch.setattr("jen.services.kea_tls.discard_local_record", never)
    monkeypatch.setattr("jen.models.user.audit", lambda *a, **k: None)
    infra._tls_after_unapplied_change(SERVER, "dhcp4", {"Dhcp4": {}}, result)
    return said, incidents


class TestAOneServerRollbackReachesItsConsumer:
    def test_a_restore_that_raised_is_not_known_from_the_rollback_to_the_page(self, monkeypatch):
        result = _one_server_change(monkeypatch, "raise")
        assert result.status == "rollback_failed"
        assert (result.still_new_ids, result.not_known_ids) == ([], [7])
        assert any(cs.RESTORE_NOT_KNOWN in text for _level, text in result.lines)
        said, incidents = _consume(monkeypatch, result)
        assert incidents == ["remote-unknown"]
        assert said[0][1].startswith("STATE NOT KNOWN on kea-a")
        assert "still in" not in said[0][1].split("so it is not known")[0]

    def test_a_restore_that_was_refused_is_still_the_partial_state(self, monkeypatch):
        result = _one_server_change(monkeypatch, "refuse")
        assert (result.still_new_ids, result.not_known_ids) == ([7], [])
        assert not any(cs.RESTORE_NOT_KNOWN in text for _level, text in result.lines)
        said, incidents = _consume(monkeypatch, result)
        assert incidents == ["tls-not-restored"]
        assert said[0][1].startswith("PARTIAL STATE on kea-a")

    def test_a_restore_that_worked_names_nobody(self, monkeypatch):
        result = _one_server_change(monkeypatch, "ok")
        assert result.status == "rolled_back"
        assert (result.still_new_ids, result.not_known_ids) == ([], [])

    def test_every_return_that_names_a_still_new_target_names_the_not_known_ones_beside_it(self):
        """The whole module: `still_new_ids=` is never passed without `not_known_ids=` on the next line."""
        lines = (ROOT / "jen/services/kea_changeset.py").read_text(encoding="utf-8").splitlines()
        sites = [i for i, ln in enumerate(lines) if ln.strip().startswith("still_new_ids=")]
        assert len(sites) == 3
        assert all(lines[i + 1].strip().startswith("not_known_ids=") for i in sites)

    def test_an_api_rollback_that_raised_is_not_named_as_still_new(self):
        src = (ROOT / "jen/services/kea_changeset.py").read_text(encoding="utf-8")
        assert "if d.key not in file_unknown and d.key not in api_unknown]," in src
        assert "if d.key in file_unknown or d.key in api_unknown]," in src


# ── AQ11, AQ18: the chain is judged by the verifier clients use ───────────────────────────────────────────────


def _mint(cn, issuer=None, issuer_key=None, ca=False, start=-10, end=300, odd_critical=False, constraints=True):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    now, day = datetime.datetime.now(datetime.timezone.utc), datetime.timedelta(days=1)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer is not None else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + start * day)
        .not_valid_after(now + end * day)
    )
    if constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    if odd_critical:
        odd = x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00")
        builder = builder.add_extension(odd, critical=True)
    return builder.sign(issuer_key or key, hashes.SHA256()), key


def _pem(cert) -> str:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key(key) -> str:
    from cryptography.hazmat.primitives import serialization as s

    return key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()).decode()


@pytest.fixture(scope="module")
def pki():
    root, root_key = _mint("root", ca=True)
    inter, inter_key = _mint("inter", root, root_key, ca=True)
    old, old_key = _mint("old-inter", root, root_key, ca=True, start=-400, end=-5)
    soon, soon_key = _mint("soon-inter", root, root_key, ca=True, start=5)
    not_ca, not_ca_key = _mint("not-a-ca", root, root_key)
    out = {"root": _pem(root), "inter": _pem(inter), "old": _pem(old), "soon": _pem(soon), "not_ca": _pem(not_ca)}
    out["elsewhere"] = _pem(_mint("another-root", ca=True)[0])
    for label, issuer, issuer_key, more in (
        ("leaf", inter, inter_key, {}),
        ("leaf_old", old, old_key, {}),
        ("leaf_soon", soon, soon_key, {}),
        ("leaf_not_ca", not_ca, not_ca_key, {}),
        ("leaf_odd", inter, inter_key, {"odd_critical": True}),
        ("self", None, None, {}),
        ("bare", None, None, {"constraints": False}),
    ):
        cert, key = _mint("jen.example.test", issuer, issuer_key, **more)
        out[label], out[label + "_key"] = _pem(cert), _key(key)
    return out


ACCEPTED = [
    ("a fullchain paste", ("leaf", "inter"), "leaf_key", ()),
    ("the chain in the CA box", ("leaf",), "leaf_key", ("inter", "root")),
    ("the CA box root first", ("leaf",), "leaf_key", ("root", "inter")),
    ("a CA-issued certificate alone", ("leaf",), "leaf_key", ()),
    ("a self-signed certificate alone", ("self",), "self_key", ()),
    ("a self-signed certificate with no extensions", ("bare",), "bare_key", ()),
    ("a self-signed certificate beside a CA that did not issue it", ("self",), "self_key", ("elsewhere",)),
    ("a certificate beside a CA that did not issue it", ("leaf",), "leaf_key", ("elsewhere",)),
    ("a chain with a root that is not its own", ("leaf",), "leaf_key", ("inter", "elsewhere")),
]

REFUSED = [
    (
        "an expired intermediate in a fullchain paste",
        ("leaf_old", "old"),
        "leaf_old_key",
        (),
        "certificate has expired",
    ),
    (
        "an expired intermediate in the CA box",
        ("leaf_old",),
        "leaf_old_key",
        ("old", "root"),
        "certificate has expired",
    ),
    ("an intermediate that is not valid yet", ("leaf_soon", "soon"), "leaf_soon_key", (), "not yet valid"),
    ("a critical extension no client handles", ("leaf_odd", "inter"), "leaf_odd_key", (), "critical extension"),
    ("an issuer that is not a CA", ("leaf_not_ca", "not_ca", "root"), "leaf_not_ca_key", (), "invalid CA"),
]


def _judge(pki, certs, key, ca):
    from jen.routes.settings.security import validate_cert_material

    return validate_cert_material("".join(pki[c] for c in certs), pki[key], "".join(pki[c] for c in ca) if ca else None)


class TestTheChainIsJudgedByAVerifier:
    @pytest.mark.parametrize("case", ACCEPTED, ids=[c[0] for c in ACCEPTED])
    def test_what_a_client_accepts_or_cannot_judge_is_accepted(self, pki, case):
        _name, certs, key, ca = case
        assert _judge(pki, certs, key, ca) is None

    @pytest.mark.parametrize("case", REFUSED, ids=[c[0] for c in REFUSED])
    def test_what_a_client_refuses_is_refused_in_its_own_words(self, pki, case):
        _name, certs, key, ca, words = case
        reason = _judge(pki, certs, key, ca)
        assert reason and reason.startswith("a client that verifies the chain refuses it (") and words in reason

    @pytest.mark.parametrize("case", REFUSED[:2], ids=[c[0] for c in REFUSED[:2]])
    def test_the_refusal_is_the_one_a_real_client_gives_the_real_server(self, pki, case, tmp_path):
        """The oracle: the same material on a real local TLS server, and a client that trusts the root. Its refusal is the sentence the upload quotes."""
        import socket
        import ssl
        import threading

        _name, certs, key, ca, words = case
        chain = tmp_path / "chain.pem"
        chain.write_text("".join(pki[c] for c in certs) + "".join(pki[c] for c in ca), encoding="utf-8")
        keyfile = tmp_path / "key.pem"
        keyfile.write_text(pki[key], encoding="utf-8")
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(chain), str(keyfile))
        listener = socket.create_server(("127.0.0.1", 0))

        def serve():
            conn, _ = listener.accept()
            try:
                server_ctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError):
                conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.load_verify_locations(cadata=pki["root"])
        with (
            socket.create_connection(listener.getsockname(), timeout=10) as raw,
            pytest.raises(ssl.SSLCertVerificationError) as refused,
        ):
            client_ctx.wrap_socket(raw)
        thread.join(10)
        listener.close()
        assert words in refused.value.verify_message

    def test_the_upload_asks_the_chain_after_the_first_certificate(self):
        src = (ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8")
        assert "return cert_refusal(cert_data) or chain_refusal(ctx, cert_data, ca_data)" in src


# ── AQ1: one reading of `use_tls` ─────────────────────────────────────────────────────────────────────────────


def _route():
    from jen.routes.settings import alerts as route

    return route


class TestUseTlsHasOneReading:
    def test_a_row_with_no_such_key_is_the_wire_the_sender_uses(self):
        route = _route()
        assert route._wire_rank({}) == 2 and route._wire_rank({"tls_verify": "false"}) == 1
        assert route._endpoint("email", {"smtp_host": "mail.example.test", "smtp_port": "587"}).startswith("smtps://")

    def test_unticking_starttls_on_such_a_row_asks_for_the_password_again(self, monkeypatch):
        route = _route()
        old = {"smtp_host": "mail.example.test", "smtp_port": "587", "smtp_user": "u", "smtp_pass": "stored"}
        monkeypatch.setattr(alerts, "get_channel_config", lambda stored: dict(old))
        typed = {"smtp_host": "mail.example.test", "smtp_port": "587", "smtp_user": "u", "smtp_pass": ""}
        refused = route._kept_secrets(
            1, "email", dict(typed, use_tls="false", tls_verify="true"), {"channel_type": "email"}
        )
        assert isinstance(refused, tuple) and refused[1] == route.DESTINATION_CHANGED
        kept = route._kept_secrets(
            1, "email", dict(typed, use_tls="true", tls_verify="true"), {"channel_type": "email"}
        )
        assert isinstance(kept, dict) and kept["smtp_pass"] == "stored"

    def test_every_reader_of_the_key_under_jen_gives_it_the_senders_default(self):
        """The whole tree: `config.get("use_tls")` with no default is the second reading."""
        bare = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"""(?<!form)\.get\(["']use_tls["']\)""", line):
                    bare.append(f"{path.relative_to(ROOT).as_posix()}:{n}")
        assert bare == []


# ── AQ2, AQ5: the ntfy target ─────────────────────────────────────────────────────────────────────────────────


class TestTheNtfyTargetIsADestinationOrNothing:
    @pytest.mark.parametrize("topic", [".", ".."])
    def test_a_dot_segment_is_no_topic_and_nothing_is_posted(self, topic, monkeypatch):
        config = {"url": "https://ntfy.example.test/base", "topic": topic, "token": "t"}
        assert alerts.ntfy_target(config) == ""

        def never(*a, **k):
            raise AssertionError("the token was posted")

        monkeypatch.setattr(alerts, "_post", never)
        with pytest.raises(Exception, match="cannot be used as a destination"):
            alerts._send_ntfy_channel("m", config)

    def test_a_topic_with_a_dot_in_it_is_a_topic(self):
        assert (
            alerts.ntfy_target({"url": "https://ntfy.example.test", "topic": "a.b"}) == "https://ntfy.example.test/a.b"
        )

    def test_user_info_of_a_stored_address_is_not_dialed(self):
        target = alerts.ntfy_target({"url": "https://someone:pw@ntfy.example.test:8443/base", "topic": "jen"})
        assert target == "https://ntfy.example.test:8443/base/jen"

    def test_the_path_a_client_dials_is_the_path_of_the_target(self):
        import requests

        for topic in ("jen", "a.b", "../admin", "a/b", "%2e%2e", "jen?x=1"):
            target = alerts.ntfy_target({"url": "https://ntfy.example.test/base", "topic": topic})
            dialed = requests.Request("POST", target).prepare().path_url
            assert dialed.startswith("/base/") and dialed.count("/") == 2, (topic, dialed)


# ── AQ15: the Kea CA card ─────────────────────────────────────────────────────────────────────────────────────


class TestTheKeaCaCardNeverCountsBelowZero:
    @pytest.mark.parametrize(
        "days,words",
        [
            (-5, "expired 5 days ago"),
            (-1, "expired 1 day ago"),
            (0, "expires in 0 days"),
            (9, "expires in 9 days"),
            (None, "expiry unreadable"),
        ],
    )
    def test_the_sentence(self, days, words):
        import jinja2

        from jen.services import reltime

        src = (ROOT / "templates/settings_kea.html").read_text(encoding="utf-8")
        (piece,) = re.findall(r"\{% if kea_ca\.days_left is none %\}.*?\{% endif %\}", src)
        env = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=True)
        env.filters["plural"] = reltime.plural
        said = env.from_string(piece).render(kea_ca={"days_left": days})
        assert said == words and "-" not in said


# ── AR1, AR2, AR3 (the v7.1.0-beta.1 pass): the two export cards mean one thing by one gesture ────────────────


class TestNothingTickedIsNothingToExport:
    def test_the_jen_cards_form_says_it_is_the_picker(self):
        page = (ROOT / "templates/database.html").read_text(encoding="utf-8")
        (form,) = re.findall(r'<form method="POST" action="/database/export/jen"[^\n]*', page)
        assert '<input type="hidden" name="picker" value="1">' in form

    def test_the_route_refuses_the_pickers_empty_form_before_it_writes_anything(self):
        src = (ROOT / "jen/routes/database.py").read_text(encoding="utf-8")
        body = src[src.index("def export_jen():") : src.index("def export_kea():")]
        refusal = body.index('if tables is None and "picker" in request.form:')
        assert 'flash("Tick at least one Jen table to export.", "error")' in body[refusal:]
        assert refusal < body.index("tempfile.mkstemp(") < body.index("dbexport.write_jen_export(tmp_path")

    @pytest.mark.parametrize("page", ["templates/database.html", "templates/database_migrate.html"])
    def test_every_page_with_an_all_box_has_the_listener_that_follows_its_boxes(self, page):
        src = (ROOT / page).read_text(encoding="utf-8")
        assert 'class="toggle-all-cb"' in src
        assert "cb.checked = !group.querySelector('input[type=checkbox]:not(:checked)');" in src

    def test_no_template_with_an_all_box_is_without_it(self):
        """The whole tree, not the two pages this Q knew about."""
        missing = [
            p.name
            for p in sorted((ROOT / "templates").glob("*.html"))
            if "toggle-all-cb" in p.read_text(encoding="utf-8")
            and "cb.checked = !group.querySelector(" not in p.read_text(encoding="utf-8")
        ]
        assert missing == []

    @pytest.mark.parametrize("doc", ["CHANGELOG.md", "docs/upgrading.md"])
    def test_no_document_says_a_migration_never_carries_leases(self, doc):
        text = (ROOT / doc).read_text(encoding="utf-8")
        assert "a Kea migration still save the `reservations_all` group, never leases" not in text
        assert "Backups and migrations still save reservations only" not in text
