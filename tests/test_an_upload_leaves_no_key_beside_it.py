"""
tests/test_an_upload_leaves_no_key_beside_it.py
───────────────────────────────────────────────
Q242 (BA1, BA17 of the executing pass on v7.1.0-beta.10; finding 1 and finding 4 of the independent review of the same tag).

7.1.0-beta.10 stopped writing a private key into the three certificate files, and its notes told an operator whose files already held one to upload the
certificate again. `commit_file_set` keeps every file it replaces as `<name>.prev`, byte for byte and with its mode: the upload moved the key from three
files of mode 0644 into three `.prev` files of mode 0644. And an upload with no CA field left the old `ca_bundle.crt`, key included, where it was.

These tests build the directory an earlier release left, run the real route, and then read EVERY file of the directory: no file but the key and the key's
own copy holds a private key, whatever the directory held before and whatever the upload carried.
"""

import datetime
import io
import os
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from jen import extensions
from jen.routes.settings import security

KEY_FILES = {"key.pem", "key.pem.prev"}


def _issue(cn, key, issuer_cert=None, issuer_key=None, ca=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert is not None else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(issuer_key or key, hashes.SHA256())


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def _a_chain(label):
    root_key, mid_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _issue(f"{label} Root", root_key, ca=True)
    mid = _issue(f"{label} Intermediate", mid_key, root, root_key, ca=True)
    leaf = _issue(f"jen.{label.lower()}.example", leaf_key, mid, mid_key)
    return {"root": _pem(root), "mid": _pem(mid), "leaf": _pem(leaf), "key": _key_pem(leaf_key)}


@pytest.fixture(scope="module")
def old():
    """The certificate the box served before the upload."""
    return _a_chain("Old")


@pytest.fixture(scope="module")
def new():
    return _a_chain("New")


@pytest.fixture
def ssl_dir(monkeypatch, tmp_path, restarts):
    d = tmp_path / "ssl"
    d.mkdir()
    for attr in ("SSL_CERT", "SSL_KEY", "SSL_CA", "SSL_COMBINED"):
        monkeypatch.setattr(extensions, attr, str(d / (attr.lower().replace("ssl_", "") + ".pem")))
    return d


@pytest.fixture
def restarts(monkeypatch):
    seen = []
    monkeypatch.setattr("jen.services.runtime.restart_service", lambda *a, **k: seen.append(1) or "systemd")
    return seen


def _put(path, text, mode=0o644):
    path.write_text(text)
    os.chmod(path, mode)


def _as_an_earlier_release_left_it(d, old, with_ca=True, where="live"):
    """`live`: a combined PEM was uploaded to 7.1.0-beta.9 or earlier, so the key is in every certificate file. `prev`: and the operator then uploaded the
    same certificate again on 7.1.0-beta.10, as its notes said, so the live files are clean and the key is in the `.prev` of each. `both`: each of the two."""
    keyed = where in ("live", "both")
    cert = old["leaf"] + (old["key"] if keyed else "")
    ca = old["mid"] + (old["key"] if keyed else "")
    _put(d / "key.pem", old["key"], 0o640)
    _put(d / "cert.pem", cert)
    if with_ca:
        _put(d / "ca.pem", ca)
    _put(d / "combined.pem", cert + (ca if with_ca else ""))
    if where in ("prev", "both"):
        _put(d / "cert.pem.prev", old["leaf"] + old["key"])
        if with_ca:
            _put(d / "ca.pem.prev", old["mid"] + old["key"])
        _put(d / "combined.pem.prev", old["leaf"] + old["key"] + old["mid"] + old["key"])


def _post(client, cert, key, ca=None):
    data = {
        "certificate": (io.BytesIO(cert.encode()), "certificate.crt"),
        "private_key": (io.BytesIO(key.encode()), "private.key"),
    }
    if ca is not None:
        data["ca_bundle"] = (io.BytesIO(ca.encode()), "ca_bundle.crt")
    return client.post("/settings/upload-cert", data=data, content_type="multipart/form-data", follow_redirects=True)


def _files_that_hold_a_key(d):
    """Every file of the directory, read: the names that hold a private key and are not the key file or its own copy."""
    return sorted(p.name for p in d.iterdir() if p.name not in KEY_FILES and "PRIVATE KEY" in p.read_text())


def _modes(d):
    return {p.name: oct(os.stat(p).st_mode & 0o777) for p in d.iterdir() if p.name not in KEY_FILES}


def _served(d, root_pem):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(d / "combined.pem"), str(d / "key.pem"))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.load_verify_locations(cadata=root_pem)
    return security._handshake(server, client)


WORLDS = [
    (where, had_ca, upload)
    for where in ("live", "prev", "both")
    for had_ca in (True, False)
    for upload in ("with a CA", "no CA field", "a full chain in the certificate field")
]


class TestEveryFileOfTheDirectoryAfterAnUpload:
    @pytest.mark.parametrize(
        "where,had_ca,upload", WORLDS, ids=[f"{w}, {'CA' if c else 'no CA'} before, {u}" for w, c, u in WORLDS]
    )
    def test_no_file_but_the_key_and_its_copy_holds_a_key(
        self, logged_in_client, ssl_dir, old, new, where, had_ca, upload
    ):
        """BA1. The route, then every file it left. At 7.1.0-beta.10 each of these worlds leaves the old key in a file of mode 0644."""
        _as_an_earlier_release_left_it(ssl_dir, old, with_ca=had_ca, where=where)
        assert _files_that_hold_a_key(ssl_dir), "the world starts with the key in a certificate file"
        if upload == "with a CA":
            r = _post(logged_in_client, new["leaf"], new["key"], new["mid"])
        elif upload == "no CA field":
            r = _post(logged_in_client, new["leaf"], new["key"])
        else:
            r = _post(logged_in_client, new["leaf"] + new["mid"], new["key"])
        assert b"validated and installed" in r.data, r.data[-600:]
        assert _files_that_hold_a_key(ssl_dir) == []
        assert set(_modes(ssl_dir).values()) == {"0o644"}, _modes(ssl_dir)
        assert (ssl_dir / "key.pem").read_text() == new["key"]
        assert (ssl_dir / "key.pem.prev").read_text() == old["key"], "the key's own copy is kept, as before"
        assert oct(os.stat(ssl_dir / "key.pem.prev").st_mode & 0o777) == "0o640"
        if upload != "no CA field":
            assert _served(ssl_dir, new["root"]) is None

    def test_the_earlier_certificates_are_kept_as_certificates(self, logged_in_client, ssl_dir, old, new):
        """What an operator may want back is still there: the certificate, its chain and the key, each in its own file."""
        _as_an_earlier_release_left_it(ssl_dir, old)
        _post(logged_in_client, new["leaf"], new["key"], new["mid"])
        assert (ssl_dir / "cert.pem.prev").read_text() == old["leaf"]
        assert (ssl_dir / "ca.pem.prev").read_text() == old["mid"]
        assert (ssl_dir / "combined.pem.prev").read_text() == old["leaf"] + old["mid"]

    def test_an_upload_with_no_ca_field_leaves_no_ca_bundle_of_the_certificate_before_it(
        self, logged_in_client, ssl_dir, old, new
    ):
        """BA17. `ca_bundle.crt` is the bundle of the certificate that is installed, or it is not there."""
        _as_an_earlier_release_left_it(ssl_dir, old)
        r = _post(logged_in_client, new["leaf"], new["key"])
        assert b"validated and installed" in r.data
        assert not (ssl_dir / "ca.pem").exists()
        assert (ssl_dir / "combined.pem").read_text() == new["leaf"]
        assert (ssl_dir / "combined.pem.prev").read_text() == old["leaf"] + old["mid"], "its certificates are here"

    def test_an_upload_with_a_ca_field_keeps_the_bundle_it_wrote(self, logged_in_client, ssl_dir, old, new):
        _as_an_earlier_release_left_it(ssl_dir, old)
        _post(logged_in_client, new["leaf"], new["key"], new["mid"])
        assert (ssl_dir / "ca.pem").read_text() == new["mid"]

    def test_a_second_upload_of_the_same_certificate_changes_nothing_more(self, logged_in_client, ssl_dir, old, new):
        """The operation run twice (RELEASE_AUDIT (r)): the second run reads what the first one left."""
        _as_an_earlier_release_left_it(ssl_dir, old, where="both")
        _post(logged_in_client, new["leaf"], new["key"], new["mid"])
        _post(logged_in_client, new["leaf"], new["key"], new["mid"])
        assert _files_that_hold_a_key(ssl_dir) == []
        assert (ssl_dir / "cert.pem.prev").read_text() == new["leaf"]
        assert (ssl_dir / "key.pem.prev").read_text() == new["key"]

    def test_a_first_upload_on_an_empty_directory_leaves_four_files(self, logged_in_client, ssl_dir, new):
        r = _post(logged_in_client, new["leaf"], new["key"], new["mid"])
        assert b"validated and installed" in r.data
        assert sorted(p.name for p in ssl_dir.iterdir()) == ["ca.pem", "cert.pem", "combined.pem", "key.pem"]

    def test_an_earlier_copy_that_is_not_certificates_is_removed(self, logged_in_client, ssl_dir, old, new):
        _as_an_earlier_release_left_it(ssl_dir, old, with_ca=False)
        _put(ssl_dir / "ca.pem.prev", "-----BEGIN PRIVATE KEY-----\nnot a certificate at all\n")
        r = _post(logged_in_client, new["leaf"], new["key"])
        assert b"validated and installed" in r.data
        assert not (ssl_dir / "ca.pem.prev").exists()


class TestACopyThatCannotBeCleanedIsSaid:
    def test_the_certificate_is_installed_and_the_page_names_the_file(
        self, logged_in_client, ssl_dir, restarts, old, new, db
    ):
        """Nothing is faked: `ca.pem.prev` is a directory, so it can be neither read nor replaced. The set is installed by then, so Jen restarts into the
        new certificate and says which file is left, on the page and in the audit row."""
        _as_an_earlier_release_left_it(ssl_dir, old, with_ca=False)
        (ssl_dir / "ca.pem.prev").mkdir()
        r = _post(logged_in_client, new["leaf"], new["key"])
        assert b"validated and installed" in r.data and restarts == [1]
        assert b"ca.pem.prev in " in r.data and b"could not be cleaned" in r.data
        assert (ssl_dir / "combined.pem").read_text() == new["leaf"]
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT details FROM audit_log WHERE action='UPLOAD_CERT' ORDER BY id DESC LIMIT 1")
            assert cur.fetchone()["details"] == "SSL certificate uploaded; not cleaned: ca.pem.prev"

    def test_an_upload_that_cleaned_everything_says_nothing_of_it(self, logged_in_client, ssl_dir, old, new, db):
        _as_an_earlier_release_left_it(ssl_dir, old)
        r = _post(logged_in_client, new["leaf"], new["key"], new["mid"])
        assert b"could not be cleaned" not in r.data
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT details FROM audit_log WHERE action='UPLOAD_CERT' ORDER BY id DESC LIMIT 1")
            assert cur.fetchone()["details"] == "SSL certificate uploaded"


class TestAnUploadThatFailsLeavesTheDirectoryAsItWas:
    def test_a_write_that_fails_inside_the_set_changes_no_file(self, logged_in_client, ssl_dir, restarts, old, new):
        """The set is all or nothing, as before this Q: `combined.pem.prev` is a directory, the copy of the file being replaced cannot be written, and
        every file reads as it did. The cleaning runs only after a set that was installed."""
        _as_an_earlier_release_left_it(ssl_dir, old)
        (ssl_dir / "combined.pem.prev").mkdir()
        before = {p.name: p.read_text() for p in ssl_dir.iterdir() if p.is_file()}
        r = _post(logged_in_client, new["leaf"], new["key"], new["mid"])
        assert b"Error uploading certificate" in r.data and restarts == []
        after = {p.name: p.read_text() for p in ssl_dir.iterdir() if p.is_file() and not p.name.endswith(".prev")}
        assert after == {name: text for name, text in before.items() if not name.endswith(".prev")}

    def test_a_refused_upload_cleans_nothing(self, logged_in_client, ssl_dir, old, new):
        """A read never deletes, and neither does a refusal: the directory is touched only by an upload that was installed."""
        _as_an_earlier_release_left_it(ssl_dir, old, where="both")
        before = {p.name: p.read_text() for p in ssl_dir.iterdir()}
        r = _post(logged_in_client, new["leaf"], old["key"], new["mid"])
        assert b"Certificate rejected" in r.data and b"Nothing was changed" in r.data
        assert {p.name: p.read_text() for p in ssl_dir.iterdir()} == before


class TestCertificatesOnly:
    def test_a_key_and_everything_that_is_not_a_certificate_goes(self, tmp_path, old):
        p = tmp_path / "x.prev"
        _put(p, "a comment\n" + old["leaf"] + old["key"] + old["mid"] + old["leaf"], 0o600)
        security.certificates_only(str(p))
        assert p.read_text() == old["leaf"] + old["mid"]
        assert oct(os.stat(p).st_mode & 0o777) == "0o644"
        assert sorted(q.name for q in tmp_path.iterdir()) == ["x.prev"], "no copy of the copy is made"

    def test_a_file_that_is_already_only_certificates_is_not_written_again(self, tmp_path, old):
        p = tmp_path / "x.prev"
        _put(p, old["leaf"] + old["mid"])
        inode = os.stat(p).st_ino
        security.certificates_only(str(p))
        assert os.stat(p).st_ino == inode and p.read_text() == old["leaf"] + old["mid"]

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n",
        ],
        ids=["empty", "only a key", "a block that cannot be parsed"],
    )
    def test_a_file_with_no_certificate_jen_can_read_is_removed(self, tmp_path, text):
        p = tmp_path / "x.prev"
        _put(p, text)
        security.certificates_only(str(p))
        assert not p.exists()

    def test_bytes_that_are_not_text_are_removed_and_do_not_raise(self, tmp_path):
        p = tmp_path / "x.prev"
        p.write_bytes(b"\xff\xfe\x00 PRIVATE KEY \x80")
        security.certificates_only(str(p))
        assert not p.exists()

    def test_a_file_that_is_not_there_is_left_alone(self, tmp_path):
        security.certificates_only(str(tmp_path / "nothing.prev"))
        assert list(tmp_path.iterdir()) == []


class TestTheUploadIsNotReadPastItsBound:
    """AW15, finding 4 of the review. The three fields were read and decoded whole before the judge counted a character."""

    def test_more_bytes_than_the_judge_takes_characters_is_refused_before_it_is_decoded(
        self, logged_in_client, ssl_dir, new
    ):
        most = 4 * security._MOST_CHARACTERS
        r = _post(logged_in_client, new["leaf"] + "#" * most, new["key"], new["mid"])
        assert b"Certificate rejected" in r.data and b"more than 4,000,000 bytes" in r.data
        assert b"Nothing was changed" in r.data and list(ssl_dir.iterdir()) == []

    def test_the_bound_is_over_the_three_fields_together(self, logged_in_client, ssl_dir, new):
        third = "#" * (4 * security._MOST_CHARACTERS // 3)
        r = _post(logged_in_client, new["leaf"] + third, new["key"] + third, new["mid"] + third)
        assert b"more than 4,000,000 bytes" in r.data and list(ssl_dir.iterdir()) == []

    def test_an_upload_under_it_and_over_the_judges_bound_gets_the_judges_sentence(
        self, logged_in_client, ssl_dir, new
    ):
        r = _post(logged_in_client, new["leaf"] + "#" * security._MOST_CHARACTERS, new["key"], new["mid"])
        assert b"Certificate rejected" in r.data and b"characters and a certificate" in r.data
        assert list(ssl_dir.iterdir()) == []

    def test_no_field_is_read_without_a_bound(self):
        """Source: the route has no `.read()` with no argument."""
        import inspect

        source = inspect.getsource(security.upload_cert)
        assert ".read()" not in source and source.count(".read(most + 1)") == 1
