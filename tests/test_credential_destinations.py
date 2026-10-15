"""
tests/test_credential_destinations.py
─────────────────────────────────────
v5.69.0-beta.11 (Q180, CRED-004 / RBAC-004) - the credential matrix, permanent.

Four reviews (of beta.7, beta.8, beta.9 and beta.10) each found a shape in which a saved secret reached a host its owner never named, and each time a form was guarded. The rule now
lives in `credentials.resolve` (what each endpoint WILL send) and `AppConfig._write_parser` (what a write may not do), so this file is the table of every shape those reviews named:
the parser as it was, the mutation as the route would make it (through `mutate`, with `typed`), the expected `resolve(after)` per endpoint, and whether the write is refused. A new
shape is a ROW BEFORE its fix (docs/RELEASE_AUDIT.md, step (n)).

Table 1 (pure, `py -m pytest --noconftest tests/test_credential_destinations.py`): the writer, on a real file. Table 2 (CI: the database and the Flask app): the seven forms driven with
crafted POST bodies as a fresh superadmin, a stale superadmin, an admin and a subnet-scoped admin.
"""

import configparser
import hashlib

import pytest

from jen import extensions
from jen.config import ConfigChangeRefused, app_config
from jen.services import access
from jen.services import credentials as cred
from tests import test_kea_connection_forms as _forms

isolated_config = _forms.isolated_config  # the fixture: a real file, the writer, the globals

BASE = """
[kea]
api_url = https://a:8000
api_user = u
api_pass = S
[kea_db]
host = db1
user = k
password = KDB
[jen_db]
host = jh
user = j
password = JP
"""


@pytest.fixture(autouse=True)
def _the_investigation_guard_is_not_this_files_question(monkeypatch):
    """The matrix is about WHICH SECRET goes WHERE and WHO may move it; the investigation guard (WHICH Kea, and whether its settings record can be read) has its own tests
    (tests/test_identity_guard.py) and reads the database, which a pure run does not have."""
    from jen import config

    monkeypatch.setattr(config, "_identity_guards", [])


def _parse(text):
    p = configparser.ConfigParser(interpolation=None)
    p.read_string(text)
    return p


def _set(section, key, value):
    def fn(p):
        if not p.has_section(section):
            p.add_section(section)
        p.set(section, key, value)

    return fn


def _all(*fns):
    def fn(p):
        for f in fns:
            f(p)

    return fn


def _drop(section, key):
    return lambda p: p.remove_option(section, key)


def _add_server(n, **keys):
    def fn(p):
        p.add_section(f"kea_server_{n}")
        for k, v in keys.items():
            p.set(f"kea_server_{n}", k, v)

    return fn


class Row:
    def __init__(self, review, before, change, *, typed=(), refused=False, expect=None):
        self.review, self.before, self.change, self.typed, self.refused, self.expect = (
            review,
            before,
            change,
            typed,
            refused,
            expect or {},
        )


# (id) -> Row. `expect`: endpoint name -> (password, source prefix, withheld) of resolve(after) - checked when the write goes through.
ROWS = {
    # ── the move rule at the writer ────────────────────────────────────────────────────────────────────────────────────────
    "a_host_change_with_the_password_unchanged_and_untyped": Row(
        "beta.9: the primary moved with its saved password (and D2 pinned beside it)",
        BASE + "[d2]\napi_url = https://a:53001\n",
        _set("kea", "api_url", "https://z:8000"),
        refused=True,
    ),
    "the_same_move_with_the_password_typed": Row(
        "beta.9: the primary moved, password typed - D2, which inherited on the old host, is left with NONE",
        BASE + "[d2]\napi_url = https://a:53001\n",
        _all(_set("kea", "api_url", "https://z:8000"), _set("kea", "api_pass", "N")),
        typed={"kea"},
        expect={"kea": ("N", "own", ""), "d2": ("", "none", "kea")},
    ),
    "a_move_to_another_spelling_of_the_same_host": Row(
        "beta.10: the direct-socket routes point a server at the address its SSH host gave",
        BASE,
        _set("kea", "api_url", "https://A:8004/"),
        expect={"kea": ("S", "own", "")},
    ),
    "a_new_server_given_the_primarys_password_on_another_host_untyped": Row(
        "beta.10: an extra server sharing the primary's password without saying so",
        BASE,
        _add_server(2, api_url="https://b:8000", api_pass="S"),
        refused=True,
    ),
    "the_same_server_with_the_share_box_ticked": Row(
        "beta.10: the 'share the primary's API password' box types it on purpose",
        BASE,
        _add_server(2, api_url="https://b:8000", api_pass="S", api_pass_shared="1"),
        typed={"server_2"},
        expect={"server_2": ("S", "own", "")},
    ),
    "a_new_server_with_no_key_on_another_host": Row(
        "beta.10: the unchecked box - no key is written and the server has NO credential (not the primary's)",
        BASE,
        _add_server(2, api_url="https://b:8000"),
        expect={"server_2": ("", "none", "kea")},
    ),
    "a_new_server_with_no_key_on_the_primarys_host": Row(
        "beta.10: ... unless it is on the primary's own host",
        BASE,
        _add_server(2, api_url="https://a:8001"),
        expect={"server_2": ("S", "inherited:kea", "")},
    ),
    "an_existing_pair_sharing_a_password_is_not_this_writes_doing": Row(
        "the upgrade's conversion made peers share the primary's on purpose: an unrelated write must not be refused for it",
        BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = S\napi_pass_shared = 1\n",
        _set("kea_server_2", "name", "renamed"),
        expect={"server_2": ("S", "own", "")},
    ),
    "a_server_moved_with_its_own_password_untyped": Row(
        "beta.9: an extra server without a key, URL changed, blank password (here it has one: it follows the endpoint)",
        BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n",
        _set("kea_server_2", "api_url", "https://c:8000"),
        refused=True,
    ),
    "a_server_without_a_key_moved_off_the_primarys_host": Row(
        "beta.9: an extra server without a key moved - it inherited on the primary's host and now has none",
        BASE + "[kea_server_2]\napi_url = https://a:8001\n",
        _set("kea_server_2", "api_url", "https://z:8000"),
        expect={"server_2": ("", "none", "kea")},
    ),
    "a_rotation_with_kea6_and_d2_pinned": Row(
        "beta.10: the primary's password rotated while [kea6] has its own and [d2] inherits on the same host",
        BASE + "[kea6]\napi_url = https://a:8006\napi_pass = K6\n[d2]\napi_url = https://a:53001\n",
        _set("kea", "api_pass", "N"),
        typed={"kea"},
        expect={"kea": ("N", "own", ""), "kea6": ("K6", "own", ""), "d2": ("N", "inherited:kea", "")},
    ),
    "the_kea_password_equal_to_the_jen_database_password": Row(
        "a new pair: one value on two hosts, untyped",
        BASE,
        _set("kea", "api_pass", "JP"),
        refused=True,
    ),
    # ── the endpoints of a server ───────────────────────────────────────────────────────────────────────────────────────────
    "an_extra_servers_ipv6_on_another_host_with_no_password": Row(
        "beta.10: the extra server's v6 endpoint on another host is NOT given the API password",
        BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n",
        _set("kea_server_2", "api6_url", "https://c:8006"),
        expect={"server_2_v6": ("", "none", "server_2")},
    ),
    "the_same_with_its_own_password_typed": Row(
        "beta.10: ... with its own password typed it is used",
        BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n",
        _all(_set("kea_server_2", "api6_url", "https://c:8006"), _set("kea_server_2", "api6_pass", "P6")),
        typed={"server_2_v6"},
        expect={"server_2_v6": ("P6", "own", "")},
    ),
    "an_extra_servers_d2_on_another_host_with_no_password": Row(
        "beta.10: the extra server's D2 endpoint, likewise",
        BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n",
        _set("kea_server_2", "api_d2_url", "https://c:53001"),
        expect={"server_2_d2": ("", "none", "server_2")},
    ),
    "an_empty_ipv6_password_is_an_answer": Row(
        "beta.10 item 6: `api6_pass =` (empty) with api6_url on another host - none, and nothing was withheld",
        BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n",
        _all(_set("kea_server_2", "api6_url", "https://c:8006"), _set("kea_server_2", "api6_pass", "")),
        expect={"server_2_v6": ("", "none", "")},
    ),
    "an_absent_ipv6_password_on_the_servers_own_host": Row(
        "beta.10 item 6: absent `api6_pass`, api6_url on the server's own host - inherits the server's",
        BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n",
        _set("kea_server_2", "api6_url", "https://b:8006"),
        expect={"server_2_v6": ("P", "inherited:server_2", "")},
    ),
    "kea6_pointed_at_another_host": Row(
        "beta.9: Kea6 with Inherit and a new host",
        BASE,
        _set("kea6", "api_url", "https://k6:8006"),
        expect={"kea6": ("", "none", "kea")},
    ),
    "the_kea6_database_pointed_at_another_host": Row(
        "beta.9: [kea6_db] with a new host and no password",
        BASE,
        _set("kea6_db", "host", "db2"),
        expect={"kea6_db": ("", "none", "kea_db")},
    ),
    "the_kea_database_moved_untyped": Row(
        "beta.9: Kea's database moved with its saved password",
        BASE,
        _set("kea_db", "host", "db9"),
        refused=True,
    ),
    "the_jen_database_moved_untyped": Row(
        "beta.9: Jen's database moved with its saved password",
        BASE,
        _set("jen_db", "host", "jh9"),
        refused=True,
    ),
    "the_jen_database_moved_with_the_password_typed": Row(
        "beta.9: ... typed",
        BASE,
        _all(_set("jen_db", "host", "jh9"), _set("jen_db", "password", "NEW")),
        typed={"jen_db"},
        expect={"jen_db": ("NEW", "own", "")},
    ),
}


def _run(tmp_path, monkeypatch, row):
    path = tmp_path / "jen.config"
    path.write_text(row.before, encoding="utf-8")
    monkeypatch.setattr(extensions, "CONFIG_FILE", str(path))
    monkeypatch.setattr(app_config, "reload", lambda: None)
    before = path.read_bytes()
    try:
        app_config.mutate(row.change, reload=False, typed=set(row.typed))
        refused, message = False, ""
    except ConfigChangeRefused as e:
        refused, message = True, str(e)
    return refused, message, before, path


@pytest.mark.parametrize("name", list(ROWS))
def test_the_row(name, tmp_path, monkeypatch):
    """One row of the matrix: refused or not, the file byte-identical when refused, and what every endpoint resolves to when it is not."""
    row = ROWS[name]
    refused, message, before, path = _run(tmp_path, monkeypatch, row)
    assert refused is row.refused, f"[{row.review}] expected refused={row.refused}, got refused={refused} ({message})"
    if refused:
        assert path.read_bytes() == before, "a refused write leaves the file byte-identical"
        return
    resolved = cred.resolve(_parse(path.read_text(encoding="utf-8")))
    for endpoint, (password, source, withheld) in row.expect.items():
        got = resolved[endpoint]
        assert (got.password, got.source.split(":")[0] if ":" not in source else got.source, got.withheld) == (
            password,
            source.split(":")[0] if ":" not in source else source,
            withheld,
        ), f"[{row.review}] {endpoint}: {got}"


def test_every_row_cites_its_review():
    assert all(
        row.review and ("beta." in row.review or "upgrade" in row.review or "pair" in row.review)
        for row in ROWS.values()
    )


def test_the_matrix_has_every_shape_the_four_reviews_named():
    """The shapes by review, so a row cannot be deleted quietly: beta.9 (inherit + typed is table 2), the extra server without a key, the primary moved with D2 pinned; beta.10 the
    unchecked share, the rotation with kea6/d2 pinned, the extra server's v6/d2 on other hosts, empty vs absent api6_pass."""
    cited = " ".join(row.review for row in ROWS.values())
    for needle in (
        "primary moved",
        "extra server without a key",
        "unchecked box",
        "rotated while [kea6]",
        "v6 endpoint on another host",
        "D2 endpoint",
        "api6_pass =",
        "absent `api6_pass`",
        "Kea6 with Inherit",
        "Jen's database moved",
    ):
        assert needle in cited, needle


class TestTheDestinationGuardSeesEveryEndpoint:
    """U5: an admin's write of ANY place Jen sends a credential is refused at the writer, byte-identical; the investigation guard keeps the four identity keys."""

    @pytest.fixture
    def cfgpath(self, tmp_path, monkeypatch):
        path = tmp_path / "jen.config"
        path.write_text(
            BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi6_url = https://b:8006\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(extensions, "CONFIG_FILE", str(path))
        monkeypatch.setattr(app_config, "reload", lambda: None)
        return path

    @staticmethod
    def _as(role):
        from flask import Flask
        from flask_login import LoginManager, UserMixin, login_user

        class _U(UserMixin):
            id = "1"

        _U.role = role
        app = Flask(__name__)
        app.secret_key = "t"
        LoginManager(app).user_loader(lambda _i: _U())
        ctx = app.test_request_context("/")
        ctx.push()
        login_user(_U())
        return ctx

    @pytest.mark.parametrize(
        "change",
        [
            [("kea6", "api_url", "https://k6:8006")],
            [("d2", "api_url", "https://d2:53001")],
            [("kea_db", "host", "dbx")],
            [("kea6_db", "host", "dbx")],
            [("jen_db", "host", "jhx")],
            [("kea_server_2", "api6_url", "https://elsewhere:8006")],
            [("kea_server_2", "api_d2_url", "https://elsewhere:53001")],
        ],
        ids=lambda c: f"{c[0][0]}.{c[0][1]}",
    )
    def test_an_admin_is_refused_byte_identical(self, cfgpath, change):
        before = cfgpath.read_bytes()
        ctx = self._as("admin")
        try:
            with pytest.raises(ConfigChangeRefused, match="superadmin's setting"):
                app_config.write_values(change)
        finally:
            ctx.pop()
        assert cfgpath.read_bytes() == before

    def test_the_destination_view_names_every_endpoint_and_the_identity_view_does_not(self):
        from jen import config

        parser = _parse(
            BASE
            + "[kea6]\napi_url = https://a:8006\n[kea_server_2]\napi_url = https://b:8000\napi6_url = https://b:8006\n"
        )
        destination, identity = config.destination_view(parser), config.identity_view(parser)
        assert destination["dest:kea6"] == "https://a:8006" and destination["dest:server_2_v6"] == "https://b:8006"
        assert destination["dest:kea_db"] == "db1:3306" and destination["dest:jen_db"] == "jh:3306"
        assert not any(k.startswith("dest:") for k in identity), "the investigation guard keeps its four identity keys"
        assert set(identity) == {"1", "2", config.MODE_KEY}

    def test_the_destination_guard_is_registered_and_the_investigation_guard_is_not_on_it(self):
        from jen import config
        from jen.services import investigation_logging as inv

        assert access.identity_change_needs_superadmin in config._destination_guards
        assert inv.identity_guard not in config._destination_guards

    def test_the_destination_guard_runs_before_the_identity_guards(self):
        import inspect

        from jen import config

        src = inspect.getsource(config.AppConfig._check_identity)
        assert src.index("_run_destination_guards") < src.index("_run_identity_guards")

    def test_a_guard_that_raises_refuses_the_write(self, cfgpath, monkeypatch):
        from jen import config

        monkeypatch.setattr(config, "_destination_guards", [lambda before, after: 1 / 0])
        before = cfgpath.read_bytes()
        with pytest.raises(ConfigChangeRefused, match="could not check who may change"):
            app_config.write_values([("kea6", "api_url", "https://k6:8006")])
        assert cfgpath.read_bytes() == before


# ── table 2 (CI) ──────────────────────────────────────────────────────────────────────────────────────────────────────────

SEVEN_FORMS = {
    "save-kea": {"api_url": "https://elsewhere:8000", "api_user": "u4", "connection_mode": "ca"},
    "save-kea6": {"api_url": "https://elsewhere:8006"},
    "save-d2": {"api_url": "https://elsewhere:53001"},
    "save-kea-db": {"host": "elsewhere-db", "user": "du", "database": "kea"},
    "save-jen-db": {"host": "elsewhere-db", "user": "ju", "database": "jen"},
}


def _extra_server_body(url="https://elsewhere:8000", password="", share="0"):
    keys = [
        "extra_id[]",
        "extra_name[]",
        "extra_role[]",
        "extra_api_url[]",
        "extra_api_user[]",
        "extra_api_pass[]",
        "extra_api6_url[]",
        "extra_api6_user[]",
        "extra_api6_pass[]",
        "extra_ssh_host[]",
        "extra_ssh_user[]",
        "extra_kea_conf[]",
    ]
    row = ["", "peer", "standby", url, "", password, "", "", "", "10.0.0.9", "jen", "/etc/kea/kea-dhcp4.conf"]
    body = {k: [v] for k, v in zip(keys, row, strict=True)}
    body["extra_share_pass[]"] = [share]
    return body


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestTheSevenFormsAreHeldByTheWriterWhoeverPosts:
    """CI: the seven forms with crafted POST bodies as a fresh superadmin, a stale superadmin, an admin and a subnet-scoped admin. A refusal writes nothing."""

    @staticmethod
    def _post(client, form, body):
        url = f"/settings/infrastructure/{form}"
        return client.post(url, data=body, follow_redirects=False)

    @pytest.mark.parametrize("form", [*SEVEN_FORMS, "save-extra-servers"])
    @pytest.mark.parametrize("who", ["admin", "scoped admin"])
    def test_an_admin_and_a_scoped_admin_are_refused_and_nothing_is_written(
        self, client, db, mock_kea, isolated_config, form, who
    ):
        from tests.conftest import restricted_client

        c, _ = restricted_client(
            client,
            db,
            None if who == "admin" else [1],
            role="admin",
            username=f"q180_{form}_{who}".replace(" ", "_")[:40],
        )
        before = _sha(isolated_config)
        body = (
            _extra_server_body(password="typed")
            if form == "save-extra-servers"
            else {**SEVEN_FORMS[form], "api_pass": "typed", "password": "typed"}
        )
        r = c.post(f"/settings/infrastructure/{form}", data=body, follow_redirects=True)
        if form in ("save-kea-db", "save-jen-db"):
            assert b"SuperAdmin access required" in r.data
        else:
            assert b"SuperAdmin access required" in r.data
        assert _sha(isolated_config) == before

    @pytest.mark.parametrize("form", [*SEVEN_FORMS, "save-extra-servers"])
    def test_a_stale_superadmin_is_sent_to_confirm_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, isolated_config, form
    ):
        from datetime import datetime, timedelta, timezone

        with logged_in_client.session_transaction() as sess:
            sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
        before = _sha(isolated_config)
        body = (
            _extra_server_body(password="typed")
            if form == "save-extra-servers"
            else {**SEVEN_FORMS[form], "api_pass": "typed", "password": "typed"}
        )
        r = self._post(logged_in_client, form, body)
        assert r.status_code == 302 and "/auth/reauth" in r.headers["Location"]
        assert _sha(isolated_config) == before

    @pytest.mark.parametrize("form", [*SEVEN_FORMS, "save-extra-servers"])
    def test_a_fresh_superadmin_posting_a_new_endpoint_with_a_blank_password_is_refused_and_nothing_is_written(
        self, logged_in_client, db, mock_kea, isolated_config, form
    ):
        before = _sha(isolated_config)
        if form == "save-extra-servers":
            # an existing server moved with no password typed: the writer's own rule, whatever the form said
            from tests.test_extra_servers import _seed

            _seed((2, {"api_url": "https://s2-a:8000", "api_pass": "P2", "name": "peer", "ssh_host": "10.0.0.9"}))
            before = _sha(isolated_config)
            body = _extra_server_body(url="https://elsewhere:8000")
            body["extra_id[]"] = ["2"]
        else:
            body = {**SEVEN_FORMS[form]}
        r = logged_in_client.post(f"/settings/infrastructure/{form}", data=body, follow_redirects=True)
        assert b"SuperAdmin access required" not in r.data
        assert _sha(isolated_config) == before, f"{form}: a blank password for a new endpoint wrote something"

    @pytest.mark.parametrize("form", list(SEVEN_FORMS))
    def test_a_fresh_superadmin_who_types_the_password_is_written(
        self, logged_in_client, db, mock_kea, isolated_config, form
    ):
        before = _sha(isolated_config)
        body = {**SEVEN_FORMS[form], "api_pass": "typed", "password": "typed"}
        self._post(logged_in_client, form, body)
        assert _sha(isolated_config) != before, f"{form}: a typed password for a new endpoint was refused"

    def test_a_crafted_extra_server_that_shares_and_types_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        before = _sha(isolated_config)
        r = logged_in_client.post(
            "/settings/infrastructure/save-extra-servers",
            data=_extra_server_body(password="typed", share="1"),
            follow_redirects=True,
        )
        assert b"Choose one for the API password" in r.data and _sha(isolated_config) == before
