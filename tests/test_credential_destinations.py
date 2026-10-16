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


NL = chr(10)
DIRECT = BASE.replace("[kea]" + NL, "[kea]" + NL + "connection_mode = direct" + NL, 1)


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
    # ── the mode switch exempts only what the mode itself moves (Q182, X1: a row for each purpose the exemption could be used for) ────────────────────────────────────
    "a_mode_switch_with_derived_urls_on_the_same_control_agent": Row(
        "beta.12 second pass (Q181): direct -> CA gives a daemon with its own password the Control Agent's address - not a move the Kea API form can type",
        DIRECT + "[kea6]" + NL + "api_pass = K6" + NL,
        _set("kea", "connection_mode", "ca"),
        expect={"kea6": ("K6", "own", "")},
    ),
    "a_mode_switch_with_an_explicit_kea6_url_on_another_host": Row(
        "beta.12 review (Q182) P2: the same flip used to carry a NEW explicit address along - the exemption was the whole flip, not the derived addresses",
        DIRECT + "[kea6]" + NL + "api_pass = K6" + NL,
        _all(_set("kea", "connection_mode", "ca"), _set("kea6", "api_url", "https://k6:8006")),
        refused=True,
    ),
    "a_mode_switch_with_an_explicit_kea6_url_on_another_host_and_the_password_typed": Row(
        "beta.12 review (Q182): ... typed, it is the superadmin's act",
        DIRECT + "[kea6]" + NL + "api_pass = K6" + NL,
        _all(
            _set("kea", "connection_mode", "ca"),
            _set("kea6", "api_url", "https://k6:8006"),
            _set("kea6", "api_pass", "K6B"),
        ),
        typed={"kea6"},
        expect={"kea6": ("K6B", "own", "")},
    ),
    "a_mode_switch_to_a_new_control_agent_host_with_a_saved_password_daemon_untyped": Row(
        "beta.12 review (Q182) P2: direct -> CA while the Control Agent's address is a NEW host - the daemon's saved password would ride to it",
        DIRECT + "[kea6]" + NL + "api_pass = K6" + NL,
        _all(
            _set("kea", "connection_mode", "ca"), _set("kea", "api_url", "https://z:8000"), _set("kea", "api_pass", "N")
        ),
        typed={"kea"},
        refused=True,
    ),
    "a_mode_switch_to_a_new_control_agent_host_with_the_daemons_password_typed": Row(
        "beta.12 review (Q182): ... typed for the daemon as well",
        DIRECT + "[kea6]" + NL + "api_pass = K6" + NL,
        _all(
            _set("kea", "connection_mode", "ca"),
            _set("kea", "api_url", "https://z:8000"),
            _set("kea", "api_pass", "N"),
            _set("kea6", "api_pass", "K6B"),
        ),
        typed={"kea", "kea6"},
        expect={"kea6": ("K6B", "own", "")},
    ),
    # ── a direct-socket removal and the next write (S4b), and two refusals nothing pinned (S7, S7b) ────────────────────────────────────────────────────────────────────
    "a_removed_direct_socket_leaves_user_and_password_and_the_next_address_is_a_move": Row(
        "beta.12 review (Q182) S4b: remove_direct_socket for dhcp6 in direct mode leaves the user and password with no address; giving it one later, untyped, is the first-address move",
        DIRECT + "[kea6]" + NL + "api_user = x" + NL + "api_pass = K6" + NL,
        _set("kea6", "api_url", "https://elsewhere:8006"),
        refused=True,
    ),
    "a_servers_ipv6_password_equal_to_the_primarys_on_another_host_untyped": Row(
        "beta.12 review (Q182) S7: a pair of endpoints on two hosts sharing the primary's password through a server's IPv6 row",
        BASE + "[kea_server_2]" + NL + "api_url = https://b:8000" + NL + "api_pass = P" + NL,
        _all(_set("kea_server_2", "api6_url", "https://c:8006"), _set("kea_server_2", "api6_pass", "S")),
        refused=True,
    ),
    "a_servers_saved_d2_password_given_its_first_address_untyped": Row(
        "beta.12 review (Q182) S7b: a server's D2 password saved with no address, then given one",
        DIRECT
        + "[kea_server_2]"
        + NL
        + "api_url = https://b:8004"
        + NL
        + "api_pass = P"
        + NL
        + "api_d2_pass = D2P"
        + NL,
        _set("kea_server_2", "api_d2_url", "https://b2:53001"),
        refused=True,
    ),
    "an_explicit_no_password_for_a_daemon_on_another_host": Row(
        "beta.10 second pass (Q180): a Kea with no authentication on another host - `api_pass =` is an answer, nothing is withheld",
        BASE,
        _all(_set("kea6", "api_url", "https://k6:8006"), _set("kea6", "api_pass", "")),
        expect={"kea6": ("", "none", "")},
    ),
    "a_legacy_extra_server_converted_by_the_upgrade_then_an_unrelated_write": Row(
        "upgrade: the conversion left the primary's password in a peer on another host (marked); an unrelated write is not refused for it",
        BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = S\napi_pass_shared = 1\n",
        _set("kea", "api_user", "renamed"),
        expect={"server_2": ("S", "own", "")},
    ),
    "a_port_change_on_an_ipv6_database_host": Row(
        "beta.11 second pass (Q180): an IPv6 literal database host, its port changed - not a move",
        BASE.replace("host = db1", "host = ::1"),
        _set("kea_db", "port", "3307"),
        expect={"kea_db": ("KDB", "own", "")},
    ),
    "a_saved_password_given_its_first_address_untyped": Row(
        "beta.11 review (Q181) P1: a saved password with no previous address gains its first one without the move check",
        DIRECT + "[kea6]" + NL + "api_pass = K6" + NL,
        _set("kea6", "api_url", "https://k6:8006"),
        refused=True,
    ),
    "the_same_with_the_password_typed": Row(
        "beta.11 review (Q181): the first address with the password typed in this request",
        DIRECT + "[kea6]" + NL + "api_pass = K6" + NL,
        _all(_set("kea6", "api_url", "https://k6:8006"), _set("kea6", "api_pass", "K6B")),
        typed={"kea6"},
        expect={"kea6": ("K6B", "own", "")},
    ),
    "a_new_server_with_a_typed_password_and_its_first_address": Row(
        "beta.11 review (Q181): first-time configuration passes because the password is typed by construction",
        BASE,
        _add_server(2, api_url="https://b:8000", api_pass="P2"),
        typed={"server_2"},
        expect={"server_2": ("P2", "own", "")},
    ),
    "no_password_before_then_an_address_is_free": Row(
        "beta.11 review (Q181): a section that had no password gains an address freely",
        DIRECT + "[kea6]" + NL + "api_user = x" + NL,
        _set("kea6", "api_url", "https://k6:8006"),
        expect={"kea6": ("", "none", "kea")},
    ),
    "an_extra_servers_blank_ipv6_url_with_its_own_password": Row(
        "beta.11 review (Q181) P1: a present-blank api6_url is no endpoint - the transport may not fall back to the v4 url",
        BASE + "[kea_server_2]" + NL + "api_url = https://b:8000" + NL + "api_pass = P2" + NL,
        _all(_set("kea_server_2", "api6_url", ""), _set("kea_server_2", "api6_pass", "P6")),
        typed={"server_2_v6"},
        expect={"server_2_v6": ("P6", "own", "")},
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


def test_every_continue_in_move_refusal_names_the_row_that_uses_it():
    """Q182 (X1): an exemption in the rule is a row in this file that uses it for a DIFFERENT purpose, before it is code. Each `continue` in `move_refusal` carries `# row: <name>`
    and the name is a row of this matrix."""
    import ast
    import pathlib
    import re

    src = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "services" / "credentials.py").read_text(
        encoding="utf-8"
    )
    lines = src.splitlines()
    function = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "move_refusal")
    skips = [n for n in ast.walk(function) if isinstance(n, ast.Continue)]
    assert len(skips) >= 4
    for node in skips:
        match = re.search(r"#\s*row:\s*(\w+)", lines[node.lineno - 1])
        assert match, f"credentials.py line {node.lineno}: a `continue` in move_refusal names no row"
        assert match.group(1) in ROWS, f"credentials.py line {node.lineno}: row {match.group(1)!r} is not in the matrix"


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


class TestADirectSocketKeepsWhatWorkedWhenTheHostChangesSpelling:
    """Q180 second pass (P2-2): `Set up direct socket` points a server at the address its SSH host gave (an IP literal); the resolver compares hosts as written, so a daemon that
    inherited the Kea API's password by NAME would lose it by number. The edit writes the password as the daemon's own (a marked copy) instead of removing the keys."""

    def _edit(self, ini, server, service, url):
        from jen.routes.settings import infrastructure as infra

        parser = _parse(ini)
        fn, changed = infra._direct_socket_edit(server, service, url, server["api_user"], server["api_pass"])
        fn(parser)
        return parser, changed

    def test_dhcp6_set_up_by_ip_on_a_primary_named_by_hostname_keeps_its_password(self):
        ini = BASE.replace("https://a:8000", "http://kea-a.lan:8000")
        server = {"id": 1, "api_user": "u", "api_pass": "S", "api_url": "http://kea-a.lan:8000"}
        parser, changed = self._edit(ini, server, "dhcp6", "http://10.0.0.5:8006")
        r = cred.resolve(parser)
        assert (r["kea6"].password, r["kea6"].withheld) == ("S", "") and parser.get("kea6", "api_pass_shared") == "1"
        assert r["kea6"].user == "u", (
            "the second pass (P2-2): the user comes with the password - a copy without it would fail Basic authentication"
        )
        assert any("kept: the address changed spelling" in c for c in changed)

    def test_the_same_host_spelled_the_same_way_still_just_inherits(self):
        server = {"id": 1, "api_user": "u", "api_pass": "S", "api_url": "https://a:8000"}
        parser, _changed = self._edit(BASE, server, "dhcp6", "https://a:8006")
        assert not parser.has_option("kea6", "api_pass") and cred.resolve(parser)["kea6"].password == "S"

    def test_a_dhcp4_switch_to_an_ip_keeps_a_pinned_kea6_that_used_the_hostname(self):
        ini = BASE.replace("https://a:8000", "http://kea-a.lan:8000") + "[kea6]\napi_url = http://kea-a.lan:8006\n"
        server = {"id": 1, "api_user": "u", "api_pass": "S", "api_url": "http://kea-a.lan:8000"}
        parser, _changed = self._edit(ini, server, "dhcp4", "http://10.0.0.5:8004")
        assert cred.resolve(parser)["kea6"].password == "S" and cred.resolve(parser)["kea6"].withheld == ""
        assert cred.resolve(parser)["kea6"].user == "u"


class TestTheFormsCanSayNoPassword:
    """CI: the Kea6, D2 and extra-server forms write an EXPLICIT blank for a Kea with no authentication - `resolve` reads it as none and nothing is withheld."""

    def test_kea6_with_no_password_on_another_host_is_written_and_resolves_to_none(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        r = logged_in_client.post(
            "/settings/infrastructure/save-kea6",
            data={"api_url": "https://k6:8006", "no_api_pass": "1"},
            follow_redirects=True,
        )
        assert b"different host from the Kea API" not in r.data
        disk = _forms._disk(isolated_config)
        assert disk.get("kea6", "api_url") == "https://k6:8006" and disk.get("kea6", "api_pass") == ""
        ep = cred.resolve(disk)["kea6"]
        assert (ep.password, ep.withheld) == ("", "")

    def test_d2_and_a_typed_password_together_are_two_answers(self, logged_in_client, db, mock_kea, isolated_config):
        before = isolated_config.read_bytes()
        r = logged_in_client.post(
            "/settings/infrastructure/save-d2",
            data={"api_url": "https://d2:53001", "no_api_pass": "1", "api_pass": "x"},
            follow_redirects=True,
        )
        assert b"Choose one for the D2 API password" in r.data and isolated_config.read_bytes() == before

    def test_an_extra_server_row_with_no_password_is_written_blank_and_not_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        body = _extra_server_body(url="https://elsewhere:8000")
        body["extra_no_pass[]"] = ["1"]
        logged_in_client.post("/settings/infrastructure/save-extra-servers", data=body, follow_redirects=True)
        disk = _forms._disk(isolated_config)
        assert disk.get("kea_server_2", "api_pass") == ""
        assert cred.resolve(disk)["server_2"].withheld == ""

    def test_the_box_and_a_typed_password_on_a_row_are_two_answers(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        before = isolated_config.read_bytes()
        body = _extra_server_body(url="https://elsewhere:8000", password="typed")
        body["extra_no_pass[]"] = ["1"]
        r = logged_in_client.post("/settings/infrastructure/save-extra-servers", data=body, follow_redirects=True)
        assert b"Choose one for the API password" in r.data and isolated_config.read_bytes() == before


class TestTheWizardsFirstStepDoesNotSendASavedPasswordToANewHost:
    """CI (P2-4): the connection step tests the address it is given; the saved Kea API and database passwords go only to the host they were saved for."""

    def test_a_new_host_with_blank_passwords_is_tested_with_none(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen.services import setup_wizard

        seen = {}

        def kea_conn(url, user, password, **k):
            seen["kea"] = (url, password)
            return {"ok": False, "attempts": [], "error": "stub", "url": url, "mode": "ca"}

        def kea_db(host, user, password, name, **k):
            seen["db"] = (host, password)
            return False, "stub"

        monkeypatch.setattr(extensions, "KEA_API_URL", "http://old-kea:8000")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "SAVED")
        monkeypatch.setattr(extensions, "KEA_DB_HOST", "old-db")
        monkeypatch.setattr(extensions, "KEA_DB_PASS", "SAVEDDB")
        monkeypatch.setattr(setup_wizard, "test_kea_connection", kea_conn)
        monkeypatch.setattr(setup_wizard, "test_kea_db", kea_db)
        logged_in_client.post(
            "/setup/connect",
            data={
                "api_url": "http://new-kea:8000",
                "api_user": "u",
                "kea_db_host": "new-db",
                "kea_db_user": "k",
                "kea_db_name": "kea",
            },
        )
        assert seen["kea"] == ("http://new-kea:8000", "") and seen["db"] == ("new-db", "")

    def test_the_saved_host_is_still_tested_with_the_saved_passwords(self, logged_in_client, db, mock_kea, monkeypatch):
        from jen.services import setup_wizard

        seen = {}

        def kea_conn(url, user, password, **k):
            seen["kea"] = (url, password)
            return {"ok": False, "attempts": [], "error": "stub", "url": url, "mode": "ca"}

        monkeypatch.setattr(extensions, "KEA_API_URL", "http://kea-a:8000")
        monkeypatch.setattr(extensions, "KEA_API_PASS", "SAVED")
        monkeypatch.setattr(setup_wizard, "test_kea_connection", kea_conn)
        monkeypatch.setattr(setup_wizard, "test_kea_db", lambda *a, **k: (False, "stub"))
        logged_in_client.post(
            "/setup/connect",
            data={
                "api_url": "http://kea-a:9000",
                "api_user": "u",
                "kea_db_host": "d",
                "kea_db_user": "k",
                "kea_db_name": "kea",
            },
        )
        assert seen["kea"] == ("http://kea-a:9000", "SAVED")


class TestTheServerRowsCanSayNoPasswordForTheirIpv6AndD2Endpoints:
    """CI, Q181 V4: `extra_api6_no_pass[]` and `extra_d2_no_pass[]` write an explicit blank beside the password inputs."""

    URL = "/settings/infrastructure/save-extra-servers"

    def _body(self, **over):
        body = _extra_server_body(url="https://elsewhere:8000", password="P2")
        body["extra_ssh_host[]"] = ["10.0.0.9"]
        body.update(over)
        return body

    def test_an_ipv6_endpoint_elsewhere_with_the_box_is_saved_blank_and_nothing_is_withheld(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        body = self._body(**{"extra_api6_url[]": ["https://v6host:8006"], "extra_api6_no_pass[]": ["1"]})
        logged_in_client.post(self.URL, data=body, follow_redirects=True)
        disk = _forms._disk(isolated_config)
        assert disk.get("kea_server_2", "api6_pass") == ""
        ep = cred.resolve(disk)["server_2_v6"]
        assert (ep.url, ep.password, ep.withheld) == ("https://v6host:8006", "", "")

    def test_an_ipv6_endpoint_elsewhere_without_a_password_or_the_box_is_refused(
        self, logged_in_client, db, mock_kea, isolated_config
    ):
        before = isolated_config.read_bytes()
        body = self._body(**{"extra_api6_url[]": ["https://v6host:8006"]})
        r = logged_in_client.post(self.URL, data=body, follow_redirects=True)
        assert b"IPv6 address" in r.data and isolated_config.read_bytes() == before

    def test_the_box_and_a_typed_ipv6_password_are_two_answers(self, logged_in_client, db, mock_kea, isolated_config):
        before = isolated_config.read_bytes()
        body = self._body(
            **{"extra_api6_url[]": ["https://v6host:8006"], "extra_api6_pass[]": ["x"], "extra_api6_no_pass[]": ["1"]}
        )
        r = logged_in_client.post(self.URL, data=body, follow_redirects=True)
        assert b"Choose one for the IPv6 API password" in r.data and isolated_config.read_bytes() == before

    def test_a_d2_socket_with_the_box_is_saved_blank(self, logged_in_client, db, mock_kea, isolated_config):
        from tests.test_extra_servers import _seed

        _seed(
            (
                2,
                {
                    "api_url": "https://s2:8000",
                    "api_pass": "P2",
                    "name": "peer",
                    "ssh_host": "10.0.0.9",
                    "api_d2_url": "https://d2host:53001",
                    "api_d2_pass": "D",
                },
            )
        )
        body = self._body(
            **{
                "extra_id[]": ["2"],
                "extra_api_url[]": ["https://s2:8000"],
                "extra_api_pass[]": [""],
                "extra_d2_no_pass[]": ["1"],
            }
        )
        body["extra_name[]"] = ["peer"]
        logged_in_client.post(self.URL, data=body, follow_redirects=True)
        assert _forms._disk(isolated_config).get("kea_server_2", "api_d2_pass") == ""


class TestTheD2BoxCanBeUnticked:
    """CI (second pass P3-7): the D2 "no password" box on a server row can be ticked AND unticked."""

    URL = "/settings/infrastructure/save-extra-servers"

    def test_untick_returns_the_endpoint_to_inherit(self, logged_in_client, db, mock_kea, isolated_config):
        from tests.test_extra_servers import _seed

        _seed(
            (
                2,
                {
                    "api_url": "https://s2:8000",
                    "api_pass": "P2",
                    "name": "peer",
                    "ssh_host": "10.0.0.9",
                    "api_d2_url": "https://s2:53001",
                    "api_d2_pass": "",
                },
            )
        )
        body = _extra_server_body(url="https://s2:8000", password="")
        body["extra_id[]"] = ["2"]
        body["extra_name[]"] = ["peer"]
        body["extra_ssh_host[]"] = ["10.0.0.9"]
        body["extra_d2_no_pass[]"] = ["0"]
        logged_in_client.post(self.URL, data=body, follow_redirects=True)
        disk = _forms._disk(isolated_config)
        assert not disk.has_option("kea_server_2", "api_d2_pass")


class TestTheCopyButtonActsOnlyOnACopy:
    """Q182 (X5b, subagent S8): "Copy the primary's again" is bound to its marker (`api_pass_shared = 1`). A password the server OWNS is not the primary's to overwrite, whoever posts."""

    URL = "/settings/infrastructure/extra-server/2/copy-primary-password"

    def _server_2(self, path, shared):
        p = _forms._disk(path)
        p.add_section("kea_server_2")
        p.set("kea_server_2", "name", "standby")
        p.set("kea_server_2", "api_url", "https://kea-b:8000")
        p.set("kea_server_2", "api_pass", "P")
        if shared:
            p.set("kea_server_2", "api_pass_shared", "1")
        with open(path, "w") as f:
            p.write(f)
        app_config.reload()

    def test_an_own_password_is_refused_and_nothing_is_written(self, logged_in_client, db, mock_kea, isolated_config):
        self._server_2(isolated_config, shared=False)
        before = isolated_config.read_bytes()
        r = logged_in_client.post(self.URL, follow_redirects=True)
        assert b"password is its own" in r.data
        assert isolated_config.read_bytes() == before

    def test_a_copy_is_copied_again(self, logged_in_client, db, mock_kea, isolated_config):
        self._server_2(isolated_config, shared=True)
        r = logged_in_client.post(self.URL, follow_redirects=True)
        assert b"was copied into that server again" in r.data
        disk = _forms._disk(isolated_config)
        assert disk.get("kea_server_2", "api_pass") == "S" and disk.get("kea_server_2", "api_pass_shared") == "1"

    def test_the_route_checks_the_marker_inside_the_write(self):
        import inspect

        from jen.routes.settings import infrastructure as infra

        source = inspect.getsource(infra.copy_primary_password)
        assert "SHARED_MARKER" in source and "_Own" in source
