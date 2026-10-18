"""
tests/probe/credential_probe.py
───────────────────────────────
v5.69.0-beta.14 (Q183, Y7) - the executing second pass, made permanent.

The adversarial passes that found beta.12's findings, beta.13's and beta.14's did not READ the credential rule - they RAN it: a temporary jen.config, the real `AppConfig.mutate` /
`write_values` / `preflight_identity_change`, `kea.kea_command` with a captured `post`, `credentials.materialise`, `config_merge.credential_refusal`, on configurations built to
make an exemption do something its comment does not say. That is the method, so it is a file: one function per scenario, each returning what it OBSERVED, and `EXPECTED` holds what
the rule says it must be. `tests/test_credential_probe.py` asserts every scenario; `py tests/probe/credential_probe.py` prints the table (and exits 1 on a difference).

A second pass on any change to the credential rule EXTENDS this file with one scenario per exemption used for a purpose its comment does not state, runs it, and reports each finding
with the executed input and the observed output (docs/RELEASE_AUDIT.md, step (n)). Pure: no database, no Kea, no network (`py -m pytest --noconftest tests/test_credential_probe.py`).

Scenario names are `<origin>_<what>`: `b12_` the beta.12 pass, `b13_` the beta.13 pass(es), `q183_` this release. Scenarios that need a Flask request or a database (the copy button, the
form routes, the wizard's HTTP steps) are NOT here; `NOT_PROBED` says where each is pinned instead.
"""

from __future__ import annotations

import configparser
import contextlib
import io
import os
import sys
import tempfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from jen import extensions  # noqa: E402
from jen.config import AppConfig, ConfigChangeRefused, app_config  # noqa: E402
from jen.services import credentials as cred  # noqa: E402
from jen.services import kea  # noqa: E402

BASE = """[kea]
api_url = https://a:8000
api_user = pu
api_pass = PS
[kea_db]
host = db1
user = k
password = KDB
[jen_db]
host = jh
user = j
password = JP
[server]
"""
DIRECT = BASE.replace("[kea]\n", "[kea]\nconnection_mode = direct\n", 1)


def parse(text: str):
    p = configparser.ConfigParser(interpolation=None)
    p.read_string(text)
    return p


class Lab:
    """A temporary jen.config under the real writer: `mutate`/`write_values`/`preflight` as the routes call them, the identity guards (investigation) out of the way, the extensions
    globals put back on exit."""

    def __init__(self, text: str):
        self.text = text

    def __enter__(self):
        self._stack = contextlib.ExitStack()
        self._dir = self._stack.enter_context(tempfile.TemporaryDirectory())
        self.path = os.path.join(self._dir, "jen.config")
        with open(self.path, "w", encoding="utf-8", newline="") as f:
            f.write(self.text)
        snapshot = dict(vars(extensions))
        self._stack.callback(lambda: [setattr(extensions, k, v) for k, v in snapshot.items()])
        self._stack.enter_context(mock.patch.object(extensions, "CONFIG_FILE", self.path))
        if (
            sys.platform == "win32"
        ):  # a scanner or indexer can hold a freshly written file for a moment: `os.replace` then raises PermissionError (the rule is not in question)
            self._stack.enter_context(mock.patch.object(os, "replace", _replace_with_retry(os.replace)))
        self._stack.enter_context(mock.patch.object(app_config, "reload", lambda: None))
        self._stack.enter_context(mock.patch("jen.config._identity_guards", []))
        return self

    def __exit__(self, *exc):
        self._stack.close()

    def read(self):
        with open(self.path, encoding="utf-8") as f:
            return parse(f.read())

    def bytes(self) -> bytes:
        with open(self.path, "rb") as f:
            return f.read()

    def mutate(self, fn, typed=()):
        return outcome(lambda: _retry(lambda: app_config.mutate(fn, reload=False, typed=set(typed))))

    def values(self, items, typed=()):
        return outcome(lambda: _retry(lambda: app_config.write_values(items, reload=False, typed=set(typed))))


def _replace_with_retry(real):
    import time

    def replace(src, dst, *a, **k):
        for attempt in range(6):
            try:
                return real(src, dst, *a, **k)
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.05 * (attempt + 1))

    return replace


def _retry(call):
    """A scanner or indexer on a Windows dev box can hold a freshly written file for a moment: `os.replace` then raises PermissionError. Retried a few times (the rule is not in question)."""
    import time

    for attempt in range(6):
        try:
            return call()
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.05 * (attempt + 1))


def outcome(call) -> str:
    """ "written", or "refused: <which rule>" - the observable of a write. The rule is read from the sentence, so a rewording does not move a scenario but a different RULE does."""
    try:
        call()
    except ConfigChangeRefused as e:
        sentence = str(e)
        for needle, rule in (
            ("first address", "first address"),
            ("moved to a different host", "moved"),
            ("same saved password on different hosts", "pair"),
            ("written without being typed", "not typed"),
        ):
            if needle in sentence:
                return f"refused: {rule}"
        return "refused: " + sentence[:60]
    return "written"


def sends(text: str, name: str):
    """What `kea.kea_command` posts for the endpoint `name`, as [(url, auth)], auth being "no header", "(user, password)" or the tuple - through a captured `post`."""
    cfg = parse(text)
    for section, body in (("jen_db", {"host": "jh"}), ("server", {}), ("kea_db", {"host": "db1"})):
        if not cfg.has_section(section):
            cfg.add_section(section)
            for k, v in body.items():
                cfg.set(section, k, v)
    calls = []

    class _Post:
        exceptions = kea.http.exceptions

        def post(self, url, **kw):
            calls.append((url, kw.get("auth")))

            class _R:
                def raise_for_status(self):
                    pass

                def json(self):
                    return [{"result": 0}]

            return _R()

    snapshot = dict(vars(extensions))
    try:
        servers = AppConfig.derive_kea_servers(cfg, quiet=True)
        AppConfig().apply(cfg)
        service, server = {"kea": ("dhcp4", servers[0]), "kea6": ("dhcp6", None), "d2": ("d2", None)}.get(
            name, (None, None)
        )
        if service is None:  # server_<N>[_v6|_d2]
            number, _, suffix = name.removeprefix("server_").partition("_")
            server = next(s for s in servers if s["id"] == int(number))
            service = {"": "dhcp4", "v6": "dhcp6", "d2": "d2"}[suffix]
        with mock.patch.object(kea, "http", _Post()):
            reply = kea.kea_command("version-get", service, server=server)
    finally:
        for k, v in snapshot.items():
            setattr(extensions, k, v)
    shown = [(u, "no header" if a is kea._NO_AUTH else a) for u, a in calls]
    return shown if shown else f"nothing sent ({str(reply.get('text', ''))[:30]})"


# ═══ beta.12 pass (Q181's second read) ═══════════════════════════════════════════════════════════════════════════════════


def b12_an_own_password_on_another_host_carries_the_primarys_user():
    e = cred.resolve(parse(BASE + "[kea6]\napi_url = https://z:8006\napi_pass = K6\n"))["kea6"]
    return (e.user, e.password, e.source)


def b12_a_direct_socket_by_ip_keeps_the_password_and_the_user():
    from jen.routes.settings import infrastructure as infra

    text = DIRECT.replace("https://a:8000", "http://kea-a.lan:8004")
    server = {"id": 1, "api_user": "pu", "api_pass": "PS", "api_url": "http://kea-a.lan:8004"}
    with Lab(text) as lab:
        fn, _ = infra._direct_socket_edit(server, "dhcp6", "http://10.0.0.5:8006", "pu", "PS")
        result = lab.mutate(fn, typed={"kea6"})
        e = cred.resolve(lab.read())["kea6"]
    return (result, e.user, e.password, e.source, e.withheld)


def b12_a_flip_for_a_password_that_already_went_to_the_parent_is_not_refused():
    text = DIRECT + "[kea6]\napi_url = https://a:8006\napi_pass = K6\n"
    with Lab(text) as lab:
        return lab.mutate(lambda p: (p.remove_option("kea6", "api_url"), p.set("kea", "connection_mode", "ca")))


def b12_an_unreadable_settings_table_is_not_an_absent_row():
    @contextlib.contextmanager
    def broken():
        raise OSError("database down")
        yield  # pragma: no cover

    with mock.patch("jen.models.db.jen_db", broken):
        return cred.beta11_flag()


def b12_the_wizard_saves_what_it_probed_not_a_stale_own_pair():
    from jen.services import setup_wizard

    with Lab(BASE + "[kea6]\napi_user = stale\napi_pass = STALE\n") as lab:
        with mock.patch("jen.models.user.set_global_setting", lambda *a, **k: None):
            error = setup_wizard.enable_v6("https://a:8006", {}, inherit_credentials=True)
        e = cred.resolve(lab.read())["kea6"]
    return (error, e.user, e.password, e.source)


def b12_no_authentication_sends_no_header_and_never_looks_in_netrc():
    got = sends(BASE + "[kea6]\napi_url = https://z:8006\napi_user =\napi_pass =\n", "kea6")
    return (got, kea._NO_AUTH(type("R", (), {"headers": {}})()).headers)


def b12_a_file_that_has_the_marker_is_never_written_by_the_conversion():
    class _Fake:
        path = "jen.config"

        def __init__(self, p):
            self.p, self.writes = p, 0

        def _read_parser(self):
            return self.p

        def mutate(self, *a, **k):
            self.writes += 1

    fake = _Fake(parse(BASE + "[kea_server_2]\napi_url = https://b:8000\n[jen]\ncredential_model = explicit\n"))
    return (cred.materialise(fake), fake.writes)


# ═══ beta.13 pass (the executing walk-through and its second pass) ═════════════════════════════════════════════════════════════


def _no_header(text, name):
    return sends(text, name)


def b13_s1_kea6_on_the_same_host_with_no_password_sends_no_header():
    return _no_header(BASE + "[kea6]\napi_url = https://a:8006\napi_pass =\n", "kea6")


def b13_s1_d2_on_the_same_host_with_no_password_sends_no_header():
    return _no_header(BASE + "[d2]\napi_url = https://a:53001\napi_pass =\n", "d2")


def b13_s1_a_servers_ipv6_endpoint_with_no_password_sends_no_header():
    return _no_header(
        BASE
        + "[kea_server_2]\napi_url = https://b:8000\napi_user = su\napi_pass = SS\napi6_url = https://b:8006\napi6_pass =\n",
        "server_2_v6",
    )


def b13_s1_the_wizards_same_box_no_authentication_saves_no_user_and_sends_no_header():
    from jen.services import setup_wizard

    with Lab(BASE + "[kea6]\napi_user = stale\n") as lab:
        with mock.patch("jen.models.user.set_global_setting", lambda *a, **k: None):
            error = setup_wizard.enable_v6("https://a:8006", {}, no_auth=True)
        saved = lab.read()
        has_user = saved.has_option("kea6", "api_user")
        text = io.StringIO()
        saved.write(text)
    return (error, has_user, _no_header(text.getvalue(), "kea6"))


def b13_s2_a_socket_set_up_by_ip_on_a_primary_named_by_hostname_is_read_with_the_probed_pair():
    from jen.routes.settings import infrastructure as infra

    text = DIRECT.replace("https://a:8000", "http://kea-a.lan:8004")
    server = {"id": 1, "api_user": "pu", "api_pass": "PS", "api_url": "http://kea-a.lan:8004"}
    with Lab(text) as lab:
        fn, _ = infra._direct_socket_edit(server, "dhcp6", "http://10.0.0.5:8006", "pu", "PS")
        lab.mutate(fn, typed={"kea6"})
        buf = io.StringIO()
        lab.read().write(buf)
    return sends(buf.getvalue(), "kea6")


def b13_s3_the_forms_default_is_the_resolvers_answer_for_a_withheld_endpoint():
    from jen.routes.settings import infrastructure as infra

    server = {"id": 1, "api_user": "pu", "api_pass": "PS", "api_url": "http://kea-a.lan:8004"}
    with Lab(DIRECT.replace("https://a:8000", "http://kea-a.lan:8004")):
        return (
            infra._daemon_creds(server, "dhcp6", "http://10.0.0.5:8006"),
            infra._daemon_creds(server, "dhcp6", "http://kea-a.lan:8006"),
        )


def b13_s4b_a_removed_socket_leaves_the_password_and_the_next_address_is_a_move():
    text = DIRECT + "[kea6]\napi_url = https://b:8006\napi_user = x\napi_pass = K6\n"
    with Lab(text) as lab:
        removed = lab.mutate(lambda p: p.remove_option("kea6", "api_url"), typed={"kea6"})
        kept = lab.read().has_option("kea6", "api_pass")
        again = lab.mutate(lambda p: p.set("kea6", "api_url", "https://elsewhere:8006"))
    return (removed, kept, again)


def b13_s5_a_blank_kea6_database_host_opens_nothing():
    import pymysql

    from jen.models import db

    snapshot = dict(vars(extensions))
    try:
        AppConfig().apply(parse(BASE + "[kea6_db]\nhost =\n"))
        with (
            mock.patch.object(db, "_make_kea6_pool", side_effect=AssertionError("a pool was made")),
            mock.patch.object(db, "_kea6_pool", None),
        ):
            try:
                db.get_kea6_db()
            except pymysql.err.OperationalError as e:
                return ("no connection", "no Kea6 database" in str(e))
    finally:
        for k, v in snapshot.items():
            setattr(extensions, k, v)
    return "a connection was offered"


def b13_s5_a_withheld_kea6_database_password_opens_nothing():
    import pymysql

    from jen.models import db

    snapshot = dict(vars(extensions))
    try:
        AppConfig().apply(parse(BASE + "[kea6_db]\nhost = db2\n"))
        withheld = extensions.KEA6_DB_WITHHELD
        with (
            mock.patch.object(db, "_make_kea6_pool", side_effect=AssertionError("a pool was made")),
            mock.patch.object(db, "_kea6_pool", None),
        ):
            try:
                db.get_kea6_db()
            except pymysql.err.OperationalError:
                return (withheld, "no connection")
    finally:
        for k, v in snapshot.items():
            setattr(extensions, k, v)
    return (withheld, "a connection was offered")


def b13_s6_a_legacy_blank_is_converted_and_a_marked_blank_is_not():
    legacy = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi6_url = https://c:8006\napi6_pass =\n"
    return (
        cred.pending_conversions(parse(legacy)),
        cred.pending_conversions(parse(legacy + "[jen]\ncredential_model = explicit\n")),
    )


def b13_s7_a_servers_ipv6_password_equal_to_the_primarys_on_another_host_is_refused():
    text = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n"
    with Lab(text) as lab:
        return lab.mutate(
            lambda p: (p.set("kea_server_2", "api6_url", "https://c:8006"), p.set("kea_server_2", "api6_pass", "PS"))
        )


def b13_s7b_a_servers_saved_d2_password_given_its_first_address_is_refused():
    text = DIRECT + "[kea_server_2]\napi_url = https://b:8004\napi_pass = P\napi_d2_pass = D2P\n"
    with Lab(text) as lab:
        return lab.mutate(lambda p: p.set("kea_server_2", "api_d2_url", "https://b2:53001"))


def b13_s9_a_restored_legacy_file_whose_database_says_converted_is_converted_not_marked():
    class _Fake:
        path = "jen.config"

        def __init__(self, p):
            self.p = p

        def _read_parser(self):
            q = configparser.ConfigParser(interpolation=None)
            q.read_dict({s: dict(self.p.items(s)) for s in self.p.sections()})
            return q

        def mutate(self, fn, reload=True, typed=None):
            q = self._read_parser()
            fn(q)
            self.p = q

    fake = _Fake(parse(BASE + "[kea_server_2]\napi_url = https://b:8000\n"))
    done = cred.materialise(fake, already_converted=True)
    return (done, fake.p.get("kea_server_2", "api_pass", fallback=None), fake.p.get("jen", "credential_model"))


def b13_p2_a_bridge_file_whose_blank_is_betas_answer_is_not_filled_in():
    class _Fake:
        path = "jen.config"

        def __init__(self, p):
            self.p = p

        def _read_parser(self):
            q = configparser.ConfigParser(interpolation=None)
            q.read_dict({s: dict(self.p.items(s)) for s in self.p.sections()})
            return q

        def mutate(self, fn, reload=True, typed=None):
            q = self._read_parser()
            fn(q)
            self.p = q

    fake = _Fake(
        parse(BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\napi6_url = https://c:8006\napi6_pass =\n")
    )
    done = cred.materialise(fake, already_converted=True)
    return (done, fake.p.get("kea_server_2", "api6_pass"))


def b13_p2_a_switch_back_by_name_is_refused_before_the_kea_host_is_touched():
    text = (
        DIRECT.replace("https://a:8000", "http://10.0.0.5:8001")
        + "direct_prev_api_url = http://kea-a.lan:8000\n[kea6]\napi_pass = K6\n"
    )

    def back(p):
        p.set("kea", "api_url", "http://kea-a.lan:8000")
        p.set("kea", "connection_mode", "ca")

    with Lab(text) as lab:
        untyped = outcome(lambda: app_config.preflight_identity_change(back, typed={"kea"}))
        typed = outcome(lambda: app_config.preflight_identity_change(back, typed={"kea", "kea6"}))
        untouched = lab.bytes() == text.encode()
    return (untyped, typed, untouched)


def b13_p2_the_installer_merge_refuses_a_moved_api_url_with_the_saved_password():
    import importlib.util

    spec = importlib.util.spec_from_file_location("config_merge", os.path.join(ROOT, "tools", "config_merge.py"))
    cm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cm)
    live = BASE
    moved = BASE.replace("https://a:8000", "https://new:8000")
    typed = moved.replace("api_pass = PS", "api_pass = NEW")
    return (
        "moved to a different host" in cm.credential_refusal(live, live, moved, moved),
        cm.credential_refusal(live, live, typed, typed),
    )


def b13_p2_an_invalid_marker_converts_nothing_and_writes_nothing():
    class _Fake:
        path = "jen.config"

        def __init__(self, p):
            self.p, self.writes = p, 0

        def _read_parser(self):
            return self.p

        def mutate(self, *a, **k):
            self.writes += 1

    fake = _Fake(parse(BASE + "[kea_server_2]\napi_url = https://b:8000\n[jen]\ncredential_model = Explicit\n"))
    return (cred.model_marker(fake.p), cred.materialise(fake), fake.writes)


# ═══ this release (Q183) ═════════════════════════════════════════════════════════════════════════════════════════════════════


def q183_y1_a_password_typed_for_another_host_then_unaddressed_then_flipped_is_refused():
    with Lab(DIRECT) as lab:
        typed = lab.values([("kea6", "api_url", "https://b:8006"), ("kea6", "api_pass", "K6")], typed={"kea6"})
        removed = lab.mutate(lambda p: p.remove_option("kea6", "api_url"))
        before = lab.bytes()
        flipped = lab.values([("kea", "connection_mode", "ca")])
        unchanged = lab.bytes() == before
    return (typed, removed, flipped, unchanged)


def q183_y2_a_new_password_copied_into_an_untyped_server_is_refused():
    text = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n"
    with Lab(text) as lab:
        return lab.mutate(
            lambda p: (p.set("kea", "api_pass", "N"), p.set("kea_server_2", "api_pass", "N")), typed={"kea"}
        )


def q183_y2_a_section_renumbered_in_one_write_with_its_password_is_refused():
    text = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n"

    def renumber(p):
        p.remove_section("kea_server_2")
        p.add_section("kea_server_3")
        p.set("kea_server_3", "api_url", "https://b:8000")
        p.set("kea_server_3", "api_pass", "P")

    with Lab(text) as lab:
        return lab.mutate(renumber)


def q183_y2_the_same_value_saved_again_is_not_a_change():
    text = BASE + "[kea_server_2]\napi_url = https://b:8000\napi_pass = P\n"
    with Lab(text) as lab:
        return lab.mutate(lambda p: (p.set("kea_server_2", "api_pass", "P"), p.set("kea_server_2", "name", "x")))


def q183_y5_a_primary_with_no_password_still_sends_its_user_and_so_does_a_daemon_on_its_host():
    text = BASE.replace("api_pass = PS\n", "") + "[kea6]\napi_url = https://a:8006\n"
    return (sends(text, "kea"), sends(text, "kea6"))


def q183_y3_a_marker_is_read_and_cleared():
    p = parse(
        BASE
        + "[kea_server_2]\napi_url = https://b:8000\napi6_url = https://b:8006\napi6_pass = X\napi6_pass_shared = 1\n"
    )
    before = cred.shared_copies(p)
    cred.clear_shared(p, "server_2_v6")
    return (sorted(before), sorted(cred.shared_copies(p)))


def q183_y6_enable_v6_answers_a_failed_write_with_text():
    from jen.services import setup_wizard

    class _Config:
        def mutate(self, fn, typed=None, **k):
            raise OSError(30, "Read-only file system")

    with (
        mock.patch("jen.config.app_config", _Config()),
        mock.patch("jen.models.user.set_global_setting", lambda *a, **k: None),
    ):
        text = setup_wizard.enable_v6("http://a:8006", {})
    return text.startswith("Jen could not write its own settings (OSError")


_UNIX_SOCKET = {"socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket"}
_API_SOCKET = {"socket-type": "http", "socket-address": "10.0.0.5", "socket-port": 8004}
_DAEMON_BLOCK = {"dhcp4": "Dhcp4", "dhcp6": "Dhcp6", "d2": "DhcpDdns"}


def _answers_like_a_lab(url):
    """The default `config-get` answer of the probe's lab: a daemon's own socket (the :8004/:8005/:8006 ports the routes create) answers as the daemon, any other address as a Control Agent."""
    return "Dhcp4" if any(f":{p}" in url for p in ("8004", "8005", "8006")) else "Control-agent"


def route_remove(
    text,
    service,
    form=None,
    *,
    ssh_host="10.0.0.5",
    server_id=1,
    identify=_answers_like_a_lab,
    host=None,
    others=None,
    preread_exc=None,
):
    """The real "Remove socket" route body (`remove_direct_socket`) on a real jen.config, with the Kea host stubbed (the change set records that it was asked, and applies): what a person
    pressing the button would cause. Returns {"touched": the Kea host was changed, "changed": jen.config changed, "flashes": the words shown, "text": the file after}. Flask is the only
    dependency (a bare request context); no database, no SSH. Q186: the Kea host is a SIMULATED daemon config (`host`, default: a unix socket and one http socket) that the change
    really edits; `identify` is what a `config-get` at any address answers as (a string, or a function of the url); the result also carries "applies", "asked" (the addresses
    identified, in order) and "host" (the daemon config after)."""
    import copy
    import inspect

    from flask import Flask

    from jen.routes.settings import infrastructure as infra
    from jen.services import kea_changeset

    flashes, applied, audits, asked, events = [], [], [], [], []
    resolved = []
    pairs = []
    host_state = {
        "cfg": copy.deepcopy(host)
        if host is not None
        else {_DAEMON_BLOCK[service]: {"control-sockets": [copy.deepcopy(_UNIX_SOCKET), copy.deepcopy(_API_SOCKET)]}}
    }
    with Lab(text) as lab, contextlib.ExitStack() as stack:
        before = lab.bytes()
        servers = AppConfig.derive_kea_servers(lab.read(), quiet=True)
        server = dict(next(x for x in servers if x["id"] == server_id), ssh_host=ssh_host)
        stack.enter_context(mock.patch.object(infra, "url_for", lambda *a, **k: "/settings/kea"))
        stack.enter_context(mock.patch.object(infra, "flash", lambda t, style="message": flashes.append(str(t))))
        stack.enter_context(mock.patch.object(infra, "_server_by_id", lambda sid: server))

        def _identify(url, *a, **k):
            asked.append(url)
            pairs.append((url, *a[:2]))
            events.append("identify")
            return identify(url) if callable(identify) else identify

        from jen.services import kea_config_edit as _edit

        stack.enter_context(mock.patch.object(infra, "_identify_daemon", _identify))
        stack.enter_context(
            mock.patch(
                "jen.services.kea_changeset.resolve_attention",
                lambda sid, svc, **kw: resolved.append((sid, svc, kw.get("categories"))) or 0,
            )
        )
        if preread_exc is None:
            stack.enter_context(
                mock.patch.object(
                    infra,
                    "_api_sockets_of",
                    lambda s, svc, errors=None: [
                        x for x in _edit.control_sockets(host_state["cfg"], svc) if _edit._is_api_socket(x)
                    ],
                )
            )
        else:
            # Q189 (AE4): the REAL pre-read, over a channel that raises - the exception is a failed read, never an escape
            from jen.services import kea_host as _kea_host

            def _cut(server, op, payload=None, timeout=60):
                if op == "read-config":
                    raise preread_exc
                raise AssertionError(f"nothing else may be sent: {op}")

            stack.enter_context(mock.patch.object(_kea_host, "helper_call", _cut))
        stack.enter_context(mock.patch.object(extensions, "KEA_SERVERS", list(others or [])))
        stack.enter_context(
            mock.patch.dict(
                infra.__dict__["__user"].__dict__,
                {"audit": lambda *a, **k: audits.append(a), "set_global_setting": lambda *a, **k: True},
            )
        )

        def apply_change(*args, **kw):
            applied.append(args[0])
            events.append("apply")
            after, code = args[1](copy.deepcopy(host_state["cfg"]))
            if code == "ok":
                host_state["cfg"] = after
                return kea_changeset.ChangeSetResult("ok", "ok", [])
            if code in ("nochange", "notfound"):
                return kea_changeset.ChangeSetResult("nothing", code, [])
            return kea_changeset.ChangeSetResult(
                "aborted", code, [("error", kw.get("code_messages", {}).get(code, code))]
            )

        stack.enter_context(mock.patch("jen.services.kea_changeset.apply_change", apply_change))
        view = infra._holding_identity_lock(inspect.unwrap(infra.remove_direct_socket))
        app = Flask(__name__)
        app.secret_key = "probe"
        with app.test_request_context(method="POST", data=form or {}):
            view(server_id, service)
        with open(lab.path, encoding="utf-8", newline="") as f:
            after = f.read()
        return {
            "touched": bool(applied),
            "changed": lab.bytes() != before,
            "flashes": " | ".join(flashes),
            "text": after,
            "audit": " | ".join(str(a[2]) for a in audits if len(a) > 2),
            "applies": len(applied),
            "asked": asked,
            "events": events,
            "resolved": resolved,
            "pairs": pairs,
            "host": host_state["cfg"],
        }


def _kv(text, section, key):
    p = parse(text)
    return p.get(section, key, fallback=None)


def _direct_on(socket_url, prev_url, extra_kea=""):
    """A direct-mode primary whose API url is the socket it set up, with the Control Agent's address remembered IN [kea] (where `setup_direct_socket` puts it)."""
    return DIRECT.replace("https://a:8000", socket_url).replace(
        "connection_mode = direct\n", f"connection_mode = direct\ndirect_prev_api_url = {prev_url}\n{extra_kea}", 1
    )


PROXY = _direct_on("http://10.0.0.5:8004", "http://proxy.lan:8000")


def q184_z1_s1b_a_control_agent_on_a_proxy_is_refused_without_a_typed_password_and_nothing_is_sent():
    r = route_remove(PROXY, "dhcp4")
    return (r["touched"], r["changed"], "moved to a different host" in r["flashes"])


def q184_z1_s2_the_same_with_the_password_typed_is_written():
    r = route_remove(PROXY, "dhcp4", {"password": "CAPW"})
    return (
        r["touched"],
        _kv(r["text"], "kea", "api_pass"),
        _kv(r["text"], "kea", "api_url"),
        _kv(r["text"], "kea", "connection_mode"),
    )


def q184_z1_s12_a_tunnel_endpoint_for_the_control_agent_is_the_same_question():
    tunnel = _direct_on("http://10.0.0.5:8004", "http://127.0.0.1:18000")
    untyped, typed = route_remove(tunnel, "dhcp4"), route_remove(tunnel, "dhcp4", {"password": "TUNNEL"})
    return (untyped["touched"], typed["touched"], _kv(typed["text"], "kea", "api_url"))


def q184_z1_s18_a_jump_host_ssh_target_is_not_a_reason_to_refuse_a_typed_switch_back():
    r = route_remove(PROXY.replace("proxy.lan", "kea-a.lan"), "dhcp4", {"password": "CAPW"}, ssh_host="10.9.9.9")
    return (r["touched"], _kv(r["text"], "kea", "api_pass"), _kv(r["text"], "kea", "connection_mode"))


def q184_z1_the_two_answers_and_the_box_are_one_question():
    both = route_remove(PROXY, "dhcp4", {"password": "x", "no_password": "1"})
    none = route_remove(PROXY, "dhcp4", {"no_password": "1"})
    return (both["touched"], "Choose one" in both["flashes"], none["touched"], _kv(none["text"], "kea", "api_pass"))


def q184_z1_f1_a_daemon_password_with_no_address_is_not_typed_by_the_button():
    text = PROXY + "[kea6]\napi_pass = K6\n"
    r = route_remove(text, "dhcp4", {"password": "CAPW"})
    cleared = route_remove(text.replace("[kea6]\napi_pass = K6\n", ""), "dhcp4", {"password": "CAPW"})
    return (r["touched"], "Kea6 API" in r["flashes"] and "Settings" in r["flashes"], cleared["touched"])


def q184_z1_f2_a_stale_previous_address_needs_the_password_typed_for_it():
    stale = _direct_on("http://z:8004", "https://a:8000")
    untyped, typed = route_remove(stale, "dhcp4"), route_remove(stale, "dhcp4", {"password": "APW"})
    return (untyped["touched"], typed["touched"], _kv(typed["text"], "kea", "api_pass"))


def q184_z2_f3_a_dhcp6_removal_in_control_agent_mode_leaves_no_daemon_pair_and_posts_with_the_cas():
    text = BASE + "[kea6]\napi_url = https://b:8006\napi_user = x\napi_pass = K6\napi_pass_shared = 1\n"
    r = route_remove(text, "dhcp6")
    p = parse(r["text"])
    return (
        r["touched"],
        [p.has_option("kea6", k) for k in ("api_url", "api_user", "api_pass", "api_pass_shared")]
        if p.has_section("kea6")
        else "section gone",
        sends(r["text"], "kea6"),
    )


def q184_z2_a_dhcp6_removal_in_direct_mode_keeps_the_pair_and_the_next_address_is_a_move():
    text = DIRECT + "[kea6]\napi_url = http://10.0.0.5:8006\napi_user = x\napi_pass = K6\n"
    r = route_remove(text, "dhcp6")
    p = parse(r["text"])
    return (r["touched"], p.get("kea6", "api_pass"), p.has_option("kea6", "api_url"))


def _setup(text, service, url, user, password, typed):
    from jen.routes.settings import infrastructure as infra

    parsed = parse(text)
    server = {
        "id": 1,
        "name": "kea-a",
        "api_url": parsed.get("kea", "api_url"),
        "api_user": parsed.get("kea", "api_user", fallback=""),
        "api_pass": parsed.get("kea", "api_pass", fallback=""),
    }
    with Lab(text) as lab:
        fn, _ = infra._direct_socket_edit(server, service, url, user, password)
        result = lab.mutate(fn, typed=typed)
        buf = io.StringIO()
        lab.read().write(buf)
    return result, buf.getvalue()


def q184_z2_s3_the_control_agents_own_pair_survives_a_dhcp4_round_trip():
    ca = (
        BASE.replace("https://a:8000", "http://kea-a.lan:8000")
        .replace("api_user = pu", "api_user = cu")
        .replace("api_pass = PS", "api_pass = CAP")
    )
    result, after_setup = _setup(ca, "dhcp4", "http://10.0.0.5:8004", "sock", "SOCKPW", {"kea"})
    saved = (
        _kv(after_setup, "kea", "direct_prev_api_user"),
        _kv(after_setup, "kea", "direct_prev_api_pass"),
        _kv(after_setup, "kea", "api_pass"),
    )
    back = route_remove(after_setup, "dhcp4", {"restore_saved": "1"}, ssh_host="10.0.0.5")
    kept = route_remove(after_setup, "dhcp4", {}, ssh_host="10.0.0.5")
    p = parse(back["text"])
    return (
        result,
        saved,
        back["touched"],
        (p.get("kea", "api_user"), p.get("kea", "api_pass"), p.get("kea", "api_url"), p.get("kea", "connection_mode")),
        p.has_option("kea", "direct_prev_api_pass"),
        kept["touched"],
    )


def q184_z2_s3_the_order_of_two_removals_ends_with_the_control_agents_pair_and_no_daemon_pair():
    ca = (
        BASE.replace("https://a:8000", "http://kea-a.lan:8000")
        .replace("api_user = pu", "api_user = cu")
        .replace("api_pass = PS", "api_pass = CAP")
    )
    _, t4 = _setup(ca, "dhcp4", "http://10.0.0.5:8004", "sock", "SOCKPW", {"kea"})
    _, t46 = _setup(t4, "dhcp6", "http://10.0.0.5:8006", "six", "SIXPW", {"kea6"})
    # order A: the primary first (kea6 keeps its own address on the box, so nothing is re-derived), then the daemon in Control Agent mode
    a1 = route_remove(t46, "dhcp4", {"restore_saved": "1"})
    a2 = route_remove(a1["text"], "dhcp6")
    pa = parse(a2["text"])
    end_a = (
        a1["touched"],
        a2["touched"],
        pa.get("kea", "api_pass"),
        pa.has_section("kea6") and pa.has_option("kea6", "api_pass"),
    )
    # order B: the daemon first, in direct mode (it keeps its pair, with no address), then the primary: the switch-back would give that pair its FIRST address - refused, naming the daemon
    b1 = route_remove(t46, "dhcp6")
    b2 = route_remove(b1["text"], "dhcp4", {"restore_saved": "1"})
    cleared = parse(b1["text"])
    for key in ("api_user", "api_pass"):
        cleared.remove_option("kea6", key)
    buf = io.StringIO()
    cleared.write(buf)
    b3 = route_remove(buf.getvalue(), "dhcp4", {"restore_saved": "1"})
    return (
        end_a,
        (b1["touched"], b2["touched"], "Kea6 API" in b2["flashes"], b3["touched"], _kv(b3["text"], "kea", "api_pass")),
    )


def q184_p2_1_a_saved_pair_without_its_address_is_neither_offered_nor_restored():
    """Finding 1: an older release's removal deletes the saved ADDRESS and leaves the pair. Restoring it would type the endpoint and write the Control Agent's password onto the socket."""
    orphan = DIRECT.replace("https://a:8000", "http://10.0.0.5:8004").replace(
        "connection_mode = direct\n",
        "connection_mode = direct\ndirect_prev_api_user = cu\ndirect_prev_api_pass = APW\n",
        1,
    )
    r = route_remove(orphan, "dhcp4", {"restore_saved": "1"})
    return (r["touched"], r["changed"], "no saved Control Agent" in r["flashes"], r["text"] == orphan)


def q184_p2_3_a_daemon_that_inherited_the_primarys_pair_is_named_after_the_switch_back():
    ca = (
        BASE.replace("https://a:8000", "http://kea-a.lan:8000")
        .replace("api_user = pu", "api_user = cu")
        .replace("api_pass = PS", "api_pass = CAP")
    )
    _, t4 = _setup(ca, "dhcp4", "http://10.0.0.5:8004", "sock", "SOCKPW", {"kea"})
    _, t46 = _setup(t4, "dhcp6", "http://10.0.0.5:8006", "sock", "SOCKPW", {"kea6"})
    inherited = not parse(t46).has_option("kea6", "api_pass")
    r = route_remove(t46, "dhcp4", {"restore_saved": "1"})
    return (inherited, r["touched"], "Kea6 API" in r["flashes"] and "now has none" in r["flashes"])


def q184_p2_5_the_form_can_name_the_control_agents_user_and_a_passwordless_pair_restores_no_password_key():
    typed = route_remove(PROXY, "dhcp4", {"password": "CAP", "user": "cu"})
    only_user = PROXY.replace("connection_mode = direct\n", "connection_mode = direct\ndirect_prev_api_user = cu\n", 1)
    restored = route_remove(only_user, "dhcp4", {"restore_saved": "1"})
    p = parse(restored["text"])
    return (
        (_kv(typed["text"], "kea", "api_user"), _kv(typed["text"], "kea", "api_pass")),
        restored["touched"],
        (
            p.get("kea", "api_user"),
            p.get("kea", "api_pass", fallback=None),
        ),  # AB4 (Q186): a password the Control Agent did not have is ABSENT again, not an explicit blank
    )


def q185_aa1_s1_a_dhcp4_no_password_removes_the_user_and_sends_no_header():
    r = route_remove(PROXY, "dhcp4", {"no_password": "1"})
    p = parse(r["text"])
    return (
        r["touched"],
        p.has_option("kea", "api_user"),
        p.get("kea", "api_pass"),
        "user and password cleared" in r["flashes"],
        sends(r["text"], "kea"),
    )


def q185_aa1_s2_a_daemon_no_password_removes_its_user_in_either_mode():
    direct = DIRECT + "[kea6]\napi_url = http://10.0.0.5:8006\napi_user = x\napi_pass = K6\n"
    d = parse(route_remove(direct, "dhcp6", {"no_password": "1"})["text"])
    ca = BASE + "[kea6]\napi_url = https://b:8006\napi_user = x\napi_pass = K6\n"
    c = parse(route_remove(ca, "dhcp6", {"no_password": "1"})["text"])
    return (
        (d.has_option("kea6", "api_user"), d.get("kea6", "api_pass")),
        (c.has_option("kea6", "api_user"), c.get("kea6", "api_pass")),
    )


def q185_aa1_s13_an_extra_servers_no_password_sends_no_header_too():
    text = (
        BASE.replace("[kea]\n", "[kea]\nconnection_mode = direct\n", 1)
        + "[kea_server_2]\nname = b\napi_url = http://10.0.0.6:8004\napi_user = su\napi_pass = SP\ndirect_prev_api_url = http://kea-b.lan:8000\n"
    )
    r = route_remove(text, "dhcp4", {"no_password": "1"}, server_id=2, ssh_host="10.0.0.6")
    p = parse(r["text"])
    return (
        r["touched"],
        p.has_option("kea_server_2", "api_user"),
        p.get("kea_server_2", "api_pass"),
        sends(r["text"], "server_2"),
    )


def q185_aa1_s3_a_typed_user_beside_no_password_or_a_restore_is_refused_whole():
    a = route_remove(PROXY, "dhcp4", {"user": "cu", "no_password": "1"})
    saved = _direct_on(
        "http://10.0.0.5:8004", "http://kea-a.lan:8000", "direct_prev_api_user = cu\ndirect_prev_api_pass = CAP\n"
    )
    b = route_remove(saved, "dhcp4", {"user": "x", "restore_saved": "1"})
    return (
        a["touched"],
        a["text"] == PROXY,
        "Choose one for the user" in a["flashes"],
        b["touched"],
        b["text"] == saved,
        "Choose one for the user" in b["flashes"],
    )


def q185_aa3_s4_the_audit_row_says_what_was_done_with_the_password_and_the_user():
    only_user = route_remove(PROXY.replace("proxy.lan", "10.0.0.5"), "dhcp4", {"user": "cu"})
    pw = route_remove(PROXY, "dhcp4", {"password": "CAPW", "user": "cu"})
    return (only_user["audit"].split("password=")[1], pw["audit"].split("password=")[1])


def q185_aa3_s5_a_same_host_switch_back_says_the_saved_pair_was_discarded():
    saved = _direct_on(
        "http://10.0.0.5:8004", "http://10.0.0.5:8000", "direct_prev_api_user = cu\ndirect_prev_api_pass = CAP\n"
    )
    r = route_remove(saved, "dhcp4")
    p = parse(r["text"])
    return (
        r["touched"],
        "DISCARDED" in r["flashes"] and "Restore" in r["flashes"],
        p.get("kea", "api_pass"),
        p.has_option("kea", "direct_prev_api_pass"),
    )


def q185_aa3_s6_a_restored_copy_keeps_its_shared_marker():
    ca = BASE.replace("https://a:8000", "http://kea-a.lan:8000") + ""
    ca = ca.replace("api_pass = PS\n", "api_pass = CAP\napi_pass_shared = 1\n", 1)
    _, t4 = _setup(ca, "dhcp4", "http://10.0.0.5:8004", "sock", "SOCKPW", {"kea"})
    saved_marker = parse(t4).get("kea", "direct_prev_api_pass_shared", fallback=None)
    socket_marker = parse(t4).has_option("kea", "api_pass_shared")
    back = route_remove(t4, "dhcp4", {"restore_saved": "1"})
    p = parse(back["text"])
    return (
        saved_marker,
        socket_marker,
        p.get("kea", "api_pass"),
        p.get("kea", "api_pass_shared", fallback=None),
        p.has_option("kea", "direct_prev_api_pass_shared"),
    )


def q185_sp1_a_dependant_keeps_the_user_it_was_sending_when_its_parents_user_is_cleared():
    """Second pass, finding 1: a Kea6 with a password of its own and NO user key inherits the primary's user; clearing the primary's user (No password) must not change what the Kea6 sends."""
    text = (
        _direct_on("http://10.0.0.5:8004", "http://proxy.lan:8000", "")
        .replace("api_user = pu", "api_user = su")
        .replace("api_pass = PS", "api_pass = SP")
        + "[kea6]\napi_url = http://10.0.0.5:8006\napi_pass = K6\n"
    )
    before = sends(text, "kea6")
    r = route_remove(text, "dhcp4", {"no_password": "1"})
    p = parse(r["text"])
    return (
        r["touched"],
        before,
        sends(r["text"], "kea6"),
        p.has_option("kea", "api_user"),
        p.get("kea6", "api_user", fallback=None),
    )


def q185_sp2_the_audit_row_names_what_was_done_to_the_user():
    cleared = route_remove(PROXY, "dhcp4", {"no_password": "1"})["audit"]
    saved = _direct_on(
        "http://10.0.0.5:8004", "http://kea-a.lan:8000", "direct_prev_api_user = cu\ndirect_prev_api_pass = CAP\n"
    )
    restored = route_remove(saved, "dhcp4", {"restore_saved": "1"})["audit"]
    daemon = DIRECT + "[kea6]\napi_url = http://10.0.0.5:8006\napi_user = x\napi_pass = K6\n"
    ignored = route_remove(daemon, "dhcp6", {"password": "NEW", "user": "crafted"})["audit"]
    return tuple(a.split("password=")[1] for a in (cleared, restored, ignored))


def q185_sp6_a_stale_shared_marker_does_not_follow_a_restore():
    ca = BASE.replace("https://a:8000", "http://kea-a.lan:8000")
    _, t4 = _setup(ca, "dhcp4", "http://10.0.0.5:8004", "sock", "SOCKPW", {"kea"})
    stale = t4.replace("api_pass = SOCKPW\n", "api_pass = SOCKPW\napi_pass_shared = 1\n", 1)
    back = route_remove(stale, "dhcp4", {"restore_saved": "1"})
    p = parse(back["text"])
    return (
        back["touched"],
        p.get("kea", "api_pass"),
        p.has_option("kea", "api_pass_shared"),
        p.has_option("kea", "direct_prev_api_pass_shared"),
    )


def q185_h1_the_mode_is_read_as_the_resolver_reads_it():
    from jen.routes.settings import infrastructure as infra

    def mode(raw):
        p = configparser.ConfigParser(interpolation=None)
        p.add_section("kea")
        if raw is not None:
            p.set("kea", "connection_mode", raw)
        return infra._mode_of(p)

    return tuple(mode(v) for v in ("direct", " Direct ", "DIRECT", "ca", "", "bogus", None))


def _setup_server(text, server_id, service, url, user, password, typed):
    """`_setup` for any server of the file (an additional server's section is `kea_server_<id>`)."""
    from jen.routes.settings import infrastructure as infra

    with Lab(text) as lab:
        server = next(s for s in AppConfig.derive_kea_servers(lab.read(), quiet=True) if s["id"] == server_id)
        fn, _ = infra._direct_socket_edit(server, service, url, user, password)
        result = lab.mutate(fn, typed=typed)
        buf = io.StringIO()
        lab.read().write(buf)
    return result, buf.getvalue()


def q186_ab3_s1_no_saved_control_agent_address_is_refused_before_the_host_is_touched():
    """Without a Control Agent address to return to, a dhcp4 removal would flip to Control Agent mode and leave `api_url` at the socket it just removed: Jen could not reach Kea."""
    no_prev = route_remove(DIRECT.replace("https://a:8000", "http://10.0.0.5:8004"), "dhcp4", {"password": "x"})
    same = _direct_on("http://10.0.0.5:8004", "http://10.0.0.5:8004")
    equal = route_remove(same, "dhcp4", {"no_password": "1"})
    return (
        (no_prev["touched"], no_prev["applies"], no_prev["changed"], "no Control Agent address" in no_prev["flashes"]),
        (equal["touched"], equal["applies"], equal["changed"], "no Control Agent address" in equal["flashes"]),
    )


def q186_ab3_s2_the_forms_address_is_identified_first_and_then_the_removal_proceeds():
    text = DIRECT.replace("https://a:8000", "http://10.0.0.5:8004")
    r = route_remove(
        text,
        "dhcp4",
        {"ca_url": "http://ca.lan:8000", "user": "cu", "password": "CAPW"},
        identify=lambda url: "Control-agent" if url == "http://ca.lan:8000" else "Dhcp4",
    )
    p = parse(r["text"])
    return (
        r["touched"],
        p.get("kea", "api_url"),
        p.get("kea", "connection_mode"),
        (p.get("kea", "api_user"), p.get("kea", "api_pass")),
        r["asked"],
        r["events"][:2],
        sends(r["text"], "kea"),
    )


def q186_ab3_s3_an_address_that_is_not_a_control_agent_or_not_typed_for_is_refused_whole():
    text = DIRECT.replace("https://a:8000", "http://10.0.0.5:8004")
    daemon = route_remove(text, "dhcp4", {"ca_url": "http://ca.lan:8000", "password": "x"}, identify="Dhcp4")
    silent = route_remove(text, "dhcp4", {"ca_url": "http://ca.lan:8000", "password": "x"}, identify=None)
    no_answer = route_remove(
        text, "dhcp4", {"ca_url": "http://10.0.0.5:8000"}, identify="Control-agent"
    )  # same host: the writer would allow it, the form still needs an answer
    itself = route_remove(text, "dhcp4", {"ca_url": "http://10.0.0.5:8004", "password": "x"}, identify="Control-agent")
    junk = route_remove(
        text, "dhcp4", {"ca_url": "http://u:p@ca.lan:8000/x?y", "password": "x"}, identify="Control-agent"
    )
    return tuple((r["touched"], r["changed"]) for r in (daemon, silent, no_answer, itself, junk)) + (
        "answered as Dhcp4" in daemon["flashes"],
        "did not answer" in silent["flashes"],
        "needs its password" in no_answer["flashes"],
        "is the socket being removed" in itself["flashes"],
    )


def q186_ab3_s4_another_server_keeping_direct_mode_needs_no_address():
    text = DIRECT.replace("https://a:8000", "http://10.0.0.5:8004")
    other = [{"id": 2, "name": "b", "api_url": "http://10.0.0.6:8004"}]
    r = route_remove(text, "dhcp4", {"password": "x"}, others=other)
    p = parse(r["text"])
    return (
        r["touched"],
        p.get("kea", "api_url"),
        p.get("kea", "connection_mode"),
        "no Control Agent URL on record" in r["flashes"],
    )


def q186_ab3_s5_a_saved_address_is_restored_and_a_typed_one_wins_over_it():
    saved = _direct_on(
        "http://10.0.0.5:8004", "http://kea-a.lan:8000", "direct_prev_api_user = cu\ndirect_prev_api_pass = CAP\n"
    )
    plain = route_remove(saved, "dhcp4", {"password": "CAPW"})
    typed = route_remove(
        saved, "dhcp4", {"ca_url": "http://ca.lan:8000", "password": "NEWPW"}, identify="Control-agent"
    )
    both = route_remove(
        saved, "dhcp4", {"ca_url": "http://ca.lan:8000", "restore_saved": "1"}, identify="Control-agent"
    )
    t = parse(typed["text"])
    return (
        _kv(plain["text"], "kea", "api_url"),
        (
            t.get("kea", "api_url"),
            t.get("kea", "api_pass"),
            t.has_option("kea", "direct_prev_api_url"),
            t.has_option("kea", "direct_prev_api_pass"),
        ),
        (both["touched"], "Choose one for the Control Agent" in both["flashes"]),
    )


def _round_trip(user, password):
    """The Control Agent as configured (user: value|None, password: value|""|None), a direct-socket setup, then the switch-back with the saved pair restored: what is sent before, and after."""
    lines = ["[kea]", "api_url = http://kea-a.lan:8000"]
    if user is not None:
        lines.append(f"api_user = {user}")
    if password is not None:
        lines.append(f"api_pass = {password}")
    ca = "\n".join(lines) + "\n" + BASE[BASE.index("[kea_db]") :]
    before = sends(ca, "kea")
    _, t4 = _setup(ca, "dhcp4", "http://10.0.0.5:8004", "sock", "SOCKPW", {"kea"})
    back = route_remove(t4, "dhcp4", {"restore_saved": "1"})
    p = parse(back["text"])
    return (
        before == sends(back["text"], "kea") and back["touched"],
        p.has_option("kea", "api_user") == (user is not None),
        p.has_option("kea", "api_pass") == (password is not None),
        any(
            p.has_option("kea", k)
            for k in (
                "direct_prev_api_user",
                "direct_prev_api_pass",
                "direct_prev_api_user_absent",
                "direct_prev_api_pass_absent",
            )
        ),
    )


def q186_ab4_s1_a_restore_puts_back_each_half_as_it_was_user_present_or_absent_by_password_present_blank_or_absent():
    return tuple(_round_trip(u, pw) for u in ("cu", None) for pw in ("CAP", "", None))


def q186_ab4_s2_an_additional_server_that_inherited_the_primarys_pair_inherits_again():
    text = BASE.replace("[server]\n", "") + "[kea_server_2]\nname = b\napi_url = https://a:8001\n[server]\n"
    before = sends(text, "server_2")
    _, t2 = _setup_server(text, 2, "dhcp4", "http://10.0.0.6:8004", "sock", "SOCKPW", {"server_2"})
    mid = parse(t2)
    back = route_remove(t2, "dhcp4", {"restore_saved": "1"}, server_id=2, ssh_host="10.0.0.6")
    p = parse(back["text"])
    return (
        before,
        (
            mid.get("kea_server_2", "direct_prev_api_user_absent", fallback=None),
            mid.get("kea_server_2", "direct_prev_api_pass_absent", fallback=None),
        ),
        back["touched"],
        (p.has_option("kea_server_2", "api_user"), p.has_option("kea_server_2", "api_pass")),
        sends(back["text"], "server_2"),
    )


def q186_ab4_s3_the_dependant_keep_writes_a_user_only_when_the_dependants_password_is_its_own():
    inherited = (
        _direct_on("http://10.0.0.5:8004", "http://proxy.lan:8000")
        .replace("api_user = pu", "api_user = su")
        .replace("api_pass = PS", "api_pass = SP")
        + "[kea6]\napi_url = http://10.0.0.5:8006\n"
    )
    own = inherited.replace("[kea6]\n", "[kea6]\napi_pass = K6\n")
    a = route_remove(inherited, "dhcp4", {"no_password": "1"})
    b = route_remove(own, "dhcp4", {"no_password": "1"})
    pa, pb = parse(a["text"]), parse(b["text"])
    return (
        (a["touched"], pa.has_option("kea6", "api_user"), sends(a["text"], "kea6")),
        (b["touched"], pb.get("kea6", "api_user", fallback=None), sends(b["text"], "kea6")),
    )


def q186_ab5_s1_a_stale_shared_marker_is_cleared_when_a_setup_writes_the_saved_pair():
    ca = BASE.replace("https://a:8000", "http://kea-a.lan:8000").replace(
        "[kea]\n", "[kea]\ndirect_prev_api_pass_shared = 1\n", 1
    )
    _, t4 = _setup(ca, "dhcp4", "http://10.0.0.5:8004", "sock", "SOCKPW", {"kea"})
    p = parse(t4)
    return (
        p.has_option("kea", "direct_prev_api_pass_shared"),
        p.get("kea", "direct_prev_api_pass"),
        p.get("kea", "direct_prev_api_url"),
    )


def q186_ab5_s2_a_typed_daemon_password_on_the_control_agent_mode_form_is_paired_with_the_control_agents_user():
    """Second pass, finding 2: AB5 first kept the daemon's own user beside a typed password in Control Agent mode, so the Control Agent was sent the SOCKET's user name with its own password."""
    text = (
        BASE
        + "[kea6]"
        + chr(10)
        + "api_url = https://b:8006"
        + chr(10)
        + "api_user = x"
        + chr(10)
        + "api_pass = K6"
        + chr(10)
    )
    typed = route_remove(text, "dhcp6", {"password": "NEWPW"})
    cleared = route_remove(text, "dhcp6", {})
    pt, pc = parse(typed["text"]), parse(cleared["text"])
    return (
        (
            pt.get("kea6", "api_user", fallback=None),
            pt.get("kea6", "api_pass", fallback=None),
            pt.has_option("kea6", "api_url"),
        ),
        (
            pc.has_section("kea6") and pc.has_option("kea6", "api_user"),
            pc.has_section("kea6") and pc.has_option("kea6", "api_pass"),
        ),
        sends(typed["text"], "kea6"),
    )


def q186_sp1_a_saved_address_that_only_differs_as_text_is_identified_before_it_is_restored():
    """Second pass, finding 1: a saved address that is an alias of the socket (or an earlier direct socket) is no proof of a Control Agent. Each row: (touched, the addresses identified, api_url, mode)."""
    rows = []
    for socket_url, prev in (
        ("http://10.0.0.5:8004", "http://kea-a.lan:8004"),
        ("http://10.0.0.5:8004", "HTTP://10.0.0.5:8004"),
        ("http://10.0.0.5:8004", "http://10.0.0.5:8004."),
        ("http://[fd00::5]:8004", "http://[FD00:0:0:0:0:0:0:5]:8004"),
        ("http://10.0.0.5:8005", "http://10.0.0.5:8004"),
        ("http://10.0.0.5:8004", "http://kea-a.lan:8000"),
    ):
        r = route_remove(_direct_on(socket_url, prev), "dhcp4", {"password": "PW"})
        p = parse(r["text"])
        rows.append((r["touched"], r["asked"], p.get("kea", "api_url"), p.get("kea", "connection_mode")))
    return tuple(rows)


def q187_ac4_s1_the_identify_pair_is_the_resolvers_for_a_half_nobody_typed():
    """An additional server on the primary's host inherits the primary's user and password. The pair its Control Agent address is asked with is what the resolver gives it (pu/PS), not the raw
    keys of its own section (blank)."""
    text = (
        DIRECT.replace("https://a:8000", "http://10.0.0.5:8000")
        + "[kea_server_2]\nname = b\napi_url = http://10.0.0.5:8104\ndirect_prev_api_url = http://10.0.0.5:8100\nssh_host = 10.0.0.5\n"
    )
    r = route_remove(text, "dhcp4", {}, server_id=2)
    return (r["touched"], r["pairs"])


def q187_ac5_s1_a_second_record_of_the_same_socket_is_refused_and_never_keeps_direct_mode():
    text = DIRECT.replace("https://a:8000", "http://10.0.0.5:8004")
    twin = route_remove(
        text, "dhcp4", {"password": "x"}, others=[{"id": 2, "name": "twin", "api_url": "http://10.0.0.5:8004/"}]
    )
    both = route_remove(
        text,
        "dhcp4",
        {"password": "x"},
        others=[
            {"id": 2, "name": "twin", "api_url": "HTTP://10.0.0.5:8004"},
            {"id": 3, "name": "real", "api_url": "http://10.0.0.6:8004"},
        ],
    )
    return tuple((r["touched"], r["changed"], "uses this same socket" in r["flashes"]) for r in (twin, both)) + (
        ("twin" in both["flashes"], "real" in both["flashes"]),
    )


def q187_ac5_s2_two_spellings_of_one_host_are_the_operators_to_keep_apart_and_the_sentence_says_so():
    text = DIRECT.replace("https://a:8000", "http://10.0.0.5:8004")
    r = route_remove(
        text, "dhcp4", {"password": "x"}, others=[{"id": 2, "name": "kea-a-dns", "api_url": "http://kea-a.lan:8004"}]
    )
    p = parse(r["text"])
    return (
        r["touched"],
        p.get("kea", "connection_mode"),
        "another spelling" in r["flashes"],
        "does no DNS lookups" in r["flashes"],
    )


def q187_ac6_s1_a_typed_address_beside_a_saved_pair_says_the_pair_was_discarded():
    saved = _direct_on(
        "http://10.0.0.5:8004", "http://kea-a.lan:8000", "direct_prev_api_user = cu\ndirect_prev_api_pass = CAP\n"
    )
    r = route_remove(saved, "dhcp4", {"ca_url": "http://ca.lan:8000", "password": "NEW", "user": "nu"})
    p = parse(r["text"])
    return (
        r["touched"],
        "DISCARDED" in r["flashes"] and "kea-a.lan" in r["flashes"],
        p.get("kea", "api_url"),
        (p.get("kea", "api_user"), p.get("kea", "api_pass")),
        any(p.has_option("kea", k) for k in ("direct_prev_api_url", "direct_prev_api_user", "direct_prev_api_pass")),
    )


def q187_ac6_s2_the_keep_direct_branch_identifies_a_saved_alias_like_the_rest():
    alias = _direct_on("http://10.0.0.5:8004", "http://kea-a.lan:8004")
    other = [{"id": 2, "name": "b", "api_url": "http://10.0.0.6:8004"}]
    refused = route_remove(alias, "dhcp4", {"password": "x"}, others=other)
    genuine = route_remove(
        _direct_on("http://10.0.0.5:8004", "http://kea-a.lan:8000"), "dhcp4", {"password": "x"}, others=other
    )
    return (
        (refused["touched"], refused["changed"], refused["asked"][-1:] == ["http://kea-a.lan:8004"]),
        (genuine["touched"], parse(genuine["text"]).get("kea", "connection_mode")),
    )


def q187_ac6_s3_the_singular_control_socket_is_removed_and_said():
    host = {"Dhcp4": {"control-socket": dict(_API_SOCKET)}}
    r = route_remove(PROXY, "dhcp4", {"password": "CAPW"}, host=host)
    return (r["touched"], r["host"], "single control-socket entry was rewritten" in r["flashes"])


def q187_ac6_s4_a_write_failure_sentence_prints_the_class_and_errno_never_the_path():
    from jen.routes.settings import infrastructure as infra

    sentence = infra._sentence_of(OSError(30, "Read-only file system", "/etc/jen/jen.config"))
    return ("OSError, errno 30: Read-only file system" in sentence, "/etc/jen" in sentence, "jen.config" in sentence)


def q187_ac6_s5_odd_entries_print_plainly_and_a_snapshot_that_is_not_a_list_of_entries_is_refused():
    from jen.services import kea_config_edit as ed

    odd = {"socket-type": "http", "socket-address": {"a": 1}, "socket-port": True}
    return (
        ed.describe_socket(odd),
        ed.describe_socket({"socket-address": "10.0.0.5"}),
        ed.describe_socket({"socket-type": ["x"], "socket-name": 5}),
        ed.restore_control_sockets({"Dhcp4": {"control-sockets": []}}, "dhcp4", [1])[1],
        ed.restore_control_sockets({"Dhcp4": {"control-sockets": []}}, "dhcp4", "no")[1],
    )


def q187_sp1_an_inherited_password_is_not_sent_to_the_saved_address_on_a_different_host():
    """Second pass, finding 1 (P1): the identify probe at the saved address was asked with the pair the endpoint sends to the SOCKET's host. An additional server on the primary's host inherits the
    primary's pair; its saved Control Agent address is on a different host, where the writer withholds it - and the probe must be asked with what the writer will leave: nothing."""
    text = (
        DIRECT.replace("https://a:8000", "http://10.0.0.5:8000")
        + "[kea_server_2]\nname = b\napi_url = http://10.0.0.5:8104\ndirect_prev_api_url = http://proxy.lan:8100\nssh_host = 10.0.0.5\n"
    )
    r = route_remove(text, "dhcp4", {}, server_id=2)
    typed = route_remove(text, "dhcp4", {"password": "TYPED", "user": "tu"}, server_id=2)
    return (r["touched"], r["pairs"], typed["pairs"])


def q187_sp8_a_typed_address_that_is_another_servers_own_is_refused():
    text = DIRECT.replace("https://a:8000", "http://10.0.0.5:8004")
    r = route_remove(
        text,
        "dhcp4",
        {"ca_url": "http://10.0.0.9:8000", "password": "x"},
        others=[{"id": 2, "name": "standby", "api_url": "http://10.0.0.9:8000"}],
    )
    ok = route_remove(
        text,
        "dhcp4",
        {"ca_url": "http://10.0.0.9:8000", "password": "x"},
        others=[{"id": 2, "name": "standby", "api_url": "http://10.0.0.8:8000"}],
    )
    return ((r["touched"], r["changed"], "standby" in r["flashes"], r["asked"]), (ok["touched"], ok["asked"]))


def q187_sp4_a_removal_clears_only_the_probe_pending_note_of_the_socket_it_removed():
    done = route_remove(PROXY, "dhcp4", {"password": "CAPW"})
    nothing = route_remove(
        PROXY, "dhcp4", {"password": "CAPW"}, host={"Dhcp4": {"control-sockets": [dict(_UNIX_SOCKET)]}}
    )
    d6 = BASE + "[kea6]\napi_url = https://b:8006\napi_user = x\napi_pass = K6\n"
    daemon = route_remove(d6, "dhcp6", {}, host={"Dhcp6": {"control-sockets": [dict(_UNIX_SOCKET), dict(_API_SOCKET)]}})
    return (done["resolved"], nothing["touched"], nothing["resolved"], daemon["resolved"])


def q187_sp10_a_singular_unix_entry_with_nothing_to_remove_is_not_said_to_be_rewritten():
    host = {"Dhcp4": {"control-socket": dict(_UNIX_SOCKET)}}
    r = route_remove(PROXY, "dhcp4", {"password": "CAPW"}, host=host)
    return (r["host"] == host, "rewritten" in r["flashes"])


def q187_sp6_describe_socket_prints_one_short_printable_line():
    from jen.services import kea_config_edit as ed

    long_one = ed.describe_socket(
        {"socket-type": "http", "socket-address": "10.0.0." + "9" * 200 + chr(10) + "x", "socket-port": 8004}
    )
    return (len(long_one) < 100, chr(10) in long_one)


def q188_ad9_s1_the_twin_refusal_covers_dhcp6_and_d2():
    d6 = DIRECT + "[kea6]" + chr(10) + "api_url = http://10.0.0.5:8006" + chr(10)
    d2 = DIRECT + "[d2]" + chr(10) + "api_url = http://10.0.0.5:53001" + chr(10)
    t6 = route_remove(
        d6,
        "dhcp6",
        {},
        host={"Dhcp6": {"control-sockets": [dict(_UNIX_SOCKET), {**_API_SOCKET, "socket-port": 8006}]}},
        others=[{"id": 2, "name": "standby", "api6_url": "http://10.0.0.5:8006/"}],
    )
    t2 = route_remove(
        d2,
        "d2",
        {},
        host={"DhcpDdns": {"control-sockets": [dict(_UNIX_SOCKET), {**_API_SOCKET, "socket-port": 53001}]}},
        others=[{"id": 2, "name": "standby", "api_d2_url": "http://10.0.0.5:53001"}],
    )
    fine = route_remove(
        d6,
        "dhcp6",
        {},
        host={"Dhcp6": {"control-sockets": [dict(_UNIX_SOCKET), {**_API_SOCKET, "socket-port": 8006}]}},
        others=[{"id": 2, "name": "standby", "api6_url": "http://10.0.0.6:8006"}],
    )
    return tuple((r["touched"], r["changed"], "uses this same socket" in r["flashes"]) for r in (t6, t2, fine))


def q188_ad9_s2_ipv6_literals_are_compared_as_addresses_and_names_stay_as_written():
    from jen.services import auth

    return (
        auth.same_endpoint("http://[FD00:0:0:0:0:0:0:5]:8004", "http://[fd00::5]:8004"),
        auth.same_endpoint("http://[::ffff:10.0.0.5]:8004", "http://10.0.0.5:8004"),
        auth.same_endpoint("http://[fd00::5]:8004", "http://[fd00::6]:8004"),
        auth.same_endpoint("http://KEA-A:8004", "http://kea-a:8004"),
        auth.same_endpoint("http://kea-a.:8004", "http://kea-a:8004"),
        auth.same_host("http://[FD00::5]:1", "https://[fd00:0:0:0:0:0:0:5]:2"),
    )


def _tls_lab(stack, incidents=None):
    """A temporary SSL directory for `kea_tls`, a CA and Jen's client pair, and the incident record stubbed over a list (Q189): what the invariants of tests/test_kea_tls_rotation.py read."""
    import tempfile

    from jen.services import kea_changeset, kea_tls

    directory = tempfile.mkdtemp(prefix="probe-ssl-")
    stack.enter_context(mock.patch.object(kea_tls, "SSL_DIR", directory))
    stack.enter_context(
        mock.patch.object(extensions, "KEA_API_CA", kea_tls.ca_paths()[0])
    )  # Jen verifies against its own CA (the setup saved it): its https endpoints are Jen's
    incidents = incidents if incidents is not None else []
    stack.enter_context(
        mock.patch.object(
            kea_changeset,
            "recovery_incidents",
            lambda strict=False: [
                {"kind": "attention", "category": c, "status": c, "service": s, "server_id": sid}
                for sid, s, c in incidents
            ],
        )
    )
    kea_tls.ensure_ca()
    kea_tls.issue_client_cert()
    return kea_tls, directory, incidents


def q189_ae1_every_inventory_shape_is_a_target_a_refusal_or_left_alone():
    """The rotation's targets come from the configuration: for each shape of what Jen holds for an https endpoint, what the inventory makes of it."""
    import os
    import pathlib

    shapes = {}
    server = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}

    def url_for(s, svc):
        return "https://10.0.0.5:8004" if svc == "dhcp4" else ""

    def seen(kea_tls):
        inv = kea_tls.rotation_inventory([server], url_for=url_for)
        return (len(inv.targets), len(inv.refusals), len(inv.external), len(inv.stale))

    for shape in (
        "complete",
        "administrators trust",
        "copy missing",
        "key missing",
        "malformed",
        "not a pair",
        "external",
        "directory missing",
        "earlier Jen CA",
    ):
        with contextlib.ExitStack() as stack:
            kea_tls, directory, _ = _tls_lab(stack)
            files = kea_tls.issue_server_cert(server, "dhcp4", "10.0.0.5")
            crt, key = kea_tls.server_copy_path(1, "dhcp4"), kea_tls.server_key_path(1, "dhcp4")
            if shape == "copy missing":
                os.unlink(crt)
            elif shape == "key missing":
                os.unlink(key)
            elif shape == "malformed":
                pathlib.Path(crt).write_text("not a certificate", encoding="ascii")
            elif shape == "not a pair":
                other = kea_tls.issue_server_cert(
                    {"id": 9, "name": "x", "ssh_host": "10.0.0.9"}, "dhcp4", "10.0.0.9", commit=False
                )
                pathlib.Path(key).write_text(other["server.key"], encoding="ascii")
            elif shape == "external":
                import datetime

                from cryptography import x509
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.x509.oid import NameOID

                name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "an administrator")])
                k = ec.generate_private_key(ec.SECP256R1())
                now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                cert = (
                    x509.CertificateBuilder()
                    .subject_name(name)
                    .issuer_name(name)
                    .public_key(k.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(minutes=5))
                    .not_valid_after(now + datetime.timedelta(days=9))
                    .sign(k, hashes.SHA256())
                )
                pathlib.Path(crt).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
                pathlib.Path(key).write_bytes(
                    k.private_bytes(
                        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                    )
                )
            elif shape == "administrators trust":
                os.unlink(crt)
                os.unlink(key)
                stack.enter_context(mock.patch.object(extensions, "KEA_API_CA", "/etc/ssl/the-administrators-ca.pem"))
            elif shape == "directory missing":
                import shutil

                shutil.rmtree(os.path.dirname(crt))
            elif shape == "earlier Jen CA":
                kea_tls.commit_rotation(kea_tls.stage_rotation())
            assert files
            shapes[shape] = seen(kea_tls)
    return shapes


def q189_ae1_an_unlistable_directory_is_a_refusal_never_an_empty_set():
    import os

    server = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}
    with contextlib.ExitStack() as stack:
        kea_tls, directory, _ = _tls_lab(stack)
        kea_tls.issue_server_cert(server, "dhcp4", "10.0.0.5")
        real = os.listdir
        listed_dir = os.path.dirname(kea_tls.server_copy_path(1, "dhcp4"))

        def listdir(path="."):
            if os.fspath(path) == listed_dir:
                raise PermissionError(13, "Permission denied")
            return real(path)

        stack.enter_context(mock.patch.object(os, "listdir", listdir))
        inv = kea_tls.rotation_inventory(
            [server], url_for=lambda s, svc: "https://10.0.0.5:8004" if svc == "dhcp4" else ""
        )
        try:
            kea_tls.issued_server_copies(strict=True)
            strict_raises = False
        except PermissionError:
            strict_raises = True
        return (
            len(inv.refusals),
            "could not read its certificate directory" in inv.refusals[0],
            strict_raises,
            kea_tls.issued_server_copies(),
        )


def q189_ae2_the_reviews_sequence_records_the_pair_the_host_accepted():
    """A1 under CA-A is live; B is committed; A2 is installed on the rollback and Jen's write of A2 fails before either file: `host_material` is A2 byte for byte, `.prev` is A2, the pair is marked stale."""
    import os
    import pathlib

    server = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}
    with contextlib.ExitStack() as stack:
        kea_tls, directory, incidents = _tls_lab(stack)
        kea_tls.issue_server_cert(server, "dhcp4", "10.0.0.5")  # A1 is live
        b = kea_tls.issue_server_cert(server, "dhcp4", "10.0.0.5", commit=False)
        kea_tls.commit_issued(1, "dhcp4", b)  # B is committed (live = B, .prev = A1)
        a2 = kea_tls.issue_server_cert(
            server, "dhcp4", "10.0.0.5", commit=False
        )  # ... A2 is issued and installed on the host
        real = os.replace
        key = kea_tls.server_key_path(1, "dhcp4")

        def failing(src, dst, *a, **k):
            if str(dst) == key:
                raise OSError(5, "Input/output error")
            return real(src, dst, *a, **k)

        stack.enter_context(mock.patch.object(os, "replace", failing))
        try:
            kea_tls.commit_issued(1, "dhcp4", a2)
            raised = None
        except OSError as e:
            raised = type(e).__name__
        record = kea_tls.host_material(1, "dhcp4")
        prev = pathlib.Path(kea_tls.server_copy_path(1, "dhcp4") + ".prev").read_text(encoding="ascii")
        return (
            raised,
            record is not None
            and record["server.crt"] == a2["server.crt"]
            and record["server.key"] == a2["server.key"],
            prev == a2["server.crt"],
            kea_tls.is_stale(1, "dhcp4"),
            kea_tls.current_material(1, "dhcp4")["server.crt"] == a2["server.crt"],
        )


def q189_ae2_a_read_only_ssl_directory_loses_the_record_and_host_material_says_unknown():
    import pathlib

    from jen.services import private_files

    server = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}
    with contextlib.ExitStack() as stack:
        kea_tls, directory, incidents = _tls_lab(stack)
        kea_tls.issue_server_cert(server, "dhcp4", "10.0.0.5")
        a2 = kea_tls.issue_server_cert(server, "dhcp4", "10.0.0.5", commit=False)

        def refuse(*a, **k):
            raise OSError(30, "Read-only file system")

        stack.enter_context(mock.patch.object(kea_tls, "commit_file_set", refuse))
        stack.enter_context(mock.patch.object(private_files, "write_private_file", refuse))
        try:
            kea_tls.commit_issued(1, "dhcp4", a2)
            lost = False
        except kea_tls.HostRecordLost:
            lost = True
        incidents.append((1, "dhcp4", "remote-unknown"))  # the route records this
        return (
            lost,
            kea_tls.host_material(1, "dhcp4"),
            pathlib.Path(kea_tls.server_copy_path(1, "dhcp4") + ".prev").exists(),
        )


def q189_ae3_a_note_that_is_not_a_note_is_refused_unchanged_and_set_aside_on_request():
    from jen.models import user as user_mod
    from jen.services import kea_changeset as cs

    stored = {}
    with contextlib.ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(user_mod, "get_global_setting", lambda k, d="", strict=False: stored.get(k, d))
        )
        stack.enter_context(mock.patch.object(user_mod, "set_global_setting", lambda k, v: stored.__setitem__(k, v)))
        stack.enter_context(mock.patch.object(user_mod, "audit", lambda *a, **k: None))

        def update(key, mutate):
            current = stored.get(key, "")
            try:
                new = mutate(current or "")
            except Exception:
                return False
            if new is not None and new != current:
                stored[key] = new
            return True

        stack.enter_context(mock.patch.object(user_mod, "update_global_setting", update))
        results = []
        for bad in ("{broken json!!!", "[]", '{"incidents": "x"}', "{}"):
            stored[cs.ATTENTION_KEY] = bad
            refused = cs.record_attention(1, "dhcp4", "x", "aborted") is False and cs.resolve_attention(1, "dhcp4") == 0
            results.append((refused, stored[cs.ATTENTION_KEY] == bad, cs.note_state()))
        stored[cs.ATTENTION_KEY] = "{broken json!!!"
        status, key, length = cs.set_aside_unreadable_note()
        after = (
            status,
            key.startswith(cs.ATTENTION_KEY + "_set_aside_"),
            length,
            stored[key] == "{broken json!!!",
            stored[cs.ATTENTION_KEY],
            cs.note_state(),
        )
        return (tuple(results), after)


def q189_ae4_a_removal_whose_preread_is_cut_sends_nothing_and_says_so():
    rows = []
    for exc in (TimeoutError("timed out"), EOFError(), OSError(104, "Connection reset by peer")):
        r = route_remove(PROXY, "dhcp4", {"password": "CAPW"}, preread_exc=exc)
        rows.append(
            (r["touched"], r["changed"], "Jen could not reach" in r["flashes"], type(exc).__name__ in r["flashes"])
        )
    return tuple(rows)


def q190_af1_the_bundle_a_trust_path_names_is_judged_by_certificate_identity_not_by_its_path():
    """For each way an operator can point `[kea] api_ca` at (or away from) Jen's CA: what `trust_kind` says, and what the inventory does with an endpoint Jen holds NO record of."""
    import pathlib
    import shutil

    server = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}
    out = {}

    def foreign_ca_pem():
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "an administrator")])
        k = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=9))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(k, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    for shape in (
        "jens file",
        "equivalent spelling",
        "byte copy",
        "bundle with another",
        "another only",
        "unreadable",
        "empty",
    ):
        with contextlib.ExitStack() as stack:
            kea_tls, directory, _ = _tls_lab(stack)
            jens = kea_tls.ca_paths()[0]
            where = pathlib.Path(directory) / "elsewhere"
            where.mkdir()
            if shape == "equivalent spelling":
                path = str(pathlib.Path(directory) / ".." / pathlib.Path(directory).name / "kea-ca.crt")
            elif shape == "byte copy":
                shutil.copy(jens, where / "copy.pem")
                path = str(where / "copy.pem")
            elif shape == "bundle with another":
                (where / "bundle.pem").write_text(
                    pathlib.Path(jens).read_text(encoding="ascii") + foreign_ca_pem(), encoding="ascii"
                )
                path = str(where / "bundle.pem")
            elif shape == "another only":
                (where / "other.pem").write_text(foreign_ca_pem(), encoding="ascii")
                path = str(where / "other.pem")
            elif shape == "unreadable":
                path = str(where / "missing.pem")
            elif shape == "empty":
                path = ""
            else:
                path = jens
            stack.enter_context(mock.patch.object(extensions, "KEA_API_CA", path))
            stack.enter_context(mock.patch.object(extensions, "KEA_API_TLS_VERIFY", True))
            inv = kea_tls.rotation_inventory(
                [server], url_for=lambda s, svc: "https://10.0.0.5:8004" if svc == "dhcp4" else ""
            )
            out[shape] = (
                kea_tls.trust_kind(),
                kea_tls.trust_includes_jens_ca(),
                len(inv.targets),
                len(inv.refusals),
                len(inv.external),
            )
    return out


def q190_af2_a_url_with_user_info_is_refused_shown_without_it_and_scrubbed_from_text():
    from jen.services import auth

    url = "https://admin:s3cret@10.0.0.5:8004/x?y=1"
    return (
        auth.valid_api_url(url),
        auth.valid_api_url("https://10.0.0.5:8004"),
        auth.shown_url(url),
        "s3cret" in auth.scrub_urls(f"Max retries exceeded with url: {url} (Caused by x)"),
        auth.userinfo_sentence(url) == auth.USERINFO_SENTENCE,
    )


def q190_af3_every_entry_of_the_note_has_a_shape_and_an_unrecognised_one_is_refused():
    import json

    from jen.services import kea_changeset as cs

    good_at = "2026-01-01T00:00:00+00:00"
    shapes = {
        "empty list": {"incidents": []},
        "attention": {
            "incidents": [
                {
                    "kind": "attention",
                    "category": "aborted",
                    "service": "dhcp4",
                    "server_id": 1,
                    "summary": "s",
                    "at": good_at,
                }
            ]
        },
        "outcome without ids": {"incidents": [{"status": "rolled_back", "service": "dhcp4", "at": good_at}]},
        "5.65.x single note": {"status": "rollback_failed", "service": "dhcp4", "at": good_at},
        "empty entry": {"incidents": [{}]},
        "unknown status": {"incidents": [{"status": "fine", "service": "dhcp4", "at": good_at}]},
        "unknown category": {
            "incidents": [
                {
                    "kind": "attention",
                    "category": "x",
                    "service": "dhcp4",
                    "server_id": 1,
                    "summary": "s",
                    "at": good_at,
                }
            ]
        },
        "mixed": {"incidents": [{"status": "rolled_back", "service": "dhcp4", "at": good_at}, {}]},
        "top-level list": [{"status": "rolled_back", "service": "dhcp4", "at": good_at}],
    }
    result = {}
    for name, value in shapes.items():
        try:
            cs._incidents_of(json.dumps(value), strict=True)
            result[name] = "read"
        except cs.MalformedNote:
            result[name] = "refused"
    return result


def q185_aa3_a_trailing_no_break_space_is_refused_and_ordinary_padding_is_not():
    from jen.services import auth

    return (
        auth.valid_api_url("http://a:8000\u00a0"),
        auth.valid_api_url("http://a:8000 \n"),
        auth.same_host("https://a:8000\u00a0", "https://a:8000"),
        auth.same_host(" https://a:8000\n", "https://a:8001"),
    )


def q184_z3_a_trailing_dot_is_a_different_name_and_odd_spaces_are_no_url():
    from jen.services import auth

    return (
        auth.same_host("https://a.:8000", "https://a:8000"),
        auth.same_host("https://a.:8000", "https://A.:9"),
        auth.valid_api_url("http://a\u00a0b:8000"),
        auth.valid_api_url("http://\uff41.example:8000"),
        auth.valid_api_url("http://a\u200b.example:8000"),
        auth.valid_api_url("http://b\u00fccher.example:8000"),
    )


def q184_z2_the_saved_pair_is_masked_in_a_support_bundle():
    from jen.services import support_bundle

    out = support_bundle.redact_ini_text("[kea]\ndirect_prev_api_user = cu\ndirect_prev_api_pass = CAP\n")
    return ("CAP" in out, "direct_prev_api_user = cu" in out)


def q183_p2_f6_a_backslash_url_is_not_the_primarys_host():
    text = BASE + "[kea6]\napi_url = http://127.0.0.1:9\\@a:8000/\n"
    e = cred.resolve(parse(text))["kea6"]
    return (e.password, e.withheld, "withheld" if e.withheld else "inherited")


SCENARIOS = {
    name: fn
    for name, fn in sorted(globals().items())
    if name.startswith(("b12_", "b13_", "q183_", "q184_", "q185_", "q186_", "q187_", "q188_", "q189_", "q190_"))
    and callable(fn)
}

#: scenario -> the observation the rule requires
EXPECTED = {
    "b12_an_own_password_on_another_host_carries_the_primarys_user": ("pu", "K6", "own"),
    "b12_a_direct_socket_by_ip_keeps_the_password_and_the_user": ("written", "pu", "PS", "own", ""),
    "b12_a_flip_for_a_password_that_already_went_to_the_parent_is_not_refused": "written",
    "b12_an_unreadable_settings_table_is_not_an_absent_row": None,
    "b12_the_wizard_saves_what_it_probed_not_a_stale_own_pair": (None, "pu", "PS", "inherited:kea"),
    "b12_no_authentication_sends_no_header_and_never_looks_in_netrc": ([("https://z:8006", "no header")], {}),
    "b12_a_file_that_has_the_marker_is_never_written_by_the_conversion": ([], 0),
    "b13_s1_kea6_on_the_same_host_with_no_password_sends_no_header": [("https://a:8006", "no header")],
    "b13_s1_d2_on_the_same_host_with_no_password_sends_no_header": [("https://a:53001", "no header")],
    "b13_s1_a_servers_ipv6_endpoint_with_no_password_sends_no_header": [("https://b:8006", "no header")],
    "b13_s1_the_wizards_same_box_no_authentication_saves_no_user_and_sends_no_header": (
        None,
        False,
        [("https://a:8006", "no header")],
    ),
    "b13_s2_a_socket_set_up_by_ip_on_a_primary_named_by_hostname_is_read_with_the_probed_pair": [
        ("http://10.0.0.5:8006", ("pu", "PS"))
    ],
    "b13_s3_the_forms_default_is_the_resolvers_answer_for_a_withheld_endpoint": (("", ""), ("pu", "PS")),
    "b13_s4b_a_removed_socket_leaves_the_password_and_the_next_address_is_a_move": (
        "written",
        True,
        "refused: first address",
    ),
    "b13_s5_a_blank_kea6_database_host_opens_nothing": ("no connection", True),
    "b13_s5_a_withheld_kea6_database_password_opens_nothing": ("kea_db", "no connection"),
    "b13_s6_a_legacy_blank_is_converted_and_a_marked_blank_is_not": (["server_2_v6"], []),
    "b13_s7_a_servers_ipv6_password_equal_to_the_primarys_on_another_host_is_refused": "refused: not typed",
    "b13_s7b_a_servers_saved_d2_password_given_its_first_address_is_refused": "refused: first address",
    "b13_s9_a_restored_legacy_file_whose_database_says_converted_is_converted_not_marked": (
        ["server_2"],
        "PS",
        "explicit",
    ),
    "b13_p2_a_bridge_file_whose_blank_is_betas_answer_is_not_filled_in": ([], ""),
    "b13_p2_a_switch_back_by_name_is_refused_before_the_kea_host_is_touched": (
        "refused: first address",
        "written",
        True,
    ),
    "b13_p2_the_installer_merge_refuses_a_moved_api_url_with_the_saved_password": (True, ""),
    "b13_p2_an_invalid_marker_converts_nothing_and_writes_nothing": ("invalid", None, 0),
    "q183_y1_a_password_typed_for_another_host_then_unaddressed_then_flipped_is_refused": (
        "written",
        "written",
        "refused: first address",
        True,
    ),
    "q183_y2_a_new_password_copied_into_an_untyped_server_is_refused": "refused: not typed",
    "q183_y2_a_section_renumbered_in_one_write_with_its_password_is_refused": "refused: not typed",
    "q183_y2_the_same_value_saved_again_is_not_a_change": "written",
    "q183_y5_a_primary_with_no_password_still_sends_its_user_and_so_does_a_daemon_on_its_host": (
        [("https://a:8000", ("pu", ""))],
        [("https://a:8006", ("pu", ""))],
    ),
    "q183_y3_a_marker_is_read_and_cleared": (["server_2_v6"], []),
    "q183_y6_enable_v6_answers_a_failed_write_with_text": True,
    "q184_z1_s1b_a_control_agent_on_a_proxy_is_refused_without_a_typed_password_and_nothing_is_sent": (
        False,
        False,
        True,
    ),
    "q184_z1_s2_the_same_with_the_password_typed_is_written": (True, "CAPW", "http://proxy.lan:8000", "ca"),
    "q184_z1_s12_a_tunnel_endpoint_for_the_control_agent_is_the_same_question": (False, True, "http://127.0.0.1:18000"),
    "q184_z1_s18_a_jump_host_ssh_target_is_not_a_reason_to_refuse_a_typed_switch_back": (True, "CAPW", "ca"),
    "q184_z1_the_two_answers_and_the_box_are_one_question": (False, True, True, ""),
    "q184_z1_f1_a_daemon_password_with_no_address_is_not_typed_by_the_button": (False, True, True),
    "q184_z1_f2_a_stale_previous_address_needs_the_password_typed_for_it": (False, True, "APW"),
    "q184_z2_f3_a_dhcp6_removal_in_control_agent_mode_leaves_no_daemon_pair_and_posts_with_the_cas": (
        True,
        "section gone",
        [("https://a:8000", ("pu", "PS"))],
    ),
    "q184_z2_a_dhcp6_removal_in_direct_mode_keeps_the_pair_and_the_next_address_is_a_move": (True, "K6", False),
    "q184_z2_s3_the_control_agents_own_pair_survives_a_dhcp4_round_trip": (
        "written",
        ("cu", "CAP", "SOCKPW"),
        True,
        ("cu", "CAP", "http://kea-a.lan:8000", "ca"),
        False,
        False,
    ),
    "q184_z2_s3_the_order_of_two_removals_ends_with_the_control_agents_pair_and_no_daemon_pair": (
        (True, True, "CAP", False),
        (True, False, True, True, "CAP"),
    ),
    "q184_p2_1_a_saved_pair_without_its_address_is_neither_offered_nor_restored": (False, False, True, True),
    "q184_p2_3_a_daemon_that_inherited_the_primarys_pair_is_named_after_the_switch_back": (True, True, True),
    "q184_p2_5_the_form_can_name_the_control_agents_user_and_a_passwordless_pair_restores_no_password_key": (
        ("cu", "CAP"),
        True,
        ("cu", None),
    ),
    "q185_aa1_s1_a_dhcp4_no_password_removes_the_user_and_sends_no_header": (
        True,
        False,
        "",
        True,
        [("http://proxy.lan:8000", "no header")],
    ),
    "q185_aa1_s2_a_daemon_no_password_removes_its_user_in_either_mode": ((False, ""), (False, "")),
    "q185_aa1_s13_an_extra_servers_no_password_sends_no_header_too": (
        True,
        False,
        "",
        [("http://kea-b.lan:8000", "no header")],
    ),
    "q185_aa1_s3_a_typed_user_beside_no_password_or_a_restore_is_refused_whole": (False, True, True, False, True, True),
    "q185_aa3_s4_the_audit_row_says_what_was_done_with_the_password_and_the_user": (
        "unchanged user=typed",
        "typed user=typed",
    ),
    "q185_aa3_s5_a_same_host_switch_back_says_the_saved_pair_was_discarded": (True, True, "PS", False),
    "q185_aa3_s6_a_restored_copy_keeps_its_shared_marker": ("1", False, "CAP", "1", False),
    "q185_sp1_a_dependant_keeps_the_user_it_was_sending_when_its_parents_user_is_cleared": (
        True,
        [("http://10.0.0.5:8006", ("su", "K6"))],
        [("http://10.0.0.5:8006", ("su", "K6"))],
        False,
        "su",
    ),
    "q185_sp2_the_audit_row_names_what_was_done_to_the_user": (
        "none user=cleared",
        "restored user=restored",
        "typed user=unchanged",
    ),
    "q185_sp6_a_stale_shared_marker_does_not_follow_a_restore": (True, "PS", False, False),
    "q185_h1_the_mode_is_read_as_the_resolver_reads_it": ("direct", "direct", "direct", "ca", "ca", "ca", "ca"),
    "q186_ab3_s1_no_saved_control_agent_address_is_refused_before_the_host_is_touched": (
        (False, 0, False, True),
        (False, 0, False, True),
    ),
    "q186_ab3_s2_the_forms_address_is_identified_first_and_then_the_removal_proceeds": (
        True,
        "http://ca.lan:8000",
        "ca",
        ("cu", "CAPW"),
        ["http://ca.lan:8000"],
        ["identify", "apply"],
        [("http://ca.lan:8000", ("cu", "CAPW"))],
    ),
    "q186_ab3_s3_an_address_that_is_not_a_control_agent_or_not_typed_for_is_refused_whole": (
        (False, False),
        (False, False),
        (False, False),
        (False, False),
        (False, False),
        True,
        True,
        True,
        True,
    ),
    "q186_ab3_s4_another_server_keeping_direct_mode_needs_no_address": (True, "http://10.0.0.5:8004", "direct", True),
    "q186_ab3_s5_a_saved_address_is_restored_and_a_typed_one_wins_over_it": (
        "http://kea-a.lan:8000",
        ("http://ca.lan:8000", "NEWPW", False, False),
        (False, True),
    ),
    "q186_ab4_s1_a_restore_puts_back_each_half_as_it_was_user_present_or_absent_by_password_present_blank_or_absent": (
        (True, True, True, False),
        (True, True, True, False),
        (True, True, True, False),
        (True, True, True, False),
        (True, True, True, False),
        (True, True, True, False),
    ),
    "q186_ab4_s2_an_additional_server_that_inherited_the_primarys_pair_inherits_again": (
        [("https://a:8001", ("pu", "PS"))],
        ("1", "1"),
        True,
        (False, False),
        [("https://a:8001", ("pu", "PS"))],
    ),
    "q186_ab4_s3_the_dependant_keep_writes_a_user_only_when_the_dependants_password_is_its_own": (
        (True, False, [("http://10.0.0.5:8006", "no header")]),
        (True, "su", [("http://10.0.0.5:8006", ("su", "K6"))]),
    ),
    "q186_ab5_s1_a_stale_shared_marker_is_cleared_when_a_setup_writes_the_saved_pair": (
        False,
        "PS",
        "http://kea-a.lan:8000",
    ),
    "q186_ab5_s2_a_typed_daemon_password_on_the_control_agent_mode_form_is_paired_with_the_control_agents_user": (
        (None, "NEWPW", False),
        (False, False),
        [("https://a:8000", ("pu", "NEWPW"))],
    ),
    "q186_sp1_a_saved_address_that_only_differs_as_text_is_identified_before_it_is_restored": (
        (False, ["http://kea-a.lan:8004"], "http://10.0.0.5:8004", "direct"),
        (False, ["HTTP://10.0.0.5:8004"], "http://10.0.0.5:8004", "direct"),
        (False, ["http://10.0.0.5:8004."], "http://10.0.0.5:8004", "direct"),
        (False, ["http://[FD00:0:0:0:0:0:0:5]:8004"], "http://[fd00::5]:8004", "direct"),
        (False, ["http://10.0.0.5:8004"], "http://10.0.0.5:8005", "direct"),
        (True, ["http://kea-a.lan:8000"], "http://kea-a.lan:8000", "ca"),
    ),
    "q187_ac4_s1_the_identify_pair_is_the_resolvers_for_a_half_nobody_typed": (
        True,
        [("http://10.0.0.5:8100", "pu", "PS")],
    ),
    "q187_ac5_s1_a_second_record_of_the_same_socket_is_refused_and_never_keeps_direct_mode": (
        (False, False, True),
        (False, False, True),
        (True, False),
    ),
    "q187_ac5_s2_two_spellings_of_one_host_are_the_operators_to_keep_apart_and_the_sentence_says_so": (
        True,
        "direct",
        True,
        True,
    ),
    "q187_ac6_s1_a_typed_address_beside_a_saved_pair_says_the_pair_was_discarded": (
        True,
        True,
        "http://ca.lan:8000",
        ("nu", "NEW"),
        False,
    ),
    "q187_ac6_s2_the_keep_direct_branch_identifies_a_saved_alias_like_the_rest": (
        (False, False, True),
        (True, "direct"),
    ),
    "q187_ac6_s3_the_singular_control_socket_is_removed_and_said": (True, {"Dhcp4": {"control-sockets": []}}, True),
    "q187_ac6_s4_a_write_failure_sentence_prints_the_class_and_errno_never_the_path": (True, False, False),
    "q187_ac6_s5_odd_entries_print_plainly_and_a_snapshot_that_is_not_a_list_of_entries_is_refused": (
        "http ?:?",
        "unix ?",
        "? ?:?",
        "unsupported",
        "unsupported",
    ),
    "q187_sp10_a_singular_unix_entry_with_nothing_to_remove_is_not_said_to_be_rewritten": (True, False),
    "q187_sp1_an_inherited_password_is_not_sent_to_the_saved_address_on_a_different_host": (
        True,
        [("http://proxy.lan:8100", "", "")],
        [("http://proxy.lan:8100", "tu", "TYPED")],
    ),
    "q187_sp4_a_removal_clears_only_the_probe_pending_note_of_the_socket_it_removed": (
        [(1, "dhcp4", ("probe-pending",))],
        True,
        [],
        [(1, "dhcp6", ("probe-pending",))],
    ),
    "q187_sp6_describe_socket_prints_one_short_printable_line": (True, False),
    "q187_sp8_a_typed_address_that_is_another_servers_own_is_refused": (
        (False, False, True, ["http://10.0.0.9:8000"]),
        (True, ["http://10.0.0.8:8000", "http://10.0.0.9:8000"]),
    ),
    "q188_ad9_s1_the_twin_refusal_covers_dhcp6_and_d2": (
        (False, False, True),
        (False, False, True),
        (True, True, False),
    ),
    "q188_ad9_s2_ipv6_literals_are_compared_as_addresses_and_names_stay_as_written": (
        True,
        True,
        False,
        True,
        False,
        True,
    ),
    "q189_ae1_an_unlistable_directory_is_a_refusal_never_an_empty_set": (1, True, True, []),
    "q189_ae1_every_inventory_shape_is_a_target_a_refusal_or_left_alone": {
        "complete": (1, 0, 0, 0),
        "administrators trust": (0, 1, 0, 0),
        "copy missing": (0, 1, 0, 0),
        "key missing": (0, 1, 0, 0),
        "malformed": (0, 1, 0, 0),
        "not a pair": (0, 1, 0, 0),
        "external": (0, 0, 1, 0),
        "directory missing": (0, 1, 0, 0),
        "earlier Jen CA": (0, 1, 0, 0),
    },
    "q189_ae2_a_read_only_ssl_directory_loses_the_record_and_host_material_says_unknown": (True, None, False),
    "q189_ae2_the_reviews_sequence_records_the_pair_the_host_accepted": ("OSError", True, True, True, False),
    "q189_ae3_a_note_that_is_not_a_note_is_refused_unchanged_and_set_aside_on_request": (
        ((True, True, "malformed"), (True, True, "malformed"), (True, True, "malformed"), (True, True, "malformed")),
        ("done", True, 15, True, "", "ok"),
    ),
    "q189_ae4_a_removal_whose_preread_is_cut_sends_nothing_and_says_so": (
        (False, False, True, True),
        (False, False, True, True),
        (False, False, True, True),
    ),
    "q190_af1_the_bundle_a_trust_path_names_is_judged_by_certificate_identity_not_by_its_path": {
        "jens file": ("jens-file", True, 0, 1, 0),
        "equivalent spelling": ("jens-file", True, 0, 1, 0),
        "byte copy": ("copy", True, 0, 1, 0),
        "bundle with another": ("bundle", True, 0, 1, 0),
        "another only": ("other", False, 0, 0, 1),
        "unreadable": ("unreadable", None, 0, 1, 0),
        "empty": ("none", None, 0, 0, 1),
    },
    "q190_af2_a_url_with_user_info_is_refused_shown_without_it_and_scrubbed_from_text": (
        False,
        True,
        "https://10.0.0.5:8004",
        False,
        True,
    ),
    "q190_af3_every_entry_of_the_note_has_a_shape_and_an_unrecognised_one_is_refused": {
        "empty list": "read",
        "attention": "read",
        "outcome without ids": "read",
        "5.65.x single note": "read",
        "empty entry": "refused",
        "unknown status": "refused",
        "unknown category": "refused",
        "mixed": "refused",
        "top-level list": "refused",
    },
    "q185_aa3_a_trailing_no_break_space_is_refused_and_ordinary_padding_is_not": (False, True, False, True),
    "q184_z3_a_trailing_dot_is_a_different_name_and_odd_spaces_are_no_url": (False, True, False, False, False, True),
    "q184_z2_the_saved_pair_is_masked_in_a_support_bundle": (False, True),
    "q183_p2_f6_a_backslash_url_is_not_the_primarys_host": ("", "kea", "withheld"),
}

#: the executed scenarios that need a Flask request or a database, and where each is pinned instead
NOT_PROBED = {
    "b12 D2 'No password' box could be ticked and not unticked": "tests/test_credential_destinations.py::TestTheD2BoxCanBeUnticked",
    "b13 S8 the copy button on an own password": "tests/test_credential_destinations.py::TestTheCopyButtonActsOnlyOnACopy",
    "b13 the dhcp6 route end to end (S2)": "tests/test_settings_direct_socket.py::TestHttpFlowSuccess",
    "b13 a failed write after the changeset (X4, step i)": "tests/test_direct_socket_lock.py::TestAFailedWriteOfJensSettingsIsHandledLikeARefusal",
    "q183 a retyped password drops its marker (routes)": "tests/test_credential_destinations.py::TestARetypedPasswordIsNoLongerASharedCopy",
}


def run_all() -> dict:
    import logging

    results = {}
    logging.disable(logging.CRITICAL)  # the rule's own warnings are not the table
    try:
        for name, fn in SCENARIOS.items():
            try:
                results[name] = fn()
            except Exception as e:  # a scenario that raises is a finding, reported as one
                results[name] = f"RAISED {type(e).__name__}: {e}"
    finally:
        logging.disable(logging.NOTSET)
    return results


def main() -> int:
    results, bad = run_all(), 0
    for name, got in results.items():
        want = EXPECTED[name]
        ok = got == want
        bad += not ok
        print(
            f"{'ok  ' if ok else 'DIFF'}  {name}\n        observed: {got!r}"
            + ("" if ok else f"\n        expected: {want!r}")
        )
    print(f"\n{len(results) - bad}/{len(results)} scenarios as the rule says")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
