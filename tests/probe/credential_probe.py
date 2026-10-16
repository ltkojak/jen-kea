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


def _removal(text, ssh_host, current_url, service, apply_fn):
    """The route's typing and the writer's preflight, through the real functions: (typed endpoints, the preflight's outcome)."""
    from jen.routes.settings import infrastructure as infra

    server = {"id": 1, "name": "kea-a", "ssh_host": ssh_host, "api_url": current_url}
    with Lab(text) as lab, mock.patch("socket.getaddrinfo", side_effect=OSError("no resolver")):
        typed = infra._typed_for_removal(server, service, app_config._read_parser(), apply_fn)
        result = outcome(lambda: app_config.preflight_identity_change(apply_fn, typed=typed))
        untouched = lab.bytes() == text.encode()
    return (sorted(typed), result, untouched)


def _switch_back(prev):
    def fn(p):
        p.set("kea", "api_url", prev)
        p.set("kea", "connection_mode", "ca")
        if p.has_option("kea", "direct_prev_api_url"):
            p.remove_option("kea", "direct_prev_api_url")

    return fn


def q183_p2_f1_a_password_typed_for_another_host_does_not_ride_the_switch_back():
    text = (
        DIRECT.replace("https://a:8000", "http://10.0.0.5:8004")
        + "direct_prev_api_url = https://a:8000\n[kea6]\napi_pass = K6\n"
    )
    return _removal(text, "10.0.0.5", "http://10.0.0.5:8004", "dhcp4", _switch_back("https://a:8000"))


def q183_p2_f1_a_daemon_that_had_an_address_on_this_box_does_ride_it():
    text = (
        DIRECT.replace("https://a:8000", "http://10.0.0.5:8004")
        + "direct_prev_api_url = http://kea-a.lan:8000\n[kea6]\napi_url = http://10.0.0.5:8006\napi_pass = K6\n"
    )

    def fn(p):
        _switch_back("http://kea-a.lan:8000")(p)
        p.remove_option("kea6", "api_url")

    return _removal(text, "10.0.0.5", "http://10.0.0.5:8004", "dhcp4", fn)


def q183_p2_f2_a_stale_previous_address_after_a_retarget_is_not_typed():
    text = DIRECT.replace("https://a:8000", "http://z:8004") + "direct_prev_api_url = https://a:8000\n"
    return _removal(text, "10.0.0.5", "http://z:8004", "dhcp4", _switch_back("https://a:8000"))


def q183_p2_f3_removing_a_dhcp6_socket_that_pointed_at_another_host_is_not_typed():
    text = BASE + "[kea6]\napi_url = https://b:8006\napi_user = x\napi_pass = K6\n"
    return _removal(text, "10.0.0.5", "https://a:8000", "dhcp6", lambda p: p.remove_option("kea6", "api_url"))


def q183_p2_f6_a_backslash_url_is_not_the_primarys_host():
    text = BASE + "[kea6]\napi_url = http://127.0.0.1:9\\@a:8000/\n"
    e = cred.resolve(parse(text))["kea6"]
    return (e.password, e.withheld, "withheld" if e.withheld else "inherited")


SCENARIOS = {
    name: fn for name, fn in sorted(globals().items()) if name.startswith(("b12_", "b13_", "q183_")) and callable(fn)
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
    "q183_p2_f1_a_password_typed_for_another_host_does_not_ride_the_switch_back": (
        ["kea"],
        "refused: first address",
        True,
    ),
    "q183_p2_f1_a_daemon_that_had_an_address_on_this_box_does_ride_it": (["kea", "kea6"], "written", True),
    "q183_p2_f2_a_stale_previous_address_after_a_retarget_is_not_typed": ([], "refused: moved", True),
    "q183_p2_f3_removing_a_dhcp6_socket_that_pointed_at_another_host_is_not_typed": ([], "refused: moved", True),
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
