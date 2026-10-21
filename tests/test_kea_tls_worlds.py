"""
tests/test_kea_tls_worlds.py
────────────────────────────
v5.69.0-beta.23 (Q192, AH0): the TLS module's inputs are its WORLDS.

Three reviews in a row found v5.29 TLS functions (`ensure_ca`, `ca_present`, `client_cert_ok`) by reading the whole archive, while our own passes executed the diff. This is the answer: a generated
matrix over every file `jen/services/kea_tls.py` reads - the CA, Jen's client pair, a server pair and the `.prev` / `.staged` / `.stale` / `.unknown` files beside it, the four `.next` files of a prepared
rotation, and the three configured paths (`api_ca`, `api_client_cert`, `api_client_key`) - in each state that applies, built as Lab worlds, and for EVERY world each ordinary action: the Health TLS row,
`issue_client_cert`, `ensure_ca`, `rotate_kea_ca` (with and without the acknowledgement of a damaged CA) and - through the setup harness - `setup_direct_socket` (https and http) and
`remove_direct_socket`. `check_invariants` (T1-T5) runs after each, plus two more:

  T6  no ORDINARY action replaces a damaged identity file: after Health / setup / remove / `issue_client_cert` / `ensure_ca` the CA files and Jen's client pair are byte-equal - except a damaged
      client pair under an ok CA, which `issue_client_cert` (and the setup that calls it) re-issues from the same CA and says so;
  T7  `ensure_ca` creates a CA ONLY in the uninitialised world (no CA files, no client pair, no server copy, no prepared rotation).

The matrix is ENUMERATED from `kea_tls`'s own path functions: a test lists the module's path functions, file suffixes, configured inputs and reading functions and fails on one that is not a row here,
so a new file the module reads is a new row. Each world's expected outcome is stated per state CLASS (CA damaged / client damaged / ...), not per cell.
"""

import ast
import os
import pathlib
import shutil
from dataclasses import dataclass

import pytest

import jen.routes.settings.infrastructure as infra
from jen import extensions
from jen.services import health, kea_tls
from tests import _tls_worlds as worlds
from tests import test_kea_tls_rotation as _rotation
from tests._fs_flake import retry_transient_replace  # noqa: F401 (autouse)
from tests.test_kea_tls_rotation import _add_external, _bundle_world, _client_world, _rotate  # noqa: F401

ROOT = pathlib.Path(__file__).resolve().parents[1]

lab = _rotation.lab  # the Lab fixture (a module-level name pytest collects as a fixture here)

# ── the matrix ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class World:
    role: str  # which input
    state: str  # in which state
    klass: str  # baseline | uninitialised | ca | client | copy | aux | config

    @property
    def id(self) -> str:
        return f"{self.role}:{self.state}"


def _worlds() -> list[World]:
    out = [World("baseline", "healthy", "baseline"), World("everything", "removed", "uninitialised")]
    out += [World("ca_crt", s, "ca") for s in ("absent", "malformed", "unreadable", "mismatched", "invalid-key")]
    # (second pass, finding 4/7) the CA's files gone while evidence they existed remains: the client pair and copies; a leftover `.prev`; an EMPTY copies directory
    out += [World("ca_both", "absent-beside-the-client-pair-and-copies", "ca")]
    out += [
        World("ca_prev_only", "everything-else-removed", "ca"),
        World("copies_dir", "empty-everything-else-removed", "ca"),
    ]
    out += [World("ca_key", s, "ca") for s in ("absent", "malformed", "unreadable", "mismatched")]
    out += [
        World("client_pem", s, "client")
        for s in ("absent", "malformed", "unreadable", "mismatched", "earlier-jen", "other-ca", "invalid-key")
    ]
    out += [World("client_key", s, "client") for s in ("absent", "malformed", "unreadable", "mismatched")]
    out += [
        World("server_crt", s, "copy")
        for s in ("absent", "malformed", "unreadable", "mismatched", "earlier-jen", "other-ca", "invalid-key")
    ]
    out += [World("server_key", s, "copy") for s in ("absent", "malformed", "unreadable", "mismatched")]
    for role in ("server_crt.prev", "server_key.prev", "server_crt.staged", "server_key.staged"):
        out += [World(role, s, "aux") for s in ("valid", "malformed", "mismatched")]
    out += [World("server.stale", "present", "aux"), World("server.unknown", "present", "aux")]
    out += [World("next", "consistent", "aux")]
    for role in ("next_ca_cert", "next_ca_key", "next_client_cert", "next_client_key"):
        out += [World(role, s, "aux") for s in ("absent", "malformed")]
    out += [World("api_ca", s, "config") for s in ("copy", "other-ca", "missing")]
    out += [World("api_client", s, "config") for s in ("none", "alias", "copy", "other", "unreadable")]
    return out


WORLDS = _worlds()
IDS = [w.id for w in WORLDS]


def _paths() -> dict:
    ca_crt, ca_key = kea_tls.ca_paths()
    pem, key = kea_tls.client_paths()
    crt, skey = kea_tls.server_copy_path(1, "dhcp4"), kea_tls.server_key_path(1, "dhcp4")
    return {
        "ca_crt": ca_crt,
        "ca_key": ca_key,
        "client_pem": pem,
        "client_key": key,
        "server_crt": crt,
        "server_key": skey,
    }


def _suffix(role: str) -> tuple[str, str]:
    base, _, suffix = role.partition(".")
    return ("server_crt" if base == "server_crt" else "server_key"), "." + suffix


def apply_world(world: World, monkeypatch, tmp_path) -> None:
    """Put the world's ONE input into its state. The directory already holds a healthy baseline (a CA, Jen's client pair, a server pair for server 1's dhcp4)."""
    p = _paths()
    role, state = world.role, world.state
    if role in ("baseline",):
        return
    if role == "everything":
        shutil.rmtree(kea_tls.SSL_DIR)
        os.makedirs(kea_tls.SSL_DIR)
        return
    if role == "ca_both":
        worlds.absent(p["ca_crt"])
        worlds.absent(p["ca_key"])
    elif role == "ca_prev_only":
        shutil.copy(p["ca_crt"], p["ca_crt"] + ".prev")
        shutil.rmtree(kea_tls.SSL_DIR)
        os.makedirs(kea_tls.SSL_DIR)
        pathlib.Path(p["ca_crt"] + ".prev").write_bytes(b"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
    elif role == "copies_dir":
        shutil.rmtree(kea_tls.SSL_DIR)
        os.makedirs(os.path.join(kea_tls.SSL_DIR, "kea-servers"))
    elif role == "ca_crt":
        if state == "invalid-key":
            pathlib.Path(p["ca_crt"]).write_bytes(worlds.invalid_public_key(pathlib.Path(p["ca_crt"]).read_bytes()))
        elif state == "mismatched":
            pathlib.Path(p["ca_crt"]).write_bytes(kea_tls._cert_pem(worlds.other_ca()[0]))
        else:
            {"absent": worlds.absent, "malformed": worlds.malformed, "unreadable": worlds.unreadable}[state](
                p["ca_crt"]
            )
    elif role == "ca_key":
        if state == "mismatched":
            pathlib.Path(p["ca_key"]).write_bytes(worlds.another_key_pem())
        else:
            {"absent": worlds.absent, "malformed": worlds.malformed, "unreadable": worlds.unreadable}[state](
                p["ca_key"]
            )
    elif role in ("client_pem", "client_key"):
        worlds.apply_state(
            state, p["client_pem"], p["client_key"], which="cert" if role == "client_pem" else "key", client=True
        )
    elif role in ("server_crt", "server_key"):
        worlds.apply_state(
            state, p["server_crt"], p["server_key"], which="cert" if role == "server_crt" else "key", client=False
        )
    elif role.startswith(("server_crt.", "server_key.")):
        which, suffix = _suffix(role)
        crt, key = p["server_crt"] + suffix, p["server_key"] + suffix
        shutil.copy(p["server_crt"], crt)
        shutil.copy(p["server_key"], key)
        target = crt if which == "server_crt" else key
        if state == "malformed":
            worlds.malformed(target)
        elif state == "mismatched":
            if which == "server_crt":
                pathlib.Path(crt).write_bytes(worlds.issued_pair(kea_tls._load_ca(), client=False)[0])
            else:
                pathlib.Path(key).write_bytes(worlds.another_key_pem())
    elif role == "server.stale":
        pathlib.Path(p["server_crt"] + ".stale").write_text("live differs from the host\n", encoding="ascii")
    elif role == "server.unknown":
        pathlib.Path(p["server_crt"] + ".unknown").write_text("unknown\n", encoding="ascii")
    elif role == "next":
        kea_tls.stage_rotation()
    elif role.startswith("next_"):
        staged = kea_tls.stage_rotation()
        target = staged[role[len("next_") :]]
        {"absent": worlds.absent, "malformed": worlds.malformed}[state](target)
    elif role == "api_ca":
        if state == "copy":
            copy_path = tmp_path / "copy-of-jens-ca.crt"
            shutil.copy(p["ca_crt"], copy_path)
            monkeypatch.setattr(extensions, "KEA_API_CA", str(copy_path))
        elif state == "other-ca":
            other = tmp_path / "administrators-ca.pem"
            other.write_bytes(kea_tls._cert_pem(worlds.other_ca()[0]))
            monkeypatch.setattr(extensions, "KEA_API_CA", str(other))
        else:
            monkeypatch.setattr(extensions, "KEA_API_CA", str(tmp_path / "does-not-exist.pem"))
    elif role == "api_client":
        _client_world(state, tmp_path, monkeypatch)
    else:
        raise AssertionError(world)


# ── what "the identity" is, and what each class of world means ───────────────────────────────────────────────────────────────────────────────────


def identity_files() -> dict:
    """The four identity files as bytes (None: absent; b'<dir>': a directory stands there) - what T6 compares."""
    out = {}
    for name, path in _paths().items():
        if not name.startswith(("ca_", "client_")):
            continue
        if os.path.isdir(path):
            out[name] = b"<dir>"
        elif os.path.lexists(path):
            out[name] = pathlib.Path(path).read_bytes()
        else:
            out[name] = None
    return out


def ca_damaged(world: World) -> bool:
    return world.klass == "ca"


def client_damaged(world: World) -> bool:
    return world.klass == "client"


def initialised(world: World) -> bool:
    return world.klass != "uninitialised"


def _health():
    return health._kea_tls_expiry({})


@pytest.fixture
def built(lab, monkeypatch, tmp_path, request):
    world = request.param
    apply_world(world, monkeypatch, tmp_path)
    if world.klass == "uninitialised":
        lab.hosts.clear()  # (no daemon holds anything in this world)
    lab.begin()  # the world IS the state before any action
    return world


def _all(test):
    return pytest.mark.parametrize("built", WORLDS, ids=IDS, indirect=True)(test)


# ── Lab worlds: Health, issue_client_cert, ensure_ca, rotate ─────────────────────────────────────────────────────────────────────────────────────


class TestTheWorldsOfTheLab:
    @_all
    def test_health_reads_every_world_without_changing_one_and_says_what_is_wrong(self, lab, built):
        lab.before = None  # a direct call to the module, not a request: T5 is about requests (T6 and T7 judge these)
        before = worlds.tree(kea_tls.SSL_DIR)
        c = _health()
        assert worlds.tree(kea_tls.SSL_DIR) == before, "Health only reads"
        assert c.status in ("ok", "warn", "fail", "skip")
        if ca_damaged(built):
            assert c.status == "fail" and "damaged" in c.detail, c.detail
        elif built.klass == "uninitialised":
            assert c.status == "skip", c.detail
        elif client_damaged(built):
            assert c.status == "fail", c.detail

    @_all
    def test_issue_client_cert_never_replaces_what_it_may_not(self, lab, built):
        lab.before = None  # a direct call to the module, not a request: T5 is about requests (T6 and T7 judge these)
        before_identity, before_tree = identity_files(), worlds.tree(kea_tls.SSL_DIR)
        if ca_damaged(built) or built.klass == "uninitialised":
            with pytest.raises(kea_tls.CaDamaged):
                kea_tls.issue_client_cert()
            assert worlds.tree(kea_tls.SSL_DIR) == before_tree
            return
        if client_damaged(built):
            directory = built.state == "unreadable"
            if directory:
                with pytest.raises(OSError):
                    kea_tls.issue_client_cert()
                assert worlds.tree(kea_tls.SSL_DIR) == before_tree, "refused as an error, nothing half-written"
                return
            result = kea_tls.issue_client_cert()
            assert result["issued"] is True and result["why"], result
            assert kea_tls.client_state() == ("ok", "")
            after = identity_files()
            assert after["ca_crt"] == before_identity["ca_crt"] and after["ca_key"] == before_identity["ca_key"], (
                "T6: the CA"
            )
            return
        result = kea_tls.issue_client_cert()
        assert result["issued"] is False and identity_files() == before_identity, (
            "T6: a healthy pair is left byte-equal"
        )
        assert worlds.tree(kea_tls.SSL_DIR) == before_tree

    @_all
    def test_ensure_ca_creates_only_in_the_uninitialised_world(self, lab, built):
        lab.before = None  # a direct call to the module, not a request: T5 is about requests (T6 and T7 judge these)
        before_identity, before_tree = identity_files(), worlds.tree(kea_tls.SSL_DIR)
        if built.klass == "uninitialised":
            result = kea_tls.ensure_ca()
            assert result["created"] is True and kea_tls.ca_state() == ("ok", ""), "T7: the one world it may create in"
            lab.hosts.clear()
            return
        if ca_damaged(built):
            with pytest.raises(kea_tls.CaDamaged):
                kea_tls.ensure_ca()
        else:
            assert kea_tls.ensure_ca()["created"] is False
        assert worlds.tree(kea_tls.SSL_DIR) == before_tree, "T7: nothing was created and nothing replaced"
        assert identity_files() == before_identity, "T6"

    @_all
    def test_rotate_without_the_acknowledgement_refuses_a_damaged_ca_and_changes_nothing(self, lab, built):
        before = worlds.tree(kea_tls.SSL_DIR)
        _rotate()
        if ca_damaged(built):
            assert "Jen's CA is damaged" in lab.texts() and "Tick the acknowledgement" in lab.texts(), lab.texts()
            assert lab.remote_actions() == 0 and worlds.tree(kea_tls.SSL_DIR) == before
        elif built.klass == "uninitialised":
            assert "No Jen-managed Kea CA exists yet" in lab.texts() and worlds.tree(kea_tls.SSL_DIR) == before
        else:
            assert "Rotate refused" in lab.texts() or "Kea CA rotated" in lab.texts() or lab.texts(), (
                "the route said SOMETHING - a rotation never ends without a word"
            )

    @_all
    def test_rotate_with_the_acknowledgement_replaces_a_damaged_ca_or_names_every_stuck_target(self, lab, built):
        _rotate({"acknowledge_damaged_ca": "1"})
        if ca_damaged(built) and "Kea CA rotated" in lab.texts():
            assert kea_tls.ca_state() == ("ok", ""), "the replacement is a pair"
            for sid in lab.hosts:
                assert lab.answers_jens_live_identity(sid), f"server {sid}'s daemon answers the replacement"
        elif ca_damaged(built):
            assert lab.texts(), "a failed recovery says why"


# ── the listing test: a file the module reads that is not a row fails here ───────────────────────────────────────────────────────────────────────


#: the path functions kea_tls reads files through - each is a row above (`ca_*` -> the CA worlds, `client_*` -> the client worlds, `server_*` and the markers -> the copy and aux worlds, `_staged_paths` ->
#: the `.next` worlds, `_copies_dir` -> the uninitialised-evidence worlds)
MATRIX_PATH_FUNCS = {
    "ca_paths",
    "client_paths",
    "server_copy_path",
    "server_key_path",
    "_stale_path",
    "_unknown_path",
    "_staged_paths",
    "_copies_dir",
}
#: the suffixes it appends to a path
MATRIX_SUFFIXES = {".prev", ".staged", ".stale", ".unknown", ".next", ".crt", ".key"}
#: the configured inputs it reads from `extensions`
MATRIX_CONFIG = {"KEA_API_CA", "KEA_API_TLS_VERIFY", "KEA_API_CLIENT_CERT", "KEA_API_CLIENT_KEY", "CONFIG_DIR"}
#: every function that opens or loads a file (or lists a directory), with the primitives it uses - a NEW reader is a new row
MATRIX_READERS = {
    "load_cert": {"open"},
    "load_key": {"open"},
    "cert_expiry": {"load_cert"},
    "issued_by": {"load_cert"},
    "ca_state": {"lexists", "load_cert", "load_key"},
    "_initialised_evidence": {"lexists", "listdir"},
    "_cn": {"load_cert"},
    "_load_ca": {"load_cert", "load_key"},
    "issue_server_cert": {"load_cert", "load_key"},
    "_material": {"load_cert", "load_key", "open"},
    "stage_issued": {"open"},
    "promote_staged": {"open"},
    "fingerprint": {"load_cert"},
    "restore_previous": {"open"},
    "mark_unknown": {"exists"},
    "is_unknown": {"exists"},
    "is_stale": {"exists"},
    "ca_consistent": {"load_cert", "load_key"},
    "client_state": {"lexists", "load_cert", "load_key"},
    "trust_bundle": {"load_cert", "load_pem_x509_certificates", "open"},
    "trust_kind": {
        "realpath",
        "open",
        "load_pem_x509_certificates",
    },  # (the recovery worlds: Jen's own CA certificate cannot be loaded, so the bundle is judged by path)
    "client_kind": {"load_cert", "load_key", "realpath"},
    "record_state": {"lexists", "open"},
    "commit_rotation": {"open"},
    "prepared_rotation": {"lexists", "load_cert", "load_key"},
    "promotion_blockers": {
        "isdir"
    },  # the `unreadable` (a directory where a file belongs) worlds of the four identity files
    "issued_server_copies": {"listdir"},
}
_READ_PRIMITIVES = {
    "open",
    "load_cert",
    "load_key",
    "load_pem_x509_certificates",
    "listdir",
    "lexists",
    "exists",
    "isfile",
    "isdir",
    "scandir",
    "stat",
    "getsize",
    "realpath",
}


def _module_facts():
    tree = ast.parse((ROOT / "jen" / "services" / "kea_tls.py").read_text(encoding="utf-8"))
    readers, suffixes, path_funcs, config = {}, set(), set(), set()
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        used = set()
        for c in ast.walk(fn):
            if isinstance(c, ast.Call):
                name = c.func.id if isinstance(c.func, ast.Name) else getattr(c.func, "attr", "")
                if name in _READ_PRIMITIVES:
                    used.add(name)
        if used:
            readers[fn.name] = used
    for n in ast.walk(tree):
        if (
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and n.value.startswith(".")
            and len(n.value) <= 10
            and n.value.strip(".")
        ):
            suffixes.add(n.value)
        if isinstance(n, ast.Call):
            name = n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", "")
            if name.endswith(("_path", "_paths")) or name == "_copies_dir":
                path_funcs.add(name)
            if (
                name == "getattr"
                and n.args
                and isinstance(n.args[0], ast.Name)
                and n.args[0].id == "extensions"
                and len(n.args) > 1
            ):
                config.add(n.args[1].value)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "extensions":
            config.add(n.attr)
    return readers, suffixes, path_funcs, config


class TestEveryInputOfTheModuleIsARow:
    def test_the_path_functions_suffixes_and_configured_inputs_are_all_in_the_matrix(self):
        _readers, suffixes, path_funcs, config = _module_facts()
        assert path_funcs <= MATRIX_PATH_FUNCS, (
            f"kea_tls reads a file through a path function that is not a row: {sorted(path_funcs - MATRIX_PATH_FUNCS)}"
        )
        assert suffixes <= MATRIX_SUFFIXES, (
            f"kea_tls appends a suffix that is not a row: {sorted(suffixes - MATRIX_SUFFIXES)}"
        )
        assert config <= MATRIX_CONFIG, (
            f"kea_tls reads a configured input that is not a row: {sorted(config - MATRIX_CONFIG)}"
        )

    def test_every_function_that_opens_or_loads_a_file_is_listed(self):
        readers, _s, _p, _c = _module_facts()
        assert readers == MATRIX_READERS, (
            "the set of functions that read a file changed - a new reader is a new row in the matrix (add its world, then list it here). "
            f"new: {sorted(set(readers) - set(MATRIX_READERS))} gone: {sorted(set(MATRIX_READERS) - set(readers))} changed: "
            f"{sorted(k for k in readers if k in MATRIX_READERS and readers[k] != MATRIX_READERS[k])}"
        )

    def test_the_matrix_covers_every_path_function_with_a_world(self):
        roles = {w.role for w in WORLDS}
        assert {"ca_crt", "ca_key"} <= roles  # ca_paths
        assert {"client_pem", "client_key"} <= roles  # client_paths
        assert {"server_crt", "server_key"} <= roles  # server_copy_path / server_key_path
        assert {"server_crt.prev", "server_crt.staged", "server.stale", "server.unknown"} <= roles  # the suffixed files
        assert {"next", "next_ca_cert", "next_client_key"} <= roles  # _staged_paths
        assert {"api_ca", "api_client"} <= roles  # the configured inputs
        assert "everything" in roles  # _copies_dir / the uninitialised evidence

    def test_the_matrix_is_big_enough_to_mean_something(self):
        # worlds x actions: five Lab actions here, three setup/remove actions in the setup harness (test_direct_socket_lock.py::TestTheWorldsOfTheSetupHarness)
        assert len(WORLDS) >= 60 and len(WORLDS) * 8 >= 480, len(WORLDS)


# ── the second pass of Q192: each finding as the sequence that found it, and the CROSSED and FAULTED worlds the single-input matrix could not build ──────────────


def _damage(role, state, tmp_path, monkeypatch):
    apply_world(World(role, state, "ca"), monkeypatch, tmp_path)


def _texts(lab):
    return lab.texts()


class TestTheSecondPassOfQ192:
    # finding 1 (P1) - a certificate that PARSES but whose public key is unusable
    @pytest.mark.parametrize("which", ["ca", "client"])
    def test_an_unusable_public_key_is_damage_never_a_500(self, lab, monkeypatch, tmp_path, which):
        lab.before = None
        if which == "ca":
            _damage("ca_crt", "invalid-key", tmp_path, monkeypatch)
        else:
            worlds.apply_state(
                "invalid-key", kea_tls.client_paths()[0], kea_tls.client_paths()[1], which="cert", client=True
            )
        lab.begin()
        state, why = kea_tls.ca_state() if which == "ca" else kea_tls.client_state()
        assert state == "damaged" and "unusable public key" in why, (state, why)
        summary = infra._kea_ca_summary()  # the Settings page: it used to raise ValueError -> 500 for every admin
        assert summary["damaged"] is True if which == "ca" else summary["client_state"] == "damaged"
        assert health._kea_tls_expiry({}).status == "fail"
        assert kea_tls.ca_refusal() == ("" if which == "client" else why)
        _rotate()
        if which == "ca":
            assert "Jen's CA is damaged" in lab.texts()
        else:
            assert "Kea CA rotated" in lab.texts() or lab.texts()

    def test_an_unusable_client_key_is_re_issued_from_an_ok_ca(self, lab):
        worlds.apply_state(
            "invalid-key", kea_tls.client_paths()[0], kea_tls.client_paths()[1], which="cert", client=True
        )
        lab.begin()
        lab.before = None
        assert kea_tls.issue_client_cert()["issued"] is True and kea_tls.client_state() == ("ok", "")

    # finding 2 (P1) - the bundle is judged by PATH when Jen's own CA certificate cannot be loaded; finding 12 - the crossed worlds
    CA_DAMAGE = [
        ("ca_crt", "absent"),
        ("ca_crt", "malformed"),
        ("ca_crt", "invalid-key"),
        ("ca_key", "absent"),
        ("ca_key", "mismatched"),
    ]

    @pytest.mark.parametrize("client", ["jens-file", "none", "copy"])
    @pytest.mark.parametrize("bundle", ["jens-file", "copy", "other-ca"])
    @pytest.mark.parametrize(("role", "state"), CA_DAMAGE, ids=[f"{r}:{s}" for r, s in CA_DAMAGE])
    def test_a_damaged_ca_crossed_with_every_bundle_and_client_shape_is_replaced_or_refused_before_anything_moves(
        self, lab, monkeypatch, tmp_path, role, state, bundle, client
    ):
        if bundle != "jens-file":
            apply_world(
                World("api_ca", bundle, "config"), monkeypatch, tmp_path
            )  # a copy of the CA BEFORE it is damaged
        if client != "jens-file":
            _client_world(client, tmp_path, monkeypatch)
        _damage(role, state, tmp_path, monkeypatch)
        _rotate({"acknowledge_damaged_ca": "1"})
        must_refuse = bundle != "jens-file" or client == "copy"
        if must_refuse:
            assert "Rotate refused" in lab.texts() and lab.remote_actions() == 0, (bundle, client, lab.texts())
            assert lab.settings_writes == []
        else:
            assert "Kea CA rotated" in lab.texts() or lab.texts(), lab.texts()
            if "Kea CA rotated" in lab.texts():
                assert kea_tls.ca_state() == ("ok", "")
                if (
                    client == "jens-file"
                ):  # (with no client pair configured Jen dials without a certificate: not a dial to hold - the Lab's stub does not apply the settings the route rewrites)
                    assert all(lab.answers_jens_configured_dial(sid) for sid in lab.hosts), (
                        "the dial holds on every endpoint"
                    )

    # finding 3 (P1, conditional) + the fault dimension - a refused install in a recovery never pushes the damaged file
    FAULTS = [(1, "install-tls", 1), (2, "install-tls", 1), (1, "service", 1)]

    @pytest.mark.parametrize("fault", FAULTS, ids=[f"{s}:{o}" for s, o, _n in FAULTS])
    @pytest.mark.parametrize(("role", "state"), CA_DAMAGE, ids=[f"{r}:{s}" for r, s in CA_DAMAGE])
    def test_a_recovery_with_a_failure_at_a_step_names_what_it_left_and_never_pushes_a_damaged_file(
        self, lab, monkeypatch, tmp_path, role, state, fault
    ):
        original_ca = {sid: lab.hosts[sid]["files"]["ca.crt"] for sid in lab.hosts}
        _damage(role, state, tmp_path, monkeypatch)
        lab.refuse.add(fault)
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" not in lab.texts(), "an injected failure is never a success"
        crt = pathlib.Path(kea_tls.ca_paths()[0])
        damaged_cert = crt.read_text(encoding="ascii", errors="replace") if crt.is_file() else None
        for sid in lab.hosts:
            held = lab.hosts[sid]["files"]["ca.crt"]
            assert damaged_cert is None or held == original_ca[sid] or held != damaged_cert, (
                f"server {sid}'s host was given the DAMAGED CA file as its trust anchor"
            )

    def test_the_install_payload_is_never_built_from_a_damaged_ca(self, lab, monkeypatch, tmp_path):
        assert kea_tls.current_material(1, "dhcp4") is not None
        _damage("ca_crt", "mismatched", tmp_path, monkeypatch)
        assert kea_tls.current_material(1, "dhcp4") is None and kea_tls.previous_material(1, "dhcp4") is None
        lab.begin()

    # finding 4 (P2) - the CA files gone but the client pair and copies remain is DAMAGED, and Rotate (acknowledged) is the way out
    def test_both_ca_files_gone_beside_a_client_pair_is_damaged_everywhere_and_the_acknowledged_rotate_recovers(
        self, lab, monkeypatch, tmp_path
    ):
        _damage("ca_both", "absent-beside-the-client-pair-and-copies", tmp_path, monkeypatch)
        lab.begin()
        assert kea_tls.ca_state()[0] == "damaged"
        summary = infra._kea_ca_summary()
        assert (
            summary["damaged"] is True
            and summary["state"] == "damaged"
            and "both CA files are missing" in summary["why"]
        )
        assert health._kea_tls_expiry({}).status == "fail"
        _rotate()
        assert "Jen's CA is damaged" in lab.texts() and "Nothing to rotate" not in lab.texts()
        lab.flashes.clear()
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()
        assert kea_tls.ca_state() == ("ok", "")

    def test_a_leftover_prev_a_directory_that_exists_and_a_dangling_one_are_all_evidence_a_ca_existed(
        self, lab, monkeypatch, tmp_path
    ):
        for role, state in (
            ("ca_prev_only", "everything-else-removed"),
            ("copies_dir", "empty-everything-else-removed"),
        ):
            apply_world(World(role, state, "ca"), monkeypatch, tmp_path)
            lab.begin()  # the world is built: this is the state before any action
            assert kea_tls.ca_state()[0] == "damaged", role
            with pytest.raises(kea_tls.CaDamaged):
                kea_tls.ensure_ca()
        lab.before = None
        lab.hosts.clear()

    # finding 5 (P2) - a damaged CA with an external endpoint: the live client pair is judged without the issuer
    @pytest.mark.parametrize("trust", ["any", None])
    def test_a_damaged_ca_beside_an_external_endpoint_that_does_not_depend_on_jens_ca_is_replaced(
        self, lab, trust, monkeypatch, tmp_path
    ):
        _add_external(lab, trust=trust)
        os.unlink(kea_tls.ca_paths()[1])
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "Kea CA rotated" in lab.texts(), lab.texts()

    def test_a_damaged_ca_beside_an_external_endpoint_that_trusts_jens_ca_for_clients_is_still_refused_by_the_probe(
        self, lab
    ):
        _add_external(lab, trust=_rotation.__dict__["_ca_pem"]())
        os.unlink(kea_tls.ca_paths()[1])
        _rotate({"acknowledge_damaged_ca": "1"})
        assert "accepts Jen's current client certificate and refuses the new one" in lab.texts(), lab.texts()
        assert lab.remote_actions() == 0

    # finding 6 (P2) - a read cannot destroy the prepared CA
    def test_the_settings_page_never_deletes_the_prepared_ca(self, lab):
        _rotation._prepare()
        staged = kea_tls._staged_paths()
        pathlib.Path(staged["client_key"]).write_text("not a key", encoding="ascii")
        summary = infra._kea_ca_summary()
        assert summary["prepared"] is False and "will discard it" in summary["prepared_note"]
        assert all(os.path.exists(p) for p in staged.values()), "a read destroyed nothing"
        lab.flashes.clear()
        _rotate()
        assert "so it was discarded" in lab.texts() and not any(os.path.exists(p) for p in staged.values())

    def test_a_prepared_ca_that_cannot_be_read_is_neither_reused_nor_discarded_nor_overwritten(self, lab, monkeypatch):
        _rotation._prepare()
        staged = kea_tls._staged_paths()
        before = {k: pathlib.Path(p).read_bytes() for k, p in staged.items()}
        real = kea_tls.load_key

        def flaky(path):
            if str(path).endswith(".next"):
                raise OSError(5, "Input/output error")
            return real(path)

        monkeypatch.setattr(kea_tls, "load_key", flaky)
        summary = infra._kea_ca_summary()
        assert summary["prepared"] is False and "cannot be read" in summary["prepared_note"]
        _rotate()
        assert "will not overwrite a CA it cannot read" in lab.texts() and lab.remote_actions() == 0
        lab.flashes.clear()
        _rotation._prepare()
        assert "Prepare refused" in lab.texts()
        monkeypatch.setattr(kea_tls, "load_key", real)
        assert {k: pathlib.Path(p).read_bytes() for k, p in staged.items()} == before, (
            "nothing was discarded or overwritten"
        )

    # finding 8 (P3) - Discard says so when it could not
    def test_discard_says_it_could_not_when_a_file_cannot_be_removed(self, lab):
        _rotation._prepare()
        staged = kea_tls._staged_paths()
        os.unlink(staged["ca_cert"])
        worlds.unreadable(staged["ca_cert"])  # a directory where the file was
        lab.flashes.clear()
        _rotation._discard_prepared()
        assert "could not be discarded" in lab.texts() and "was discarded" not in lab.texts()

    # finding 9 (P3) - the `.prev` names the promotion writes
    def test_a_directory_where_a_prev_copy_belongs_is_a_refusal_before_any_host_moves(self, lab):
        os.makedirs(kea_tls.client_paths()[1] + ".prev")
        assert any(".prev is a directory" in b for b in kea_tls.promotion_blockers())
        _rotate()
        assert "Rotate refused" in lab.texts() and "Jen cannot promote a new CA" in lab.texts()
        assert lab.remote_actions() == 0

    # finding 11 (P3) - a prepared pair that is expired or about to expire is not one to promote
    @pytest.mark.parametrize("age_days", [kea_tls.LEAF_DAYS + 5, kea_tls.LEAF_DAYS - 10])
    def test_a_prepared_client_certificate_that_is_expired_or_nearly_so_is_discarded_not_promoted(
        self, lab, monkeypatch, age_days
    ):
        import datetime

        real_now = kea_tls._now
        monkeypatch.setattr(kea_tls, "_now", lambda: real_now() - datetime.timedelta(days=age_days))
        kea_tls.stage_rotation()
        monkeypatch.setattr(kea_tls, "_now", real_now)
        staged, note = kea_tls.prepared_rotation()
        assert staged is None and "damaged or inconsistent" in note
        _rotate()
        assert "so it was discarded" in lab.texts() and "Kea CA rotated" in lab.texts(), lab.texts()
        assert kea_tls.client_state() == ("ok", ""), "what was promoted is valid"
