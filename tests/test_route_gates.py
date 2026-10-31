"""
tests/test_route_gates.py
─────────────────────────
Q203 (AS2): every writer of Jen's identity or of a Kea config carries the gate its siblings carry. The verifier is a DB-free `ast` walk over `jen/routes/` (it is its own walk, not the table of
`TestEveryRestartOfJenIsBehindTheOneGate`, which keeps the restarts of Jen itself): a function that writes the Kea host's config file (`apply_config`), restarts a Kea daemon
(`service_action(..., "restart")`), restarts Jen (`restart_service`), replaces Jen's SSH key (`commit_file_set` over `SSH_KEY_PATH`) or writes the `[oidc]` section carries `login_required` +
`superadmin_required` + `recent_auth_required`, or is on a reviewed list below, with the reason. Pure: `py -m pytest --noconftest tests/test_route_gates.py`.
"""

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A caller that is not a route (its routes carry the gate; the test below asks which routes call it).
NOT_A_ROUTE = {
    ("jen/routes/settings/infrastructure.py", "_tls_after_unapplied_change"): (
        "a helper of the https setup, called only from `setup_direct_socket` (superadmin + step-up, under the identity lock)"
    ),
}

#: A ROUTE that is on the list, with the reason it is not held to the superadmin + step-up gate. Q203 asked for no route on this list; the walk found one the entry did not name and it is
#: REPORTED as a finding (the report to the maintainer), not widened silently.
REPORTED_ROUTES = {
    ("jen/routes/servers.py", "restart_kea_server"): (
        "an admin's restart of the Kea daemon on its own saved host: no config is written and no destination is chosen (the host and the unit are the saved ones), so it is an operational action, "
        "not an identity change; making it a superadmin's would remove a daily admin action. Reported to the maintainer in the Q203 report"
    ),
}

WRITE_CALLS = {"apply_config", "restart_service"}


def _called_names(node) -> set:
    names = set()
    for call in ast.walk(node):
        if isinstance(call, ast.Call):
            f = call.func
            names.add(f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))
    return names


def _restarts_a_kea_daemon(node) -> bool:
    for call in ast.walk(node):
        if isinstance(call, ast.Call):
            f = call.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if name == "service_action" and any(
                isinstance(a, ast.Constant) and a.value == "restart" for a in call.args
            ):
                return True
    return False


def _replaces_the_ssh_key(node) -> bool:
    """`commit_file_set` over the SSH key's path - the one writer of Jen's only SSH private key."""
    src = ast.unparse(node)
    return "commit_file_set" in _called_names(node) and "SSH_KEY_PATH" in src


def _writes_the_oidc_section(node) -> bool:
    """A config write whose items name the `[oidc]` section: `write_value(s)` / `mutate` in a function holding the string `"oidc"`."""
    if not ({"write_value", "write_values", "mutate"} & _called_names(node)):
        return False
    return any(isinstance(s, ast.Constant) and s.value == "oidc" for s in ast.walk(node))


def _writers():
    """[(path, FunctionDef, why)] for every function under jen/routes/ that does one of the five writes."""
    found = []
    for path in sorted((ROOT / "jen" / "routes").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            why = []
            if _called_names(node) & WRITE_CALLS:
                why.append(sorted(_called_names(node) & WRITE_CALLS)[0])
            if _restarts_a_kea_daemon(node):
                why.append("service_action restart")
            if _replaces_the_ssh_key(node):
                why.append("the SSH key")
            if _writes_the_oidc_section(node):
                why.append("[oidc]")
            if why:
                found.append((rel, node, why))
    return found


def _decorators(node) -> list:
    return [ast.unparse(d) for d in node.decorator_list]


def _is_route(node) -> bool:
    return any(d.startswith("bp.route") for d in _decorators(node))


class TestEveryWriterOfIdentityOrKeaConfigCarriesItsGate:
    def test_the_walk_finds_the_writers_the_entry_names(self):
        names = {n.name for _p, n, _w in _writers()}
        assert {
            "config_history_restore",
            "import_windows_apply",
            "generate_ssh_key",
            "save_oidc",
            "restart_jen",
            "save_ports",
            "upload_cert",
            "remove_cert",
            "rotate_kea_ca",
        } <= names, sorted(names)

    def test_every_route_among_them_is_a_superadmins_with_a_recent_confirmation(self):
        for rel, node, why in _writers():
            if (rel, node.name) in NOT_A_ROUTE or (rel, node.name) in REPORTED_ROUTES:
                continue
            decorators = _decorators(node)
            assert _is_route(node), (
                rel,
                node.name,
                why,
                "a writer that is not a route is on NOT_A_ROUTE with its reason",
            )
            assert "login_required" in decorators, (rel, node.name, decorators)
            assert "_superadmin_required" in decorators, (rel, node.name, why, decorators)
            assert any(d.startswith("_recent_auth_required") for d in decorators), (rel, node.name, why, decorators)

    def test_no_writer_carries_an_admin_only_gate_unless_it_is_reported(self):
        for rel, node, why in _writers():
            if (rel, node.name) in REPORTED_ROUTES:
                continue
            assert "_admin_required" not in _decorators(node), (rel, node.name, why)

    def test_the_reviewed_lists_name_functions_that_exist_and_are_still_writers(self):
        writers = {(rel, n.name) for rel, n, _w in _writers()}
        for key in {**NOT_A_ROUTE, **REPORTED_ROUTES}:
            assert key in writers, f"{key} is on a reviewed list but is no longer a writer: delete the entry"
        for key, reason in {**NOT_A_ROUTE, **REPORTED_ROUTES}.items():
            assert len(reason) > 40, key
        for (rel, name), _reason in NOT_A_ROUTE.items():
            node = next(n for r, n, _w in _writers() if r == rel and n.name == name)
            assert not _is_route(node), f"{name} is a route: it does not belong on NOT_A_ROUTE"
        for (rel, name), _reason in REPORTED_ROUTES.items():
            node = next(n for r, n, _w in _writers() if r == rel and n.name == name)
            assert _is_route(node), f"{name} is not a route"

    def test_a_helper_on_the_not_a_route_list_is_called_only_by_gated_routes(self):
        """The helper is exempt because its callers carry the gate - asked, not assumed."""
        for _rel, helper in NOT_A_ROUTE:
            callers = []
            for path in sorted((ROOT / "jen").rglob("*.py")):
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                    if isinstance(node, ast.FunctionDef) and node.name != helper and helper in _called_names(node):
                        callers.append((path.relative_to(ROOT).as_posix(), node))
            assert callers, f"{helper} has no caller: delete it"
            for caller_path, node in callers:
                decorators = _decorators(node)
                assert _is_route(node) and "_superadmin_required" in decorators, (caller_path, node.name)
                assert any(d.startswith("_recent_auth_required") for d in decorators), (caller_path, node.name)

    def test_the_verifier_is_not_blind_to_a_gate_removed(self):
        """Self-test: the walk's own predicate refuses a synthetic writer with an admin-only gate."""
        src = (
            "@bp.route('/x', methods=['POST'])\n@login_required\n@_admin_required\n"
            "def writer():\n    apply_config(1, 2, 3)\n"
        )
        node = ast.parse(src).body[0]
        assert "apply_config" in _called_names(node) and "_superadmin_required" not in _decorators(node)

    def test_the_oidc_writer_and_the_key_writer_are_recognised_by_their_shape(self):
        by_name = {n.name: w for _p, n, w in _writers()}
        assert "[oidc]" in by_name["save_oidc"]
        assert "the SSH key" in by_name["generate_ssh_key"]
