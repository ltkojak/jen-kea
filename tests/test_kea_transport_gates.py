"""
tests/test_kea_transport_gates.py
─────────────────────────────────
Q212 (BB7 d) - a route reads or writes a Kea configuration through the TARGET'S TRANSPORT (`kea_host.read_via_transport`, `kea_changeset._transport`), never through the SSH flag. Whole-tree: every
function under jen/routes/ that tests `get("ssh_host")` AND touches a configuration (read, test or write) is on the reviewed list below with the reason it stays; a moved gate may not come back; a
reviewed entry that no longer exists fails (the list is not allowed to rot). Pure `ast`: runs under `--noconftest`.
"""

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG_CALLS = {
    "read_config",
    "read_config_versioned",
    "apply_config",
    "test_config",
    "apply_change",
    "read_via_transport",
}

# (file, function) -> why the SSH flag is still asked there
REVIEWED = {
    (
        "jen/routes/settings/authoring.py",
        "author_kea_config_preview",
    ): "authoring a host's FIRST file is file-only (absent_is_expected): there is no daemon to ask yet",
    (
        "jen/routes/settings/authoring.py",
        "author_kea_config_post",
    ): "the same: Author Kea Config writes a first file over SSH (helper_only) and is never an API path",
    (
        "jen/routes/settings/infrastructure.py",
        "setup_direct_socket",
    ): "a change to control-sockets is never sent over the socket it changes: transport='file', host work",
    ("jen/routes/settings/infrastructure.py", "remove_direct_socket"): "the same, in the other direction",
    (
        "jen/routes/subnets.py",
        "edit_subnet_preview",
    ): "the only `ssh_host` read is the name fallback `server.get('name') or server.get('ssh_host')`, not a gate",
    ("jen/routes/subnets.py", "edit_subnet6_preview"): "the same name fallback",
    ("jen/routes/subnets.py", "dhcp_class_preview"): "the same name fallback in the failure line",
    (
        "jen/routes/subnets.py",
        "import_windows_apply_reservations",
    ): "the reservation retry exists for a failed RESTART; an import applied over the API has none, so this step is file-only",
}

# the gates that MOVED to the transport: they may not test the SSH flag any more
MOVED = {
    ("jen/routes/subnets.py", "_config_shas"),
    ("jen/routes/ddns.py", "_naming_tab_context"),
    ("jen/routes/ddns.py", "_d2config_tab_context"),
    ("jen/routes/ddns.py", "ddns_naming_save"),
    ("jen/routes/subnets.py", "import_windows_preview"),
    ("jen/routes/subnets.py", "import_windows_apply"),
}


def _ssh_gets(fn):
    return [
        c
        for c in ast.walk(fn)
        if isinstance(c, ast.Call)
        and isinstance(c.func, ast.Attribute)
        and c.func.attr == "get"
        and c.args
        and isinstance(c.args[0], ast.Constant)
        and c.args[0].value == "ssh_host"
    ]


def _calls(fn):
    return {
        (c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, "id", ""))
        for c in ast.walk(fn)
        if isinstance(c, ast.Call)
    }


def _functions():
    out = {}
    for path in sorted((ROOT / "jen" / "routes").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        for fn in (n for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))) if isinstance(n, ast.FunctionDef)):
            out[(rel, fn.name)] = fn
    return out


class TestRoutesAskTheTransportNotTheFlag:
    def test_a_function_that_touches_a_configuration_and_asks_the_ssh_flag_is_reviewed(self):
        offenders = []
        for key, fn in _functions().items():
            if _ssh_gets(fn) and _calls(fn) & CONFIG_CALLS and key not in REVIEWED:
                offenders.append((key, sorted(_calls(fn) & CONFIG_CALLS)))
        assert offenders == [], f"a route reads or writes a configuration behind the SSH flag: {offenders}"

    def test_the_reviewed_list_has_no_stale_entry(self):
        functions = _functions()
        stale = [
            key
            for key in REVIEWED
            if key not in functions or not (_ssh_gets(functions[key]) and _calls(functions[key]) & CONFIG_CALLS)
        ]
        assert stale == [], f"reviewed entries that no longer test the flag beside a configuration call: {stale}"

    def test_a_moved_gate_does_not_come_back(self):
        functions = _functions()
        missing = [k for k in MOVED if k not in functions]
        assert missing == []
        back = [k for k in MOVED if _ssh_gets(functions[k])]
        assert back == [], f"these functions asked the SSH flag again: {back}"

    def test_the_thirteen_reads_go_through_one_dispatch(self):
        """No route reads a dhcp4/dhcp6/d2 configuration with `read_config_versioned` / `read_config` any more, except the file-only places on the reviewed list and the host-feature routes."""
        direct = []
        for key, fn in _functions().items():
            for c in ast.walk(fn):
                if isinstance(c, ast.Call):
                    name = c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, "id", "")
                    if name in ("read_config", "read_config_versioned"):
                        direct.append(key)
        allowed = {
            ("jen/routes/subnets.py", "import_windows_apply_reservations"),  # the file-only retry
            ("jen/routes/settings/authoring.py", "_author_kea_config_for"),  # authoring's own read (a first file)
            (
                "jen/routes/settings/authoring.py",
                "_author_server_state",
            ),  # authoring's own read of what the host has (a first file: there may be no daemon)
            (
                "jen/routes/settings/infrastructure.py",
                "_api_sockets_of",
            ),  # the direct-socket setup reads the FILE's control-sockets: file-only by design
            (
                "jen/routes/settings/infrastructure.py",
                "_preread_refusal",
            ),  # the direct-socket pre-read: file-only by design
            (
                "jen/routes/servers.py",
                "config_history_restore",
            ),  # the file branch of the restore (the api branch reads through kea_api_config)
        }
        extra = sorted(set(direct) - allowed)
        assert extra == [], f"direct file reads in routes: {extra}"
