"""
tests/test_sudoers_command_matching.py
────────────────────────────────────────
v5.2.9 — a real bug this test would have caught before it shipped:
the v5.2.6 security fix's sudoers rule authorized
`/usr/bin/systemctl start jen-update.service`, but the actual code
invoked `/usr/bin/systemctl start --no-block jen-update.service` — an
extra `--no-block` flag added for a real behavioral reason (so the
Flask worker doesn't block waiting on a service whose own final step
kills that exact worker) but never reflected in the sudoers rule.

sudo matches commands LITERALLY, argument-by-argument, unless
wildcards are used in the sudoers rule itself (which this project
deliberately doesn't — a wildcard here would reopen exactly the kind
of attacker-controllable-input gap the v5.2.6 rewrite exists to close).
That means a `sudo <command>` invocation whose exact argument list
doesn't match what's authorized fails with a permission denial, not a
"command not found" or similar — which is precisely what happened:
self-update was completely broken on every attempt from v5.2.6 onward,
not just during the one expected transition-release gap, because the
mismatch was permanent, not transitional.

This test parses jen-sudoers directly and cross-checks every
sudo-invoking subprocess.run() call in jen/routes/settings.py against
it via AST — not string-matching on source text, which would be
fragile against reformatting — so any future addition or edit to a
sudo command is checked against what's actually authorized, not just
assumed to match.
"""

import ast
import pathlib


def _parse_sudoers_authorized_commands(path="jen-sudoers"):
    """Return the set of authorized command strings (everything after
    'NOPASSWD: ') from the sudoers file, one per line."""
    text = pathlib.Path(path).read_text()
    commands = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        marker = "NOPASSWD: "
        idx = line.find(marker)
        if idx == -1:
            continue
        commands.add(line[idx + len(marker) :].strip())
    return commands


def _find_sudo_invocations(path="jen/routes/settings.py"):
    """
    Walk the AST of the given file and return every argument list
    passed to subprocess.run() (or subprocess.Popen()) whose first
    element is "/usr/bin/sudo", as a list of the literal string
    arguments. Only picks up calls where every argument is a plain
    string literal (the actual case for every sudo call in this
    codebase — none of them build the command from a variable or an
    f-string, which is itself a property worth it being true).
    """
    tree = ast.parse(pathlib.Path(path).read_text())
    invocations = []

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node):
            func = node.func
            is_subprocess_call = isinstance(func, ast.Attribute) and func.attr in ("run", "Popen")
            if is_subprocess_call and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.List):
                    elements = first_arg.elts
                    if elements and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elements):
                        values = [e.value for e in elements]
                        if values and values[0] == "/usr/bin/sudo":
                            invocations.append(values)
            self.generic_visit(node)

    Visitor().visit(tree)
    return invocations


class TestEverySudoInvocationMatchesAnAuthorizedCommand:
    def test_at_least_one_sudo_invocation_and_one_authorized_command_exist(self):
        """Sanity check that both extraction methods actually found
        something — if either comes back empty, the rest of this
        test class would trivially (and misleadingly) pass."""
        assert len(_parse_sudoers_authorized_commands()) >= 1
        assert len(_find_sudo_invocations()) >= 1

    def test_every_invoked_sudo_command_is_authorized_in_sudoers(self):
        authorized = _parse_sudoers_authorized_commands()
        invocations = _find_sudo_invocations()
        mismatches = []
        for argv in invocations:
            # argv[0] is "/usr/bin/sudo" itself — not part of the
            # authorized command, which describes what may be run AS
            # root, not the sudo invocation that requests it.
            invoked_command = " ".join(argv[1:])
            if invoked_command not in authorized:
                mismatches.append(invoked_command)
        assert not mismatches, (
            f"The following command(s) are invoked via sudo in "
            f"jen/routes/settings.py but do not exactly match any "
            f"command authorized in jen-sudoers (sudo matches "
            f"literally — any difference, including an added/removed "
            f"flag, causes a permission denial at runtime): {mismatches}. "
            f"Authorized commands are: {sorted(authorized)}"
        )

    def test_jen_update_service_trigger_includes_no_block(self):
        """The specific regression this test exists for: confirms
        --no-block is present in BOTH the invoked command and the
        sudoers authorization, not just that they happen to match each
        other (which they'd also do if --no-block were removed from
        both — this pins down that this specific behavioral choice is
        still what's actually shipped)."""
        invocations = _find_sudo_invocations()
        update_calls = [argv for argv in invocations if "jen-update.service" in argv]
        assert len(update_calls) == 1, f"expected exactly one jen-update.service sudo call, found {len(update_calls)}"
        assert "--no-block" in update_calls[0]

        authorized = _parse_sudoers_authorized_commands()
        update_rules = [cmd for cmd in authorized if "jen-update.service" in cmd]
        assert len(update_rules) == 1, (
            f"expected exactly one jen-update.service sudoers rule, found {len(update_rules)}"
        )
        assert "--no-block" in update_rules[0]

    def test_no_sudoers_rule_uses_a_wildcard(self):
        """A wildcard in a NOPASSWD sudoers rule would let www-data's
        exact-match requirement be satisfied by attacker-influenced
        input again — exactly the class of gap the v5.2.6 rewrite
        exists to close. Every authorized command in this file must be
        a complete, literal, fixed string."""
        authorized = _parse_sudoers_authorized_commands()
        for cmd in authorized:
            assert "*" not in cmd, f"sudoers rule contains a wildcard: {cmd!r}"
