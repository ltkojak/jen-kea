"""
tests/typed_claims.py
─────────────────────
v5.69.0-beta.16 (Q185, AA2) - the checker behind `tests/test_credentials.py::TestTypedIsAHumansAct`, reduced to the rule CRED-004 states.

The registry: the writer's `typed` set is a human's act in this request or the one-time conversion; a route never derives it from hosts, DNS or history. Beta.15's checker accepted a
broader language than that (it whitelisted `extensions` wholesale, trusted any parameter, left f-strings and comprehension elements unchecked, refused `.add()` only under `if`/`while`,
and matched the writer by attribute name), and an executing pass found seventeen shapes derived from hosts, configuration or history that it let through. This one accepts exactly:

  (a) a set display of string literals;
  (b) `None` or `set()`;
  (c) `A if COND else B` where COND is a boolean expression over `request.form.get(...)` / `request.form.getlist(...)` (optionally `.strip()`ed), constants, string-literal
      set/tuple/list membership and comparisons - and names bound EXACTLY ONCE, in the same function, to such an expression - and nothing else; `B` may be another conditional;
  (d) a NAME bound exactly once in the function to one of (a)-(c), whose only other occurrence is as the `typed=` argument of a writer call.

AND the control flow that reaches a claim is judged too: a writer call that makes a claim may sit under an `if` only when the `if`'s test is itself form-only (the statement spelling of
`A if COND else B`), never under a loop, never in an `except`/`finally` handler.

What the reach layer IS (Q186, AB4): SYNTACTIC. It reads the ancestors of the writer call inside the innermost function that contains it, so a claim placed under an `if`, loop or handler the
request does not decide is caught. It is a smell detector, not a proof: a claim reached through a call into another function is not followed, and an UNCONDITIONAL literal claim
(`typed={"kea"}`) is accepted by design - a literal names an endpoint the function was written to claim. The guarantee is the shape rule above; the reach layer is what notices code that
moved a claim somewhere the shape rule does not look.

Anything else fails: a read of `extensions`, any call that is not `request.form.get/getlist`, an f-string, a comprehension, a walrus, a lambda, `getattr`, `partial`, a parameter (the
caller's claim is not this function's), a name that is rebound, `.add()`ed to or handed anywhere, an aliased writer or an aliased `app_config`, a shadowed `request`, `*args`/`**kwargs`.

Eight functions are dynamic by nature, and `DYNAMIC` names each with the ONE extra thing it may do, WHICH parts of it, and why - the test asserts the list, so it cannot grow silently:
the one-time conversion; the setup wizard's two service functions (the route passes them the form's values, and only the named parameters count); the three direct-socket routes and the
copy button (the endpoint the URL names - the button pressed is the claim); and the extra-servers form (one claim per row the person typed a password on or ticked the share box for).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

#: the objects whose methods are the config writer. `AppConfig` is a singleton named `app_config`; a route imports it as `app_config` or reaches it as `__config.app_config`.
WRITER_OBJECTS = {"app_config", "__config.app_config", "config.app_config"}
WRITERS = {
    "write_values": 1,
    "write_value": 3,
    "mutate": 1,
    "preflight_identity_change": 1,
}  # name -> positional arguments the call may have
#: calls that take a `typed=` keyword and are not the writer (Explain's typed INPUTS)
NOT_THE_WRITER = {"build_inputs"}

#: (file, function) -> (capability, why, details). The capability is the ONE thing that function may do beyond the strict rule; `details` narrows it.
DYNAMIC = {
    ("jen/services/credentials.py", "materialise"): (
        "conversion",
        "the one-time conversion types every endpoint it writes, by design (CRED-004, U2)",
        {},
    ),
    ("jen/services/setup_wizard.py", "save_connection"): (
        "params",
        "the wizard route passes the passwords the person typed; the claim is over those parameters",
        {"params": {"api_pass", "kea_db_pass"}},
    ),
    ("jen/services/setup_wizard.py", "enable_v6"): (
        "params",
        "the wizard route passes the password the person typed; the claim is over that parameter",
        {"params": {"api_pass"}},
    ),
    ("jen/routes/settings/infrastructure.py", "setup_direct_socket"): (
        "endpoint_name",
        "the endpoint the URL names: the person pressed THIS button with this socket's password",
        {},
    ),
    ("jen/routes/settings/infrastructure.py", "_write_direct_socket_config"): (
        "endpoint_name",
        "the endpoint the URL names",
        {},
    ),
    ("jen/routes/settings/infrastructure.py", "remove_direct_socket"): (
        "endpoint_name",
        "the endpoint the URL names, claimed only when the form carried an answer",
        {"cond_required": True},
    ),
    ("jen/routes/settings/infrastructure.py", "copy_primary_password"): (
        "server_fstring",
        "the server the URL names; pressing 'copy again' is the claim",
        {},
    ),
    ("jen/routes/settings/infrastructure.py", "save_extra_servers"): (
        "adds",
        "one claim per row the person typed a password on or ticked the share box for",
        {
            "adder": "_rewrite_extra_servers",
            # Q199 (AO2): `row_id` is the id the form carried, or - for a blank-id row whose SSH host and address are exactly a saved server's - that server's own number, read from the
            # snapshot under the lock; it can only NAME an existing server (it never makes a password typed), so the pin follows the row number the loop computes
            "out": "row_id if row_id is not None else max({1, *existing, *seen_ids}) + 1",
        },
    ),
}

PURE_BUILTINS = {"bool", "str", "len", "int", "set", "zip", "enumerate", "range", "sum", "any", "all", "list", "tuple"}
PURE_METHODS = {"strip", "lower", "upper", "startswith", "endswith", "isdigit"}
FORM_RECEIVERS = {"request.form"}
FORM_METHODS = {"get", "getlist"}
COND_OPS = (ast.Eq, ast.NotEq, ast.In, ast.NotIn, ast.Is, ast.IsNot)
SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


@dataclass
class _Caps:
    cap: str = ""
    details: dict = field(default_factory=dict)

    def has(self, name: str) -> bool:
        return self.cap == name


class _Scope:
    """One function's own bindings (nested functions and lambdas are scopes of their own)."""

    def __init__(self, node, parent):
        self.node, self.parent = node, parent
        self.params: set[str] = set()
        self.binds: dict[str, list[tuple[str, ast.AST | None]]] = {}
        args = node.args
        for a in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
            if a is not None:
                self.params.add(a.arg)
        body = node.body if isinstance(node.body, list) else [node.body]
        for stmt in body:
            self._walk(stmt)

    def _bind(self, target, kind, value):
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name):
                self.binds.setdefault(sub.id, []).append((kind, value))

    def _walk(self, node):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            self.binds.setdefault(node.name, []).append(("def", node))
            return  # its body is its own scope
        if isinstance(node, ast.Lambda | ast.ClassDef):
            return
        if isinstance(node, ast.Assign):
            for t in node.targets:
                self._bind(t, "assign" if isinstance(t, ast.Name) else "unpack", node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            self._bind(node.target, "assign", node.value)
        elif isinstance(node, ast.AugAssign):
            self._bind(node.target, "aug", node.value)
        elif isinstance(node, ast.For | ast.AsyncFor):
            self._bind(node.target, "for", node.iter)
        elif isinstance(node, ast.comprehension):
            self._bind(node.target, "comp", node.iter)
        elif isinstance(node, ast.NamedExpr):
            self._bind(node.target, "walrus", node.value)
        elif isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, "with", item.context_expr)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                self.binds.setdefault((alias.asname or alias.name).split(".")[0], []).append(("import", node))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self.binds.setdefault(node.name, []).append(("except", node))
        elif isinstance(node, ast.Global | ast.Nonlocal):
            for n in node.names:
                self.binds.setdefault(n, []).append(("global", node))
        for child in ast.iter_child_nodes(node):
            self._walk(child)

    def lookup(self, name):
        """The scope that binds `name` (this one, or an enclosing function's), else None."""
        scope = self
        while scope is not None:
            if name in scope.binds or name in scope.params:
                return scope
            scope = scope.parent
        return None


def _request_is_shadowed(scope) -> bool:
    return scope is not None and scope.lookup("request") is not None


def _is_form_call(node, scope=None) -> bool:
    """`request.form.get("x", "")` / `.getlist("x")`, optionally followed by `.strip()`; arguments are constants; `request` is the framework's, never a name this code bound."""
    if _request_is_shadowed(scope):
        return False
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "strip"
        and not node.args
        and not node.keywords
    ):
        return _is_form_call(node.func.value, scope)
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in FORM_METHODS):
        return False
    return (
        ast.unparse(node.func.value) in FORM_RECEIVERS
        and not any(isinstance(a, ast.Starred) for a in node.args)
        and all(isinstance(a, ast.Constant) for a in node.args)
        and all(k.arg is not None and isinstance(k.value, ast.Constant) for k in node.keywords)
    )


def _operand(node, scope, caps, seen) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Set | ast.Tuple | ast.List):
        return all(isinstance(e, ast.Constant) for e in node.elts)
    if _is_form_call(node, scope):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("bool", "len")
        and len(node.args) == 1
        and not node.keywords
    ):
        return _is_form_call(node.args[0], scope)  # bool(request.form.get("x")) / len(request.form.getlist("x"))
    if isinstance(node, ast.Attribute):
        return ast.unparse(node) == "request.form" and not _request_is_shadowed(
            scope
        )  # as the right side of `"x" in request.form`
    if isinstance(node, ast.Name):
        return _name_ok(node.id, scope, caps, seen, _operand_or_cond)
    return False


def _operand_or_cond(node, scope, caps, seen) -> bool:
    return _cond(node, scope, caps, seen) or _operand(node, scope, caps, seen)


def _cond(node, scope, caps, seen) -> bool:
    """A boolean expression over the REQUEST's form values and constants - nothing else."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BoolOp):
        return all(_operand_or_cond(v, scope, caps, seen) for v in node.values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _operand_or_cond(node.operand, scope, caps, seen)
    if isinstance(node, ast.Compare):
        return all(isinstance(op, COND_OPS) for op in node.ops) and all(
            _operand(x, scope, caps, seen) for x in [node.left, *node.comparators]
        )
    if isinstance(node, ast.Call | ast.Name):
        return _operand(node, scope, caps, seen)
    return False


def _name_ok(name, scope, caps, seen, judge) -> bool:
    """A name is as good as its single binding: bound EXACTLY once in the function that owns it, by a plain assignment, to something `judge` accepts. A parameter is the caller's claim,
    accepted only for the parameters a DYNAMIC `params` entry names, and only if the function never rebinds it."""
    if name in seen:
        return False
    owner = scope.lookup(name) if scope is not None else None
    if owner is None:
        return False
    if name in owner.params:
        return (
            caps.has("params")
            and owner is scope
            and name in caps.details.get("params", set())
            and name not in owner.binds
        )
    binds = owner.binds.get(name, [])
    if len(binds) != 1 or binds[0][0] != "assign":
        return False
    return judge(binds[0][1], owner, caps, seen | {name})


def _endpoint_arg_ok(node, scope) -> bool:
    """An argument of `_endpoint_name(server, service)` is one of the ROUTE'S OWN parameters (`service`, `server_id`), or a name bound once to `_server_by_id(<parameter>)` - the endpoint
    the URL names; never a value computed from anything else."""
    if isinstance(node, ast.Constant):
        return True
    if not isinstance(node, ast.Name) or scope is None:
        return False
    owner = scope.lookup(node.id)
    if owner is None:
        return False
    if node.id in owner.params:
        return node.id not in owner.binds
    binds = owner.binds.get(node.id, [])
    if len(binds) != 1 or binds[0][0] != "assign":
        return False
    value = binds[0][1]
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "_server_by_id"
        and len(value.args) == 1
        and not value.keywords
        and isinstance(value.args[0], ast.Name)
        and value.args[0].id in owner.params
        and value.args[0].id not in owner.binds
    )


def _name_element(node, scope, caps) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if caps.has("endpoint_name") and isinstance(node, ast.Call):
        return (
            getattr(node.func, "id", "") == "_endpoint_name"
            and not node.keywords
            and len(node.args) == 2
            and all(_endpoint_arg_ok(a, scope) for a in node.args)
        )
    if caps.has("server_fstring") and isinstance(node, ast.JoinedStr):
        return (
            ast.unparse(node) in ("f'server_{server_id}'", 'f"server_{server_id}"')
            and scope is not None
            and "server_id" in scope.params
            and "server_id" not in scope.binds
        )
    return False


def _typed_value(node, scope, caps, seen=frozenset()) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is None
    if isinstance(node, ast.Set):
        return all(_name_element(e, scope, caps) for e in node.elts)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "set" and not node.args and not node.keywords:
            return True
        return caps.has("conversion") and ast.unparse(node) == "set(resolve(probe))"
    if isinstance(node, ast.IfExp):
        return (
            _cond_for(node.test, scope, caps)
            and _typed_value(node.body, scope, caps, seen)
            and _typed_value(node.orelse, scope, caps, seen)
        )
    if isinstance(node, ast.SetComp):
        # the setup wizard's `{n for n, v in (("kea", api_pass), ("kea_db", kea_db_pass)) if v}`: a literal table of (name, parameter) pairs and a test on the value
        if not caps.has("params") or not (isinstance(node.elt, ast.Name) and len(node.generators) == 1):
            return False
        gen = node.generators[0]
        allowed = caps.details.get("params", set())
        names = [t.id for t in gen.target.elts if isinstance(t, ast.Name)] if isinstance(gen.target, ast.Tuple) else []
        if len(names) != 2 or node.elt.id != names[0]:
            return False
        return (
            isinstance(gen.iter, ast.Tuple)
            and all(
                isinstance(t, ast.Tuple)
                and len(t.elts) == 2
                and isinstance(t.elts[0], ast.Constant)
                and isinstance(t.elts[1], ast.Name)
                and t.elts[1].id in allowed
                and t.elts[1].id not in scope.binds
                for t in gen.iter.elts
            )
            and all(isinstance(i, ast.Name) and i.id == names[1] for i in gen.ifs)
        )
    if isinstance(node, ast.Name):
        if caps.has("adds"):
            return _built_by_adds(node.id, scope, caps)
        return _name_ok(node.id, scope, caps, seen, lambda v, s, c, sn: _typed_value(v, s, c, sn))
    return False


def _cond_for(test, scope, caps) -> bool:
    if caps.has("params"):
        return _params_cond(test, scope, caps)
    return _cond(test, scope, caps, frozenset())


def _params_cond(node, scope, caps) -> bool:
    """For the wizard's service functions: a boolean over the NAMED parameters (never rebound), constants and `not`/`and`/`or`."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return node.id in caps.details.get("params", set()) and node.id in scope.params and node.id not in scope.binds
    if isinstance(node, ast.BoolOp):
        return all(_params_cond(v, scope, caps) for v in node.values)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _params_cond(node.operand, scope, caps)
    return False


# ── the extra-servers form: one claim per row ────────────────────────────────────────────────────────────────────────────────────────────────
def _wide_pure(node, scope, seen=frozenset()) -> bool:
    """For the `adds` capability only: an expression over the REQUEST (names bound to form lists, loop variables over them, `len`, subscripts, string methods). No `extensions`, no
    parameters, no walrus, no calls beyond the builtins and string methods."""
    if node is None or isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        if node.id in ("None", "True", "False") or node.id in seen:
            return True
        owner = scope.lookup(node.id) if scope is not None else None
        if owner is None or node.id in owner.params:
            return False
        binds = owner.binds.get(node.id, [])
        return bool(binds) and all(
            k in ("assign", "for", "comp", "unpack") and _wide_pure(v, owner, seen | {node.id}) for k, v in binds
        )
    if isinstance(node, ast.Attribute):
        return ast.unparse(node) in ("request.form",) and not _request_is_shadowed(scope)
    if isinstance(node, ast.Subscript):
        return _wide_pure(node.value, scope, seen) and _wide_pure(node.slice, scope, seen)
    if isinstance(node, ast.Call):
        if any(k.arg is None for k in node.keywords) or any(isinstance(a, ast.Starred) for a in node.args):
            return False
        if _is_form_call(node, scope):
            return True
        args_ok = all(_wide_pure(a, scope, seen) for a in node.args) and all(
            _wide_pure(k.value, scope, seen) for k in node.keywords
        )
        if isinstance(node.func, ast.Name):
            return node.func.id in PURE_BUILTINS and args_ok
        if isinstance(node.func, ast.Attribute) and node.func.attr in PURE_METHODS:
            return _wide_pure(node.func.value, scope, seen) and args_ok
        return False
    if isinstance(node, ast.BoolOp | ast.UnaryOp | ast.Compare | ast.IfExp | ast.Tuple | ast.List | ast.Set):
        return all(
            _wide_pure(c, scope, seen)
            for c in ast.iter_child_nodes(node)
            if not isinstance(c, ast.expr_context | ast.operator | ast.cmpop | ast.boolop | ast.unaryop)
        )
    return False


def _top(node):
    top = node
    while getattr(node, "parent", None) is not None:
        node = node.parent
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            top = node
    return top


_SCOPES: dict[int, _Scope] = {}


def _scope_of(node):
    """The innermost function scope containing `node` (built on demand, parents linked)."""
    chain = []
    cur = node
    while cur is not None:
        if isinstance(cur, SCOPES):
            chain.append(cur)
        cur = getattr(cur, "parent", None)
    scope = None
    for fn in reversed(chain):
        key = id(fn)
        if key not in _SCOPES:
            _SCOPES[key] = _Scope(fn, scope)
        scope = _SCOPES[key]
    return scope


def _built_by_adds(name, scope, caps) -> bool:
    if not caps.has("adds") or scope is None:
        return False
    owner = scope.lookup(name)
    if owner is None:
        return False
    binds = owner.binds.get(name, [])
    if len(binds) != 1 or binds[0][0] != "assign" or ast.unparse(binds[0][1]) != "set()":
        return False
    top = _top(owner.node)
    adder = caps.details.get("adder", "")
    adds = []
    for node in ast.walk(top):
        if isinstance(node, ast.Global | ast.Nonlocal) and name in node.names:
            return False
        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return False
        if isinstance(node, ast.Name) and node.id == name:
            parent = getattr(node, "parent", None)
            is_add = (
                isinstance(parent, ast.Attribute)
                and parent.attr == "add"
                and isinstance(getattr(parent, "parent", None), ast.Call)
                and parent.parent.func is parent
            )
            is_typed = isinstance(parent, ast.keyword) and parent.arg == "typed"
            if isinstance(node.ctx, ast.Load) and not (is_add or is_typed):
                return False  # handed to a helper, returned, iterated, ...: only `.add(...)` and `typed=` may touch it
            if is_add:
                adds.append(parent.parent)
    if not adds:
        return False
    # the row number the claim names is the one the form's own loop computes - pinned, so `out = dns_pick(host)` is not an edit that passes
    out_binds = [b for fn in ast.walk(top) if isinstance(fn, SCOPES) for b in _Scope(fn, None).binds.get("out", [])]
    if not out_binds or any(ast.unparse(v) != caps.details.get("out") for _k, v in out_binds):
        return False
    for call in adds:
        if len(call.args) != 1 or call.keywords or not isinstance(call.args[0], ast.JoinedStr):
            return False
        if ast.unparse(call.args[0]) not in ("f'server_{out}'", "f'server_{out}_v6'"):
            return False
        inner = _scope_of(call)
        if getattr(inner.node, "name", "") != adder:
            return False  # an add in any other nested function (called under who knows what) is not the form's loop
        ancestor = getattr(call, "parent", None)
        while ancestor is not None and not isinstance(ancestor, (*SCOPES, ast.Module)):
            if isinstance(ancestor, ast.If | ast.IfExp | ast.While) and not _wide_pure(ancestor.test, inner):
                return False
            if isinstance(ancestor, ast.For | ast.AsyncFor) and not _wide_pure(ancestor.iter, inner):
                return False
            if isinstance(ancestor, ast.With | ast.AsyncWith | ast.Try):
                return False
            ancestor = getattr(ancestor, "parent", None)
    # an early `continue`/`break`/`return` in the form's loop may only be guarded by the request (a refusal `raise` on any test is the safe direction and is allowed)
    for fn in ast.walk(top):
        if isinstance(fn, ast.FunctionDef) and fn.name == adder:
            inner = _scope_of(fn)
            for stmt in ast.walk(fn):
                if isinstance(stmt, ast.Continue | ast.Break | ast.Return):
                    if not isinstance(stmt, ast.Return):
                        # a continue/break only skips an add that sits in the same loop body
                        loop = getattr(stmt, "parent", None)
                        while (
                            loop is not None
                            and loop is not fn
                            and not isinstance(loop, ast.For | ast.AsyncFor | ast.While)
                        ):
                            loop = getattr(loop, "parent", None)
                        if loop is None or loop is fn or not any(_is_inside(a, loop) for a in adds):
                            continue
                    guard = getattr(stmt, "parent", None)
                    while guard is not None and guard is not fn:
                        if isinstance(guard, ast.If | ast.While) and not _wide_pure(guard.test, inner):
                            return False
                        guard = getattr(guard, "parent", None)
    return True


def _is_inside(node, ancestor) -> bool:
    while node is not None:
        if node is ancestor:
            return True
        node = getattr(node, "parent", None)
    return False


def _claim_is_empty(value) -> bool:
    return (isinstance(value, ast.Constant) and value.value is None) or (
        isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "set" and not value.args
    )


def untyped_claims(source: str, path: str = "<snippet>") -> list[str]:
    """One line per violation of the rule in `source`: a `typed=` that is not a human's act, a writer reached by an alias, positional or `**` arguments smuggling it, a claim reached through
    control flow the request does not decide."""
    _SCOPES.clear()
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    bad: list[str] = []

    def named(node):
        found, cur = "<module>", node
        while cur is not None:
            if isinstance(cur, ast.FunctionDef | ast.AsyncFunctionDef):
                found = cur.name
                break
            cur = getattr(cur, "parent", None)
        return found

    def outermost(node):
        found, cur = None, node
        while cur is not None:
            if isinstance(cur, ast.FunctionDef | ast.AsyncFunctionDef):
                found = cur
            cur = getattr(cur, "parent", None)
        return found

    for node in ast.walk(tree):
        # aliases of the writer object, getattr on it, a writer method that is not called here, an import under another name
        if (
            isinstance(node, ast.Assign | ast.AnnAssign)
            and node.value is not None
            and ast.unparse(node.value) in WRITER_OBJECTS
        ):
            bad.append(
                f"{path}:{node.lineno} in {named(node)}(): an alias of the config writer ({ast.unparse(node)[:60]})"
            )
        if isinstance(node, ast.ImportFrom) and any(a.name == "app_config" and a.asname for a in node.names):
            bad.append(f"{path}:{node.lineno} in {named(node)}(): app_config imported under another name")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and node.args
            and ast.unparse(node.args[0]) in WRITER_OBJECTS
        ):
            bad.append(f"{path}:{node.lineno} in {named(node)}(): getattr on the config writer")
        if (
            isinstance(node, ast.Attribute)
            and node.attr in WRITERS
            and ast.unparse(node.value) in WRITER_OBJECTS
            and not (isinstance(getattr(node, "parent", None), ast.Call) and node.parent.func is node)
        ):
            bad.append(
                f"{path}:{node.lineno} in {named(node)}(): a config writer method that is not called here ({ast.unparse(node)})"
            )
        if not isinstance(node, ast.Call):
            continue
        is_writer = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in WRITERS
            and ast.unparse(node.func.value) in WRITER_OBJECTS
        )
        typed_kws = [k for k in node.keywords if k.arg == "typed"]
        callee = getattr(node.func, "attr", getattr(node.func, "id", ""))
        if not is_writer:
            if typed_kws and callee not in NOT_THE_WRITER:
                reason = (
                    "a writer method on an object that is not app_config"
                    if callee in WRITERS
                    else "which is not the config writer"
                )
                bad.append(
                    f"{path}:{node.lineno} in {named(node)}(): typed= handed to {callee or 'a call'}(), {reason}"
                )
            continue
        func_name = named(node)
        entry = DYNAMIC.get((path, func_name))
        caps = _Caps(entry[0], entry[2]) if entry else _Caps()
        scope = _scope_of(node)
        top_fn = outermost(node)
        if any(isinstance(a, ast.Starred) for a in node.args) or len(node.args) > WRITERS[node.func.attr]:
            bad.append(
                f"{path}:{node.lineno} in {func_name}(): positional or * arguments beyond the writer's own ({ast.unparse(node)[:80]})"
            )
        if top_fn is not None and any(isinstance(n, ast.Global | ast.Nonlocal) for n in ast.walk(top_fn)):
            bad.append(
                f"{path}:{node.lineno} in {func_name}(): global/nonlocal in a function that calls the config writer"
            )
        for kw in node.keywords:
            if kw.arg is None:
                bad.append(f"{path}:{node.lineno} in {func_name}(): ** arguments to the config writer")
            elif kw.arg == "typed":
                ok = _typed_value(kw.value, scope, caps)
                if ok and isinstance(kw.value, ast.Name) and not caps.has("adds"):
                    # (d): a bound name's ONLY other occurrence is as a typed= argument of a writer call
                    for use in ast.walk(top_fn if top_fn is not None else tree):
                        if isinstance(use, ast.Name) and use.id == kw.value.id and isinstance(use.ctx, ast.Load):
                            parent = getattr(use, "parent", None)
                            if not (isinstance(parent, ast.keyword) and parent.arg == "typed"):
                                ok = False
                if ok and entry and entry[2].get("cond_required"):
                    # "claimed only when the form carried an answer": a conditional (directly, or through the one name bound to it)
                    value = kw.value
                    if isinstance(value, ast.Name):
                        owner = scope.lookup(value.id) if scope else None
                        binds = owner.binds.get(value.id, []) if owner else []
                        value = binds[0][1] if len(binds) == 1 else value
                    ok = isinstance(value, ast.IfExp)
                # the control flow that reaches a claim: the statement spelling of `A if COND else B`
                if ok and not _claim_is_empty(kw.value):
                    ancestor = getattr(node, "parent", None)
                    while ancestor is not None and not isinstance(ancestor, (*SCOPES, ast.Module)):
                        if isinstance(ancestor, ast.If):
                            test_ok = (
                                _wide_pure(ancestor.test, scope)
                                if caps.has("adds")
                                else _cond_for(ancestor.test, scope, caps)
                            )
                            if not test_ok:
                                ok = False
                        elif isinstance(
                            ancestor, ast.While | ast.For | ast.AsyncFor | ast.IfExp | ast.ExceptHandler
                        ) or (
                            isinstance(ancestor, ast.Try)
                            and node in [n for h in ancestor.handlers for n in ast.walk(h)]
                        ):
                            ok = False
                        ancestor = getattr(ancestor, "parent", None)
                if not ok:
                    bad.append(f"{path}:{node.lineno} in {func_name}(): typed={ast.unparse(kw.value)}")
    return bad
