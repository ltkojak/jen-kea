"""
tests/typed_claims.py
─────────────────────
v5.69.0-beta.15 (Q184, Z4) - the checker behind `tests/test_credentials.py::TestTypedIsAHumansAct`.

CRED-004's design rule: the writer's `typed` set is a human's act in this request (or the one-time conversion); a route never derives it from hosts, DNS or history. This reads source
with `ast` and reports every `typed=` handed to the config writer (or its preflight) whose value is not demonstrably that:

  * a literal set of endpoint names (`{"kea"}`, `{f"server_{n}"}`, `{_endpoint_name(server, service)}`), `set()`, or `None`;
  * a conditional (`X if TEST else Y`, a set comprehension's `if`, an `.add()` under `if TEST:`) whose TEST is PURE: constants, names, comparisons, boolean operators, subscripts and
    attributes of `request` / `extensions`, calls to a short list of builtins and to string methods, and `request.form.get(...)` / `.getlist(...)` - nothing that asks about a host, a
    resolver, a file or the configuration. A name in a test is pure when it is a parameter (the caller's claim) or every assignment to it is pure, recursively;
  * a name built that way and only ever `.add()`ed to (a constant or an f-string of names), never `.update()`d, `|=`ed or handed to a function.

Beta.13 and beta.14 each wrote `typed={...} if _same_box(url, ssh) else set()`; the first version of this checker accepted that shape because it looked only at the branches. The test
lists the shapes that slipped through (`SLIPS`) and requires every one to be caught.
"""

from __future__ import annotations

import ast

WRITERS = {
    "write_values": 1,
    "write_value": 3,
    "mutate": 1,
    "preflight_identity_change": 1,
}  # name -> positional arguments the call may have
PURE_BUILTINS = {"bool", "str", "len", "int", "set", "zip", "enumerate", "range", "sum", "any", "all", "list", "tuple"}
PURE_METHODS = {"strip", "lower", "upper", "startswith", "endswith", "isdigit", "get", "getlist"}
FORM_RECEIVERS = {"request.form", "request.args", "request.values"}
MUTATORS = {
    "update",
    "union",
    "discard",
    "remove",
    "pop",
    "clear",
    "intersection_update",
    "difference_update",
    "symmetric_difference_update",
}


def _outermost_function(node):
    found = None
    while node is not None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            found = node
        node = getattr(node, "parent", None)
    return found


class _Scope:
    def __init__(self, root):
        self.root = root
        self.params: set[str] = set()
        self.assigned: dict[str, list[ast.AST]] = {}
        self.adds: dict[str, list[ast.Call]] = {}
        self.other_mutations: set[str] = set()
        for node in ast.walk(root):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                args = node.args
                for a in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
                    if a is not None:
                        self.params.add(a.arg)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    self._bind(target, node.value)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                self._bind(node.target, node.value)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                self.other_mutations.add(node.target.id)
            elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
                self._bind(node.target, node.iter)
            elif isinstance(node, ast.With):
                for item in node.items:
                    if item.optional_vars is not None:
                        self._bind(item.optional_vars, item.context_expr)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
            ):
                if node.func.attr == "add":
                    self.adds.setdefault(node.func.value.id, []).append(node)
                elif node.func.attr in MUTATORS:
                    self.other_mutations.add(node.func.value.id)
            elif (
                isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store) and isinstance(node.value, ast.Name)
            ):
                self.other_mutations.add(node.value.id)

    def _bind(self, target, value):
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name):
                self.assigned.setdefault(sub.id, []).append(value)


def _pure(node, scope, seen=frozenset()) -> bool:
    """Is `node` an expression about the REQUEST and constants only?"""
    if node is None or isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return _name_pure(node.id, scope, seen)
    if isinstance(node, ast.Attribute):
        base = node
        while isinstance(base, ast.Attribute):
            base = base.value
        return isinstance(base, ast.Name) and base.id in ("request", "extensions")
    if isinstance(node, ast.Subscript):
        return _pure(node.value, scope, seen) and _pure(node.slice, scope, seen)
    if isinstance(node, ast.Call):
        func = node.func
        args_ok = all(_pure(a, scope, seen) for a in node.args) and all(
            _pure(k.value, scope, seen) for k in node.keywords if k.arg is not None
        )
        if any(k.arg is None for k in node.keywords):
            return False
        if isinstance(func, ast.Name):
            return func.id in PURE_BUILTINS and args_ok
        if isinstance(func, ast.Attribute) and func.attr in PURE_METHODS:
            if func.attr in ("get", "getlist"):
                return ast.unparse(func.value) in FORM_RECEIVERS and args_ok
            return _pure(func.value, scope, seen) and args_ok
        return False
    if isinstance(
        node,
        ast.BoolOp
        | ast.UnaryOp
        | ast.Compare
        | ast.IfExp
        | ast.Tuple
        | ast.List
        | ast.Set
        | ast.Starred
        | ast.JoinedStr
        | ast.FormattedValue
        | ast.BinOp,
    ):
        return all(
            _pure(child, scope, seen)
            for child in ast.iter_child_nodes(node)
            if not isinstance(child, ast.expr_context | ast.operator | ast.cmpop | ast.boolop | ast.unaryop)
        )
    if isinstance(node, ast.ListComp | ast.GeneratorExp | ast.SetComp):
        return _pure(node.elt, scope, seen) and all(
            _pure(g.iter, scope, seen) and all(_pure(i, scope, seen) for i in g.ifs) for g in node.generators
        )
    return False


def _name_pure(name, scope, seen) -> bool:
    if name in ("request", "extensions", "None", "True", "False"):
        return True
    if name in seen:
        return True  # a cycle (a loop variable that feeds itself) adds nothing the other assignments do not already say
    values = scope.assigned.get(name)
    if values:
        return all(_pure(v, scope, seen | {name}) for v in values)
    return name in scope.params  # a parameter is the caller's claim; an unknown name (a global) is not


def _interpolation_ok(node) -> bool:
    """An f-string in a typed set may interpolate names and attributes (`server_{n}`), never a call (`{dns_name(host)}`)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.FormattedValue) and any(isinstance(x, ast.Call) for x in ast.walk(sub.value)):
            return False
    return True


def _name_element_ok(node, scope) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return _interpolation_ok(node)
    if isinstance(node, ast.Name):
        return True  # a loop variable over a literal tuple of names, checked by the comprehension's iterable
    if isinstance(node, ast.Call):
        # the endpoint the route's own URL names (`/direct-socket/<server_id>/<service>`): its arguments are names and constants, not another call
        return getattr(node.func, "id", "") == "_endpoint_name" and all(
            isinstance(a, ast.Name | ast.Constant) for a in node.args
        )
    return False


def _typed_ok(node, scope, parents) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is None
    if isinstance(node, ast.Set):
        return all(_name_element_ok(e, scope) for e in node.elts)
    if isinstance(node, ast.Call):
        return isinstance(node.func, ast.Name) and node.func.id == "set" and not node.args and not node.keywords
    if isinstance(node, ast.SetComp):
        if not _name_element_ok(node.elt, scope) and not isinstance(node.elt, ast.Name):
            return False
        return all(
            isinstance(g.iter, ast.Tuple | ast.List | ast.Set) and all(_pure(i, scope) for i in g.ifs)
            for g in node.generators
        )
    if isinstance(node, ast.IfExp):
        return (
            _pure(node.test, scope) and _typed_ok(node.body, scope, parents) and _typed_ok(node.orelse, scope, parents)
        )
    if isinstance(node, ast.Name):
        values = scope.assigned.get(node.id)
        if not values or node.id in scope.other_mutations:
            return False
        if not all(_typed_ok(v, scope, parents) for v in values):
            return False
        for add in scope.adds.get(node.id, []):
            if len(add.args) != 1 or not _name_element_ok(add.args[0], scope) or isinstance(add.args[0], ast.Name):
                return False
            ancestor = parents.get(add)
            while ancestor is not None and not isinstance(
                ancestor, ast.FunctionDef | ast.AsyncFunctionDef | ast.Module
            ):
                if isinstance(ancestor, ast.If | ast.IfExp | ast.While) and not _pure(ancestor.test, scope):
                    return False
                ancestor = parents.get(ancestor)
        return True
    return False


def untyped_claims(source: str, path: str = "<snippet>") -> list[str]:
    """One line per `typed=` (or positional/`**` smuggling of it) handed to a config writer in `source` that is not demonstrably a human's act."""
    tree = ast.parse(source)
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
            child.parent = parent  # type: ignore[attr-defined]
    scopes: dict[int, _Scope] = {}
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "attr", getattr(node.func, "id", ""))
        if name not in WRITERS:
            continue
        if isinstance(node.func, ast.Attribute) and ast.unparse(node.func.value) in (
            "self",
            "cfg",
            "parser",
            "p",
            "pm",
        ):
            continue  # not the writer (`parser.mutate` and the like are not AppConfig's)
        owner = _outermost_function(node) or tree
        scope = scopes.setdefault(id(owner), _Scope(owner))
        where = getattr(_outermost_function(node), "name", "<module>")
        if len(node.args) > WRITERS[name]:
            bad.append(
                f"{path}:{node.lineno} in {where}(): positional arguments beyond the writer's own ({ast.unparse(node)[:80]})"
            )
        for kw in node.keywords:
            if kw.arg is None:
                bad.append(f"{path}:{node.lineno} in {where}(): ** arguments to a writer")
            elif kw.arg == "typed" and not _typed_ok(kw.value, scope, parents):
                bad.append(f"{path}:{node.lineno} in {where}(): typed={ast.unparse(kw.value)}")
    return bad
