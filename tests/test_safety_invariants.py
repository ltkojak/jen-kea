"""
tests/test_safety_invariants.py
───────────────────────────────
v5.68.0-beta.29+ (Q166) - `docs/SAFETY_INVARIANTS.md` is the version-controlled list of the rules this project has learned, one per entry, each with the tests that enforce it. A list nobody
checks rots: a test gets renamed, a class is deleted in a refactor, and the registry keeps naming a guard that no longer exists. This file parses the registry with the standard library and
fails when

  * an entry has no id, no rule sentence, no Q, or no test reference (an entry without an automated test must say `(no automated test: <reason>)`, and is listed in this test's output);
  * a reference `path::Class`, `path::function` or `path::Class::method` does not resolve - the file is walked with `ast`, nothing is grepped - or names a function that is not a test;
  * an id is used twice, or an id in the Retired section is used again;
  * the registry is not pointed at from CLAUDE.md and the release-audit procedure.

Pure - no database, no Flask: `py -m pytest --noconftest tests/test_safety_invariants.py`.
"""

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "docs" / "SAFETY_INVARIANTS.md"

_HEADER = re.compile(r"^### ([A-Z][A-Z0-9]*-\d{3}) - (.+?)\s*$", re.M)
_SECTION = re.compile(r"^## (.+?)\s*$", re.M)
_NO_TEST = re.compile(r"^\(no automated test:\s*(.+)\)\s*$")
_REF = re.compile(r"^`([^`]+)`")


def _field(block: str, name: str, until: tuple) -> str:
    m = re.search(rf"\*\*{re.escape(name)}\.\*\*\s*(.*?)(?=\n\*\*(?:{'|'.join(until)})\.\*\*|\Z)", block, re.S)
    return " ".join(m.group(1).split()) if m else ""


def parse_registry(text: str) -> tuple[list[dict], list[str]]:
    """([entry], [retired id]). An entry is {"id", "title", "rule", "established", "enforced_at", "tests": [ref], "no_test_reason": str | None, "line"}."""
    headers = list(_HEADER.finditer(text))
    sections = [m.start() for m in _SECTION.finditer(text)]
    entries = []
    for i, h in enumerate(headers):
        ends = [headers[i + 1].start()] if i + 1 < len(headers) else []
        ends += [s for s in sections if s > h.end()][:1]
        block = text[h.end() : min(ends) if ends else len(text)]
        tests, reason = [], None
        tests_part = block.split("**Tests.**", 1)[1] if "**Tests.**" in block else ""
        for raw in tests_part.splitlines():
            item = raw.strip()
            if not item.startswith("- "):
                continue
            item = item[2:].strip()
            m = _NO_TEST.match(item)
            if m:
                reason = m.group(1).strip()
                continue
            ref = _REF.match(item)
            if ref:
                tests.append(ref.group(1))
        entries.append(
            {
                "id": h.group(1),
                "title": h.group(2),
                "rule": _field(block, "Rule", ("Established", "Enforced at", "Tests")),
                "established": _field(block, "Established", ("Enforced at", "Tests")),
                "enforced_at": _field(block, "Enforced at", ("Tests",)),
                "tests": tests,
                "no_test_reason": reason,
                "line": text[: h.start()].count("\n") + 1,
            }
        )
    retired = []
    m = re.search(r"^## Retired ids\s*$(.*)", text, re.M | re.S)
    if m:
        retired = re.findall(r"^- `([A-Z][A-Z0-9]*-\d{3})`", m.group(1), re.M)
    return entries, retired


def _tests_in(rel: str):
    """{class name: {method names}, "<function>": ...} of the top level of one test file, or None when the file does not exist."""
    path = ROOT / rel
    if not path.is_file():
        return None
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            found[node.name] = {n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found[node.name] = None
    return found


def resolve(ref: str) -> str:
    """ "" when `ref` names something that exists, else the reason it does not."""
    parts = ref.split("::")
    rel = parts[0]
    if not rel.startswith("tests/") or not rel.endswith(".py"):
        return f"{ref!r}: the path must be a tests/*.py file"
    found = _tests_in(rel)
    if found is None:
        return f"{ref!r}: {rel} does not exist"
    if len(parts) == 1:
        return ""
    name = parts[1]
    if name not in found:
        return f"{ref!r}: {rel} has no top-level {name}"
    if len(parts) == 2:
        if found[name] is None and not name.startswith("test"):
            return f"{ref!r}: {name} is a helper, not a test"
        if found[name] is not None and not name.startswith("Test"):
            return f"{ref!r}: {name} is a class that pytest would not collect (its name must start with Test)"
        return ""
    if len(parts) == 3:
        if found[name] is None or parts[2] not in found[name]:
            return f"{ref!r}: {name} has no method {parts[2]}"
        return ""
    return f"{ref!r}: more than three parts"


def problems(entries: list[dict], retired: list[str]) -> list[str]:
    out, seen = [], {}
    for e in entries:
        where = f"{e['id']} (docs/SAFETY_INVARIANTS.md:{e['line']})"
        if e["id"] in seen:
            out.append(f"{where}: the id is used twice (first at line {seen[e['id']]})")
        seen.setdefault(e["id"], e["line"])
        if e["id"] in retired:
            out.append(f"{where}: this id is in the Retired section and may not be used again")
        if len(e["rule"]) < 20:
            out.append(f"{where}: no rule sentence")
        if not re.search(r"\bQ\d+", e["established"]):
            out.append(f"{where}: 'Established' names no Q")
        if not e["enforced_at"]:
            out.append(f"{where}: 'Enforced at' is empty")
        if not e["tests"] and not e["no_test_reason"]:
            out.append(f"{where}: no test reference and no '(no automated test: <reason>)' note")
        if e["no_test_reason"] is not None and len(e["no_test_reason"]) < 10:
            out.append(f"{where}: the no-test reason is not a reason")
        for ref in e["tests"]:
            why = resolve(ref)
            if why:
                out.append(f"{where}: {why}")
    if len(set(retired)) != len(retired):
        out.append("the Retired section lists an id twice")
    return out


class TestTheRegistryIsTrue:
    @pytest.fixture(scope="class")
    def parsed(self):
        return parse_registry(REGISTRY.read_text(encoding="utf-8"))

    def test_the_registry_has_entries(self, parsed):
        entries, _retired = parsed
        assert len(entries) >= 19, f"the initial registry had 19 entries; found {len(entries)}"

    def test_every_entry_is_complete_and_every_reference_resolves(self, parsed):
        entries, retired = parsed
        assert not problems(entries, retired), "\n" + "\n".join(problems(entries, retired))

    def test_the_entries_without_an_automated_test_are_listed(self, parsed, capsys):
        entries, _retired = parsed
        bare = [(e["id"], e["no_test_reason"]) for e in entries if not e["tests"]]
        print(f"SAFETY INVARIANTS: {len(entries)} entries, {len(bare)} without an automated test")
        for ident, reason in bare:
            print(f"  {ident}: (no automated test: {reason})")
        assert all(reason for _id, reason in bare)

    def test_the_ids_follow_the_family_and_number_shape(self, parsed):
        entries, _retired = parsed
        families = {e["id"].rsplit("-", 1)[0] for e in entries}
        assert families >= {"INV", "RBAC", "DEF", "ALERT", "CFG", "FILE", "MIG", "TXN", "BG", "FAIL", "STATE", "IDENT"}

    def test_it_is_pointed_at_from_the_places_a_person_starts(self):
        assert "docs/SAFETY_INVARIANTS.md" in (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        audit = (ROOT / "docs" / "RELEASE_AUDIT.md").read_text(encoding="utf-8")
        assert "SAFETY_INVARIANTS.md" in audit and "test_safety_invariants.py" in audit


class TestTheCheckerCatchesWhatItIsFor:
    """The registry test is itself a guard, so it is tested against fabricated registries."""

    GOOD = """## A

### TST-001 - a rule
**Rule.** Nothing may ever write this without asking first.
**Established.** Q166.
**Enforced at.** one function.
**Tests.**
- `tests/test_safety_invariants.py::TestTheCheckerCatchesWhatItIsFor`

## Retired ids

- `OLD-001` - gone
"""

    def _problems(self, text):
        return problems(*parse_registry(text))

    def test_a_good_entry_is_clean(self):
        assert self._problems(self.GOOD) == []

    def test_a_missing_class_is_reported(self):
        bad = self.GOOD.replace("::TestTheCheckerCatchesWhatItIsFor", "::TestNoSuchClassAnywhere")
        assert any("has no top-level TestNoSuchClassAnywhere" in p for p in self._problems(bad))

    def test_a_missing_file_is_reported(self):
        bad = self.GOOD.replace("test_safety_invariants.py", "test_no_such_file.py")
        assert any("does not exist" in p for p in self._problems(bad))

    def test_a_missing_method_is_reported(self):
        bad = self.GOOD.replace("TestTheCheckerCatchesWhatItIsFor`", "TestTheCheckerCatchesWhatItIsFor::test_nope`")
        assert any("has no method test_nope" in p for p in self._problems(bad))

    def test_a_helper_function_is_not_a_test(self):
        bad = self.GOOD.replace("::TestTheCheckerCatchesWhatItIsFor", "::parse_registry")
        assert any("is a helper, not a test" in p for p in self._problems(bad))

    def test_an_entry_with_no_test_is_refused_unless_it_says_why(self):
        bare = self.GOOD.replace("- `tests/test_safety_invariants.py::TestTheCheckerCatchesWhatItIsFor`\n", "")
        assert any("no test reference" in p for p in self._problems(bare))
        said = bare.replace("**Tests.**\n", "**Tests.**\n- (no automated test: the thing is a person's judgement)\n")
        assert self._problems(said) == []
        entries, _r = parse_registry(said)
        assert entries[0]["no_test_reason"] == "the thing is a person's judgement"

    def test_an_id_used_twice_is_reported(self):
        twice = self.GOOD.replace(
            "## Retired ids", self.GOOD.split("## A\n")[1].split("## Retired ids")[0] + "\n## Retired ids"
        )
        assert any("used twice" in p for p in self._problems(twice))

    def test_a_retired_id_cannot_come_back(self):
        back = self.GOOD.replace("TST-001", "OLD-001")
        assert any("Retired section" in p for p in self._problems(back))

    def test_an_entry_without_a_q_or_a_rule_is_reported(self):
        thin = self.GOOD.replace("Q166", "later").replace("Nothing may ever write this without asking first.", "x")
        found = self._problems(thin)
        assert any("names no Q" in p for p in found) and any("no rule sentence" in p for p in found)
