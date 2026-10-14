"""
tests/test_problems_generation_source.py
────────────────────────────────────────
v5.69.0-beta.9 (Q178, PROBLEMS-IDENTITY-002) - the whole-tree rule behind the generation: every SQL statement on `client_problems` in `client_problems.py` carries `generation` (an INSERT lists
it, a SELECT/UPDATE filters by it), except the three reviewed ones that apply to EVERY row of a server by design - the resolution of any idle row, the 30-day retention prune and the closing of a removed server's
rows - and the one statement that CLOSES older generations. Nothing outside that module touches the table. Pure (an `ast` read): `pytest --noconftest tests/test_problems_generation_source.py`.
"""

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATEMENT = re.compile(r"(?:FROM|UPDATE|INTO)\s+client_problems\b")
REVIEWED_UNFILTERED = (
    "WHERE resolved_at IS NULL AND last_seen < %s",  # an idle row of ANY server or generation is resolved after 24 h
    "WHERE last_seen < %s",  # the 30-day retention prune
    "WHERE server_id=%s AND resolved_at IS NULL",  # a REMOVED server's open rows are closed, whatever their generation (its number may be given to a new server)
)


def _statements(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            text = "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        else:
            continue
        if STATEMENT.search(text) and re.match(r"\s*(SELECT|UPDATE|INSERT|DELETE)", text):
            out.append((node.lineno, text))
    return out


class TestEveryStatementCarriesTheGeneration:
    def test_each_statement_in_the_module_filters_or_lists_the_generation_or_is_reviewed(self):
        found = _statements(ROOT / "jen" / "services" / "client_problems.py")
        assert len(found) >= 12, found
        offenders = [
            (line, text[:90])
            for line, text in found
            if "generation" not in text and not any(marker in text for marker in REVIEWED_UNFILTERED)
        ]
        assert offenders == [], f"a statement on client_problems with no generation: {offenders}"

    def test_the_reviewed_unfiltered_ones_are_exactly_three(self):
        found = _statements(ROOT / "jen" / "services" / "client_problems.py")
        loose = [t for _l, t in found if "generation" not in t]
        assert len(loose) == 3, loose

    def test_nothing_else_in_the_tree_touches_the_table(self):
        offenders = []
        for base in ("jen", "plugins"):
            for p in (ROOT / base).rglob("*.py"):
                rel = p.relative_to(ROOT).as_posix()
                if rel in ("jen/services/client_problems.py", "jen/models/migrations.py"):
                    continue
                if _statements(p):
                    offenders.append(rel)
        assert offenders == [], offenders
