"""The tree is written in American English (Q207, 5.70.0-beta.3).

The maintainer writes American English and the product is written in it:
"color", never "colour". Q205's entry was written with "colour" and the word
went straight into the shipped 5.70.0-beta.1 - the Subnets picker's title and
aria-label, its error toast, the route's error, the CHANGELOG heading and the
upgrading page. A spelling in a spec is a spelling in the product, so the rule
is a test over the whole tree, not a reminder.

The table below is a LIST of British -> American word pairs. It is never a
suffix rule: a bare ``-ise`` rule would rewrite ``advertise``, ``promise``,
``exercise`` and ``raise``, so every verb the rule covers is named, and
``TestTheTable`` holds the words the table must leave alone.

A word is matched as a whole word or as one word of an identifier: every run
of letters is split at its humps and each hump is looked up in the table, so
``badge_colour``, ``badgeColour`` and ``BADGE_COLOUR`` are hits while
``discolour`` and ``colourway`` are not (the table does not name them). The
replacement keeps the case of the match (``Colour`` -> ``Color``, ``COLOUR``
-> ``COLOR``).

Exclusions, each with its reason:

* ``plugins/`` - every bundled plugin is vendored from its own repository and
  gets the same pass there, with its own version, in the next plugin round. The
  count under ``plugins/`` is printed as a reminder; the test never fails on it.
* ``jen-kea-helper`` - a change to the helper is a helper build (its hits are in
  comments only); they go with the next helper Q. Printed the same way.
* ``docs/release-history/`` - frozen archives of released upgrading pages.
* ``static/js/htmx.min.js`` and ``static/js/chart.umd.min.js`` - vendored
  libraries; ``tests/test_htmx_vendoring.py`` pins htmx's bytes.
* this file - it holds the table.

``ALLOWLIST`` is for a British spelling that MUST stay because it is a
contract, not a sentence: a stored settings key, a library's own exception
name, an API field's name as it shipped, the route path and flash sentence of
the excluded wol plugin and the reply field of the excluded helper that this
tree dials and reads. Q207 expected it empty and found twelve.
``TestTheAllowlistIsLive`` fails the day an entry no longer matches, so a
reviewed exception cannot outlive what it excused (the pattern of
``tests/test_csp.py``'s handler allowlist).

Pure: no database, no Flask, no Kea. Runs with ``--noconftest``.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# The table
# --------------------------------------------------------------------------

# Verbs the tree writes with -ise; each expands to its -ise/-ises/-ised/-ising/
# -isation(s)/-isable/-iser(s) forms. A LIST of verbs, never a suffix rule.
_ISE_VERBS = [
    "authoris",
    "capitalis",
    "categoris",
    "centralis",
    "characteris",
    "customis",
    "deserialis",
    "emphasis",
    "equalis",
    "finalis",
    "formalis",
    "generalis",
    "globalis",
    "harmonis",
    "initialis",
    "itemis",
    "localis",
    "materialis",
    "maximis",
    "memoris",
    "minimis",
    "mobilis",
    "modernis",
    "monetis",
    "neutralis",
    "normalis",
    "optimis",
    "organis",
    "parameteris",
    "personalis",
    "prioritis",
    "randomis",
    "rationalis",
    "realis",
    "recognis",
    "sanitis",
    "scrutinis",
    "serialis",
    "specialis",
    "stabilis",
    "standardis",
    "sterilis",
    "summaris",
    "synchronis",
    "tokenis",
    "utilis",
    "virtualis",
    "visualis",
]

_ISE_SUFFIXES = [
    ("e", "e"),
    ("es", "es"),
    ("ed", "ed"),
    ("ing", "ing"),
    ("ation", "ation"),
    ("ations", "ations"),
    ("able", "able"),
    ("er", "er"),
    ("ers", "ers"),
]


def _ise_pairs() -> list[tuple[str, str]]:
    pairs = []
    for stem in _ISE_VERBS:
        z_stem = stem[:-1] + "z"
        for british_suffix, american_suffix in _ISE_SUFFIXES:
            pairs.append((stem + british_suffix, z_stem + american_suffix))
    return pairs


# Full-word pairs. Inflections are listed one by one so a shared spelling is
# never touched (``programmed`` and ``cancellation`` are American; ``programme``
# and ``cancelled`` are not).
_WORD_PAIRS: list[tuple[str, str]] = [
    # -our
    ("colour", "color"),
    ("colours", "colors"),
    ("coloured", "colored"),
    ("colouring", "coloring"),
    ("colourful", "colorful"),
    ("colourless", "colorless"),
    ("behaviour", "behavior"),
    ("behaviours", "behaviors"),
    ("behavioural", "behavioral"),
    ("favour", "favor"),
    ("favours", "favors"),
    ("favoured", "favored"),
    ("favouring", "favoring"),
    ("favourable", "favorable"),
    ("favourite", "favorite"),
    ("favourites", "favorites"),
    ("flavour", "flavor"),
    ("flavours", "flavors"),
    ("harbour", "harbor"),
    ("harbours", "harbors"),
    ("honour", "honor"),
    ("honours", "honors"),
    ("honoured", "honored"),
    ("honouring", "honoring"),
    ("humour", "humor"),
    ("labour", "labor"),
    ("labours", "labors"),
    ("neighbour", "neighbor"),
    ("neighbours", "neighbors"),
    ("neighbouring", "neighboring"),
    ("neighbourhood", "neighborhood"),
    ("rumour", "rumor"),
    ("rumours", "rumors"),
    ("saviour", "savior"),
    ("vigour", "vigor"),
    ("endeavour", "endeavor"),
    ("endeavours", "endeavors"),
    ("armour", "armor"),
    ("odour", "odor"),
    ("odours", "odors"),
    # -yse
    ("analyse", "analyze"),
    ("analysed", "analyzed"),
    ("analysing", "analyzing"),
    ("analyser", "analyzer"),
    ("analysers", "analyzers"),
    ("paralyse", "paralyze"),
    ("paralysed", "paralyzed"),
    ("catalyse", "catalyze"),
    # -ogue
    ("catalogue", "catalog"),
    ("catalogues", "catalogs"),
    ("catalogued", "cataloged"),
    ("cataloguing", "cataloging"),
    # -re
    ("centre", "center"),
    ("centres", "centers"),
    ("centred", "centered"),
    ("centring", "centering"),
    ("metre", "meter"),
    ("metres", "meters"),
    ("litre", "liter"),
    ("litres", "liters"),
    ("fibre", "fiber"),
    ("fibres", "fibers"),
    ("calibre", "caliber"),
    ("manoeuvre", "maneuver"),
    ("manoeuvres", "maneuvers"),
    ("theatre", "theater"),
    ("sombre", "somber"),
    ("spectre", "specter"),
    # -ce / -se
    ("licence", "license"),
    ("licences", "licenses"),
    ("licenced", "licensed"),
    ("defence", "defense"),
    ("defences", "defenses"),
    ("offence", "offense"),
    ("offences", "offenses"),
    ("pretence", "pretense"),
    ("practise", "practice"),
    ("practised", "practiced"),
    ("practises", "practices"),
    ("practising", "practicing"),
    # -ll-
    ("cancelled", "canceled"),
    ("cancelling", "canceling"),
    ("labelled", "labeled"),
    ("labelling", "labeling"),
    ("modelled", "modeled"),
    ("modelling", "modeling"),
    ("travelled", "traveled"),
    ("travelling", "traveling"),
    ("traveller", "traveler"),
    ("travellers", "travelers"),
    ("signalled", "signaled"),
    ("signalling", "signaling"),
    ("channelled", "channeled"),
    ("channelling", "channeling"),
    ("dialled", "dialed"),
    ("dialling", "dialing"),
    ("tunnelled", "tunneled"),
    ("tunnelling", "tunneling"),
    ("totalled", "totaled"),
    ("totalling", "totaling"),
    ("levelled", "leveled"),
    ("levelling", "leveling"),
    ("fuelled", "fueled"),
    ("fuelling", "fueling"),
    ("marshalled", "marshaled"),
    ("marshalling", "marshaling"),
    ("initialled", "initialed"),
    ("equalled", "equaled"),
    ("rivalled", "rivaled"),
    ("trialled", "trialed"),
    ("trialling", "trialing"),
    ("unravelled", "unraveled"),
    ("jewellery", "jewelry"),
    ("woollen", "woolen"),
    # -l / -ll
    ("fulfil", "fulfill"),
    ("fulfils", "fulfills"),
    ("fulfilment", "fulfillment"),
    ("fulfilments", "fulfillments"),
    ("enrol", "enroll"),
    ("enrols", "enrolls"),
    ("enrolment", "enrollment"),
    ("enrolments", "enrollments"),
    ("instalment", "installment"),
    ("instalments", "installments"),
    ("skilful", "skillful"),
    ("skilfully", "skillfully"),
    ("wilful", "willful"),
    ("wilfully", "willfully"),
    ("appal", "appall"),
    ("distil", "distill"),
    ("distils", "distills"),
    # -e- / -ae- / -oe- and odd ones
    ("judgement", "judgment"),
    ("judgements", "judgments"),
    ("acknowledgement", "acknowledgment"),
    ("acknowledgements", "acknowledgments"),
    ("artefact", "artifact"),
    ("artefacts", "artifacts"),
    ("programme", "program"),
    ("programmes", "programs"),
    ("aluminium", "aluminum"),
    ("mould", "mold"),
    ("moulds", "molds"),
    ("moulded", "molded"),
    ("mouldy", "moldy"),
    ("sceptical", "skeptical"),
    ("sceptic", "skeptic"),
    ("scepticism", "skepticism"),
    ("grey", "gray"),
    ("greys", "grays"),
    ("greyed", "grayed"),
    ("greyish", "grayish"),
    ("ageing", "aging"),
    ("enquire", "inquire"),
    ("enquired", "inquired"),
    ("enquiring", "inquiring"),
    ("enquiry", "inquiry"),
    ("enquiries", "inquiries"),
    ("speciality", "specialty"),
    ("specialities", "specialties"),
    ("orientated", "oriented"),
    ("maths", "math"),
    ("whilst", "while"),
    ("amongst", "among"),
    ("amidst", "amid"),
    ("learnt", "learned"),
    ("spelt", "spelled"),
    ("dreamt", "dreamed"),
    ("towards", "toward"),
    ("afterwards", "afterward"),
    # prefixed forms - one hump each, so each is its own pair (the tree had
    # ``unrecognised`` 28 times and ``uninitialised`` 23 times when the table
    # was first run without them)
    ("unrecognised", "unrecognized"),
    ("unrecognisable", "unrecognizable"),
    ("uninitialised", "uninitialized"),
    ("unauthorised", "unauthorized"),
    ("unnormalised", "unnormalized"),
    ("unsanitised", "unsanitized"),
    ("unoptimised", "unoptimized"),
    ("unsynchronised", "unsynchronized"),
    ("unserialisable", "unserializable"),
    ("unrealised", "unrealized"),
    ("unutilised", "unutilized"),
    ("uncategorised", "uncategorized"),
    ("reinitialise", "reinitialize"),
    ("reinitialised", "reinitialized"),
    ("reinitialising", "reinitializing"),
    ("reorganise", "reorganize"),
    ("reorganised", "reorganized"),
    ("reorganising", "reorganizing"),
    ("reorganisation", "reorganization"),
    ("resynchronise", "resynchronize"),
    ("resynchronised", "resynchronized"),
    ("renormalise", "renormalize"),
    ("renormalised", "renormalized"),
    ("relabelled", "relabeled"),
    ("relabelling", "relabeling"),
    ("unlabelled", "unlabeled"),
    ("mislabelled", "mislabeled"),
    ("mislabelling", "mislabeling"),
    ("discoloured", "discolored"),
    ("recolour", "recolor"),
    ("recoloured", "recolored"),
    ("unfavourable", "unfavorable"),
    ("dishonour", "dishonor"),
    ("dishonoured", "dishonored"),
    ("uncancelled", "uncanceled"),
    ("miscategorised", "miscategorized"),
]

PAIRS: list[tuple[str, str]] = _WORD_PAIRS + _ise_pairs()

# Words a suffix rule would rewrite and this table must leave alone.
AMERICAN_TOO = [
    "advertise",
    "promise",
    "exercise",
    "raise",
    "premise",
    "surprise",
    "comprise",
    "supervise",
    "compromise",
    "revise",
    "devise",
    "advise",
    "otherwise",
    "precise",
    "concise",
    "enterprise",
    "improvise",
    "expertise",
    "likewise",
    "analysis",
    "analyses",
    "programmed",
    "programmer",
    "programming",
    "cancellation",
    "fulfilled",
    "fulfilling",
    "enrolled",
    "enrolling",
    "centered",
    "lightgrey",
    "discolor",
    "unrecognizable",
    "uninitialized",
    "practice",
    "license",
    "defensive",
    "offensive",
    "dialog",
    "dialogue",
    "glamour",
    "contour",
    "detour",
    "tour",
    "velour",
    "forward",
    "forwards",
    "backwards",
    "upwards",
]

# (path, literal, reason) - a British spelling that MUST stay: the literal is the
# identifier or string as written in the file, and a hit on a line that carries it,
# inside it, is excused. A path ending in "/" names a directory. Every entry here is
# a persisted or external contract, never prose: a stored key, a library's own name,
# a field name as it shipped, the name an EXCLUDED component (a plugin, the helper)
# gives a thing that this tree reads or dials.
_WOL = "the wol plugin's own name for it (plugins/ is excluded: the plugin's pass is its own release, and until then the tree dials and reads what it ships)"
_HELPER = "a field of jen-kea-helper's JSON reply (build 17, `_restore_state`); the helper is excluded and its field is a contract"
ALLOWLIST: list[tuple[str, str, str]] = [
    (
        "jen/services/credentials.py",
        "credentials_materialised",
        "the settings-table KEY beta.11's one-time conversion wrote on every upgraded box; a stored key is a contract, not a spelling",
    ),
    (
        "tests/test_credentials.py",
        "credentials_materialised",
        "the source test that pins the same key (the materialize rule's bridge flag)",
    ),
    ("jen/services/provider_budget.py", "CancelledError", "concurrent.futures' own exception name"),
    (
        "CHANGELOG.md",
        "pool_utilisation",
        "the API field's name as it shipped in that release; the entry records what a script against it used, and a record is not re-spelled",
    ),
    ("jen/services/investigation_logging.py", '"signalled"', _HELPER),
    ("tests/test_kea_helper_investigation.py", '"signalled"', _HELPER),
    (
        "tests/_investigation_world.py",
        '"signalled"',
        _HELPER + "; the fake models how the helper is observed, field for field",
    ),
    ("tests/", "/favourites/", _WOL + " - the route path"),
    ("tests/test_authz_matrix.py", "delete_favourite", _WOL + " - a view function"),
    ("tests/test_authz_matrix.py", "wake_favourite", _WOL + " - a view function"),
    ("tests/test_authz_matrix.py", "add_favourite", _WOL + " - a view function"),
    (
        "tests/test_stored_objects_wol.py",
        "That favourite is not yours to change.",
        _WOL + " - its flash sentence, asserted as the plugin prints it",
    ),
]

# --------------------------------------------------------------------------
# The sweep
# --------------------------------------------------------------------------

SWEPT_DIRS = [
    "templates",
    "jen",
    "tests",
    "docs",
    "tools",
    "static",
    ".github",
]
SWEPT_FILES = [
    "CHANGELOG.md",
    "README.md",
    "Dockerfile",
    "ruff.toml",
    "install.sh",
    "run.py",
]
SWEPT_GLOBS = ["docker-compose*.yml", "requirements*.txt"]

TEXT_SUFFIXES = {
    ".py",
    ".html",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".toml",
    ".json",
    ".js",
    ".css",
    ".sh",
    ".cfg",
    ".ini",
    ".conf",
    ".svg",
    ".in",
    ".j2",
    ".service",
    ".timer",
    ".env",
    ".example",
    ".sql",
    ".csv",
    ".webmanifest",
}

# path (posix, relative to ROOT) -> reason. A directory excludes its tree.
EXCLUDED: dict[str, str] = {
    "plugins": "vendored from each plugin's own repository; the pass is made there, with its own version (count printed)",
    "jen-kea-helper": "a change to the helper is a helper build; its comment-only hits go with the next helper Q (count printed)",
    "docs/release-history": "frozen archives of released upgrading pages",
    "static/js/htmx.min.js": "vendored library; tests/test_htmx_vendoring.py pins its bytes",
    "static/js/chart.umd.min.js": "vendored library (Chart.js)",
    "tests/test_american_spelling.py": "this file holds the table",
}

# Excluded paths whose counts the sweep PRINTS (a reminder, never a failure).
REMINDER_PATHS = ["plugins", "jen-kea-helper"]


_LETTER_RUN = re.compile(r"[A-Za-z]+")
# A run of letters split at its humps: ``badgeColour`` -> ``badge``, ``Colour``;
# ``XMLColour`` -> ``XML``, ``Colour``; ``BADGE`` -> ``BADGE``; ``colours`` -> ``colours``.
_HUMP = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")

FIX_FOR: dict[str, str] = dict(PAIRS)


def cased_like(match_text: str, replacement: str) -> str:
    """``colour``->``color``, ``Colour``->``Color``, ``COLOUR``->``COLOR``."""
    if match_text.isupper() and len(match_text) > 1:
        return replacement.upper()
    if match_text[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement


def humps(run: str) -> list[str]:
    return _HUMP.findall(run)


def british_humps(text: str) -> list[tuple[int, str, str]]:
    """``(offset, hump as written, run it sits in)`` for every hump of ``text`` the table names; the offset is the hump's own.

    A hump is a whole word, or one word of an identifier (``badge_colour``,
    ``badgeColour``, ``BADGE_COLOUR`` are hits); a longer word the table does
    not name (``discolour``, ``colourway``) is not.
    """
    found = []
    for run in _LETTER_RUN.finditer(text):
        pos = run.start()
        for hump in humps(run.group(0)):
            if hump.lower() in FIX_FOR:
                found.append((pos, hump, run.group(0)))
            pos += len(hump)
    return found


def fix_for(hump: str) -> str:
    return cased_like(hump, FIX_FOR[hump.lower()])


def _fix_run(m: re.Match[str]) -> str:
    return "".join(fix_for(h) if h.lower() in FIX_FOR else h for h in humps(m.group(0)))


def fix_text(text: str) -> str:
    """Apply the table to a string. The throwaway pass script used this; the test keeps it."""
    return _LETTER_RUN.sub(_fix_run, text)


def _is_excluded(rel_posix: str) -> bool:
    return any(rel_posix == ex or rel_posix.startswith(ex + "/") for ex in EXCLUDED)


def _is_text_file(path: pathlib.Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return bool(path.name in ("Dockerfile", "jen-kea-helper", "jen-sudoers") or path.name.startswith("Dockerfile."))


def swept_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for d in SWEPT_DIRS:
        base = ROOT / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if p.is_file() and _is_text_file(p) and "__pycache__" not in p.parts:
                files.append(p)
    for name in SWEPT_FILES:
        p = ROOT / name
        if p.is_file():
            files.append(p)
    for g in SWEPT_GLOBS:
        files.extend(sorted(p for p in ROOT.glob(g) if p.is_file()))
    out = []
    seen = set()
    for p in files:
        rel = p.relative_to(ROOT).as_posix()
        if rel in seen or _is_excluded(rel):
            continue
        seen.add(rel)
        out.append(p)
    return out


def hits_in(path: pathlib.Path) -> list[tuple[int, str, str]]:
    """``(lineno, british as written, american)`` for every match in the file."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    found = []
    rel = rel_of(path)
    for lineno, line in enumerate(text.splitlines(), 1):
        for pos, hump, _run in british_humps(line):
            if _allowlisted(rel, line, pos, pos + len(hump)):
                continue
            found.append((lineno, hump, fix_for(hump)))
    return found


def rel_of(path: pathlib.Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def _entry_covers(entry_path: str, rel_posix: str) -> bool:
    return rel_posix == entry_path or (entry_path.endswith("/") and rel_posix.startswith(entry_path))


def _allowlisted(rel_posix: str, line: str, start: int, end: int) -> bool:
    """An entry excuses the hump at ``line[start:end]`` when an occurrence of the entry's literal on that line contains it.

    Positional on purpose: ``reply["signalled"]  # the daemon was signalled`` keeps the field and loses the prose.
    """
    for entry_path, lit, _reason in ALLOWLIST:
        if not _entry_covers(entry_path, rel_posix):
            continue
        at = line.find(lit)
        while at != -1:
            if at <= start and end <= at + len(lit):
                return True
            at = line.find(lit, at + 1)
    return False


def fixed_text(rel_posix: str, text: str) -> str:
    """The table applied to one file's text, keeping every hump the allowlist excuses there.

    The pass that made the tree American (Q207) was this function over ``swept_files()``.
    """
    return "\n".join(_fixed_line(rel_posix, line) for line in text.split("\n"))


def _fixed_line(rel_posix: str, line: str) -> str:
    def _run(m: re.Match[str]) -> str:
        out = []
        pos = m.start()
        for hump in humps(m.group(0)):
            if hump.lower() in FIX_FOR and not _allowlisted(rel_posix, line, pos, pos + len(hump)):
                out.append(fix_for(hump))
            else:
                out.append(hump)
            pos += len(hump)
        return "".join(out)

    return _LETTER_RUN.sub(_run, line)


def sweep() -> list[str]:
    """Every hit in the swept tree, as ``path:line: word -> fix``."""
    findings = []
    for path in swept_files():
        rel = path.relative_to(ROOT).as_posix()
        for lineno, word, fix in hits_in(path):
            findings.append(f"{rel}:{lineno}: {word} -> {fix}")
    return findings


def reminder_counts() -> dict[str, int]:
    counts = {}
    for rel in REMINDER_PATHS:
        base = ROOT / rel
        n = 0
        if base.is_dir():
            for p in base.rglob("*"):
                if p.is_file() and _is_text_file(p) and "__pycache__" not in p.parts:
                    n += len(hits_in(p))
        elif base.is_file():
            n = len(hits_in(base))
        counts[rel] = n
    return counts


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


class TestTheTable:
    def test_every_pair_matches_its_own_british_form_and_not_its_american_one(self):
        wrong = []
        for british, american in PAIRS:
            if not british_humps(british):
                wrong.append(("misses itself", british))
            if fix_text(british) != american:
                wrong.append(("fixes to the wrong word", british, fix_text(british)))
            if british_humps(american):
                wrong.append(("matches its own fix", british, american))
            if british == american:
                wrong.append(("identical", british))
        assert not wrong, wrong

    def test_no_pair_is_listed_twice(self):
        britishes = [b for b, _a in PAIRS]
        dupes = sorted({b for b in britishes if britishes.count(b) > 1})
        assert not dupes, dupes

    @pytest.mark.parametrize("word", AMERICAN_TOO)
    def test_a_word_that_is_american_too_is_left_alone(self, word):
        assert not british_humps(word), f"the table rewrites {word!r}"
        assert fix_text(word) == word
        assert fix_text(word.capitalize()) == word.capitalize()
        assert fix_text(word.upper()) == word.upper()

    def test_case_is_kept(self):
        assert fix_text("colour Colour COLOUR") == "color Color COLOR"
        assert fix_text("Behaviour behaviours") == "Behavior behaviors"

    def test_identifiers_are_hits_and_longer_words_are_not(self):
        assert fix_text("badge_colour") == "badge_color"
        assert fix_text("badgeColour") == "badgeColor"
        assert fix_text("BADGE_COLOUR") == "BADGE_COLOR"
        assert fix_text("badge-colour") == "badge-color"
        assert fix_text("colour-picker") == "color-picker"
        assert fix_text("XMLColour") == "XMLColor"
        assert fix_text("MFA_ENROLL") == "MFA_ENROLL"  # all-caps ENROL is not inside ENROLL
        assert (
            fix_text("CancelledError") == "CanceledError"
        )  # a hit; the library's name is on ALLOWLIST where it is used
        assert fix_text("discolour") == "discolour"  # not in the table (discoloured is)
        assert fix_text("colourway") == "colourway"
        assert fix_text("Colourway") == "Colourway"
        assert fix_text("unrecognised") == "unrecognized"  # a prefixed form is its own pair

    def test_the_ise_table_is_a_list_of_verbs_not_a_suffix(self):
        assert all(stem.endswith("is") for stem in _ISE_VERBS), "a stem is the verb up to its -ise"
        assert len(_ISE_VERBS) == len(set(_ISE_VERBS))
        for banned in (
            "advertis",
            "promis",
            "exercis",
            "rais",
            "premis",
            "surpris",
            "compris",
            "supervis",
            "compromis",
        ):
            assert banned not in _ISE_VERBS


class TestTheExclusions:
    @pytest.mark.parametrize("rel", sorted(EXCLUDED))
    def test_each_excluded_path_exists_and_has_a_reason(self, rel):
        assert (ROOT / rel).exists(), f"{rel} is excluded but does not exist - drop the entry or restore the path"
        assert EXCLUDED[rel].strip(), rel

    def test_the_reminder_paths_are_excluded_ones(self):
        assert set(REMINDER_PATHS) <= set(EXCLUDED)

    def test_the_swept_tree_is_not_empty_and_skips_the_exclusions(self):
        files = swept_files()
        rels = {p.relative_to(ROOT).as_posix() for p in files}
        assert len(files) > 200, len(files)
        assert "templates/base.html" in rels
        assert "jen/routes/subnets.py" in rels
        assert "CHANGELOG.md" in rels
        assert "install.sh" in rels
        assert not any(_is_excluded(r) for r in rels)
        assert not any(r.startswith("plugins/") for r in rels)
        assert "static/js/htmx.min.js" not in rels


class TestTheAllowlistIsLive:
    def test_every_allowlist_entry_still_matches(self):
        stale = []
        for rel, literal, reason in ALLOWLIST:
            assert reason.strip(), (rel, literal)
            if not british_humps(literal):
                stale.append((rel, literal, "carries no British spelling - the entry excuses nothing"))
                continue
            if rel.endswith("/"):
                files = [p for p in swept_files() if rel_of(p).startswith(rel)]
                if not files:
                    stale.append((rel, literal, "directory gone or not swept"))
                    continue
            else:
                files = [ROOT / rel]
                if not files[0].is_file():
                    stale.append((rel, literal, "file gone"))
                    continue
            if not any(literal in f.read_text(encoding="utf-8") for f in files):
                stale.append((rel, literal, "no longer in the file(s)"))
        assert not stale, f"allowlist entries no longer excuse anything (stale or moved): {stale}"

    def test_the_allowlist_names_only_contracts(self):
        """The reviewed list: a stored key, a library's name, a field name as it shipped,
        and what the excluded wol plugin and Kea helper call the things this tree dials
        and reads. Q207 expected it empty and found these twelve; a new entry is a
        contract with its reason, never a sentence someone would rather not re-spell."""
        assert sorted((p, lit) for p, lit, _r in ALLOWLIST) == [
            ("CHANGELOG.md", "pool_utilisation"),
            ("jen/services/credentials.py", "credentials_materialised"),
            ("jen/services/investigation_logging.py", '"signalled"'),
            ("jen/services/provider_budget.py", "CancelledError"),
            ("tests/", "/favourites/"),
            ("tests/_investigation_world.py", '"signalled"'),
            ("tests/test_authz_matrix.py", "add_favourite"),
            ("tests/test_authz_matrix.py", "delete_favourite"),
            ("tests/test_authz_matrix.py", "wake_favourite"),
            ("tests/test_credentials.py", "credentials_materialised"),
            ("tests/test_kea_helper_investigation.py", '"signalled"'),
            ("tests/test_stored_objects_wol.py", "That favourite is not yours to change."),
        ]

    def test_an_excused_line_keeps_the_contract_and_loses_the_prose(self):
        line = 'reply["signalled"]  # the daemon was signalled'
        assert (
            fixed_text("tests/test_kea_helper_investigation.py", line)
            == 'reply["signalled"]  # the daemon was signaled'
        )
        assert fixed_text("tests/test_other.py", line) == 'reply["signaled"]  # the daemon was signaled'
        url = 'pclient.post(WOL + "/favourites/add")  # a favourite'
        assert (
            fixed_text("tests/system/test_boundaries.py", url) == 'pclient.post(WOL + "/favourites/add")  # a favorite'
        )
        assert fixed_text("jen/routes/x.py", url) == 'pclient.post(WOL + "/favorites/add")  # a favorite'


class TestTheTree:
    def test_the_tree_is_written_in_american_english(self, capsys):
        reminders = reminder_counts()
        with capsys.disabled():
            for rel, n in reminders.items():
                print(f"\n[american-spelling] {rel}: {n} British spelling(s) remain (excluded: {EXCLUDED[rel]})")
        findings = sweep()
        assert not findings, (
            f"{len(findings)} British spelling(s) in the swept tree (fix each as shown; a spelling that MUST stay goes on ALLOWLIST with its reason):\n"
            + "\n".join(findings)
        )
