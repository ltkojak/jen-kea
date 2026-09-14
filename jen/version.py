"""
jen/version.py
──────────────
v5.32.0 (Q38) — the ONE version parser, and the release picker the two
update channels share.

Grammar: `X.Y.Z` (a stable release) or `X.Y.Z-beta.N` / `X.Y.Z-rc.N`
(a prerelease, N ≥ 1). Ordering is semver's:

    5.31.3 < 5.32.0-beta.1 < 5.32.0-beta.2 < 5.32.0-rc.1 < 5.32.0

Everything that compares Jen versions goes through here: the Updates
page check, plugin `requires_jen` gating (on the numeric triple — a
beta of X.Y.Z satisfies a plugin that needs X.Y.Z), the About page's
changelog order, and the root-privileged updater — which cannot import
this package and therefore carries a BYTE-IDENTICAL copy of the block
between the BEGIN/END markers below (`tests/test_version.py` diffs the
two; edit here, then paste there).
"""

import re

# ── BEGIN shared-with-root ─── copied verbatim into jen-update-root.py ──────
# (`re` is imported at the top of both files; the block itself imports nothing.)
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-(beta|rc)\.(\d+))?$")
_PRE_RANK = {"beta": 0, "rc": 1}
_FINAL_RANK = 2
CHANNELS = ("stable", "beta")


def parse_version(v):
    """'X.Y.Z[-beta.N|-rc.N]' → (X, Y, Z, rank, N) where rank is 0 for
    beta, 1 for rc, 2 for a final release (N = 0 then), so tuples order
    the way semver does. Anything else → (0, 0, 0, 0, 0), the lowest
    possible version — an unparsable tag is never "newer"."""
    m = _VERSION_RE.match(str(v or "").strip())
    if not m:
        return (0, 0, 0, 0, 0)
    x, y, z, kind, n = m.groups()
    if kind is None:
        return (int(x), int(y), int(z), _FINAL_RANK, 0)
    return (int(x), int(y), int(z), _PRE_RANK[kind], int(n))


def numeric(v):
    """(X, Y, Z) only — for `requires_jen`-style minimums, where a
    prerelease of X.Y.Z counts as X.Y.Z."""
    return parse_version(v)[:3]


def is_prerelease(v):
    return parse_version(v)[3] != _FINAL_RANK and parse_version(v) != (0, 0, 0, 0, 0)


def pick_release(releases, channel):
    """The newest usable GitHub release for `channel` from a
    /repos/{repo}/releases listing, or None. Drafts are never offered;
    `stable` sees only non-prereleases; `beta` sees everything. Chosen by
    parsed tag, never by list position — GitHub orders by creation."""
    best, best_key = None, None
    for rel in releases or []:
        if not isinstance(rel, dict) or rel.get("draft"):
            continue
        if channel != "beta" and rel.get("prerelease"):
            continue
        key = parse_version(str(rel.get("tag_name", "")).lstrip("v"))
        if key == (0, 0, 0, 0, 0):
            continue
        if best_key is None or key > best_key:
            best, best_key = rel, key
    return best


# ── END shared-with-root ────────────────────────────────────────────────────
