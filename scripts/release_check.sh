#!/usr/bin/env bash
# release_check.sh — version-sync guard, run before every package.
# Verifies the release version appears consistently in ALL living documents,
# not just the badge. Exits 1 on any mismatch.
set -u
cd "$(dirname "$0")/.."

VER=$(grep -m1 'JEN_VERSION = ' jen/__init__.py | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
FAIL=0

check() {  # check <file> <description> <grep-pattern>
    if ! grep -q "$3" "$1"; then
        echo "FAIL: $1 — $2 (expected to match: $3)"
        FAIL=1
    fi
}

echo "Release version: $VER"
check install.sh        "JEN_VERSION"        "JEN_VERSION=\"$VER\""
check README.md         "version badge"      "Version-$VER-blue"
check CHANGELOG.md      "top entry"          "^## \\[$VER\\]"
check Dockerfile             "LABEL version"  "LABEL version=\"$VER\""
check docker-compose.yml     "image tag"      "image: jen-dhcp:$VER"
check docker-compose.mysql.yml "image tag"    "image: jen-dhcp:$VER"

# No stale *numeric* tarball references anywhere in living docs. Only the
# README is required to name the current version (it's in the bump list
# enforced by tests/test_dependency_consistency.py); the guides use a
# jen-vX.Y.Z.tar.gz placeholder since v5.8.4 — they had drifted to 5.3.3
# and 3.8.0 because nothing bumped them.
for f in README.md docs/admin-guide.md docs/installation.md docs/manual-install.md; do
    STALE=$(grep -oE 'jen-v[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' "$f" | grep -v "jen-v$VER.tar.gz" | sort -u)
    if [ -n "$STALE" ]; then
        echo "FAIL: $f contains stale tarball reference(s): $STALE"
        FAIL=1
    fi
done
grep -q "jen-v$VER.tar.gz" README.md || { echo "FAIL: README.md has no jen-v$VER.tar.gz reference"; FAIL=1; }

[ $FAIL -eq 0 ] && echo "PASS: all living documents at $VER" || echo "RELEASE CHECK FAILED"
exit $FAIL
