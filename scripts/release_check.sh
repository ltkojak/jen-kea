#!/usr/bin/env bash
# release_check.sh — version-sync guard, run before every package.
# Verifies the release version appears consistently in ALL living documents,
# not just the badge. Exits 1 on any mismatch.
set -u
cd "$(dirname "$0")/.."

VER=$(grep -m1 'JEN_VERSION = ' jen/__init__.py | grep -oP '\d+\.\d+\.\d+')
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

# No stale tarball references anywhere in living docs
for f in README.md docs/admin-guide.md; do
    STALE=$(grep -oP 'jen-v\d+\.\d+\.\d+\.tar\.gz' "$f" | grep -v "jen-v$VER.tar.gz" | sort -u)
    if [ -n "$STALE" ]; then
        echo "FAIL: $f contains stale tarball reference(s): $STALE"
        FAIL=1
    fi
    grep -q "jen-v$VER.tar.gz" "$f" || { echo "FAIL: $f has no jen-v$VER.tar.gz reference"; FAIL=1; }
done

[ $FAIL -eq 0 ] && echo "PASS: all living documents at $VER" || echo "RELEASE CHECK FAILED"
exit $FAIL
