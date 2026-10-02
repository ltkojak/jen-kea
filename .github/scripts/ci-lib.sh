# Sourced by CI steps (`source .github/scripts/ci-lib.sh`) — v5.67.0-beta.10 (Q122).
#
# Small helpers so a CI assertion is spelled the one way that cannot be a no-op:
#   * no `! grep` (bash exempts a negated command from errexit),
#   * no `cmd | grep -q` (under pipefail a grep that exits early SIGPIPEs the
#     writer and fails the pipeline for the wrong reason).
# tests/test_workflow_hygiene.py refuses both spellings in every workflow.

JEN_URL="${JEN_URL:-http://127.0.0.1:5050}"

# jen_version [URL] — the VALUE of jen_version from /api/v1/health, never just
# whether the key is present.
jen_version() {
    local body
    body=$(curl -sf "${1:-$JEN_URL}/api/v1/health") || return 1
    python3 -c 'import json,sys; print(json.loads(sys.argv[1])["jen_version"])' "$body"
}

# expect_eq ACTUAL EXPECTED WHAT — fail the step, naming WHAT, when they differ.
expect_eq() {
    if [[ "$1" != "$2" ]]; then
        echo "::error::$3: expected '$2', got '$1'"
        exit 1
    fi
}

# refuse PATTERN TEXT MESSAGE — fail the step when TEXT contains PATTERN.
refuse() {
    if grep -q -- "$1" <<< "$2"; then
        echo "::error::$3"
        exit 1
    fi
}

# require PATTERN TEXT MESSAGE — fail the step unless TEXT contains PATTERN.
require() {
    if ! grep -q -- "$1" <<< "$2"; then
        echo "::error::$3"
        exit 1
    fi
}

# sha_of FILE — the file's sha256, read with sudo (the redirect form `sudo sha256sum < FILE` opens FILE as
# the UNPRIVILEGED shell, which cannot read a root-only 0700 script).
sha_of() {
    sudo sha256sum "$1" | cut -d' ' -f1
}

# jen_login COOKIEJAR PASSWORD — a real login as admin through the form.
jen_login() {
    local cookie="$1" pass="$2" csrf
    csrf=$(curl -sc "$cookie" "$JEN_URL/login" | grep -m1 -oP 'name="csrf_token" value="\K[^"]+') || true
    if [[ -z "$csrf" ]]; then
        echo "::error::no csrf token on the login page"
        exit 1
    fi
    curl -sb "$cookie" -c "$cookie" -X POST "$JEN_URL/login" \
        --data-urlencode "username=admin" --data-urlencode "password=$pass" --data-urlencode "csrf_token=$csrf" \
        -o /dev/null
}
