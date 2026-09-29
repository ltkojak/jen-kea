"""
tests/test_public_surface.py
─────────────────────────────
v5.66.0-beta.4 (Q106) — Grok's review of 5.66.0-beta.3 found that Jen has never once said out
loud, anywhere, which routes answer with no session and no API key — `/api/v1/health` and
`/api/v1/openapi.json` are public BY DECISION (docs/ARCHITECTURE.md §3.15), but a page/route
becoming anonymously reachable by accident has never had a test to catch it.

This walks the REAL `app.url_map` — every GET-capable rule, with fabricated path arguments —
and requests each one with a fresh, unauthenticated `client` (no session, no API key, no
cookie). A route "answers" if it doesn't redirect to /login and doesn't return 401/403; that
set is compared against PUBLIC_ENDPOINTS below. A route that starts answering anonymously
without being added here on purpose fails this test — the allowlist is the actual contract,
not a guess at one.

Deliberately dynamic, not a decorator scan: several of these routes (every /api/v1/* endpoint
except health and openapi.json) gate on a hand-rolled `_api_auth()` check inside the function
body, not a decorator — a static scan for `@login_required`-shaped names would have missed
them entirely (and did, on the first pass of this file).
"""

from werkzeug.routing import BuildError

# The complete, intentional anonymous surface — every GET-capable Flask endpoint that answers
# with no session and no API key. Add a new one here only on purpose, alongside a line in
# docs/ARCHITECTURE.md §3.15 saying why.
PUBLIC_ENDPOINTS = {
    "api.api_v1_health",  # jen_version only (v5.65.12, Q101) — the self-updater/restore poll
    "api.api_v1_openapi",  # the OpenAPI document describing this same surface
    "auth.login",  # the sign-in page itself
    "content.content_icon",  # uploaded brand icon — an <img> src, same posture as /static
    "content.content_branding",  # nav logo — same
    "static",  # Flask's own static handler: CSS/JS/htmx/Chart.js/the PWA manifest/icons
    "favicon",  # /favicon.ico
}


def _candidate_values(rule):
    """A couple of guesses at path-argument values, tried in order. Almost every dynamic
    segment in this app is <int:...>; a couple (icon/branding names, the static path) are
    strings. Trying int first and falling back to string covers both without needing to
    introspect Werkzeug's (private) converter classes."""
    return [
        dict.fromkeys(rule.arguments, 999999),
        dict.fromkeys(rule.arguments, "probe"),
    ]


def _anonymous_public_endpoints(app, client):
    adapter = app.url_map.bind("localhost")
    answered = set()
    for rule in app.url_map.iter_rules():
        if "GET" not in (rule.methods or set()):
            continue
        url = None
        for values in _candidate_values(rule):
            try:
                url = adapter.build(rule.endpoint, values=values, method="GET")
            except (BuildError, ValueError, TypeError):
                continue
            else:
                break
        if url is None:
            continue  # a rule this fixed guessing can't satisfy - not this test's job to solve
        resp = client.get(url, follow_redirects=False)
        if resp.status_code in (401, 403):
            continue
        if resp.status_code in (301, 302, 303, 307, 308) and "/login" in resp.headers.get("Location", ""):
            continue
        answered.add(rule.endpoint)
    return answered


class TestPublicSurface:
    def test_anonymous_get_matches_the_pinned_allowlist(self, app, client):
        answered = _anonymous_public_endpoints(app, client)
        unexpected = answered - PUBLIC_ENDPOINTS
        missing = PUBLIC_ENDPOINTS - answered
        assert not unexpected, (
            f"route(s) now answer anonymously without being in PUBLIC_ENDPOINTS - either this "
            f"is a real regression (fix the auth gate) or it's intentional (add it here AND to "
            f"docs/ARCHITECTURE.md §3.15): {sorted(unexpected)}"
        )
        assert not missing, (
            f"route(s) pinned as public no longer answer anonymously - PUBLIC_ENDPOINTS is stale, "
            f"or something newly gates them: {sorted(missing)}"
        )
