r"""
tests/test_csp.py
───────────────────
v5.22.0 (Q18) — script-src drops 'unsafe-inline' in favor of a
per-request nonce (jen/services/csp.py::nonce() → g.csp_nonce, exposed
to templates as csp_nonce). Every <script> tag in templates/ and
plugins/*/templates now carries nonce="{{ csp_nonce }}" (except the two
vendored src= scripts, htmx.min.js and chart.umd.min.js — 'self'
already covers those), and all ~148 inline on*= handlers were converted
to either base.html's data-confirm/data-href/data-submit dispatcher or
a named function bound with addEventListener. style-src deliberately
keeps 'unsafe-inline' (1,212 style="" attributes — a redesign, not a
hardening pass).

Regex note: the pinned spec's inline-handler check is `\son[a-z]+\s*=`.
Applied to raw file text that also includes each page's own <script>
body, that pattern matches legitimate JS property assignments the very
same conversion introduced — `okBtn.onclick = function() {...}`
(base.html), `sel.onchange = function() {...}` (devices.html),
`reader.onload = function(e) {...}` (user_profile.html), several
`.onsubmit = null` cleanups. Those are JS-land property assignments on
already-fetched DOM nodes inside a nonced <script>, not inline HTML
attributes — CSP's script-src has no opinion on them. Requiring the
attribute-shaped `="` immediately after the handler name (matching the
sweep actually used while converting these templates) tells the two
apart; `\bon[a-z]+\s*=\s*"` catches real attributes including the
Jinja-abutting `%}onclick="` shape (`\b` also matches at `}`|`o`, which
bare `\s` does not) while leaving the JS assignments alone.
"""

import pathlib
import re

TEMPLATE_HTML_FILES = sorted(pathlib.Path("templates").rglob("*.html")) + sorted(
    pathlib.Path("plugins").rglob("*.html")
)


def _read_without_js_comments(path):
    """Every scan below reads real markup/JS, not prose describing it —
    and several of these templates now carry `// v5.22.0 (Q18) — was
    onclick="..."` / `// ...covers <script>` comments narrating exactly
    the shapes these regexes look for. Blanking out `//`-only lines
    keeps the scan honest without needing a full JS/HTML comment
    parser (nothing here writes a `/* block */` comment or an inline
    trailing `// comment` after real code)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join("" if line.strip().startswith("//") else line for line in lines)


SCRIPT_OPEN_RE = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
INLINE_ATTR_HANDLER_RE = re.compile(r'\bon[a-z]+\s*=\s*"')
LOOSE_HANDLER_RE = re.compile(r"\bon[a-z]+\s*=")  # the pinned spec's own regex, used repo-wide below
JS_HREF_RE = re.compile(r"javascript\s*:", re.IGNORECASE)

# (file, line-content substring, reason) — same shape as
# tests/test_no_raw_exception_leaks.py's ALLOWED_RAW_EXCEPTION_LINES.
# branding.py's own SVG-upload rejection writes "on[a-z]+=" as regex
# *source* (and names onload= in a comment) — not a live HTML
# attribute — so the repo-wide sweep below allow-lists it explicitly.
ALLOWLISTED_HANDLER_LINES = [
    ("jen/routes/settings/branding.py", "onload= handler", "comment naming the pattern the SVG regex rejects"),
    ("jen/routes/settings/branding.py", r"\bon[a-z]+\s*=", "regex source text in _SVG_FORBIDDEN, not a live attribute"),
]


class TestScriptTagsHaveNonce:
    def test_every_inline_script_tag_has_a_nonce(self):
        missing = []
        for path in TEMPLATE_HTML_FILES:
            content = _read_without_js_comments(path)
            for attrs in SCRIPT_OPEN_RE.findall(content):
                if "src=" in attrs:
                    continue  # vendored htmx.min.js / chart.umd.min.js — 'self', not inline
                if "nonce=" not in attrs:
                    missing.append(str(path))
        assert not missing, f"<script> tag(s) missing nonce=: {missing}"

    def test_htmx_swapped_partials_contain_no_script_tag(self):
        """The true swap-target set, from grepping jen/routes/*.py for
        render_template("_....html" call sites — not just every
        underscore-prefixed filename. _dhcp_options_table.html, for
        example, has a <script> but is only ever {% include %}d, never
        route-rendered directly, so it's not in this list."""
        swapped_partials = [
            "templates/_recent_leases_rows.html",
            "templates/_recent_leases.html",
            "templates/_devices_results.html",
            "templates/_devices6_results.html",
            "templates/_health_checks.html",
            "templates/_leases_results.html",
            "templates/_leases6_results.html",
            "templates/_reservations_results.html",
            "templates/_reservations6_results.html",
            "templates/_class_preview.html",
        ]
        offenders = []
        for rel in swapped_partials:
            path = pathlib.Path(rel)
            assert path.exists(), f"expected htmx-swapped partial not found: {rel}"
            if "<script" in path.read_text(encoding="utf-8").lower():
                offenders.append(rel)
        assert not offenders, f"htmx-swapped partial(s) contain a <script> tag: {offenders}"


class TestNoInlineEventHandlers:
    def test_no_on_attr_handlers_in_templates_or_plugins(self):
        findings = []
        for path in TEMPLATE_HTML_FILES:
            content = _read_without_js_comments(path)
            for lineno, line in enumerate(content.splitlines(), 1):
                if INLINE_ATTR_HANDLER_RE.search(line):
                    findings.append((str(path), lineno, line.strip()))
        assert not findings, f"inline on*= HTML attribute handler(s) found: {findings}"

    def test_no_on_attr_pattern_repo_wide_except_allowlist(self):
        """The pinned spec's own regex (\\son[a-z]+\\s*=), applied
        repo-wide as defense-in-depth against a future Python string
        builder emitting an on*= attribute into rendered HTML — not
        just the template files checked precisely above."""
        findings = []
        for path in sorted(pathlib.Path("jen").rglob("*.py")):
            content = path.read_text(encoding="utf-8")
            posix = path.as_posix()
            for lineno, line in enumerate(content.splitlines(), 1):
                if not LOOSE_HANDLER_RE.search(line):
                    continue
                if any(posix.endswith(f) and sig in line for f, sig, _ in ALLOWLISTED_HANDLER_LINES):
                    continue
                findings.append((posix, lineno, line.strip()))
        assert not findings, f"unexpected on*= pattern outside the allowlist: {findings}"

    def test_allowlist_entries_still_exist_in_their_files(self):
        stale = []
        for filepath, signature, _reason in ALLOWLISTED_HANDLER_LINES:
            text = pathlib.Path(filepath).read_text(encoding="utf-8")
            if signature not in text:
                stale.append((filepath, signature))
        assert not stale, f"allowlist entries no longer found in their files (stale or moved): {stale}"


class TestNoJavascriptHrefs:
    def test_no_javascript_scheme_hrefs(self):
        findings = []
        for path in TEMPLATE_HTML_FILES:
            content = _read_without_js_comments(path)
            for lineno, line in enumerate(content.splitlines(), 1):
                if JS_HREF_RE.search(line):
                    findings.append((str(path), lineno, line.strip()))
        assert not findings, f"javascript: href(s) found: {findings}"


class TestNoMermaidOrEval:
    def test_no_mermaid_or_eval_usage(self):
        """Never used in this app — asserted so a future addition can't
        slip in without someone reconsidering allowEval/script-src."""
        for path in TEMPLATE_HTML_FILES:
            content = _read_without_js_comments(path)
            assert "mermaid" not in content.lower(), f"{path} references mermaid"
            for lineno, line in enumerate(content.splitlines(), 1):
                assert re.search(r"\beval\s*\(", line) is None, f"{path}:{lineno} calls eval("

    def test_htmx_eval_disabled(self):
        content = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
        assert "htmx.config.allowEval = false" in content


class TestSecurityHeaders:
    def test_report_only_header_present_with_nonce_and_no_unsafe_inline_script(self, logged_in_client):
        resp = logged_in_client.get("/")
        ro = resp.headers.get("Content-Security-Policy-Report-Only")
        assert ro is not None
        m = re.search(r"script-src ([^;]+);", ro)
        assert m is not None
        script_src = m.group(1)
        assert "'unsafe-inline'" not in script_src
        assert "'nonce-" in script_src

    def test_enforcing_header_still_has_unsafe_inline_script_for_now(self, logged_in_client):
        """Step 1/2 ships Report-Only alongside the unchanged enforcing
        header — nothing can break even if the handler conversion
        missed a spot. Step 2 flips this."""
        resp = logged_in_client.get("/")
        csp = resp.headers.get("Content-Security-Policy")
        assert csp is not None
        assert "script-src 'self' 'unsafe-inline'" in csp

    def test_style_src_keeps_unsafe_inline(self, logged_in_client):
        resp = logged_in_client.get("/")
        for header_name in ("Content-Security-Policy", "Content-Security-Policy-Report-Only"):
            header = resp.headers.get(header_name)
            assert header is not None
            assert "style-src 'self' 'unsafe-inline'" in header

    def test_two_requests_get_different_nonces(self, logged_in_client):
        first = logged_in_client.get("/").headers.get("Content-Security-Policy-Report-Only")
        second = logged_in_client.get("/").headers.get("Content-Security-Policy-Report-Only")
        nonce_re = re.compile(r"'nonce-([^']+)'")
        n1, n2 = nonce_re.search(first).group(1), nonce_re.search(second).group(1)
        assert n1 != n2

    def test_rendered_page_script_nonce_matches_header_nonce(self, logged_in_client):
        """The nonce a template actually emits must be the same value
        the browser is told to trust — that's the entire mechanism."""
        resp = logged_in_client.get("/")
        ro = resp.headers.get("Content-Security-Policy-Report-Only")
        header_nonce = re.search(r"'nonce-([^']+)'", ro).group(1)
        body = resp.get_data(as_text=True)
        assert f'nonce="{header_nonce}"' in body
