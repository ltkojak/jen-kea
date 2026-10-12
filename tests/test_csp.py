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

    @staticmethod
    def _route_rendered_partials():
        """Every `_*.html` a route (jen/routes/**, plugins/*/plugin.py) hands to render_template with a literal
            name, multi-line-aware: `render_template(
        "_x.html", ...)` is found too."""
        import re

        call = re.compile(r"render_template\(\s*[\"'](?:[\w./-]*/)?(_[\w.-]+\.html)[\"']", re.S)
        files = sorted(pathlib.Path("jen/routes").rglob("*.py")) + sorted(pathlib.Path("plugins").glob("*/plugin.py"))
        found = {}
        for path in files:
            for name in call.findall(path.read_text(encoding="utf-8")):
                found.setdefault(name, path.as_posix())
        return found

    def test_htmx_swapped_partials_contain_no_script_tag(self):
        """The true swap-target set: every `_*.html` a route renders directly, DERIVED from the code (the old
        hand-typed list had drifted: `_explain_result`, `_ha_maintenance_status`, `_timeline_rows` and
        `_trace_results` were route-rendered and not in it). _dhcp_options_table.html, for example, has a
        <script> but is only ever {% include %}d, never route-rendered directly, so the scan does not list it."""
        rendered = self._route_rendered_partials()
        assert len(rendered) >= 10, f"the scan found only {sorted(rendered)}: it has stopped working"
        for name in (
            "_explain_result.html",
            "_ha_maintenance_status.html",
            "_timeline_rows.html",
            "_trace_results.html",
            "_recent_leases_rows.html",
        ):
            assert name in rendered, f"the scan no longer finds {name}"
        names = sorted(rendered)
        offenders = []
        for name in names:
            candidates = [pathlib.Path("templates") / name, *pathlib.Path("plugins").glob(f"*/templates/**/{name}")]
            path = next((c for c in candidates if c.exists()), None)
            assert path is not None, f"route-rendered partial not found on disk: {name}"
            if "<script" in path.read_text(encoding="utf-8").lower():
                offenders.append(path.as_posix())
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


class TestNoHeredocsInTemplates:
    def test_no_heredoc_operator_cookbook_command_in_templates(self):
        """v5.65.13 (Q102) — a multi-line heredoc (`sudo tee <<'EOF' ... EOF`) pastes badly into
        some terminals/web consoles; every operator copy box in templates/ is now a single
        `printf '%s\\n' ... | sudo tee ... && ...` line. Docs (docs/*.md) may still show a heredoc
        INSIDE a fenced block that documents a file's contents rather than a command to paste, so
        this guard is templates-only."""
        findings = []
        for path in TEMPLATE_HTML_FILES:
            content = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(content.splitlines(), 1):
                if "<<'EOF'" in line or "<<EOF" in line or "&lt;&lt;'EOF'" in line or "&lt;&lt;EOF" in line:
                    findings.append((str(path), lineno, line.strip()))
        assert not findings, f"heredoc-shaped operator command found in a template: {findings}"


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


class TestJenFetchIsDefinedBeforeTheContentBlock:
    """Q173: leases.html and reservations.html call jenFetch from a script inside {% block content %}, which renders before the
    scripts at the end of base.html - so the definition lives in the head script."""

    def test_base_defines_it_in_the_head(self):
        text = pathlib.Path("templates/base.html").read_text(encoding="utf-8")
        assert text.index("window.jenFetch = function") < text.index("{% block content %}")

    def test_no_other_template_defines_its_own(self):
        for path in TEMPLATE_HTML_FILES:
            if path.name != "base.html":
                # a CALL (the dns-sync plugin's `window.jenFetch(...)`) is fine; a second DEFINITION is not
                assert not re.search(r"window\.jenFetch\s*=[^=]", path.read_text(encoding="utf-8")), path


SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.S | re.I)
EXPR_RE = re.compile(r"\{\{(.*?)\}\}", re.S)
# "templates/<file>.html": {"<expression as written>": "why it is safe without |tojson"}
TOJSON_REVIEWED: dict = {
    # a boolean literal the template itself picks between 'true' and 'false' - no data in it. The file is the bundled copy of the IPAM plugin's release,
    # byte-identical to its tag (the registry pins its sha256), so it is changed at its source in the plugin sweep (Q174), not here.
    "plugins/ipam/templates/ipam/subnet.html": {
        "'true' if unmanaged else 'false'": "a literal true/false chosen by the template, no value is interpolated",
    },
}


class TestJsContextsUseTojson:
    """Q173: a Jinja value inside a <script> body is JS, and HTML autoescaping is not JS escaping (CLAUDE.md, Frontend)."""

    @staticmethod
    def _js_spans(text):
        """(start, end) of every JS body: a <script> without src, and a child template's `{% block scripts %}` (base.html puts that block INSIDE its own <script>, so the
        child writes bare JS with no tag around it - the script regex alone never saw it)."""
        spans = [(m.start(2), m.end(2)) for m in SCRIPT_RE.finditer(text) if "src=" not in m.group(1)]
        spans += [
            (m.start(1), m.end(1)) for m in re.finditer(r"\{% block scripts %\}(.*?)\{% endblock %\}", text, re.S)
        ]
        merged = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    def _sites(self):
        out = []
        for path in TEMPLATE_HTML_FILES:
            text = path.read_text(encoding="utf-8")
            for start, end in self._js_spans(text):
                for e in EXPR_RE.finditer(text[start:end]):
                    expr = e.group(1).strip()
                    line = text[text.rfind("\n", 0, start + e.start()) + 1 : text.find("\n", start + e.start())]
                    if "<script" in line:  # the nonce attribute of a script tag a block re-opens: markup, not JS
                        continue
                    if "tojson" in expr or expr in TOJSON_REVIEWED.get(path.as_posix(), {}):
                        continue
                    out.append((path.as_posix(), text[: start + e.start()].count("\n") + 1, expr))
        return out

    def test_every_value_in_a_script_is_tojson_or_reviewed(self):
        assert self._sites() == [], (
            "a value in a JS context without |tojson: add the filter, or argue it onto TOJSON_REVIEWED"
        )

    def test_the_reviewed_list_is_live(self):
        for rel, exprs in TOJSON_REVIEWED.items():
            text = pathlib.Path(rel).read_text(encoding="utf-8")
            scripts = " ".join(text[s:e] for s, e in self._js_spans(text))
            for expr in exprs:
                assert expr in scripts, f"{rel} no longer has {expr!r}: drop it from TOJSON_REVIEWED"


class TestSecurityHeaders:
    def test_enforcing_header_has_nonce_and_no_unsafe_inline_script(self, logged_in_client):
        """Step 2/2 — the nonce-based script-src is now enforcing, not
        Report-Only; there is no Content-Security-Policy-Report-Only
        header left to fall back on."""
        resp = logged_in_client.get("/")
        assert resp.headers.get("Content-Security-Policy-Report-Only") is None
        csp = resp.headers.get("Content-Security-Policy")
        assert csp is not None
        m = re.search(r"script-src ([^;]+);", csp)
        assert m is not None
        script_src = m.group(1)
        assert "'unsafe-inline'" not in script_src
        assert "'nonce-" in script_src

    def test_style_src_keeps_unsafe_inline(self, logged_in_client):
        resp = logged_in_client.get("/")
        csp = resp.headers.get("Content-Security-Policy")
        assert csp is not None
        assert "style-src 'self' 'unsafe-inline'" in csp

    def test_img_src_allows_data_urls(self, logged_in_client):
        """v5.31.1 — the TOTP enrolment QR (`data:image/png;base64,…`) and
        uploaded avatars are data: URLs. Without an img-src directive they
        fell through to default-src 'self' and every browser blocked them
        — the enrolment page showed a broken image from v4.4.5 (when the
        header arrived) until this. Only images get the scheme; scripts,
        styles and everything else keep 'self'."""
        resp = logged_in_client.get("/")
        csp = resp.headers.get("Content-Security-Policy")
        assert "img-src 'self' data:" in csp
        assert "default-src 'self';" in csp
        # No other directive picked up data: along the way.
        for directive in ("script-src", "style-src", "default-src"):
            m = re.search(directive + r" ([^;]+)", csp)
            assert m and "data:" not in m.group(1), directive

    def test_mfa_enrolment_page_embeds_a_real_png_qr(self, logged_in_client):
        """The image the policy now permits must actually be there: the
        route renders a base64 PNG (iVBOR… is the PNG magic) inline."""
        page = logged_in_client.get("/mfa/enroll").get_data(as_text=True)
        assert 'src="data:image/png;base64,iVBOR' in page

    def test_two_requests_get_different_nonces(self, logged_in_client):
        first = logged_in_client.get("/").headers.get("Content-Security-Policy")
        second = logged_in_client.get("/").headers.get("Content-Security-Policy")
        nonce_re = re.compile(r"'nonce-([^']+)'")
        n1, n2 = nonce_re.search(first).group(1), nonce_re.search(second).group(1)
        assert n1 != n2

    def test_rendered_page_script_nonce_matches_header_nonce(self, logged_in_client):
        """The nonce a template actually emits must be the same value
        the browser is told to trust — that's the entire mechanism."""
        resp = logged_in_client.get("/")
        csp = resp.headers.get("Content-Security-Policy")
        header_nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
        body = resp.get_data(as_text=True)
        assert f'nonce="{header_nonce}"' in body
