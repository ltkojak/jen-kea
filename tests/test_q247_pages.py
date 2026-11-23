"""
tests/test_q247_pages.py
────────────────────────
v7.2.0-beta.5 (Q247) - the page defects of the look over v7.2.0-beta.4 that a rendered page can hold (the navigation rows are in
tests/test_settings_ia.py and tests/e2e/test_navigation.py; the phone and theme rows are the screenshot job's).

* U5  the Health check that is green when no server is at investigation logging is titled for the good state, under its old id.
* U9  an API key's subnets are checkboxes that post the field the route always read, and the route reads them as it read the list.
* U10 the Prometheus open-access checkbox is one sentence.
* U11 a plugin's description is printed whole.
* U15 the About page says the HTTP port redirects only when a certificate is installed.
"""

import re

from jen.services import health


class TestHealthTitle:
    def test_the_title_names_the_good_state_and_the_id_is_unchanged(self):
        assert health._CHECK_META["debug_logging_left_on"][0] == "No DEBUG logging left on"

    def test_no_message_names_the_row_by_its_old_title(self):
        import pathlib

        root = pathlib.Path(health.__file__).resolve().parent
        for name in ("health.py", "investigation_logging.py"):
            text = (root / name).read_text(encoding="utf-8")
            assert not re.search(r"(?<!No )DEBUG logging left on", text), name


class TestApiKeySubnetsAreCheckboxes:
    def test_the_form_is_a_list_of_checkboxes_named_as_the_route_reads_them(self, logged_in_client):
        html = logged_in_client.get("/settings/api-keys").get_data(as_text=True)
        assert '<input type="checkbox" name="subnet_ids" value="all" checked>' in html
        assert re.search(r'<input type="checkbox" name="subnet_ids" value="\d+">', html), (
            "no subnet is offered as a checkbox"
        )
        assert "<select" not in html.split('id="f-subnet_ids"', 1)[1].split("</div>", 1)[0]
        assert "Ctrl/Cmd" not in html

    def test_a_ticked_subnet_makes_a_key_for_that_subnet(self, logged_in_client, app):
        from jen.models.db import jen_db

        html = logged_in_client.get("/settings/api-keys").get_data(as_text=True)
        ids = re.findall(r'name="subnet_ids" value="(\d+)"', html)
        assert ids, "the test configuration has no subnet to tick"
        picked = ids[:2]  # every subnet the suite configures, at most two (it configures one)
        r = logged_in_client.post(
            "/settings/api-keys/create",
            data={"name": "q247-ticked-subnets", "subnet_ids": picked},
            follow_redirects=True,
        )
        assert r.status_code == 200
        try:
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT subnet_access FROM api_keys WHERE name=%s", ("q247-ticked-subnets",))
                row = cur.fetchone()
            assert row is not None, "the key was not created"
            stored = row["subnet_access"] if isinstance(row, dict) else row[0]
            assert sorted(re.findall(r"\d+", str(stored))) == sorted(picked), stored
        finally:
            with jen_db() as db, db.cursor() as cur:
                cur.execute("DELETE FROM api_keys WHERE name=%s", ("q247-ticked-subnets",))


class TestTheScriptsBlockIsAlreadyAScript:
    def test_no_template_opens_a_script_tag_inside_the_scripts_block(self):
        """Q247 (fixup 1). base.html prints `{% block scripts %}` INSIDE its own <script> element, so a template that opens a <script> tag there puts markup into JavaScript:
        the browser stops at "Unexpected token '<'" and none of the page's script runs, base.html's included. The API keys page of the release commit did, and the GUI tour
        found it (the unit suite and the browser journeys did not open that page with an error listener)."""
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        base = (root / "templates" / "base.html").read_text(encoding="utf-8")
        before = base[: base.index("{% block scripts %}")]
        assert before.rfind("<script") > before.rfind("</script>"), (
            "base.html no longer prints the scripts block inside a script element: this test's premise moved"
        )
        bad = []
        for path in sorted(root.glob("templates/**/*.html")) + sorted(root.glob("plugins/*/templates/**/*.html")):
            text = path.read_text(encoding="utf-8")
            for block in re.findall(r"{%-?\s*block scripts\s*-?%}(.*?){%-?\s*endblock", text, flags=re.S):
                # the first script tag of the block must CLOSE base.html's element (Reports and Kea servers do that to load a library, then open their own);
                # a line that is a JavaScript comment may name the tag
                code = "\n".join(line for line in block.splitlines() if not line.strip().startswith("//"))
                first = re.search(r"<(/?)script\b", code)
                if path.name != "base.html" and first is not None and first.group(1) != "/":
                    bad.append(str(path.relative_to(root)).replace("\\", "/"))
        assert not bad, bad


class TestSentences:
    def test_the_open_access_checkbox_is_one_sentence(self, logged_in_client):
        html = logged_in_client.get("/settings/alerts").get_data(as_text=True)
        assert (
            "<span>Allow open access with no token - only if <code>/metrics</code> is already restricted at the network or "
            "reverse-proxy level</span>"
        ) in re.sub(r"\s+", " ", html)

    def test_a_plugins_description_is_not_cut(self, logged_in_client, monkeypatch):
        import json
        import pathlib

        from jen.services import plugins as plugins_svc

        # Q248 (V42): a plugin's whole description is on the Plugin Manager page now (Settings - System lists the name, the version and the
        # status); neither template cuts one
        monkeypatch.setattr(plugins_svc, "fetch_registry", lambda: ([], ""))
        html = logged_in_client.get("/settings/plugins").get_data(as_text=True)
        for name in ("settings_system.html", "plugins.html"):
            assert "[:80]" not in pathlib.Path("templates", name).read_text(encoding="utf-8"), name
        manifest = json.loads(pathlib.Path("plugins/ipam/manifest.json").read_text(encoding="utf-8"))
        if "IPAM Lite" in html:  # the unit suite runs with no plugin directory; the page then lists none
            assert manifest["description"][:120] in html.replace("&#39;", "'").replace("&amp;", "&")


class TestAboutSaysWhatIsSo:
    @staticmethod
    def _port_rows(html):
        """The two port rows of the System card; the page also prints the release notes, which quote both sentences."""
        start = html.index(">HTTP Port</td>")
        return html[start : html.index(">Config File</td>", start)]

    def test_without_a_certificate_the_http_port_does_not_claim_a_redirect(self, logged_in_client, monkeypatch):
        import jen.config

        monkeypatch.setattr(jen.config, "ssl_configured", lambda: False)
        row = self._port_rows(logged_in_client.get("/about").get_data(as_text=True))
        assert "(redirects to HTTPS)" not in row
        assert "(not in use: no certificate is installed)" in row

    def test_with_a_certificate_it_does(self, logged_in_client, monkeypatch):
        import jen.config

        monkeypatch.setattr(jen.config, "ssl_configured", lambda: True)
        row = self._port_rows(logged_in_client.get("/about").get_data(as_text=True))
        assert "(redirects to HTTPS)" in row and "✓ Active" in row
        assert "(not in use: no certificate is installed)" not in row
