"""
tests/test_api_spec.py
──────────────────────
v5.34.0 (Q33) — /api/v1/openapi.json, generated from one dict in
jen/routes/api_spec.py, and the drift guard: every /api/v1/ rule in the
app's URL map must appear in the document with exactly its methods, and
every documented path must be a real route. Add a route without
documenting it (or the reverse) and this fails.
"""

import json

import pytest

from jen.routes.api_spec import build_spec, flask_rule_to_openapi_path


class TestPathConversion:
    @pytest.mark.parametrize(
        "rule,path",
        [
            ("/api/v1/health", "/api/v1/health"),
            ("/api/v1/devices/<mac>", "/api/v1/devices/{mac}"),
            ("/api/v1/reservations/<int:host_id>", "/api/v1/reservations/{host_id}"),
            ("/api/v1/subnets/<int:subnet_id>/notes", "/api/v1/subnets/{subnet_id}/notes"),
        ],
    )
    def test_convert(self, rule, path):
        assert flask_rule_to_openapi_path(rule) == path


class TestDocumentShape:
    def test_is_openapi_3_with_bearer_scheme(self):
        spec = build_spec("5.34.0-beta.1", "https://jen.lan")
        assert spec["openapi"].startswith("3.0")
        assert spec["info"]["version"] == "5.34.0-beta.1"
        assert spec["servers"] == [{"url": "https://jen.lan"}]
        assert spec["components"]["securitySchemes"]["BearerKey"]["scheme"] == "bearer"

    def test_every_ref_resolves(self):
        spec = build_spec("1.0.0")
        text = json.dumps(spec)
        schemas = set(spec["components"]["schemas"])
        import re

        for ref in set(re.findall(r'"\$ref": "#/components/schemas/([A-Za-z]+)"', text)):
            assert ref in schemas, ref

    def test_write_operations_require_the_key_and_document_403(self):
        spec = build_spec("1.0.0")
        writes = [
            ("/api/v1/reservations", "post"),
            ("/api/v1/reservations/{host_id}", "delete"),
            ("/api/v1/devices/{mac}", "patch"),
            ("/api/v1/subnets/{subnet_id}/notes", "post"),
        ]
        for path, method in writes:
            op = spec["paths"][path][method]
            assert op["security"] == [{"BearerKey": []}], (path, method)
            assert "403" in op["responses"], (path, method)


class TestDriftAgainstTheApp:
    def _routes(self, app):
        out = {}
        for rule in app.url_map.iter_rules():
            if not rule.rule.startswith("/api/v1/"):
                continue
            methods = {m.lower() for m in rule.methods if m not in ("HEAD", "OPTIONS")}
            out.setdefault(flask_rule_to_openapi_path(rule.rule), set()).update(methods)
        return out

    def test_every_route_is_documented_and_every_documented_path_exists(self, app):
        spec = build_spec("x")
        routes = self._routes(app)
        documented = {
            p: {m for m in ops if m in ("get", "post", "put", "patch", "delete")} for p, ops in spec["paths"].items()
        }
        assert set(routes) == set(documented), {
            "undocumented routes": sorted(set(routes) - set(documented)),
            "documented but missing": sorted(set(documented) - set(routes)),
        }
        for path in routes:
            assert routes[path] == documented[path], (path, routes[path], documented[path])

    def test_served_without_auth_and_matches_the_builder(self, client):
        r = client.get("/api/v1/openapi.json")
        assert r.status_code == 200
        assert r.headers["Content-Type"].startswith("application/json")
        body = r.get_json()
        assert body["openapi"].startswith("3.0")
        from jen import JEN_VERSION

        assert body["info"]["version"] == JEN_VERSION
        assert set(body["paths"]) == set(build_spec("x")["paths"])
