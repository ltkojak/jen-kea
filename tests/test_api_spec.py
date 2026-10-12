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
            # v5.57.0 (Q73) — plugin routes live under this prefix too
            # (mounted by each plugin's own register(app)) but are
            # documented in the plugin's own README, not here.
            if rule.rule.startswith("/api/v1/plugins/"):
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


class TestNoInstanceDataBeyondVersionAndServerUrl:
    """v5.66.0-beta.4 (Q106) — /api/v1/openapi.json is public by decision
    (docs/ARCHITECTURE.md §3.15): the document is built from one static dict,
    and the ONLY values in it that come from this particular install are
    `info.version` (already public on /api/v1/health) and `servers[0].url`
    (the request's own host reflected back). Pinning that as a property —
    not just trusting build_spec's current implementation to stay that way —
    is what actually backs the "it stays public" decision."""

    def test_only_version_and_server_url_vary_with_the_builder_inputs(self):
        a = build_spec("1.2.3-beta.4", "https://jen-a.example")
        b = build_spec("9.9.9", "https://jen-b.example")
        a["info"]["version"] = b["info"]["version"] = "SAME"
        a["servers"] = b["servers"] = "SAME"
        assert a == b, "something besides info.version/servers[0].url changes with build_spec's own inputs"

    def test_anonymous_body_carries_no_fixture_seed_data(self, client):
        """Scans the RAW served body (not a hand-built one) for markers from this suite's own
        seeded fixture data — a real subnet/server name/CIDR, and a bundled plugin id used only
        as an illustrative path segment, never as data. The version string is stripped first
        so it can never coincidentally match one of the (unrelated) markers below."""
        from jen import JEN_VERSION

        r = client.get("/api/v1/openapi.json")
        text = r.get_data(as_text=True).replace(JEN_VERSION, "")
        for marker in ("Test Kea", "Test Network", "10.99.0.0", "ipam", "network-discovery"):
            assert marker not in text, f"fixture/instance marker {marker!r} leaked into the public API spec"


class TestEveryDocumentedResponseMatchesTheSchema:
    """v5.69.0-beta.5 (Q174): the document drifted from the code in quiet ways (a Subnet `reserved` that was `reservations`, a Lease with no `obtained`, a Device `name` that was `device_name`).
    Each documented GET without a path parameter is called with a real key; the response's top-level keys must be properties of its schema, every `required` key must be present, and
    for a list the same holds for each item."""

    @staticmethod
    def _headers(db):
        import hashlib

        from tests.test_api_key_authorization import _insert_admin_user, _insert_api_key

        admin_id = _insert_admin_user(db, "q174_spec_admin")
        key_id = _insert_api_key(db, "_q174_spec_key", created_by=admin_id)
        raw = "jen_q174_spec_key_value"
        with db.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET key_hash=%s WHERE id=%s", (hashlib.sha256(raw.encode()).hexdigest(), key_id)
            )
        db.commit()
        return {"Authorization": f"Bearer {raw}"}

    @staticmethod
    def _schema(spec, node):
        while "$ref" in node:
            node = spec["components"]["schemas"][node["$ref"].rsplit("/", 1)[1]]
        return node

    def _check(self, spec, schema, body, where):
        schema = self._schema(spec, schema)
        props = schema.get("properties") or {}
        if not props:
            return
        extra = set(body) - set(props)
        assert not extra, f"{where}: keys the document does not describe: {sorted(extra)}"
        missing = set(schema.get("required") or []) - set(body)
        assert not missing, f"{where}: required keys absent: {sorted(missing)}"
        for name, sub in props.items():
            sub = self._schema(spec, sub)
            if name in body and sub.get("type") == "array" and isinstance(body[name], list):
                item_schema = self._schema(spec, sub.get("items") or {})
                for i, item in enumerate(body[name][:3]):
                    if isinstance(item, dict):
                        self._check(spec, item_schema, item, f"{where}.{name}[{i}]")

    def test_the_get_responses_match(self, client, db, mock_kea, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: {"name": "Office", "cidr": "10.99.0.0/24"}})
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)='AABBCCDDEE71'")
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCCDDEE72'")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state, hostname) VALUES "
                "(INET_ATON('10.99.0.171'), UNHEX('AABBCCDDEE71'), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0, 'q174-lease')"
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('AABBCCDDEE72'), 0, 1, INET_ATON('10.99.0.172'), 'q174-host')"
            )
            cur.execute("DELETE FROM devices WHERE mac='aa:bb:cc:dd:ee:71'")
            cur.execute(
                "INSERT INTO devices (mac, device_name, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) "
                "VALUES ('aa:bb:cc:dd:ee:71', 'q174 device', '10.99.0.171', 'q174-lease', 1, NOW(), NOW())"
            )
        db.commit()
        headers = self._headers(db)
        spec = build_spec("x")
        checked = []
        try:
            for path, item in spec["paths"].items():
                if "{" in path or "get" not in item or path == "/api/v1/openapi.json":
                    continue
                ok = item["get"]["responses"].get("200") or {}
                schema = ((ok.get("content") or {}).get("application/json") or {}).get("schema")
                if not schema:
                    continue
                r = client.get(path, headers=headers)
                assert r.status_code == 200, (path, r.status_code, r.get_data(as_text=True)[:200])
                self._check(spec, schema, r.get_json(), path)
                checked.append(path)
            for path in ("/api/v1/leases/aa:bb:cc:dd:ee:71", "/api/v1/devices/aa:bb:cc:dd:ee:71"):
                r = client.get(path, headers=headers)
                assert r.status_code == 200, (path, r.status_code)
                spec_path = path.rsplit("/", 1)[0] + "/{mac}"
                schema = spec["paths"][spec_path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
                self._check(spec, schema, r.get_json(), path)
                checked.append(path)
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)='AABBCCDDEE71'")
                cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)='AABBCCDDEE72'")
                cur.execute("DELETE FROM devices WHERE mac='aa:bb:cc:dd:ee:71'")
            db.commit()
        assert "/api/v1/subnets" in checked and "/api/v1/leases" in checked and "/api/v1/reservations" in checked
