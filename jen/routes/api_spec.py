"""
jen/routes/api_spec.py
──────────────────────
v5.34.0 (Q33) — the OpenAPI 3.0 description of /api/v1/, as ONE Python
dict. Not introspected from Flask and not a new dependency: hand-kept,
and kept honest by tests/test_api_spec.py, which walks the app's URL
map and fails when a /api/v1/ route and this document disagree in
either direction (a route without a path entry, a path entry without a
route, or a method mismatch).

Served at GET /api/v1/openapi.json (no auth — like /api/v1/health; it
describes the surface, it doesn't expose data).
"""

_KEY = {"BearerKey": []}
_ERR = {"description": "Error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}}


def _resp(desc, schema_ref):
    return {
        "description": desc,
        "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{schema_ref}"}}},
    }


def _q(name, desc, kind="string"):
    return {"name": name, "in": "query", "required": False, "schema": {"type": kind}, "description": desc}


def build_spec(version: str, base_url: str = "") -> dict:
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Jen REST API",
            "version": version,
            "description": (
                "Jen's integration API. Reads for Home Assistant, Zabbix and scripts; "
                "writes (v5.34.0) for reservations, device names and subnet notes with a key that has write access. "
                "Nothing that edits a Kea configuration file is exposed here."
            ),
        },
        "servers": [{"url": base_url or "/"}],
        "components": {
            "securitySchemes": {
                "BearerKey": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "An API key from Settings → Access & Security → API Keys (`jen_…`). "
                    "Write endpoints additionally need the key's *Allow writes* flag.",
                }
            },
            "schemas": {
                "Error": {"type": "object", "properties": {"error": {"type": "string"}}, "required": ["error"]},
                "Health": {
                    "type": "object",
                    "properties": {
                        "jen_version": {"type": "string"},
                        "kea_up": {"type": "boolean"},
                        "kea_version": {"type": "string"},
                        "subnets": {"type": "integer"},
                    },
                },
                "Subnet": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"},
                        "cidr": {"type": "string"},
                        "active_leases": {"type": "integer"},
                        "reserved": {"type": "integer"},
                        "pool_size": {"type": "integer"},
                        "utilization_pct": {"type": "number"},
                        "peak_30d": {
                            "type": "integer",
                            "nullable": True,
                            "description": "Highest active-lease count in the last 30 days of snapshots (v5.36.0).",
                        },
                        "trend_per_day": {
                            "type": "number",
                            "nullable": True,
                            "description": "Least-squares slope of the daily peaks, leases per day; null until 7 days of history.",
                        },
                        "days_to_90pct": {
                            "type": "integer",
                            "nullable": True,
                            "description": "Days until the trend reaches 90% of the pool; null when flat, falling, beyond 365 days or unknown.",
                        },
                        "forecast": {
                            "type": "string",
                            "enum": ["rising", "flat", "falling", "insufficient", "no-pool"],
                        },
                    },
                },
                "SubnetList": {
                    "type": "object",
                    "properties": {"subnets": {"type": "array", "items": {"$ref": "#/components/schemas/Subnet"}}},
                },
                "PacketHealth": {
                    "type": "object",
                    "nullable": True,
                    "description": "null until the server has two statistic-get-all snapshots (Q42).",
                    "properties": {
                        "status": {"type": "string", "enum": ["ok", "warn", "fail", "no_traffic"]},
                        "window_minutes": {"type": "integer", "description": "Actual minutes of data covered."},
                        "rates": {
                            "type": "object",
                            "description": "pkt4-*/v4-* counter name to per-minute rate over the window.",
                            "additionalProperties": {"type": "number"},
                        },
                    },
                },
                "Server": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"},
                        "role": {"type": "string"},
                        "up": {"type": "boolean"},
                        "ha_state": {"type": "string", "nullable": True},
                        "version": {"type": "string"},
                        "packet_health": {"$ref": "#/components/schemas/PacketHealth"},
                    },
                },
                "ServerList": {
                    "type": "object",
                    "properties": {
                        "servers": {"type": "array", "items": {"$ref": "#/components/schemas/Server"}},
                        "count": {"type": "integer"},
                    },
                },
                "Lease": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "mac": {"type": "string"},
                        "hostname": {"type": "string"},
                        "subnet_id": {"type": "integer"},
                        "subnet_name": {"type": "string"},
                        "expires": {"type": "string"},
                        "active": {"type": "boolean"},
                    },
                },
                "LeaseList": {
                    "type": "object",
                    "properties": {
                        "leases": {"type": "array", "items": {"$ref": "#/components/schemas/Lease"}},
                        "count": {"type": "integer"},
                    },
                },
                "Device": {
                    "type": "object",
                    "properties": {
                        "mac": {"type": "string"},
                        "name": {"type": "string", "nullable": True},
                        "owner": {"type": "string", "nullable": True},
                        "notes": {"type": "string", "nullable": True},
                        "last_ip": {"type": "string", "nullable": True},
                        "subnet_id": {"type": "integer", "nullable": True},
                        "online": {"type": "boolean"},
                    },
                },
                "DeviceList": {
                    "type": "object",
                    "properties": {
                        "devices": {"type": "array", "items": {"$ref": "#/components/schemas/Device"}},
                        "count": {"type": "integer"},
                    },
                },
                "Reservation": {
                    "type": "object",
                    "properties": {
                        "host_id": {"type": "integer", "nullable": True},
                        "ip": {"type": "string"},
                        "mac": {"type": "string"},
                        "hostname": {"type": "string"},
                        "subnet_id": {"type": "integer"},
                        "subnet_name": {"type": "string"},
                    },
                },
                "ReservationList": {
                    "type": "object",
                    "properties": {
                        "reservations": {"type": "array", "items": {"$ref": "#/components/schemas/Reservation"}},
                        "count": {"type": "integer"},
                    },
                },
                "ReservationCreate": {
                    "type": "object",
                    "required": ["subnet_id", "ip", "mac"],
                    "properties": {
                        "subnet_id": {"type": "integer"},
                        "ip": {"type": "string", "example": "10.0.0.50"},
                        "mac": {"type": "string", "example": "aa:bb:cc:dd:ee:ff"},
                        "hostname": {"type": "string"},
                        "dns": {"type": "string", "description": "Per-host domain-name-servers override"},
                        "notes": {"type": "string", "description": "Kept in Jen's reservation_notes"},
                    },
                },
                "ReservationDeleted": {
                    "type": "object",
                    "properties": {
                        "deleted": {"type": "integer"},
                        "ip": {"type": "string"},
                        "mac": {"type": "string"},
                        "subnet_id": {"type": "integer"},
                    },
                },
                "DevicePatch": {
                    "type": "object",
                    "description": "Any subset; null clears a field.",
                    "properties": {
                        "name": {"type": "string", "nullable": True},
                        "owner": {"type": "string", "nullable": True},
                        "notes": {"type": "string", "nullable": True},
                    },
                },
                "SubnetNotes": {
                    "type": "object",
                    "properties": {"text": {"type": "string", "description": "Empty string clears the note"}},
                },
                "SubnetNotesResult": {
                    "type": "object",
                    "properties": {"subnet_id": {"type": "integer"}, "notes": {"type": "string"}},
                },
            },
        },
        "paths": {
            "/api/v1/health": {
                "get": {"summary": "Kea status and Jen version (no auth)", "responses": {"200": _resp("OK", "Health")}}
            },
            "/api/v1/subnets": {
                "get": {
                    "summary": "Subnet utilization",
                    "security": [_KEY],
                    "responses": {"200": _resp("OK", "SubnetList"), "401": _ERR},
                }
            },
            "/api/v1/servers": {
                "get": {
                    "summary": "Kea servers, HA state and packet health (Q42)",
                    "security": [_KEY],
                    "responses": {"200": _resp("OK", "ServerList"), "401": _ERR},
                }
            },
            "/api/v1/leases": {
                "get": {
                    "summary": "Active leases",
                    "security": [_KEY],
                    "parameters": [
                        _q("subnet", "Subnet name or id"),
                        _q("mac", "Filter by MAC"),
                        _q("hostname", "Filter by hostname (substring)"),
                        _q("limit", "Max rows, default 200, max 1000", "integer"),
                    ],
                    "responses": {"200": _resp("OK", "LeaseList"), "401": _ERR},
                }
            },
            "/api/v1/leases/{mac}": {
                "get": {
                    "summary": "One device's current lease",
                    "security": [_KEY],
                    "parameters": [{"name": "mac", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": _resp("OK", "Lease"), "401": _ERR, "404": _ERR},
                }
            },
            "/api/v1/devices": {
                "get": {
                    "summary": "Device inventory",
                    "security": [_KEY],
                    "parameters": [
                        _q("mac", "Filter by MAC"),
                        _q("name", "Filter by name (substring)"),
                        _q("subnet", "Subnet name or id"),
                        _q("limit", "Max rows", "integer"),
                    ],
                    "responses": {"200": _resp("OK", "DeviceList"), "401": _ERR},
                }
            },
            "/api/v1/devices/{mac}": {
                "get": {
                    "summary": "One device with online status and current lease",
                    "security": [_KEY],
                    "parameters": [{"name": "mac", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": _resp("OK", "Device"), "401": _ERR, "404": _ERR},
                },
                "patch": {
                    "summary": "Set a device's name, owner and/or notes (write key)",
                    "security": [_KEY],
                    "parameters": [{"name": "mac", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/DevicePatch"}}},
                    },
                    "responses": {
                        "200": _resp("Updated", "Device"),
                        "400": _ERR,
                        "401": _ERR,
                        "403": _ERR,
                        "404": _ERR,
                        "429": _ERR,
                    },
                },
            },
            "/api/v1/reservations": {
                "get": {
                    "summary": "Reservations",
                    "security": [_KEY],
                    "parameters": [_q("subnet", "Subnet name or id"), _q("limit", "Max rows", "integer")],
                    "responses": {"200": _resp("OK", "ReservationList"), "401": _ERR},
                },
                "post": {
                    "summary": "Create a reservation through Kea's host_cmds hook (write key)",
                    "security": [_KEY],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ReservationCreate"}}},
                    },
                    "responses": {
                        "201": _resp("Created", "Reservation"),
                        "400": _ERR,
                        "401": _ERR,
                        "403": _ERR,
                        "404": _ERR,
                        "429": _ERR,
                        "502": {
                            "description": "Kea refused (its own message in `error`)",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                        },
                    },
                },
            },
            "/api/v1/reservations/{host_id}": {
                "delete": {
                    "summary": "Delete a reservation by Kea host id (write key)",
                    "security": [_KEY],
                    "parameters": [{"name": "host_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {
                        "200": _resp("Deleted", "ReservationDeleted"),
                        "401": _ERR,
                        "403": _ERR,
                        "404": _ERR,
                        "429": _ERR,
                        "502": _ERR,
                    },
                }
            },
            "/api/v1/subnets/{subnet_id}/notes": {
                "post": {
                    "summary": "Set the subnet's note (write key)",
                    "security": [_KEY],
                    "parameters": [
                        {"name": "subnet_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SubnetNotes"}}},
                    },
                    "responses": {
                        "200": _resp("Saved", "SubnetNotesResult"),
                        "400": _ERR,
                        "401": _ERR,
                        "403": _ERR,
                        "404": _ERR,
                        "429": _ERR,
                    },
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "summary": "This document (no auth)",
                    "responses": {"200": {"description": "OpenAPI 3.0 document"}},
                }
            },
        },
    }


def flask_rule_to_openapi_path(rule: str) -> str:
    """`/api/v1/devices/<mac>` → `/api/v1/devices/{mac}`;
    `/x/<int:host_id>` → `/x/{host_id}`."""
    import re

    return re.sub(r"<(?:[a-z]+:)?([A-Za-z_]+)>", r"{\1}", rule)
