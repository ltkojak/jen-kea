"""
tests/_kea_host_fakes.py
────────────────────────
v5.11.0 — FakeHelper stands in for jen/services/kea_host.py::helper_call
so route tests can drive the helper path (and the legacy fallback, via
`missing_for`) without SSH or a real Kea host.

    fake = FakeHelper()
    fake.configs[(1, "dhcp4")] = {"Dhcp4": {"subnet4": [{"id": 10}]}}
    monkeypatch.setattr(kea_host, "helper_call", fake.helper_call)
"""


class FakeHelper:
    def __init__(self):
        self.configs = {}  # (server_id, service) -> config dict
        self.shas = {}  # (server_id, service) -> sha256 string (v2 read-config)
        self.responses = {}  # op -> dict | callable(server, op, payload) -> dict
        self.calls = []  # list of (server_id, op, payload)
        self.missing_for = set()  # server ids that raise HelperMissing
        self.helper_version = 2  # what `version` and every envelope reports

    def helper_call(self, server, op, payload=None, timeout=60):
        from jen.services import kea_host

        sid = server.get("id")
        payload = dict(payload or {})
        self.calls.append((sid, op, payload))

        if sid in self.missing_for:
            raise kea_host.HelperMissing("fake: helper not installed on this host")

        if op == "version":
            return {"ok": True, "helper_version": self.helper_version, "python": "3.12.0"}

        if op == "read-config":
            cfg = self.configs.get((sid, payload.get("service")))
            if cfg is None:
                return {"ok": False, "error": "missing", "helper_version": self.helper_version}
            out = {"ok": True, "config": cfg, "helper_version": self.helper_version}
            sha = self.shas.get((sid, payload.get("service")))
            if sha is not None:
                out["sha256"] = sha
            return out

        r = self.responses.get(op)
        if r is None:
            # A registered-but-forgotten op would otherwise look like a
            # HelperError; be loud instead.
            raise AssertionError(f"FakeHelper: no response registered for op {op!r}")
        return r(server, op, payload) if callable(r) else r

    # convenience
    def ops(self):
        return [op for (_sid, op, _p) in self.calls]

    def payload_for(self, op):
        return next(p for (_sid, o, p) in self.calls if o == op)
