"""
tests/_author_world.py - two Kea hosts whose config files really change, for the Author Kea Config route tests (Q150).

`World` makes tests/_kea_host_fakes.py::FakeHelper STATEFUL: apply-config / remove-config change what read-config answers, so a
"restore" is observed as the state of the fake hosts and not as a call count. `fail_apply` / `fail_test` / `fail_remove` are sets of
server ids whose op is refused.
"""

from jen import extensions
from jen.services import kea_host
from tests._kea_host_fakes import FakeHelper

A = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1", "kea_conf": "/etc/kea/kea-dhcp6.conf"}
B = {"id": 2, "name": "kea-b", "ssh_host": "10.0.0.2", "kea_conf": "/etc/kea/kea-dhcp6.conf"}
URL = "/settings/infrastructure/author-kea/dhcp6"
FORM = {
    "interfaces": "eth0",
    "control_socket": "/run/kea6.sock",
    "db_host": "h",
    "db_user": "u",
    "db_name": "kea",
    "subnets": "1 = V6LAN, 2001:db8::/64",
}


class World:
    def __init__(self, monkeypatch):
        self.fake = FakeHelper()
        self.fail_apply, self.fail_test, self.fail_remove = set(), set(), set()
        self.counter = 0
        self.fake.responses["test-config"] = self._test
        self.fake.responses["apply-config"] = self._apply
        self.fake.responses["remove-config"] = self._remove
        monkeypatch.setattr(kea_host, "helper_call", self.fake.helper_call)
        monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
        monkeypatch.setattr(kea_host, "helper_status", dict)
        monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a, **k: None)
        monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
        monkeypatch.setattr(extensions, "KEA_SERVERS", [dict(A), dict(B)])
        monkeypatch.setattr(extensions, "SUBNET6_MAP", {})
        self.subnet_writes = []
        monkeypatch.setattr("jen.config.write_subnets6_config", lambda d: self.subnet_writes.append(d))

    def put(self, server_id, cfg, sha):
        self.fake.configs[(server_id, "dhcp6")] = cfg
        self.fake.shas[(server_id, "dhcp6")] = sha

    def has(self, server_id):
        return (server_id, "dhcp6") in self.fake.configs

    def sha(self, server_id):
        return self.fake.shas.get((server_id, "dhcp6"))

    def calls(self, op):
        return [(sid, p) for (sid, o, p) in self.fake.calls if o == op]

    def _test(self, server, op, payload):
        if server["id"] in self.fail_test:
            return {"ok": False, "error": "testerror", "detail": f"bad interface on {server['name']}"}
        return {"ok": True}

    def _apply(self, server, op, payload):
        sid, key = server["id"], (server["id"], payload["service"])
        current = self.fake.shas.get(key) if key in self.fake.configs else None
        expect = payload.get("expect_sha256")
        if expect is not None and ((current is not None) if expect == "" else (current != expect)):
            return {"ok": False, "error": "conflict", "sha256": current or ""}
        if key in self.fake.configs and not payload.get("allow_overwrite", True):
            return {"ok": False, "error": "exists"}
        if sid in self.fail_apply:
            return {"ok": False, "error": "testerror", "detail": f"could not write on {server['name']}"}
        self.counter += 1
        self.fake.configs[key] = payload["config"]
        self.fake.shas[key] = f"written-{sid}-{self.counter}"
        return {"ok": True, "sha256": self.fake.shas[key], "backup": None}

    def _remove(self, server, op, payload):
        sid, key = server["id"], (server["id"], payload["service"])
        if sid in self.fail_remove:
            return {"ok": False, "error": "helper-exception", "detail": "disk went away"}
        if self.fake.shas.get(key) != payload.get("expect_sha256"):
            return {"ok": False, "error": "conflict"}
        self.fake.configs.pop(key, None)
        self.fake.shas.pop(key, None)
        return {"ok": True}
