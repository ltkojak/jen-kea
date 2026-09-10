"""
tests/test_service_hardening.py
───────────────────────────────
v5.17.0 (Q6 6E) — the systemd sandboxing added to jen.service. NOT
NoNewPrivileges / CapabilityBoundingSet / ProtectProc — Jen shells out to
sudo (self-updater, legacy Kea path) and needs the setuid transition.
"""

import configparser
import pathlib

_REPO = pathlib.Path(__file__).resolve().parent.parent


def _unit(name):
    cp = configparser.ConfigParser(strict=False)
    cp.optionxform = str  # keep directive case
    cp.read(_REPO / name)
    return dict(cp["Service"])


class TestJenServiceHardening:
    PRESENT = [
        "ProtectSystem",
        "ReadWritePaths",
        "PrivateTmp",
        "ProtectHome",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectControlGroups",
        "PrivateDevices",
        "RestrictRealtime",
        "RestrictSUIDSGID",
        "LockPersonality",
        "SystemCallArchitectures",
    ]

    def test_each_directive_present(self):
        svc = _unit("jen.service")
        for d in self.PRESENT:
            assert d in svc, f"jen.service missing {d}"
        assert svc["ProtectSystem"] == "strict"
        assert "/etc/jen" in svc["ReadWritePaths"] and "/var/lib/jen" in svc["ReadWritePaths"]
        assert "/opt/jen" not in svc["ReadWritePaths"]  # read-only since Q4

    def test_no_new_privileges_is_absent(self):
        svc = _unit("jen.service")
        assert "NoNewPrivileges" not in svc
        assert "CapabilityBoundingSet" not in svc
        assert "ProtectProc" not in svc

    def test_updater_unit_is_not_sandboxed(self):
        """The root self-updater must not inherit ProtectSystem=strict —
        it writes /opt/jen and /usr/local/sbin."""
        svc = _unit("jen-update.service")
        assert "ProtectSystem" not in svc
