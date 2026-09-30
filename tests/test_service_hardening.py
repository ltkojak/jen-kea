"""
tests/test_service_hardening.py
───────────────────────────────
v5.17.0 (Q6 6E) — the systemd sandboxing added to jen.service. NOT
NoNewPrivileges / CapabilityBoundingSet / ProtectProc — Jen shells out to
sudo (self-updater, legacy Kea path) and needs the setuid transition.

v5.67.0 (Q114) — jen.service is now RENDERED from jen.service.template
(@@APP_DIR@@/@@CONFIG_DIR@@/@@DATA_DIR@@ placeholders, filled in by
install.sh/jen-update-root.py from the resolved layout) rather than
shipped as a ready-to-use unit — this file reads the template directly,
so the directive-presence assertions below still hold regardless of where
a given install's app/config/data actually live.
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
        svc = _unit("jen.service.template")
        for d in self.PRESENT:
            assert d in svc, f"jen.service.template missing {d}"
        assert svc["ProtectSystem"] == "strict"
        assert "@@CONFIG_DIR@@" in svc["ReadWritePaths"] and "@@DATA_DIR@@" in svc["ReadWritePaths"]
        assert "@@APP_DIR@@" not in svc["ReadWritePaths"]  # read-only since Q4

    def test_no_new_privileges_is_absent(self):
        svc = _unit("jen.service.template")
        assert "NoNewPrivileges" not in svc
        assert "CapabilityBoundingSet" not in svc
        assert "ProtectProc" not in svc

    def test_rendering_with_default_layout_reproduces_the_historical_paths(self):
        # The template's own placeholders don't prove a rendered unit is
        # correct — render it with today's literal defaults (what every
        # install before Q114 gets) and check the result matches exactly
        # what the old static jen.service always shipped.
        text = (_REPO / "jen.service.template").read_text(encoding="utf-8")
        rendered = (
            text.replace("@@APP_DIR@@", "/opt/jen")
            .replace("@@CONFIG_DIR@@", "/etc/jen")
            .replace("@@DATA_DIR@@", "/var/lib/jen")
        )
        assert "WorkingDirectory=/opt/jen/current/app" in rendered
        assert "ExecStart=/opt/jen/current/venv/bin/python /opt/jen/current/app/run.py" in rendered
        assert "ReadWritePaths=/etc/jen /var/lib/jen" in rendered
        assert "@@" not in rendered

    def test_updater_unit_is_not_sandboxed(self):
        """The root self-updater must not inherit ProtectSystem=strict —
        it writes /opt/jen and /usr/local/sbin."""
        svc = _unit("jen-update.service")
        assert "ProtectSystem" not in svc
