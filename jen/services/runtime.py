"""
jen/services/runtime.py
────────────────────────
deployment() -> "systemd" | "docker" | "dev"

v5.67.0-beta.6 (Q118) — the ONE place that answers "what kind of host is
this process actually running on." Before this, jen/services/plugins.py's
is_systemd_host() answered a narrower version of the same question by
checking whether JEN_ROOT was set in the environment — a heuristic that
broke the moment Q114 (5.67.0-beta.2) started setting
`Environment=JEN_ROOT=<app_dir>/current/app` in the rendered systemd
unit itself: from that release, every native install answered "not
systemd" exactly like a dev checkout does, losing its Update/Restart
controls on Settings -> System and routing plugin installs onto the
in-process path meant for Docker. `content_dir_incomplete()`
(jen/services/content.py) and the venv-migration check (jen/__init__.py)
had the identical JEN_ROOT-as-condition bug for the same reason.

JEN_ROOT says nothing about deployment — it is a PATH override, read the
same way by a relocated production install, a Docker container, and a
bare dev checkout (jen/extensions.py keeps it as exactly that: a path
default, nothing more). The real signals are `/.dockerenv` for a
container, and for systemd either an explicit
`Environment=JEN_SERVICE_MANAGER=systemd` line (added to
jen.service.template by this release) or `INVOCATION_ID` in the
environment — systemd sets this for every unit it starts, which covers
a unit rendered before this release and a hand-written one from
docs/manual-install.md without needing the new line at all.
"""

import os


def deployment() -> str:
    """ "systemd" | "docker" | "dev" — never derived from JEN_ROOT."""
    if os.path.exists("/.dockerenv"):
        return "docker"
    if os.environ.get("JEN_SERVICE_MANAGER") == "systemd" or "INVOCATION_ID" in os.environ:
        return "systemd"
    return "dev"
