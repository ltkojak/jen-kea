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
import signal
import subprocess
import threading
import time


def deployment() -> str:
    """ "systemd" | "docker" | "dev" — never derived from JEN_ROOT."""
    if os.path.exists("/.dockerenv"):
        return "docker"
    if os.environ.get("JEN_SERVICE_MANAGER") == "systemd" or "INVOCATION_ID" in os.environ:
        return "systemd"
    return "dev"


def restart_service(delay: float = 2.0) -> str:
    """Schedule a restart of THIS Jen and say how: "systemd", "docker" or "none" (v5.67.0-beta.10, Q122).

    "Save & Restart", the port change, the certificate upload and removal each ran `sudo systemctl
    restart jen` unconditionally. In a container there is no sudo and no unit: the call failed silently in
    a thread, the page said "Jen is restarting...", and nothing restarted. The restart is now chosen by
    deployment():

      * systemd -> `sudo /usr/bin/systemctl restart jen`, byte for byte the command jen-sudoers grants
        (docs/ARCHITECTURE.md §3.1) — this function adds no new sudo string;
      * docker  -> SIGTERM to the gunicorn master (this worker's parent); the container exits and its
        `restart: unless-stopped` policy (both compose files) brings it back with the new config;
      * dev     -> "none": nothing is restarted, and the caller must say so instead of claiming it.

    The restart runs in a daemon thread after `delay` seconds so the HTTP response that asked for it is
    delivered first."""
    kind = deployment()
    if kind == "systemd":

        def _go():
            subprocess.run(["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "jen"])  # nosec B603
    elif kind == "docker":

        def _go():
            os.kill(os.getppid(), signal.SIGTERM)
    else:
        return "none"

    def _later():
        time.sleep(delay)
        _go()

    threading.Thread(target=_later, daemon=True).start()
    return kind


RESTART_BY_HAND = (
    "This Jen is not running under systemd or Docker, so it cannot restart itself — restart it yourself "
    "for the change to take effect."
)
