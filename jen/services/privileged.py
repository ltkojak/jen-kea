"""
jen/services/privileged.py
──────────────────────────
v7.1.0-beta.3 (Q213) - how the app asks root for something, with no sudoers line.

Jen's own box had three `NOPASSWD` lines (`/etc/sudoers.d/jen`): restart Jen, start the update unit, start the
plugin-install unit. Each was a fixed, zero-parameter command, matched byte for byte, and rule 8 kept the file and
the three call sites identical by hand. None is needed:

  * a RESTART needs no root at all - `jen.service` has `Restart=always`, so Jen stops its own gunicorn master and
    systemd starts it again (`runtime.restart_service`; the mechanism a container always used);
  * an UPDATE and a PLUGIN install are each a TRIGGER FILE in `/run/jen`, the unit's own runtime directory
    (`RuntimeDirectory=jen`), which a systemd PATH unit watches (`jen-update.path`, `jen-plugin-install.path`).
    The file carries nothing: its existence is the request, exactly what the sudo command was. Root's first act
    is to remove it (`jen-update-root.py`, `consume_trigger`), through a handle on `/run/jen` that follows no link.

THE TRANSITION. An in-app update from a release before this one is run by the OLD root script, which knows no path
unit. So `request` asks systemd whether the path unit is active and, while it is not, runs the old sudo command -
the grant is still on such a box. The NEW root script installs and enables the path units at the start of every
run and only then removes the grant (`converge_triggers`); `converge_at_startup` fires the plugin trigger once so
that happens by itself. `install.sh` does all of it in one step. This module holds the ONLY `sudo` strings left
under `jen/` for Jen's own box, and `tests/test_sudoers_command_matching.py` says so over the whole tree.
"""

import logging
import os
import subprocess

from jen.services import runtime

logger = logging.getLogger(__name__)

TRIGGER_DIR = "/run/jen"

# kind -> (the trigger file's name, the path unit that watches it, the service it starts)
TRIGGERS = {
    "update": ("update.request", "jen-update.path", "jen-update.service"),
    "plugins": ("plugins.request", "jen-plugin-install.path", "jen-plugin-install.service"),
}


def trigger_path(kind: str) -> str:
    return os.path.join(TRIGGER_DIR, TRIGGERS[kind][0])


def path_unit_active(kind: str) -> bool:
    """Is the path unit of this kind watching? A read-only query that needs no privilege. Anything but systemd's
    own "active" - the unit absent, failed, systemctl missing, a timeout - is False, and the caller then takes
    the legacy command, which fails with its own sentence on a box that has no grant either."""
    try:
        done = subprocess.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", TRIGGERS[kind][1]],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"could not ask systemd about {TRIGGERS[kind][1]}: {e}")
        return False
    return done.returncode == 0


def _write_trigger(kind: str) -> tuple[bool, str]:
    path = trigger_path(kind)
    try:
        # no link is followed and nothing is written: the file's existence is the whole request
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
    except OSError as e:
        return False, f"could not write {path}: {e.strerror or e}"
    return True, "path"


def _legacy_start(kind: str) -> tuple[bool, str]:
    """The command `/etc/sudoers.d/jen` granted before this release, byte for byte. Reached only while the path
    unit is not active: a box updated in place from an earlier release, until its root script has run once."""
    service = TRIGGERS[kind][2]
    try:
        done = subprocess.run(  # nosec B603 - a fixed argument list, no input
            ["/usr/bin/sudo", "/usr/bin/systemctl", "start", "--no-block", service],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"could not start {service}: {e}"
    if done.returncode != 0:
        return False, f"{service} did not start (exit {done.returncode}): {(done.stderr or '').strip()}"
    return True, "sudo"


def request(kind: str) -> tuple[bool, str]:
    """Ask root to run the update or the plugin unit. `(True, "path" | "sudo")` when the request was made, else
    `(False, why)`. The trigger file when the path unit is watching; the old sudo command while it is not."""
    if kind not in TRIGGERS:
        raise ValueError(f"unknown privileged request {kind!r}")
    if path_unit_active(kind):
        return _write_trigger(kind)
    return _legacy_start(kind)


REPAIR = "run `sudo ./install.sh` on the Jen host to install the trigger units, then try again"


def converge_at_startup() -> str:
    """Once per start, under systemd: when the plugin path unit is not watching yet, start the plugin unit through
    the old grant. With no request waiting it does nothing as a plugin run - and the root script it runs is this
    release's, whose first step installs the path units and removes the grant. Says what it did: "watching",
    "asked", "not-systemd" or "legacy-unavailable" (no grant either: `install.sh` repairs it, Health says so)."""
    if runtime.deployment() != "systemd":
        return "not-systemd"
    if path_unit_active("plugins") and path_unit_active("update"):
        return "watching"
    ok, why = _legacy_start("plugins")
    if ok:
        logger.info("The trigger units are not active yet: asked the root script to install them (Q213).")
        return "asked"
    logger.warning(f"The trigger units are not active and the earlier grant did not answer ({why}); {REPAIR}.")
    return "legacy-unavailable"
