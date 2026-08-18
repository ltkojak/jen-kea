"""
tests/test_self_update.py
────────────────────────────
self_update() had zero test coverage before this — which is exactly how
a real, significant bug survived undetected across every release before
v4.4.16: run.py was never in the generated helper script's copy list at
all, meaning anyone using the self-update button as their actual
deployment path (rather than `install.sh --upgrade`) was silently
running a stale run.py forever, regardless of what changed in it. Found
only because a logging-config change to run.py itself made the gap
externally visible for the first time.

This test doesn't hit the network or touch the real filesystem outside
of tmp_path — it mocks GitHub's API response and serves a real,
minimal, valid tar.gz built on the fly, then intercepts the generated
helper script's actual file content before cleanup deletes it. That's
the level of white-box coverage that would have caught the original bug
on day one.
"""

import io
import json
import tarfile
from unittest.mock import patch, MagicMock

import pytest


def _build_fake_release_tarball(version="4.4.16", with_static=False):
    """A real, valid tar.gz with exactly the top-level layout self_update()
    expects: jen/{run.py, jen/__init__.py, templates/index.html,
    jen.service, jen-sudoers}. Minimal but structurally real — this is
    parsed by the actual tarfile module in self_update(), not a mock."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def add(path, content):
            data = content.encode()
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        add("jen/run.py", "#!/usr/bin/env python3\n# fake run.py content for testing\n")
        add("jen/jen/__init__.py", f'JEN_VERSION = "{version}"\n')
        add("jen/templates/index.html", "<html></html>\n")
        add("jen/jen.service", "[Unit]\nDescription=fake\n")
        add("jen/jen-sudoers", "www-data ALL=(root) NOPASSWD: /bin/true\n")
        if with_static:
            add("jen/static/favicon.ico", "fake-favicon-bytes\n")
            add("jen/static/js/htmx.min.js", "// fake htmx\n")
            add("jen/static/js/chart.umd.min.js", "// fake chart.js\n")
            add("jen/static/icons/brands/apple.svg", "<svg></svg>\n")
    buf.seek(0)
    return buf.read()


class TestSelfUpdateCopiesRunPy:
    """The actual regression guard: run.py must be in the generated
    helper script's copy commands. Everything else in this test class
    is scaffolding to reach that one assertion safely."""

    def test_run_py_is_in_the_generated_copy_commands(self, logged_in_client, tmp_path, monkeypatch):
        tarball_bytes = _build_fake_release_tarball()

        fake_api_response = MagicMock()
        fake_api_response.status_code = 200
        fake_api_response.json.return_value = {
            "tag_name": "v4.4.16",
            "assets": [
                {"name": "jen-v4.4.16.tar.gz",
                 "browser_download_url": "https://github.com/ltkojak/jen-kea/releases/download/v4.4.16/jen-v4.4.16.tar.gz"},
            ],
        }

        fake_download_response = MagicMock()
        fake_download_response.status_code = 200
        fake_download_response.iter_content = lambda chunk_size: [tarball_bytes]

        def fake_get(url, **kwargs):
            if "api.github.com" in url:
                return fake_api_response
            return fake_download_response

        # Capture the helper script's actual content before self_update()
        # deletes it — this is the file a real deployment would run via
        # sudo. Return a fake successful CompletedProcess instead of
        # really invoking sudo/bash.
        captured_helper_content = {}

        def fake_subprocess_run(cmd, **kwargs):
            if cmd[:2] == ["/usr/bin/sudo", "/bin/bash"]:
                helper_path = cmd[2]
                with open(helper_path) as f:
                    captured_helper_content["script"] = f.read()
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            return result

        with patch("jen.routes.settings.requests.get", side_effect=fake_get), \
             patch("jen.routes.settings.subprocess.run", side_effect=fake_subprocess_run), \
             patch("jen.routes.settings.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            r = logged_in_client.post("/settings/infrastructure/self-update",
                                      data={"version": "4.4.16", "db_backup": "0"},
                                      follow_redirects=True)

        assert r.status_code == 200
        assert "script" in captured_helper_content, (
            "self_update() never reached the point of writing/running the "
            "helper script — check the route path and request are correct"
        )
        script = captured_helper_content["script"]

        # The actual regression guard. Specifically checks for a `cp`
        # command targeting run.py — not just any mention of the string
        # "run.py" anywhere in the script, since the chown line also
        # legitimately mentions run.py and a loose substring check would
        # pass even if the actual copy command were missing (caught this
        # exact false-positive while validating this test: a substring
        # check passed against deliberately-reverted buggy code, because
        # only the copy line was missing, not the chown line).
        import re
        assert re.search(r'cp\s+"[^"]*run\.py"\s+"[^"]*run\.py"', script), (
            "No `cp ... run.py ... run.py` command found in the generated "
            "self-update helper script — this is exactly the v4.4.16 bug: "
            "the jen/ package gets updated correctly but the entry point "
            "systemd actually executes doesn't, silently, on every release."
        )
        # And confirm the other known-good copy targets are still present,
        # so this test would also catch a regression removing THEM instead.
        assert "jen\"" in script or "install_dir}/jen\"" in script or '/jen"' in script
        assert "templates" in script


def _run_self_update_and_capture_helper_script(logged_in_client, version="5.1.6", with_static=False):
    """Shared scaffolding: run self_update() against a real (in-memory)
    tarball and capture the generated helper script's content before
    self_update() deletes it. Same approach as
    TestSelfUpdateCopiesRunPy above."""
    tarball_bytes = _build_fake_release_tarball(version=version, with_static=with_static)

    fake_api_response = MagicMock()
    fake_api_response.status_code = 200
    fake_api_response.json.return_value = {
        "tag_name": f"v{version}",
        "assets": [
            {"name": f"jen-v{version}.tar.gz",
             "browser_download_url": f"https://github.com/ltkojak/jen-kea/releases/download/v{version}/jen-v{version}.tar.gz"},
        ],
    }

    fake_download_response = MagicMock()
    fake_download_response.status_code = 200
    fake_download_response.iter_content = lambda chunk_size: [tarball_bytes]

    def fake_get(url, **kwargs):
        if "api.github.com" in url:
            return fake_api_response
        return fake_download_response

    captured = {}

    def fake_subprocess_run(cmd, **kwargs):
        if cmd[:2] == ["/usr/bin/sudo", "/bin/bash"]:
            helper_path = cmd[2]
            with open(helper_path) as f:
                captured["script"] = f.read()
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        return result

    with patch("jen.routes.settings.requests.get", side_effect=fake_get), \
         patch("jen.routes.settings.subprocess.run", side_effect=fake_subprocess_run), \
         patch("jen.routes.settings.threading.Thread") as mock_thread:
        mock_thread.return_value = MagicMock()
        r = logged_in_client.post("/settings/infrastructure/self-update",
                                  data={"version": version, "db_backup": "0"},
                                  follow_redirects=True)

    assert r.status_code == 200
    assert "script" in captured, (
        "self_update() never reached the point of writing/running the "
        "helper script — check the route path and request are correct"
    )
    return captured["script"]


class TestSelfUpdateCopiesStaticAssets:
    """v5.1.6 — self_update() previously only copied
    static/icons/brands/*.svg, with a comment explicitly excluding
    "other static/ subfolders (nav_logo, favicon, generated JS, etc.)".
    That lumped vendored release assets (htmx.min.js,
    chart.umd.min.js, favicon.ico — all committed to the repo and
    shipped in every release tarball) in with genuine user uploads
    (static/icons/custom/), meaning anyone using the self-update button
    never received ANY update to vendored JS on ANY release — a
    separate, independently-maintained gap from the same-shaped bug
    already found and fixed in install.sh (v5.1.5). This is the
    self-update code path's fix for it."""

    def test_static_directory_copy_command_present(self, logged_in_client):
        script = _run_self_update_and_capture_helper_script(logged_in_client, with_static=True)
        import re
        assert re.search(r'cp\s+-r\s+"[^"]*static[^"]*"\s+"[^"]*static[^"]*"', script), (
            "No recursive `cp -r ... static ...` command found in the "
            "generated self-update helper script — vendored JS "
            "(chart.umd.min.js, htmx.min.js) and favicon.ico would never "
            "be deployed via the self-update button."
        )

    def test_static_copy_never_targets_icons_custom(self, logged_in_client):
        """The copy must be a directory-level cp from the extracted
        tarball's static/ into the install dir's static/ — not
        something that could plausibly clobber static/icons/custom/
        (user-uploaded device icons), which doesn't exist in the
        tarball at all and must never be referenced as a copy target
        or deletion target. And unlike templates/jen/ (which get
        `rm -rf`'d before being replaced), static/ must be a plain
        additive copy — an rm -rf here would wipe out custom icons
        that legitimately live only in the install dir, never in the
        tarball."""
        script = _run_self_update_and_capture_helper_script(logged_in_client, with_static=True)
        assert "icons/custom" not in script
        for line in script.splitlines():
            if "rm -rf" in line:
                assert "static" not in line

    def test_run_still_succeeds_without_static_dir_in_tarball(self, logged_in_client):
        """Older/malformed tarballs without a static/ directory
        shouldn't crash self_update() — the copy command is
        conditional on the directory actually existing in the
        extracted tarball, same pattern as the other copy_cmds."""
        script = _run_self_update_and_capture_helper_script(logged_in_client, with_static=False)
        assert script  # helper script still gets written and run
        assert "run.py" in script  # other copy commands still present
