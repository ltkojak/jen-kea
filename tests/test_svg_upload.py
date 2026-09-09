"""
tests/test_svg_upload.py
────────────────────────
v5.8.4 — uploaded SVGs (custom brand icons, nav logo) are served
same-origin from /static/ under a CSP that allows 'unsafe-inline', so an
SVG carrying <script>/on*=/javascript:/<foreignObject> is stored XSS by
an admin against whoever opens it — including a superadmin. Uploads are
now refused, not sanitized. The pure checker is tested directly; the two
routes are exercised through the real multipart path against tmp dirs.
"""

import io
import os

import pytest

from jen import extensions
from jen.routes.settings.branding import svg_upload_rejection

CLEAN = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4" fill="#0af"/></svg>'


class TestSvgUploadRejection:
    def test_clean_svg_is_accepted(self):
        assert svg_upload_rejection(CLEAN) is None

    @pytest.mark.parametrize(
        "payload",
        [
            b"<svg><script>alert(1)</script></svg>",
            b"<svg><SCRIPT>alert(1)</SCRIPT></svg>",
            b'<svg onload="alert(1)"></svg>',
            b'<svg><a href="javascript:alert(1)"><text>x</text></a></svg>',
            b'<svg><a xlink:href="JavaScript:alert(1)"><text>x</text></a></svg>',
            b"<svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg>",
            b'<svg><image href="https://evil.example/x.svg"/></svg>',
            b'<svg><image xlink:href="data:image/svg+xml;base64,AAAA"/></svg>',
            b'<svg><set attributeName="onmouseover" to="alert(1)"/></svg>',
            b'<svg><animate attributeName="href" values="javascript:alert(1)"/></svg>',
            b'<!DOCTYPE svg [<!ENTITY x "y">]><svg>&x;</svg>',
            b"<svg><iframe src=x></iframe></svg>",
        ],
    )
    def test_active_content_is_rejected(self, payload):
        assert svg_upload_rejection(payload) is not None

    def test_not_an_svg_is_rejected(self):
        assert svg_upload_rejection(b"<html><body>hi</body></html>") is not None

    def test_local_fragment_href_is_fine(self):
        # <use href="#id"> and same-document references are normal SVG.
        assert svg_upload_rejection(b'<svg><defs><g id="a"/></defs><use href="#a"/></svg>') is None


class TestCustomIconUploadRoute:
    def _post(self, client, name, payload):
        return client.post(
            "/settings/icons/upload",
            data={"icon_name": name, "icon": (io.BytesIO(payload), f"{name}.svg")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def _custom_dir(self, tmp_path, monkeypatch):
        # The redirect target (/settings/icons) listdir()s this, so it has
        # to exist even when the upload is refused before creating it.
        d = tmp_path / "custom"
        d.mkdir()
        monkeypatch.setattr(extensions, "ICONS_CUSTOM_DIR", str(d))
        return d

    def test_clean_icon_is_saved(self, logged_in_client, tmp_path, monkeypatch):
        d = self._custom_dir(tmp_path, monkeypatch)
        r = self._post(logged_in_client, "cleanbrand", CLEAN)
        assert r.status_code == 200
        assert (d / "cleanbrand.svg").read_bytes() == CLEAN

    def test_scripted_icon_is_refused_and_not_written(self, logged_in_client, tmp_path, monkeypatch):
        self._custom_dir(tmp_path, monkeypatch)
        r = self._post(logged_in_client, "evilbrand", b"<svg><script>alert(1)</script></svg>")
        assert r.status_code == 200
        assert b"SVG rejected" in r.data
        assert not os.path.exists(tmp_path / "custom" / "evilbrand.svg")


class TestNavLogoUploadRoute:
    def test_scripted_svg_logo_is_refused(self, logged_in_client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "NAV_LOGO_PATH", str(tmp_path / "nav_logo"))
        monkeypatch.setattr(extensions, "STATIC_DIR", str(tmp_path))
        r = logged_in_client.post(
            "/settings/upload-nav-logo",
            data={"logo": (io.BytesIO(b'<svg onload="alert(1)"></svg>'), "logo.svg")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert b"SVG rejected" in r.data
        assert not os.path.exists(tmp_path / "nav_logo.svg")

    def test_clean_svg_logo_is_saved(self, logged_in_client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "NAV_LOGO_PATH", str(tmp_path / "nav_logo"))
        monkeypatch.setattr(extensions, "STATIC_DIR", str(tmp_path))
        r = logged_in_client.post(
            "/settings/upload-nav-logo",
            data={"logo": (io.BytesIO(CLEAN), "logo.svg")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert r.status_code == 200
        assert (tmp_path / "nav_logo.svg").read_bytes() == CLEAN
